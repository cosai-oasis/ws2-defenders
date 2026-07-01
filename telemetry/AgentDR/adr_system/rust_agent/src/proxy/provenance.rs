//! Process provenance — resolve *which local process* opened a connection
//! to the LLM Guard reverse proxy.
//!
//! Because the guard listens on loopback, every client is a local process.
//! Knowing the caller's PID, executable path and command line turns an
//! otherwise anonymous "someone hit Ollama" event into actionable
//! provenance ("`/usr/bin/python3 exfil.py` hit Ollama"), and lets the
//! agent reuse its existing [`identify_agent`](crate::models::identify_agent)
//! signatures to attribute the call to a known AI agent.
//!
//! Resolution is inherently OS-specific:
//!   * **Linux** — parse `/proc/net/tcp{,6}` to map the client's
//!     `ip:port` to a socket inode, then scan `/proc/<pid>/fd/*` for a
//!     symlink to `socket:[<inode>]`. No elevated privileges are needed for
//!     the caller's own processes; cross-user lookups degrade gracefully to
//!     a PID-less record.
//!   * **Other OSes** — we return a best-effort record with just the peer
//!     address (the heavy lifting needs ETW / EndpointSecurity and a signed
//!     helper, mirroring `monitors::kernel`).

use serde::Serialize;
use serde_json::{json, Value};
use std::net::SocketAddr;

/// Provenance about the local process that issued a proxied request.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Provenance {
    /// Caller PID, if it could be resolved.
    pub pid: Option<u32>,
    /// Absolute executable path of the caller.
    pub exe: Option<String>,
    /// Full command line (argv) of the caller.
    pub cmdline: Vec<String>,
    /// Process name (argv[0] / comm).
    pub name: Option<String>,
    /// The remote peer address as seen by the proxy (always available).
    pub peer: String,
}

impl Provenance {
    /// A concatenated `name exe cmdline` haystack suitable for
    /// [`identify_agent`](crate::models::identify_agent).
    pub fn haystack(&self) -> String {
        format!(
            "{} {} {}",
            self.name.as_deref().unwrap_or(""),
            self.exe.as_deref().unwrap_or(""),
            self.cmdline.join(" "),
        )
    }

    /// Render as the OCSF-friendly `actor` object carried on an event.
    pub fn to_actor(&self) -> Value {
        json!({
            "pid":     self.pid,
            "exe":     self.exe,
            "cmdline": self.cmdline,
            "name":    self.name,
            "peer":    self.peer,
        })
    }
}

/// Resolve provenance for a client `peer` (the address the proxy saw the
/// connection come from). Never fails — falls back to a peer-only record.
pub fn resolve(peer: SocketAddr) -> Provenance {
    let mut prov = Provenance { peer: peer.to_string(), ..Default::default() };
    #[cfg(target_os = "linux")]
    {
        if let Some(pid) = linux::pid_for_peer(peer) {
            prov.pid = Some(pid);
            linux::fill_process_details(pid, &mut prov);
        }
    }
    prov
}

/// Outcome of a process access-control evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclDecision {
    /// The caller may proceed.
    Allow,
    /// The caller is rejected; the string is a human-readable reason.
    Deny(String),
}

impl crate::config::ProcessAclConfig {
    /// Evaluate this ACL against a resolved [`Provenance`] and the optional
    /// attributed agent name. `deny` rules win over `allow` rules; when neither
    /// matches, the configured `default` (`"deny"` / `"allow"`) decides.
    ///
    /// Matching is a case-insensitive substring test against a haystack of
    /// `name + exe + cmdline + agent_name`.
    pub fn evaluate(&self, prov: &Provenance, agent_name: Option<&str>) -> AclDecision {
        if !self.enabled {
            return AclDecision::Allow;
        }

        let mut hay = prov.haystack().to_lowercase();
        if let Some(a) = agent_name {
            hay.push(' ');
            hay.push_str(&a.to_lowercase());
        }

        // Deny always wins.
        for pat in &self.deny {
            let p = pat.trim().to_lowercase();
            if !p.is_empty() && hay.contains(&p) {
                return AclDecision::Deny(format!("matched deny rule '{}'", pat.trim()));
            }
        }
        // Then an explicit allow.
        for pat in &self.allow {
            let p = pat.trim().to_lowercase();
            if !p.is_empty() && hay.contains(&p) {
                return AclDecision::Allow;
            }
        }
        // Unresolved callers (no PID) can't match exe/cmdline rules; gate them
        // explicitly so an allowlist on a host that can't resolve provenance
        // isn't silently bypassed.
        if prov.pid.is_none() && self.block_unresolved {
            return AclDecision::Deny("caller process could not be resolved".into());
        }
        // Fall back to the default policy.
        match self.default.trim().to_ascii_lowercase().as_str() {
            "allow" => AclDecision::Allow,
            _ => AclDecision::Deny("no allow rule matched (default deny)".into()),
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Provenance;
    use std::net::SocketAddr;

    /// Find the PID that owns the local socket whose *local* endpoint equals
    /// `peer` (from the client's perspective). Returns the first matching PID.
    pub fn pid_for_peer(peer: SocketAddr) -> Option<u32> {
        let inode = socket_inode_for(peer)?;
        pid_for_inode(inode)
    }

    /// Walk `/proc/net/tcp` + `/proc/net/tcp6` for a row whose local address
    /// equals `peer`, returning its socket inode.
    fn socket_inode_for(peer: SocketAddr) -> Option<u64> {
        let want_port = peer.port();
        let want_ip = peer.ip();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(content) = std::fs::read_to_string(path) else { continue };
            for line in content.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                // 1: local_address (hex ip:port), 9: inode
                if cols.len() < 10 { continue; }
                let Some((ip, port)) = parse_hex_addr(cols[1]) else { continue };
                if port != want_port { continue; }
                // Loopback clients usually present as the same family; accept a
                // port match on loopback even if v4/v6 representations differ.
                if ip == want_ip || ip.is_loopback() && want_ip.is_loopback() {
                    if let Ok(inode) = cols[9].parse::<u64>() {
                        return Some(inode);
                    }
                }
            }
        }
        None
    }

    /// Decode a `/proc/net/tcp` hex `address:port` field (little-endian IPv4
    /// or IPv6) into a [`std::net::IpAddr`] + port.
    fn parse_hex_addr(s: &str) -> Option<(std::net::IpAddr, u16)> {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let (ip_hex, port_hex) = s.split_once(':')?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        match ip_hex.len() {
            8 => {
                let raw = u32::from_str_radix(ip_hex, 16).ok()?;
                // /proc stores the IPv4 address in host (little-endian) byte order.
                let ip = Ipv4Addr::from(raw.to_le_bytes());
                Some((ip.into(), port))
            }
            32 => {
                let mut bytes = [0u8; 16];
                for i in 0..16 {
                    bytes[i] = u8::from_str_radix(&ip_hex[i * 2..i * 2 + 2], 16).ok()?;
                }
                // Each 32-bit word is little-endian; swap within each 4-byte group.
                for chunk in bytes.chunks_mut(4) {
                    chunk.reverse();
                }
                Some((Ipv6Addr::from(bytes).into(), port))
            }
            _ => None,
        }
    }

    /// Scan `/proc/<pid>/fd/*` for a symlink to `socket:[<inode>]`.
    fn pid_for_inode(inode: u64) -> Option<u32> {
        let want = format!("socket:[{inode}]");
        let entries = std::fs::read_dir("/proc").ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(pid) = name.parse::<u32>() else { continue };
            let fd_dir = format!("/proc/{pid}/fd");
            let Ok(fds) = std::fs::read_dir(&fd_dir) else { continue };
            for fd in fds.flatten() {
                if let Ok(target) = std::fs::read_link(fd.path()) {
                    if target.to_string_lossy() == want {
                        return Some(pid);
                    }
                }
            }
        }
        None
    }

    /// Populate `exe`, `cmdline` and `name` for a PID from `/proc`.
    pub fn fill_process_details(pid: u32, prov: &mut Provenance) {
        if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
            prov.exe = Some(exe.to_string_lossy().to_string());
        }
        if let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) {
            let args: Vec<String> = raw
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect();
            if !args.is_empty() {
                prov.name = args.first().map(|a| {
                    std::path::Path::new(a)
                        .file_name()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_else(|| a.clone())
                });
                prov.cmdline = args;
            }
        }
        if prov.name.is_none() {
            if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                prov.name = Some(comm.trim().to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProcessAclConfig;

    fn prov_with(name: &str, exe: &str, cmdline: &[&str], pid: Option<u32>) -> Provenance {
        Provenance {
            pid,
            exe: Some(exe.into()),
            cmdline: cmdline.iter().map(|s| s.to_string()).collect(),
            name: Some(name.into()),
            peer: "127.0.0.1:54321".into(),
        }
    }

    #[test]
    fn disabled_acl_always_allows() {
        let acl = ProcessAclConfig { enabled: false, default: "deny".into(), ..Default::default() };
        let p = prov_with("python3", "/usr/bin/python3", &["python3", "x.py"], Some(7));
        assert_eq!(acl.evaluate(&p, None), AclDecision::Allow);
    }

    #[test]
    fn allowlist_default_deny_blocks_unlisted() {
        let acl = ProcessAclConfig {
            enabled: true,
            default: "deny".into(),
            allow: vec!["ollama".into(), "claude-code".into()],
            ..Default::default()
        };
        // Listed by attributed agent name → allowed.
        let p = prov_with("node", "/usr/bin/node", &["node", "cli.js"], Some(7));
        assert_eq!(acl.evaluate(&p, Some("claude-code")), AclDecision::Allow);
        // Not listed → denied by default.
        let p2 = prov_with("python3", "/usr/bin/python3", &["python3", "exfil.py"], Some(8));
        assert!(matches!(acl.evaluate(&p2, None), AclDecision::Deny(_)));
    }

    #[test]
    fn denylist_default_allow_blocks_listed() {
        let acl = ProcessAclConfig {
            enabled: true,
            default: "allow".into(),
            deny: vec!["exfil".into()],
            ..Default::default()
        };
        let p = prov_with("python3", "/usr/bin/python3", &["python3", "exfil.py"], Some(8));
        assert!(matches!(acl.evaluate(&p, None), AclDecision::Deny(_)));
        let ok = prov_with("ollama", "/usr/local/bin/ollama", &["ollama", "run"], Some(9));
        assert_eq!(acl.evaluate(&ok, None), AclDecision::Allow);
    }

    #[test]
    fn deny_wins_over_allow() {
        let acl = ProcessAclConfig {
            enabled: true,
            default: "deny".into(),
            allow: vec!["python".into()],
            deny: vec!["exfil".into()],
            ..Default::default()
        };
        let p = prov_with("python3", "/usr/bin/python3", &["python3", "exfil.py"], Some(8));
        assert!(matches!(acl.evaluate(&p, None), AclDecision::Deny(_)));
    }

    #[test]
    fn block_unresolved_gates_pidless_callers() {
        let base = ProcessAclConfig { enabled: true, default: "allow".into(), ..Default::default() };
        let unresolved = Provenance { peer: "127.0.0.1:5555".into(), ..Default::default() };
        // default allow, not blocking unresolved → allowed
        assert_eq!(base.evaluate(&unresolved, None), AclDecision::Allow);
        // ...but block_unresolved flips it to deny
        let strict = ProcessAclConfig { block_unresolved: true, ..base };
        assert!(matches!(strict.evaluate(&unresolved, None), AclDecision::Deny(_)));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let acl = ProcessAclConfig {
            enabled: true,
            default: "deny".into(),
            allow: vec!["Ollama".into()],
            ..Default::default()
        };
        let p = prov_with("ollama", "/usr/local/bin/ollama", &["ollama"], Some(3));
        assert_eq!(acl.evaluate(&p, None), AclDecision::Allow);
    }
}
