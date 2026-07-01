//! Tier 6 — OS-native kernel telemetry.
//!
//! Linux: subscribes to the kernel audit netlink (`NETLINK_AUDIT`)
//!        multicast group and emits AGENT_ACTION events for syscall /
//!        path records. Requires the agent process to have
//!        `CAP_AUDIT_READ` (granted by the systemd unit's capability
//!        bracket) or to run as root. When unavailable, falls back to
//!        a periodic /proc/<pid>/io scan for the agent process tree.
//!
//! macOS: EndpointSecurity requires a com.apple.developer.endpoint-security.client
//!        entitlement and an Apple Developer ID. The agent emits a
//!        single startup event explaining the requirement; operators
//!        deploy the EndpointSecurity extension via MDM as a sidecar
//!        and stream its `es_event_*` JSON into AgentDR's file
//!        monitor. See packaging/macos/.
//!
//! Windows: ETW (Event Tracing for Windows) requires Administrator
//!        privileges and an EventConsumer registration. The agent
//!        emits a single startup event recommending operators enable
//!        the Microsoft-Windows-Kernel-Process and -Audit-General
//!        providers via `wevtutil` and forward to AgentDR through the
//!        syslog exporter.

use crate::models::*;
use serde_json::json;
use tokio::sync::mpsc;
use tracing::{debug, info};

pub struct KernelMonitor {
    audit_group: u32,
    tx: mpsc::UnboundedSender<EventRecord>,
}

impl KernelMonitor {
    pub fn new(audit_group: u32, tx: mpsc::UnboundedSender<EventRecord>) -> Self {
        Self { audit_group, tx }
    }

    pub async fn run(self, shutdown: tokio::sync::watch::Receiver<bool>) {
        // Emit a single startup banner so the dashboard can show "kernel
        // telemetry attached" status.
        let mut ev = EventRecord::new("kernel_monitor_start", json!({
            "platform": std::env::consts::OS,
            "audit_group": self.audit_group,
        }), "low");
        ev.set_op(AiOperation::AgentAction, ACTIVITY_CREATE);
        ev.activity_id = Some(ACTIVITY_CREATE);
        ev.status_id = Some(STATUS_SUCCESS);
        ev.source = Some("kernel_monitor".into());
        ev.message = Some(format!("kernel monitor attached on {}", std::env::consts::OS));
        let _ = self.tx.send(ev);

        #[cfg(target_os = "linux")]
        linux::run(self.audit_group, self.tx, shutdown).await;

        #[cfg(target_os = "macos")]
        macos::run(self.tx, shutdown).await;

        #[cfg(target_os = "windows")]
        windows::run(self.tx, shutdown).await;
    }
}

// ── Linux: NETLINK_AUDIT multicast subscriber ─────────────────────────────
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use tokio::io::unix::AsyncFd;

    const NETLINK_AUDIT: i32 = 9;
    const AUDIT_NLGRP_READLOG: u32 = 1;

    pub async fn run(_audit_group: u32, tx: mpsc::UnboundedSender<EventRecord>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        // Open NETLINK_AUDIT socket.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_AUDIT) };
        if fd < 0 {
            emit_warning(&tx, "netlink audit socket: cannot open (need CAP_AUDIT_READ or root). Falling back to /proc scan.");
            proc_fallback(tx, shutdown).await;
            return;
        }
        // Bind to the readlog multicast group.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = AUDIT_NLGRP_READLOG;
        let bind_rc = unsafe {
            libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32)
        };
        if bind_rc < 0 {
            unsafe { libc::close(fd) };
            emit_warning(&tx, "netlink audit bind failed; falling back to /proc scan.");
            proc_fallback(tx, shutdown).await;
            return;
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let async_fd = match AsyncFd::new(owned) {
            Ok(f) => f,
            Err(e) => {
                emit_warning(&tx, &format!("netlink audit AsyncFd: {e}"));
                return;
            }
        };
        info!("kernel: subscribed to NETLINK_AUDIT multicast");

        let mut buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                guard = async_fd.readable() => {
                    let mut g = match guard { Ok(g) => g, Err(_) => continue };
                    let raw_fd = g.get_ref().as_raw_fd();
                    let n = unsafe { libc::recv(raw_fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
                    if n <= 0 {
                        g.clear_ready();
                        continue;
                    }
                    let payload = &buf[..n as usize];
                    parse_audit_payload(payload, &tx);
                    g.clear_ready();
                }
                _ = shutdown.changed() => break,
            }
        }
    }

    fn parse_audit_payload(buf: &[u8], tx: &mpsc::UnboundedSender<EventRecord>) {
        // Netlink frames: 16-byte nlmsghdr (length, type, flags, seq, pid)
        // followed by an audit-style ASCII record:
        //   "audit(1715800000.123:42): syscall=257 ... comm=\"bash\" ..."
        // We only emit a coarse-grained event, leaving deep parsing to
        // operators who want full audisp coverage.
        let mut cursor = 0;
        while cursor + 16 <= buf.len() {
            let len = u32::from_ne_bytes(buf[cursor..cursor+4].try_into().unwrap_or([0;4])) as usize;
            if len < 16 || cursor + len > buf.len() { break; }
            let msg_type = u16::from_ne_bytes(buf[cursor+4..cursor+6].try_into().unwrap_or([0;2]));
            let body = &buf[cursor+16..cursor+len];
            let text = String::from_utf8_lossy(body);
            let trimmed = text.trim_end_matches('\u{0}').trim();
            if !trimmed.is_empty() {
                let mut ev = EventRecord::new("kernel_audit", json!({
                    "msg_type": msg_type,
                    "record":   trimmed,
                }), "low");
                ev.set_op(AiOperation::AgentAction, ACTIVITY_DETECT);
                ev.activity_id = Some(ACTIVITY_DETECT);
                ev.status_id = Some(STATUS_SUCCESS);
                ev.source = Some("kernel_audit".into());
                let _ = tx.send(ev);
            }
            cursor += (len + 3) & !3; // NLMSG_ALIGN
        }
    }

    async fn proc_fallback(tx: mpsc::UnboundedSender<EventRecord>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Ok(rd) = std::fs::read_dir("/proc") {
                        let mut total = 0u64;
                        let mut seen = 0u32;
                        for entry in rd.flatten() {
                            let n = entry.file_name();
                            if let Some(s) = n.to_str() {
                                if s.chars().all(|c| c.is_ascii_digit()) {
                                    seen += 1;
                                    let p = entry.path().join("io");
                                    if let Ok(txt) = std::fs::read_to_string(&p) {
                                        for line in txt.lines() {
                                            if let Some((k, v)) = line.split_once(": ") {
                                                if k == "read_bytes" || k == "write_bytes" {
                                                    if let Ok(n) = v.parse::<u64>() { total += n; }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        let mut ev = EventRecord::new("kernel_proc_scan", json!({
                            "processes": seen, "io_bytes_total": total,
                        }), "low");
                        ev.set_op(AiOperation::AgentAction, ACTIVITY_DETECT);
                        ev.activity_id = Some(ACTIVITY_DETECT);
                        ev.source = Some("kernel_proc_scan".into());
                        let _ = tx.send(ev);
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    pub async fn run(tx: mpsc::UnboundedSender<EventRecord>, _shutdown: tokio::sync::watch::Receiver<bool>) {
        emit_warning(&tx, "macOS EndpointSecurity requires a signed entitled sidecar. \
            Deploy the AgentDR-ES sidecar via MDM and forward its events to the file monitor.");
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    pub async fn run(tx: mpsc::UnboundedSender<EventRecord>, _shutdown: tokio::sync::watch::Receiver<bool>) {
        emit_warning(&tx, "Windows ETW requires Administrator. Enable the \
            Microsoft-Windows-Kernel-Process and Microsoft-Windows-Audit providers \
            with wevtutil and forward to AgentDR via the syslog exporter.");
    }
}

#[allow(dead_code)]
fn emit_warning(tx: &mpsc::UnboundedSender<EventRecord>, msg: &str) {
    let mut ev = EventRecord::new("kernel_monitor_warning", json!({"message": msg}), "low");
    ev.set_op(AiOperation::AgentAction, ACTIVITY_DETECT);
    ev.activity_id = Some(ACTIVITY_DETECT);
    ev.source = Some("kernel_monitor".into());
    ev.message = Some(msg.into());
    let _ = tx.send(ev);
    debug!("kernel monitor warning: {}", msg);
}
