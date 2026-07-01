//! Tier 7 — multi-tool agent inventory.
//!
//! Many developers run several AI coding agents on one machine (Claude
//! Code in one terminal, Cursor in the editor, OpenCode for a quick
//! session, Aider in a CI runner). AgentDR's pipeline supports this
//! natively — every monitor is multi-subject by design, every event
//! carries `agent_name`, and the UEBA baselines are keyed by
//! `(host, user, agent)` so each runtime gets its own profile. This
//! module surfaces that state as a single CLI command:
//!
//!     adr-agent agents list           # human-readable table
//!     adr-agent agents list --json    # machine-readable
//!
//! For every supported coding agent we report:
//!   - whether its binary is on $PATH (and where)
//!   - whether AgentDR's runtime hook is installed
//!   - which MCP servers it has configured
//!   - which PIDs (if any) are running right now

use crate::hooks;
use crate::mcp;
use crate::models::identify_agent;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use sysinfo::System;

#[derive(Debug, Serialize)]
pub struct AgentInventory {
    pub agents: Vec<AgentStatus>,
}

#[derive(Debug, Serialize)]
pub struct AgentStatus {
    pub id:                   String,
    pub name:                 String,
    pub binary_on_path:       Option<String>,
    pub hooks_installed:      bool,
    pub hook_endpoint:        Option<String>,
    pub mcp_servers:          Vec<String>,
    pub running_pids:         Vec<u32>,
}

/// Build the multi-tool inventory.
pub fn list() -> AgentInventory {
    let hook_st = hooks::status();
    let mcp_inv = mcp::inventory::scan();

    // Snapshot the process table once.
    let mut sys = System::new_all();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut running_by_signature: HashMap<String, Vec<u32>> = HashMap::new();
    for (pid, proc) in sys.processes() {
        let name = proc.name().to_string_lossy().to_string();
        let exe = proc.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
        let cmd: Vec<String> = proc.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect();
        let hay = format!("{} {} {}", name, exe, cmd.join(" "));
        if let Some(sig) = identify_agent(&hay) {
            running_by_signature.entry(sig.name).or_default().push(pid.as_u32());
        }
    }

    // Mapping: (id, display name, hook state, binary candidate, mcp runtime key)
    let entries: Vec<(&str, &str, &hooks::common::HookState, &str, &str)> = vec![
        ("claude-code", "Claude Code", &hook_st.claude_code, "claude",   "claude-code"),
        ("cursor",      "Cursor",      &hook_st.cursor,      "cursor",   "cursor"),
        ("codex",       "Codex CLI",   &hook_st.codex,       "codex",    "codex"),
        ("aider",       "Aider",       &hook_st.aider,       "aider",    "aider"),
        ("opencode",    "OpenCode",    &hook_st.opencode,    "opencode", "opencode"),
    ];

    let mut agents = Vec::with_capacity(entries.len());
    for (id, display, hs, binary, mcp_runtime) in entries {
        let mcp_servers: Vec<String> = mcp_inv
            .servers
            .iter()
            .filter(|s| s.runtime == mcp_runtime
                       || s.runtime == format!("{}-project", mcp_runtime))
            .map(|s| s.name.clone())
            .collect();
        agents.push(AgentStatus {
            id: id.into(),
            name: display.into(),
            binary_on_path: which_on_path(binary),
            hooks_installed: hs.installed,
            hook_endpoint: hs.endpoint.clone(),
            mcp_servers,
            running_pids: running_by_signature.get(display).cloned().unwrap_or_default(),
        });
    }
    AgentInventory { agents }
}

/// Render an `AgentInventory` as a fixed-width table for terminals.
pub fn render_table(inv: &AgentInventory) -> String {
    let mut out = String::new();
    out.push_str("AGENT          BINARY ON PATH                       HOOKS    MCP SERVERS                 RUNNING\n");
    out.push_str("─────────────  ───────────────────────────────────  ───────  ──────────────────────────  ────────\n");
    for a in &inv.agents {
        let bin = a.binary_on_path.clone().unwrap_or_else(|| "—".into());
        let bin = truncate(&bin, 35);
        let hooks = if a.hooks_installed { "yes" } else { "no" };
        let mcp = if a.mcp_servers.is_empty() {
            "—".to_string()
        } else {
            truncate(&a.mcp_servers.join(", "), 26)
        };
        let running = if a.running_pids.is_empty() {
            "—".to_string()
        } else {
            format!("{} pid{}", a.running_pids.len(), if a.running_pids.len() == 1 { "" } else { "s" })
        };
        out.push_str(&format!(
            "{:<13}  {:<35}  {:<7}  {:<26}  {:<8}\n",
            truncate(&a.name, 13), bin, hooks, mcp, running,
        ));
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.into() }
    else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

fn which_on_path(name: &str) -> Option<String> {
    let exts: &[&str] = if cfg!(windows) { &[".exe", ".cmd", ".bat", ""] } else { &[""] };
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() { return Some(candidate.display().to_string()); }
        }
    }
    None
}
