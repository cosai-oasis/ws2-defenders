//! Discovery scanner.
//!
//! Walks every "evidence source" we know about — $PATH, well-known
//! install locations, package-manager footprints, presence of a hook
//! config, MCP entries, recently-running processes — and folds the
//! results into one `DiscoveredAgent` per supported runtime.

use crate::hooks;
use crate::mcp;
use crate::models::identify_agent;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use sysinfo::System;

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub scanned_at: String,
    pub agents: Vec<DiscoveredAgent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredAgent {
    pub id: String,                // claude-code, cursor, codex, aider, opencode
    pub name: String,              // Claude Code
    pub category: String,          // coding | general | workflow | enterprise | browser
    pub confidence: f32,           // 0.0..1.0, sum of weighted evidence
    pub evidence: Vec<Evidence>,
    /// True if AgentDR's runtime hook is already installed for this agent.
    pub already_monitored: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    BinaryOnPath          { path: String },
    KnownInstallLocation  { path: String, hint: String },
    HookConfigPresent     { path: String, marker_present: bool },
    McpEntries            { path: String, server_count: usize },
    ProcessRunning        { pid: u32 },
}

/// Run a full scan now.
pub fn scan() -> ScanReport {
    let mut by_id: BTreeMap<String, DiscoveredAgent> = BTreeMap::new();

    // Seed entries for every supported coding runtime so even agents
    // that aren't installed appear in the report (status: no evidence).
    for (id, name, category) in supported() {
        by_id.insert(id.into(), DiscoveredAgent {
            id: id.into(), name: name.into(), category: category.into(),
            confidence: 0.0, evidence: Vec::new(), already_monitored: false,
        });
    }

    // 1. $PATH binaries
    for (id, _name, _cat) in supported() {
        if let Some(p) = which_on_path(id) {
            if let Some(a) = by_id.get_mut(id) {
                a.evidence.push(Evidence::BinaryOnPath { path: p });
                a.confidence += 0.40;
            }
        }
    }

    // 2. Well-known install locations
    for (id, location, hint) in known_install_locations() {
        if PathBuf::from(&location).exists() {
            if let Some(a) = by_id.get_mut(id) {
                a.evidence.push(Evidence::KnownInstallLocation {
                    path: location.into(), hint: hint.into(),
                });
                a.confidence += 0.25;
            }
        }
    }

    // 3. Hook config presence (also tells us if we already manage it)
    let hs = hooks::status();
    let pairs: [(&'static str, &hooks::common::HookState); 5] = [
        ("claude-code", &hs.claude_code),
        ("cursor",      &hs.cursor),
        ("codex",       &hs.codex),
        ("aider",       &hs.aider),
        ("opencode",    &hs.opencode),
    ];
    for (id, st) in pairs {
        if let Some(p) = &st.config_path {
            if PathBuf::from(p).exists() {
                if let Some(a) = by_id.get_mut(id) {
                    a.evidence.push(Evidence::HookConfigPresent {
                        path: p.clone(),
                        marker_present: st.installed,
                    });
                    a.confidence += if st.installed { 0.50 } else { 0.25 };
                    if st.installed {
                        a.already_monitored = true;
                    }
                }
            }
        }
    }

    // 4. MCP server entries pointing at this runtime
    let mcp_inv = mcp::inventory::scan();
    let mut per_runtime: BTreeMap<&str, (String, usize)> = BTreeMap::new();
    for s in &mcp_inv.servers {
        let id = match s.runtime.as_str() {
            "cursor" | "cursor-project"        => "cursor",
            "claude-code"                       => "claude-code",
            "claude-desktop"                    => "claude-code",
            "opencode" | "opencode-project"     => "opencode",
            _                                   => continue,
        };
        let e = per_runtime.entry(id).or_insert((s.source_path.clone(), 0));
        e.1 += 1;
    }
    for (id, (path, count)) in per_runtime {
        if let Some(a) = by_id.get_mut(id) {
            a.evidence.push(Evidence::McpEntries { path, server_count: count });
            a.confidence += 0.15;
        }
    }

    // 5. Currently-running processes
    let mut sys = System::new_all();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    for (pid, proc) in sys.processes() {
        let name = proc.name().to_string_lossy().to_string();
        let exe = proc.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
        let cmd: Vec<String> = proc.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect();
        let hay = format!("{} {} {}", name, exe, cmd.join(" "));
        if let Some(sig) = identify_agent(&hay) {
            let id = signature_to_id(&sig.name);
            if let Some(a) = by_id.get_mut(id) {
                a.evidence.push(Evidence::ProcessRunning { pid: pid.as_u32() });
                a.confidence += 0.30;
            }
        }
    }

    // Filter: drop agents with no evidence
    let agents: Vec<DiscoveredAgent> = by_id
        .into_values()
        .filter(|a| !a.evidence.is_empty())
        .map(|mut a| { if a.confidence > 1.0 { a.confidence = 1.0; } a })
        .collect();

    ScanReport {
        scanned_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        agents,
    }
}

/// Render a discovered list as a human-readable table.
pub fn render_table(rep: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("AgentDR discovery scan @ {}\n\n", rep.scanned_at));
    if rep.agents.is_empty() {
        out.push_str("(no supported AI agents found on this host)\n");
        return out;
    }
    out.push_str("AGENT          CATEGORY  CONFIDENCE  MANAGED  EVIDENCE\n");
    out.push_str("─────────────  ────────  ──────────  ───────  ─────────────────────────────────────\n");
    for a in &rep.agents {
        let managed = if a.already_monitored { "yes" } else { "no" };
        let ev = a.evidence.iter().map(evidence_short).collect::<Vec<_>>().join(", ");
        out.push_str(&format!(
            "{:<13}  {:<8}  {:>10.0}%  {:<7}  {}\n",
            truncate(&a.name, 13),
            truncate(&a.category, 8),
            a.confidence * 100.0,
            managed,
            truncate(&ev, 60),
        ));
    }
    out
}

fn evidence_short(e: &Evidence) -> String {
    match e {
        Evidence::BinaryOnPath { .. }            => "binary".into(),
        Evidence::KnownInstallLocation { hint, .. } => format!("install({})", hint),
        Evidence::HookConfigPresent { marker_present: true, .. } => "hook-managed".into(),
        Evidence::HookConfigPresent { .. }       => "hook-config".into(),
        Evidence::McpEntries { server_count, .. } => format!("mcp×{}", server_count),
        Evidence::ProcessRunning { pid }         => format!("pid={pid}"),
    }
}

fn truncate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max { s.to_string() }
    else {
        let mut t: String = chars.iter().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Supported coding-agent runtimes we know how to hook.
pub fn supported() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("claude-code", "Claude Code", "coding"),
        ("cursor",      "Cursor",      "coding"),
        ("codex",       "Codex CLI",   "coding"),
        ("aider",       "Aider",       "coding"),
        ("opencode",    "OpenCode",    "coding"),
    ]
}

fn signature_to_id(name: &str) -> &'static str {
    match name {
        "Claude Code" => "claude-code",
        "Cursor"      => "cursor",
        "Codex CLI"   => "codex",
        "Aider"       => "aider",
        "OpenCode"    => "opencode",
        _              => "",
    }
}

/// (agent id, absolute path that exists if this agent is installed, short hint).
fn known_install_locations() -> Vec<(&'static str, String, &'static str)> {
    let mut out = Vec::new();
    if let Some(h) = dirs::home_dir() {
        // macOS: applications
        out.push(("cursor", "/Applications/Cursor.app".into(), "macos-app"));
        out.push(("cursor", h.join("Applications/Cursor.app").display().to_string(), "user-app"));
        // Common npm-global / pipx / pip / cargo install paths
        out.push(("aider", h.join(".local/bin/aider").display().to_string(), "pipx"));
        out.push(("opencode", h.join(".local/bin/opencode").display().to_string(), "user-bin"));
        out.push(("codex", h.join(".local/bin/codex").display().to_string(), "user-bin"));
        out.push(("claude-code", h.join(".npm-global/bin/claude").display().to_string(), "npm-global"));
        // Linux distro-managed
        out.push(("cursor", "/opt/cursor".into(), "linux-opt"));
        out.push(("cursor", "/usr/share/cursor".into(), "linux-distro"));
        // Hook config presence on disk even when the binary moves around
        out.push(("opencode", h.join(".config/opencode").display().to_string(), "config-dir"));
    }
    // Windows
    #[cfg(target_os = "windows")]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            out.push(("cursor", format!("{local}\\Programs\\cursor"), "windows-localappdata"));
        }
        if let Ok(progfiles) = std::env::var("ProgramFiles") {
            out.push(("cursor", format!("{progfiles}\\Cursor"), "program-files"));
        }
    }
    out
}

fn which_on_path(name: &str) -> Option<String> {
    let bin = match name {
        "claude-code" => "claude",
        other          => other,
    };
    let exts: &[&str] = if cfg!(windows) { &[".exe", ".cmd", ".bat", ""] } else { &[""] };
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{bin}{ext}"));
            if candidate.is_file() { return Some(candidate.display().to_string()); }
        }
    }
    None
}
