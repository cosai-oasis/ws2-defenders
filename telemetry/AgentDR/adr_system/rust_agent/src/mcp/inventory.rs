//! Enumerate MCP server configurations across known AI runtimes.
//!
//! Every server declared in any of the following places becomes an
//! ai_operation=mcp_operation (API Activity 6003) event with `activity_id = 2 (Read)`, so SIEM rules
//! can baseline "which MCP servers are present on which endpoints."
//!
//! Scanned locations:
//!  * `~/.cursor/mcp.json`                       — Cursor (user level)
//!  * `<repo>/.cursor/mcp.json`                  — Cursor (project level, current dir)
//!  * `~/.codeium/windsurf/mcp_config.json`      — Windsurf
//!  * `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
//!  * `$APPDATA/Claude/claude_desktop_config.json` (Windows)
//!  * `~/.config/Claude/claude_desktop_config.json` (Linux)
//!  * `~/.claude/mcp.json`                       — Claude Code
//!  * `~/.continue/config.json` (`mcpServers`)   — Continue.dev
//!  * `<cwd>/.vscode/mcp.json`                   — VS Code project MCP
//!  * `$XDG_CONFIG_HOME/agentdr/mcp.json`        — operator-supplied extras

use crate::models::*;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct InventoryReport {
    pub scanned_paths: Vec<String>,
    pub servers: Vec<DiscoveredServer>,
    pub events: Vec<EventRecord>,
}

#[derive(Debug, Serialize, Clone)]
pub struct DiscoveredServer {
    pub runtime: String,
    pub source_path: String,
    pub name: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub transport: String,
    pub env_keys: Vec<String>,
}

pub fn scan() -> InventoryReport {
    let mut report = InventoryReport {
        scanned_paths: Vec::new(),
        servers: Vec::new(),
        events: Vec::new(),
    };

    for (runtime, path) in candidate_paths() {
        report.scanned_paths.push(path.display().to_string());
        if !path.exists() {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&path) else { continue };
        let Ok(value): Result<Value, _> = serde_json::from_str(&body) else { continue };

        // Different runtimes spell the MCP block differently:
        //   Cursor / Claude / Windsurf / Continue / VS Code  → `mcpServers`
        //   OpenCode                                          → `mcp`
        let servers_map = value.get("mcpServers")
            .or_else(|| value.get("mcp"))
            .and_then(|v| v.as_object())
            .cloned();
        if let Some(map) = servers_map {
            for (name, def) in map {
                let server = parse_server(&runtime, &path, &name, &def);
                let ev = to_event(&server);
                report.servers.push(server);
                report.events.push(ev);
            }
        }
    }

    report
}

fn candidate_paths() -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    if let Some(h) = dirs::home_dir() {
        out.push(("cursor".into(),         h.join(".cursor").join("mcp.json")));
        out.push(("claude-code".into(),    h.join(".claude").join("mcp.json")));
        out.push(("windsurf".into(),       h.join(".codeium").join("windsurf").join("mcp_config.json")));
        out.push(("continue".into(),       h.join(".continue").join("config.json")));
        out.push(("opencode".into(),       h.join(".config").join("opencode").join("opencode.json")));

        // Claude Desktop varies by OS
        #[cfg(target_os = "macos")]
        out.push(("claude-desktop".into(), h.join("Library").join("Application Support").join("Claude").join("claude_desktop_config.json")));
        #[cfg(target_os = "linux")]
        out.push(("claude-desktop".into(), h.join(".config").join("Claude").join("claude_desktop_config.json")));
    }
    #[cfg(target_os = "windows")]
    if let Ok(appdata) = std::env::var("APPDATA") {
        out.push(("claude-desktop".into(), PathBuf::from(appdata).join("Claude").join("claude_desktop_config.json")));
    }

    // Project-level configs in current working directory
    if let Ok(cwd) = std::env::current_dir() {
        out.push(("cursor-project".into(),   cwd.join(".cursor").join("mcp.json")));
        out.push(("vscode-project".into(),   cwd.join(".vscode").join("mcp.json")));
        out.push(("opencode-project".into(), cwd.join("opencode.json")));
    }

    // Operator-supplied extra config
    if let Some(cfg) = dirs::config_dir() {
        out.push(("agentdr".into(), cfg.join("agentdr").join("mcp.json")));
    }
    out
}

fn parse_server(runtime: &str, path: &Path, name: &str, def: &Value) -> DiscoveredServer {
    // `command` can be either a string (Cursor / Claude Desktop / Continue)
    // or a string array (OpenCode: `["adr-agent", "mcp", "wrap", ...]`).
    // Normalise to (head_command, args[]) so both layouts produce the same
    // event shape.
    let (command, args): (Option<String>, Vec<String>) = match def.get("command") {
        Some(Value::String(s)) => {
            let args = def.get("args").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            (Some(s.clone()), args)
        }
        Some(Value::Array(arr)) => {
            let mut iter = arr.iter().filter_map(|x| x.as_str().map(String::from));
            let head = iter.next();
            let rest: Vec<String> = iter.collect();
            (head, rest)
        }
        _ => (None, Vec::new()),
    };

    let url = def.get("url").and_then(|v| v.as_str()).map(String::from);
    let transport = if let Some(t) = def.get("type").and_then(|v| v.as_str()) {
        // OpenCode uses `type: "local"` or `type: "remote"`.
        match t {
            "local"  => "stdio".to_string(),
            "remote" => def.get("transport").and_then(|v| v.as_str()).unwrap_or("http").to_string(),
            other    => other.to_string(),
        }
    } else if url.is_some() {
        def.get("transport").and_then(|v| v.as_str()).unwrap_or("http").to_string()
    } else {
        "stdio".to_string()
    };
    // OpenCode spells the env block `environment`; everyone else uses `env`.
    let env_keys: Vec<String> = def
        .get("env")
        .or_else(|| def.get("environment"))
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    DiscoveredServer {
        runtime: runtime.into(),
        source_path: path.display().to_string(),
        name: name.into(),
        command,
        args,
        url,
        transport,
        env_keys,
    }
}

fn to_event(s: &DiscoveredServer) -> EventRecord {
    let mut details: BTreeMap<String, Value> = BTreeMap::new();
    details.insert("runtime".into(), Value::String(s.runtime.clone()));
    details.insert("source_path".into(), Value::String(s.source_path.clone()));
    details.insert("name".into(), Value::String(s.name.clone()));
    if let Some(c) = &s.command { details.insert("command".into(), Value::String(c.clone())); }
    details.insert("args".into(), json!(s.args));
    if let Some(u) = &s.url { details.insert("url".into(), Value::String(u.clone())); }
    details.insert("transport".into(), Value::String(s.transport.clone()));
    details.insert("env_keys".into(), json!(s.env_keys));

    let mut ev = EventRecord::new(
        "mcp_server_inventory",
        Value::Object(details.into_iter().collect()),
        "low",
    );
    ev.set_op(AiOperation::McpOperation, ACTIVITY_READ);
    ev.activity_id = Some(ACTIVITY_READ);
    ev.status_id = Some(STATUS_SUCCESS);
    ev.mcp_server = Some(s.name.clone());
    ev.source = Some("mcp_inventory".into());
    ev.message = Some(format!(
        "MCP server '{}' declared in {} (runtime={}, transport={})",
        s.name, s.source_path, s.runtime, s.transport
    ));
    ev
}
