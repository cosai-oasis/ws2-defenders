//! Cursor hook installer.
//!
//! Cursor does not currently expose a generic OTLP env-var path, but it does
//! consume a per-user MCP config at `~/.cursor/mcp.json`. AgentDR ships an
//! MCP-recorder server (via `adr-agent mcp wrap`) that other MCP servers can
//! sit behind. The installer:
//!   1. Adds an `agentdr-recorder` entry to `~/.cursor/mcp.json` that wraps
//!      a no-op echo command — its only job is to make agent activity
//!      against Cursor's MCP stack visible to MCP traffic capture.
//!   2. Writes `~/.cursor/User/agentdr-settings.json` with OTel-compatible
//!      environment variables that Cursor passes to spawned MCP servers
//!      (this matches Cursor's documented `env` field on MCP entries).

use super::common::*;
use serde_json::{json, Value};
use std::path::PathBuf;

fn mcp_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".cursor").join("mcp.json"))
}

fn settings_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".cursor").join("User").join("agentdr-settings.json"))
}

pub fn install(endpoint: &str) -> Result<(), String> {
    // 1) ~/.cursor/mcp.json
    let path = mcp_path()?;
    let mut root = read_json(&path)?;
    ensure_object(&mut root);
    let obj = root.as_object_mut().unwrap();

    let mut servers = match obj.remove("mcpServers") {
        Some(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    // The recorder uses a shell command that pipes through `adr-agent mcp wrap`
    // around a no-op server. When a real MCP server is configured, operators
    // wrap that one instead — see docs/.
    servers.insert(
        "agentdr-recorder".into(),
        json!({
            "command": "adr-agent",
            "args": ["mcp", "wrap", "--name", "cursor-noop", "--", "cat"],
            "env": otel_env(endpoint, "cursor")
        }),
    );
    obj.insert("mcpServers".into(), Value::Object(servers));

    let mut marker = serde_json::Map::new();
    marker.insert("endpoint".into(), Value::String(endpoint.into()));
    marker.insert("description".into(), Value::String(MARKER_VALUE.into()));
    obj.insert(MARKER_KEY.into(), Value::Object(marker));
    write_json(&path, &root)?;
    println!("✓ cursor: wrote {}", path.display());

    // 2) ~/.cursor/User/agentdr-settings.json (env propagation reference for operators)
    let s_path = settings_path()?;
    let body = json!({
        MARKER_KEY: MARKER_VALUE,
        "endpoint": endpoint,
        "note": "Cursor reads MCP env from mcp.json. This file is informational.",
        "env": otel_env(endpoint, "cursor"),
    });
    write_json(&s_path, &body)?;
    println!("✓ cursor: wrote {}", s_path.display());
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let path = mcp_path()?;
    let mut root = read_json(&path)?;
    if let Some(obj) = root.as_object_mut() {
        if let Some(Value::Object(servers)) = obj.get_mut("mcpServers") {
            servers.remove("agentdr-recorder");
        }
        obj.remove(MARKER_KEY);
    }
    write_json(&path, &root)?;
    println!("✓ cursor: removed AgentDR entries from {}", path.display());

    let s_path = settings_path()?;
    let _ = std::fs::remove_file(&s_path);
    println!("✓ cursor: removed {}", s_path.display());
    Ok(())
}

pub fn status() -> HookState {
    let path = match mcp_path() {
        Ok(p) => p,
        Err(e) => return HookState::absent(&e),
    };
    match read_json(&path) {
        Ok(Value::Object(obj)) => {
            let installed = obj
                .get("mcpServers")
                .and_then(|v| v.as_object())
                .map(|m| m.contains_key("agentdr-recorder"))
                .unwrap_or(false);
            let endpoint = obj
                .get(MARKER_KEY)
                .and_then(|v| v.get("endpoint"))
                .and_then(|v| v.as_str())
                .map(String::from);
            HookState {
                installed,
                config_path: Some(path.display().to_string()),
                endpoint,
                notes: Some(if installed { "managed".into() } else { "no agentdr-recorder entry".into() }),
            }
        }
        _ => HookState {
            installed: false,
            config_path: Some(path.display().to_string()),
            endpoint: None,
            notes: Some("no ~/.cursor/mcp.json".into()),
        },
    }
}
