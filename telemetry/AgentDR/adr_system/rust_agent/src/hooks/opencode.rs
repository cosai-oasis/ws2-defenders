//! OpenCode hook installer.
//!
//! OpenCode (opencode.ai) is a Go/TypeScript-based terminal coding agent
//! that reads JSON config from `~/.config/opencode/opencode.json` (with
//! a project-level override at `<cwd>/opencode.json`). The config supports
//! an `mcp` block — same role as Cursor's `mcpServers` — so AgentDR drops
//! a recorder entry there and additionally provides a shell wrapper that
//! exports the AgentDR OTLP env vars for any OTel-aware child SDK
//! OpenCode may invoke.
//!
//! Discovery: <https://opencode.ai/docs/config/>

use super::common::*;
use serde_json::{json, Value};
use std::path::PathBuf;

fn config_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".config").join("opencode").join("opencode.json"))
}

fn wrapper_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".local").join("bin").join("opencode-agentdr"))
}

fn marker_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".config").join("opencode").join(".agentdr.json"))
}

pub fn install(endpoint: &str) -> Result<(), String> {
    // 1) ~/.config/opencode/opencode.json — add an MCP recorder entry
    let path = config_path()?;
    let mut root = read_json(&path)?;
    ensure_object(&mut root);
    let obj = root.as_object_mut().unwrap();

    // OpenCode uses `mcp` (singular) instead of Cursor's `mcpServers`.
    let mut mcp_map = match obj.remove("mcp") {
        Some(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    mcp_map.insert(
        "agentdr-recorder".into(),
        json!({
            "type": "local",
            "command": ["adr-agent", "mcp", "wrap", "--name", "opencode-noop", "--", "cat"],
            "enabled": true,
            "environment": otel_env(endpoint, "opencode")
        }),
    );
    obj.insert("mcp".into(), Value::Object(mcp_map));

    let mut marker = serde_json::Map::new();
    marker.insert("endpoint".into(), Value::String(endpoint.into()));
    marker.insert("description".into(), Value::String(MARKER_VALUE.into()));
    obj.insert(MARKER_KEY.into(), Value::Object(marker));
    write_json(&path, &root)?;
    println!("✓ opencode: wrote {}", path.display());

    // 2) ~/.local/bin/opencode-agentdr — env-exporting wrapper script
    let wp = wrapper_path()?;
    if let Some(parent) = wp.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let script = format!(
        "#!/usr/bin/env sh\n\
         # AgentDR managed wrapper for opencode.\n\
         export OTEL_EXPORTER_OTLP_ENDPOINT={ep}\n\
         export OTEL_EXPORTER_OTLP_PROTOCOL=http/json\n\
         export OTEL_SERVICE_NAME=opencode\n\
         export OTEL_TRACES_EXPORTER=otlp\n\
         export OTEL_LOGS_EXPORTER=otlp\n\
         export OTEL_METRICS_EXPORTER=otlp\n\
         exec opencode \"$@\"\n",
        ep = endpoint
    );
    std::fs::write(&wp, script).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&wp) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&wp, perms);
        }
    }
    println!("✓ opencode: wrote {} (use this in place of `opencode`)", wp.display());

    // Sentinel
    let body = json!({ MARKER_KEY: MARKER_VALUE, "endpoint": endpoint });
    write_json(&marker_path()?, &body)?;
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let path = config_path()?;
    let mut root = read_json(&path)?;
    if let Some(obj) = root.as_object_mut() {
        if let Some(Value::Object(mcp)) = obj.get_mut("mcp") {
            mcp.remove("agentdr-recorder");
        }
        obj.remove(MARKER_KEY);
    }
    write_json(&path, &root)?;
    println!("✓ opencode: removed AgentDR entries from {}", path.display());

    let _ = std::fs::remove_file(wrapper_path()?);
    let _ = std::fs::remove_file(marker_path()?);
    Ok(())
}

pub fn status() -> HookState {
    let path = match config_path() {
        Ok(p) => p,
        Err(e) => return HookState::absent(&e),
    };
    match read_json(&path) {
        Ok(Value::Object(obj)) => {
            let installed = obj.contains_key(MARKER_KEY)
                || obj
                    .get("mcp")
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
                notes: Some(if installed {
                    "managed".into()
                } else {
                    "opencode.json present but no AgentDR keys".into()
                }),
            }
        }
        _ => HookState {
            installed: false,
            config_path: Some(path.display().to_string()),
            endpoint: None,
            notes: Some("no ~/.config/opencode/opencode.json".into()),
        },
    }
}
