//! Claude Code hook installer.
//!
//! Claude Code supports first-class OpenTelemetry export. Setting
//! `CLAUDE_CODE_ENABLE_TELEMETRY=1` plus the standard `OTEL_*` env vars in
//! the user's `~/.claude/settings.json` redirects all tool-call, file-edit
//! and prompt events through AgentDR's OTLP collector — no shell wrapper
//! required.

use super::common::*;
use serde_json::{json, Value};
use std::path::PathBuf;

fn settings_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".claude").join("settings.json"))
}

pub fn install(endpoint: &str) -> Result<(), String> {
    let path = settings_path()?;
    let mut root = read_json(&path)?;
    ensure_object(&mut root);
    let obj = root.as_object_mut().unwrap();

    // env block
    let mut env = match obj.remove("env") {
        Some(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    env.insert("CLAUDE_CODE_ENABLE_TELEMETRY".into(), Value::String("1".into()));
    for (k, v) in otel_env(endpoint, "claude-code") {
        env.insert(k, v);
    }
    obj.insert("env".into(), Value::Object(env));

    // marker so we can identify our edits
    let mut marker = serde_json::Map::new();
    marker.insert("endpoint".into(), Value::String(endpoint.into()));
    marker.insert("description".into(), Value::String(MARKER_VALUE.into()));
    obj.insert(MARKER_KEY.into(), Value::Object(marker));

    write_json(&path, &root)?;
    println!("✓ claude-code: wrote {}", path.display());
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let path = settings_path()?;
    let mut root = read_json(&path)?;
    if let Some(obj) = root.as_object_mut() {
        if let Some(Value::Object(env)) = obj.get_mut("env") {
            env.remove("CLAUDE_CODE_ENABLE_TELEMETRY");
            for k in [
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "OTEL_EXPORTER_OTLP_PROTOCOL",
                "OTEL_SERVICE_NAME",
                "OTEL_TRACES_EXPORTER",
                "OTEL_LOGS_EXPORTER",
                "OTEL_METRICS_EXPORTER",
            ] {
                env.remove(k);
            }
        }
        obj.remove(MARKER_KEY);
    }
    write_json(&path, &root)?;
    println!("✓ claude-code: removed AgentDR keys from {}", path.display());
    Ok(())
}

pub fn status() -> HookState {
    let path = match settings_path() {
        Ok(p) => p,
        Err(e) => return HookState::absent(&e),
    };
    match read_json(&path) {
        Ok(Value::Object(obj)) => {
            let installed = obj.contains_key(MARKER_KEY)
                || obj
                    .get("env")
                    .and_then(|e| e.as_object())
                    .map(|e| e.contains_key("CLAUDE_CODE_ENABLE_TELEMETRY"))
                    .unwrap_or(false);
            let endpoint = obj
                .get("env")
                .and_then(|e| e.get("OTEL_EXPORTER_OTLP_ENDPOINT"))
                .and_then(|v| v.as_str())
                .map(String::from);
            HookState {
                installed,
                config_path: Some(path.display().to_string()),
                endpoint,
                notes: Some(if installed { "managed".into() } else { "claude-code settings present but no AgentDR keys".into() }),
            }
        }
        _ => HookState {
            installed: false,
            config_path: Some(path.display().to_string()),
            endpoint: None,
            notes: Some("no ~/.claude/settings.json".into()),
        },
    }
}

#[allow(dead_code)]
pub fn example_payload(endpoint: &str) -> Value {
    json!({
        "env": {
            "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
            "OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
            "OTEL_SERVICE_NAME": "claude-code",
        }
    })
}
