//! Shared utilities for AgentDR runtime-hook installers.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Marker that AgentDR places in every file it touches so we can recognise &
/// roll back its edits.
pub const MARKER_KEY: &str = "_agentdr";
pub const MARKER_VALUE: &str = "AgentDR managed — do not edit by hand";

/// True if the given file content carries any AgentDR-placed marker.
/// Works across all hook config formats (JSON keys, TOML/YAML banners,
/// wrapper-script comments) because every installer writes either the
/// JSON key, the marker value string, or both.
pub fn has_marker(content: &str) -> bool {
    content.contains(MARKER_KEY) || content.contains(MARKER_VALUE)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HookState {
    pub installed: bool,
    pub config_path: Option<String>,
    pub endpoint: Option<String>,
    pub notes: Option<String>,
}

impl HookState {
    pub fn absent(notes: &str) -> Self {
        Self { installed: false, config_path: None, endpoint: None, notes: Some(notes.into()) }
    }
}

pub fn home() -> Result<PathBuf, String> {
    dirs::home_dir().ok_or_else(|| "could not resolve $HOME".to_string())
}

/// Read a JSON file, returning `Value::Null` if missing.
pub fn read_json(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        return Ok(Value::Null);
    }
    let s = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if s.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&s).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Atomic-ish write: creates parent dirs, writes to `<path>.agentdr.tmp`, rename.
pub fn write_json(path: &Path, v: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("agentdr.tmp");
    let body = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    let mut f = fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
    f.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    drop(f);
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
}

/// Insert (or merge) `obj[key] = value` while preserving any unrelated existing keys.
pub fn ensure_object(root: &mut Value) {
    if !root.is_object() {
        *root = Value::Object(serde_json::Map::new());
    }
}

/// Standard OTel env vars the CoSAI hook installer enables. The agent
/// framework field names mirror Claude Code's documented settings.
pub fn otel_env(endpoint: &str, service_name: &str) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("OTEL_EXPORTER_OTLP_ENDPOINT".into(), Value::String(endpoint.to_string()));
    m.insert("OTEL_EXPORTER_OTLP_PROTOCOL".into(), Value::String("http/json".into()));
    m.insert("OTEL_SERVICE_NAME".into(), Value::String(service_name.to_string()));
    m.insert("OTEL_TRACES_EXPORTER".into(), Value::String("otlp".into()));
    m.insert("OTEL_LOGS_EXPORTER".into(), Value::String("otlp".into()));
    m.insert("OTEL_METRICS_EXPORTER".into(), Value::String("otlp".into()));
    m
}
