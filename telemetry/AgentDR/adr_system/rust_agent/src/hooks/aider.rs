//! Aider hook installer.
//!
//! Aider has no native OTLP emitter, so we capture coverage two ways:
//!   1. A shell wrapper at `~/.local/bin/aider-agentdr` that exports the
//!      AgentDR OTLP env (in case a future Aider release picks them up via
//!      its embedded `litellm` / `openai` SDK), then execs the real `aider`.
//!   2. A managed block in `~/.aider.conf.yml` that turns on Aider's
//!      built-in logging hooks (`chat-history-file`, `llm-history-file`)
//!      pointing at AgentDR's runtime log directory so the agent's file
//!      monitor can ingest them as ai_operation=inference (API Activity 6003) events.

use super::common::*;
use serde_json::{json, Value};
use std::path::PathBuf;

fn yaml_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".aider.conf.yml"))
}

fn wrapper_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".local").join("bin").join("aider-agentdr"))
}

fn marker_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".aider").join(".agentdr.json"))
}

fn history_dir() -> Result<PathBuf, String> {
    Ok(home()?.join(".agentdr").join("aider-history"))
}

pub fn install(endpoint: &str) -> Result<(), String> {
    let yp = yaml_path()?;
    let prev = std::fs::read_to_string(&yp).unwrap_or_default();
    let cleaned = strip_managed_block(&prev);
    let hist = history_dir()?;
    std::fs::create_dir_all(&hist).map_err(|e| e.to_string())?;
    let block = format!(
        "\n# >>> AgentDR managed (do not edit) >>>\n\
         chat-history-file: {hist}/chat-history.md\n\
         llm-history-file: {hist}/llm-history.jsonl\n\
         # <<< AgentDR managed <<<\n",
        hist = hist.display(),
    );
    let new = format!("{}{}", cleaned.trim_end(), block);
    std::fs::write(&yp, new).map_err(|e| e.to_string())?;
    println!("✓ aider: wrote {}", yp.display());

    let wp = wrapper_path()?;
    if let Some(parent) = wp.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let script = format!(
        "#!/usr/bin/env sh\n\
         # AgentDR managed wrapper for aider.\n\
         export OTEL_EXPORTER_OTLP_ENDPOINT={ep}\n\
         export OTEL_EXPORTER_OTLP_PROTOCOL=http/json\n\
         export OTEL_SERVICE_NAME=aider\n\
         export OTEL_TRACES_EXPORTER=otlp\n\
         export OTEL_LOGS_EXPORTER=otlp\n\
         exec aider \"$@\"\n",
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
    println!("✓ aider: wrote {} (use this in place of `aider`)", wp.display());

    let body = json!({ MARKER_KEY: MARKER_VALUE, "endpoint": endpoint, "history_dir": hist.display().to_string() });
    write_json(&marker_path()?, &body)?;
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let yp = yaml_path()?;
    if yp.exists() {
        let prev = std::fs::read_to_string(&yp).unwrap_or_default();
        std::fs::write(&yp, strip_managed_block(&prev)).map_err(|e| e.to_string())?;
        println!("✓ aider: removed AgentDR block from {}", yp.display());
    }
    let _ = std::fs::remove_file(wrapper_path()?);
    let _ = std::fs::remove_file(marker_path()?);
    Ok(())
}

pub fn status() -> HookState {
    let path = match yaml_path() {
        Ok(p) => p,
        Err(e) => return HookState::absent(&e),
    };
    let body = std::fs::read_to_string(&path).unwrap_or_default();
    let installed = body.contains("# >>> AgentDR managed");
    let endpoint = std::fs::read_to_string(marker_path().unwrap_or_default())
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.get("endpoint").and_then(|x| x.as_str()).map(String::from));
    HookState {
        installed,
        config_path: Some(path.display().to_string()),
        endpoint,
        notes: Some(if installed { "managed".into() } else { "no AgentDR block in ~/.aider.conf.yml".into() }),
    }
}

fn strip_managed_block(src: &str) -> String {
    let start = "# >>> AgentDR managed (do not edit) >>>";
    let end = "# <<< AgentDR managed <<<";
    let mut out = src.to_string();
    while let (Some(a), Some(b)) = (out.find(start), out.find(end)) {
        if b > a {
            let cut_end = b + end.len();
            let cut_end = if out.as_bytes().get(cut_end).copied() == Some(b'\n') { cut_end + 1 } else { cut_end };
            out.replace_range(a..cut_end, "");
        } else {
            break;
        }
    }
    out
}
