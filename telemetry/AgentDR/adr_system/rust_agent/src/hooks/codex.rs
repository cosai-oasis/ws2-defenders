//! Codex CLI hook installer.
//!
//! Codex CLI (the OpenAI `codex` binary) reads configuration from
//! `~/.codex/config.toml`. We write an `[telemetry]` block plus the standard
//! OTel env vars so any OTel-aware child SDK picks them up. For coverage of
//! Codex versions that ignore the [telemetry] block, the installer also drops
//! a shell wrapper at `~/.local/bin/codex-agentdr` that exports the same
//! variables and execs the real `codex`.

use super::common::*;
use serde_json::json;
use std::path::PathBuf;

fn config_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".codex").join("config.toml"))
}

fn wrapper_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".local").join("bin").join("codex-agentdr"))
}

fn marker_path() -> Result<PathBuf, String> {
    Ok(home()?.join(".codex").join(".agentdr.json"))
}

pub fn install(endpoint: &str) -> Result<(), String> {
    let cfg = config_path()?;
    if let Some(parent) = cfg.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    // We rewrite our managed [telemetry] block but preserve everything else.
    let prev = std::fs::read_to_string(&cfg).unwrap_or_default();
    let cleaned = strip_managed_block(&prev);
    let block = format!(
        "\n# >>> AgentDR managed (do not edit) >>>\n\
         [telemetry]\n\
         enabled = true\n\
         otlp_endpoint = \"{}\"\n\
         otlp_protocol = \"http/json\"\n\
         service_name = \"codex\"\n\
         # <<< AgentDR managed <<<\n",
        endpoint
    );
    let new = format!("{}{}", cleaned.trim_end(), block);
    std::fs::write(&cfg, new).map_err(|e| e.to_string())?;
    println!("✓ codex: wrote {}", cfg.display());

    // Wrapper script
    let wp = wrapper_path()?;
    if let Some(parent) = wp.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let script = format!(
        "#!/usr/bin/env sh\n\
         # AgentDR managed wrapper for codex.\n\
         export CLAUDE_CODE_ENABLE_TELEMETRY=1\n\
         export OTEL_EXPORTER_OTLP_ENDPOINT={ep}\n\
         export OTEL_EXPORTER_OTLP_PROTOCOL=http/json\n\
         export OTEL_SERVICE_NAME=codex\n\
         export OTEL_TRACES_EXPORTER=otlp\n\
         export OTEL_LOGS_EXPORTER=otlp\n\
         export OTEL_METRICS_EXPORTER=otlp\n\
         exec codex \"$@\"\n",
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
    println!("✓ codex: wrote {} (use this in place of `codex`)", wp.display());

    // Sentinel
    let body = json!({ MARKER_KEY: MARKER_VALUE, "endpoint": endpoint });
    write_json(&marker_path()?, &body)?;
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let cfg = config_path()?;
    if cfg.exists() {
        let prev = std::fs::read_to_string(&cfg).unwrap_or_default();
        let cleaned = strip_managed_block(&prev);
        std::fs::write(&cfg, cleaned).map_err(|e| e.to_string())?;
        println!("✓ codex: removed AgentDR block from {}", cfg.display());
    }
    let _ = std::fs::remove_file(wrapper_path()?);
    let _ = std::fs::remove_file(marker_path()?);
    Ok(())
}

pub fn status() -> HookState {
    let path = match config_path() {
        Ok(p) => p,
        Err(e) => return HookState::absent(&e),
    };
    let body = std::fs::read_to_string(&path).unwrap_or_default();
    let installed = body.contains("# >>> AgentDR managed");
    let endpoint = extract_endpoint(&body);
    HookState {
        installed,
        config_path: Some(path.display().to_string()),
        endpoint,
        notes: Some(if installed { "managed".into() } else { "no AgentDR block in codex config".into() }),
    }
}

fn strip_managed_block(src: &str) -> String {
    let start = "# >>> AgentDR managed (do not edit) >>>";
    let end = "# <<< AgentDR managed <<<";
    let mut out = src.to_string();
    while let (Some(a), Some(b)) = (out.find(start), out.find(end)) {
        if b > a {
            let cut_end = b + end.len();
            // Also remove trailing newline if present
            let cut_end = if out.as_bytes().get(cut_end).copied() == Some(b'\n') { cut_end + 1 } else { cut_end };
            out.replace_range(a..cut_end, "");
        } else {
            break;
        }
    }
    out
}

fn extract_endpoint(body: &str) -> Option<String> {
    body.lines().find_map(|l| {
        let l = l.trim();
        l.strip_prefix("otlp_endpoint")
            .and_then(|rest| rest.split('=').nth(1))
            .map(|v| v.trim().trim_matches('"').to_string())
    })
}
