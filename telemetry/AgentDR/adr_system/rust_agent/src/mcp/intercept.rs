//! MCP stdio transport interceptor.
//!
//! Used like:
//!     adr-agent mcp wrap --name github-server -- npx -y @modelcontextprotocol/server-github
//!
//! AgentDR re-execs the given command with its stdin/stdout piped through
//! the agent. JSON-RPC frames are decoded as MCP messages on each side and
//! an ai_operation=mcp_operation (API Activity 6003) event is emitted per RPC, with
//! `tool_name` set to the JSON-RPC `method` and `mcp_server` set to the
//! supplied name. The events go to the same JSONL log the rest of the
//! agent writes to, so SIEM ingestion works identically.

use crate::models::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

pub async fn run(server_name: &str, cmd: &[String], log_path: &Path) -> Result<i32, String> {
    if cmd.is_empty() {
        return Err("missing command after `--`".into());
    }

    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log = Arc::new(EventLog::new(log_path.to_path_buf()));

    // Initial event: wrap started.
    {
        let mut ev = EventRecord::new(
            "mcp_wrap_start",
            json!({ "server": server_name, "cmd": cmd }),
            "low",
        );
        ev.set_op(AiOperation::McpOperation, ACTIVITY_CREATE);
        ev.activity_id = Some(ACTIVITY_CREATE);
        ev.status_id = Some(STATUS_SUCCESS);
        ev.mcp_server = Some(server_name.into());
        ev.source = Some("mcp_intercept".into());
        ev.message = Some(format!("MCP wrap start: {}", server_name));
        log.write(&ev);
    }

    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn '{}': {e}", cmd[0]))?;

    let child_stdin = child.stdin.take().ok_or("no stdin on child")?;
    let child_stdout = child.stdout.take().ok_or("no stdout on child")?;
    let child_stdin = Arc::new(Mutex::new(child_stdin));

    // host stdin → child stdin  (client → server: requests)
    let log_a = log.clone();
    let name_a = server_name.to_string();
    let stdin_to_child = {
        let child_stdin = child_stdin.clone();
        tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let reader = BufReader::new(stdin);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() { continue; }
                emit_rpc(&log_a, &name_a, &line, "request");
                let mut guard = child_stdin.lock().await;
                if guard.write_all(line.as_bytes()).await.is_err() { break; }
                if guard.write_all(b"\n").await.is_err() { break; }
                if guard.flush().await.is_err() { break; }
            }
            drop(child_stdin);
        })
    };

    // child stdout → host stdout (server → client: responses / notifications)
    let log_b = log.clone();
    let name_b = server_name.to_string();
    let child_to_stdout = tokio::spawn(async move {
        let reader = BufReader::new(child_stdout);
        let mut lines = reader.lines();
        let mut out = tokio::io::stdout();
        while let Ok(Some(line)) = lines.next_line().await {
            emit_rpc(&log_b, &name_b, &line, "response");
            if out.write_all(line.as_bytes()).await.is_err() { break; }
            if out.write_all(b"\n").await.is_err() { break; }
            let _ = out.flush().await;
        }
    });

    let exit_status = child.wait().await.map_err(|e| e.to_string())?;
    let code = exit_status.code().unwrap_or(if exit_status.success() { 0 } else { 1 });

    // Stop the stdin pump; the read loop will exit when stdin closes.
    stdin_to_child.abort();
    let _ = child_to_stdout.await;

    // Final event: wrap ended.
    {
        let mut ev = EventRecord::new(
            "mcp_wrap_end",
            json!({ "server": server_name, "exit_code": code }),
            "low",
        );
        ev.set_op(AiOperation::McpOperation, ACTIVITY_DELETE);
        ev.activity_id = Some(ACTIVITY_DELETE);
        ev.status_id = if code == 0 { Some(STATUS_SUCCESS) } else { Some(STATUS_FAILURE) };
        ev.mcp_server = Some(server_name.into());
        ev.source = Some("mcp_intercept".into());
        ev.message = Some(format!("MCP wrap end: {} (exit {})", server_name, code));
        log.write(&ev);
    }
    info!("MCP wrap '{}' exited with {}", server_name, code);
    Ok(code)
}

fn emit_rpc(log: &EventLog, server_name: &str, raw: &str, direction: &str) {
    // Parse as JSON; ignore non-JSON lines (some servers print a banner before
    // initialising the protocol).
    let Ok(value): Result<Value, _> = serde_json::from_str(raw) else {
        debug!("MCP non-JSON line dropped: {}", raw.chars().take(40).collect::<String>());
        return;
    };

    let method = value.get("method").and_then(|v| v.as_str()).map(String::from);
    let id = value.get("id").cloned();
    let is_error = value.get("error").is_some();
    let params = value.get("params").cloned();
    let result = value.get("result").cloned();

    let activity = if direction == "request" { ACTIVITY_EXECUTE } else { ACTIVITY_READ };

    // Risk heuristic: tool execution and resource access are medium; init/list
    // / handshake messages are low.
    let risk = match method.as_deref() {
        Some(m) if m.starts_with("tools/call") => "medium",
        Some(m) if m.starts_with("resources/read") => "medium",
        Some(m) if m.starts_with("prompts/") => "medium",
        Some(_) => "low",
        None => "low",
    };

    let details = json!({
        "direction": direction,
        "method": method,
        "id": id,
        "is_error": is_error,
        // Keep params/result as JSON (operators can redact via downstream pipeline).
        "params": params,
        "result": result,
    });

    let mut ev = EventRecord::new("mcp_rpc", details, risk);
    ev.set_op(AiOperation::McpOperation, activity);
    ev.activity_id = Some(activity);
    ev.status_id = if is_error { Some(STATUS_FAILURE) } else { Some(STATUS_SUCCESS) };
    ev.mcp_server = Some(server_name.into());
    ev.tool_name = method.clone();
    ev.source = Some("mcp_intercept".into());
    ev.message = Some(format!(
        "MCP {} {}",
        direction,
        method.unwrap_or_else(|| "<no-method>".into())
    ));
    log.write(&ev);
}

/// Minimal JSONL appender — independent of the Agent engine so `mcp wrap`
/// runs even when the main agent is not started.
struct EventLog {
    path: PathBuf,
}

impl EventLog {
    fn new(path: PathBuf) -> Self { Self { path } }

    fn write(&self, ev: &EventRecord) {
        let Ok(line) = serde_json::to_string(ev) else { return };
        match std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(mut f) => {
                use std::io::Write;
                let _ = writeln!(f, "{}", line);
            }
            Err(e) => error!("mcp event log open {}: {e}", self.path.display()),
        }
    }
}
