//! Tier 6 — shell / TTY recorder.
//!
//! `adr-agent shell wrap -- <cmd>` re-execs a command (typically a shell
//! or a non-interactive script) with stdin / stdout / stderr piped
//! through the agent. Each input line and each output line is emitted as
//! an API Activity (OCSF 6003, ai_operation=tool_execution) event so SOC can audit *what an
//! agent shell-execed* and *what came back* — not merely that a process
//! ran. Designed to be invoked from inside an AI agent's shell-tool
//! handler:
//!
//!   {
//!     "command": "adr-agent",
//!     "args":    ["shell", "wrap", "--name", "claude-bash", "--", "bash", "-c", "<cmd>"]
//!   }
//!
//! Limitations: pipe-based wrapping (not a real PTY) — full-screen TUIs
//! like vim or htop will not render correctly. For interactive sessions
//! operators should pipe `script(1)` output through file_monitor instead.

use crate::models::*;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex;
use tracing::{debug, error, info};

pub async fn run(session_name: &str, cmd: &[String], log_path: &Path) -> Result<i32, String> {
    if cmd.is_empty() {
        return Err("missing command after `--`".into());
    }
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log = Arc::new(EventLog::new(log_path.to_path_buf()));

    // Start event
    {
        let mut ev = EventRecord::new(
            "shell_wrap_start",
            json!({ "session": session_name, "cmd": cmd }),
            "low",
        );
        ev.set_op(AiOperation::ToolExecution, ACTIVITY_CREATE);
        ev.activity_id = Some(ACTIVITY_CREATE);
        ev.status_id = Some(STATUS_SUCCESS);
        ev.tool_name = Some("shell".into());
        ev.source = Some("shell_wrap".into());
        ev.actor = Some(json!({ "user": user(), "host": host_name() }));
        ev.message = Some(format!("shell wrap start: {} -- {}", session_name, cmd.join(" ")));
        log.write(&ev);
    }

    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn '{}': {e}", cmd[0]))?;

    let child_stdin  = Arc::new(Mutex::new(child.stdin.take().ok_or("no stdin")?));
    let child_stdout = child.stdout.take().ok_or("no stdout")?;
    let child_stderr = child.stderr.take().ok_or("no stderr")?;

    // stdin → child + emit input events
    let log_in = log.clone();
    let name_in = session_name.to_string();
    let stdin_to_child = {
        let child_stdin = child_stdin.clone();
        tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let mut lines = BufReader::new(stdin).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                emit_io(&log_in, &name_in, "stdin", &line);
                let mut g = child_stdin.lock().await;
                if g.write_all(line.as_bytes()).await.is_err() { break; }
                if g.write_all(b"\n").await.is_err() { break; }
                if g.flush().await.is_err() { break; }
            }
        })
    };

    // child stdout → host stdout + emit output events
    let log_out = log.clone();
    let name_out = session_name.to_string();
    let stdout_pump = tokio::spawn(async move {
        let reader = BufReader::new(child_stdout);
        let mut lines = reader.lines();
        let mut out = tokio::io::stdout();
        while let Ok(Some(line)) = lines.next_line().await {
            emit_io(&log_out, &name_out, "stdout", &line);
            if out.write_all(line.as_bytes()).await.is_err() { break; }
            if out.write_all(b"\n").await.is_err() { break; }
            let _ = out.flush().await;
        }
    });

    // child stderr → host stderr + emit output events (marked as stderr)
    let log_err = log.clone();
    let name_err = session_name.to_string();
    let stderr_pump = tokio::spawn(async move {
        let reader = BufReader::new(child_stderr);
        let mut lines = reader.lines();
        let mut err = tokio::io::stderr();
        while let Ok(Some(line)) = lines.next_line().await {
            emit_io(&log_err, &name_err, "stderr", &line);
            if err.write_all(line.as_bytes()).await.is_err() { break; }
            if err.write_all(b"\n").await.is_err() { break; }
            let _ = err.flush().await;
        }
    });

    let exit_status = child.wait().await.map_err(|e| e.to_string())?;
    let code = exit_status.code().unwrap_or(if exit_status.success() { 0 } else { 1 });
    stdin_to_child.abort();
    let _ = tokio::join!(stdout_pump, stderr_pump);

    // End event
    {
        let mut ev = EventRecord::new(
            "shell_wrap_end",
            json!({ "session": session_name, "exit_code": code }),
            "low",
        );
        ev.set_op(AiOperation::ToolExecution, ACTIVITY_DELETE);
        ev.activity_id = Some(ACTIVITY_DELETE);
        ev.status_id = if code == 0 { Some(STATUS_SUCCESS) } else { Some(STATUS_FAILURE) };
        ev.tool_name = Some("shell".into());
        ev.source = Some("shell_wrap".into());
        ev.message = Some(format!("shell wrap end: {} (exit {})", session_name, code));
        log.write(&ev);
    }
    info!("shell wrap '{}' exited {}", session_name, code);
    Ok(code)
}

fn emit_io(log: &EventLog, session: &str, stream: &str, raw: &str) {
    // Truncate huge lines to a reasonable cap to keep events small.
    let trimmed = if raw.len() > 4096 { &raw[..4096] } else { raw };
    let risk = if stream == "stdin" { "medium" } else { "low" };
    let mut ev = EventRecord::new(
        match stream {
            "stdin"  => "shell_input",
            "stderr" => "shell_stderr",
            _        => "shell_stdout",
        },
        json!({ "session": session, "stream": stream, "line": trimmed, "truncated": raw.len() > 4096 }),
        risk,
    );
    ev.set_op(AiOperation::ToolExecution, ACTIVITY_EXECUTE);
    ev.activity_id = Some(ACTIVITY_EXECUTE);
    ev.status_id = Some(STATUS_SUCCESS);
    ev.tool_name = Some("shell".into());
    ev.source = Some("shell_wrap".into());
    log.write(&ev);
}

fn user() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default()
}
fn host_name() -> String {
    hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_default()
}

struct EventLog { path: PathBuf }
impl EventLog {
    fn new(path: PathBuf) -> Self { Self { path } }
    fn write(&self, ev: &EventRecord) {
        let Ok(line) = serde_json::to_string(ev) else { return };
        match std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(mut f) => {
                use std::io::Write;
                let _ = writeln!(f, "{}", line);
            }
            Err(e) => error!("shell wrap log open {}: {e}", self.path.display()),
        }
        debug!("shell wrap: emitted event");
    }
}
