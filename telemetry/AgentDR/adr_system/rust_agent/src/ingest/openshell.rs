//! NVIDIA OpenShell audit-log ingest.
//!
//! [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) is a secure-by-design
//! runtime that sandboxes autonomous AI agents and routes every action through a
//! Gateway that records an allow/deny decision. When `ocsf_json_enabled` is set,
//! OpenShell writes one **OCSF v1.7.0** JSON object per line to a rotating file
//! (`/var/log/openshell-ocsf.YYYY-MM-DD.log`).
//!
//! This module tails that file and re-emits each decision as an AITF
//! `EventRecord`, enriching it with the `ai_operation` profile and the reused
//! OCSF `class_uid` so OpenShell's enforcement telemetry flows through the same
//! detection / policy / exporter pipeline as everything else AgentDR observes.
//! AgentDR is the detection / SIEM layer *over* OpenShell's enforcement layer —
//! it consumes the Gateway's audit trail rather than duplicating enforcement.

use crate::config::OpenShellConfig;
use crate::models::*;
use serde_json::{json, Value};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

pub struct OpenShellIngest {
    tx: mpsc::UnboundedSender<EventRecord>,
    dir: PathBuf,
    prefix: String,
    poll: Duration,
}

impl OpenShellIngest {
    pub fn new(cfg: &OpenShellConfig, tx: mpsc::UnboundedSender<EventRecord>) -> Self {
        let (dir, prefix) = split_glob(&cfg.log_glob);
        Self {
            tx,
            dir,
            prefix,
            poll: Duration::from_secs(cfg.poll_interval_seconds.max(1)),
        }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        info!(
            "OpenShell ingest watching {}/{}*.log",
            self.dir.display(),
            self.prefix
        );
        let mut current: Option<PathBuf> = None;
        let mut offset: u64 = 0;
        let mut tick = interval(self.poll);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if let Some(path) = newest_log(&self.dir, &self.prefix) {
                        // A new file (daily rotation) resets the read offset.
                        if current.as_deref() != Some(path.as_path()) {
                            debug!("OpenShell ingest switching to {}", path.display());
                            current = Some(path.clone());
                            offset = 0;
                        }
                        offset = self.drain(&path, offset);
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { break; }
                }
            }
        }
    }

    /// Read newly-appended complete lines from `path` starting at `offset`,
    /// emit one EventRecord per parsed OCSF record, and return the new offset.
    fn drain(&self, path: &Path, mut offset: u64) -> u64 {
        let Ok(mut f) = std::fs::File::open(path) else { return offset };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len < offset {
            offset = 0; // file truncated/rotated under us
        }
        if f.seek(SeekFrom::Start(offset)).is_err() {
            return offset;
        }
        let mut buf = String::new();
        if f.read_to_string(&mut buf).is_err() || buf.is_empty() {
            return offset;
        }
        // Only consume up to the last complete line so a partially-written
        // trailing line is re-read on the next poll.
        let Some(last_nl) = buf.rfind('\n') else { return offset };
        let complete = &buf[..=last_nl];
        for line in complete.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(line) {
                Ok(v) => {
                    if let Some(ev) = map_ocsf(&v) {
                        let _ = self.tx.send(ev);
                    }
                }
                Err(e) => warn!("OpenShell ingest: skipping malformed line: {e}"),
            }
        }
        offset + complete.len() as u64
    }
}

/// Split a glob like `/var/log/openshell-ocsf*.log` into (`/var/log`,
/// `openshell-ocsf`). Without a `*`, the basename is used as the prefix.
fn split_glob(glob: &str) -> (PathBuf, String) {
    let head = glob.split('*').next().unwrap_or(glob);
    let p = Path::new(head);
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/log"));
    let prefix = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "openshell-ocsf".to_string());
    (dir, prefix)
}

/// Pick the most-recently-modified `<prefix>*.log` file in `dir`.
fn newest_log(dir: &Path, prefix: &str) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(prefix) && name.ends_with(".log") {
            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            if best.as_ref().map_or(true, |(b, _)| mtime >= *b) {
                best = Some((mtime, entry.path()));
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Map one OpenShell OCSF v1.7.0 audit record onto an AITF `EventRecord`.
fn map_ocsf(v: &Value) -> Option<EventRecord> {
    // ── disposition (ALLOWED / DENIED / BLOCKED) ──
    let disposition = str_at(v, "disposition")
        .or_else(|| str_at(v, "action"))
        .map(|s| s.to_ascii_uppercase());
    let disposition_id = v.get("disposition_id").and_then(Value::as_i64);
    let denied = matches!(disposition.as_deref(), Some("DENIED") | Some("BLOCKED"))
        || matches!(disposition_id, Some(2) | Some(3));

    let ocsf_class = v.get("class_uid").and_then(Value::as_i64).unwrap_or(0);
    let reason = str_at(v, "status_detail")
        .or_else(|| str_at(v, "message"))
        .unwrap_or("")
        .to_string();

    // Salient resource fields (defensive: OpenShell maps to several OCSF classes).
    let host = first_str(
        v,
        &["dst_endpoint.hostname", "url.hostname", "http_request.url.hostname"],
    );
    let file_path = first_str(v, &["file.path", "file.name"]);
    let process_name = first_str(v, &["process.name", "actor.process.name"]);
    let sandbox = first_str(v, &["device.name", "device.hostname", "metadata.product.name"]);
    let user = first_str(v, &["actor.user.name", "actor.user.uid"]);
    let policy_rule = first_str(v, &["finding_info.uid", "policy.uid", "rule.uid"]);

    // ── choose AITF ai_operation + risk ──
    let is_network = host.is_some() || (4000..4100).contains(&ocsf_class);
    let is_file = file_path.is_some() || ocsf_class == 1001;
    let ai_info = host.as_deref().and_then(classify_ai_endpoint);
    let messaging = host.as_deref().and_then(classify_messaging_endpoint);

    let (op, activity, risk) = if denied {
        // A policy refusal. Unverified-skill / unreviewed-binary denials are a
        // supply-chain concern; everything else is a compliance finding.
        let lower = reason.to_lowercase();
        if lower.contains("skill")
            || lower.contains("binary")
            || lower.contains("unverified")
            || lower.contains("unreviewed")
        {
            (AiOperation::SupplyChain, ACTIVITY_BLOCK, "high")
        } else {
            (AiOperation::ComplianceViolation, ACTIVITY_BLOCK, "high")
        }
    } else if is_network {
        if ai_info.is_some() {
            (AiOperation::Inference, ACTIVITY_EXECUTE, "medium")
        } else if messaging.is_some() {
            (AiOperation::PermissionEscalation, ACTIVITY_EXECUTE, "high")
        } else {
            (AiOperation::AgentAction, ACTIVITY_EXECUTE, "low")
        }
    } else if is_file {
        (AiOperation::ToolExecution, ACTIVITY_EXECUTE, "low")
    } else {
        // process / config / other allowed control-plane action
        (AiOperation::AgentAction, ACTIVITY_EXECUTE, "low")
    };

    let mut ev = EventRecord::new(
        "openshell_decision",
        json!({
            "disposition": disposition,
            "ocsf_class_uid": ocsf_class,
            "host": host,
            "file_path": file_path,
            "process": process_name,
            "sandbox": sandbox,
            "policy_rule": policy_rule,
            "reason": reason,
        }),
        risk,
    );
    ev.set_op(op, activity);
    ev.activity_id = Some(activity);
    ev.status_id = Some(if denied { STATUS_BLOCKED } else { STATUS_SUCCESS });
    ev.source = Some("openshell".into());

    // Attribution: identify the sandboxed agent from the process/sandbox name.
    let haystack = format!(
        "{} {}",
        process_name.clone().unwrap_or_default(),
        sandbox.clone().unwrap_or_default()
    );
    if let Some(sig) = identify_agent(&haystack) {
        ev.agent_detected = Some(sig.name.clone());
        ev.agent_name = Some(sig.name);
        ev.agent_framework = Some(sig.framework);
    }
    if let Some(ai) = ai_info {
        ev.provider = Some(ai.provider);
        ev.model = Some(ai.model);
    }
    if user.is_some() || sandbox.is_some() {
        ev.actor = Some(json!({ "user": user, "sandbox": sandbox }));
    }
    if !policy_rule.clone().unwrap_or_default().is_empty() {
        ev.compliance = Some(json!({ "frameworks": ["NVIDIA-OpenShell"], "policy_rule": policy_rule }));
    }
    ev.message = Some(build_message(&disposition, &host, &file_path, &process_name, &reason));

    // Preserve OpenShell's correlation id so multi-step agent tasks reconstruct.
    if let Some(cid) = first_str(v, &["metadata.correlation_uid", "metadata.uid", "uid"]) {
        ev.trace_id = cid;
    }

    Some(ev)
}

fn build_message(
    disposition: &Option<String>,
    host: &Option<String>,
    file_path: &Option<String>,
    process: &Option<String>,
    reason: &str,
) -> String {
    let disp = disposition.as_deref().unwrap_or("DECISION");
    let target = host
        .clone()
        .or_else(|| file_path.clone())
        .or_else(|| process.clone())
        .unwrap_or_else(|| "action".into());
    if reason.is_empty() {
        format!("OpenShell {disp}: {target}")
    } else {
        format!("OpenShell {disp}: {target} ({reason})")
    }
}

// ── dotted-path JSON helpers ──

fn dotted<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn str_at<'a>(v: &'a Value, path: &str) -> Option<&'a str> {
    dotted(v, path).and_then(Value::as_str)
}

fn first_str(v: &Value, paths: &[&str]) -> Option<String> {
    for p in paths {
        if let Some(s) = dotted(v, p) {
            if let Some(s) = s.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            } else if s.is_number() {
                return Some(s.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_denied_network_to_compliance_finding() {
        let v: Value = serde_json::from_str(
            r#"{
                "class_uid": 4001,
                "disposition": "DENIED",
                "status_detail": "host not in network policy allowlist",
                "dst_endpoint": {"hostname": "evil.example.com"},
                "device": {"name": "sandbox-claude-code"},
                "metadata": {"correlation_uid": "abc123"}
            }"#,
        )
        .unwrap();
        let ev = map_ocsf(&v).unwrap();
        assert_eq!(ev.class_uid, Some(OCSF_COMPLIANCE_FINDING));
        assert_eq!(ev.ai_operation.as_deref(), Some("compliance_violation"));
        assert_eq!(ev.status_id, Some(STATUS_BLOCKED));
        assert_eq!(ev.trace_id, "abc123");
    }

    #[test]
    fn maps_allowed_file_access_to_tool_execution() {
        let v: Value = serde_json::from_str(
            r#"{
                "class_uid": 1001,
                "disposition": "ALLOWED",
                "file": {"path": "/home/user/project/main.rs"},
                "device": {"name": "sandbox-codex"}
            }"#,
        )
        .unwrap();
        let ev = map_ocsf(&v).unwrap();
        assert_eq!(ev.class_uid, Some(OCSF_API_ACTIVITY));
        assert_eq!(ev.ai_operation.as_deref(), Some("tool_execution"));
        assert_eq!(ev.status_id, Some(STATUS_SUCCESS));
    }

    #[test]
    fn maps_unverified_skill_denial_to_supply_chain() {
        let v: Value = serde_json::from_str(
            r#"{"class_uid": 1007, "disposition": "BLOCKED",
                "status_detail": "execution of unverified skill binary refused"}"#,
        )
        .unwrap();
        let ev = map_ocsf(&v).unwrap();
        assert_eq!(ev.class_uid, Some(OCSF_VULNERABILITY_FINDING));
        assert_eq!(ev.ai_operation.as_deref(), Some("supply_chain"));
    }
}
