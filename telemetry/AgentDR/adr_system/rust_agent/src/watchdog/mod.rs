//! Tier 7 — AgentDR self-protection / watchdog.
//!
//! Monitors the files AgentDR depends on for its own behaviour and emits
//! events when they're tampered with — with a special focus on detecting
//! a monitored AI agent that tries to *escape surveillance* by removing
//! AgentDR's marker from its own hook config.
//!
//! Tracked surfaces:
//!   - <root>/config.toml            — agent's own runtime config
//!   - <exe>                         — the AgentDR binary on disk
//!   - cosai-community/rules/*.json  — community rule pack
//!   - cosai-community/policies/policies.yaml — policy pack
//!   - Every hook config we ever wrote (claude-code, cursor, codex, aider, opencode)
//!
//! Detection logic per tick:
//!   * SHA-256 unchanged                          → silence
//!   * Hash changed + marker still present        → INFORMATIONAL
//!     (legitimate operator edit of a managed file)
//!   * Hash changed + marker MISSING (was present) → CRITICAL evasion
//!     (a monitored agent or another process removed AgentDR's footprint)
//!   * File deleted                                → CRITICAL
//!   * Rule pack / binary changed                  → HIGH / CRITICAL
//!
//! Self-heal (off by default): when an evasion attempt is detected on a
//! hook config the watchdog calls `hooks::install(<agent>)` to put the
//! marker back. The remediation itself emits a follow-up event.

use crate::config::WatchdogConfig;
use crate::hooks;
use crate::models::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

pub struct WatchdogMonitor {
    cfg: WatchdogConfig,
    root: PathBuf,
    endpoint: String,
    tx: mpsc::UnboundedSender<EventRecord>,
}

#[derive(Debug, Clone)]
struct Guard {
    label: String,
    path: PathBuf,
    kind: GuardKind,
    last_hash: Option<[u8; 32]>,
    last_marker_present: bool,
    last_seen: bool,
}

#[derive(Debug, Clone)]
enum GuardKind {
    HookConfig { agent: &'static str },
    AgentConfig,
    RuleFile,
    PolicyFile,
    Binary,
}

impl WatchdogMonitor {
    pub fn new(
        cfg: WatchdogConfig,
        root: PathBuf,
        endpoint: String,
        tx: mpsc::UnboundedSender<EventRecord>,
    ) -> Self {
        Self { cfg, root, endpoint, tx }
    }

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut guards = self.discover_guards();

        // Establish baselines.
        for g in guards.iter_mut() {
            refresh_one(g);
        }

        // Startup announcement so the dashboard reflects the protected surface.
        let mut start = EventRecord::new(
            "watchdog_started",
            json!({
                "tracked":          guards.len(),
                "interval_seconds": self.cfg.interval_seconds,
                "self_heal":        self.cfg.self_heal,
                "paths":            guards.iter().map(|g| g.path.display().to_string()).collect::<Vec<_>>(),
            }),
            "low",
        );
        start.set_op(AiOperation::AgentAction, ACTIVITY_CREATE);
        start.activity_id = Some(ACTIVITY_CREATE);
        start.status_id   = Some(STATUS_SUCCESS);
        start.source      = Some("watchdog".into());
        start.message     = Some(format!(
            "AgentDR watchdog: tracking {} paths every {}s (self-heal {})",
            guards.len(),
            self.cfg.interval_seconds,
            if self.cfg.self_heal { "on" } else { "off" },
        ));
        let _ = self.tx.send(start);

        let mut ticker = interval(Duration::from_secs(self.cfg.interval_seconds.max(5)));
        ticker.tick().await; // skip the immediate fire (covered by the baseline above)

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    for g in guards.iter_mut() {
                        if let Some(ev) = self.check_one(g) {
                            let _ = self.tx.send(ev);
                        }
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
        info!("watchdog shutting down");
    }

    fn discover_guards(&self) -> Vec<Guard> {
        let mut out = Vec::new();

        // 1. Agent's own config
        out.push(new_guard("agent config.toml", self.root.join("config.toml"), GuardKind::AgentConfig));

        // 2. Binary on disk
        if let Ok(exe) = std::env::current_exe() {
            out.push(new_guard("adr-agent binary", exe, GuardKind::Binary));
        }

        // 3. Rule pack + policy pack — same discovery logic as RuleIntegrity
        let cosai_root = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|p| p.join("../cosai-community")))
            .filter(|p| p.exists())
            .unwrap_or_else(|| PathBuf::from("cosai-community"));
        for name in ["agent-signatures.json", "ai-endpoints.json", "messaging-endpoints.json"] {
            out.push(new_guard(
                &format!("rule pack: {}", name),
                cosai_root.join("rules").join(name),
                GuardKind::RuleFile,
            ));
        }
        out.push(new_guard(
            "policy pack: policies.yaml",
            cosai_root.join("policies").join("policies.yaml"),
            GuardKind::PolicyFile,
        ));
        out.push(new_guard(
            "rule pack: detection-rules.json",
            cosai_root.join("policies").join("detection-rules.json"),
            GuardKind::RuleFile,
        ));

        // 4. Every installed hook config
        let st = hooks::status();
        for (agent, hs) in [
            ("claude-code", &st.claude_code),
            ("cursor",      &st.cursor),
            ("codex",       &st.codex),
            ("aider",       &st.aider),
            ("opencode",    &st.opencode),
        ] {
            if let Some(p) = &hs.config_path {
                out.push(new_guard(
                    &format!("{} hook config", agent),
                    PathBuf::from(p),
                    GuardKind::HookConfig { agent },
                ));
            }
        }
        out
    }

    fn check_one(&self, g: &mut Guard) -> Option<EventRecord> {
        let bytes = std::fs::read(&g.path).ok();
        let exists = bytes.is_some();

        // Disappearance
        if g.last_seen && !exists {
            g.last_seen = false;
            g.last_hash = None;
            g.last_marker_present = false;
            return Some(self.event(
                "watchdog_file_missing",
                g,
                "critical",
                "tracked file was deleted",
            ));
        }
        if !exists {
            return None;
        }
        let bytes = bytes.unwrap();
        let new_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&bytes);
            h.finalize().into()
        };
        if g.last_hash == Some(new_hash) {
            return None;
        }
        let marker_now = std::str::from_utf8(&bytes)
            .map(hooks::common::has_marker)
            .unwrap_or(false);

        // Build the right event for this kind.
        let ev = match &g.kind {
            GuardKind::HookConfig { agent } => {
                if g.last_marker_present && !marker_now {
                    // Evasion detected — re-install if requested.
                    if self.cfg.self_heal {
                        match hooks::install(agent, &self.endpoint) {
                            Ok(()) => info!(
                                "watchdog: self-heal restored {} hook after evasion attempt",
                                agent
                            ),
                            Err(e) => warn!("watchdog: self-heal failed for {}: {}", agent, e),
                        }
                    }
                    let mut e = self.event(
                        "watchdog_evasion_detected",
                        g,
                        "critical",
                        &format!(
                            "AgentDR marker removed from {agent} hook config — surveillance evasion suspected{}",
                            if self.cfg.self_heal { " (auto-remediated)" } else { "" }
                        ),
                    );
                    e.agent_detected = Some((*agent).into());
                    e.agent_name = Some((*agent).into());
                    e
                } else if marker_now {
                    self.event(
                        "watchdog_config_changed",
                        g,
                        "low",
                        "tracked hook config changed; AgentDR marker still present",
                    )
                } else {
                    // Never had a marker — it's not under AgentDR's management; ignore.
                    g.last_hash = Some(new_hash);
                    g.last_seen = true;
                    return None;
                }
            }
            GuardKind::AgentConfig => self.event(
                "watchdog_config_changed",
                g,
                "medium",
                "agent config.toml was modified",
            ),
            GuardKind::RuleFile => self.event(
                "watchdog_rule_pack_changed",
                g,
                "high",
                "community rule-pack file was modified",
            ),
            GuardKind::PolicyFile => self.event(
                "watchdog_policy_pack_changed",
                g,
                "high",
                "policy pack was modified",
            ),
            GuardKind::Binary => self.event(
                "watchdog_binary_changed",
                g,
                "critical",
                "AgentDR binary on disk was replaced",
            ),
        };

        g.last_hash = Some(new_hash);
        g.last_marker_present = marker_now;
        g.last_seen = true;
        Some(ev)
    }

    fn event(&self, event_type: &str, g: &Guard, risk: &str, message: &str) -> EventRecord {
        let mut ev = EventRecord::new(
            event_type,
            json!({
                "label": g.label,
                "path":  g.path.display().to_string(),
                "kind":  format!("{:?}", g.kind),
            }),
            risk,
        );
        let activity = if event_type == "watchdog_evasion_detected" || event_type == "watchdog_file_missing" {
            ACTIVITY_BLOCK
        } else {
            ACTIVITY_DETECT
        };
        ev.set_op(AiOperation::ComplianceViolation, activity);
        ev.activity_id = Some(activity);
        ev.status_id   = if activity == ACTIVITY_BLOCK { Some(STATUS_BLOCKED) } else { Some(STATUS_SUCCESS) };
        ev.source      = Some("watchdog".into());
        ev.message     = Some(format!("watchdog: {} — {}", g.label, message));
        ev.security_finding = Some(json!({
            "rule_id":    "AGENTDR-WATCHDOG",
            "title":      "AgentDR self-protection",
            "severity":   risk,
            "owasp_llm":  "LLM06",
        }));
        ev.compliance = Some(json!({
            "frameworks": ["OWASP-LLM-Top10", "NIST-AI-RMF"],
            "mappings": {"OWASP-LLM-Top10": "LLM06"},
        }));
        ev
    }
}

fn new_guard(label: &str, path: PathBuf, kind: GuardKind) -> Guard {
    Guard {
        label: label.into(),
        path,
        kind,
        last_hash: None,
        last_marker_present: false,
        last_seen: false,
    }
}

fn refresh_one(g: &mut Guard) {
    match std::fs::read(&g.path) {
        Ok(bytes) => {
            let mut h = Sha256::new();
            h.update(&bytes);
            g.last_hash = Some(h.finalize().into());
            g.last_seen = true;
            g.last_marker_present = std::str::from_utf8(&bytes)
                .map(hooks::common::has_marker)
                .unwrap_or(false);
        }
        Err(_) => {
            g.last_hash = None;
            g.last_seen = false;
            g.last_marker_present = false;
        }
    }
}

// ── tests ────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn make_wd() -> WatchdogMonitor {
        let (tx, _rx) = mpsc::unbounded_channel();
        WatchdogMonitor::new(
            WatchdogConfig { enabled: true, interval_seconds: 30, self_heal: false },
            PathBuf::from("."),
            "http://127.0.0.1:4318".into(),
            tx,
        )
    }

    #[test]
    fn hook_marker_removal_is_evasion() {
        let tmp = tempdir_unique();
        let path = tmp.join("hook.json");
        std::fs::write(&path, r#"{"_agentdr": "AgentDR managed — do not edit by hand"}"#).unwrap();
        let mut g = new_guard("test hook", path.clone(), GuardKind::HookConfig { agent: "test" });
        refresh_one(&mut g);
        assert!(g.last_marker_present);

        // Operator (or evasive agent) wipes the marker.
        std::fs::write(&path, r#"{"other": "stuff"}"#).unwrap();
        let wd = make_wd();
        let ev = wd.check_one(&mut g).expect("should fire");
        assert_eq!(ev.event_type, "watchdog_evasion_detected");
        assert_eq!(ev.risk_level, "critical");
        assert_eq!(ev.status_id, Some(STATUS_BLOCKED));
        assert_eq!(ev.agent_detected.as_deref(), Some("test"));
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn hook_change_with_marker_intact_is_informational() {
        let tmp = tempdir_unique();
        let path = tmp.join("hook.json");
        std::fs::write(&path, r#"{"_agentdr": "AgentDR managed — do not edit by hand", "env": {"X": "1"}}"#).unwrap();
        let mut g = new_guard("test hook", path.clone(), GuardKind::HookConfig { agent: "test" });
        refresh_one(&mut g);
        // Operator edits a value but keeps the marker.
        std::fs::write(&path, r#"{"_agentdr": "AgentDR managed — do not edit by hand", "env": {"X": "2"}}"#).unwrap();
        let wd = make_wd();
        let ev = wd.check_one(&mut g).expect("should fire");
        assert_eq!(ev.event_type, "watchdog_config_changed");
        assert_eq!(ev.risk_level, "low");
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn deletion_is_critical() {
        let tmp = tempdir_unique();
        let path = tmp.join("hook.json");
        std::fs::write(&path, r#"{"_agentdr": "AgentDR managed — do not edit by hand"}"#).unwrap();
        let mut g = new_guard("test hook", path.clone(), GuardKind::HookConfig { agent: "test" });
        refresh_one(&mut g);
        std::fs::remove_file(&path).unwrap();
        let wd = make_wd();
        let ev = wd.check_one(&mut g).expect("should fire");
        assert_eq!(ev.event_type, "watchdog_file_missing");
        assert_eq!(ev.risk_level, "critical");
        let _ = std::fs::remove_dir_all(tmp);
    }

    fn tempdir_unique() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos()).unwrap_or(0);
        let p = std::env::temp_dir()
            .join(format!("agentdr-wd-{}-{}-{}", std::process::id(), nanos, n));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
