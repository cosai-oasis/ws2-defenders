//! Pattern detection engine — all 20 CoSAI detection rules + Tier 6
//! credential attribution.

use crate::config::DetectionConfig;
use crate::models::*;
use serde_json::json;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

type TimedEntry = (Instant, String);
type TimedSize = (Instant, u64);

/// Active agent process tracked for Tier 6 credential attribution.
#[derive(Debug, Clone)]
struct ActiveAgent {
    seen_at: Instant,
    pid: u32,
    agent_name: String,
    agent_framework: Option<String>,
    user: Option<String>,
    exe: Option<String>,
}

pub struct PatternDetector {
    cfg: DetectionConfig,
    // Original rule trackers
    file_mod_times: VecDeque<TimedEntry>,
    api_call_times: VecDeque<Instant>,
    deleted_sizes: VecDeque<TimedSize>,
    // New agent-specific trackers
    skill_file_events: VecDeque<TimedEntry>,
    messaging_events: VecDeque<TimedEntry>,
    shell_exec_events: VecDeque<TimedEntry>,
    credential_access_events: VecDeque<TimedEntry>,
    ai_api_hosts: VecDeque<TimedEntry>,
    messaging_hosts: VecDeque<TimedEntry>,
    /// Tier 6 — running window of AI-agent processes for credential
    /// attribution. We don't always know which PID actually read the
    /// credential file (the file monitor on Linux/macOS doesn't carry
    /// PIDs), so we list all live agent processes and let SOC narrow
    /// down. The window is 10 minutes by default.
    active_agents: VecDeque<ActiveAgent>,
}

impl PatternDetector {
    pub fn new(cfg: DetectionConfig) -> Self {
        Self {
            cfg,
            file_mod_times: VecDeque::new(),
            api_call_times: VecDeque::new(),
            deleted_sizes: VecDeque::new(),
            skill_file_events: VecDeque::new(),
            messaging_events: VecDeque::new(),
            shell_exec_events: VecDeque::new(),
            credential_access_events: VecDeque::new(),
            ai_api_hosts: VecDeque::new(),
            messaging_hosts: VecDeque::new(),
            active_agents: VecDeque::new(),
        }
    }

    /// Window for credential attribution. We retain agent process events
    /// for this long after they fire.
    const ATTRIBUTION_WINDOW: Duration = Duration::from_secs(600);

    fn record_agent_process(&mut self, event: &EventRecord) {
        // Only track process_started events with an identified agent.
        if event.event_type != "process_started" { return; }
        let Some(agent_name) = event.agent_name.clone() else { return; };
        let pid = event.actor.as_ref()
            .and_then(|a| a.get("pid"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let user = event.actor.as_ref()
            .and_then(|a| a.get("user"))
            .and_then(|v| v.as_str()).map(String::from);
        let exe = event.details.get("exe").and_then(|v| v.as_str()).map(String::from);
        self.active_agents.push_back(ActiveAgent {
            seen_at: Instant::now(),
            pid,
            agent_name,
            agent_framework: event.agent_framework.clone(),
            user,
            exe,
        });
        // Hard cap so a noisy host doesn't unbounded-grow.
        while self.active_agents.len() > 256 { self.active_agents.pop_front(); }
    }

    fn prune_attribution(&mut self, now: Instant) {
        let cutoff = now - Self::ATTRIBUTION_WINDOW;
        while self.active_agents.front().map_or(false, |a| a.seen_at < cutoff) {
            self.active_agents.pop_front();
        }
    }

    fn attribute(&self) -> Vec<serde_json::Value> {
        self.active_agents.iter().map(|a| json!({
            "pid":         a.pid,
            "agent_name":  a.agent_name,
            "framework":   a.agent_framework,
            "user":        a.user,
            "exe":         a.exe,
            "age_seconds": a.seen_at.elapsed().as_secs(),
        })).collect()
    }

    /// Analyze an event and return any alerts it triggers.
    pub fn analyze(&mut self, event: &EventRecord) -> Vec<EventRecord> {
        let mut alerts = Vec::new();
        let now = Instant::now();
        let et = event.event_type.as_str();
        let details = &event.details;

        // Tier 6 — feed the per-process attribution window.
        self.record_agent_process(event);
        self.prune_attribution(now);

        // Original rules
        if et == "file_modified" {
            alerts.extend(self.check_rapid_modifications(event, now));
        }
        if et == "network_request" {
            alerts.extend(self.check_api_volume(event, now));
        }
        if et == "file_deleted" {
            alerts.extend(self.check_large_deletions(event, now));
        }

        // DET-015: Malicious skill/plugin
        if (et == "file_created" || et == "file_modified") && details.get("is_skill_path") == Some(&json!(true)) {
            alerts.extend(self.check_skill_plugin(event, now));
        }

        // DET-016: Unauthorized messaging
        if et == "messaging_channel_access" {
            alerts.extend(self.check_messaging_channel(event));
        }

        // DET-017: Shell command execution
        if et == "process_started" && self.is_shell_process(event) {
            alerts.extend(self.check_shell_execution(event, now));
        }

        // DET-018: Credential access
        if matches!(et, "file_created" | "file_modified" | "file_read") && is_credential_file(details.get("path").and_then(|v| v.as_str()).unwrap_or("")) {
            alerts.extend(self.check_credential_access(event));
        }

        // DET-019: Cross-platform data relay
        if et == "network_request" || et == "messaging_channel_access" {
            let host = details.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if details.get("ai_provider").is_some() {
                self.ai_api_hosts.push_back((now, host.clone()));
            }
            if details.get("messaging_platform").and_then(|v| v.as_str()).is_some() {
                self.messaging_hosts.push_back((now, host));
            }
            alerts.extend(self.check_cross_platform_relay(event, now));
        }

        // DET-020: Unvetted skill installation
        if et == "file_created" && details.get("is_skill_path") == Some(&json!(true)) {
            alerts.extend(self.check_unvetted_skill(event));
        }

        alerts
    }

    // ── Alert builder ──

    fn make_alert(
        &self,
        rule_id: &str,
        event_type: &str,
        details: serde_json::Value,
        risk: &str,
        agent_detected: Option<&str>,
        parent_trace_id: Option<&str>,
    ) -> EventRecord {
        let rules = detection_rules();
        let rule = rules.get(rule_id);
        // Detections are findings: the rule's ai_operation yields the reused
        // OCSF finding class (Detection 2004 / Compliance 2003 / Vulnerability 2002).
        let op = rule.map(|r| r.op).unwrap_or(AiOperation::GuardrailEvent);

        let mut ev = EventRecord::new(event_type, json!({
            "rule_id": rule_id,
            "rule_name": rule.map(|r| r.name).unwrap_or("Unknown"),
            "owasp_category": rule.map(|r| r.owasp).unwrap_or("LLM00"),
            "alert_details": details,
        }), risk);
        ev.source = Some("detector".into());
        ev.set_op(op, ACTIVITY_DETECT);
        ev.activity_id = Some(ACTIVITY_DETECT);
        ev.status_id = Some(STATUS_SUCCESS);
        ev.message = Some(format!("[{}] {}", rule_id, rule.map(|r| r.name).unwrap_or(event_type)));
        ev.agent_detected = agent_detected.map(|s| s.to_string());
        ev.security_finding = Some(json!({
            "rule_id": rule_id,
            "title": rule.map(|r| r.name).unwrap_or("Unknown"),
            "severity": risk,
            "owasp_llm": rule.map(|r| r.owasp).unwrap_or("LLM00"),
        }));
        ev.compliance = Some(json!({
            "frameworks": ["OWASP-LLM-Top10", "NIST-AI-RMF"],
            "mappings": { "OWASP-LLM-Top10": rule.map(|r| r.owasp).unwrap_or("LLM00") },
        }));
        if let Some(tid) = parent_trace_id {
            ev.trace_id = tid.to_string();
        }
        ev
    }

    // ── DET-009: Rapid file modifications ──

    fn check_rapid_modifications(&mut self, event: &EventRecord, now: Instant) -> Vec<EventRecord> {
        let rule = &self.cfg.rapid_file_modifications;
        if !rule.enabled { return Vec::new(); }

        let path = event.details.get("path").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        self.file_mod_times.push_back((now, path));
        let cutoff = now - std::time::Duration::from_secs(rule.window_seconds);
        while self.file_mod_times.front().map_or(false, |(t, _)| *t < cutoff) {
            self.file_mod_times.pop_front();
        }

        let unique: std::collections::HashSet<&str> = self.file_mod_times.iter().map(|(_, p)| p.as_str()).collect();
        let count = unique.len();
        if count <= rule.threshold_count { return Vec::new(); }

        let risk = if count <= rule.threshold_count * 2 { "high" } else { "critical" };
        vec![self.make_alert("AITF-DET-009", "alert_rapid_file_modifications",
            json!({ "count": count, "window_seconds": rule.window_seconds, "threshold": rule.threshold_count }),
            risk, Some("possible_agent_automation"), Some(&event.trace_id))]
    }

    // ── DET-012: Unusual API volume ──

    fn check_api_volume(&mut self, event: &EventRecord, now: Instant) -> Vec<EventRecord> {
        let rule = &self.cfg.unusual_api_call_volume;
        if !rule.enabled { return Vec::new(); }

        self.api_call_times.push_back(now);
        let cutoff = now - std::time::Duration::from_secs(rule.window_seconds);
        while self.api_call_times.front().map_or(false, |t| *t < cutoff) {
            self.api_call_times.pop_front();
        }

        let count = self.api_call_times.len();
        if count <= rule.threshold_count { return Vec::new(); }

        let risk = if count <= rule.threshold_count * 2 { "medium" } else { "high" };
        vec![self.make_alert("AITF-DET-012", "alert_unusual_api_call_volume",
            json!({ "count": count, "window_seconds": rule.window_seconds, "threshold": rule.threshold_count }),
            risk, Some("possible_agent_networking"), Some(&event.trace_id))]
    }

    // ── DET-010: Large file deletions ──

    fn check_large_deletions(&mut self, event: &EventRecord, now: Instant) -> Vec<EventRecord> {
        let rule = &self.cfg.large_file_deletions;
        if !rule.enabled { return Vec::new(); }

        let size = event.details.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        self.deleted_sizes.push_back((now, size));
        let cutoff = now - std::time::Duration::from_secs(rule.window_seconds);
        while self.deleted_sizes.front().map_or(false, |(t, _)| *t < cutoff) {
            self.deleted_sizes.pop_front();
        }

        let mut alerts = Vec::new();
        let single_threshold = (rule.single_file_mb * 1024.0 * 1024.0) as u64;
        let total_threshold = (rule.window_total_mb * 1024.0 * 1024.0) as u64;
        let window_total: u64 = self.deleted_sizes.iter().map(|(_, s)| *s).sum();

        if size >= single_threshold {
            alerts.push(self.make_alert("AITF-DET-010", "alert_large_file_deleted",
                json!({ "size_bytes": size, "threshold_mb": rule.single_file_mb }),
                "high", Some("possible_agent_cleanup"), Some(&event.trace_id)));
        }
        if window_total >= total_threshold {
            alerts.push(self.make_alert("AITF-DET-010", "alert_bulk_file_deletions",
                json!({ "total_deleted_bytes": window_total, "threshold_mb": rule.window_total_mb }),
                "critical", Some("possible_destructive_behavior"), Some(&event.trace_id)));
        }
        alerts
    }

    // ── DET-015: Malicious skill/plugin ──

    fn check_skill_plugin(&mut self, event: &EventRecord, now: Instant) -> Vec<EventRecord> {
        let rule = &self.cfg.malicious_skill_plugin;
        if !rule.enabled { return Vec::new(); }

        let path = event.details.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        self.skill_file_events.push_back((now, path.clone()));
        let cutoff = now - std::time::Duration::from_secs(rule.window_seconds);
        while self.skill_file_events.front().map_or(false, |(t, _)| *t < cutoff) {
            self.skill_file_events.pop_front();
        }

        let suspicious_exts = [".py", ".js", ".sh", ".bat", ".exe", ".dll", ".so"];
        let is_exec = suspicious_exts.iter().any(|ext| path.ends_with(ext));
        let burst = self.skill_file_events.len() >= rule.threshold_count;

        if !is_exec && !burst { return Vec::new(); }

        let risk = if burst { "critical" } else { "high" };
        vec![self.make_alert("AITF-DET-015", "alert_malicious_skill_plugin",
            json!({ "path": path, "is_executable": is_exec, "skill_files_in_window": self.skill_file_events.len() }),
            risk, Some("openclaw_skill_install"), Some(&event.trace_id))]
    }

    // ── DET-016: Unauthorized messaging ──

    fn check_messaging_channel(&mut self, event: &EventRecord) -> Vec<EventRecord> {
        if !self.cfg.unauthorized_messaging.enabled { return Vec::new(); }

        let platform = event.details.get("messaging_platform").and_then(|v| v.as_str()).unwrap_or("unknown");
        let host = event.details.get("host").and_then(|v| v.as_str()).unwrap_or("");

        vec![self.make_alert("AITF-DET-016", "alert_unauthorized_messaging",
            json!({ "platform": platform, "host": host }),
            "high", Some("messaging_agent"), Some(&event.trace_id))]
    }

    // ── DET-017: Shell command execution ──

    fn check_shell_execution(&mut self, event: &EventRecord, now: Instant) -> Vec<EventRecord> {
        let rule = &self.cfg.shell_command_execution;
        if !rule.enabled { return Vec::new(); }

        let cmd = event.details.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        self.shell_exec_events.push_back((now, cmd.clone()));
        let cutoff = now - std::time::Duration::from_secs(rule.window_seconds);
        while self.shell_exec_events.front().map_or(false, |(t, _)| *t < cutoff) {
            self.shell_exec_events.pop_front();
        }

        let count = self.shell_exec_events.len();
        let risk = if count >= rule.threshold_count { "critical" } else { "high" };
        vec![self.make_alert("AITF-DET-017", "alert_shell_command_execution",
            json!({ "command": cmd, "count": count }),
            risk, Some("shell_executing_agent"), Some(&event.trace_id))]
    }

    // ── DET-018: Credential access ──

    fn check_credential_access(&mut self, event: &EventRecord) -> Vec<EventRecord> {
        if !self.cfg.credential_access.enabled { return Vec::new(); }

        let path = event.details.get("path").and_then(|v| v.as_str()).unwrap_or("");
        // Tier 6 attribution: list every agent process active in the
        // attribution window so SOC can pivot from "credential file was
        // touched" to "Claude Code (pid 12345) was running at that moment".
        let suspects = self.attribute();
        vec![self.make_alert("AITF-DET-018", "alert_credential_access",
            json!({
                "path": path,
                "event_type": event.event_type,
                "candidate_agents": suspects,
                "attribution_window_seconds": Self::ATTRIBUTION_WINDOW.as_secs(),
            }),
            "critical", Some("credential_harvesting"), Some(&event.trace_id))]
    }

    // ── DET-019: Cross-platform data relay ──

    fn check_cross_platform_relay(&mut self, event: &EventRecord, now: Instant) -> Vec<EventRecord> {
        let rule = &self.cfg.cross_platform_relay;
        if !rule.enabled { return Vec::new(); }

        let cutoff = now - std::time::Duration::from_secs(rule.window_seconds);
        while self.ai_api_hosts.front().map_or(false, |(t, _)| *t < cutoff) {
            self.ai_api_hosts.pop_front();
        }
        while self.messaging_hosts.front().map_or(false, |(t, _)| *t < cutoff) {
            self.messaging_hosts.pop_front();
        }

        if self.ai_api_hosts.is_empty() || self.messaging_hosts.is_empty() {
            return Vec::new();
        }

        let ai: Vec<&str> = self.ai_api_hosts.iter().map(|(_, h)| h.as_str()).collect();
        let msg: Vec<&str> = self.messaging_hosts.iter().map(|(_, h)| h.as_str()).collect();

        vec![self.make_alert("AITF-DET-019", "alert_cross_platform_relay",
            json!({ "ai_api_hosts": ai, "messaging_hosts": msg, "window_seconds": rule.window_seconds }),
            "critical", Some("data_relay_agent"), Some(&event.trace_id))]
    }

    // ── DET-020: Unvetted skill installation ──

    fn check_unvetted_skill(&self, event: &EventRecord) -> Vec<EventRecord> {
        if !self.cfg.unvetted_skill_install.enabled { return Vec::new(); }

        let path = event.details.get("path").and_then(|v| v.as_str()).unwrap_or("");
        vec![self.make_alert("AITF-DET-020", "alert_unvetted_skill_installation",
            json!({ "path": path, "size_bytes": event.details.get("size_bytes") }),
            "high", Some("skill_installer"), Some(&event.trace_id))]
    }

    // ── Helpers ──

    fn is_shell_process(&self, event: &EventRecord) -> bool {
        let name = event.details.get("name").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        let shells = ["bash", "sh", "zsh", "cmd", "powershell", "pwsh", "fish"];
        shells.iter().any(|s| name == *s || name.contains(s))
    }
}
