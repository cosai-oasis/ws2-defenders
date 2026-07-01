//! Policy engine. Loads policies from YAML at startup, evaluates every
//! event against every policy, and emits Compliance Finding events (OCSF
//! 2003, ai_operation=compliance_violation) for matches with the
//! appropriate Decision attached.

use super::matcher::Match;
use crate::models::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// What to do when a policy matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Just log a record (no severity escalation).
    Log,
    /// Emit a Compliance Finding event (OCSF 2003).
    Alert,
    /// Same as Alert, plus signal upstream consumers (the proxy) to
    /// drop the in-flight network attempt.
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_severity")]
    pub severity: String,                  // low | medium | high | critical
    #[serde(default = "default_action")]
    pub action: Action,
    pub when: Match,
    /// Optional reason text included on the emitted alert.
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional compliance framework tags (OWASP-LLM-Top10, NIST-AI-RMF, ...).
    #[serde(default)]
    pub compliance: Vec<String>,
}

fn default_severity() -> String { "medium".into() }
fn default_action() -> Action { Action::Alert }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPack {
    #[serde(default)]
    pub policies: Vec<Policy>,
}

/// Outcome of evaluating an event against the whole pack.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    /// Strongest action across all matching policies.
    pub action: Action,
    pub matched: Vec<MatchedPolicy>,
    pub events: Vec<EventRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchedPolicy {
    pub id: String,
    pub name: String,
    pub action: Action,
    pub severity: String,
    pub reason: Option<String>,
}

pub struct PolicyEngine {
    policies: Vec<Policy>,
    source: PathBuf,
}

impl PolicyEngine {
    pub fn empty() -> Self {
        Self { policies: Vec::new(), source: PathBuf::new() }
    }

    /// Discover a policy pack: prefer the explicit path, else the
    /// canonical `cosai-community/policies/policies.yaml` next to the
    /// agent binary.
    pub fn load_default() -> Self {
        let candidates = default_paths();
        for p in &candidates {
            if p.exists() {
                match Self::load_from(p) {
                    Ok(e) => return e,
                    Err(err) => {
                        eprintln!("[policy] {} failed to load: {}", p.display(), err);
                    }
                }
            }
        }
        Self::empty()
    }

    pub fn load_from(path: &Path) -> Result<Self, String> {
        let body = std::fs::read_to_string(path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        let pack: PolicyPack = serde_yaml::from_str(&body)
            .map_err(|e| format!("parse {}: {e}", path.display()))?;
        Ok(Self { policies: pack.policies, source: path.to_path_buf() })
    }

    pub fn len(&self) -> usize { self.policies.len() }
    pub fn source(&self) -> &Path { &self.source }
    pub fn is_empty(&self) -> bool { self.policies.is_empty() }

    /// Evaluate `event` against every policy. Returns the strongest
    /// action and one EventRecord per match (Compliance Finding, OCSF 2003).
    pub fn evaluate(&self, event: &EventRecord) -> Decision {
        let serialized = serde_json::to_value(event).unwrap_or(Value::Null);
        let mut matched: Vec<MatchedPolicy> = Vec::new();
        let mut events:  Vec<EventRecord>   = Vec::new();
        let mut strongest = Action::Log;

        for pol in &self.policies {
            if !pol.when.evaluate(&serialized) { continue; }
            if action_rank(pol.action) > action_rank(strongest) {
                strongest = pol.action;
            }
            matched.push(MatchedPolicy {
                id: pol.id.clone(),
                name: pol.name.clone(),
                action: pol.action,
                severity: pol.severity.clone(),
                reason: pol.reason.clone(),
            });
            events.push(make_violation_event(pol, event));
        }

        Decision { action: strongest, matched, events }
    }
}

fn action_rank(a: Action) -> u8 {
    match a { Action::Log => 1, Action::Alert => 2, Action::Block => 3 }
}

fn make_violation_event(pol: &Policy, src: &EventRecord) -> EventRecord {
    let activity = match pol.action {
        Action::Block => ACTIVITY_BLOCK,
        _             => ACTIVITY_DETECT,
    };
    let mut ev = EventRecord::new(
        match pol.action {
            Action::Block => "policy_block",
            Action::Alert => "policy_alert",
            Action::Log   => "policy_log",
        },
        json!({
            "policy_id":   pol.id,
            "policy_name": pol.name,
            "severity":    pol.severity,
            "reason":      pol.reason,
            "source_event_type": src.event_type,
        }),
        &pol.severity,
    );
    ev.set_op(AiOperation::ComplianceViolation, activity);
    ev.activity_id = Some(activity);
    ev.status_id = if matches!(pol.action, Action::Block) {
        Some(STATUS_BLOCKED)
    } else {
        Some(STATUS_SUCCESS)
    };
    ev.source = Some("policy".into());
    ev.message = Some(format!(
        "[{}] {}{}",
        pol.id,
        pol.name,
        pol.reason.as_ref().map(|r| format!(": {}", r)).unwrap_or_default(),
    ));
    ev.trace_id = src.trace_id.clone();
    ev.security_finding = Some(json!({
        "rule_id":  pol.id,
        "title":    pol.name,
        "severity": pol.severity,
        "policy":   true,
    }));
    if !pol.compliance.is_empty() {
        ev.compliance = Some(json!({
            "frameworks": pol.compliance,
        }));
    }
    // Carry over identity / agent context so downstream filters work
    ev.agent_name = src.agent_name.clone();
    ev.agent_framework = src.agent_framework.clone();
    ev.provider = src.provider.clone();
    ev.model = src.model.clone();
    ev.tool_name = src.tool_name.clone();
    ev.mcp_server = src.mcp_server.clone();
    ev.actor = src.actor.clone();
    ev
}

fn default_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            out.push(parent.join("../cosai-community/policies/policies.yaml"));
            out.push(parent.join("../cosai-community/policies/policy.yaml"));
        }
    }
    out.push(PathBuf::from("cosai-community/policies/policies.yaml"));
    out.push(PathBuf::from("/etc/agentdr/policies.yaml"));
    out
}
