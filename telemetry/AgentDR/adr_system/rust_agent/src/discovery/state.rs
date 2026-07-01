//! Persisted record of past discovery decisions so we don't re-prompt
//! the user (or re-apply policy) for an agent they've already answered
//! about.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryState {
    #[serde(default)]
    pub decisions: BTreeMap<String, RecordedDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedDecision {
    /// "monitor" | "skip"
    pub decision: String,
    /// Where the decision came from: "state" | "policy" | "tty" | "automatic" | ...
    pub source:   String,
    /// RFC3339 timestamp.
    pub decided_at: String,
}

impl DiscoveryState {
    pub fn load(path: &Path) -> Option<Self> {
        let body = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&body).ok()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, body).map_err(|e| e.to_string())
    }

    pub fn decision_for(&self, agent_id: &str) -> Option<&RecordedDecision> {
        self.decisions.get(agent_id)
    }

    /// Insert / overwrite a decision.
    pub fn record(&mut self, agent_id: &str, decision: &str, source: &str) {
        self.decisions.insert(agent_id.into(), RecordedDecision {
            decision: decision.into(),
            source: source.into(),
            decided_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });
    }
}
