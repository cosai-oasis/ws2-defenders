//! Discovery policy loader.
//!
//! Loads YAML of the shape (see cosai-community/policies/discovery.yaml):
//!
//!     defaults:
//!       coding: monitor
//!       browser: prompt
//!       ...
//!     agents:
//!       - id: openclaw
//!         decision: monitor
//!         self_heal: true
//!
//! `decide(agent)` evaluates per-agent rules first, then category
//! defaults, then a global fallback of `Skip`.

use super::scan::DiscoveredAgent;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Monitor,
    Prompt,
    Skip,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryPolicy {
    #[serde(default)]
    pub defaults: BTreeMap<String, String>,
    #[serde(default)]
    pub agents: Vec<AgentRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRule {
    pub id: String,
    pub decision: String,
    #[serde(default)]
    pub self_heal: bool,
}

impl DiscoveryPolicy {
    pub fn decide(&self, agent: &DiscoveredAgent) -> PolicyDecision {
        // Per-agent rule first
        if let Some(rule) = self.agents.iter().find(|r| r.id == agent.id) {
            return parse_decision(&rule.decision);
        }
        // Category default
        if let Some(s) = self.defaults.get(&agent.category) {
            return parse_decision(s);
        }
        PolicyDecision::Skip
    }

    /// True if a per-agent override says self-heal for this agent.
    pub fn self_heal_for(&self, agent_id: &str) -> bool {
        self.agents.iter().any(|r| r.id == agent_id && r.self_heal)
    }
}

fn parse_decision(s: &str) -> PolicyDecision {
    match s.trim().to_ascii_lowercase().as_str() {
        "monitor" => PolicyDecision::Monitor,
        "prompt"  => PolicyDecision::Prompt,
        _          => PolicyDecision::Skip,
    }
}

/// Discover and parse a policy file. If `override_path` is empty, fall
/// through the standard search locations.
pub fn load(override_path: &str) -> Result<DiscoveryPolicy, String> {
    let candidates = if !override_path.is_empty() {
        vec![PathBuf::from(override_path)]
    } else {
        default_paths()
    };
    for p in &candidates {
        if !p.exists() { continue; }
        let body = std::fs::read_to_string(p)
            .map_err(|e| format!("read {}: {e}", p.display()))?;
        let pol: DiscoveryPolicy = serde_yaml::from_str(&body)
            .map_err(|e| format!("parse {}: {e}", p.display()))?;
        return Ok(pol);
    }
    Err(format!(
        "no discovery policy found (searched: {})",
        candidates.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
    ))
}

fn default_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            out.push(parent.join("../cosai-community/policies/discovery.yaml"));
        }
    }
    out.push(PathBuf::from("cosai-community/policies/discovery.yaml"));
    out.push(PathBuf::from("/etc/agentdr/discovery.yaml"));
    out
}

impl Default for DiscoveryPolicy {
    fn default() -> Self {
        // Sane minimal defaults if no YAML file is found:
        // monitor coding agents, prompt on browser-use, skip enterprise.
        let mut defaults: BTreeMap<String, String> = BTreeMap::new();
        for k in ["coding", "general", "workflow"] {
            defaults.insert(k.into(), "monitor".into());
        }
        defaults.insert("browser".into(), "prompt".into());
        defaults.insert("enterprise".into(), "skip".into());
        Self { defaults, agents: Vec::new() }
    }
}
