//! Tier 8 — auto-discovery of AI agents on the host.
//!
//! Goes beyond `agents::list()` (which only checks $PATH + hook state) by
//! examining known install locations, package-manager footprints, hook
//! config presence even when the binary is absent, MCP config entries
//! and recently-running PIDs. The result is a list of `DiscoveredAgent`s
//! with weighted evidence and a recommended action.
//!
//! Decision modes (see config.rs::DiscoveryConfig):
//!   - off         : scan and report; never install
//!   - interactive : prompt the local user via stdin
//!   - policy      : apply `cosai-community/policies/discovery.yaml`
//!   - automatic   : install every supported agent that's found
//!
//! Recorded decisions are persisted to
//! `<root>/runtime/discovery-state.json` so the user is never asked
//! twice. The CLI exposes:
//!
//!     adr-agent discovery scan                # report only
//!     adr-agent discovery scan --apply        # scan + apply per mode
//!     adr-agent discovery prompt              # interactive prompt loop
//!     adr-agent discovery status              # show recorded decisions

pub mod policy;
pub mod prompt;
pub mod scan;
pub mod state;

pub use policy::{DiscoveryPolicy, PolicyDecision};
pub use scan::{DiscoveredAgent, ScanReport};
#[allow(unused_imports)]
pub use scan::Evidence;
pub use state::DiscoveryState;
#[allow(unused_imports)]
pub use state::RecordedDecision;

use crate::config::DiscoveryConfig;
use crate::hooks;
use serde::Serialize;
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Hook already installed (from a previous run or by hand).
    AlreadyMonitored,
    /// Install the hook now (silently).
    Monitor,
    /// Wait for an interactive prompt; never install without user consent.
    Prompt,
    /// Don't install. Operator opt-out, or `mode = off`.
    Skip,
}

/// One row in the apply-report — what we found, decided, did.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyRow {
    pub agent_id:    String,
    pub action:      Action,
    pub from:        &'static str, // policy | state | mode-default | tty
    pub result:      ApplyResult,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyResult {
    Skipped,
    Installed,
    AlreadyManaged,
    PromptDeferred,
    InstallFailed { error: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyReport {
    pub scanned: ScanReport,
    pub mode: String,
    pub actions: Vec<ApplyRow>,
}

/// Scan only (no mutations). Returns the discovery report verbatim so the
/// caller (CLI or engine) can render it.
pub fn scan_only() -> ScanReport {
    scan::scan()
}

/// Scan and apply per the configured mode. Honors persisted decisions
/// and refuses to prompt when stdin isn't a TTY. The agent's runtime
/// endpoint is needed so that "install hook" calls point hooks at the
/// right OTLP collector.
pub fn scan_and_apply(cfg: &DiscoveryConfig, root: &PathBuf, endpoint: &str) -> ApplyReport {
    let scan = scan::scan();
    let pol = match policy::load(&cfg.policy_path) {
        Ok(p) => p,
        Err(e) => {
            warn!("discovery: could not load policy ({e}); falling back to defaults");
            policy::DiscoveryPolicy::default()
        }
    };
    let mut st = state::DiscoveryState::load(&root.join(&cfg.state_file)).unwrap_or_default();
    let mode = ModeStr::parse(&cfg.mode);

    let interactive_possible = mode == ModeStr::Interactive && atty_stdin();

    let mut actions: Vec<ApplyRow> = Vec::new();
    for a in &scan.agents {
        let (action, from) = decide_one(a, mode, &pol, &st, interactive_possible);
        let result = match action {
            Action::AlreadyMonitored => ApplyResult::AlreadyManaged,
            Action::Skip             => ApplyResult::Skipped,
            Action::Prompt           => ApplyResult::PromptDeferred,
            Action::Monitor          => match hooks::install(&a.id, endpoint) {
                Ok(()) => {
                    st.record(&a.id, "monitor", from);
                    info!("discovery: installed hook for {}", a.id);
                    ApplyResult::Installed
                }
                Err(e) => {
                    warn!("discovery: install {} failed: {}", a.id, e);
                    ApplyResult::InstallFailed { error: e }
                }
            },
        };
        actions.push(ApplyRow {
            agent_id: a.id.clone(),
            action,
            from,
            result,
        });
    }

    // Save any new decisions
    let _ = st.save(&root.join(&cfg.state_file));

    ApplyReport { scanned: scan, mode: cfg.mode.clone(), actions }
}

/// Pure decision: given a discovered agent + mode + policy + state, what
/// should we do? Pulled out for testing.
pub fn decide_one(
    a: &DiscoveredAgent,
    mode: ModeStr,
    policy: &DiscoveryPolicy,
    state: &DiscoveryState,
    interactive_possible: bool,
) -> (Action, &'static str) {
    if a.already_monitored {
        return (Action::AlreadyMonitored, "hook-already-installed");
    }

    // User's prior decision wins over everything else.
    if let Some(d) = state.decision_for(&a.id) {
        return match d.decision.as_str() {
            "monitor" => (Action::Monitor, "state"),
            _         => (Action::Skip,    "state"),
        };
    }

    match mode {
        ModeStr::Off => (Action::Skip, "mode=off"),
        ModeStr::Automatic => (Action::Monitor, "mode=automatic"),
        ModeStr::Interactive => {
            if interactive_possible {
                (Action::Prompt, "mode=interactive")
            } else {
                // No TTY — fail safe to skip; operators can run
                // `adr-agent discovery prompt` later from a terminal.
                (Action::Skip, "mode=interactive-no-tty")
            }
        }
        ModeStr::Policy => match policy.decide(a) {
            PolicyDecision::Monitor => (Action::Monitor, "policy"),
            PolicyDecision::Skip    => (Action::Skip,    "policy"),
            PolicyDecision::Prompt  => {
                if interactive_possible {
                    (Action::Prompt, "policy+tty")
                } else {
                    (Action::Skip, "policy+no-tty")
                }
            }
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeStr {
    Off, Interactive, Policy, Automatic,
}
impl ModeStr {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "off"         => ModeStr::Off,
            "interactive" => ModeStr::Interactive,
            "automatic"   => ModeStr::Automatic,
            _             => ModeStr::Policy,
        }
    }
}

#[cfg(unix)]
fn atty_stdin() -> bool {
    use std::os::fd::AsRawFd;
    unsafe { libc::isatty(std::io::stdin().as_raw_fd()) == 1 }
}
#[cfg(not(unix))]
fn atty_stdin() -> bool { true } // best-effort fallback for non-unix

// ── tests ────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use scan::Evidence;

    fn agent(id: &str, category: &str) -> DiscoveredAgent {
        DiscoveredAgent {
            id: id.into(), name: id.into(), category: category.into(),
            confidence: 1.0,
            evidence: vec![Evidence::BinaryOnPath { path: "/x".into() }],
            already_monitored: false,
        }
    }

    #[test]
    fn state_wins_over_mode() {
        let mut st = DiscoveryState::default();
        st.record("foo", "skip", "test");
        let p = DiscoveryPolicy::default();
        let (a, from) = decide_one(&agent("foo", "coding"), ModeStr::Automatic, &p, &st, true);
        assert_eq!(a, Action::Skip);
        assert_eq!(from, "state");
    }

    #[test]
    fn already_monitored_short_circuits() {
        let mut a = agent("foo", "coding");
        a.already_monitored = true;
        let (act, from) = decide_one(&a, ModeStr::Automatic, &DiscoveryPolicy::default(),
                                     &DiscoveryState::default(), true);
        assert_eq!(act, Action::AlreadyMonitored);
        assert_eq!(from, "hook-already-installed");
    }

    #[test]
    fn no_tty_demotes_interactive_to_skip() {
        let (act, from) = decide_one(&agent("foo", "coding"), ModeStr::Interactive,
                                     &DiscoveryPolicy::default(), &DiscoveryState::default(), false);
        assert_eq!(act, Action::Skip);
        assert_eq!(from, "mode=interactive-no-tty");
    }

    #[test]
    fn policy_browser_default_is_prompt_then_skip_without_tty() {
        let p = DiscoveryPolicy::default(); // defaults: browser=prompt
        let (act, _) = decide_one(&agent("foo", "browser"), ModeStr::Policy, &p,
                                  &DiscoveryState::default(), false);
        assert_eq!(act, Action::Skip);
    }

    #[test]
    fn policy_enterprise_default_is_skip() {
        let p = DiscoveryPolicy::default(); // defaults: enterprise=skip
        let (act, _) = decide_one(&agent("foo", "enterprise"), ModeStr::Policy, &p,
                                  &DiscoveryState::default(), true);
        assert_eq!(act, Action::Skip);
    }
}
