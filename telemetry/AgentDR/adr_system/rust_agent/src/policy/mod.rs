//! Tier 5 — policy-as-code over CoSAI AITF events.
//!
//! Policies live in YAML under `cosai-community/policies/policies.yaml` and
//! describe a match condition over an EventRecord plus an action
//! (`alert | block | log`). The engine evaluates every policy against
//! every event the agent observes and emits a Compliance Finding (OCSF 2003,
//! ai_operation=compliance_violation) event for each match. The inline blocking proxy
//! (`src/proxy/`) re-uses the same engine so deny decisions are
//! policy-driven end-to-end.
//!
//! Why YAML matchers and not CEL/Rego: zero new heavy deps, deterministic
//! evaluation, easily diffable in PRs, and operators familiar with
//! Falco/Sigma will recognise the shape. The matcher is intentionally
//! small (~150 LoC) and ships with field-path navigation, regex,
//! contains, in-list, numeric comparisons and `all`/`any`/`not`
//! composition.

pub mod engine;
pub mod matcher;

pub use engine::{Action, PolicyEngine};
#[allow(unused_imports)]
pub use engine::{Decision, Policy};
#[allow(unused_imports)]
pub use matcher::Match;
