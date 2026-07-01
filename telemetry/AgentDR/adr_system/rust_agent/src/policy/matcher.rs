//! YAML matcher AST. Compiles to a tree of predicates over
//! `serde_json::Value` (the serialized EventRecord) with cheap
//! dotted-path navigation.
//!
//! Operator-friendly YAML shape (Sigma / Falco style):
//!
//! ```yaml
//! when:
//!   all:
//!     - field: class_uid
//!       eq: 2004        # OCSF Detection Finding (ai_operation=data_exfiltration)
//!     - field: details.path
//!       regex: "\\.aws/credentials"
//!     - not:
//!         field: actor.user
//!         in: ["root", "ec2-user"]
//! ```
//!
//! Each matcher node is a struct with optional combinator fields
//! (`all`, `any`, `not`) and an optional leaf (`field` + one operator
//! key). Empty matchers (all fields None) evaluate to true.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Match {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<Match>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<Match>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not: Option<Box<Match>>,

    /// Dotted path to a field on the EventRecord, e.g. `details.path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,

    // ── Operators (mutually exclusive; only one is set per leaf) ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eq: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ne: Option<Value>,
    #[serde(default, alias = "in", skip_serializing_if = "Option::is_none", rename = "in")]
    pub in_: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_in: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_contains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starts_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ends_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gt: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gte: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lt: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lte: Option<f64>,
    /// `exists: {}` truthy — present-and-non-null check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exists: Option<Value>,
    /// `missing: {}` truthy — absent or null check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<Value>,
}

impl Match {
    pub fn evaluate(&self, event: &Value) -> bool {
        if let Some(list) = &self.all {
            if !list.iter().all(|m| m.evaluate(event)) { return false; }
        }
        if let Some(list) = &self.any {
            if !list.iter().any(|m| m.evaluate(event)) { return false; }
        }
        if let Some(inner) = &self.not {
            if inner.evaluate(event) { return false; }
        }
        if let Some(field) = &self.field {
            if !self.evaluate_leaf(event, field) { return false; }
        }
        true
    }

    fn evaluate_leaf(&self, event: &Value, field: &str) -> bool {
        let actual = pick(event, field);
        if self.exists.is_some() {
            return actual.map(|v| !v.is_null()).unwrap_or(false);
        }
        if self.missing.is_some() {
            return actual.map(|v| v.is_null()).unwrap_or(true);
        }
        let Some(a) = actual else { return false };
        if a.is_null() { return false; }

        if let Some(want) = &self.eq          { return a == want; }
        if let Some(want) = &self.ne          { return a != want; }
        if let Some(list) = &self.in_         { return list.iter().any(|w| w == a); }
        if let Some(list) = &self.not_in      { return list.iter().all(|w| w != a); }
        if let Some(s)    = &self.contains    { return as_str(a).map(|x|  x.contains(s)).unwrap_or(false); }
        if let Some(s)    = &self.not_contains{ return as_str(a).map(|x| !x.contains(s)).unwrap_or(false); }
        if let Some(s)    = &self.starts_with { return as_str(a).map(|x|  x.starts_with(s)).unwrap_or(false); }
        if let Some(s)    = &self.ends_with   { return as_str(a).map(|x|  x.ends_with(s)).unwrap_or(false); }
        if let Some(pat)  = &self.regex {
            return cached_regex(pat)
                .and_then(|r| as_str(a).map(|x| r.is_match(&x)))
                .unwrap_or(false);
        }
        if let Some(n) = self.gt  { return as_num(a).map(|x| x >  n).unwrap_or(false); }
        if let Some(n) = self.gte { return as_num(a).map(|x| x >= n).unwrap_or(false); }
        if let Some(n) = self.lt  { return as_num(a).map(|x| x <  n).unwrap_or(false); }
        if let Some(n) = self.lte { return as_num(a).map(|x| x <= n).unwrap_or(false); }

        // No operator set → treat as "field exists" check.
        true
    }
}

fn pick<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for part in path.split('.') {
        match cur {
            Value::Object(m) => match m.get(part) {
                Some(next) => cur = next,
                None => return None,
            },
            Value::Array(a) => {
                let idx: usize = match part.parse() { Ok(n) => n, Err(_) => return None };
                cur = a.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

fn as_num(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        Value::Bool(b)   => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

fn as_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b)   => Some(b.to_string()),
        Value::Null      => None,
        _ => Some(serde_json::to_string(v).unwrap_or_default()),
    }
}

fn cached_regex(pat: &str) -> Option<&'static Regex> {
    static CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<String, &'static Regex>>> = OnceLock::new();
    let map = CACHE.get_or_init(|| std::sync::Mutex::new(Default::default()));
    let mut g = map.lock().ok()?;
    if let Some(r) = g.get(pat) { return Some(*r); }
    let r = Regex::new(pat).ok()?;
    let leaked: &'static Regex = Box::leak(Box::new(r));
    g.insert(pat.to_string(), leaked);
    Some(leaked)
}

// ── tests ────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev() -> Value {
        json!({
            "class_uid": 2004,
            "ai_operation": "data_exfiltration",
            "risk_level": "critical",
            "details": { "path": "/home/u/.aws/credentials" },
            "actor": { "user": "david" },
        })
    }

    #[test]
    fn yaml_all_and_contains() {
        let y = r#"
all:
  - field: class_uid
    eq: 2004
  - field: details.path
    contains: ".aws/credentials"
"#;
        let m: Match = serde_yaml::from_str(y).unwrap();
        assert!(m.evaluate(&ev()));
    }

    #[test]
    fn yaml_not_in() {
        let y = r#"
not:
  field: actor.user
  in: ["root", "ec2-user"]
"#;
        let m: Match = serde_yaml::from_str(y).unwrap();
        assert!(m.evaluate(&ev()));
    }

    #[test]
    fn yaml_regex() {
        let y = r#"
field: details.path
regex: "\\.aws/credentials$"
"#;
        let m: Match = serde_yaml::from_str(y).unwrap();
        assert!(m.evaluate(&ev()));
    }

    #[test]
    fn yaml_missing() {
        let y = r#"
field: tool_name
missing: {}
"#;
        let m: Match = serde_yaml::from_str(y).unwrap();
        assert!(m.evaluate(&ev()));
    }
}
