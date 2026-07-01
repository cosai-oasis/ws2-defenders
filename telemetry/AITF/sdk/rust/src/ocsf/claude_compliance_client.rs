//! Claude Compliance Activity Feed poller (feature `client`).
//!
//! Pages through `GET /v1/compliance/activities` using the documented cursor
//! contract (`after_id` / `last_id` / `has_more`), invoking a handler for each
//! raw Activity record. Pair with [`ClaudeComplianceMapper`] to normalize the
//! records to OCSF. Ported from the Go `ocsf/claude_compliance_client.go`.
//!
//! Docs: <https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed>

use serde::Deserialize;
use serde_json::Value;

use crate::ocsf::claude_compliance::ClaudeComplianceMapper;
use crate::ocsf::AIBaseEvent;

/// The default Activity Feed endpoint.
pub const CLAUDE_COMPLIANCE_BASE_URL: &str = "https://api.anthropic.com/v1/compliance/activities";

/// The maximum page size the feed accepts.
pub const CLAUDE_COMPLIANCE_MAX_LIMIT: i64 = 5000;

/// Options for the Claude Compliance Activity Feed poller.
///
/// Repeatable filters (`activity_types`, `organization_ids`, `actor_ids`) are
/// encoded with array-bracket query keys (e.g. `activity_types[]`). `after_id`
/// lets a caller resume from a previously persisted cursor.
#[derive(Debug, Clone, Default)]
pub struct ActivityFeedOptions {
    pub activity_types: Vec<String>,
    pub organization_ids: Vec<String>,
    pub actor_ids: Vec<String>,
    pub created_at_gte: Option<String>,
    pub created_at_lt: Option<String>,
    pub after_id: Option<String>,
    /// Page size; default 100, valid range 1..=5000.
    pub limit: Option<i64>,
    /// Override the base URL (e.g. for a test server).
    pub base_url: Option<String>,
}

/// The decoded JSON envelope for a single feed page.
#[derive(Debug, Deserialize)]
struct ActivityFeedPage {
    #[serde(default)]
    data: Vec<Value>,
    #[serde(default)]
    has_more: bool,
    #[serde(default)]
    last_id: String,
}

/// Errors raised by the poller.
#[derive(Debug)]
pub enum Error {
    /// `limit` was outside the valid 1..=5000 range.
    InvalidLimit(i64),
    /// The HTTP transport failed.
    Http(String),
    /// A non-2xx HTTP status was returned.
    Status(u16, String),
    /// A response body could not be decoded.
    Decode(String),
    /// A user-supplied handler returned an error.
    Handler(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidLimit(l) => {
                write!(f, "limit must be between 1 and {CLAUDE_COMPLIANCE_MAX_LIMIT}, got {l}")
            }
            Error::Http(e) => write!(f, "http error: {e}"),
            Error::Status(code, body) => {
                write!(f, "compliance activities request failed: status {code}: {body}")
            }
            Error::Decode(e) => write!(f, "decode error: {e}"),
            Error::Handler(e) => write!(f, "handler error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Resolves and validates the effective limit (default 100, valid 1..=5000).
pub fn resolve_limit(limit: Option<i64>) -> Result<i64, Error> {
    let limit = limit.unwrap_or(100);
    if !(1..=CLAUDE_COMPLIANCE_MAX_LIMIT).contains(&limit) {
        return Err(Error::InvalidLimit(limit));
    }
    Ok(limit)
}

/// Builds the static (non-cursor) query parameters for a request, mirroring the
/// Go poller's array-bracket encoding. Returned as `(key, value)` pairs.
pub fn build_base_params(opts: &ActivityFeedOptions, limit: i64) -> Vec<(String, String)> {
    let mut params: Vec<(String, String)> = Vec::new();
    params.push(("limit".to_string(), limit.to_string()));
    for v in &opts.activity_types {
        params.push(("activity_types[]".to_string(), v.clone()));
    }
    for v in &opts.organization_ids {
        params.push(("organization_ids[]".to_string(), v.clone()));
    }
    for v in &opts.actor_ids {
        params.push(("actor_ids[]".to_string(), v.clone()));
    }
    if let Some(gte) = opts.created_at_gte.as_deref().filter(|s| !s.is_empty()) {
        params.push(("created_at.gte".to_string(), gte.to_string()));
    }
    if let Some(lt) = opts.created_at_lt.as_deref().filter(|s| !s.is_empty()) {
        params.push(("created_at.lt".to_string(), lt.to_string()));
    }
    params
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn encode_query(params: &[(String, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Pages the feed, invoking `handler` for each raw Activity record. Stops when
/// `has_more` is false, the handler returns an error, or a request fails.
pub fn for_each_activity<F>(
    api_key: &str,
    opts: &ActivityFeedOptions,
    mut handler: F,
) -> Result<(), Error>
where
    F: FnMut(Value) -> Result<(), String>,
{
    let limit = resolve_limit(opts.limit)?;
    let base_url = opts
        .base_url
        .clone()
        .unwrap_or_else(|| CLAUDE_COMPLIANCE_BASE_URL.to_string());
    let base_params = build_base_params(opts, limit);

    let mut cursor = opts.after_id.clone().unwrap_or_default();
    loop {
        let mut params = base_params.clone();
        if !cursor.is_empty() {
            params.push(("after_id".to_string(), cursor.clone()));
        }
        let req_url = format!("{base_url}?{}", encode_query(&params));

        let resp = ureq::get(&req_url)
            .set("x-api-key", api_key)
            .call();

        let response = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                return Err(Error::Status(code, body));
            }
            Err(e) => return Err(Error::Http(e.to_string())),
        };

        let body = response
            .into_string()
            .map_err(|e| Error::Http(e.to_string()))?;
        let page: ActivityFeedPage =
            serde_json::from_str(&body).map_err(|e| Error::Decode(e.to_string()))?;

        for activity in page.data {
            handler(activity).map_err(Error::Handler)?;
        }

        if !page.has_more {
            break;
        }
        cursor = page.last_id;
        if cursor.is_empty() {
            break;
        }
    }
    Ok(())
}

/// Convenience: pages the feed and returns every Activity mapped to an
/// [`AIBaseEvent`] via [`ClaudeComplianceMapper`].
pub fn collect_activities_as_events(
    api_key: &str,
    opts: &ActivityFeedOptions,
) -> Result<Vec<AIBaseEvent>, Error> {
    let mapper = ClaudeComplianceMapper::new();
    let mut events = Vec::new();
    for_each_activity(api_key, opts, |activity| {
        events.push(mapper.map_activity(&activity));
        Ok(())
    })?;
    Ok(events)
}
