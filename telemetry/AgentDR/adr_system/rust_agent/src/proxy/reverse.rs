//! Reverse proxy that protects local LLM backends (Ollama, LM Studio,
//! llama.cpp).
//!
//! Unlike the forward CONNECT proxy in [`super`], this component terminates
//! the HTTP request itself, so it can read the request/response *bodies*.
//! That unlocks the body-inspecting controls that a forward tunnel cannot
//! perform:
//!
//!   * **Authentication** — static API keys or HS256 JWTs ([`super::auth`]),
//!     so a loopback model server that has no auth of its own gains one.
//!   * **Rate limiting** — per-caller sliding window ([`super::rate_limit`]).
//!   * **Process provenance** — which local PID / binary issued the call
//!     ([`super::provenance`]), attributed to a known AI agent.
//!   * **Prompt-injection / PII scanning** — request bodies are parsed and
//!     analysed ([`super::monitor`]); matches can be alerted on or blocked.
//!   * **Token-usage tracking** — the upstream response's `usage` /
//!     `eval_count` fields are recorded for cost/volume accounting.
//!   * **Upstream health** — periodic backend probes ([`super::health`])
//!     surfaced at `GET /healthz`.
//!
//! Clients point at the guard (e.g. `http://127.0.0.1:8011/ollama`) instead
//! of the backend directly; requests are routed to the matching backend by
//! `route_prefix` (longest match wins) and the prefix is stripped before
//! forwarding. Every request emits an OCSF/AITF [`EventRecord`] into the
//! shared event bus, mirroring the rest of the agent.
//!
//! Responses are buffered (bounded by `max_body_bytes`) so token usage can be
//! parsed; this means streamed (`"stream": true`) responses are delivered in
//! one shot rather than incrementally.

use crate::config::{BackendConfig, LlmGuardConfig};
use crate::models::*;
use super::auth::{AuthOutcome, Authenticator};
use super::health::{self, HealthRegistry};
use super::monitor;
use super::provenance::{self, AclDecision, Provenance};
use super::rate_limit::KeyedRateLimiter;
use super::InlineProxy;
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Hop-by-hop headers that must not be forwarded verbatim (RFC 7230 §6.1)
/// plus the guard's own auth headers.
const STRIP_HEADERS: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "authorization",
    "x-api-key",
];

/// Shared state for the reverse-proxy HTTP handlers.
pub struct Guard {
    /// Upstream backends, pre-sorted by descending `route_prefix` length so
    /// the longest (most specific) prefix matches first.
    backends: Vec<BackendConfig>,
    auth: Authenticator,
    limiter: KeyedRateLimiter,
    monitoring: crate::config::MonitoringConfig,
    acl: crate::config::ProcessAclConfig,
    max_body: usize,
    client: reqwest::Client,
    health: Arc<HealthRegistry>,
    tx: mpsc::UnboundedSender<EventRecord>,
}

/// Run the reverse proxy bound to `cfg.listen_address` until shutdown.
pub async fn serve(
    cfg: &LlmGuardConfig,
    tx: mpsc::UnboundedSender<EventRecord>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.upstream_timeout_seconds.max(1)))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("llm-guard: failed to build HTTP client: {e}");
            return;
        }
    };

    // Sort backends longest-prefix-first for routing.
    let mut backends = cfg.backends.clone();
    backends.sort_by(|a, b| b.route_prefix.len().cmp(&a.route_prefix.len()));

    let health = Arc::new(HealthRegistry::new());

    let guard = Arc::new(Guard {
        backends,
        auth: Authenticator::new(cfg.auth_tokens.clone(), cfg.jwt.clone()),
        limiter: KeyedRateLimiter::new(&cfg.rate_limits),
        monitoring: cfg.monitoring.clone(),
        acl: cfg.process_acl.clone(),
        max_body: cfg.max_body_bytes,
        client: client.clone(),
        health: health.clone(),
        tx,
    });

    // Periodic backend health probing + rate-limiter state reclamation.
    if cfg.health_check_interval_seconds > 0 {
        let interval = Duration::from_secs(cfg.health_check_interval_seconds);
        let guard_bg = guard.clone();
        let mut hb_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        for backend in &guard_bg.backends {
                            let h = health::probe(&guard_bg.client, backend).await;
                            guard_bg.health.update(h);
                        }
                        // Drop limiter state for keys that fully recovered,
                        // bounding memory on long-running guards.
                        guard_bg.limiter.retain_recent();
                    }
                    _ = hb_shutdown.changed() => break,
                }
            }
        });
    }

    let app = Router::new()
        .route("/healthz", get(healthz))
        .fallback(proxy_handler)
        .with_state(guard);

    let listener = match TcpListener::bind(&cfg.listen_address).await {
        Ok(l) => l,
        Err(e) => {
            error!("llm-guard: failed to bind {}: {e}", cfg.listen_address);
            return;
        }
    };
    info!(
        "llm-guard reverse proxy listening on http://{} ({} backend(s); auth={}, rate_limit={}, monitoring={})",
        cfg.listen_address,
        cfg.backends.len(),
        // re-derive for the log line:
        !(cfg.auth_tokens.is_empty() && !cfg.jwt.enabled),
        cfg.rate_limits.enabled,
        cfg.monitoring.enabled,
    );

    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    );
    tokio::select! {
        res = serve => {
            if let Err(e) = res {
                error!("llm-guard server error: {e}");
            }
        }
        _ = shutdown.changed() => {
            info!("llm-guard reverse proxy shutting down");
        }
    }
}

/// `GET /healthz` — latest cached backend statuses.
async fn healthz(State(guard): State<Arc<Guard>>) -> Json<Value> {
    let backends = guard.health.snapshot();
    Json(json!({
        "status": if guard.health.all_healthy() || backends.is_empty() { "ok" } else { "degraded" },
        "backends": backends,
    }))
}

/// Catch-all handler: authenticate → rate-limit → inspect → forward.
async fn proxy_handler(
    State(guard): State<Arc<Guard>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map(|q| q.to_string());
    let headers = parts.headers.clone();

    // ── Caller provenance + agent attribution ──
    let prov = provenance::resolve(peer);
    let agent = identify_agent(&prov.haystack());

    // ── 0) Process access control ──
    // Gate on *which local process* is calling (allow/deny lists over the
    // resolved exe / cmdline / attributed agent), before spending work on
    // auth or body inspection.
    if let AclDecision::Deny(reason) =
        guard.acl.evaluate(&prov, agent.as_ref().map(|a| a.name.as_str()))
    {
        guard.emit_block(
            "llm_guard_process_denied",
            AiOperation::Identity,
            "high",
            4,
            &format!("llm-guard: process denied ({reason})"),
            &prov,
            agent.as_ref(),
            None,
        );
        return (
            StatusCode::FORBIDDEN,
            "forbidden: caller process not permitted",
        )
            .into_response();
    }

    // ── 1) Authentication ──
    let bearer = bearer_from(&headers, "authorization");
    let api_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let (subject, auth_method) = match guard.auth.authenticate(bearer.as_deref(), api_key.as_deref()) {
        AuthOutcome::Allowed { subject, method } => (subject, method),
        AuthOutcome::Denied { reason } => {
            guard.emit_block(
                "llm_guard_auth_denied",
                AiOperation::Identity,
                "high",
                4,
                &format!("llm-guard: auth denied ({reason})"),
                &prov,
                agent.as_ref(),
                None,
            );
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer realm=\"AgentDR\"")],
                "unauthorized",
            )
                .into_response();
        }
    };

    // ── 2) Rate limiting ──
    let rl_key = if subject != "anonymous" {
        subject.clone()
    } else {
        prov.pid
            .map(|pid| format!("pid:{pid}"))
            .unwrap_or_else(|| format!("peer:{peer}"))
    };
    if !guard.limiter.check(&rl_key) {
        guard.emit_block(
            "llm_guard_rate_limited",
            AiOperation::GuardrailEvent,
            "medium",
            3,
            &format!("llm-guard: rate limit exceeded for {rl_key} ({}/min)", guard.limiter.per_minute()),
            &prov,
            agent.as_ref(),
            None,
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", "1")],
            "rate limit exceeded",
        )
            .into_response();
    }

    // ── 3) Route to a backend ──
    let Some((backend, upstream_path)) = guard.route(&path) else {
        guard.emit_block(
            "llm_guard_no_route",
            AiOperation::GuardrailEvent,
            "low",
            2,
            &format!("llm-guard: no backend matches {path}"),
            &prov,
            agent.as_ref(),
            None,
        );
        return (StatusCode::BAD_GATEWAY, "no matching backend").into_response();
    };

    // ── 4) Read (bounded) request body ──
    let body_bytes = match axum::body::to_bytes(body, guard.max_body).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
        }
    };

    // ── 5) Inspect prompt (injection / PII) ──
    let mut analysis = None;
    if guard.monitoring.enabled {
        if let Ok(json_body) = serde_json::from_slice::<Value>(&body_bytes) {
            let prompt = monitor::extract_prompt(&json_body);
            if !prompt.is_empty() {
                let a = monitor::analyze(
                    &prompt,
                    guard.monitoring.detect_prompt_injection,
                    guard.monitoring.detect_pii,
                    guard.monitoring.max_prompt_chars,
                );
                let block_injection = a.has_injection() && guard.monitoring.block_on_injection;
                let block_pii = a.has_pii() && guard.monitoring.block_on_pii;
                if block_injection || block_pii {
                    guard.emit_finding(&backend, &a, &prov, agent.as_ref(), true);
                    let kind = if block_injection { "prompt injection" } else { "PII" };
                    return (
                        StatusCode::FORBIDDEN,
                        format!("blocked by llm-guard ({kind} detected)"),
                    )
                        .into_response();
                }
                analysis = Some(a);
            }
        }
    }

    // ── 6) Forward to the upstream backend ──
    let upstream_url = build_upstream_url(&backend.url, &upstream_path, query.as_deref());
    let resp = match guard
        .forward(&method, &upstream_url, &headers, body_bytes.clone())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            guard.emit_block(
                "llm_guard_upstream_error",
                AiOperation::GuardrailEvent,
                "medium",
                3,
                &format!("llm-guard: upstream {} error: {e}", backend.name),
                &prov,
                agent.as_ref(),
                Some(&backend),
            );
            return (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response();
        }
    };

    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let resp_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::BAD_GATEWAY, format!("upstream read error: {e}")).into_response();
        }
    };

    // ── 7) Token usage + observation event ──
    let token_usage = if guard.monitoring.track_tokens {
        serde_json::from_slice::<Value>(&resp_bytes)
            .ok()
            .and_then(|v| monitor::extract_token_usage(&v))
    } else {
        None
    };
    guard.emit_observation(
        &backend,
        &method,
        &upstream_path,
        status.as_u16(),
        analysis.as_ref(),
        token_usage,
        &prov,
        agent.as_ref(),
        &subject,
        auth_method,
    );

    // ── 8) Relay the upstream response back to the client ──
    build_client_response(status, &resp_headers, resp_bytes)
}

impl Guard {
    /// Pick the backend whose `route_prefix` matches `path` (longest first;
    /// an empty prefix is the default). Returns the backend and the path to
    /// forward (prefix stripped).
    fn route(&self, path: &str) -> Option<(BackendConfig, String)> {
        select_backend(&self.backends, path).map(|(b, p)| (b.clone(), p))
    }

    /// Forward the request to the upstream backend.
    async fn forward(
        &self,
        method: &Method,
        url: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut fwd_headers = HeaderMap::new();
        for (name, value) in headers.iter() {
            if STRIP_HEADERS.iter().any(|s| name.as_str().eq_ignore_ascii_case(s)) {
                continue;
            }
            fwd_headers.insert(name.clone(), value.clone());
        }
        self.client
            .request(method.clone(), url)
            .headers(fwd_headers)
            .body(body)
            .send()
            .await
    }

    /// Emit a blocking / error finding event.
    #[allow(clippy::too_many_arguments)]
    fn emit_block(
        &self,
        event_type: &str,
        op: AiOperation,
        risk: &str,
        severity_id: u32,
        message: &str,
        prov: &Provenance,
        agent: Option<&AgentSignature>,
        backend: Option<&BackendConfig>,
    ) {
        let mut ev = EventRecord::new(
            event_type,
            json!({ "peer": prov.peer, "backend": backend.map(|b| &b.name) }),
            risk,
        );
        ev.set_op(op, ACTIVITY_BLOCK);
        ev.activity_id = Some(ACTIVITY_BLOCK);
        ev.status_id = Some(STATUS_BLOCKED);
        ev.severity_id = Some(severity_id);
        ev.message = Some(message.to_string());
        ev.source = Some("llm-guard".into());
        if let Some(b) = backend {
            ev.provider = Some(b.kind.clone());
        }
        InlineProxy::enrich_event(&mut ev, Some(prov), agent);
        let _ = self.tx.send(ev);
    }

    /// Emit a prompt-injection / PII Detection Finding (OCSF 2004).
    fn emit_finding(
        &self,
        backend: &BackendConfig,
        analysis: &monitor::Analysis,
        prov: &Provenance,
        agent: Option<&AgentSignature>,
        blocked: bool,
    ) {
        let op = if analysis.has_injection() {
            AiOperation::PromptInjection
        } else {
            AiOperation::DataExfiltration
        };
        let activity = if blocked { ACTIVITY_BLOCK } else { ACTIVITY_DETECT };
        let mut ev = EventRecord::new(
            "llm_guard_finding",
            json!({
                "backend": backend.name,
                "labels": analysis.labels(),
                "prompt_chars": analysis.prompt_len,
                "excerpt": analysis.excerpt,
            }),
            "high",
        );
        ev.set_op(op, activity);
        ev.activity_id = Some(activity);
        ev.status_id = Some(if blocked { STATUS_BLOCKED } else { STATUS_SUCCESS });
        ev.severity_id = Some(if blocked { 4 } else { 3 });
        ev.provider = Some(backend.kind.clone());
        ev.source = Some("llm-guard".into());
        ev.security_finding = Some(json!({
            "injections": analysis.injections.iter().map(|f| &f.label).collect::<Vec<_>>(),
            "pii": analysis.pii.iter().map(|f| &f.label).collect::<Vec<_>>(),
            "blocked": blocked,
        }));
        ev.message = Some(format!(
            "llm-guard: {} {} on {} [{}]",
            if blocked { "blocked" } else { "detected" },
            op.as_str(),
            backend.name,
            analysis.labels().join(", "),
        ));
        InlineProxy::enrich_event(&mut ev, Some(prov), agent);
        let _ = self.tx.send(ev);
    }

    /// Emit the per-request inference observation (success path).
    #[allow(clippy::too_many_arguments)]
    fn emit_observation(
        &self,
        backend: &BackendConfig,
        method: &Method,
        path: &str,
        status_code: u16,
        analysis: Option<&monitor::Analysis>,
        token_usage: Option<Value>,
        prov: &Provenance,
        agent: Option<&AgentSignature>,
        subject: &str,
        auth_method: &str,
    ) {
        // If a (non-blocking) finding was present, surface it as its own
        // Detection Finding so alert-only mode still reports.
        if let Some(a) = analysis {
            if a.has_injection() || a.has_pii() {
                self.emit_finding(backend, a, prov, agent, false);
            }
        }

        let risk = if status_code >= 400 { "medium" } else { "low" };
        let mut ev = EventRecord::new(
            "llm_guard_request",
            json!({
                "backend": backend.name,
                "method": method.as_str(),
                "path": path,
                "status": status_code,
                "subject": subject,
                "auth_method": auth_method,
            }),
            risk,
        );
        ev.set_op(AiOperation::Inference, ACTIVITY_EXECUTE);
        ev.activity_id = Some(ACTIVITY_EXECUTE);
        ev.status_id = Some(if status_code >= 400 { STATUS_FAILURE } else { STATUS_SUCCESS });
        ev.provider = Some(backend.kind.clone());
        ev.source = Some("llm-guard".into());
        if let Some(tu) = token_usage {
            ev.token_usage = Some(tu);
        }
        ev.message = Some(format!(
            "llm-guard: {} {} -> {} ({})",
            method.as_str(),
            path,
            backend.name,
            status_code
        ));
        InlineProxy::enrich_event(&mut ev, Some(prov), agent);
        let _ = self.tx.send(ev);
        debug!("llm-guard proxied {} {} -> {} {}", method.as_str(), path, backend.name, status_code);
    }
}

/// Select the backend whose `route_prefix` matches `path`. `backends` must be
/// pre-sorted longest-prefix-first. Returns a borrow of the backend plus the
/// path to forward (with the prefix stripped). An empty prefix is the default
/// route (matches anything).
fn select_backend<'a>(
    backends: &'a [BackendConfig],
    path: &str,
) -> Option<(&'a BackendConfig, String)> {
    for b in backends {
        if b.route_prefix.is_empty() {
            return Some((b, path.to_string()));
        }
        let prefix = b.route_prefix.trim_end_matches('/');
        if path == prefix {
            return Some((b, "/".to_string()));
        }
        if let Some(rest) = path.strip_prefix(prefix) {
            if rest.starts_with('/') {
                return Some((b, rest.to_string()));
            }
        }
    }
    None
}

/// Build the upstream URL from the backend base, the (stripped) path, and the
/// original query string.
fn build_upstream_url(base: &str, path: &str, query: Option<&str>) -> String {
    let base = base.trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    match query {
        Some(q) if !q.is_empty() => format!("{base}{path}?{q}"),
        _ => format!("{base}{path}"),
    }
}

/// Extract a bearer token from a header value (case-insensitive scheme).
fn bearer_from(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(name).and_then(|v| v.to_str().ok())?.trim();
    if let Some(rest) = raw.strip_prefix("Bearer ").or_else(|| raw.strip_prefix("bearer ")) {
        Some(rest.trim().to_string())
    } else if raw.is_empty() {
        None
    } else {
        Some(raw.to_string())
    }
}

/// Convert the upstream reqwest response into an axum response, copying
/// status and headers (minus hop-by-hop) and the buffered body.
fn build_client_response(status: StatusCode, headers: &HeaderMap, body: Bytes) -> Response {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers.iter() {
        if STRIP_HEADERS.iter().any(|s| name.as_str().eq_ignore_ascii_case(s)) {
            continue;
        }
        // Re-validate names/values into this http version's types.
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            builder = builder.header(n, v);
        }
    }
    match builder.body(Body::from(body)) {
        Ok(r) => r,
        Err(e) => {
            warn!("llm-guard: failed to build response: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "response build error").into_response()
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BackendConfig;

    fn backend(name: &str, url: &str, prefix: &str) -> BackendConfig {
        BackendConfig {
            name: name.into(),
            kind: name.into(),
            url: url.into(),
            route_prefix: prefix.into(),
            health_path: "/health".into(),
        }
    }

    /// Backends are expected pre-sorted longest-prefix-first.
    fn sorted(mut v: Vec<BackendConfig>) -> Vec<BackendConfig> {
        v.sort_by(|a, b| b.route_prefix.len().cmp(&a.route_prefix.len()));
        v
    }

    #[test]
    fn routes_by_longest_prefix() {
        let backends = sorted(vec![
            backend("ollama", "http://127.0.0.1:11434", "/ollama"),
            backend("lmstudio", "http://127.0.0.1:1234", "/lmstudio"),
        ]);
        let (b, path) = select_backend(&backends, "/ollama/api/generate").unwrap();
        assert_eq!(b.name, "ollama");
        assert_eq!(path, "/api/generate");

        let (b, path) = select_backend(&backends, "/lmstudio/v1/chat/completions").unwrap();
        assert_eq!(b.name, "lmstudio");
        assert_eq!(path, "/v1/chat/completions");
    }

    #[test]
    fn prefix_exact_match_forwards_root() {
        let backends = sorted(vec![backend("ollama", "http://x", "/ollama")]);
        let (_, path) = select_backend(&backends, "/ollama").unwrap();
        assert_eq!(path, "/");
    }

    #[test]
    fn empty_prefix_is_default_route() {
        let backends = sorted(vec![
            backend("ollama", "http://x", "/ollama"),
            backend("default", "http://y", ""),
        ]);
        // Longest-first means /ollama is tried before the empty default.
        let (b, path) = select_backend(&backends, "/api/tags").unwrap();
        assert_eq!(b.name, "default");
        assert_eq!(path, "/api/tags");
    }

    #[test]
    fn no_match_without_default() {
        let backends = sorted(vec![backend("ollama", "http://x", "/ollama")]);
        // A partial token that isn't a path-segment boundary must not match.
        assert!(select_backend(&backends, "/ollamaXYZ/foo").is_none());
        assert!(select_backend(&backends, "/other").is_none());
    }

    #[test]
    fn builds_upstream_url_with_and_without_query() {
        assert_eq!(
            build_upstream_url("http://127.0.0.1:11434/", "/api/generate", None),
            "http://127.0.0.1:11434/api/generate"
        );
        assert_eq!(
            build_upstream_url("http://127.0.0.1:11434", "api/tags", Some("x=1")),
            "http://127.0.0.1:11434/api/tags?x=1"
        );
    }

    #[test]
    fn bearer_parsing_handles_scheme_and_raw() {
        let mut h = HeaderMap::new();
        h.insert("authorization", HeaderValue::from_static("Bearer abc123"));
        assert_eq!(bearer_from(&h, "authorization").as_deref(), Some("abc123"));

        let mut h2 = HeaderMap::new();
        h2.insert("authorization", HeaderValue::from_static("rawtoken"));
        assert_eq!(bearer_from(&h2, "authorization").as_deref(), Some("rawtoken"));

        let empty = HeaderMap::new();
        assert_eq!(bearer_from(&empty, "authorization"), None);
    }
}
