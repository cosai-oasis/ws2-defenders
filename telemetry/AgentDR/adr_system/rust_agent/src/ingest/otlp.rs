//! OTLP/HTTP JSON ingest server.
//!
//! Accepts POST /v1/traces, /v1/logs, /v1/metrics encoded as OTLP JSON
//! (`OTEL_EXPORTER_OTLP_PROTOCOL=http/json`). Walks each ResourceLogs /
//! ResourceSpans payload looking for attributes that follow the OpenTelemetry
//! `gen_ai.*` semantic conventions
//! (<https://opentelemetry.io/docs/specs/semconv/gen-ai/>) and emits an
//! `EventRecord` per log record / span into the agent's event bus.
//!
//! Mapping (current OTel gen_ai semconv → AITF Class-Reuse / ai_operation):
//!
//! | OTel attribute / signal                | AITF / OCSF field           |
//! |----------------------------------------|-----------------------------|
//! | `gen_ai.system`                        | `provider`                  |
//! | `gen_ai.request.model`                 | `model` (preferred)         |
//! | `gen_ai.response.model`                | `model` (fallback)          |
//! | `gen_ai.operation.name`                | event_type qualifier        |
//! | `gen_ai.agent.name`                    | `agent_name`                |
//! | `gen_ai.agent.id` / `gen_ai.client.id` | `actor.user`                |
//! | `gen_ai.tool.name`                     | `tool_name`, ai_op=tool_execution → 6003 |
//! | `gen_ai.usage.input_tokens`            | `token_usage.input`         |
//! | `gen_ai.usage.output_tokens`           | `token_usage.output`        |
//! | `gen_ai.usage.total_tokens`            | `token_usage.total`         |
//! | `gen_ai.response.finish_reasons[]`     | `details.finish_reasons`    |
//! | `gen_ai.prompt` / `gen_ai.completion`  | redacted unless config      |
//! | resource `service.name`                | `agent_framework`           |
//! | resource `host.name` / `user.name`     | `actor.user`                |
//!
//! Inference (`gen_ai.system` present) → ai_operation=inference → API Activity 6003
//! Tool spans (`gen_ai.tool.name`)     → ai_operation=tool_execution → API Activity 6003
//! MCP spans (name contains "mcp")     → ai_operation=mcp_operation → API Activity 6003
//! Approval/policy spans               → ai_operation=permission_escalation → Detection Finding 2004

use crate::models::*;
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use flate2::read::GzDecoder;
use serde_json::{json, Value};
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{debug, error, info, warn};

/// Channel sink the OTLP server uses to publish parsed events.
#[derive(Clone)]
pub struct OtlpSink {
    tx: mpsc::UnboundedSender<EventRecord>,
    redact_content: bool,
}

impl OtlpSink {
    pub fn new(tx: mpsc::UnboundedSender<EventRecord>, redact_content: bool) -> Self {
        Self { tx, redact_content }
    }
}

/// Run the OTLP HTTP server bound to `bind` on the agent's event bus until shutdown.
pub async fn serve(
    bind: &str,
    max_body_bytes: usize,
    sink: OtlpSink,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let state = Arc::new(sink);

    let app = Router::new()
        .route("/v1/traces", post(traces))
        .route("/v1/logs", post(logs))
        .route("/v1/metrics", post(metrics))
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .with_state(state);

    let listener = match TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            error!("OTLP server failed to bind {bind}: {e}");
            return;
        }
    };
    info!("OTLP ingest listening on http://{bind} (traces, logs, metrics)");

    let serve = axum::serve(listener, app);
    tokio::select! {
        res = serve => {
            if let Err(e) = res {
                error!("OTLP server error: {e}");
            }
        }
        _ = shutdown.changed() => {
            info!("OTLP server shutting down");
        }
    }
}

/// Standalone (non-engine) OTLP runner that writes events to a JSONL file.
/// Used by `adr-agent otlp` for collector-only deployments.
pub async fn serve_standalone(bind: &str, log_path: &std::path::Path) {
    let (tx, mut rx) = mpsc::unbounded_channel::<EventRecord>();
    let sink = OtlpSink::new(tx, false);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let log_path = PathBuf::from(log_path);

    // Writer task
    tokio::spawn(async move {
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        while let Some(ev) = rx.recv().await {
            if let Ok(line) = serde_json::to_string(&ev) {
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true).append(true).open(&log_path)
                {
                    use std::io::Write;
                    let _ = writeln!(f, "{}", line);
                }
            }
        }
    });

    // Ctrl+C handler
    let ctrl_c_tx = _shutdown_tx;
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = ctrl_c_tx.send(true);
    });

    serve(bind, 4 * 1024 * 1024, sink, shutdown_rx).await;
}

// ── HTTP handlers ──

async fn traces(
    State(sink): State<Arc<OtlpSink>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let value = match decode_body(&headers, &body) {
        Ok(v) => v,
        Err(e) => return reject(e),
    };
    let n = handle_traces(&sink, &value);
    debug!("OTLP /v1/traces: {} events emitted", n);
    accept()
}

async fn logs(
    State(sink): State<Arc<OtlpSink>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let value = match decode_body(&headers, &body) {
        Ok(v) => v,
        Err(e) => return reject(e),
    };
    let n = handle_logs(&sink, &value);
    debug!("OTLP /v1/logs: {} events emitted", n);
    accept()
}

async fn metrics(
    State(_sink): State<Arc<OtlpSink>>,
    _headers: HeaderMap,
    _body: Bytes,
) -> impl IntoResponse {
    // Metrics are accepted but not yet mapped (cost/token spend is carried on
    // spans/logs in current gen_ai semconv; metrics-based mapping comes later).
    accept()
}

fn accept() -> axum::response::Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], "{}").into_response()
}

fn reject(msg: &'static str) -> axum::response::Response {
    warn!("OTLP rejected: {msg}");
    (StatusCode::BAD_REQUEST, msg).into_response()
}

fn decode_body(headers: &HeaderMap, body: &Bytes) -> Result<Value, &'static str> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Only JSON encoding is supported in this build (protobuf can be added by
    // generating types from opentelemetry-proto). OTLP/JSON is what
    // Claude Code, Codex and the OTel SDKs emit when
    // OTEL_EXPORTER_OTLP_PROTOCOL=http/json.
    if !ct.is_empty() && !ct.starts_with("application/json") {
        return Err("only OTLP/JSON (Content-Type: application/json) is supported");
    }

    let bytes: Vec<u8> = match headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
    {
        Some("gzip") => {
            let mut d = GzDecoder::new(body.as_ref());
            let mut out = Vec::new();
            d.read_to_end(&mut out).map_err(|_| "gzip decode failed")?;
            out
        }
        _ => body.to_vec(),
    };
    serde_json::from_slice(&bytes).map_err(|_| "invalid OTLP JSON")
}

// ── OTLP/JSON walkers ──

fn handle_traces(sink: &OtlpSink, payload: &Value) -> usize {
    let mut count = 0;
    let Some(resource_spans) = payload.get("resourceSpans").and_then(|v| v.as_array()) else {
        return 0;
    };
    for rs in resource_spans {
        let resource_attrs = collect_attrs(rs.get("resource").and_then(|r| r.get("attributes")));
        let Some(scope_spans) = rs.get("scopeSpans").and_then(|v| v.as_array()) else { continue };
        for ss in scope_spans {
            let Some(spans) = ss.get("spans").and_then(|v| v.as_array()) else { continue };
            for span in spans {
                if let Some(ev) = span_to_event(span, &resource_attrs, sink.redact_content) {
                    if sink.tx.send(ev).is_ok() {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

fn handle_logs(sink: &OtlpSink, payload: &Value) -> usize {
    let mut count = 0;
    let Some(resource_logs) = payload.get("resourceLogs").and_then(|v| v.as_array()) else {
        return 0;
    };
    for rl in resource_logs {
        let resource_attrs = collect_attrs(rl.get("resource").and_then(|r| r.get("attributes")));
        let Some(scope_logs) = rl.get("scopeLogs").and_then(|v| v.as_array()) else { continue };
        for sl in scope_logs {
            let Some(records) = sl.get("logRecords").and_then(|v| v.as_array()) else { continue };
            for rec in records {
                if let Some(ev) = log_to_event(rec, &resource_attrs, sink.redact_content) {
                    if sink.tx.send(ev).is_ok() {
                        count += 1;
                    }
                }
            }
        }
    }
    count
}

// ── Span → AITF event ──

fn span_to_event(span: &Value, resource: &Attrs, redact: bool) -> Option<EventRecord> {
    let span_attrs = collect_attrs(span.get("attributes"));
    let span_name = span.get("name").and_then(|v| v.as_str()).unwrap_or("span");
    let trace_id_hex = span.get("traceId").and_then(|v| v.as_str()).map(String::from);
    let span_id_hex = span.get("spanId").and_then(|v| v.as_str()).map(String::from);

    let mut combined = resource.clone();
    combined.extend(span_attrs.into_iter());

    // Only emit if this span looks like a gen_ai signal.
    let gen_ai_system = combined.get("gen_ai.system").cloned();
    let tool_name = combined.get("gen_ai.tool.name").cloned();
    let is_mcp = span_name.to_lowercase().contains("mcp")
        || combined.keys().any(|k| k.starts_with("mcp."));
    // Tier 5 — approval flow: any span with gen_ai.approval.* or
    // gen_ai.policy.* attributes is treated as a permission-escalation
    // Detection Finding (OCSF 2004) so analysts can review approve/deny
    // actions a user took inside a coding agent.
    let is_approval = combined.keys().any(|k| k.starts_with("gen_ai.approval.") || k.starts_with("gen_ai.policy."));
    // AITF 0.2 — agent-to-agent delegation lifecycle (proposed OCSF class 9002).
    let is_delegation = combined.keys().any(|k| k.starts_with("delegation.") || k.starts_with("gen_ai.delegation."));

    if gen_ai_system.is_none() && tool_name.is_none() && !is_mcp && !is_approval && !is_delegation {
        return None;
    }

    let (op, activity_id, event_type) = if is_delegation {
        let revoke = combined
            .get("delegation.action")
            .or_else(|| combined.get("gen_ai.delegation.action"))
            .map(|a| a.eq_ignore_ascii_case("revoke"))
            .unwrap_or(false);
        let activity = if revoke { ACTIVITY_DELETE } else { ACTIVITY_CREATE };
        (AiOperation::Delegation, activity, "gen_ai.delegation")
    } else if is_approval {
        (AiOperation::PermissionEscalation, ACTIVITY_DETECT, "gen_ai.approval")
    } else if tool_name.is_some() {
        (AiOperation::ToolExecution, ACTIVITY_EXECUTE, "gen_ai.tool")
    } else if is_mcp {
        (AiOperation::McpOperation, ACTIVITY_EXECUTE, "gen_ai.mcp")
    } else {
        (AiOperation::Inference, ACTIVITY_EXECUTE, "gen_ai.inference")
    };

    let mut ev = EventRecord::new(event_type, json!({
        "span_name": span_name,
        "operation": combined.get("gen_ai.operation.name"),
        "finish_reasons": combined.get("gen_ai.response.finish_reasons"),
    }), severity_for_op(op));

    ev.set_op(op, activity_id);
    ev.activity_id = Some(activity_id);
    ev.status_id = Some(STATUS_SUCCESS);
    ev.source = Some("otlp".into());

    apply_common_attrs(&mut ev, &combined, redact);
    if let Some(tn) = tool_name {
        ev.tool_name = Some(tn);
    }
    if is_approval {
        // Lift the approval decision onto the top-level event for easy filtering.
        let decision = combined.get("gen_ai.approval.decision").cloned();
        let actor    = combined.get("gen_ai.approval.actor").cloned();
        let scope    = combined.get("gen_ai.approval.scope").cloned();
        let reason   = combined.get("gen_ai.approval.reason").cloned();
        ev.details = json!({
            "decision": decision,  // typically "allow"|"deny"|"defer"
            "actor":    actor,
            "scope":    scope,
            "reason":   reason,
        });
        if decision.as_deref() == Some("deny") {
            ev.risk_level = "high".into();
            ev.severity_id = Some(4);
            ev.status_id   = Some(STATUS_BLOCKED);
        }
        ev.message = Some(format!(
            "approval {}{}",
            decision.unwrap_or_else(|| "(unknown)".into()),
            scope.map(|s| format!(" — {}", s)).unwrap_or_default()
        ));
    }
    if let Some(t) = trace_id_hex {
        ev.trace_id = t;
    }
    if let Some(s) = span_id_hex {
        ev.span_id = s;
    }
    Some(ev)
}

// ── Log record → AITF event ──

fn log_to_event(rec: &Value, resource: &Attrs, redact: bool) -> Option<EventRecord> {
    let rec_attrs = collect_attrs(rec.get("attributes"));
    let mut combined = resource.clone();
    combined.extend(rec_attrs.into_iter());

    let event_name = rec.get("eventName")
        .or(rec.get("event_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let body = rec.get("body").and_then(|b| b.get("stringValue")).and_then(|v| v.as_str());

    let gen_ai = combined.get("gen_ai.system").is_some()
        || combined.keys().any(|k| k.starts_with("gen_ai."))
        || event_name.starts_with("gen_ai.");
    if !gen_ai {
        return None;
    }

    let op = match event_name {
        "gen_ai.user.message" | "gen_ai.system.message" | "gen_ai.assistant.message"
        | "gen_ai.choice" => AiOperation::Inference,
        "gen_ai.tool.message" => AiOperation::ToolExecution,
        _ => AiOperation::Inference,
    };

    let mut ev = EventRecord::new(
        if event_name.is_empty() { "gen_ai.event" } else { event_name },
        json!({
            "log_body": if redact { None } else { body.map(String::from) },
            "severity_text": rec.get("severityText"),
        }),
        severity_for_op(op),
    );
    ev.set_op(op, ACTIVITY_EXECUTE);
    ev.activity_id = Some(ACTIVITY_EXECUTE);
    ev.status_id = Some(STATUS_SUCCESS);
    ev.source = Some("otlp".into());
    apply_common_attrs(&mut ev, &combined, redact);

    if let Some(tid) = rec.get("traceId").and_then(|v| v.as_str()) {
        ev.trace_id = tid.to_string();
    }
    if let Some(sid) = rec.get("spanId").and_then(|v| v.as_str()) {
        ev.span_id = sid.to_string();
    }
    Some(ev)
}

fn apply_common_attrs(ev: &mut EventRecord, attrs: &Attrs, redact: bool) {
    if let Some(sys) = attrs.get("gen_ai.system") {
        ev.provider = Some(sys.clone());
    }
    let model = attrs
        .get("gen_ai.request.model")
        .or_else(|| attrs.get("gen_ai.response.model"));
    if let Some(m) = model {
        ev.model = Some(m.clone());
    }
    if let Some(agent) = attrs.get("gen_ai.agent.name").or_else(|| attrs.get("service.name")) {
        ev.agent_name = Some(agent.clone());
    }
    if let Some(fw) = attrs.get("gen_ai.framework").or_else(|| attrs.get("telemetry.sdk.name")) {
        ev.agent_framework = Some(fw.clone());
    }

    let input = attrs.get("gen_ai.usage.input_tokens")
        .or_else(|| attrs.get("gen_ai.usage.prompt_tokens"));
    let output = attrs.get("gen_ai.usage.output_tokens")
        .or_else(|| attrs.get("gen_ai.usage.completion_tokens"));
    let total = attrs.get("gen_ai.usage.total_tokens");
    if input.is_some() || output.is_some() || total.is_some() {
        let to_num = |v: Option<&String>| v.and_then(|s| s.parse::<u64>().ok());
        ev.token_usage = Some(json!({
            "input":  to_num(input),
            "output": to_num(output),
            "total":  to_num(total),
        }));
    }

    // `gen_ai.agent.id` is the *agent's* identity (→ ai_agent.uid), not the
    // human user; keep it out of actor.user.
    let user = attrs.get("user.name")
        .or_else(|| attrs.get("enduser.id"));
    let host = attrs.get("host.name");
    if user.is_some() || host.is_some() {
        ev.actor = Some(json!({
            "user": user.cloned(),
            "host": host.cloned(),
        }));
    }

    // AITF 0.2 ai_agent object (provisional, OCSF PR #1641). uid from the
    // explicit agent id when present; instance_uid from the conversation /
    // session / thread id.
    let agent_uid = attrs.get("gen_ai.agent.id").map(String::as_str);
    let instance_uid = attrs
        .get("gen_ai.conversation.id")
        .or_else(|| attrs.get("gen_ai.thread.id"))
        .or_else(|| attrs.get("session.id"))
        .map(String::as_str);
    ev.build_ai_agent(agent_uid, instance_uid);

    // AITF 0.2 delegation object: grantor/grantee/scope/action/ttl_seconds.
    let dget = |k1: &str, k2: &str| attrs.get(k1).or_else(|| attrs.get(k2)).cloned();
    if attrs.keys().any(|k| k.starts_with("delegation.") || k.starts_with("gen_ai.delegation.")) {
        let ttl = attrs
            .get("delegation.ttl_seconds")
            .or_else(|| attrs.get("delegation.ttl"))
            .or_else(|| attrs.get("gen_ai.delegation.ttl_seconds"))
            .and_then(|s| s.parse::<u64>().ok());
        ev.delegation = Some(json!({
            "grantor":     dget("delegation.grantor", "gen_ai.delegation.grantor"),
            "grantee":     dget("delegation.grantee", "gen_ai.delegation.grantee"),
            "scope":       dget("delegation.scope", "gen_ai.delegation.scope"),
            "action":      dget("delegation.action", "gen_ai.delegation.action"),
            "ttl_seconds": ttl,
        }));
    }

    // Redaction: drop prompt/completion bodies if requested.
    if redact {
        // No-op: we never copied them into ev.details. Future content modes
        // will branch here.
    }

    if let Some(provider) = ev.provider.clone() {
        ev.message = Some(format!(
            "OTLP {} from {}",
            ev.tool_name.as_deref().unwrap_or("inference"),
            provider
        ));
    }
}

fn severity_for_op(op: AiOperation) -> &'static str {
    match op {
        AiOperation::ToolExecution | AiOperation::McpOperation => "medium",
        _ => "low",
    }
}

// ── OTLP attribute flattening ──

type Attrs = std::collections::BTreeMap<String, String>;

fn collect_attrs(input: Option<&Value>) -> Attrs {
    let mut out = Attrs::new();
    let Some(arr) = input.and_then(|v| v.as_array()) else { return out };
    for kv in arr {
        let Some(key) = kv.get("key").and_then(|v| v.as_str()) else { continue };
        if let Some(val) = kv.get("value") {
            if let Some(s) = scalar_value(val) {
                out.insert(key.to_string(), s);
            }
        }
    }
    out
}

fn scalar_value(v: &Value) -> Option<String> {
    if let Some(s) = v.get("stringValue").and_then(|x| x.as_str()) {
        return Some(s.to_string());
    }
    if let Some(b) = v.get("boolValue").and_then(|x| x.as_bool()) {
        return Some(b.to_string());
    }
    if let Some(i) = v.get("intValue") {
        // OTLP/JSON encodes int64 as string; accept either.
        if let Some(s) = i.as_str() { return Some(s.to_string()); }
        if let Some(n) = i.as_i64() { return Some(n.to_string()); }
    }
    if let Some(d) = v.get("doubleValue").and_then(|x| x.as_f64()) {
        return Some(d.to_string());
    }
    if let Some(arr) = v.get("arrayValue").and_then(|x| x.get("values")).and_then(|x| x.as_array()) {
        let joined: Vec<String> = arr.iter().filter_map(scalar_value).collect();
        return Some(joined.join(","));
    }
    None
}
