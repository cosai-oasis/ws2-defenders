//! OCSF mapper: turns AITF span data into reused OCSF AI events.
//!
//! Mirrors the Python/Go dispatch order. AI-specific context is attached to
//! every event via the OCSF `ai_operation` profile (OCSF PR #1641 / issue
//! #1640) by [`OcsfMapper::map_span`].

use std::collections::HashMap;

use crate::ocsf::crosswalk::{
    build_agent_message, build_ai_agent, build_delegation, build_delegation_lineage,
};
use crate::ocsf::schema::*;
use crate::semconv;

/// A single OTel-style attribute value.
#[derive(Debug, Clone)]
pub enum AttrValue {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    StrList(Vec<String>),
}

impl AttrValue {
    /// Returns the value as a string slice when it is a [`AttrValue::Str`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AttrValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns the value as an `i64`, converting from float when needed.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            AttrValue::Int(i) => Some(*i),
            AttrValue::Float(f) => Some(*f as i64),
            _ => None,
        }
    }

    /// Returns the value as an `f64`, converting from int when needed.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            AttrValue::Float(f) => Some(*f),
            AttrValue::Int(i) => Some(*i as f64),
            _ => None,
        }
    }

    /// Returns the value as a `bool` when it is a [`AttrValue::Bool`].
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            AttrValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns the value as a string list when it is a [`AttrValue::StrList`].
    pub fn as_str_list(&self) -> Option<&[String]> {
        match self {
            AttrValue::StrList(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// Renders any value as its string form (mirrors Go's `fmt.Sprintf("%v")`).
    pub fn to_attr_string(&self) -> String {
        match self {
            AttrValue::Str(s) => s.clone(),
            AttrValue::Int(i) => i.to_string(),
            AttrValue::Float(f) => f.to_string(),
            AttrValue::Bool(b) => b.to_string(),
            AttrValue::StrList(v) => v.join(","),
        }
    }

    /// Normalizes any value into a `Vec<String>`.
    pub fn to_str_list(&self) -> Vec<String> {
        match self {
            AttrValue::StrList(v) => v.clone(),
            other => vec![other.to_attr_string()],
        }
    }
}

impl From<&str> for AttrValue {
    fn from(s: &str) -> Self {
        AttrValue::Str(s.to_string())
    }
}
impl From<String> for AttrValue {
    fn from(s: String) -> Self {
        AttrValue::Str(s)
    }
}
impl From<i64> for AttrValue {
    fn from(i: i64) -> Self {
        AttrValue::Int(i)
    }
}
impl From<f64> for AttrValue {
    fn from(f: f64) -> Self {
        AttrValue::Float(f)
    }
}
impl From<bool> for AttrValue {
    fn from(b: bool) -> Self {
        AttrValue::Bool(b)
    }
}

/// Minimal span representation consumed by the mapper.
#[derive(Default)]
pub struct SpanData {
    pub name: String,
    pub attributes: HashMap<String, AttrValue>,
    pub start_time_unix_nano: Option<u64>,
}

impl SpanData {
    /// Builds a [`SpanData`] from a name and an attribute iterator.
    pub fn new(name: impl Into<String>) -> Self {
        SpanData {
            name: name.into(),
            attributes: HashMap::new(),
            start_time_unix_nano: None,
        }
    }

    /// Inserts an attribute, returning `self` for chaining.
    pub fn with_attr(mut self, key: impl Into<String>, value: impl Into<AttrValue>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }
}

// --- attribute accessors ---------------------------------------------------

fn attrs(span: &SpanData) -> &HashMap<String, AttrValue> {
    &span.attributes
}

fn attr_str(a: &HashMap<String, AttrValue>, key: &str, default: &str) -> String {
    a.get(key).map(|v| v.to_attr_string()).unwrap_or_else(|| default.to_string())
}

fn opt_str(a: &HashMap<String, AttrValue>, key: &str) -> Option<String> {
    a.get(key).map(|v| v.to_attr_string())
}

fn attr_i64(a: &HashMap<String, AttrValue>, key: &str, default: i64) -> i64 {
    a.get(key).and_then(|v| v.as_i64()).unwrap_or(default)
}

fn opt_i64(a: &HashMap<String, AttrValue>, key: &str) -> Option<i64> {
    a.get(key).and_then(|v| v.as_i64())
}

fn attr_f64(a: &HashMap<String, AttrValue>, key: &str, default: f64) -> f64 {
    a.get(key).and_then(|v| v.as_f64()).unwrap_or(default)
}

fn opt_f64(a: &HashMap<String, AttrValue>, key: &str) -> Option<f64> {
    a.get(key).and_then(|v| v.as_f64())
}

fn attr_bool(a: &HashMap<String, AttrValue>, key: &str, default: bool) -> bool {
    a.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

fn opt_bool(a: &HashMap<String, AttrValue>, key: &str) -> Option<bool> {
    a.get(key).and_then(|v| v.as_bool())
}

fn span_time(span: &SpanData) -> String {
    match span.start_time_unix_nano {
        Some(nanos) => format!("1970-01-01T00:00:00Z+{}", nanos / 1_000_000_000),
        None => format!("1970-01-01T00:00:00Z+{}", now_secs()),
    }
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn first_non_empty(values: &[Option<String>]) -> Option<String> {
    values.iter().find_map(|v| v.clone().filter(|s| !s.is_empty()))
}

/// Maps AITF span data to reused OCSF AI events (OCSF PR #1641 / issue #1640).
#[derive(Default)]
pub struct OcsfMapper;

impl OcsfMapper {
    pub fn new() -> Self {
        OcsfMapper
    }

    /// Maps a span to an OCSF event, or `None` if it is not AI-related. Every
    /// returned event is enriched with the `ai_operation` profile.
    pub fn map_span(&self, span: &SpanData) -> Option<AIBaseEvent> {
        let a = attrs(span);
        let name = span.name.as_str();

        let mut event = if is_inference_span(name, a) {
            map_inference(span, a)
        } else if is_agent_comm_span(name, a) {
            map_agent_communication(span, a)?
        } else if is_agent_span(name, a) {
            map_agent_activity(span, a)
        } else if is_tool_span(name, a) {
            map_tool_execution(span, a)
        } else if is_rag_span(name, a) {
            map_data_retrieval(span, a)
        } else if is_security_span(name, a) {
            map_security_finding(span, a)
        } else if is_supply_chain_span(name, a) {
            map_supply_chain(span, a)
        } else if is_governance_span(name, a) {
            map_governance(span, a)
        } else if is_identity_span(name, a) {
            map_identity(span, a)
        } else if is_model_ops_span(name, a) {
            map_model_ops(span, a)
        } else if is_asset_inventory_span(name, a) {
            map_asset_inventory(span, a)
        } else {
            return None;
        };

        enrich_ai_operation(&mut event, a);
        Some(event)
    }

    /// Returns the OCSF event-type string for a span, or `None` if unrecognized.
    pub fn classify_span(&self, span: &SpanData) -> Option<&'static str> {
        let a = attrs(span);
        let name = span.name.as_str();
        if is_inference_span(name, a) {
            Some("model_inference")
        } else if is_agent_comm_span(name, a) {
            Some("agent_communication")
        } else if is_agent_span(name, a) {
            Some("agent_activity")
        } else if is_tool_span(name, a) {
            Some("tool_execution")
        } else if is_rag_span(name, a) {
            Some("data_retrieval")
        } else if is_security_span(name, a) {
            Some("security_finding")
        } else if is_supply_chain_span(name, a) {
            Some("supply_chain")
        } else if is_governance_span(name, a) {
            Some("governance")
        } else if is_identity_span(name, a) {
            Some("identity")
        } else if is_model_ops_span(name, a) {
            Some("model_ops")
        } else if is_asset_inventory_span(name, a) {
            Some("asset_inventory")
        } else {
            None
        }
    }
}

/// Attaches the OCSF `ai_operation` profile (`ai_agent` + `delegation`) to an
/// event, mirroring Python's `_enrich_ai_operation`.
fn enrich_ai_operation(event: &mut AIBaseEvent, a: &HashMap<String, AttrValue>) {
    if let Some(ai_agent) = build_ai_agent(a) {
        if event.ai_model.is_none() {
            event.ai_model = ai_agent.ai_model.clone();
        }
        event.ai_agent = Some(ai_agent);
    }
    if let Some(delegation) = build_delegation(a) {
        event.delegation = Some(delegation);
    }
    if let Some(lineage) = build_delegation_lineage(a) {
        event.delegation_lineage = Some(lineage);
    }
}

// --- classification --------------------------------------------------------

fn any_key_prefix(a: &HashMap<String, AttrValue>, prefixes: &[&str]) -> bool {
    a.keys().any(|k| prefixes.iter().any(|p| k.starts_with(p)))
}

fn is_inference_span(name: &str, a: &HashMap<String, AttrValue>) -> bool {
    name.starts_with("chat ")
        || name.starts_with("embeddings ")
        || name.starts_with("text_completion ")
        || a.contains_key(semconv::gen_ai::SYSTEM)
}

fn is_agent_comm_span(name: &str, a: &HashMap<String, AttrValue>) -> bool {
    name.starts_with("a2a.")
        || name.starts_with("acp.")
        || name.starts_with("anp.")
        || any_key_prefix(a, &["a2a.", "acp.", "anp.", "agent.comm."])
}

fn is_agent_span(name: &str, a: &HashMap<String, AttrValue>) -> bool {
    name.starts_with("agent.") || a.contains_key(semconv::agent::NAME)
}

fn is_tool_span(name: &str, a: &HashMap<String, AttrValue>) -> bool {
    name.starts_with("mcp.tool.")
        || name.starts_with("skill.invoke")
        || a.contains_key(semconv::gen_ai::TOOL_NAME)
        || a.contains_key(semconv::skill::NAME)
}

fn is_rag_span(name: &str, a: &HashMap<String, AttrValue>) -> bool {
    name.starts_with("rag.")
        || a.contains_key(semconv::rag::RETRIEVE_DATABASE)
        || a.contains_key(semconv::rag::RETRIEVE_INDEX)
}

fn is_security_span(_name: &str, a: &HashMap<String, AttrValue>) -> bool {
    a.contains_key(semconv::security::THREAT_DETECTED)
}

fn is_supply_chain_span(name: &str, a: &HashMap<String, AttrValue>) -> bool {
    name.starts_with("supply_chain.") || a.contains_key(semconv::supply_chain::MODEL_SOURCE)
}

fn is_governance_span(name: &str, a: &HashMap<String, AttrValue>) -> bool {
    name.starts_with("governance.")
        || name.starts_with("compliance.")
        || a.contains_key(semconv::compliance::FRAMEWORKS)
}

fn is_identity_span(name: &str, a: &HashMap<String, AttrValue>) -> bool {
    name.starts_with("identity.") || a.contains_key(semconv::identity::AGENT_ID)
}

fn is_model_ops_span(name: &str, a: &HashMap<String, AttrValue>) -> bool {
    name.starts_with("model_ops.")
        || name.starts_with("drift.")
        || a.contains_key(semconv::model_ops::TRAINING_RUN_ID)
        || a.contains_key(semconv::model_ops::EVALUATION_RUN_ID)
        || a.contains_key(semconv::model_ops::DEPLOYMENT_ID)
        || a.contains_key(semconv::drift::MODEL_ID)
}

fn is_asset_inventory_span(name: &str, a: &HashMap<String, AttrValue>) -> bool {
    name.starts_with("asset.") || a.contains_key(semconv::asset_inventory::ID)
}

// --- mapping ---------------------------------------------------------------

fn map_inference(span: &SpanData, a: &HashMap<String, AttrValue>) -> AIBaseEvent {
    let model_id = attr_str(a, semconv::gen_ai::REQUEST_MODEL, "unknown");
    let system = attr_str(a, semconv::gen_ai::SYSTEM, "unknown");
    let operation = attr_str(a, semconv::gen_ai::OPERATION_NAME, "chat");

    let activity_id = match operation.as_str() {
        "chat" => 1,
        "text_completion" => 2,
        "embeddings" => 3,
        _ => ACTIVITY_OTHER,
    };

    let model_type = if operation == "embeddings" { "embedding" } else { "llm" };

    let mut params: HashMap<String, serde_json::Value> = HashMap::new();
    for (k, v) in a.iter() {
        if k.starts_with("gen_ai.request.") && k != semconv::gen_ai::REQUEST_MODEL {
            let param = k.trim_start_matches("gen_ai.request.").to_string();
            params.insert(param, attr_to_json(v));
        }
    }

    let mut event = AIBaseEvent::new(CATEGORY_UID_APPLICATION, CLASS_UID_API_ACTIVITY, activity_id);

    let model = AIModelInfo {
        model_id: model_id.clone(),
        name: Some(model_id.clone()),
        provider: Some(system),
        model_type: Some(model_type.to_string()),
        parameters: if params.is_empty() { None } else { Some(params) },
        ..Default::default()
    };
    // Carry the model on the ai_operation profile (ai_model is a string in the
    // base event; full model detail is preserved on an enrichment).
    event.ai_model = Some(model.model_id.clone());

    let mut token_usage = AITokenUsage {
        input_tokens: attr_i64(a, semconv::gen_ai::USAGE_INPUT_TOKENS, 0),
        output_tokens: attr_i64(a, semconv::gen_ai::USAGE_OUTPUT_TOKENS, 0),
        cached_tokens: opt_i64(a, semconv::gen_ai::USAGE_CACHED_TOKENS),
        reasoning_tokens: opt_i64(a, semconv::gen_ai::USAGE_REASONING_TOKENS),
        ..Default::default()
    };
    token_usage.compute_total();

    let _ = (&token_usage, &model); // detail retained via enrichments below

    event.message = format!("{} {}", operation, model_id);
    event.time = span_time(span);
    if attr_bool(a, semconv::gen_ai::REQUEST_STREAM, false) {
        event.enrichments.push(enrichment("ai.streaming", "true"));
    }

    // Surface token usage + finish reason as enrichments so they are not lost.
    event.enrichments.push(enrichment("ai.model.id", &model_id));
    event.enrichments.push(enrichment(
        "ai.token_usage.total",
        &token_usage.total_tokens.to_string(),
    ));
    if let Some(reasons) = a.get(semconv::gen_ai::RESPONSE_FINISH_REASONS) {
        event
            .enrichments
            .push(enrichment("ai.finish_reason", &reasons.to_attr_string()));
    }
    if a.contains_key(semconv::latency::TOTAL_MS) {
        let total = attr_f64(a, semconv::latency::TOTAL_MS, 0.0);
        event
            .enrichments
            .push(enrichment("ai.latency.total_ms", &total.to_string()));
        let _ = (
            opt_f64(a, semconv::latency::TIME_TO_FIRST_TOKEN_MS),
            opt_f64(a, semconv::latency::TOKENS_PER_SECOND),
        );
    }
    if a.contains_key(semconv::cost::TOTAL_COST) {
        let total = attr_f64(a, semconv::cost::TOTAL_COST, 0.0);
        event
            .enrichments
            .push(enrichment("ai.cost.total_usd", &total.to_string()));
    }

    event
}

fn map_agent_communication(
    span: &SpanData,
    a: &HashMap<String, AttrValue>,
) -> Option<AIBaseEvent> {
    let msg = build_agent_message(a)?;

    let activity_id = match msg.direction.as_deref() {
        Some("request") => 1,
        Some("response") => 2,
        Some("stream") => 3,
        Some("notification") => 4,
        _ => ACTIVITY_OTHER,
    };

    let status_id =
        if msg.status.as_deref() == Some("failed") || msg.error_code.as_deref().is_some_and(|c| !c.is_empty()) {
            STATUS_FAILURE
        } else {
            STATUS_SUCCESS
        };

    let mut event =
        AIBaseEvent::new(CATEGORY_UID_AI, CLASS_UID_AGENT_COMMUNICATION, activity_id);
    event.status_id = status_id;
    event.message = if span.name.is_empty() {
        format!(
            "agent.comm.{}",
            msg.protocol.clone().unwrap_or_else(|| "unknown".to_string())
        )
    } else {
        span.name.clone()
    };
    event.time = span_time(span);

    // Carry agent_message fields as enrichments + keep error_code accessible.
    if let Some(ref ec) = msg.error_code {
        event.enrichments.push(enrichment("agent.comm.error_code", ec));
    }
    if let Some(ref status) = msg.status {
        event.enrichments.push(enrichment("agent.comm.status", status));
    }
    event.enrichments.push(enrichment(
        "agent.comm.protocol_id",
        &msg.protocol_id.to_string(),
    ));
    event.agent_message = Some(msg);
    Some(event)
}

fn map_agent_activity(span: &SpanData, a: &HashMap<String, AttrValue>) -> AIBaseEvent {
    let name = span.name.as_str();
    let activity_id = if name.contains("session") {
        1
    } else if name.contains("delegation") || name.contains("delegate") {
        4
    } else if name.contains("memory") {
        5
    } else {
        3
    };

    let mut event = AIBaseEvent::new(CATEGORY_UID_AI, CLASS_UID_AGENT_ACTIVITY, activity_id);
    event.message = span.name.clone();
    event.time = span_time(span);

    push_opt(&mut event, "agent.name", opt_str(a, semconv::agent::NAME));
    push_opt(&mut event, "agent.id", opt_str(a, semconv::agent::ID));
    push_opt(
        &mut event,
        "agent.session_id",
        opt_str(a, semconv::agent::SESSION_ID),
    );
    push_opt(&mut event, "agent.framework", opt_str(a, semconv::agent::FRAMEWORK));
    push_opt(&mut event, "agent.step.type", opt_str(a, semconv::agent::STEP_TYPE));
    event
}

fn map_tool_execution(span: &SpanData, a: &HashMap<String, AttrValue>) -> AIBaseEvent {
    let (tool_name, tool_type, activity_id) = if a.contains_key(semconv::gen_ai::TOOL_NAME) {
        (attr_str(a, semconv::gen_ai::TOOL_NAME, "unknown"), "mcp_tool", 2)
    } else if a.contains_key(semconv::skill::NAME) {
        (attr_str(a, semconv::skill::NAME, "unknown"), "skill", 3)
    } else {
        (attr_str(a, semconv::gen_ai::TOOL_NAME, "unknown"), "function", 1)
    };

    let mut event = AIBaseEvent::new(CATEGORY_UID_APPLICATION, CLASS_UID_API_ACTIVITY, activity_id);
    event.message = if span.name.is_empty() {
        format!("tool.execute {tool_name}")
    } else {
        span.name.clone()
    };
    event.time = span_time(span);

    event.enrichments.push(enrichment("tool.name", &tool_name));
    event.enrichments.push(enrichment("tool.type", tool_type));
    push_opt(
        &mut event,
        "tool.input",
        first_non_empty(&[opt_str(a, semconv::mcp::TOOL_INPUT), opt_str(a, semconv::skill::INPUT)]),
    );
    push_opt(
        &mut event,
        "tool.output",
        first_non_empty(&[opt_str(a, semconv::mcp::TOOL_OUTPUT), opt_str(a, semconv::skill::OUTPUT)]),
    );
    push_opt(&mut event, "tool.mcp_server", opt_str(a, semconv::mcp::TOOL_SERVER));
    let _ = (
        attr_bool(a, semconv::mcp::TOOL_IS_ERROR, false),
        opt_bool(a, semconv::mcp::TOOL_APPROVED),
        opt_f64(a, semconv::mcp::TOOL_DURATION_MS),
    );
    event
}

fn map_data_retrieval(span: &SpanData, a: &HashMap<String, AttrValue>) -> AIBaseEvent {
    let database = attr_str(a, semconv::rag::RETRIEVE_DATABASE, "unknown");
    let stage = attr_str(a, semconv::rag::PIPELINE_STAGE, "retrieve");

    let activity_id = match stage.as_str() {
        "retrieve" => 1,
        "rerank" => 5,
        _ => ACTIVITY_OTHER,
    };

    let mut event =
        AIBaseEvent::new(CATEGORY_UID_APPLICATION, CLASS_UID_DATASTORE_ACTIVITY, activity_id);
    event.message = if span.name.is_empty() {
        format!("rag.{stage} {database}")
    } else {
        span.name.clone()
    };
    event.time = span_time(span);

    event.enrichments.push(enrichment("rag.database", &database));
    event.enrichments.push(enrichment("rag.pipeline.stage", &stage));
    event.enrichments.push(enrichment(
        "rag.results_count",
        &attr_i64(a, semconv::rag::RETRIEVE_RESULTS_COUNT, 0).to_string(),
    ));
    push_opt(&mut event, "rag.query", opt_str(a, semconv::rag::QUERY));
    let _ = (
        opt_i64(a, semconv::rag::RETRIEVE_TOP_K),
        opt_f64(a, semconv::rag::RETRIEVE_MIN_SCORE),
        opt_f64(a, semconv::rag::RETRIEVE_MAX_SCORE),
    );
    event
}

fn map_security_finding(span: &SpanData, a: &HashMap<String, AttrValue>) -> AIBaseEvent {
    let risk_level = attr_str(a, semconv::security::RISK_LEVEL, "medium");
    let finding_type = attr_str(a, semconv::security::THREAT_TYPE, "unknown");

    let mut event = AIBaseEvent::new(CATEGORY_UID_FINDINGS, CLASS_UID_DETECTION_FINDING, 1);
    event.severity_id = match risk_level.as_str() {
        "critical" => SEVERITY_CRITICAL,
        "high" => SEVERITY_HIGH,
        "medium" => SEVERITY_MEDIUM,
        "low" => SEVERITY_LOW,
        "info" => SEVERITY_INFORMATIONAL,
        _ => SEVERITY_MEDIUM,
    };
    event.message = if span.name.is_empty() {
        format!("security.{finding_type}")
    } else {
        span.name.clone()
    };
    event.time = span_time(span);

    event.enrichments.push(enrichment("security.finding_type", &finding_type));
    event.enrichments.push(enrichment("security.risk_level", &risk_level));
    event.enrichments.push(enrichment(
        "security.risk_score",
        &attr_f64(a, semconv::security::RISK_SCORE, 50.0).to_string(),
    ));
    event.enrichments.push(enrichment(
        "security.confidence",
        &attr_f64(a, semconv::security::CONFIDENCE, 0.5).to_string(),
    ));
    let _ = (
        attr_bool(a, semconv::security::BLOCKED, false),
        opt_str(a, semconv::security::OWASP_CATEGORY),
    );
    event
}

fn map_supply_chain(span: &SpanData, a: &HashMap<String, AttrValue>) -> AIBaseEvent {
    let name = span.name.as_str();
    let activity_id = if name.contains("verify") || name.contains("validate") {
        1
    } else if name.contains("audit") {
        2
    } else if name.contains("sign") {
        3
    } else {
        ACTIVITY_OTHER
    };

    let mut event =
        AIBaseEvent::new(CATEGORY_UID_FINDINGS, CLASS_UID_VULNERABILITY_FINDING, activity_id);
    event.message = if name.is_empty() { "supply_chain.event".to_string() } else { span.name.clone() };
    event.time = span_time(span);

    let source = attr_str(a, semconv::supply_chain::MODEL_SOURCE, "unknown");
    event.enrichments.push(enrichment("supply_chain.model_source", &source));
    push_opt(&mut event, "supply_chain.model_hash", opt_str(a, semconv::supply_chain::MODEL_HASH));
    if a.contains_key(semconv::supply_chain::MODEL_SIGNED) {
        event.enrichments.push(enrichment(
            "supply_chain.model_signed",
            &attr_bool(a, semconv::supply_chain::MODEL_SIGNED, false).to_string(),
        ));
    }
    event
}

fn map_governance(span: &SpanData, a: &HashMap<String, AttrValue>) -> AIBaseEvent {
    let name = span.name.as_str();
    let activity_id = if name.contains("audit") {
        1
    } else if name.contains("assess") || name.contains("check") {
        2
    } else if name.contains("violat") {
        3
    } else if name.contains("remedia") {
        4
    } else {
        ACTIVITY_OTHER
    };

    let mut event = AIBaseEvent::new(CATEGORY_UID_FINDINGS, CLASS_UID_COMPLIANCE_FINDING, activity_id);
    event.message = if name.is_empty() { "governance.event".to_string() } else { span.name.clone() };
    event.time = span_time(span);

    let frameworks = a
        .get(semconv::compliance::FRAMEWORKS)
        .map(|v| v.to_str_list())
        .unwrap_or_default();
    if !frameworks.is_empty() {
        event
            .enrichments
            .push(enrichment("governance.frameworks", &frameworks.join(",")));
    }
    let event_type = if name.contains('.') {
        name.rsplit('.').next().unwrap_or(name).to_string()
    } else {
        name.to_string()
    };
    event.enrichments.push(enrichment("governance.event_type", &event_type));
    event
}

fn map_identity(span: &SpanData, a: &HashMap<String, AttrValue>) -> AIBaseEvent {
    let name = span.name.as_str();
    let activity_id = if name.contains("auth ") || name.contains(".auth ") {
        1
    } else if name.contains("authz") {
        2
    } else if name.contains("delegate") {
        3
    } else if name.contains("trust") {
        4
    } else if name.contains("lifecycle") {
        5
    } else if name.contains("session") {
        6
    } else {
        ACTIVITY_OTHER
    };

    let mut event = AIBaseEvent::new(CATEGORY_UID_IAM, CLASS_UID_AUTHENTICATION, activity_id);
    event.message = if name.is_empty() { "identity.event".to_string() } else { span.name.clone() };
    event.time = span_time(span);

    event.enrichments.push(enrichment(
        "identity.auth_method",
        &attr_str(a, semconv::identity::AUTH_METHOD, "unknown"),
    ));
    event.enrichments.push(enrichment(
        "identity.auth_result",
        &attr_str(a, semconv::identity::AUTH_RESULT, "unknown"),
    ));
    push_opt(&mut event, "identity.agent_id", opt_str(a, semconv::identity::AGENT_ID));
    event
}

fn map_model_ops(span: &SpanData, a: &HashMap<String, AttrValue>) -> AIBaseEvent {
    let name = span.name.as_str();
    let (operation_type, activity_id) = if name.starts_with("model_ops.training")
        || a.contains_key(semconv::model_ops::TRAINING_RUN_ID)
    {
        ("training", 1)
    } else if name.starts_with("model_ops.evaluation")
        || a.contains_key(semconv::model_ops::EVALUATION_RUN_ID)
    {
        ("evaluation", 2)
    } else if name.starts_with("model_ops.registry") {
        ("registry", 3)
    } else if name.starts_with("model_ops.deployment")
        || a.contains_key(semconv::model_ops::DEPLOYMENT_ID)
    {
        ("deployment", 4)
    } else if name.starts_with("model_ops.serving") {
        ("serving", 5)
    } else if name.starts_with("model_ops.monitoring") {
        ("monitoring", 6)
    } else if name.starts_with("model_ops.prompt") {
        ("prompt", 7)
    } else if name.starts_with("drift.") || a.contains_key(semconv::drift::MODEL_ID) {
        ("monitoring", 6)
    } else {
        ("unknown", ACTIVITY_OTHER)
    };

    let mut event =
        AIBaseEvent::new(CATEGORY_UID_APPLICATION, CLASS_UID_APPLICATION_LIFECYCLE, activity_id);
    event.message = if name.is_empty() {
        format!("model_ops.{operation_type}")
    } else {
        span.name.clone()
    };
    event.time = span_time(span);

    event.enrichments.push(enrichment("model_ops.operation_type", operation_type));
    push_opt(&mut event, "model_ops.training_type", opt_str(a, semconv::model_ops::TRAINING_TYPE));
    push_opt(&mut event, "model_ops.strategy", opt_str(a, semconv::model_ops::DEPLOYMENT_STRATEGY));
    if let Some(score) =
        opt_f64(a, semconv::model_ops::MONITORING_DRIFT_SCORE).or_else(|| opt_f64(a, semconv::drift::SCORE))
    {
        event.enrichments.push(enrichment("model_ops.drift_score", &score.to_string()));
    }
    if let Some(loss) = opt_f64(a, semconv::model_ops::TRAINING_LOSS_FINAL) {
        event.enrichments.push(enrichment("model_ops.loss_final", &loss.to_string()));
    }
    event
}

fn map_asset_inventory(span: &SpanData, a: &HashMap<String, AttrValue>) -> AIBaseEvent {
    let name = span.name.as_str();
    let (operation_type, activity_id) = if name.contains("register") {
        ("register", 1)
    } else if name.contains("discover") {
        ("discover", 2)
    } else if name.contains("audit") {
        ("audit", 3)
    } else if name.contains("classify") {
        ("classify", 4)
    } else if name.contains("decommission") {
        ("decommission", 5)
    } else {
        ("unknown", ACTIVITY_OTHER)
    };

    let mut event = AIBaseEvent::new(CATEGORY_UID_DISCOVERY, CLASS_UID_INVENTORY_INFO, activity_id);
    event.message = if name.is_empty() {
        format!("asset.{operation_type}")
    } else {
        span.name.clone()
    };
    event.time = span_time(span);

    event.enrichments.push(enrichment("asset.operation_type", operation_type));
    push_opt(&mut event, "asset.id", opt_str(a, semconv::asset_inventory::ID));
    push_opt(
        &mut event,
        "asset.risk_classification",
        opt_str(a, semconv::asset_inventory::RISK_CLASSIFICATION),
    );
    if let Some(found) = opt_i64(a, semconv::asset_inventory::DISCOVERY_ASSETS_FOUND) {
        event.enrichments.push(enrichment("asset.assets_found", &found.to_string()));
    }
    if let Some(shadow) = opt_i64(a, semconv::asset_inventory::DISCOVERY_SHADOW_ASSETS) {
        event.enrichments.push(enrichment("asset.shadow_assets", &shadow.to_string()));
    }
    event
}

// --- small helpers ---------------------------------------------------------

fn enrichment(name: &str, value: &str) -> OCSFEnrichment {
    OCSFEnrichment {
        name: name.to_string(),
        value: value.to_string(),
        ..Default::default()
    }
}

fn push_opt(event: &mut AIBaseEvent, name: &str, value: Option<String>) {
    if let Some(v) = value.filter(|s| !s.is_empty()) {
        event.enrichments.push(enrichment(name, &v));
    }
}

fn attr_to_json(v: &AttrValue) -> serde_json::Value {
    match v {
        AttrValue::Str(s) => serde_json::Value::String(s.clone()),
        AttrValue::Int(i) => serde_json::Value::from(*i),
        AttrValue::Float(f) => serde_json::Value::from(*f),
        AttrValue::Bool(b) => serde_json::Value::Bool(*b),
        AttrValue::StrList(l) => {
            serde_json::Value::Array(l.iter().map(|s| serde_json::Value::String(s.clone())).collect())
        }
    }
}
