//! AITF OCSF AI event schema.
//!
//! OCSF v1.1.0 base objects and AI-specific extension models. Following OCSF's
//! "reuse existing objects and profiles" approach (OCSF PR #1641 / issue #1640),
//! AITF emits AI telemetry under existing OCSF classes enriched with the
//! `ai_operation` profile, using the proposed "ai" category (uid 9) only for the
//! genuinely new agent / delegation control-plane classes.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// AITF SDK version reported in OCSF metadata.
pub const VERSION: &str = "1.0.0";

// --- OCSF Severity ---------------------------------------------------------

pub const SEVERITY_UNKNOWN: i32 = 0;
pub const SEVERITY_INFORMATIONAL: i32 = 1;
pub const SEVERITY_LOW: i32 = 2;
pub const SEVERITY_MEDIUM: i32 = 3;
pub const SEVERITY_HIGH: i32 = 4;
pub const SEVERITY_CRITICAL: i32 = 5;
pub const SEVERITY_FATAL: i32 = 6;

// --- OCSF Status -----------------------------------------------------------

pub const STATUS_UNKNOWN: i32 = 0;
pub const STATUS_SUCCESS: i32 = 1;
pub const STATUS_FAILURE: i32 = 2;
pub const STATUS_OTHER: i32 = 99;

// --- OCSF Activity ---------------------------------------------------------

pub const ACTIVITY_UNKNOWN: i32 = 0;
pub const ACTIVITY_CREATE: i32 = 1;
pub const ACTIVITY_READ: i32 = 2;
pub const ACTIVITY_UPDATE: i32 = 3;
pub const ACTIVITY_DELETE: i32 = 4;
pub const ACTIVITY_OTHER: i32 = 99;

// --- OCSF Category UIDs ----------------------------------------------------

/// The proposed "AI Activity" category (OCSF issue #1640).
pub const CATEGORY_UID_AI: i32 = 9;
pub const CATEGORY_UID_FINDINGS: i32 = 2;
pub const CATEGORY_UID_IAM: i32 = 3;
pub const CATEGORY_UID_DISCOVERY: i32 = 5;
pub const CATEGORY_UID_APPLICATION: i32 = 6;

// --- OCSF Class UIDs (full reuse set) --------------------------------------

pub const CLASS_UID_VULNERABILITY_FINDING: i32 = 2002;
pub const CLASS_UID_COMPLIANCE_FINDING: i32 = 2003;
pub const CLASS_UID_DETECTION_FINDING: i32 = 2004;
pub const CLASS_UID_ACCOUNT_CHANGE: i32 = 3001;
pub const CLASS_UID_AUTHENTICATION: i32 = 3002;
pub const CLASS_UID_ENTITY_MANAGEMENT: i32 = 3004;
pub const CLASS_UID_USER_ACCESS_MANAGEMENT: i32 = 3005;
pub const CLASS_UID_INVENTORY_INFO: i32 = 5001;
pub const CLASS_UID_WEB_RESOURCES_ACTIVITY: i32 = 6001;
pub const CLASS_UID_APPLICATION_LIFECYCLE: i32 = 6002;
pub const CLASS_UID_API_ACTIVITY: i32 = 6003;
pub const CLASS_UID_DATASTORE_ACTIVITY: i32 = 6005;
/// New control-plane classes in the proposed "ai" category (provisional UIDs).
pub const CLASS_UID_AGENT_ACTIVITY: i32 = 9001;
pub const CLASS_UID_DELEGATION_ACTIVITY: i32 = 9002;
pub const CLASS_UID_AGENT_COMMUNICATION: i32 = 9003;

// --- Agent type IDs (OCSF ai_agent.type_id, PR #1641) ----------------------

pub const AGENT_TYPE_ID_UNKNOWN: i32 = 0;
pub const AGENT_TYPE_ID_NATIVE: i32 = 1;
pub const AGENT_TYPE_ID_LANGCHAIN: i32 = 2;
pub const AGENT_TYPE_ID_AUTOGEN: i32 = 3;
pub const AGENT_TYPE_ID_CREWAI: i32 = 4;
pub const AGENT_TYPE_ID_OTHER: i32 = 99;

/// Returns the OCSF caption for an `ai_agent.type_id`, or `""` for Unknown.
pub fn agent_type_label(type_id: i32) -> &'static str {
    match type_id {
        AGENT_TYPE_ID_UNKNOWN => "Unknown",
        AGENT_TYPE_ID_NATIVE => "Native",
        AGENT_TYPE_ID_LANGCHAIN => "LangChain",
        AGENT_TYPE_ID_AUTOGEN => "AutoGen",
        AGENT_TYPE_ID_CREWAI => "CrewAI",
        AGENT_TYPE_ID_OTHER => "Other",
        _ => "Other",
    }
}

/// Maps an AITF framework string to an OCSF `ai_agent.type_id`. Empty -> Unknown
/// (0); known frameworks -> their enum member; any other value -> Other (99).
pub fn normalize_agent_type_id(framework: &str) -> i32 {
    let f = framework.trim().to_lowercase();
    if f.is_empty() {
        return AGENT_TYPE_ID_UNKNOWN;
    }
    match f.as_str() {
        "native" => AGENT_TYPE_ID_NATIVE,
        "langchain" => AGENT_TYPE_ID_LANGCHAIN,
        "langgraph" => AGENT_TYPE_ID_LANGCHAIN,
        "autogen" => AGENT_TYPE_ID_AUTOGEN,
        "crewai" => AGENT_TYPE_ID_CREWAI,
        _ => AGENT_TYPE_ID_OTHER,
    }
}

// --- Agent protocol IDs (OCSF agent_message.protocol_id) --------------------

pub const AGENT_PROTOCOL_ID_UNKNOWN: i32 = 0;
pub const AGENT_PROTOCOL_ID_A2A: i32 = 1;
pub const AGENT_PROTOCOL_ID_ACP: i32 = 2;
pub const AGENT_PROTOCOL_ID_ANP: i32 = 3;
pub const AGENT_PROTOCOL_ID_MCP: i32 = 4;
pub const AGENT_PROTOCOL_ID_OTHER: i32 = 99;

/// Returns the caption for an `agent_message.protocol_id`.
pub fn agent_protocol_label(protocol_id: i32) -> &'static str {
    match protocol_id {
        AGENT_PROTOCOL_ID_UNKNOWN => "Unknown",
        AGENT_PROTOCOL_ID_A2A => "A2A",
        AGENT_PROTOCOL_ID_ACP => "ACP",
        AGENT_PROTOCOL_ID_ANP => "ANP",
        AGENT_PROTOCOL_ID_MCP => "MCP",
        AGENT_PROTOCOL_ID_OTHER => "Other",
        _ => "Other",
    }
}

/// Maps a protocol string to an OCSF `agent_message.protocol_id`. Empty ->
/// Unknown (0); known protocols -> their enum member; any other value -> Other.
pub fn normalize_agent_protocol_id(protocol: &str) -> i32 {
    let p = protocol.trim().to_lowercase();
    if p.is_empty() {
        return AGENT_PROTOCOL_ID_UNKNOWN;
    }
    match p.as_str() {
        "a2a" => AGENT_PROTOCOL_ID_A2A,
        "acp" => AGENT_PROTOCOL_ID_ACP,
        "anp" => AGENT_PROTOCOL_ID_ANP,
        "mcp" => AGENT_PROTOCOL_ID_MCP,
        _ => AGENT_PROTOCOL_ID_OTHER,
    }
}

/// Computes the OCSF `type_uid` as `class_uid * 100 + activity_id`.
pub fn compute_type_uid(class_uid: i32, activity_id: i32) -> i32 {
    class_uid * 100 + activity_id
}

// --- OCSF Base Objects -----------------------------------------------------

/// OCSF event metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OCSFMetadata {
    pub version: String,
    pub product: HashMap<String, String>,
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_time: Option<String>,
    pub logged_time: String,
}

impl OCSFMetadata {
    /// Creates metadata with AITF defaults.
    pub fn new() -> Self {
        let mut product = HashMap::new();
        product.insert("name".to_string(), "AITF".to_string());
        product.insert("vendor_name".to_string(), "AITF".to_string());
        product.insert("version".to_string(), VERSION.to_string());
        OCSFMetadata {
            version: "1.1.0".to_string(),
            product,
            uid: generate_uid(),
            correlation_uid: None,
            original_time: None,
            logged_time: now_rfc3339(),
        }
    }
}

/// OCSF actor information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OCSFActor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
}

/// OCSF device / host information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OCSFDevice {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub device_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<HashMap<String, String>>,
}

/// OCSF enrichment data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OCSFEnrichment {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub enrichment_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// OCSF observable value.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OCSFObservable {
    pub name: String,
    #[serde(rename = "type")]
    pub observable_type: String,
    pub value: String,
}

// --- OCSF ai_operation profile objects -------------------------------------

/// OCSF `ai_agent` object (OCSF PR #1641): an autonomous AI agent operating
/// under delegated authority.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OCSFAIAgent {
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub agent_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charter: Option<String>,
}

/// OCSF `delegation` object (OCSF issue #1640): a durable authorization context.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OCSFDelegation {
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegatee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub delegation_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
}

/// A single node in an OCSF `delegation_lineage` graph (OCSF issue #1640).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OCSFDelegationNode {
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_uid: Option<String>,
    pub depth: i32,
}

/// OCSF `delegation_lineage` directed graph for ancestry queries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OCSFDelegationLineage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<OCSFDelegationNode>>,
}

/// OCSF `agent_message` object — one generic representation of an
/// agent-to-agent communication across A2A / ACP / ANP / MCP.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OCSFAgentMessage {
    pub protocol_id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_agent: Option<OCSFAIAgent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_agent: Option<OCSFAIAgent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<OCSFDelegation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_trust_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_domain: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

// --- AI-specific extension models ------------------------------------------

/// AI model information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AIModelInfo {
    pub model_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub model_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, serde_json::Value>>,
}

/// AI token usage statistics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AITokenUsage {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd: Option<f64>,
}

impl AITokenUsage {
    /// Sets `total_tokens` to `input + output` when it is zero.
    pub fn compute_total(&mut self) {
        if self.total_tokens == 0 {
            self.total_tokens = self.input_tokens + self.output_tokens;
        }
    }
}

/// AI operation latency metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AILatencyMetrics {
    pub total_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_to_first_token_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_per_second: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_time_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference_time_ms: Option<f64>,
}

/// AI operation cost information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AICostInfo {
    pub input_cost_usd: f64,
    pub output_cost_usd: f64,
    pub total_cost_usd: f64,
    pub currency: String,
}

/// Security finding details.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AISecurityFinding {
    pub finding_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp_category: Option<String>,
    pub risk_level: String,
    pub risk_score: f64,
    pub confidence: f64,
    pub detection_method: String,
    pub blocked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

// --- OCSF Base Event -------------------------------------------------------

/// The base OCSF event for AITF AI events.
///
/// `category_uid` / `class_uid` are set to the OCSF class the event reuses
/// (OCSF PR #1641 / issue #1640); AI-specific context rides on the
/// `ai_operation` profile (`ai_agent`, `ai_model`, `delegation`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AIBaseEvent {
    pub activity_id: i32,
    pub category_uid: i32,
    pub class_uid: i32,
    pub type_uid: i32,
    pub time: String,
    pub severity_id: i32,
    pub status_id: i32,
    pub message: String,
    pub metadata: OCSFMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<OCSFActor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<OCSFDevice>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub enrichments: Vec<OCSFEnrichment>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub observables: Vec<OCSFObservable>,

    // OCSF ai_operation profile (PR #1641) + delegation context (issue #1640).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_agent: Option<OCSFAIAgent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<OCSFDelegation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_lineage: Option<OCSFDelegationLineage>,

    /// OCSF `agent_message` object, present only on agent-communication events
    /// (class 9003).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_message: Option<OCSFAgentMessage>,

    /// Compliance-framework metadata, attached by the [`crate::ocsf::ComplianceMapper`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<crate::ocsf::compliance::ComplianceMetadata>,
}

impl AIBaseEvent {
    /// Creates a base event with default values, reusing the given OCSF
    /// `category_uid` / `class_uid`.
    pub fn new(category_uid: i32, class_uid: i32, activity_id: i32) -> Self {
        AIBaseEvent {
            activity_id,
            category_uid,
            class_uid,
            type_uid: compute_type_uid(class_uid, activity_id),
            time: now_rfc3339(),
            severity_id: SEVERITY_INFORMATIONAL,
            status_id: STATUS_SUCCESS,
            message: String::new(),
            metadata: OCSFMetadata::new(),
            actor: None,
            device: None,
            enrichments: Vec::new(),
            observables: Vec::new(),
            ai_agent: None,
            ai_model: None,
            delegation: None,
            delegation_lineage: None,
            agent_message: None,
            compliance: None,
        }
    }

    /// Recomputes and returns `type_uid` as `class_uid * 100 + activity_id`.
    pub fn compute_type_uid(&self) -> i32 {
        compute_type_uid(self.class_uid, self.activity_id)
    }

    /// Serializes the event to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// --- helpers ---------------------------------------------------------------

/// A counter-based, dependency-free pseudo-unique identifier. The Go/Python SDKs
/// use crypto-random UIDs; this v0 crate avoids extra runtime deps, so the UID
/// is process-local and not globally unique (sufficient for correlation in a
/// single emitter run).
fn generate_uid() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:032x}", (nanos << 16) ^ (n as u128))
}

/// Returns the current UTC time as a coarse RFC3339-style timestamp.
///
/// v0 avoids a date/time dependency; it emits an epoch-seconds marker so the
/// field is always populated. Mappers overwrite this with the span time.
fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("1970-01-01T00:00:00Z+{secs}")
}
