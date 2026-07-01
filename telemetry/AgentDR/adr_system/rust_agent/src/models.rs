//! AITF OCSF Class-Reuse constants, the `ai_operation` profile, `EventRecord`,
//! agent signatures, and detection rules.
//!
//! AITF (the CoSAI AI Telemetry Framework) **dropped its bespoke "Category 7"**
//! and now maps every AI event onto an *existing* OCSF class enriched with an
//! `ai_operation` profile (per the OCSF principle of reusing classes rather
//! than minting bespoke AI event classes). Data-plane events flow through the
//! standard categories (2–6); only the control-plane agent/delegation lifecycle
//! uses the proposed Category 9 classes (OCSF issue #1640, provisional).
//!
//! Detection signatures, AI-endpoint rules, and messaging-endpoint rules are
//! loaded at runtime from the `cosai-community/rules/` JSON files so they can
//! be updated **without recompiling** the agent binary.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;
use uuid::Uuid;

// ── OCSF reused class_uids (AITF Class-Reuse Model) ──
// Data-plane events reuse existing OCSF classes (categories 2–6).
pub const OCSF_APP_LIFECYCLE: u32 = 6002; // Application Lifecycle — model operations
pub const OCSF_API_ACTIVITY: u32 = 6003; // API Activity — inference, tool & MCP calls
pub const OCSF_DATASTORE_ACTIVITY: u32 = 6005; // Datastore Activity — RAG / vector retrieval
pub const OCSF_INVENTORY_INFO: u32 = 5001; // Inventory Info — asset inventory
pub const OCSF_AUTHENTICATION: u32 = 3002; // Authentication — identity / delegation auth
pub const OCSF_DETECTION_FINDING: u32 = 2004; // Detection Finding — security findings
pub const OCSF_COMPLIANCE_FINDING: u32 = 2003; // Compliance Finding — governance
pub const OCSF_VULNERABILITY_FINDING: u32 = 2002; // Vulnerability Finding — supply chain
// Control-plane lifecycle uses the proposed Category 9 (OCSF #1640, provisional).
pub const OCSF_AGENT_ACTIVITY: u32 = 9001; // agent_activity (proposed)
pub const OCSF_DELEGATION_ACTIVITY: u32 = 9002; // delegation_activity (proposed)

/// The AITF **`ai_operation` profile**: the AI-specific semantic carried on a
/// reused OCSF class. Because AITF collapses many AI operations onto a handful
/// of OCSF classes (e.g. inference, tool and MCP calls all map to API Activity
/// `6003`), this enum preserves the fine-grained operation while
/// [`ocsf_class_uid`](AiOperation::ocsf_class_uid) yields the canonical class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiOperation {
    Inference,
    AgentAction,
    ToolExecution,
    McpOperation,
    DataRetrieval,
    ModelOps,
    PromptInjection,
    DataExfiltration,
    PermissionEscalation,
    GuardrailEvent,
    CostAnomaly,
    ComplianceViolation,
    SupplyChain,
    Identity,
    AssetInventory,
    Delegation,
}

impl AiOperation {
    /// The `ai_operation` profile string emitted alongside the OCSF class.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inference => "inference",
            Self::AgentAction => "agent_action",
            Self::ToolExecution => "tool_execution",
            Self::McpOperation => "mcp_operation",
            Self::DataRetrieval => "data_retrieval",
            Self::ModelOps => "model_ops",
            Self::PromptInjection => "prompt_injection",
            Self::DataExfiltration => "data_exfiltration",
            Self::PermissionEscalation => "permission_escalation",
            Self::GuardrailEvent => "guardrail",
            Self::CostAnomaly => "cost_anomaly",
            Self::ComplianceViolation => "compliance_violation",
            Self::SupplyChain => "supply_chain",
            Self::Identity => "identity",
            Self::AssetInventory => "asset_inventory",
            Self::Delegation => "delegation",
        }
    }

    /// The reused OCSF `class_uid` this AI operation maps onto.
    pub fn ocsf_class_uid(&self) -> u32 {
        match self {
            Self::Inference | Self::ToolExecution | Self::McpOperation => OCSF_API_ACTIVITY,
            Self::DataRetrieval => OCSF_DATASTORE_ACTIVITY,
            Self::ModelOps => OCSF_APP_LIFECYCLE,
            Self::AgentAction => OCSF_AGENT_ACTIVITY,
            Self::Delegation => OCSF_DELEGATION_ACTIVITY,
            Self::PromptInjection
            | Self::DataExfiltration
            | Self::PermissionEscalation
            | Self::GuardrailEvent
            | Self::CostAnomaly => OCSF_DETECTION_FINDING,
            Self::ComplianceViolation => OCSF_COMPLIANCE_FINDING,
            Self::SupplyChain => OCSF_VULNERABILITY_FINDING,
            Self::Identity => OCSF_AUTHENTICATION,
            Self::AssetInventory => OCSF_INVENTORY_INFO,
        }
    }
}

// ── Activity IDs ──
pub const ACTIVITY_CREATE: u32 = 1;
pub const ACTIVITY_READ: u32 = 2;
pub const ACTIVITY_UPDATE: u32 = 3;
pub const ACTIVITY_DELETE: u32 = 4;
pub const ACTIVITY_EXECUTE: u32 = 5;
pub const ACTIVITY_DETECT: u32 = 6;
pub const ACTIVITY_BLOCK: u32 = 7;

// ── Status IDs ──
pub const STATUS_SUCCESS: u32 = 1;
pub const STATUS_FAILURE: u32 = 2;
pub const STATUS_BLOCKED: u32 = 3;

/// Map risk level string to OCSF severity_id.
pub fn severity_from_risk(risk: &str) -> u32 {
    match risk {
        "low" => 1,
        "medium" => 3,
        "high" => 4,
        "critical" => 5,
        _ => 1,
    }
}

pub fn utc_now_iso() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn gen_trace_id() -> String {
    Uuid::new_v4().simple().to_string()[..32].to_string()
}

pub fn gen_span_id() -> String {
    Uuid::new_v4().simple().to_string()[..16].to_string()
}

// ══════════════════════════════════════════════════════════════════════
// JSON rule-file loader — reads cosai-community/rules/ at runtime so
// detection signatures can be updated without recompiling the binary.
// ══════════════════════════════════════════════════════════════════════

fn rules_dir() -> PathBuf {
    // Resolve: <exe_dir>/../cosai-community/rules/  (development layout)
    // Falls back to <cwd>/cosai-community/rules/ if the first doesn't exist.
    let exe = std::env::current_exe().unwrap_or_default();
    let dev = exe.parent().unwrap_or(std::path::Path::new("."))
        .join("../cosai-community/rules");
    if dev.exists() { return dev; }
    PathBuf::from("cosai-community/rules")
}

fn load_json(filename: &str) -> serde_json::Value {
    let path = rules_dir().join(filename);
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
        Err(_) => {
            eprintln!("[cosai] warning: could not load {:?}", path);
            serde_json::Value::Null
        }
    }
}

// ── Agent Categories ──

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentCategory {
    Coding, General, Workflow, Enterprise, Browser, Unknown,
}

impl AgentCategory {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Coding     => "coding",
            Self::General    => "general",
            Self::Workflow   => "workflow",
            Self::Enterprise => "enterprise",
            Self::Browser    => "browser",
            Self::Unknown    => "unknown",
        }
    }
    fn from_str(s: &str) -> Self {
        match s {
            "coding"     => Self::Coding,
            "general"    => Self::General,
            "workflow"   => Self::Workflow,
            "enterprise" => Self::Enterprise,
            "browser"    => Self::Browser,
            _            => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentSignature {
    pub name: String,
    pub framework: String,
    pub category: AgentCategory,
}

/// Flattened (pattern → signature) pairs loaded from agent-signatures.json.
struct LoadedSignatures {
    entries: Vec<(String, AgentSignature)>,
}

fn loaded_signatures() -> &'static LoadedSignatures {
    static INSTANCE: OnceLock<LoadedSignatures> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let val = load_json("agent-signatures.json");
        let mut entries = Vec::new();
        if let Some(sigs) = val.get("signatures").and_then(|v| v.as_array()) {
            for sig in sigs {
                let name = sig.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let framework = sig.get("framework").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let cat = AgentCategory::from_str(
                    sig.get("category").and_then(|v| v.as_str()).unwrap_or("unknown")
                );
                if let Some(pats) = sig.get("process_patterns").and_then(|v| v.as_array()) {
                    for pat in pats {
                        if let Some(p) = pat.as_str() {
                            entries.push((p.to_string(), AgentSignature {
                                name: name.clone(), framework: framework.clone(), category: cat.clone(),
                            }));
                        }
                    }
                }
            }
        }
        LoadedSignatures { entries }
    })
}

/// Identify an AI agent from process details (name + exe + cmdline concatenated).
pub fn identify_agent(haystack: &str) -> Option<AgentSignature> {
    let lower = haystack.to_lowercase();
    for (key, sig) in &loaded_signatures().entries {
        if lower.contains(key.as_str()) {
            return Some(sig.clone());
        }
    }
    None
}

// ── AI provider classification (loaded from ai-endpoints.json) ──

#[derive(Debug, Clone, Serialize)]
pub struct AiProviderInfo {
    pub provider: String,
    pub model: String,
}

#[derive(Debug)]
struct AiEndpointRule {
    patterns: Vec<String>,
    requires_also: Option<String>,
    provider: String,
    model: String,
}

struct LoadedAiEndpoints {
    rules: Vec<AiEndpointRule>,
}

fn loaded_ai_endpoints() -> &'static LoadedAiEndpoints {
    static INSTANCE: OnceLock<LoadedAiEndpoints> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let val = load_json("ai-endpoints.json");
        let mut rules = Vec::new();
        if let Some(eps) = val.get("endpoints").and_then(|v| v.as_array()) {
            for ep in eps {
                let patterns: Vec<String> = ep.get("patterns")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|p| p.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let requires_also = ep.get("requires_also").and_then(|v| v.as_str()).map(String::from);
                let provider = ep.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let model = ep.get("model").and_then(|v| v.as_str()).unwrap_or("").to_string();
                rules.push(AiEndpointRule { patterns, requires_also, provider, model });
            }
        }
        LoadedAiEndpoints { rules }
    })
}

pub fn classify_ai_endpoint(host: &str) -> Option<AiProviderInfo> {
    let h = host.to_lowercase();
    if h.is_empty() { return None; }
    for rule in &loaded_ai_endpoints().rules {
        if let Some(ref also) = rule.requires_also {
            if !h.contains(also.as_str()) { continue; }
        }
        for pat in &rule.patterns {
            if h.contains(pat.as_str()) {
                return Some(AiProviderInfo {
                    provider: rule.provider.clone(),
                    model: rule.model.clone(),
                });
            }
        }
    }
    None
}

// ── Messaging platform classification (loaded from messaging-endpoints.json) ──

struct LoadedMessagingEndpoints {
    entries: Vec<(String, String)>,
}

fn loaded_messaging_endpoints() -> &'static LoadedMessagingEndpoints {
    static INSTANCE: OnceLock<LoadedMessagingEndpoints> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let val = load_json("messaging-endpoints.json");
        let mut entries = Vec::new();
        if let Some(eps) = val.get("endpoints").and_then(|v| v.as_array()) {
            for ep in eps {
                let pat = ep.get("pattern").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let plat = ep.get("platform").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if !pat.is_empty() { entries.push((pat, plat)); }
            }
        }
        LoadedMessagingEndpoints { entries }
    })
}

pub fn classify_messaging_endpoint(host: &str) -> Option<String> {
    let h = host.to_lowercase();
    for (endpoint, platform) in &loaded_messaging_endpoints().entries {
        if h.contains(endpoint.as_str()) {
            return Some(platform.clone());
        }
    }
    None
}

// ── Skill path detection ──

static SKILL_PATHS: &[&str] = &[
    ".openclaw/skills",
    "openclaw_skills",
    "skills/",
    ".autogpt/plugins",
    "plugins/",
    ".agent/tools",
    ".hermes/skills",
    ".nous/skills",
    "agentskills",
];

pub fn is_skill_path(filepath: &str) -> bool {
    let lower = filepath.to_lowercase().replace('\\', "/");
    SKILL_PATHS.iter().any(|sp| lower.contains(sp))
}

// ── Detection rules ──

#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub name: &'static str,
    pub owasp: &'static str,
    /// AITF `ai_operation` profile for the emitted finding. Its
    /// [`ocsf_class_uid`](AiOperation::ocsf_class_uid) yields the reused OCSF
    /// finding class (Detection `2004`, Compliance `2003`, Vulnerability `2002`).
    pub op: AiOperation,
}

pub fn detection_rules() -> HashMap<&'static str, DetectionRule> {
    use AiOperation::*;
    let mut m = HashMap::new();
    // IDs 001–014 are the canonical AITF built-in rules; 015–020 are AgentDR
    // endpoint-specific extensions. Names mirror cosai-community/policies/detection-rules.json.
    m.insert("AITF-DET-001", DetectionRule { name: "Unusual Token Usage",            owasp: "LLM01", op: CostAnomaly });
    m.insert("AITF-DET-002", DetectionRule { name: "Model Switching Attack",         owasp: "LLM02", op: PromptInjection });
    m.insert("AITF-DET-003", DetectionRule { name: "Prompt Injection Attempt",       owasp: "LLM04", op: PromptInjection });
    m.insert("AITF-DET-004", DetectionRule { name: "Excessive Cost Spike",           owasp: "LLM05", op: CostAnomaly });
    m.insert("AITF-DET-005", DetectionRule { name: "Agent Loop Detection",           owasp: "LLM08", op: GuardrailEvent });
    m.insert("AITF-DET-006", DetectionRule { name: "Unauthorized Agent Delegation",  owasp: "LLM03", op: PermissionEscalation });
    m.insert("AITF-DET-007", DetectionRule { name: "Agent Session Hijack",           owasp: "LLM02", op: PermissionEscalation });
    m.insert("AITF-DET-008", DetectionRule { name: "Excessive Tool Calls",           owasp: "LLM04", op: GuardrailEvent });
    m.insert("AITF-DET-009", DetectionRule { name: "MCP Server Impersonation",       owasp: "LLM08", op: PermissionEscalation });
    m.insert("AITF-DET-010", DetectionRule { name: "Tool Permission Bypass",         owasp: "LLM06", op: PermissionEscalation });
    m.insert("AITF-DET-011", DetectionRule { name: "Data Exfiltration via Tools",    owasp: "LLM05", op: DataExfiltration });
    m.insert("AITF-DET-012", DetectionRule { name: "PII Exfiltration Chain",         owasp: "LLM04", op: DataExfiltration });
    m.insert("AITF-DET-013", DetectionRule { name: "Jailbreak Escalation",           owasp: "LLM05", op: GuardrailEvent });
    m.insert("AITF-DET-014", DetectionRule { name: "Supply Chain Compromise",        owasp: "LLM09", op: SupplyChain });
    m.insert("AITF-DET-015", DetectionRule { name: "Malicious Skill/Plugin Loaded",  owasp: "LLM03", op: SupplyChain });
    m.insert("AITF-DET-016", DetectionRule { name: "Unauthorized Messaging Channel", owasp: "LLM05", op: DataExfiltration });
    m.insert("AITF-DET-017", DetectionRule { name: "Shell Command Execution",        owasp: "LLM08", op: PermissionEscalation });
    m.insert("AITF-DET-018", DetectionRule { name: "Credential / Secret Access",     owasp: "LLM06", op: DataExfiltration });
    m.insert("AITF-DET-019", DetectionRule { name: "Cross-Platform Data Relay",      owasp: "LLM02", op: DataExfiltration });
    m.insert("AITF-DET-020", DetectionRule { name: "Unvetted Skill Installation",    owasp: "LLM03", op: SupplyChain });
    m
}

// ── Credential file patterns ──

pub static CREDENTIAL_PATTERNS: &[&str] = &[
    ".env", ".env.local", ".env.production", ".env.development",
    "id_rsa", "id_ed25519", "id_ecdsa", "known_hosts", "authorized_keys",
    ".aws/credentials", ".aws/config",
    ".gcloud/credentials.json", ".config/gcloud",
    ".npmrc", ".pypirc",
    "secrets.json", "service-account.json", "keyfile.json",
];

pub fn is_credential_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    CREDENTIAL_PATTERNS.iter().any(|p| lower.contains(&p.to_lowercase()))
}

// ── The core event record ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub timestamp: String,
    pub event_type: String,
    pub details: serde_json::Value,
    pub risk_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_detected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    // AITF OCSF Class-Reuse fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_uid: Option<u32>,
    /// AITF `ai_operation` profile — the AI-specific semantic carried on the
    /// reused OCSF class (e.g. `inference`, `tool_execution`, `mcp_operation`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_framework: Option<String>,
    /// AITF 0.2 `ai_agent` object (provisional, OCSF PR #1641) — structured
    /// agent identity carried on every AI-attributable event: `uid` (required,
    /// stable logical id), `instance_uid`, `name`, `type`, `type_id`,
    /// `ai_model`, `version`, `charter`. Built from the flat `agent_name` /
    /// `agent_framework` / `model` fields (kept for backward compatibility) via
    /// [`EventRecord::build_ai_agent`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_agent: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<serde_json::Value>,
    /// AITF 0.2 `delegation` object — agent-to-agent authorization grant/revoke
    /// (`grantor`, `grantee`, `scope`, `ttl_seconds`, `action`). Set on events
    /// carrying delegation telemetry (`ai_operation = delegation`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_finding: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_usage: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_info: Option<serde_json::Value>,
    pub trace_id: String,
    pub span_id: String,
}

impl EventRecord {
    pub fn new(event_type: &str, details: serde_json::Value, risk_level: &str) -> Self {
        let severity_id = severity_from_risk(risk_level);
        Self {
            timestamp: utc_now_iso(),
            event_type: event_type.to_string(),
            details,
            risk_level: risk_level.to_string(),
            agent_detected: None,
            source: None,
            class_uid: None,
            ai_operation: None,
            type_uid: None,
            activity_id: None,
            severity_id: Some(severity_id),
            status_id: Some(STATUS_SUCCESS),
            message: None,
            provider: None,
            model: None,
            agent_name: None,
            agent_framework: None,
            ai_agent: None,
            tool_name: None,
            mcp_server: None,
            actor: None,
            delegation: None,
            compliance: None,
            security_finding: None,
            token_usage: None,
            cost_info: None,
            trace_id: gen_trace_id(),
            span_id: gen_span_id(),
        }
    }

    /// Apply the AITF `ai_operation` profile: set the reused OCSF `class_uid`,
    /// the derived `type_uid` (`class_uid * 100 + activity_id`, per OCSF), and
    /// the `ai_operation` string in one call.
    pub fn set_op(&mut self, op: AiOperation, activity_id: u32) {
        let class_uid = op.ocsf_class_uid();
        self.class_uid = Some(class_uid);
        self.type_uid = Some(class_uid * 100 + activity_id);
        self.ai_operation = Some(op.as_str().to_string());
    }

    /// Build the AITF 0.2 `ai_agent` object from the flat agent fields on this
    /// event. Called after `agent_name` / `agent_framework` / `model` are set.
    ///
    /// * `uid` — `explicit_uid` when known (e.g. `gen_ai.agent.id`), else a
    ///   deterministic [`stable_agent_uid`] of the name (+framework) so the
    ///   same logical agent keeps a stable id across restarts / hosts.
    /// * `instance_uid` — restart-sensitive running instance (conversation /
    ///   session id), when available.
    /// * `type` / `type_id` — framework caption + normalized enum.
    /// * `ai_model` — the backing model.
    ///
    /// No-op when there is no agent identity to describe.
    pub fn build_ai_agent(&mut self, explicit_uid: Option<&str>, instance_uid: Option<&str>) {
        let has_identity = explicit_uid.is_some()
            || self.agent_name.is_some()
            || self.agent_framework.is_some();
        if !has_identity {
            return;
        }

        let uid = match explicit_uid {
            Some(u) if !u.is_empty() => u.to_string(),
            _ => stable_agent_uid(self.agent_name.as_deref(), self.agent_framework.as_deref()),
        };

        let mut obj = serde_json::Map::new();
        obj.insert("uid".into(), serde_json::Value::String(uid));
        if let Some(iid) = instance_uid.filter(|s| !s.is_empty()) {
            obj.insert("instance_uid".into(), serde_json::Value::String(iid.to_string()));
        }
        if let Some(name) = &self.agent_name {
            obj.insert("name".into(), serde_json::Value::String(name.clone()));
        }
        if let Some(fw) = &self.agent_framework {
            obj.insert("type".into(), serde_json::Value::String(fw.clone()));
            obj.insert("type_id".into(), serde_json::Value::from(framework_type_id(fw)));
        }
        if let Some(model) = &self.model {
            obj.insert("ai_model".into(), serde_json::Value::String(model.clone()));
        }
        self.ai_agent = Some(serde_json::Value::Object(obj));
    }
}

/// Deterministic, stable logical agent `uid` derived from the agent name (and
/// framework) when no explicit id is provided by telemetry. Uses FNV-1a so the
/// same identity yields the same `agent:<hex>` id across restarts and hosts.
pub fn stable_agent_uid(name: Option<&str>, framework: Option<&str>) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let feed = |h: &mut u64, s: &str| {
        for b in s.bytes() {
            *h ^= b as u64;
            *h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    feed(&mut h, name.unwrap_or("unknown"));
    feed(&mut h, "|");
    feed(&mut h, framework.unwrap_or(""));
    format!("agent:{h:016x}")
}

/// Normalize an agent framework string to the AITF `ai_agent.type_id` enum
/// (mirrors OCSF PR #1641; `0` = Unknown, `99` = Other). The specific codes
/// track the ratified enum once #1641 lands; today this is a best-effort
/// normalization over the frameworks AgentDR recognizes.
pub fn framework_type_id(framework: &str) -> u32 {
    let f = framework.to_ascii_lowercase();
    if f.is_empty() {
        0
    } else if f.contains("langgraph") {
        2
    } else if f.contains("langchain") {
        1
    } else if f.contains("llamaindex") || f.contains("llama-index") || f.contains("llama_index") {
        3
    } else if f.contains("autogen") {
        4
    } else if f.contains("crewai") || f.contains("crew-ai") {
        5
    } else if f.contains("semantic") && f.contains("kernel") {
        6
    } else if f.contains("pydantic") {
        7
    } else if f.contains("google") && f.contains("adk") {
        8
    } else if f.contains("strands") {
        9
    } else if f.contains("openai") && (f.contains("agent") || f.contains("assistant")) {
        10
    } else if f.contains("anthropic") || f.contains("claude") {
        11
    } else {
        99
    }
}

#[cfg(test)]
mod ai_agent_tests {
    use super::*;

    #[test]
    fn stable_uid_is_deterministic_and_identity_scoped() {
        let a = stable_agent_uid(Some("claude-code"), Some("anthropic"));
        let b = stable_agent_uid(Some("claude-code"), Some("anthropic"));
        assert_eq!(a, b, "same identity → same uid");
        assert!(a.starts_with("agent:"));
        assert_ne!(a, stable_agent_uid(Some("cursor"), Some("anthropic")));
        assert_ne!(a, stable_agent_uid(Some("claude-code"), Some("langchain")));
    }

    #[test]
    fn framework_type_id_normalizes_known_and_unknown() {
        assert_eq!(framework_type_id(""), 0);
        assert_eq!(framework_type_id("LangChain"), 1);
        assert_eq!(framework_type_id("langgraph"), 2); // langgraph before langchain
        assert_eq!(framework_type_id("LlamaIndex"), 3);
        assert_eq!(framework_type_id("some-bespoke-framework"), 99);
    }

    #[test]
    fn build_ai_agent_from_flat_fields() {
        let mut ev = EventRecord::new("otlp_span", serde_json::json!({}), "low");
        ev.agent_name = Some("claude-code".into());
        ev.agent_framework = Some("anthropic".into());
        ev.model = Some("claude-opus-4".into());
        ev.build_ai_agent(None, Some("conv-123"));

        let a = ev.ai_agent.expect("ai_agent built");
        assert_eq!(a["name"], "claude-code");
        assert_eq!(a["type"], "anthropic");
        assert_eq!(a["type_id"], 11);
        assert_eq!(a["ai_model"], "claude-opus-4");
        assert_eq!(a["instance_uid"], "conv-123");
        assert!(a["uid"].as_str().unwrap().starts_with("agent:"));
    }

    #[test]
    fn explicit_uid_wins_over_derived() {
        let mut ev = EventRecord::new("otlp_span", serde_json::json!({}), "low");
        ev.agent_name = Some("worker".into());
        ev.build_ai_agent(Some("agent-abc-123"), None);
        assert_eq!(ev.ai_agent.unwrap()["uid"], "agent-abc-123");
    }

    #[test]
    fn no_identity_is_noop() {
        let mut ev = EventRecord::new("proxy_request", serde_json::json!({}), "low");
        ev.build_ai_agent(None, None);
        assert!(ev.ai_agent.is_none());
    }
}
