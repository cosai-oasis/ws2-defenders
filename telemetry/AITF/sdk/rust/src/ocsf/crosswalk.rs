//! AITF <-> OCSF agentic crosswalk.
//!
//! Implements OCSF's "reuse existing objects and profiles" direction (OCSF PR
//! #1641 — `ai_agent` + `ai_operation` profile; OCSF issue #1640 — the proposed
//! "ai" category, the `delegation` object, `delegation_lineage` graph, and the
//! `agent_activity` / `delegation_activity` control-plane classes).
//!
//! Provides the object builders plus the authoritative AITF event -> OCSF class
//! table and the control-plane activity crosswalks. Logic mirrors the Go and
//! Python SDKs exactly.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ocsf::mapper::AttrValue;
use crate::ocsf::schema::*;
use crate::semconv;

// --- attribute helpers -----------------------------------------------------

fn attr_str(attrs: &HashMap<String, AttrValue>, key: &str) -> Option<String> {
    attrs.get(key).map(|v| v.to_attr_string())
}

fn attr_str_nonempty(attrs: &HashMap<String, AttrValue>, key: &str) -> Option<String> {
    attr_str(attrs, key).filter(|s| !s.is_empty())
}

fn first_attr_str(attrs: &HashMap<String, AttrValue>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = attr_str_nonempty(attrs, k) {
            return Some(s);
        }
    }
    None
}

fn attr_str_list(attrs: &HashMap<String, AttrValue>, key: &str) -> Option<Vec<String>> {
    attrs.get(key).map(|v| v.to_str_list())
}

// --- ai_operation profile builders -----------------------------------------

/// Builds an OCSF `ai_agent` object (PR #1641) from span attributes. Returns
/// `None` when no agent identity is present.
pub fn build_ai_agent(attrs: &HashMap<String, AttrValue>) -> Option<OCSFAIAgent> {
    let uid = first_attr_str(
        attrs,
        &[
            semconv::agent::ID,
            semconv::identity::AGENT_ID,
            semconv::agent::WORKFLOW_ID,
        ],
    );
    let name = first_attr_str(attrs, &[semconv::agent::NAME, semconv::identity::AGENT_NAME]);

    if uid.is_none() && name.is_none() {
        return None;
    }

    let framework = attr_str(attrs, semconv::agent::FRAMEWORK).unwrap_or_default();
    let type_id = normalize_agent_type_id(&framework);

    let resolved_uid = uid.clone().or_else(|| name.clone()).unwrap_or_default();

    let type_label = if type_id != AGENT_TYPE_ID_UNKNOWN {
        Some(agent_type_label(type_id).to_string())
    } else {
        None
    };

    Some(OCSFAIAgent {
        uid: resolved_uid,
        instance_uid: attr_str_nonempty(attrs, semconv::agent::SESSION_ID),
        name,
        agent_type: type_label,
        type_id: Some(type_id),
        ai_model: first_attr_str(
            attrs,
            &[semconv::gen_ai::REQUEST_MODEL, semconv::gen_ai::RESPONSE_MODEL],
        ),
        version: attr_str_nonempty(attrs, semconv::agent::VERSION),
        charter: attr_str_nonempty(attrs, semconv::agent::DESCRIPTION),
    })
}

/// Builds an OCSF `delegation` object (issue #1640). Returns `None` when no
/// delegation context is present.
pub fn build_delegation(attrs: &HashMap<String, AttrValue>) -> Option<OCSFDelegation> {
    let delegatee_id = first_attr_str(
        attrs,
        &[
            semconv::identity::DELEGATION_DELEGATEE_ID,
            semconv::agent::DELEGATION_TARGET_AGENT_ID,
        ],
    );
    let delegator_id = attr_str_nonempty(attrs, semconv::identity::DELEGATION_DELEGATOR_ID);
    let delegatee = first_attr_str(
        attrs,
        &[
            semconv::identity::DELEGATION_DELEGATEE,
            semconv::agent::DELEGATION_TARGET_AGENT,
        ],
    );
    let delegator = attr_str_nonempty(attrs, semconv::identity::DELEGATION_DELEGATOR);
    let deleg_type = attr_str_nonempty(attrs, semconv::identity::DELEGATION_TYPE);
    let chain = attr_str_list(attrs, semconv::identity::DELEGATION_CHAIN).unwrap_or_default();

    if delegatee_id.is_none()
        && delegator_id.is_none()
        && delegatee.is_none()
        && delegator.is_none()
        && deleg_type.is_none()
        && chain.is_empty()
    {
        return None;
    }

    let uid = delegatee_id
        .clone()
        .or_else(|| delegatee.clone())
        .or_else(|| chain.last().cloned())
        .unwrap_or_else(|| "unknown".to_string());

    let ttl_seconds = attrs
        .get(semconv::identity::DELEGATION_TTL_SECONDS)
        .and_then(|v| v.as_i64());

    Some(OCSFDelegation {
        uid,
        parent_uid: delegator_id,
        issuer_uid: attr_str_nonempty(attrs, semconv::identity::PROVIDER),
        delegator,
        delegatee,
        delegation_type: deleg_type,
        scope: attr_str_list(attrs, semconv::identity::DELEGATION_SCOPE_DELEGATED),
        proof_type: attr_str_nonempty(attrs, semconv::identity::DELEGATION_PROOF_TYPE),
        ttl_seconds,
    })
}

/// Builds an OCSF `delegation_lineage` graph from a delegation chain. Returns
/// `None` when no chain is present.
pub fn build_delegation_lineage(attrs: &HashMap<String, AttrValue>) -> Option<OCSFDelegationLineage> {
    let chain = attr_str_list(attrs, semconv::identity::DELEGATION_CHAIN).unwrap_or_default();
    if chain.is_empty() {
        return None;
    }
    let mut nodes = Vec::with_capacity(chain.len());
    let mut parent: Option<String> = None;
    for (depth, node_uid) in chain.iter().enumerate() {
        nodes.push(OCSFDelegationNode {
            uid: node_uid.clone(),
            parent_uid: parent.clone(),
            agent_uid: Some(node_uid.clone()),
            depth: depth as i32,
        });
        parent = Some(node_uid.clone());
    }
    Some(OCSFDelegationLineage { nodes: Some(nodes) })
}

// --- agent-to-agent communication normalization ----------------------------

/// Normalizes an A2A `task.state` value to the canonical status set.
fn a2a_status(status: &str) -> Option<&'static str> {
    use semconv::agent_comm::*;
    Some(match status {
        "submitted" => STATUS_SUBMITTED,
        "working" => STATUS_WORKING,
        "input-required" => STATUS_INPUT_REQUIRED,
        "auth-required" => STATUS_INPUT_REQUIRED,
        "completed" => STATUS_COMPLETED,
        "failed" => STATUS_FAILED,
        "rejected" => STATUS_FAILED,
        "canceled" => STATUS_CANCELED,
        _ => return None,
    })
}

/// Normalizes an ACP `run.status` value to the canonical status set.
fn acp_status(status: &str) -> Option<&'static str> {
    use semconv::agent_comm::*;
    Some(match status {
        "created" => STATUS_SUBMITTED,
        "in-progress" => STATUS_WORKING,
        "awaiting" => STATUS_INPUT_REQUIRED,
        "completed" => STATUS_COMPLETED,
        "failed" => STATUS_FAILED,
        "cancelling" => STATUS_CANCELING,
        "cancelled" => STATUS_CANCELED,
        _ => return None,
    })
}

/// Normalizes a protocol-specific lifecycle state to the canonical status set.
/// Unknown values pass through unchanged; an empty status returns "".
pub fn canonical_comm_status(protocol_id: i32, status: &str) -> String {
    if status.is_empty() {
        return String::new();
    }
    let mapped = match protocol_id {
        AGENT_PROTOCOL_ID_A2A => a2a_status(status),
        AGENT_PROTOCOL_ID_ACP => acp_status(status),
        _ => None,
    };
    mapped.map(|s| s.to_string()).unwrap_or_else(|| status.to_string())
}

fn any_key_has_prefix(attrs: &HashMap<String, AttrValue>, prefix: &str) -> bool {
    attrs.keys().any(|k| k.starts_with(prefix))
}

fn detect_protocol(attrs: &HashMap<String, AttrValue>) -> i32 {
    if let Some(explicit) = attr_str_nonempty(attrs, semconv::agent_comm::PROTOCOL) {
        return normalize_agent_protocol_id(&explicit);
    }
    if any_key_has_prefix(attrs, "a2a.") {
        return AGENT_PROTOCOL_ID_A2A;
    }
    if any_key_has_prefix(attrs, "acp.") {
        return AGENT_PROTOCOL_ID_ACP;
    }
    if any_key_has_prefix(attrs, "anp.") {
        return AGENT_PROTOCOL_ID_ANP;
    }
    AGENT_PROTOCOL_ID_UNKNOWN
}

fn has_attr(attrs: &HashMap<String, AttrValue>, key: &str) -> bool {
    attrs.contains_key(key)
}

/// Builds a generic OCSF `agent_message` from A2A/ACP/ANP and canonical
/// `agent.comm.*` attributes. Returns `None` when the span carries no
/// agent-communication context.
pub fn build_agent_message(attrs: &HashMap<String, AttrValue>) -> Option<OCSFAgentMessage> {
    let protocol_id = detect_protocol(attrs);
    if protocol_id == AGENT_PROTOCOL_ID_UNKNOWN && !has_attr(attrs, semconv::agent_comm::UNIT_ID) {
        return None;
    }

    let mut msg = OCSFAgentMessage {
        protocol_id,
        protocol: attr_str_nonempty(attrs, semconv::agent_comm::PROTOCOL),
        ..Default::default()
    };

    match protocol_id {
        AGENT_PROTOCOL_ID_A2A => {
            msg.protocol_version = attr_str_nonempty(attrs, semconv::a2a::PROTOCOL_VERSION);
            msg.transport = attr_str_nonempty(attrs, semconv::a2a::TRANSPORT);
            msg.operation = attr_str_nonempty(attrs, semconv::a2a::METHOD);
            if has_attr(attrs, semconv::a2a::TASK_ID) {
                msg.unit_uid = attr_str_nonempty(attrs, semconv::a2a::TASK_ID);
                msg.unit_type = Some("task".to_string());
                msg.status = canon_opt(
                    protocol_id,
                    attr_str(attrs, semconv::a2a::TASK_STATE),
                );
                msg.previous_status = canon_opt(
                    protocol_id,
                    attr_str(attrs, semconv::a2a::TASK_PREVIOUS_STATE),
                );
            } else {
                msg.unit_uid = attr_str_nonempty(attrs, semconv::a2a::MESSAGE_ID);
                msg.unit_type = Some("message".to_string());
            }
            let mode = attr_str(attrs, semconv::a2a::INTERACTION_MODE)
                .unwrap_or_default()
                .to_lowercase();
            msg.direction = Some(match mode.as_str() {
                "stream" => "stream".to_string(),
                "push" => "notification".to_string(),
                _ => "request".to_string(),
            });
            msg.parts_count = attrs.get(semconv::a2a::MESSAGE_PARTS_COUNT).and_then(|v| v.as_i64());
            msg.part_types = attr_str_list(attrs, semconv::a2a::MESSAGE_PART_TYPES);
            msg.artifacts_count =
                attrs.get(semconv::a2a::TASK_ARTIFACTS_COUNT).and_then(|v| v.as_i64());
            msg.peer_endpoint = attr_str_nonempty(attrs, semconv::a2a::AGENT_URL);
            msg.error_code = attr_str_nonempty(attrs, semconv::a2a::JSONRPC_ERROR_CODE);
            msg.error_message = attr_str_nonempty(attrs, semconv::a2a::JSONRPC_ERROR_MESSAGE);
            if let Some(name) = attr_str_nonempty(attrs, semconv::a2a::AGENT_NAME) {
                msg.dst_agent = Some(OCSFAIAgent {
                    uid: name.clone(),
                    name: Some(name),
                    version: attr_str_nonempty(attrs, semconv::a2a::AGENT_VERSION),
                    ..Default::default()
                });
            }
        }
        AGENT_PROTOCOL_ID_ACP => {
            msg.operation =
                first_attr_str(attrs, &[semconv::acp::OPERATION, semconv::acp::RUN_MODE]);
            msg.unit_uid = attr_str_nonempty(attrs, semconv::acp::RUN_ID);
            msg.unit_type = Some("run".to_string());
            msg.status = canon_opt(protocol_id, attr_str(attrs, semconv::acp::RUN_STATUS));
            msg.previous_status =
                canon_opt(protocol_id, attr_str(attrs, semconv::acp::RUN_PREVIOUS_STATUS));
            let mode = attr_str(attrs, semconv::acp::RUN_MODE)
                .unwrap_or_default()
                .to_lowercase();
            msg.direction = Some(if mode == "stream" {
                "stream".to_string()
            } else {
                "request".to_string()
            });
            msg.transport = Some("http".to_string());
            msg.endpoint = attr_str_nonempty(attrs, semconv::acp::HTTP_URL);
            msg.parts_count = attrs.get(semconv::acp::MESSAGE_PARTS_COUNT).and_then(|v| v.as_i64());
            msg.part_types = attr_str_list(attrs, semconv::acp::MESSAGE_CONTENT_TYPES);
            msg.duration_ms = attrs.get(semconv::acp::RUN_DURATION_MS).and_then(|v| v.as_f64());
            msg.error_code = attr_str_nonempty(attrs, semconv::acp::RUN_ERROR_CODE);
            msg.error_message = attr_str_nonempty(attrs, semconv::acp::RUN_ERROR_MESSAGE);
            if let Some(name) = attr_str_nonempty(attrs, semconv::acp::AGENT_NAME) {
                msg.dst_agent = Some(OCSFAIAgent {
                    uid: name.clone(),
                    name: Some(name),
                    ..Default::default()
                });
            }
        }
        AGENT_PROTOCOL_ID_ANP => {
            msg.protocol_version = attr_str_nonempty(attrs, semconv::anp::PROTOCOL_VERSION);
            msg.transport = attr_str_nonempty(attrs, semconv::anp::TRANSPORT);
            msg.operation =
                first_attr_str(attrs, &[semconv::anp::META_PROTOCOL_NAME, semconv::anp::MESSAGE_TYPE]);
            msg.unit_uid = attr_str_nonempty(attrs, semconv::anp::MESSAGE_ID);
            msg.unit_type = Some("message".to_string());
            msg.parts_count = attrs.get(semconv::anp::MESSAGE_PARTS_COUNT).and_then(|v| v.as_i64());
            msg.peer_did = attr_str_nonempty(attrs, semconv::anp::PEER_DID);
            msg.trust_domain = attr_str_nonempty(attrs, semconv::anp::TRUST_DOMAIN);
            msg.peer_trust_domain = attr_str_nonempty(attrs, semconv::anp::PEER_TRUST_DOMAIN);
            msg.cross_domain = attrs.get(semconv::anp::CROSS_DOMAIN).and_then(|v| v.as_bool());
            msg.error_code = attr_str_nonempty(attrs, semconv::anp::ERROR_CODE);
            msg.error_message = attr_str_nonempty(attrs, semconv::anp::ERROR_MESSAGE);
        }
        _ => {}
    }

    apply_canonical(&mut msg, attrs);

    if msg.src_agent.is_none() {
        msg.src_agent = build_ai_agent(attrs);
    }
    msg.delegation = build_delegation(attrs);
    Some(msg)
}

/// Helper: canonicalize an optional protocol status string into an Option,
/// dropping empties.
fn canon_opt(protocol_id: i32, status: Option<String>) -> Option<String> {
    let s = status.unwrap_or_default();
    let c = canonical_comm_status(protocol_id, &s);
    if c.is_empty() {
        None
    } else {
        Some(c)
    }
}

/// Overlays explicit canonical `agent.comm.*` attributes onto `msg`.
fn apply_canonical(msg: &mut OCSFAgentMessage, attrs: &HashMap<String, AttrValue>) {
    use semconv::agent_comm as ac;

    macro_rules! ov {
        ($field:expr, $key:expr) => {
            if let Some(v) = attr_str(attrs, $key) {
                $field = Some(v);
            }
        };
    }
    ov!(msg.protocol_version, ac::PROTOCOL_VERSION);
    ov!(msg.direction, ac::DIRECTION);
    ov!(msg.role, ac::ROLE);
    ov!(msg.operation, ac::OPERATION);
    ov!(msg.unit_uid, ac::UNIT_ID);
    ov!(msg.unit_type, ac::UNIT_TYPE);
    ov!(msg.status, ac::STATUS);
    ov!(msg.previous_status, ac::PREVIOUS_STATUS);
    ov!(msg.transport, ac::TRANSPORT);
    ov!(msg.endpoint, ac::ENDPOINT);
    ov!(msg.peer_endpoint, ac::PEER_ENDPOINT);
    ov!(msg.trust_domain, ac::TRUST_DOMAIN);
    ov!(msg.peer_trust_domain, ac::PEER_TRUST_DOMAIN);
    ov!(msg.peer_did, ac::PEER_DID);
    ov!(msg.error_code, ac::ERROR_CODE);
    ov!(msg.error_message, ac::ERROR_MESSAGE);

    if let Some(p) = attrs.get(ac::PARTS_COUNT).and_then(|v| v.as_i64()) {
        msg.parts_count = Some(p);
    }
    if let Some(p) = attrs.get(ac::ARTIFACTS_COUNT).and_then(|v| v.as_i64()) {
        msg.artifacts_count = Some(p);
    }
    if has_attr(attrs, ac::PART_TYPES) {
        msg.part_types = attr_str_list(attrs, ac::PART_TYPES);
    }
    if let Some(p) = attrs.get(ac::CROSS_DOMAIN).and_then(|v| v.as_bool()) {
        msg.cross_domain = Some(p);
    }
    if let Some(p) = attrs.get(ac::DURATION_MS).and_then(|v| v.as_f64()) {
        msg.duration_ms = Some(p);
    }

    let peer_id = attr_str_nonempty(attrs, ac::PEER_AGENT_ID);
    let peer_name = attr_str_nonempty(attrs, ac::PEER_AGENT_NAME);
    if peer_id.is_some() || peer_name.is_some() {
        let uid = peer_id.clone().or_else(|| peer_name.clone()).unwrap_or_default();
        msg.dst_agent = Some(OCSFAIAgent {
            uid,
            name: peer_name,
            ..Default::default()
        });
    }
}

// --- control-plane crosswalk tables (OCSF issue #1640) ---------------------

/// Maps an AITF agent `activity_id` to the OCSF `agent_activity` activity name.
pub fn ocsf_agent_activity_crosswalk(activity_id: i32) -> Option<&'static str> {
    Some(match activity_id {
        1 => "Spawn",
        2 => "Terminate",
        3 => "Update",
        4 => "Register",
        5 => "Resume",
        6 => "Resume",
        7 => "Suspend",
        99 => "Unknown",
        _ => return None,
    })
}

/// Maps an AITF delegation activity to the OCSF `delegation_activity` name.
pub fn ocsf_delegation_activity_crosswalk(activity: &str) -> Option<&'static str> {
    Some(match activity {
        "create" => "Create",
        "grant" => "Create",
        "revoke" => "Revoke",
        "expire" => "Expire",
        "complete" => "Complete",
        _ => return None,
    })
}

/// Describes the OCSF class an AITF event reuses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OCSFClassCrosswalkEntry {
    pub ocsf_category_uid: i32,
    pub ocsf_class_uid: i32,
    pub ocsf_class: &'static str,
}

/// Returns the authoritative AITF event -> OCSF class mapping for an event name.
pub fn ocsf_class_crosswalk(event_name: &str) -> Option<OCSFClassCrosswalkEntry> {
    let e = |cat, cls, name| {
        Some(OCSFClassCrosswalkEntry {
            ocsf_category_uid: cat,
            ocsf_class_uid: cls,
            ocsf_class: name,
        })
    };
    match event_name {
        "model_inference" => e(CATEGORY_UID_APPLICATION, CLASS_UID_API_ACTIVITY, "api_activity"),
        "tool_execution" => e(CATEGORY_UID_APPLICATION, CLASS_UID_API_ACTIVITY, "api_activity"),
        "data_retrieval" => e(
            CATEGORY_UID_APPLICATION,
            CLASS_UID_DATASTORE_ACTIVITY,
            "datastore_activity",
        ),
        "model_ops" => e(
            CATEGORY_UID_APPLICATION,
            CLASS_UID_APPLICATION_LIFECYCLE,
            "application_lifecycle",
        ),
        "security_finding" => e(
            CATEGORY_UID_FINDINGS,
            CLASS_UID_DETECTION_FINDING,
            "detection_finding",
        ),
        "supply_chain" => e(
            CATEGORY_UID_FINDINGS,
            CLASS_UID_VULNERABILITY_FINDING,
            "vulnerability_finding",
        ),
        "governance" => e(
            CATEGORY_UID_FINDINGS,
            CLASS_UID_COMPLIANCE_FINDING,
            "compliance_finding",
        ),
        "identity" => e(CATEGORY_UID_IAM, CLASS_UID_AUTHENTICATION, "authentication"),
        "asset_inventory" => e(CATEGORY_UID_DISCOVERY, CLASS_UID_INVENTORY_INFO, "inventory_info"),
        "agent_activity" => e(CATEGORY_UID_AI, CLASS_UID_AGENT_ACTIVITY, "agent_activity"),
        "delegation_activity" => e(
            CATEGORY_UID_AI,
            CLASS_UID_DELEGATION_ACTIVITY,
            "delegation_activity",
        ),
        "agent_communication" => e(
            CATEGORY_UID_AI,
            CLASS_UID_AGENT_COMMUNICATION,
            "agent_communication",
        ),
        _ => None,
    }
}
