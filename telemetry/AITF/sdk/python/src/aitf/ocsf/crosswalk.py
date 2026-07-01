"""AITF <-> OCSF agentic alignment helpers.

Implements OCSF's "reuse existing objects and profiles" direction:

  * OCSF PR #1641  -- ``objects/ai_agent.json`` + the ``ai_operation`` profile
  * OCSF issue #1640 -- the proposed ``ai`` category (uid 9), the
    ``delegation`` object, ``delegation_lineage``/``delegation_node`` graph,
    and the ``agent_activity`` / ``delegation_activity`` control-plane classes.

AITF emits AI telemetry under existing OCSF classes (API Activity, Datastore
Activity, Findings, IAM, Discovery, ...) enriched with the ``ai_operation``
profile (``ai_agent`` + ``ai_model``) and the ``delegation`` object; only
agent/delegation lifecycle use the proposed ``ai`` category. This module
provides the object builders and publishes ``OCSF_CLASS_CROSSWALK`` (the
authoritative AITF event -> OCSF class table) plus the control-plane activity
crosswalks.
"""

from __future__ import annotations

from typing import Any

from aitf.ocsf.schema import (
    AGENT_TYPE_LABELS,
    OCSF_AI_CATEGORY_UID,
    AgentProtocolID,
    AgentTypeID,
    OCSFAgentMessage,
    OCSFAIAgent,
    OCSFDelegation,
    OCSFDelegationLineage,
    OCSFDelegationNode,
    normalize_agent_protocol_id,
    normalize_agent_type_id,
)
from aitf.semantic_conventions.attributes import (
    A2AAttributes,
    ACPAttributes,
    ANPAttributes,
    AgentAttributes,
    AgentCommAttributes,
    GenAIAttributes,
    IdentityAttributes,
)

__all__ = [
    "build_ai_agent",
    "build_delegation",
    "build_delegation_lineage",
    "build_agent_message",
    "canonical_comm_status",
    "OCSF_AGENT_ACTIVITY_CROSSWALK",
    "OCSF_DELEGATION_ACTIVITY_CROSSWALK",
    "OCSF_CLASS_CROSSWALK",
]


def _opt_str(val: Any) -> str | None:
    return str(val) if val is not None else None


def _opt_int(val: Any) -> int | None:
    return int(val) if val is not None else None


def _opt_float(val: Any) -> float | None:
    return float(val) if val is not None else None


def _opt_bool(val: Any) -> bool | None:
    return bool(val) if val is not None else None


def _as_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val]
    return [str(val)]


def build_ai_agent(attrs: dict[str, Any]) -> OCSFAIAgent | None:
    """Build an OCSF ``ai_agent`` object (PR #1641) from span attributes.

    Returns ``None`` when no agent identity is present, so non-agentic events
    are left untouched.
    """
    uid = (
        attrs.get(GenAIAttributes.AGENT_ID)
        or attrs.get(IdentityAttributes.AGENT_ID)
        or attrs.get(AgentAttributes.WORKFLOW_ID)
    )
    name = attrs.get(GenAIAttributes.AGENT_NAME) or attrs.get(IdentityAttributes.AGENT_NAME)
    if uid is None and name is None:
        return None

    framework = _opt_str(attrs.get(AgentAttributes.FRAMEWORK))
    type_id = normalize_agent_type_id(framework)

    return OCSFAIAgent(
        uid=str(uid if uid is not None else name),
        instance_uid=_opt_str(attrs.get(GenAIAttributes.CONVERSATION_ID)),
        name=_opt_str(name),
        type=AGENT_TYPE_LABELS.get(type_id, AGENT_TYPE_LABELS[AgentTypeID.OTHER])
        if type_id != AgentTypeID.UNKNOWN
        else None,
        type_id=type_id,
        ai_model=_opt_str(
            attrs.get(GenAIAttributes.REQUEST_MODEL)
            or attrs.get(GenAIAttributes.RESPONSE_MODEL)
        ),
        version=_opt_str(attrs.get(GenAIAttributes.AGENT_VERSION)),
        charter=_opt_str(attrs.get(GenAIAttributes.AGENT_DESCRIPTION)),
    )


def build_delegation(attrs: dict[str, Any]) -> OCSFDelegation | None:
    """Build an OCSF ``delegation`` object (issue #1640) from span attributes.

    Returns ``None`` when no delegation context is present.
    """
    delegatee_id = attrs.get(IdentityAttributes.DELEGATION_DELEGATEE_ID) or attrs.get(
        AgentAttributes.DELEGATION_TARGET_AGENT_ID
    )
    delegator_id = attrs.get(IdentityAttributes.DELEGATION_DELEGATOR_ID)
    delegatee = attrs.get(IdentityAttributes.DELEGATION_DELEGATEE) or attrs.get(
        AgentAttributes.DELEGATION_TARGET_AGENT
    )
    delegator = attrs.get(IdentityAttributes.DELEGATION_DELEGATOR)
    deleg_type = attrs.get(IdentityAttributes.DELEGATION_TYPE)
    chain = attrs.get(IdentityAttributes.DELEGATION_CHAIN)

    if not any([delegatee_id, delegator_id, delegatee, delegator, deleg_type, chain]):
        return None

    # OCSF delegation.uid is the stable identifier of the granted authority.
    uid = delegatee_id or delegatee or (chain[-1] if isinstance(chain, (list, tuple)) and chain else None)

    return OCSFDelegation(
        uid=str(uid) if uid is not None else "unknown",
        parent_uid=_opt_str(delegator_id),
        issuer_uid=_opt_str(attrs.get(IdentityAttributes.PROVIDER)),
        delegator=_opt_str(delegator),
        delegatee=_opt_str(delegatee),
        type=_opt_str(deleg_type),
        scope=_as_list(attrs.get(IdentityAttributes.DELEGATION_SCOPE_DELEGATED)),
        proof_type=_opt_str(attrs.get(IdentityAttributes.DELEGATION_PROOF_TYPE)),
        ttl_seconds=(
            int(attrs[IdentityAttributes.DELEGATION_TTL_SECONDS])
            if attrs.get(IdentityAttributes.DELEGATION_TTL_SECONDS) is not None
            else None
        ),
    )


def build_delegation_lineage(attrs: dict[str, Any]) -> OCSFDelegationLineage | None:
    """Build an OCSF ``delegation_lineage`` graph from a delegation chain.

    The AITF ``identity.delegation.chain`` (ordered from origin to current)
    is materialized into the directed ``delegation_node`` graph proposed in
    OCSF issue #1640.
    """
    chain = attrs.get(IdentityAttributes.DELEGATION_CHAIN)
    if not isinstance(chain, (list, tuple)) or not chain:
        return None

    nodes: list[OCSFDelegationNode] = []
    parent: str | None = None
    for depth, node_uid in enumerate(chain):
        nodes.append(
            OCSFDelegationNode(
                uid=str(node_uid),
                parent_uid=parent,
                agent_uid=str(node_uid),
                depth=depth,
            )
        )
        parent = str(node_uid)
    return OCSFDelegationLineage(nodes=nodes)


# --- Control-plane crosswalk tables (OCSF issue #1640) ---------------------
#
# OCSF issue #1640 proposes a native ``ai`` category (uid 9) with dedicated
# control-plane classes. These tables map AITF activities onto the proposed
# OCSF activities. UIDs for the proposed classes are not yet finalized
# upstream, so only the activity-name mapping (which is stable) is published.

# AITF agent activity_id -> OCSF agent_activity activity.
OCSF_AGENT_ACTIVITY_CROSSWALK: dict[int, str] = {
    1: "Spawn",       # AITF Session Start  -> agent spawned
    2: "Terminate",   # AITF Session End    -> agent terminated
    3: "Update",      # AITF Step Execute   -> agent state update
    4: "Register",    # AITF Delegation     -> registers delegated authority
    5: "Resume",      # AITF Memory Access  -> resume/continue
    6: "Resume",      # AITF Error Recovery -> resume after recovery
    7: "Suspend",     # AITF Human Approval -> suspended pending human input
    99: "Unknown",
}

# AITF identity delegation activity -> OCSF delegation_activity.
OCSF_DELEGATION_ACTIVITY_CROSSWALK: dict[str, str] = {
    "create": "Create",
    "grant": "Create",
    "revoke": "Revoke",
    "expire": "Expire",
    "complete": "Complete",
}

# Authoritative AITF -> OCSF class mapping (the classes AITF actually emits).
# Per OCSF's "reuse existing objects and profiles" model: data-plane AI
# activity reuses existing OCSF classes carrying the ``ai_operation`` profile;
# only agent / delegation lifecycle use the proposed ``ai`` category (uid 9).
OCSF_CLASS_CROSSWALK: dict[str, dict[str, Any]] = {
    "model_inference": {"ocsf_category_uid": 6, "ocsf_class_uid": 6003, "ocsf_class": "api_activity"},
    "tool_execution": {"ocsf_category_uid": 6, "ocsf_class_uid": 6003, "ocsf_class": "api_activity"},
    "data_retrieval": {"ocsf_category_uid": 6, "ocsf_class_uid": 6005, "ocsf_class": "datastore_activity"},
    "model_ops": {"ocsf_category_uid": 6, "ocsf_class_uid": 6002, "ocsf_class": "application_lifecycle"},
    "security_finding": {"ocsf_category_uid": 2, "ocsf_class_uid": 2004, "ocsf_class": "detection_finding"},
    "supply_chain": {"ocsf_category_uid": 2, "ocsf_class_uid": 2002, "ocsf_class": "vulnerability_finding"},
    "governance": {"ocsf_category_uid": 2, "ocsf_class_uid": 2003, "ocsf_class": "compliance_finding"},
    "identity": {"ocsf_category_uid": 3, "ocsf_class_uid": 3002, "ocsf_class": "authentication"},
    "asset_inventory": {"ocsf_category_uid": 5, "ocsf_class_uid": 5001, "ocsf_class": "inventory_info"},
    # New control-plane classes in the proposed ``ai`` category (provisional UIDs).
    "agent_activity": {"ocsf_category_uid": OCSF_AI_CATEGORY_UID, "ocsf_class_uid": 9001, "ocsf_class": "agent_activity"},
    "delegation_activity": {"ocsf_category_uid": OCSF_AI_CATEGORY_UID, "ocsf_class_uid": 9002, "ocsf_class": "delegation_activity"},
    "agent_communication": {"ocsf_category_uid": OCSF_AI_CATEGORY_UID, "ocsf_class_uid": 9003, "ocsf_class": "agent_communication"},
}


# --- Agent-to-agent communication normalization (A2A / ACP / ANP) ----------
#
# One generic OCSF ``agent_message`` object with a ``protocol_id`` discriminator
# rather than a per-protocol object. Per-protocol lifecycle states are
# normalized to a single canonical status set.

_CANONICAL = AgentCommAttributes.Status

# A2A task.state -> canonical
_A2A_STATUS: dict[str, str] = {
    "submitted": _CANONICAL.SUBMITTED,
    "working": _CANONICAL.WORKING,
    "input-required": _CANONICAL.INPUT_REQUIRED,
    "auth-required": _CANONICAL.INPUT_REQUIRED,
    "completed": _CANONICAL.COMPLETED,
    "failed": _CANONICAL.FAILED,
    "rejected": _CANONICAL.FAILED,
    "canceled": _CANONICAL.CANCELED,
}

# ACP run.status -> canonical
_ACP_STATUS: dict[str, str] = {
    "created": _CANONICAL.SUBMITTED,
    "in-progress": _CANONICAL.WORKING,
    "awaiting": _CANONICAL.INPUT_REQUIRED,
    "completed": _CANONICAL.COMPLETED,
    "failed": _CANONICAL.FAILED,
    "cancelling": _CANONICAL.CANCELING,
    "cancelled": _CANONICAL.CANCELED,
}

_STATUS_TABLES: dict[int, dict[str, str]] = {
    AgentProtocolID.A2A: _A2A_STATUS,
    AgentProtocolID.ACP: _ACP_STATUS,
}


def canonical_comm_status(protocol_id: int, status: Any) -> str | None:
    """Normalize a protocol-specific lifecycle state to the canonical set."""
    if status is None:
        return None
    table = _STATUS_TABLES.get(protocol_id, {})
    raw = str(status)
    return table.get(raw, raw)


def _detect_protocol(attrs: dict[str, Any]) -> int:
    """Detect the agent-comm protocol from attribute namespaces."""
    explicit = attrs.get(AgentCommAttributes.PROTOCOL)
    if explicit:
        return normalize_agent_protocol_id(str(explicit))
    if any(k.startswith("a2a.") for k in attrs):
        return AgentProtocolID.A2A
    if any(k.startswith("acp.") for k in attrs):
        return AgentProtocolID.ACP
    if any(k.startswith("anp.") for k in attrs):
        return AgentProtocolID.ANP
    return AgentProtocolID.UNKNOWN


def _first(attrs: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if attrs.get(k) is not None:
            return attrs[k]
    return None


def build_agent_message(attrs: dict[str, Any]) -> OCSFAgentMessage | None:
    """Build a generic OCSF ``agent_message`` from A2A/ACP/ANP/canonical attrs.

    Returns ``None`` when the span carries no agent-communication context.
    """
    protocol_id = _detect_protocol(attrs)
    if protocol_id == AgentProtocolID.UNKNOWN and AgentCommAttributes.UNIT_ID not in attrs:
        return None

    msg = OCSFAgentMessage(
        protocol_id=protocol_id,
        protocol=_opt_str(attrs.get(AgentCommAttributes.PROTOCOL)),
    )

    if protocol_id == AgentProtocolID.A2A:
        msg.protocol_version = _opt_str(attrs.get(A2AAttributes.PROTOCOL_VERSION))
        msg.transport = _opt_str(attrs.get(A2AAttributes.TRANSPORT))
        msg.operation = _opt_str(attrs.get(A2AAttributes.METHOD))
        if attrs.get(A2AAttributes.TASK_ID) is not None:
            msg.unit_uid = _opt_str(attrs[A2AAttributes.TASK_ID])
            msg.unit_type = "task"
            msg.status = canonical_comm_status(protocol_id, attrs.get(A2AAttributes.TASK_STATE))
            msg.previous_status = canonical_comm_status(protocol_id, attrs.get(A2AAttributes.TASK_PREVIOUS_STATE))
        else:
            msg.unit_uid = _opt_str(attrs.get(A2AAttributes.MESSAGE_ID))
            msg.unit_type = "message"
        mode = str(attrs.get(A2AAttributes.INTERACTION_MODE, "")).lower()
        msg.direction = "stream" if mode == "stream" else ("notification" if mode == "push" else "request")
        msg.parts_count = _opt_int(attrs.get(A2AAttributes.MESSAGE_PARTS_COUNT))
        msg.part_types = _as_list(attrs.get(A2AAttributes.MESSAGE_PART_TYPES))
        msg.artifacts_count = _opt_int(attrs.get(A2AAttributes.TASK_ARTIFACTS_COUNT))
        msg.peer_endpoint = _opt_str(attrs.get(A2AAttributes.AGENT_URL))
        msg.error_code = _opt_str(attrs.get(A2AAttributes.JSONRPC_ERROR_CODE))
        msg.error_message = _opt_str(attrs.get(A2AAttributes.JSONRPC_ERROR_MESSAGE))
        if attrs.get(A2AAttributes.AGENT_NAME):
            msg.dst_agent = OCSFAIAgent(uid=str(attrs[A2AAttributes.AGENT_NAME]),
                                       name=str(attrs[A2AAttributes.AGENT_NAME]),
                                       version=_opt_str(attrs.get(A2AAttributes.AGENT_VERSION)))

    elif protocol_id == AgentProtocolID.ACP:
        msg.operation = _opt_str(_first(attrs, ACPAttributes.OPERATION, ACPAttributes.RUN_MODE))
        msg.unit_uid = _opt_str(attrs.get(ACPAttributes.RUN_ID))
        msg.unit_type = "run"
        msg.status = canonical_comm_status(protocol_id, attrs.get(ACPAttributes.RUN_STATUS))
        msg.previous_status = canonical_comm_status(protocol_id, attrs.get(ACPAttributes.RUN_PREVIOUS_STATUS))
        mode = str(attrs.get(ACPAttributes.RUN_MODE, "")).lower()
        msg.direction = "stream" if mode == "stream" else "request"
        msg.transport = "http"
        msg.endpoint = _opt_str(attrs.get(ACPAttributes.HTTP_URL))
        msg.parts_count = _opt_int(attrs.get(ACPAttributes.MESSAGE_PARTS_COUNT))
        msg.part_types = _as_list(attrs.get(ACPAttributes.MESSAGE_CONTENT_TYPES))
        msg.duration_ms = _opt_float(attrs.get(ACPAttributes.RUN_DURATION_MS))
        msg.error_code = _opt_str(attrs.get(ACPAttributes.RUN_ERROR_CODE))
        msg.error_message = _opt_str(attrs.get(ACPAttributes.RUN_ERROR_MESSAGE))
        if attrs.get(ACPAttributes.AGENT_NAME):
            msg.dst_agent = OCSFAIAgent(uid=str(attrs[ACPAttributes.AGENT_NAME]),
                                       name=str(attrs[ACPAttributes.AGENT_NAME]))

    elif protocol_id == AgentProtocolID.ANP:
        msg.protocol_version = _opt_str(attrs.get(ANPAttributes.PROTOCOL_VERSION))
        msg.transport = _opt_str(attrs.get(ANPAttributes.TRANSPORT))
        msg.operation = _opt_str(_first(attrs, ANPAttributes.META_PROTOCOL_NAME, ANPAttributes.MESSAGE_TYPE))
        msg.unit_uid = _opt_str(attrs.get(ANPAttributes.MESSAGE_ID))
        msg.unit_type = "message"
        msg.parts_count = _opt_int(attrs.get(ANPAttributes.MESSAGE_PARTS_COUNT))
        msg.peer_did = _opt_str(attrs.get(ANPAttributes.PEER_DID))
        msg.trust_domain = _opt_str(attrs.get(ANPAttributes.TRUST_DOMAIN))
        msg.peer_trust_domain = _opt_str(attrs.get(ANPAttributes.PEER_TRUST_DOMAIN))
        msg.cross_domain = _opt_bool(attrs.get(ANPAttributes.CROSS_DOMAIN))
        msg.error_code = _opt_str(attrs.get(ANPAttributes.ERROR_CODE))
        msg.error_message = _opt_str(attrs.get(ANPAttributes.ERROR_MESSAGE))

    # Canonical agent.comm.* attributes override / fill in any protocol.
    _apply_canonical(msg, attrs)

    # Source agent from gen_ai.agent.* / canonical, if present.
    if msg.src_agent is None:
        msg.src_agent = build_ai_agent(attrs)

    # Delegation context (issue #1640) rides on the comms event when present.
    msg.delegation = build_delegation(attrs)
    return msg


def _apply_canonical(msg: OCSFAgentMessage, attrs: dict[str, Any]) -> None:
    """Overlay explicit canonical agent.comm.* attributes onto the message."""
    A = AgentCommAttributes
    overrides = {
        "protocol_version": A.PROTOCOL_VERSION,
        "direction": A.DIRECTION,
        "role": A.ROLE,
        "operation": A.OPERATION,
        "unit_uid": A.UNIT_ID,
        "unit_type": A.UNIT_TYPE,
        "status": A.STATUS,
        "previous_status": A.PREVIOUS_STATUS,
        "transport": A.TRANSPORT,
        "endpoint": A.ENDPOINT,
        "peer_endpoint": A.PEER_ENDPOINT,
        "trust_domain": A.TRUST_DOMAIN,
        "peer_trust_domain": A.PEER_TRUST_DOMAIN,
        "peer_did": A.PEER_DID,
        "error_code": A.ERROR_CODE,
        "error_message": A.ERROR_MESSAGE,
    }
    for field, key in overrides.items():
        if attrs.get(key) is not None:
            setattr(msg, field, _opt_str(attrs[key]))
    if attrs.get(A.PARTS_COUNT) is not None:
        msg.parts_count = _opt_int(attrs[A.PARTS_COUNT])
    if attrs.get(A.ARTIFACTS_COUNT) is not None:
        msg.artifacts_count = _opt_int(attrs[A.ARTIFACTS_COUNT])
    if attrs.get(A.PART_TYPES) is not None:
        msg.part_types = _as_list(attrs[A.PART_TYPES])
    if attrs.get(A.CROSS_DOMAIN) is not None:
        msg.cross_domain = _opt_bool(attrs[A.CROSS_DOMAIN])
    if attrs.get(A.DURATION_MS) is not None:
        msg.duration_ms = _opt_float(attrs[A.DURATION_MS])
    if attrs.get(A.PEER_AGENT_ID) or attrs.get(A.PEER_AGENT_NAME):
        msg.dst_agent = OCSFAIAgent(
            uid=str(attrs.get(A.PEER_AGENT_ID) or attrs.get(A.PEER_AGENT_NAME)),
            name=_opt_str(attrs.get(A.PEER_AGENT_NAME)),
        )
