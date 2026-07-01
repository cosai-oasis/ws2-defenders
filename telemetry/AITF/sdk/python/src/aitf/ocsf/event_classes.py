"""AITF OCSF AI Event Classes (class-reuse model).

Defines the ten AI event types, each mapped onto its reused OCSF class
(OCSF PR #1641 / issue #1640) rather than a bespoke Category 7.
Based on event classes from the AITelemetry project, extended
for AITF with MCP, Skills, ModelOps, Asset Inventory, and enhanced agent support.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from aitf.ocsf.schema import (
    AIBaseEvent,
    AICostInfo,
    AILatencyMetrics,
    AIModelInfo,
    AISecurityFinding,
    AITeamInfo,
    AITokenUsage,
    OCSFAgentMessage,
    OCSFCategoryUID,
    OCSFClassUID,
)


class AIModelInferenceEvent(AIBaseEvent):
    """AI model inference — reuses OCSF API Activity (6003).

    The model call is an API operation; AI specifics ride on the
    ``ai_operation`` profile (``ai_agent``, ``ai_model``).
    """
    category_uid: int = OCSFCategoryUID.APPLICATION
    class_uid: int = OCSFClassUID.API_ACTIVITY
    model: AIModelInfo
    token_usage: AITokenUsage = Field(default_factory=AITokenUsage)
    latency: AILatencyMetrics | None = None
    request_content: str | None = None
    response_content: str | None = None
    streaming: bool = False
    tools_provided: int = 0
    finish_reason: str = "stop"
    cost: AICostInfo | None = None
    error: dict[str, Any] | None = None


class AIAgentActivityEvent(AIBaseEvent):
    """Agent lifecycle — new OCSF ``agent_activity`` in the ai category (9).

    Genuinely new control-plane class proposed in OCSF issue #1640.
    UID is provisional pending ratification.
    """
    category_uid: int = OCSFCategoryUID.AI
    class_uid: int = OCSFClassUID.AGENT_ACTIVITY
    agent_name: str
    agent_id: str
    agent_type: str = "autonomous"
    framework: str | None = None
    session_id: str
    step_type: str | None = None
    step_index: int | None = None
    thought: str | None = None
    action: str | None = None
    observation: str | None = None
    delegation_target: str | None = None
    team_info: AITeamInfo | None = None


class AIAgentCommunicationEvent(AIBaseEvent):
    """Agent-to-agent communication (A2A / ACP / ANP / MCP).

    A single generic event for inter-agent messaging across protocols, in the
    proposed OCSF ``ai`` category. The wire protocol is a discriminator on the
    ``agent_message`` object rather than a dedicated class per protocol.
    """
    category_uid: int = OCSFCategoryUID.AI
    class_uid: int = OCSFClassUID.AGENT_COMMUNICATION
    agent_message: OCSFAgentMessage


class AIToolExecutionEvent(AIBaseEvent):
    """Tool/MCP/function execution — reuses OCSF API Activity (6003)."""
    category_uid: int = OCSFCategoryUID.APPLICATION
    class_uid: int = OCSFClassUID.API_ACTIVITY
    tool_name: str
    tool_type: str  # "function", "mcp_tool", "skill", "api"
    tool_input: str | None = None
    tool_output: str | None = None
    is_error: bool = False
    duration_ms: float | None = None
    mcp_server: str | None = None
    mcp_transport: str | None = None
    skill_category: str | None = None
    skill_version: str | None = None
    approval_required: bool = False
    approved: bool | None = None


class AIDataRetrievalEvent(AIBaseEvent):
    """RAG / vector search — reuses OCSF Datastore Activity (6005)."""
    category_uid: int = OCSFCategoryUID.APPLICATION
    class_uid: int = OCSFClassUID.DATASTORE_ACTIVITY
    database_name: str
    database_type: str
    query: str | None = None
    top_k: int | None = None
    results_count: int = 0
    min_score: float | None = None
    max_score: float | None = None
    filter: str | None = None
    embedding_model: str | None = None
    embedding_dimensions: int | None = None
    pipeline_name: str | None = None
    pipeline_stage: str | None = None
    quality_scores: dict[str, float] | None = None


class AISecurityFindingEvent(AIBaseEvent):
    """AI security finding — reuses OCSF Detection Finding (2004)."""
    category_uid: int = OCSFCategoryUID.FINDINGS
    class_uid: int = OCSFClassUID.DETECTION_FINDING
    finding: AISecurityFinding


class AISupplyChainEvent(AIBaseEvent):
    """AI supply chain — reuses OCSF Vulnerability Finding (2002)."""
    category_uid: int = OCSFCategoryUID.FINDINGS
    class_uid: int = OCSFClassUID.VULNERABILITY_FINDING
    model_source: str
    model_hash: str | None = None
    model_license: str | None = None
    model_signed: bool = False
    model_signer: str | None = None
    verification_result: str | None = None  # "pass", "fail", "unknown"
    ai_bom_id: str | None = None
    ai_bom_components: str | None = None  # JSON
    ai_bom_format: str | None = None  # "aitf", "cyclonedx", "spdx"
    ai_bom_component_count: int | None = None
    ai_bom_vulnerability_count: int | None = None


class AIGovernanceEvent(AIBaseEvent):
    """AI governance/compliance — reuses OCSF Compliance Finding (2003)."""
    category_uid: int = OCSFCategoryUID.FINDINGS
    class_uid: int = OCSFClassUID.COMPLIANCE_FINDING
    frameworks: list[str] = Field(default_factory=list)
    controls: str | None = None  # JSON
    event_type: str = ""
    violation_detected: bool = False
    violation_severity: str | None = None
    remediation: str | None = None
    audit_id: str | None = None


class AIIdentityEvent(AIBaseEvent):
    """Agent identity/auth — reuses OCSF Authentication (3002, IAM).

    Delegation *lifecycle* maps to the new ``delegation_activity`` in the ai
    category; the delegation context itself rides on the ``ai_operation``
    profile (``delegation`` object) regardless of class.
    """
    category_uid: int = OCSFCategoryUID.IAM
    class_uid: int = OCSFClassUID.AUTHENTICATION
    agent_name: str
    agent_id: str
    auth_method: str  # "api_key", "oauth", "mtls", "jwt"
    auth_result: str  # "success", "failure", "denied"
    permissions: list[str] = Field(default_factory=list)
    credential_type: str | None = None
    delegation_chain: list[str] = Field(default_factory=list)
    scope: str | None = None


class AIModelOpsEvent(AIBaseEvent):
    """Model lifecycle ops — reuses OCSF Application Lifecycle (6002)."""
    category_uid: int = OCSFCategoryUID.APPLICATION
    class_uid: int = OCSFClassUID.APPLICATION_LIFECYCLE
    operation_type: str  # "training", "evaluation", "deployment", "serving", "monitoring", "prompt"
    model_id: str | None = None
    run_id: str | None = None
    framework: str | None = None
    status: str | None = None
    # Training-specific
    training_type: str | None = None
    base_model: str | None = None
    dataset_id: str | None = None
    epochs: int | None = None
    loss_final: float | None = None
    output_model_id: str | None = None
    # Evaluation-specific
    evaluation_type: str | None = None
    metrics: str | None = None  # JSON
    passed: bool | None = None
    # Deployment-specific
    deployment_id: str | None = None
    strategy: str | None = None
    environment: str | None = None
    endpoint: str | None = None
    # Serving-specific
    selected_model: str | None = None
    fallback_chain: str | None = None  # JSON
    cache_hit: bool | None = None
    # Monitoring-specific
    check_type: str | None = None
    drift_score: float | None = None
    drift_type: str | None = None
    action_triggered: str | None = None


class AIAssetInventoryEvent(AIBaseEvent):
    """AI asset inventory — reuses OCSF Inventory Info (5001, Discovery)."""
    category_uid: int = OCSFCategoryUID.DISCOVERY
    class_uid: int = OCSFClassUID.INVENTORY_INFO
    operation_type: str  # "register", "discover", "audit", "classify", "decommission"
    asset_id: str | None = None
    asset_name: str | None = None
    asset_type: str | None = None
    asset_version: str | None = None
    owner: str | None = None
    deployment_environment: str | None = None
    risk_classification: str | None = None
    # Discovery-specific
    discovery_scope: str | None = None
    discovery_method: str | None = None
    assets_found: int | None = None
    new_assets: int | None = None
    shadow_assets: int | None = None
    # Audit-specific
    audit_type: str | None = None
    audit_result: str | None = None
    audit_framework: str | None = None
    audit_findings: str | None = None  # JSON
    # Classification-specific
    classification_framework: str | None = None
    previous_classification: str | None = None
    classification_reason: str | None = None
