"""AITF OCSF Category 7 Event Classes.

Defines all ten AI event classes (7001-7010) for OCSF integration.
Based on event classes from the AITelemetry project, extended
for AITF with MCP, Skills, ModelOps, Asset Inventory, and enhanced agent support.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from aitf.ocsf.schema import (
    AIBaseEvent,
    AIClassUID,
    AICostInfo,
    AILatencyMetrics,
    AIModelInfo,
    AISecurityFinding,
    AITeamInfo,
    AITokenUsage,
)


class AIModelInferenceEvent(AIBaseEvent):
    """OCSF Class 7001: AI Model Inference.

    Represents an AI model inference operation (request + response).
    """
    class_uid: int = AIClassUID.MODEL_INFERENCE
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
    """OCSF Class 7002: AI Agent Activity.

    Represents an AI agent lifecycle event (session, step, delegation).
    """
    class_uid: int = AIClassUID.AGENT_ACTIVITY
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


class AIToolExecutionEvent(AIBaseEvent):
    """OCSF Class 7003: AI Tool Execution.

    Represents a tool/function execution, including MCP tools and skills.
    """
    class_uid: int = AIClassUID.TOOL_EXECUTION
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
    """OCSF Class 7004: AI Data Retrieval.

    Represents RAG and vector search operations.
    """
    class_uid: int = AIClassUID.DATA_RETRIEVAL
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
    """OCSF Class 7005: AI Security Finding.

    Represents a security finding in AI operations.
    """
    class_uid: int = AIClassUID.SECURITY_FINDING
    finding: AISecurityFinding


class AISupplyChainEvent(AIBaseEvent):
    """OCSF Class 7006: AI Supply Chain.

    Represents AI supply chain events (model provenance, integrity).
    """
    class_uid: int = AIClassUID.SUPPLY_CHAIN
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
    """OCSF Class 7007: AI Governance.

    Represents compliance and governance events.
    """
    class_uid: int = AIClassUID.GOVERNANCE
    frameworks: list[str] = Field(default_factory=list)
    controls: str | None = None  # JSON
    event_type: str = ""
    violation_detected: bool = False
    violation_severity: str | None = None
    remediation: str | None = None
    audit_id: str | None = None


class AIIdentityEvent(AIBaseEvent):
    """OCSF Class 7008: AI Identity.

    Represents agent identity and authentication events.
    """
    class_uid: int = AIClassUID.IDENTITY
    agent_name: str
    agent_id: str
    auth_method: str  # "api_key", "oauth", "mtls", "jwt"
    auth_result: str  # "success", "failure", "denied"
    permissions: list[str] = Field(default_factory=list)
    credential_type: str | None = None
    delegation_chain: list[str] = Field(default_factory=list)
    scope: str | None = None


class AIModelOpsEvent(AIBaseEvent):
    """OCSF Class 7009: AI Model Operations.

    Represents model lifecycle operations: training, evaluation,
    deployment, serving, and monitoring.
    """
    class_uid: int = AIClassUID.MODEL_OPS
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
    """OCSF Class 7010: AI Asset Inventory.

    Represents AI asset lifecycle events: registration, discovery,
    audit, classification, and decommissioning.
    """
    class_uid: int = AIClassUID.ASSET_INVENTORY
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
