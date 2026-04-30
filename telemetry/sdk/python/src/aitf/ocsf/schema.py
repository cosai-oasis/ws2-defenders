"""AITF OCSF Base Schema.

OCSF v1.1.0 base objects and AI-specific extension models.
Based on the OCSF schema from the AITelemetry project, enhanced
for AITF Category 7 AI events.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


# --- OCSF Enumerations ---

class OCSFSeverity(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class OCSFStatus(IntEnum):
    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2
    OTHER = 99


class OCSFActivity(IntEnum):
    UNKNOWN = 0
    CREATE = 1
    READ = 2
    UPDATE = 3
    DELETE = 4
    OTHER = 99


class AIClassUID(IntEnum):
    """AITF OCSF Category 7 class UIDs."""
    MODEL_INFERENCE = 7001
    AGENT_ACTIVITY = 7002
    TOOL_EXECUTION = 7003
    DATA_RETRIEVAL = 7004
    SECURITY_FINDING = 7005
    SUPPLY_CHAIN = 7006
    GOVERNANCE = 7007
    IDENTITY = 7008
    MODEL_OPS = 7009
    ASSET_INVENTORY = 7010


# --- OCSF Base Objects ---

class OCSFMetadata(BaseModel):
    """OCSF event metadata."""
    version: str = "1.1.0"
    product: dict[str, str] = Field(
        default_factory=lambda: {
            "name": "AITF",
            "vendor_name": "AITF",
            "version": "1.0.0",
        }
    )
    uid: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_uid: str | None = None
    original_time: str | None = None
    logged_time: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class OCSFActor(BaseModel):
    """OCSF actor information."""
    user: dict[str, Any] | None = None
    session: dict[str, Any] | None = None
    app_name: str | None = None


class OCSFDevice(BaseModel):
    """OCSF device/host information."""
    hostname: str | None = None
    ip: str | None = None
    type: str | None = None
    os: dict[str, str] | None = None
    cloud: dict[str, str] | None = None
    container: dict[str, str] | None = None


class OCSFEnrichment(BaseModel):
    """OCSF enrichment data."""
    name: str
    value: str
    type: str | None = None
    provider: str | None = None


class OCSFObservable(BaseModel):
    """OCSF observable value."""
    name: str
    type: str
    value: str


# --- AI-Specific Extension Models ---

class AIModelInfo(BaseModel):
    """AI model information."""
    model_id: str
    name: str | None = None
    version: str | None = None
    provider: str | None = None
    type: str | None = None  # llm, embedding, image, audio, multimodal
    parameters: dict[str, Any] | None = None


class AITokenUsage(BaseModel):
    """AI token usage statistics."""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cached_tokens: int = 0
    reasoning_tokens: int = 0
    estimated_cost_usd: float | None = None

    @model_validator(mode="after")
    def compute_total(self) -> "AITokenUsage":
        if self.total_tokens == 0:
            self.total_tokens = self.input_tokens + self.output_tokens
        return self


class AILatencyMetrics(BaseModel):
    """AI operation latency metrics."""
    total_ms: float = 0.0
    time_to_first_token_ms: float | None = None
    tokens_per_second: float | None = None
    queue_time_ms: float | None = None
    inference_time_ms: float | None = None


class AICostInfo(BaseModel):
    """AI operation cost information."""
    input_cost_usd: float = 0.0
    output_cost_usd: float = 0.0
    total_cost_usd: float = 0.0
    currency: str = "USD"


class AITeamInfo(BaseModel):
    """Multi-agent team information."""
    team_name: str
    team_id: str | None = None
    topology: str | None = None
    members: list[str] = Field(default_factory=list)
    coordinator: str | None = None


class AISecurityFinding(BaseModel):
    """Security finding details."""
    finding_type: str
    owasp_category: str | None = None
    risk_level: str
    risk_score: float
    confidence: float
    detection_method: str = "pattern"
    blocked: bool = False
    details: str | None = None
    pii_types: list[str] = Field(default_factory=list)
    matched_patterns: list[str] = Field(default_factory=list)
    remediation: str | None = None


class ComplianceMetadata(BaseModel):
    """Compliance framework mappings."""
    nist_ai_rmf: dict[str, Any] | None = None
    mitre_atlas: dict[str, Any] | None = None
    iso_42001: dict[str, Any] | None = None
    eu_ai_act: dict[str, Any] | None = None
    soc2: dict[str, Any] | None = None
    gdpr: dict[str, Any] | None = None
    ccpa: dict[str, Any] | None = None
    csa_aicm: dict[str, Any] | None = None


# --- OCSF Base Event ---

class AIBaseEvent(BaseModel):
    """Base OCSF event for all AITF Category 7 events."""
    activity_id: int = OCSFActivity.OTHER
    category_uid: int = 7  # AI System Activity
    class_uid: int
    type_uid: int = 0
    time: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    severity_id: int = OCSFSeverity.INFORMATIONAL
    status_id: int = OCSFStatus.SUCCESS
    message: str = ""
    metadata: OCSFMetadata = Field(default_factory=OCSFMetadata)
    actor: OCSFActor | None = None
    device: OCSFDevice | None = None
    compliance: ComplianceMetadata | None = None
    observables: list[OCSFObservable] = Field(default_factory=list)
    enrichments: list[OCSFEnrichment] = Field(default_factory=list)

    @model_validator(mode="after")
    def compute_type_uid(self) -> "AIBaseEvent":
        if self.type_uid == 0:
            self.type_uid = self.class_uid * 100 + self.activity_id
        return self
