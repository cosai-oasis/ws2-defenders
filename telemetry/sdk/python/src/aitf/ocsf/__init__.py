"""AITF OCSF Module.

Provides OCSF v1.1.0 schema definitions for AI events (Category 7),
event class models, span-to-OCSF mapping, and compliance mapping.

Based on the OCSF schema extensions from the AITelemetry project.
"""

from aitf.ocsf.schema import (
    AIBaseEvent,
    AICostInfo,
    AILatencyMetrics,
    AIModelInfo,
    AITokenUsage,
    OCSFActor,
    OCSFDevice,
    OCSFMetadata,
)
from aitf.ocsf.event_classes import (
    AIAgentActivityEvent,
    AIAssetInventoryEvent,
    AIDataRetrievalEvent,
    AIGovernanceEvent,
    AIIdentityEvent,
    AIModelInferenceEvent,
    AIModelOpsEvent,
    AISecurityFindingEvent,
    AISupplyChainEvent,
    AIToolExecutionEvent,
)
from aitf.ocsf.mapper import OCSFMapper
from aitf.ocsf.compliance_mapper import ComplianceMapper
from aitf.ocsf.vendor_mapper import VendorMapper, VendorMapping

__all__ = [
    "OCSFMetadata",
    "OCSFActor",
    "OCSFDevice",
    "AIModelInfo",
    "AITokenUsage",
    "AILatencyMetrics",
    "AICostInfo",
    "AIBaseEvent",
    "AIModelInferenceEvent",
    "AIAgentActivityEvent",
    "AIToolExecutionEvent",
    "AIDataRetrievalEvent",
    "AISecurityFindingEvent",
    "AISupplyChainEvent",
    "AIGovernanceEvent",
    "AIIdentityEvent",
    "AIModelOpsEvent",
    "AIAssetInventoryEvent",
    "OCSFMapper",
    "ComplianceMapper",
    "VendorMapper",
    "VendorMapping",
]
