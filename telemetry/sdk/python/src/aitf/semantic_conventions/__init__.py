"""AITF Semantic Conventions.

Defines all attribute constants, metric names, and span names used by AITF.
Extends OpenTelemetry GenAI semantic conventions with AITF-specific namespaces.
"""

from aitf.semantic_conventions.attributes import (
    AIBOMAttributes,
    AgentAttributes,
    ComplianceAttributes,
    CostAttributes,
    GenAIAttributes,
    MCPAttributes,
    MemoryAttributes,
    QualityAttributes,
    RAGAttributes,
    SecurityAttributes,
    SkillAttributes,
    SupplyChainAttributes,
)
from aitf.semantic_conventions.metrics import AITFMetrics
from aitf.semantic_conventions.resource import AITFResource

__all__ = [
    "GenAIAttributes",
    "AgentAttributes",
    "MCPAttributes",
    "SkillAttributes",
    "RAGAttributes",
    "SecurityAttributes",
    "ComplianceAttributes",
    "CostAttributes",
    "QualityAttributes",
    "SupplyChainAttributes",
    "AIBOMAttributes",
    "MemoryAttributes",
    "AITFMetrics",
    "AITFResource",
]
