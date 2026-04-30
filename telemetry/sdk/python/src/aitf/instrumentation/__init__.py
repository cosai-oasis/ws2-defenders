"""AITF Instrumentation modules for AI system telemetry.

Provides auto-instrumentation for LLM inference, agent execution,
MCP protocol, RAG pipelines, skill invocations, model operations
(LLMOps/MLOps), agentic identity management, AI asset inventory,
model drift detection, and agentic communication protocols (A2A, ACP).
"""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

from aitf.instrumentation.a2a import A2AInstrumentor
from aitf.instrumentation.acp import ACPInstrumentor
from aitf.instrumentation.agent import AgentInstrumentor
from aitf.instrumentation.agentic_log import AgenticLogInstrumentor
from aitf.instrumentation.asset_inventory import AssetInventoryInstrumentor
from aitf.instrumentation.drift_detection import DriftDetectionInstrumentor
from aitf.instrumentation.identity import IdentityInstrumentor
from aitf.instrumentation.llm import LLMInstrumentor
from aitf.instrumentation.mcp import MCPInstrumentor
from aitf.instrumentation.model_ops import ModelOpsInstrumentor
from aitf.instrumentation.rag import RAGInstrumentor
from aitf.instrumentation.skills import SkillInstrumentor


class AITFInstrumentor:
    """Main AITF instrumentor that manages all sub-instrumentors.

    Usage:
        instrumentor = AITFInstrumentor()
        instrumentor.instrument_all()

        # Or selectively:
        instrumentor.instrument(llm=True, agent=True, mcp=True)
    """

    def __init__(self, tracer_provider: TracerProvider | None = None):
        self._tracer_provider = tracer_provider
        self._llm = LLMInstrumentor(tracer_provider=tracer_provider)
        self._agent = AgentInstrumentor(tracer_provider=tracer_provider)
        self._mcp = MCPInstrumentor(tracer_provider=tracer_provider)
        self._rag = RAGInstrumentor(tracer_provider=tracer_provider)
        self._skills = SkillInstrumentor(tracer_provider=tracer_provider)
        self._model_ops = ModelOpsInstrumentor(tracer_provider=tracer_provider)
        self._identity = IdentityInstrumentor(tracer_provider=tracer_provider)
        self._asset_inventory = AssetInventoryInstrumentor(tracer_provider=tracer_provider)
        self._drift_detection = DriftDetectionInstrumentor(tracer_provider=tracer_provider)
        self._a2a = A2AInstrumentor(tracer_provider=tracer_provider)
        self._acp = ACPInstrumentor(tracer_provider=tracer_provider)
        self._agentic_log = AgenticLogInstrumentor(tracer_provider=tracer_provider)
        self._instrumented = False

    def instrument_all(self) -> None:
        """Instrument all supported AI components."""
        self._llm.instrument()
        self._agent.instrument()
        self._mcp.instrument()
        self._rag.instrument()
        self._skills.instrument()
        self._model_ops.instrument()
        self._identity.instrument()
        self._asset_inventory.instrument()
        self._drift_detection.instrument()
        self._a2a.instrument()
        self._acp.instrument()
        self._agentic_log.instrument()
        self._instrumented = True

    def instrument(
        self,
        llm: bool = False,
        agent: bool = False,
        mcp: bool = False,
        rag: bool = False,
        skills: bool = False,
        model_ops: bool = False,
        identity: bool = False,
        asset_inventory: bool = False,
        drift_detection: bool = False,
        a2a: bool = False,
        acp: bool = False,
        agentic_log: bool = False,
    ) -> None:
        """Selectively instrument AI components."""
        if llm:
            self._llm.instrument()
        if agent:
            self._agent.instrument()
        if mcp:
            self._mcp.instrument()
        if rag:
            self._rag.instrument()
        if skills:
            self._skills.instrument()
        if model_ops:
            self._model_ops.instrument()
        if identity:
            self._identity.instrument()
        if asset_inventory:
            self._asset_inventory.instrument()
        if drift_detection:
            self._drift_detection.instrument()
        if a2a:
            self._a2a.instrument()
        if acp:
            self._acp.instrument()
        if agentic_log:
            self._agentic_log.instrument()
        self._instrumented = True

    def uninstrument_all(self) -> None:
        """Remove all instrumentation."""
        self._llm.uninstrument()
        self._agent.uninstrument()
        self._mcp.uninstrument()
        self._rag.uninstrument()
        self._skills.uninstrument()
        self._model_ops.uninstrument()
        self._identity.uninstrument()
        self._asset_inventory.uninstrument()
        self._drift_detection.uninstrument()
        self._a2a.uninstrument()
        self._acp.uninstrument()
        self._agentic_log.uninstrument()
        self._instrumented = False

    @property
    def is_instrumented(self) -> bool:
        return self._instrumented

    @property
    def llm(self) -> LLMInstrumentor:
        return self._llm

    @property
    def agent(self) -> AgentInstrumentor:
        return self._agent

    @property
    def mcp(self) -> MCPInstrumentor:
        return self._mcp

    @property
    def rag(self) -> RAGInstrumentor:
        return self._rag

    @property
    def skills(self) -> SkillInstrumentor:
        return self._skills

    @property
    def model_ops(self) -> ModelOpsInstrumentor:
        return self._model_ops

    @property
    def identity(self) -> IdentityInstrumentor:
        return self._identity

    @property
    def asset_inventory(self) -> AssetInventoryInstrumentor:
        return self._asset_inventory

    @property
    def drift_detection(self) -> DriftDetectionInstrumentor:
        return self._drift_detection

    @property
    def a2a(self) -> A2AInstrumentor:
        return self._a2a

    @property
    def acp(self) -> ACPInstrumentor:
        return self._acp

    @property
    def agentic_log(self) -> AgenticLogInstrumentor:
        return self._agentic_log


__all__ = [
    "AITFInstrumentor",
    "LLMInstrumentor",
    "AgentInstrumentor",
    "MCPInstrumentor",
    "RAGInstrumentor",
    "SkillInstrumentor",
    "ModelOpsInstrumentor",
    "IdentityInstrumentor",
    "AssetInventoryInstrumentor",
    "DriftDetectionInstrumentor",
    "A2AInstrumentor",
    "ACPInstrumentor",
    "AgenticLogInstrumentor",
]
