"""Tests for AITF semantic convention constants."""

from aitf.semantic_conventions.attributes import (
    AgentAttributes,
    ComplianceAttributes,
    CostAttributes,
    GenAIAttributes,
    MCPAttributes,
    QualityAttributes,
    RAGAttributes,
    SecurityAttributes,
    SkillAttributes,
)
from aitf.semantic_conventions.metrics import AITFMetrics


class TestGenAIAttributes:
    def test_system_attribute(self):
        assert GenAIAttributes.SYSTEM == "gen_ai.system"

    def test_request_model(self):
        assert GenAIAttributes.REQUEST_MODEL == "gen_ai.request.model"

    def test_usage_tokens(self):
        assert GenAIAttributes.USAGE_INPUT_TOKENS == "gen_ai.usage.input_tokens"
        assert GenAIAttributes.USAGE_OUTPUT_TOKENS == "gen_ai.usage.output_tokens"

    def test_system_values(self):
        assert GenAIAttributes.System.OPENAI == "openai"
        assert GenAIAttributes.System.ANTHROPIC == "anthropic"
        assert GenAIAttributes.System.BEDROCK == "bedrock"

    def test_operation_values(self):
        assert GenAIAttributes.Operation.CHAT == "chat"
        assert GenAIAttributes.Operation.EMBEDDINGS == "embeddings"


class TestAgentAttributes:
    def test_namespace(self):
        assert AgentAttributes.NAME.startswith("aitf.agent.")
        assert AgentAttributes.SESSION_ID.startswith("aitf.agent.session.")
        assert AgentAttributes.STEP_TYPE.startswith("aitf.agent.step.")

    def test_step_types(self):
        assert AgentAttributes.StepType.PLANNING == "planning"
        assert AgentAttributes.StepType.TOOL_USE == "tool_use"
        assert AgentAttributes.StepType.DELEGATION == "delegation"

    def test_team_topologies(self):
        assert AgentAttributes.TeamTopology.HIERARCHICAL == "hierarchical"
        assert AgentAttributes.TeamTopology.SWARM == "swarm"


class TestMCPAttributes:
    def test_namespace(self):
        assert MCPAttributes.SERVER_NAME.startswith("aitf.mcp.server.")
        assert MCPAttributes.TOOL_NAME.startswith("aitf.mcp.tool.")
        assert MCPAttributes.RESOURCE_URI.startswith("aitf.mcp.resource.")
        assert MCPAttributes.PROMPT_NAME.startswith("aitf.mcp.prompt.")

    def test_transport_values(self):
        assert MCPAttributes.Transport.STDIO == "stdio"
        assert MCPAttributes.Transport.SSE == "sse"
        assert MCPAttributes.Transport.STREAMABLE_HTTP == "streamable_http"


class TestSkillAttributes:
    def test_namespace(self):
        assert SkillAttributes.NAME == "aitf.skill.name"
        assert SkillAttributes.VERSION == "aitf.skill.version"

    def test_categories(self):
        assert SkillAttributes.Category.SEARCH == "search"
        assert SkillAttributes.Category.CODE == "code"

    def test_status_values(self):
        assert SkillAttributes.Status.SUCCESS == "success"
        assert SkillAttributes.Status.DENIED == "denied"


class TestSecurityAttributes:
    def test_owasp_categories(self):
        assert SecurityAttributes.OWASP.LLM01 == "LLM01"
        assert SecurityAttributes.OWASP.LLM10 == "LLM10"

    def test_threat_types(self):
        assert SecurityAttributes.ThreatType.PROMPT_INJECTION == "prompt_injection"
        assert SecurityAttributes.ThreatType.JAILBREAK == "jailbreak"


class TestCostAttributes:
    def test_namespace(self):
        assert CostAttributes.TOTAL_COST == "aitf.cost.total_cost"
        assert CostAttributes.ATTRIBUTION_USER == "aitf.cost.attribution.user"


class TestRAGAttributes:
    def test_namespace(self):
        assert RAGAttributes.PIPELINE_NAME == "aitf.rag.pipeline.name"
        assert RAGAttributes.RETRIEVE_DATABASE == "aitf.rag.retrieve.database"


class TestMetrics:
    def test_genai_metrics(self):
        assert AITFMetrics.GEN_AI_TOKEN_USAGE == "gen_ai.client.token.usage"

    def test_aitf_metrics(self):
        assert AITFMetrics.AGENT_SESSIONS == "aitf.agent.sessions"
        assert AITFMetrics.MCP_TOOL_INVOCATIONS == "aitf.mcp.tool.invocations"
        assert AITFMetrics.SKILL_INVOCATIONS == "aitf.skill.invocations"
        assert AITFMetrics.COST_TOTAL == "aitf.cost.total"
        assert AITFMetrics.SECURITY_THREATS_DETECTED == "aitf.security.threats_detected"
