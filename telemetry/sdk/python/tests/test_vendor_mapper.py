"""Tests for AITF Vendor Mapper."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aitf.ocsf.vendor_mapper import VendorMapper, VendorMapping

# Path to the built-in mapping files
MAPPINGS_DIR = Path(__file__).parent.parent / "src" / "aitf" / "ocsf" / "vendor_mappings"


# ---------------------------------------------------------------------------
# Helpers – create mock ReadableSpan objects
# ---------------------------------------------------------------------------

def _make_span(name: str, attributes: dict | None = None) -> MagicMock:
    """Create a mock ReadableSpan with the given name and attributes."""
    span = MagicMock()
    span.name = name
    span.attributes = attributes or {}
    span.start_time = 1700000000_000000000  # nanoseconds
    return span


# ---------------------------------------------------------------------------
# TestVendorMapping – unit tests for a single mapping file
# ---------------------------------------------------------------------------

class TestVendorMapping:
    """Test VendorMapping parsed from JSON."""

    def setup_method(self):
        langchain_path = MAPPINGS_DIR / "langchain.json"
        data = json.loads(langchain_path.read_text(encoding="utf-8"))
        self.mapping = VendorMapping(data)

    def test_vendor_name(self):
        assert self.mapping.vendor == "langchain"

    def test_version(self):
        assert self.mapping.version == "0.3"

    def test_classify_inference_span(self):
        assert self.mapping.classify_span("ChatOpenAI") == "inference"
        assert self.mapping.classify_span("ChatAnthropic") == "inference"
        assert self.mapping.classify_span("OpenAIEmbeddings") == "inference"

    def test_classify_agent_span(self):
        assert self.mapping.classify_span("AgentExecutor") == "agent"
        assert self.mapping.classify_span("LangGraph") == "agent"

    def test_classify_tool_span(self):
        assert self.mapping.classify_span("Tool:search") == "tool"
        assert self.mapping.classify_span("StructuredTool:calculator") == "tool"

    def test_classify_retrieval_span(self):
        assert self.mapping.classify_span("Retriever:pinecone") == "retrieval"
        assert self.mapping.classify_span("VectorStoreRetriever") == "retrieval"

    def test_classify_unknown_span(self):
        assert self.mapping.classify_span("something-unknown") is None

    def test_translate_inference_attributes(self):
        vendor_attrs = {
            "ls_provider": "openai",
            "ls_model_name": "gpt-4o",
            "ls_temperature": 0.7,
            "llm.token_count.prompt": 100,
            "llm.token_count.completion": 50,
        }
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.system"] == "openai"
        assert result["gen_ai.request.model"] == "gpt-4o"
        assert result["gen_ai.request.temperature"] == 0.7
        assert result["gen_ai.usage.input_tokens"] == 100
        assert result["gen_ai.usage.output_tokens"] == 50
        # Default should be applied
        assert result["gen_ai.operation.name"] == "chat"

    def test_translate_applies_defaults(self):
        result = self.mapping.translate_attributes("inference", {})
        assert result["gen_ai.operation.name"] == "chat"

    def test_translate_does_not_override_explicit(self):
        vendor_attrs = {"ls_model_type": "embeddings"}
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.operation.name"] == "embeddings"

    def test_ocsf_class_uid(self):
        assert self.mapping.get_ocsf_class_uid("inference") == 7001
        assert self.mapping.get_ocsf_class_uid("agent") == 7002
        assert self.mapping.get_ocsf_class_uid("tool") == 7003
        assert self.mapping.get_ocsf_class_uid("retrieval") == 7004

    def test_ocsf_activity_id(self):
        assert self.mapping.get_ocsf_activity_id("inference", "chat") == 1
        assert self.mapping.get_ocsf_activity_id("inference", "embeddings") == 3
        assert self.mapping.get_ocsf_activity_id("inference") == 99  # default

    def test_provider_detection_from_model(self):
        vendor_attrs = {"ls_model_name": "gpt-4o"}
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.system"] == "openai"

    def test_provider_detection_from_attribute(self):
        vendor_attrs = {"ls_provider": "anthropic", "ls_model_name": "claude-3.5-sonnet"}
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.system"] == "anthropic"


# ---------------------------------------------------------------------------
# TestCrewAIMapping – CrewAI-specific tests
# ---------------------------------------------------------------------------

class TestCrewAIMapping:
    """Test CrewAI vendor mapping."""

    def setup_method(self):
        crewai_path = MAPPINGS_DIR / "crewai.json"
        data = json.loads(crewai_path.read_text(encoding="utf-8"))
        self.mapping = VendorMapping(data)

    def test_vendor_name(self):
        assert self.mapping.vendor == "crewai"

    def test_classify_inference(self):
        assert self.mapping.classify_span("LLM Call gpt-4o") == "inference"
        assert self.mapping.classify_span("CrewAI.LLM.call") == "inference"
        assert self.mapping.classify_span("LiteLLM.completion") == "inference"

    def test_classify_agent(self):
        assert self.mapping.classify_span("Crew Execution") == "agent"
        assert self.mapping.classify_span("Agent Execution") == "agent"
        assert self.mapping.classify_span("Task Execution") == "agent"

    def test_classify_tool(self):
        assert self.mapping.classify_span("Tool Usage") == "tool"
        assert self.mapping.classify_span("Tool Execution search") == "tool"

    def test_classify_delegation(self):
        assert self.mapping.classify_span("Task Delegation") == "delegation"
        assert self.mapping.classify_span("Delegation: to-agent") == "delegation"

    def test_translate_agent_attributes(self):
        vendor_attrs = {
            "crewai.agent.role": "researcher",
            "crewai.agent.goal": "Find relevant papers",
            "crewai.agent.id": "agent-001",
            "crewai.agent.llm": "gpt-4o",
            "crewai.crew.name": "research-crew",
            "crewai.crew.process": "sequential",
        }
        result = self.mapping.translate_attributes("agent", vendor_attrs)
        assert result["aitf.agent.name"] == "researcher"
        assert result["aitf.agent.goal"] == "Find relevant papers"
        assert result["aitf.agent.id"] == "agent-001"
        assert result["aitf.agent.model"] == "gpt-4o"
        assert result["aitf.agent.team.name"] == "research-crew"
        assert result["aitf.agent.team.topology"] == "sequential"
        # Defaults
        assert result["aitf.agent.framework"] == "crewai"
        assert result["aitf.agent.type"] == "autonomous"

    def test_translate_inference_with_litellm(self):
        vendor_attrs = {
            "litellm.model": "claude-3.5-sonnet",
            "litellm.provider": "anthropic",
            "litellm.input_tokens": 200,
            "litellm.output_tokens": 100,
        }
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.request.model"] == "claude-3.5-sonnet"
        assert result["gen_ai.system"] == "anthropic"
        assert result["gen_ai.usage.input_tokens"] == 200
        assert result["gen_ai.usage.output_tokens"] == 100

    def test_translate_tool_attributes(self):
        vendor_attrs = {
            "crewai.tool.name": "web_search",
            "crewai.tool.input": '{"query": "AI telemetry"}',
            "crewai.tool.output": "Results...",
            "crewai.tool.duration_ms": 450.5,
        }
        result = self.mapping.translate_attributes("tool", vendor_attrs)
        assert result["aitf.mcp.tool.name"] == "web_search"
        assert result["aitf.mcp.tool.input"] == '{"query": "AI telemetry"}'
        assert result["aitf.mcp.tool.output"] == "Results..."
        assert result["aitf.mcp.tool.duration_ms"] == 450.5

    def test_translate_delegation_attributes(self):
        vendor_attrs = {
            "crewai.delegation.from_agent": "manager",
            "crewai.delegation.to_agent": "researcher",
            "crewai.delegation.task": "Find papers on LLM security",
            "crewai.delegation.reason": "Specialized knowledge needed",
        }
        result = self.mapping.translate_attributes("delegation", vendor_attrs)
        assert result["aitf.agent.name"] == "manager"
        assert result["aitf.agent.delegation.target_agent"] == "researcher"
        assert result["aitf.agent.delegation.task"] == "Find papers on LLM security"

    def test_ocsf_class_uids(self):
        assert self.mapping.get_ocsf_class_uid("inference") == 7001
        assert self.mapping.get_ocsf_class_uid("agent") == 7002
        assert self.mapping.get_ocsf_class_uid("tool") == 7003
        assert self.mapping.get_ocsf_class_uid("delegation") == 7002

    def test_severity_mapping(self):
        assert self.mapping.get_severity_id("crewai.task.status", "completed") == 1
        assert self.mapping.get_severity_id("crewai.task.status", "error") == 4
        assert self.mapping.get_severity_id("crewai.delegation.status", "rejected") == 3


# ---------------------------------------------------------------------------
# TestOpenRouterMapping – OpenRouter-specific tests
# ---------------------------------------------------------------------------

class TestOpenRouterMapping:
    """Test OpenRouter vendor mapping."""

    def setup_method(self):
        openrouter_path = MAPPINGS_DIR / "openrouter.json"
        data = json.loads(openrouter_path.read_text(encoding="utf-8"))
        self.mapping = VendorMapping(data)

    def test_vendor_name(self):
        assert self.mapping.vendor == "openrouter"

    def test_classify_inference_native_prefix(self):
        assert self.mapping.classify_span("openrouter.chat") == "inference"
        assert self.mapping.classify_span("OpenRouter.completion") == "inference"

    def test_classify_inference_provider_prefix(self):
        """OpenRouter model IDs include the provider prefix."""
        assert self.mapping.classify_span("chat anthropic/claude-sonnet-4-5-20250929") == "inference"
        assert self.mapping.classify_span("chat openai/gpt-4o") == "inference"
        assert self.mapping.classify_span("chat google/gemini-2.0-flash") == "inference"
        assert self.mapping.classify_span("chat meta-llama/llama-3.3-70b") == "inference"
        assert self.mapping.classify_span("chat deepseek/deepseek-r1") == "inference"

    def test_classify_unknown_span(self):
        assert self.mapping.classify_span("http.request GET /api") is None

    def test_translate_inference_attributes(self):
        vendor_attrs = {
            "openrouter.model": "anthropic/claude-sonnet-4-5-20250929",
            "openrouter.route.provider": "anthropic",
            "openrouter.request.temperature": 0.5,
            "openrouter.request.max_tokens": 4096,
            "openrouter.usage.prompt_tokens": 500,
            "openrouter.usage.completion_tokens": 200,
            "openrouter.usage.total_tokens": 700,
            "openrouter.cost.prompt": 0.0015,
            "openrouter.cost.completion": 0.003,
            "openrouter.cost.total": 0.0045,
            "openrouter.latency.total_ms": 1250.0,
            "openrouter.response.finish_reason": "end_turn",
            "openrouter.response.id": "gen-abc123",
        }
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.request.model"] == "anthropic/claude-sonnet-4-5-20250929"
        assert result["gen_ai.request.temperature"] == 0.5
        assert result["gen_ai.request.max_tokens"] == 4096
        assert result["gen_ai.usage.input_tokens"] == 500
        assert result["gen_ai.usage.output_tokens"] == 200
        assert result["gen_ai.usage.total_tokens"] == 700
        assert result["aitf.cost.input_cost"] == 0.0015
        assert result["aitf.cost.output_cost"] == 0.003
        assert result["aitf.cost.total_cost"] == 0.0045
        assert result["aitf.latency.total_ms"] == 1250.0
        assert result["gen_ai.response.finish_reasons"] == "end_turn"
        assert result["gen_ai.response.id"] == "gen-abc123"
        # Default
        assert result["gen_ai.operation.name"] == "chat"

    def test_translate_routing_attributes(self):
        """OpenRouter-specific routing metadata should be preserved."""
        vendor_attrs = {
            "openrouter.model": "openai/gpt-4o",
            "openrouter.route.provider": "openai",
            "openrouter.route.model": "gpt-4o-2025-01-01",
            "openrouter.route.id": "route-xyz789",
            "openrouter.request.transforms": "middle-out",
            "openrouter.request.route": "fallback",
        }
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["aitf.openrouter.route_provider"] == "openai"
        assert result["aitf.openrouter.route_model"] == "gpt-4o-2025-01-01"
        assert result["aitf.openrouter.transforms"] == "middle-out"
        assert result["aitf.openrouter.route_preference"] == "fallback"

    def test_provider_detection_from_model_prefix(self):
        """Detect provider from OpenRouter model ID prefix."""
        # Anthropic model
        vendor_attrs = {"openrouter.model": "anthropic/claude-sonnet-4-5-20250929"}
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.system"] == "anthropic"

        # OpenAI model
        vendor_attrs = {"openrouter.model": "openai/gpt-4o"}
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.system"] == "openai"

        # Google model
        vendor_attrs = {"openrouter.model": "google/gemini-2.0-flash"}
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.system"] == "google"

        # DeepSeek model
        vendor_attrs = {"openrouter.model": "deepseek/deepseek-r1"}
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.system"] == "deepseek"

    def test_provider_detection_from_explicit_attribute(self):
        """Explicit route.provider takes priority over model prefix."""
        vendor_attrs = {
            "openrouter.model": "anthropic/claude-sonnet-4-5-20250929",
            "openrouter.route.provider": "anthropic",
        }
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.system"] == "anthropic"

    def test_ocsf_class_uid(self):
        assert self.mapping.get_ocsf_class_uid("inference") == 7001

    def test_ocsf_activity_id(self):
        assert self.mapping.get_ocsf_activity_id("inference", "chat") == 1
        assert self.mapping.get_ocsf_activity_id("inference", "embeddings") == 3
        assert self.mapping.get_ocsf_activity_id("inference") == 1  # default

    def test_severity_mapping(self):
        assert self.mapping.get_severity_id("openrouter.response.status", "success") == 1
        assert self.mapping.get_severity_id("openrouter.response.status", "rate_limited") == 3
        assert self.mapping.get_severity_id("openrouter.response.status", "error") == 4

    def test_passthrough_standard_genai_attributes(self):
        """Standard gen_ai.* attributes should pass through correctly."""
        vendor_attrs = {
            "gen_ai.system": "anthropic",
            "gen_ai.request.model": "claude-sonnet-4-5-20250929",
            "gen_ai.usage.input_tokens": 300,
            "gen_ai.usage.output_tokens": 150,
        }
        result = self.mapping.translate_attributes("inference", vendor_attrs)
        assert result["gen_ai.system"] == "anthropic"
        assert result["gen_ai.request.model"] == "claude-sonnet-4-5-20250929"
        assert result["gen_ai.usage.input_tokens"] == 300
        assert result["gen_ai.usage.output_tokens"] == 150


# ---------------------------------------------------------------------------
# TestVendorMapper – integration tests for the main mapper class
# ---------------------------------------------------------------------------

class TestVendorMapper:
    """Test VendorMapper loading and span normalization."""

    def setup_method(self):
        self.mapper = VendorMapper()

    def test_loads_builtin_vendors(self):
        vendors = self.mapper.vendors
        assert "langchain" in vendors
        assert "crewai" in vendors
        assert "openrouter" in vendors

    def test_loads_specific_vendors(self):
        mapper = VendorMapper(vendors=["langchain"])
        assert mapper.vendors == ["langchain"]

    def test_get_mapping(self):
        mapping = self.mapper.get_mapping("langchain")
        assert mapping is not None
        assert mapping.vendor == "langchain"

    def test_get_mapping_unknown(self):
        assert self.mapper.get_mapping("unknown-vendor") is None

    def test_list_supported_vendors(self):
        vendor_list = self.mapper.list_supported_vendors()
        assert len(vendor_list) >= 2
        names = [v["vendor"] for v in vendor_list]
        assert "langchain" in names
        assert "crewai" in names

    # -- detect_vendor tests ------------------------------------------------

    def test_detect_langchain_inference_span(self):
        span = _make_span("ChatOpenAI")
        result = self.mapper.detect_vendor(span)
        assert result == ("langchain", "inference")

    def test_detect_langchain_agent_span(self):
        span = _make_span("AgentExecutor")
        result = self.mapper.detect_vendor(span)
        assert result == ("langchain", "agent")

    def test_detect_crewai_agent_span(self):
        span = _make_span("Crew Execution")
        result = self.mapper.detect_vendor(span)
        assert result == ("crewai", "agent")

    def test_detect_crewai_tool_span(self):
        span = _make_span("Tool Usage")
        result = self.mapper.detect_vendor(span)
        assert result == ("crewai", "tool")

    def test_detect_crewai_inference_span(self):
        span = _make_span("LLM Call gpt-4o")
        result = self.mapper.detect_vendor(span)
        assert result == ("crewai", "inference")

    def test_detect_unknown_span(self):
        span = _make_span("http.request GET /api/health")
        result = self.mapper.detect_vendor(span)
        assert result is None

    def test_detect_vendor_from_attributes(self):
        span = _make_span("custom-span", {"crewai.agent.role": "writer"})
        result = self.mapper.detect_vendor(span)
        assert result is not None
        vendor, event_type = result
        assert vendor == "crewai"
        assert event_type == "agent"

    def test_detect_openrouter_inference_span(self):
        span = _make_span("chat anthropic/claude-sonnet-4-5-20250929")
        result = self.mapper.detect_vendor(span)
        assert result == ("openrouter", "inference")

    def test_detect_openrouter_native_span(self):
        span = _make_span("openrouter.chat.completion")
        result = self.mapper.detect_vendor(span)
        assert result == ("openrouter", "inference")

    # -- normalize_span tests -----------------------------------------------

    def test_normalize_langchain_inference(self):
        span = _make_span("ChatOpenAI", {
            "ls_provider": "openai",
            "ls_model_name": "gpt-4o",
            "llm.token_count.prompt": 150,
            "llm.token_count.completion": 75,
        })
        result = self.mapper.normalize_span(span)
        assert result is not None
        vendor, event_type, attrs = result
        assert vendor == "langchain"
        assert event_type == "inference"
        assert attrs["gen_ai.system"] == "openai"
        assert attrs["gen_ai.request.model"] == "gpt-4o"
        assert attrs["gen_ai.usage.input_tokens"] == 150
        assert attrs["gen_ai.usage.output_tokens"] == 75

    def test_normalize_crewai_agent(self):
        span = _make_span("Agent Execution", {
            "crewai.agent.role": "analyst",
            "crewai.agent.goal": "Analyze data",
            "crewai.crew.name": "data-crew",
        })
        result = self.mapper.normalize_span(span)
        assert result is not None
        vendor, event_type, attrs = result
        assert vendor == "crewai"
        assert event_type == "agent"
        assert attrs["aitf.agent.name"] == "analyst"
        assert attrs["aitf.agent.framework"] == "crewai"

    def test_normalize_openrouter_inference(self):
        span = _make_span("chat anthropic/claude-sonnet-4-5-20250929", {
            "openrouter.model": "anthropic/claude-sonnet-4-5-20250929",
            "openrouter.route.provider": "anthropic",
            "openrouter.usage.prompt_tokens": 500,
            "openrouter.usage.completion_tokens": 200,
            "openrouter.cost.total": 0.0045,
            "openrouter.latency.total_ms": 1250.0,
        })
        result = self.mapper.normalize_span(span)
        assert result is not None
        vendor, event_type, attrs = result
        assert vendor == "openrouter"
        assert event_type == "inference"
        assert attrs["gen_ai.request.model"] == "anthropic/claude-sonnet-4-5-20250929"
        assert attrs["gen_ai.system"] == "anthropic"
        assert attrs["gen_ai.usage.input_tokens"] == 500
        assert attrs["gen_ai.usage.output_tokens"] == 200
        assert attrs["aitf.cost.total_cost"] == 0.0045
        assert attrs["aitf.latency.total_ms"] == 1250.0

    def test_normalize_unknown_span(self):
        span = _make_span("http.request")
        assert self.mapper.normalize_span(span) is None

    # -- normalize_attributes tests -----------------------------------------

    def test_normalize_attributes_direct(self):
        attrs = {"crewai.tool.name": "calculator", "crewai.tool.input": "2+2"}
        result = self.mapper.normalize_attributes("crewai", "tool", attrs)
        assert result["aitf.mcp.tool.name"] == "calculator"
        assert result["aitf.mcp.tool.input"] == "2+2"
        assert result["tool_type"] == "function"

    def test_normalize_attributes_unknown_vendor(self):
        with pytest.raises(ValueError, match="Unknown vendor"):
            self.mapper.normalize_attributes("unknown", "tool", {})

    # -- OCSF helpers -------------------------------------------------------

    def test_get_ocsf_class_uid(self):
        assert self.mapper.get_ocsf_class_uid("langchain", "inference") == 7001
        assert self.mapper.get_ocsf_class_uid("crewai", "agent") == 7002
        assert self.mapper.get_ocsf_class_uid("openrouter", "inference") == 7001
        assert self.mapper.get_ocsf_class_uid("unknown", "agent") is None

    def test_get_ocsf_activity_id(self):
        assert self.mapper.get_ocsf_activity_id("langchain", "inference", "chat") == 1
        assert self.mapper.get_ocsf_activity_id("crewai", "agent", "crew_execution") == 1
        assert self.mapper.get_ocsf_activity_id("crewai", "agent", "delegation") == 4
        assert self.mapper.get_ocsf_activity_id("openrouter", "inference", "chat") == 1

    # -- load_file test -----------------------------------------------------

    def test_load_file(self, tmp_path):
        mapping_data = {
            "vendor": "test-vendor",
            "version": "1.0",
            "span_name_patterns": {
                "inference": ["^TestLLM$"]
            },
            "attribute_mappings": {
                "inference": {
                    "vendor_to_aitf": {
                        "test.model": "gen_ai.request.model"
                    },
                    "ocsf_class_uid": 7001,
                    "defaults": {}
                }
            }
        }
        path = tmp_path / "test_vendor.json"
        path.write_text(json.dumps(mapping_data))

        mapping = self.mapper.load_file(path)
        assert mapping.vendor == "test-vendor"
        assert "test-vendor" in self.mapper.vendors

        # Verify the loaded mapping works
        span = _make_span("TestLLM", {"test.model": "test-model-v1"})
        result = self.mapper.normalize_span(span)
        assert result is not None
        assert result[0] == "test-vendor"
        assert result[2]["gen_ai.request.model"] == "test-model-v1"


# ---------------------------------------------------------------------------
# TestMappingFileIntegrity – validates the JSON mapping files themselves
# ---------------------------------------------------------------------------

class TestMappingFileIntegrity:
    """Validate that all vendor mapping JSON files are well-formed."""

    @pytest.fixture(params=list(MAPPINGS_DIR.glob("*.json")))
    def mapping_file(self, request):
        return request.param

    def test_valid_json(self, mapping_file):
        data = json.loads(mapping_file.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_required_fields(self, mapping_file):
        data = json.loads(mapping_file.read_text(encoding="utf-8"))
        assert "vendor" in data
        assert "span_name_patterns" in data
        assert "attribute_mappings" in data

    def test_span_patterns_are_valid_regex(self, mapping_file):
        data = json.loads(mapping_file.read_text(encoding="utf-8"))
        for event_type, patterns in data["span_name_patterns"].items():
            for pattern in patterns:
                import re
                re.compile(pattern)  # should not raise

    def test_attribute_mappings_have_vendor_to_aitf(self, mapping_file):
        data = json.loads(mapping_file.read_text(encoding="utf-8"))
        for event_type, block in data["attribute_mappings"].items():
            assert "vendor_to_aitf" in block, (
                f"Missing vendor_to_aitf in {event_type}"
            )
            assert isinstance(block["vendor_to_aitf"], dict)

    def test_ocsf_class_uids_are_valid(self, mapping_file):
        data = json.loads(mapping_file.read_text(encoding="utf-8"))
        valid_uids = {7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008}
        for event_type, block in data["attribute_mappings"].items():
            if "ocsf_class_uid" in block:
                assert block["ocsf_class_uid"] in valid_uids, (
                    f"Invalid class_uid {block['ocsf_class_uid']} in {event_type}"
                )

    def test_metadata_present(self, mapping_file):
        data = json.loads(mapping_file.read_text(encoding="utf-8"))
        assert "metadata" in data
        assert "ocsf_product" in data["metadata"]
        product = data["metadata"]["ocsf_product"]
        assert "name" in product
        assert "vendor_name" in product
