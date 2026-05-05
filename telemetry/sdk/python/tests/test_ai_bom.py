"""Tests for AITF AI-BOM Generator."""

import json

from aitf.generators.ai_bom import (
    AIBOMComponent,
    AIBOMDocument,
    AIBOMGenerator,
    AIBOMVulnerability,
)
from aitf.semantic_conventions.attributes import AIBOMAttributes


class TestAIBOMComponent:
    def test_component_id_deterministic(self):
        c1 = AIBOMComponent(type="model", name="gpt-4o", version="2024-08")
        c2 = AIBOMComponent(type="model", name="gpt-4o", version="2024-08")
        assert c1.component_id == c2.component_id

    def test_component_id_differs_by_version(self):
        c1 = AIBOMComponent(type="model", name="gpt-4o", version="2024-08")
        c2 = AIBOMComponent(type="model", name="gpt-4o", version="2025-01")
        assert c1.component_id != c2.component_id

    def test_component_id_differs_by_type(self):
        c1 = AIBOMComponent(type="model", name="gpt-4o")
        c2 = AIBOMComponent(type="dataset", name="gpt-4o")
        assert c1.component_id != c2.component_id

    def test_component_defaults(self):
        c = AIBOMComponent(type="model", name="test-model")
        assert c.version is None
        assert c.provider is None
        assert c.dependencies == []
        assert c.properties == {}
        assert c.occurrence_count == 1
        assert c.first_seen is not None
        assert c.last_seen is not None


class TestAIBOMDocument:
    def setup_method(self):
        self.components = [
            AIBOMComponent(type="model", name="gpt-4o", provider="openai"),
            AIBOMComponent(type="model", name="claude-sonnet-4-20250514", provider="anthropic"),
            AIBOMComponent(type="vector_db", name="pinecone"),
            AIBOMComponent(type="mcp_server", name="filesystem"),
        ]
        self.doc = AIBOMDocument(
            bom_id="test-bom-001",
            components=self.components,
            metadata={"system_name": "test-system"},
        )

    def test_component_count(self):
        assert self.doc.component_count == 4

    def test_component_types(self):
        types = self.doc.component_types
        assert types["model"] == 2
        assert types["vector_db"] == 1
        assert types["mcp_server"] == 1

    def test_to_dict(self):
        d = self.doc.to_dict()
        assert d["bom_id"] == "test-bom-001"
        assert d["format"] == "aitf"
        assert len(d["components"]) == 4
        assert d["summary"]["total_components"] == 4
        assert d["metadata"]["system_name"] == "test-system"

    def test_to_json(self):
        j = self.doc.to_json()
        parsed = json.loads(j)
        assert parsed["bom_id"] == "test-bom-001"
        assert len(parsed["components"]) == 4

    def test_to_cyclonedx(self):
        cdx = self.doc.to_cyclonedx()
        assert cdx["bomFormat"] == "CycloneDX"
        assert cdx["specVersion"] == "1.6"
        assert len(cdx["components"]) == 4
        # Check model maps to machine-learning-model
        model_comp = next(c for c in cdx["components"] if c["name"] == "gpt-4o")
        assert model_comp["type"] == "machine-learning-model"
        assert model_comp["supplier"]["name"] == "openai"
        # Check MCP server maps to application
        mcp_comp = next(c for c in cdx["components"] if c["name"] == "filesystem")
        assert mcp_comp["type"] == "application"

    def test_to_spdx(self):
        spdx = self.doc.to_spdx()
        assert spdx["spdxVersion"] == "SPDX-2.3"
        assert spdx["dataLicense"] == "CC0-1.0"
        assert len(spdx["packages"]) == 4
        model_pkg = next(p for p in spdx["packages"] if p["name"] == "gpt-4o")
        assert model_pkg["primaryPackagePurpose"] == "APPLICATION"
        assert model_pkg["supplier"] == "Organization: openai"

    def test_vulnerability_summary(self):
        self.doc.vulnerabilities = [
            AIBOMVulnerability(
                component_id="abc", vulnerability_id="CVE-2024-001",
                severity="critical",
            ),
            AIBOMVulnerability(
                component_id="def", vulnerability_id="CVE-2024-002",
                severity="high",
            ),
            AIBOMVulnerability(
                component_id="ghi", vulnerability_id="CVE-2024-003",
                severity="critical",
            ),
        ]
        summary = self.doc.vulnerability_summary
        assert summary["critical"] == 2
        assert summary["high"] == 1

    def test_cyclonedx_with_vulnerabilities(self):
        comp = self.components[0]
        self.doc.vulnerabilities = [
            AIBOMVulnerability(
                component_id=comp.component_id,
                vulnerability_id="CVE-2024-9999",
                severity="high",
                description="Test vulnerability",
            ),
        ]
        cdx = self.doc.to_cyclonedx()
        assert len(cdx["vulnerabilities"]) == 1
        assert cdx["vulnerabilities"][0]["id"] == "CVE-2024-9999"

    def test_cyclonedx_with_dependencies(self):
        self.components[0].dependencies = [self.components[2].component_id]
        cdx = self.doc.to_cyclonedx()
        deps = cdx["dependencies"]
        assert len(deps) == 1
        assert deps[0]["ref"] == self.components[0].component_id

    def test_spdx_with_dependencies(self):
        self.components[0].dependencies = [self.components[2].component_id]
        spdx = self.doc.to_spdx()
        rels = spdx["relationships"]
        assert len(rels) == 1
        assert rels[0]["relationshipType"] == "DEPENDS_ON"


class TestAIBOMGenerator:
    def setup_method(self):
        self.gen = AIBOMGenerator(system_name="test-app", system_version="1.0")

    def test_add_component(self):
        comp = self.gen.add_component(
            component_type="model",
            name="gpt-4o",
            version="2024-08",
            provider="openai",
            license="proprietary",
        )
        assert comp.name == "gpt-4o"
        assert comp.provider == "openai"
        assert self.gen.component_count == 1

    def test_add_multiple_components(self):
        self.gen.add_component(component_type="model", name="gpt-4o", provider="openai")
        self.gen.add_component(component_type="model", name="claude-sonnet-4-20250514", provider="anthropic")
        self.gen.add_component(component_type="vector_db", name="pinecone")
        assert self.gen.component_count == 3

    def test_upsert_merges_info(self):
        self.gen.add_component(component_type="model", name="gpt-4o")
        self.gen.add_component(
            component_type="model", name="gpt-4o", provider="openai",
        )
        assert self.gen.component_count == 1
        comp = self.gen.components[0]
        assert comp.provider == "openai"
        assert comp.occurrence_count == 2

    def test_upsert_preserves_existing_info(self):
        self.gen.add_component(
            component_type="model", name="gpt-4o", provider="openai",
            license="proprietary",
        )
        self.gen.add_component(
            component_type="model", name="gpt-4o", hash="sha256:abc",
        )
        assert self.gen.component_count == 1
        comp = self.gen.components[0]
        assert comp.provider == "openai"  # Not overwritten
        assert comp.license == "proprietary"  # Not overwritten
        assert comp.hash == "sha256:abc"  # Filled in

    def test_add_vulnerability(self):
        self.gen.add_component(component_type="model", name="gpt-4o")
        vuln = self.gen.add_vulnerability(
            component_type="model",
            component_name="gpt-4o",
            vulnerability_id="CVE-2024-001",
            severity="high",
            description="Test vuln",
        )
        assert vuln is not None
        assert vuln.severity == "high"

    def test_add_vulnerability_missing_component(self):
        vuln = self.gen.add_vulnerability(
            component_type="model",
            component_name="nonexistent",
            vulnerability_id="CVE-2024-001",
            severity="high",
        )
        assert vuln is None

    def test_generate_bom(self):
        self.gen.add_component(component_type="model", name="gpt-4o", provider="openai")
        self.gen.add_component(component_type="vector_db", name="pinecone")

        bom = self.gen.generate(bom_id="test-123")
        assert bom.bom_id == "test-123"
        assert bom.component_count == 2
        assert bom.metadata["system_name"] == "test-app"
        assert bom.metadata["system_version"] == "1.0"

    def test_generate_auto_id(self):
        bom = self.gen.generate()
        assert bom.bom_id is not None
        assert len(bom.bom_id) > 0

    def test_get_component_summary(self):
        self.gen.add_component(component_type="model", name="gpt-4o")
        self.gen.add_component(component_type="model", name="claude-sonnet-4-20250514")
        self.gen.add_component(component_type="tool", name="web-search")

        summary = self.gen.get_component_summary()
        assert summary["total_components"] == 3
        assert summary["component_types"]["model"] == 2
        assert summary["component_types"]["tool"] == 1

    def test_reset(self):
        self.gen.add_component(component_type="model", name="gpt-4o")
        assert self.gen.component_count == 1
        self.gen.reset()
        assert self.gen.component_count == 0

    def test_generate_cyclonedx_format(self):
        self.gen.add_component(
            component_type="model", name="gpt-4o", provider="openai",
        )
        bom = self.gen.generate(output_format="cyclonedx")
        cdx = bom.to_cyclonedx()
        assert cdx["bomFormat"] == "CycloneDX"
        assert len(cdx["components"]) == 1

    def test_generate_spdx_format(self):
        self.gen.add_component(
            component_type="model", name="gpt-4o", provider="openai",
        )
        bom = self.gen.generate(output_format="spdx")
        spdx = bom.to_spdx()
        assert spdx["spdxVersion"] == "SPDX-2.3"
        assert len(spdx["packages"]) == 1

    def test_component_with_dependencies(self):
        self.gen.add_component(component_type="model", name="base-llm")
        self.gen.add_component(component_type="dataset", name="train-data")

        base = self.gen._find_component("model", "base-llm")
        ds = self.gen._find_component("dataset", "train-data")

        self.gen.add_component(
            component_type="model", name="fine-tuned-llm",
            dependencies=[base.component_id, ds.component_id],
            properties={"derived_from": "base-llm"},
        )

        bom = self.gen.generate()
        fine_tuned = next(
            c for c in bom.components if c.name == "fine-tuned-llm"
        )
        assert len(fine_tuned.dependencies) == 2


class TestAIBOMGeneratorSpanExtraction:
    """Test component extraction from mock span attributes."""

    def setup_method(self):
        self.gen = AIBOMGenerator(system_name="test-app")

    def test_extract_model_component(self):
        self.gen._extract_model_component({
            "gen_ai.request.model": "gpt-4o",
            "gen_ai.system": "openai",
            "gen_ai.request.temperature": 0.7,
        })
        assert self.gen.component_count == 1
        comp = self.gen.components[0]
        assert comp.type == "model"
        assert comp.name == "gpt-4o"
        assert comp.provider == "openai"
        assert comp.properties.get("temperature") == 0.7

    def test_extract_agent_component(self):
        self.gen._extract_agent_component({
            "aitf.agent.name": "research-agent",
            "aitf.agent.version": "2.0",
            "aitf.agent.type": "autonomous",
            "aitf.agent.framework": "langchain",
        })
        assert self.gen.component_count == 1
        comp = self.gen.components[0]
        assert comp.type == "agent"
        assert comp.name == "research-agent"
        assert comp.version == "2.0"
        assert comp.properties["framework"] == "langchain"

    def test_extract_mcp_server_component(self):
        self.gen._extract_mcp_component({
            "aitf.mcp.server.name": "filesystem",
            "aitf.mcp.server.version": "1.0.0",
            "aitf.mcp.server.transport": "stdio",
        })
        assert self.gen.component_count == 1
        comp = self.gen.components[0]
        assert comp.type == "mcp_server"
        assert comp.name == "filesystem"
        assert comp.properties["transport"] == "stdio"

    def test_extract_mcp_tool_component(self):
        self.gen._extract_mcp_component({
            "aitf.mcp.server.name": "filesystem",
            "aitf.mcp.tool.name": "read_file",
            "aitf.mcp.tool.server": "filesystem",
        })
        # Should create both server and tool
        assert self.gen.component_count == 2
        tool = self.gen._find_component("tool", "read_file")
        assert tool is not None
        assert tool.provider == "filesystem"

    def test_extract_rag_component(self):
        self.gen._extract_rag_component({
            "aitf.rag.retrieve.database": "pinecone",
            "aitf.rag.pipeline.name": "qa-pipeline",
        })
        assert self.gen.component_count == 1
        comp = self.gen.components[0]
        assert comp.type == "vector_db"
        assert comp.name == "pinecone"

    def test_extract_skill_component(self):
        self.gen._extract_skill_component({
            "aitf.skill.name": "web-search",
            "aitf.skill.version": "1.0",
            "aitf.skill.provider": "builtin",
            "aitf.skill.category": "search",
        })
        assert self.gen.component_count == 1
        comp = self.gen.components[0]
        assert comp.type == "plugin"
        assert comp.name == "web-search"

    def test_extract_training_components(self):
        self.gen._extract_training_component({
            "aitf.model_ops.training.base_model": "meta-llama/Llama-3.1-70B",
            "aitf.model_ops.training.type": "lora",
            "aitf.model_ops.training.dataset.id": "customer-support-v3",
            "aitf.model_ops.training.dataset.version": "3.0",
            "aitf.model_ops.training.output_model.id": "cs-llama-70b-lora",
            "aitf.model_ops.training.output_model.hash": "sha256:abc123",
        })
        # Should create base model, dataset, and output model
        assert self.gen.component_count == 3

        base = self.gen._find_component("model", "meta-llama/Llama-3.1-70B")
        assert base is not None
        assert base.properties["training_type"] == "lora"

        ds = self.gen._find_component("dataset", "customer-support-v3")
        assert ds is not None
        assert ds.version == "3.0"

        output = self.gen._find_component("model", "cs-llama-70b-lora")
        assert output is not None
        assert output.hash == "sha256:abc123"
        assert len(output.dependencies) == 2

    def test_extract_embedding_component(self):
        self.gen._extract_embedding_component({
            "aitf.rag.query.embedding_model": "text-embedding-3-small",
            "aitf.rag.query.embedding_dimensions": 1536,
        })
        assert self.gen.component_count == 1
        comp = self.gen.components[0]
        assert comp.type == "embedding_model"
        assert comp.name == "text-embedding-3-small"
        assert comp.properties["dimensions"] == 1536

    def test_extract_supply_chain_component(self):
        self.gen._extract_supply_chain_component({
            "aitf.supply_chain.model.source": "huggingface.co/meta-llama/Llama-3.1",
            "aitf.supply_chain.model.hash": "sha256:deadbeef",
            "aitf.supply_chain.model.license": "Llama 3.1 Community",
            "aitf.supply_chain.model.signed": True,
            "aitf.supply_chain.model.signer": "Meta",
        })
        assert self.gen.component_count == 1
        comp = self.gen.components[0]
        assert comp.hash == "sha256:deadbeef"
        assert comp.license == "Llama 3.1 Community"
        assert comp.properties["signed"] is True

    def test_empty_attrs_skip(self):
        """Extractors should skip when key attributes are empty."""
        self.gen._extract_model_component({"gen_ai.request.model": ""})
        self.gen._extract_agent_component({"aitf.agent.name": ""})
        self.gen._extract_rag_component({"aitf.rag.retrieve.database": ""})
        assert self.gen.component_count == 0

    def test_duplicate_model_across_spans(self):
        """Same model seen across multiple spans should be merged."""
        for _ in range(5):
            self.gen._extract_model_component({
                "gen_ai.request.model": "gpt-4o",
                "gen_ai.system": "openai",
            })
        assert self.gen.component_count == 1
        comp = self.gen.components[0]
        assert comp.occurrence_count == 5


class TestAIBOMAttributes:
    def test_attribute_constants(self):
        assert AIBOMAttributes.BOM_ID == "aitf.ai_bom.id"
        assert AIBOMAttributes.BOM_VERSION == "aitf.ai_bom.version"
        assert AIBOMAttributes.COMPONENT_TYPE == "aitf.ai_bom.component.type"
        assert AIBOMAttributes.VULNERABILITY_COUNT == "aitf.ai_bom.vulnerability.count"

    def test_component_types(self):
        assert AIBOMAttributes.ComponentType.MODEL == "model"
        assert AIBOMAttributes.ComponentType.DATASET == "dataset"
        assert AIBOMAttributes.ComponentType.MCP_SERVER == "mcp_server"
        assert AIBOMAttributes.ComponentType.AGENT == "agent"

    def test_format_values(self):
        assert AIBOMAttributes.Format.AITF == "aitf"
        assert AIBOMAttributes.Format.CYCLONEDX == "cyclonedx"
        assert AIBOMAttributes.Format.SPDX == "spdx"
