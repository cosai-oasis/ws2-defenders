"""Tests for AITF OCSF schema, event classes, and mapper."""

from unittest.mock import MagicMock

from aitf.ocsf.schema import (
    AIBaseEvent,
    AIClassUID,
    AIModelInfo,
    AITokenUsage,
    AILatencyMetrics,
    AICostInfo,
    AISecurityFinding,
    ComplianceMetadata,
    OCSFMetadata,
    OCSFSeverity,
    OCSFStatus,
)
from aitf.ocsf.event_classes import (
    AIModelInferenceEvent,
    AIAgentActivityEvent,
    AIToolExecutionEvent,
    AIDataRetrievalEvent,
    AISecurityFindingEvent,
    AISupplyChainEvent,
    AIGovernanceEvent,
    AIIdentityEvent,
    AIModelOpsEvent,
    AIAssetInventoryEvent,
)
from aitf.ocsf.mapper import OCSFMapper
from aitf.ocsf.compliance_mapper import ComplianceMapper
from aitf.semantic_conventions.attributes import (
    ComplianceAttributes,
    DriftDetectionAttributes,
    GenAIAttributes,
    IdentityAttributes,
    ModelOpsAttributes,
    AssetInventoryAttributes,
    SupplyChainAttributes,
    AgentAttributes,
    MCPAttributes,
    RAGAttributes,
    SecurityAttributes,
)


class TestOCSFSchema:
    def test_class_uids(self):
        # AITF reuses existing OCSF classes (OCSF PR #1641 / issue #1640).
        assert AIClassUID.API_ACTIVITY == 6003
        assert AIClassUID.DATASTORE_ACTIVITY == 6005
        assert AIClassUID.APPLICATION_LIFECYCLE == 6002
        assert AIClassUID.DETECTION_FINDING == 2004
        assert AIClassUID.VULNERABILITY_FINDING == 2002
        assert AIClassUID.COMPLIANCE_FINDING == 2003
        assert AIClassUID.AUTHENTICATION == 3002
        assert AIClassUID.INVENTORY_INFO == 5001
        # New control-plane classes in the proposed ai category (uid 9).
        assert AIClassUID.AGENT_ACTIVITY == 9001
        assert AIClassUID.DELEGATION_ACTIVITY == 9002

    def test_token_usage_total(self):
        usage = AITokenUsage(input_tokens=100, output_tokens=50)
        assert usage.total_tokens == 150

    def test_metadata_defaults(self):
        meta = OCSFMetadata()
        assert meta.version == "1.1.0"
        assert meta.product["name"] == "AITF"
        assert meta.uid is not None

    def test_base_event_type_uid(self):
        event = AIBaseEvent(class_uid=6003, activity_id=1, category_uid=6)
        assert event.type_uid == 600301
        assert event.category_uid == 6


class TestEventClasses:
    def test_model_inference_event(self):
        event = AIModelInferenceEvent(
            activity_id=1,
            model=AIModelInfo(model_id="gpt-4o", provider="openai"),
            token_usage=AITokenUsage(input_tokens=100, output_tokens=50),
            finish_reason="stop",
        )
        assert event.class_uid == 6003  # OCSF API Activity
        assert event.type_uid == 600301
        assert event.model.model_id == "gpt-4o"
        assert event.token_usage.total_tokens == 150

    def test_agent_activity_event(self):
        event = AIAgentActivityEvent(
            activity_id=3,
            agent_name="research-agent",
            agent_id="agent-001",
            session_id="sess-001",
            step_type="planning",
            step_index=1,
        )
        assert event.class_uid == 9001  # OCSF ai category agent_activity
        assert event.category_uid == 9
        assert event.agent_name == "research-agent"

    def test_tool_execution_event(self):
        event = AIToolExecutionEvent(
            activity_id=2,
            tool_name="read_file",
            tool_type="mcp_tool",
            mcp_server="filesystem",
            is_error=False,
        )
        assert event.class_uid == 6003  # OCSF API Activity
        assert event.tool_type == "mcp_tool"

    def test_data_retrieval_event(self):
        event = AIDataRetrievalEvent(
            activity_id=1,
            database_name="pinecone",
            database_type="pinecone",
            top_k=10,
            results_count=8,
        )
        assert event.class_uid == 6005  # OCSF Datastore Activity
        assert event.results_count == 8

    def test_event_serialization(self):
        event = AIModelInferenceEvent(
            model=AIModelInfo(model_id="gpt-4o", provider="openai"),
            finish_reason="stop",
        )
        data = event.model_dump(exclude_none=True)
        assert data["class_uid"] == 6003
        assert data["category_uid"] == 6
        assert data["model"]["model_id"] == "gpt-4o"

    def test_supply_chain_event(self):
        event = AISupplyChainEvent(
            activity_id=1,
            model_source="huggingface",
            model_hash="sha256:abc123",
            model_signed=True,
            model_signer="meta",
        )
        assert event.class_uid == 2002  # OCSF Vulnerability Finding
        assert event.model_source == "huggingface"
        assert event.model_signed is True

    def test_governance_event(self):
        event = AIGovernanceEvent(
            activity_id=1,
            frameworks=["eu_ai_act", "nist_ai_rmf"],
            event_type="audit",
        )
        assert event.class_uid == 2003  # OCSF Compliance Finding
        assert len(event.frameworks) == 2

    def test_identity_event(self):
        event = AIIdentityEvent(
            activity_id=1,
            agent_name="orchestrator",
            agent_id="agent-001",
            auth_method="mtls",
            auth_result="success",
        )
        assert event.class_uid == 3002  # OCSF Authentication (IAM)
        assert event.auth_method == "mtls"

    def test_model_ops_event(self):
        event = AIModelOpsEvent(
            activity_id=1,
            operation_type="training",
            model_id="llama-70b",
            training_type="fine_tuning",
            epochs=10,
            loss_final=0.42,
        )
        assert event.class_uid == 6002  # OCSF Application Lifecycle
        assert event.operation_type == "training"
        assert event.loss_final == 0.42

    def test_asset_inventory_event(self):
        event = AIAssetInventoryEvent(
            activity_id=2,
            operation_type="discover",
            discovery_scope="organization",
            assets_found=15,
            shadow_assets=3,
        )
        assert event.class_uid == 5001  # OCSF Inventory Info (Discovery)
        assert event.operation_type == "discover"
        assert event.shadow_assets == 3


def _make_mock_span(name: str, attributes: dict) -> MagicMock:
    """Create a mock ReadableSpan for testing the mapper."""
    span = MagicMock()
    span.name = name
    span.attributes = attributes
    span.start_time = 1700000000_000000000  # nanoseconds
    return span


class TestOCSFMapper:
    """Tests for the OCSFMapper covering all 10 event classes."""

    def setup_method(self):
        self.mapper = OCSFMapper()

    def test_map_inference_span(self):
        span = _make_mock_span("chat gpt-4o", {
            GenAIAttributes.SYSTEM: "openai",
            GenAIAttributes.REQUEST_MODEL: "gpt-4o",
            GenAIAttributes.OPERATION_NAME: "chat",
            GenAIAttributes.USAGE_INPUT_TOKENS: 100,
            GenAIAttributes.USAGE_OUTPUT_TOKENS: 50,
            GenAIAttributes.RESPONSE_FINISH_REASONS: ["stop"],
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 6003
        assert event.activity_id == 1

    def test_map_agent_span(self):
        span = _make_mock_span("agent.session orchestrator", {
            GenAIAttributes.AGENT_NAME: "orchestrator",
            GenAIAttributes.AGENT_ID: "agent-001",
            GenAIAttributes.CONVERSATION_ID: "sess-001",
            AgentAttributes.FRAMEWORK: "crewai",
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 9001
        # OCSF ai_operation profile (PR #1641) is attached by the crosswalk.
        assert event.ai_agent is not None
        assert event.ai_agent.uid == "agent-001"
        assert event.ai_agent.type_id == 4  # CrewAI
        assert event.ai_agent.type == "CrewAI"

    def test_map_tool_span(self):
        span = _make_mock_span("mcp.tool.invoke read_file", {
            GenAIAttributes.TOOL_NAME: "read_file",
            MCPAttributes.TOOL_SERVER: "filesystem",
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 6003

    def test_map_rag_span(self):
        span = _make_mock_span("rag.retrieve pinecone", {
            GenAIAttributes.DATA_SOURCE_ID: "pinecone",
            RAGAttributes.PIPELINE_STAGE: "retrieve",
            RAGAttributes.RETRIEVE_RESULTS_COUNT: 5,
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 6005

    def test_map_security_span(self):
        span = _make_mock_span("security.prompt_injection", {
            SecurityAttributes.THREAT_DETECTED: True,
            SecurityAttributes.THREAT_TYPE: "prompt_injection",
            SecurityAttributes.RISK_LEVEL: "high",
            SecurityAttributes.RISK_SCORE: 85.0,
            SecurityAttributes.CONFIDENCE: 0.9,
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 2004

    def test_map_supply_chain_span(self):
        span = _make_mock_span("supply_chain.verify llama-70b", {
            SupplyChainAttributes.MODEL_SOURCE: "huggingface",
            SupplyChainAttributes.MODEL_HASH: "sha256:abc",
            SupplyChainAttributes.MODEL_SIGNED: True,
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 2002
        assert event.model_source == "huggingface"
        assert event.activity_id == 1  # verify

    def test_map_governance_span(self):
        span = _make_mock_span("governance.audit eu-ai-act", {
            ComplianceAttributes.FRAMEWORKS: ["eu_ai_act", "nist_ai_rmf"],
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 2003
        assert event.activity_id == 1  # audit
        assert len(event.frameworks) == 2

    def test_map_identity_span(self):
        span = _make_mock_span("identity.auth orchestrator", {
            IdentityAttributes.AGENT_ID: "agent-001",
            IdentityAttributes.AGENT_NAME: "orchestrator",
            IdentityAttributes.AUTH_METHOD: "mtls",
            IdentityAttributes.AUTH_RESULT: "success",
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 3002  # OCSF Authentication (IAM)
        assert event.auth_method == "mtls"
        assert event.activity_id == 1  # authenticate

    def test_map_model_ops_training_span(self):
        span = _make_mock_span("model_ops.training run-001", {
            ModelOpsAttributes.TRAINING_RUN_ID: "run-001",
            ModelOpsAttributes.TRAINING_TYPE: "fine_tuning",
            ModelOpsAttributes.TRAINING_BASE_MODEL: "llama-70b",
            ModelOpsAttributes.TRAINING_EPOCHS: 10,
            ModelOpsAttributes.TRAINING_LOSS_FINAL: 0.42,
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 6002
        assert event.operation_type == "training"
        assert event.training_type == "fine_tuning"
        assert event.loss_final == 0.42

    def test_map_model_ops_deployment_span(self):
        span = _make_mock_span("model_ops.deployment deploy-001", {
            ModelOpsAttributes.DEPLOYMENT_ID: "deploy-001",
            ModelOpsAttributes.DEPLOYMENT_MODEL_ID: "llama-70b-v2",
            ModelOpsAttributes.DEPLOYMENT_STRATEGY: "canary",
            ModelOpsAttributes.DEPLOYMENT_ENVIRONMENT: "production",
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 6002
        assert event.operation_type == "deployment"
        assert event.strategy == "canary"

    def test_map_drift_detection_span(self):
        span = _make_mock_span("drift.detect data_distribution model-001", {
            DriftDetectionAttributes.MODEL_ID: "model-001",
            DriftDetectionAttributes.TYPE: "data_distribution",
            DriftDetectionAttributes.SCORE: 0.85,
            DriftDetectionAttributes.ACTION_TRIGGERED: "retrain",
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 6002  # Drift maps to ModelOps
        assert event.operation_type == "monitoring"
        assert event.drift_score == 0.85

    def test_map_asset_register_span(self):
        span = _make_mock_span("asset.register model customer-llm", {
            AssetInventoryAttributes.ID: "asset-001",
            AssetInventoryAttributes.NAME: "customer-llm",
            AssetInventoryAttributes.TYPE: "model",
            AssetInventoryAttributes.OWNER: "ml-team",
            AssetInventoryAttributes.RISK_CLASSIFICATION: "high_risk",
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 5001
        assert event.operation_type == "register"
        assert event.risk_classification == "high_risk"

    def test_map_asset_discover_span(self):
        span = _make_mock_span("asset.discover organization", {
            AssetInventoryAttributes.DISCOVERY_SCOPE: "organization",
            AssetInventoryAttributes.DISCOVERY_ASSETS_FOUND: 42,
            AssetInventoryAttributes.DISCOVERY_SHADOW_ASSETS: 5,
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 5001
        assert event.operation_type == "discover"
        assert event.assets_found == 42
        assert event.shadow_assets == 5

    def test_map_unrelated_span_returns_none(self):
        span = _make_mock_span("http.request GET /api/users", {
            "http.method": "GET",
            "http.url": "/api/users",
        })
        event = self.mapper.map_span(span)
        assert event is None

    def test_all_event_types_map_to_reused_ocsf_classes(self):
        """Every AITF span type maps onto its reused OCSF class (PR #1641 / #1640)."""
        test_spans = [
            ("chat gpt-4o", {GenAIAttributes.SYSTEM: "openai", GenAIAttributes.REQUEST_MODEL: "gpt-4o", GenAIAttributes.RESPONSE_FINISH_REASONS: ["stop"]}),
            ("agent.step research", {GenAIAttributes.AGENT_NAME: "r", GenAIAttributes.AGENT_ID: "1", GenAIAttributes.CONVERSATION_ID: "s1"}),
            ("mcp.tool.invoke read", {GenAIAttributes.TOOL_NAME: "read"}),
            ("rag.retrieve db", {GenAIAttributes.DATA_SOURCE_ID: "db", RAGAttributes.RETRIEVE_RESULTS_COUNT: 1}),
            ("security.threat", {SecurityAttributes.THREAT_DETECTED: True, SecurityAttributes.RISK_LEVEL: "high", SecurityAttributes.RISK_SCORE: 90, SecurityAttributes.CONFIDENCE: 0.9}),
            ("supply_chain.verify m", {SupplyChainAttributes.MODEL_SOURCE: "hf"}),
            ("governance.audit x", {ComplianceAttributes.FRAMEWORKS: ["eu_ai_act"]}),
            ("identity.auth a", {IdentityAttributes.AGENT_ID: "1", IdentityAttributes.AGENT_NAME: "a"}),
            ("model_ops.training r", {ModelOpsAttributes.TRAINING_RUN_ID: "r1"}),
            ("asset.register model m", {AssetInventoryAttributes.ID: "a1"}),
        ]
        class_uids = set()
        for name, attrs in test_spans:
            span = _make_mock_span(name, attrs)
            event = self.mapper.map_span(span)
            assert event is not None, f"Span '{name}' was not mapped"
            class_uids.add(event.class_uid)

        # Inference and tool execution both reuse API Activity (6003), so the
        # 10 span types collapse to 9 distinct OCSF classes.
        expected = {6003, 9001, 6005, 2004, 2002, 2003, 3002, 6002, 5001}
        assert class_uids == expected, f"Missing class UIDs: {expected - class_uids}"


class TestOCSFCrosswalk:
    """Tests for the AITF <-> OCSF agentic crosswalk (PR #1641 / issue #1640)."""

    def setup_method(self):
        self.mapper = OCSFMapper()

    def test_normalize_agent_type_id(self):
        from aitf.ocsf import normalize_agent_type_id

        assert normalize_agent_type_id("native") == 1
        assert normalize_agent_type_id("langchain") == 2
        assert normalize_agent_type_id("langgraph") == 2
        assert normalize_agent_type_id("autogen") == 3
        assert normalize_agent_type_id("crewai") == 4
        assert normalize_agent_type_id("semantic_kernel") == 99  # OTHER
        assert normalize_agent_type_id(None) == 0  # UNKNOWN

    def test_build_ai_agent_object(self):
        from aitf.ocsf import build_ai_agent

        agent = build_ai_agent({
            GenAIAttributes.AGENT_ID: "agt-1",
            GenAIAttributes.AGENT_NAME: "planner",
            GenAIAttributes.AGENT_VERSION: "1.2.0",
            GenAIAttributes.REQUEST_MODEL: "gpt-4o",
            AgentAttributes.FRAMEWORK: "langchain",
        })
        assert agent is not None
        assert agent.uid == "agt-1"
        assert agent.name == "planner"
        assert agent.type_id == 2
        assert agent.type == "LangChain"
        assert agent.ai_model == "gpt-4o"
        assert agent.version == "1.2.0"

    def test_build_ai_agent_none_when_no_identity(self):
        from aitf.ocsf import build_ai_agent

        assert build_ai_agent({"http.method": "GET"}) is None

    def test_build_delegation_object(self):
        from aitf.ocsf import build_delegation

        deleg = build_delegation({
            IdentityAttributes.DELEGATION_DELEGATEE_ID: "agt-2",
            IdentityAttributes.DELEGATION_DELEGATOR_ID: "agt-1",
            IdentityAttributes.DELEGATION_TYPE: "on_behalf_of",
            IdentityAttributes.DELEGATION_SCOPE_DELEGATED: ["read", "write"],
            IdentityAttributes.DELEGATION_TTL_SECONDS: 3600,
        })
        assert deleg is not None
        assert deleg.uid == "agt-2"          # OCSF delegation.uid
        assert deleg.parent_uid == "agt-1"   # OCSF delegation.parent_uid
        assert deleg.type == "on_behalf_of"
        assert deleg.scope == ["read", "write"]
        assert deleg.ttl_seconds == 3600

    def test_build_delegation_lineage_graph(self):
        from aitf.ocsf import build_delegation_lineage

        lineage = build_delegation_lineage({
            IdentityAttributes.DELEGATION_CHAIN: ["root", "agt-1", "agt-2"],
        })
        assert lineage is not None
        assert len(lineage.nodes) == 3
        assert lineage.nodes[0].parent_uid is None
        assert lineage.nodes[0].depth == 0
        assert lineage.nodes[2].parent_uid == "agt-1"
        assert lineage.nodes[2].depth == 2

    def test_identity_span_carries_delegation(self):
        span = _make_mock_span("identity.delegate orchestrator", {
            IdentityAttributes.AGENT_ID: "agt-1",
            IdentityAttributes.AGENT_NAME: "orchestrator",
            IdentityAttributes.AUTH_METHOD: "mtls",
            IdentityAttributes.AUTH_RESULT: "success",
            IdentityAttributes.DELEGATION_DELEGATEE_ID: "agt-2",
            IdentityAttributes.DELEGATION_DELEGATOR_ID: "agt-1",
            IdentityAttributes.DELEGATION_TYPE: "token_exchange",
        })
        event = self.mapper.map_span(span)
        assert event is not None
        assert event.class_uid == 3002
        assert event.delegation is not None
        assert event.delegation.uid == "agt-2"
        assert event.delegation.type == "token_exchange"

    def test_control_plane_crosswalk_tables(self):
        from aitf.ocsf import (
            OCSF_AGENT_ACTIVITY_CROSSWALK,
            OCSF_CLASS_CROSSWALK,
            OCSF_DELEGATION_ACTIVITY_CROSSWALK,
        )

        # Agent Session Start -> OCSF agent_activity Spawn (issue #1640)
        assert OCSF_AGENT_ACTIVITY_CROSSWALK[1] == "Spawn"
        assert OCSF_AGENT_ACTIVITY_CROSSWALK[2] == "Terminate"
        # Delegation lifecycle -> OCSF delegation_activity
        assert OCSF_DELEGATION_ACTIVITY_CROSSWALK["revoke"] == "Revoke"
        # Data-plane AI activity reuses existing OCSF classes...
        assert OCSF_CLASS_CROSSWALK["model_inference"]["ocsf_class_uid"] == 6003
        assert OCSF_CLASS_CROSSWALK["security_finding"]["ocsf_class_uid"] == 2004
        assert OCSF_CLASS_CROSSWALK["identity"]["ocsf_class_uid"] == 3002
        # ...while agent/delegation lifecycle use the proposed ai category (9).
        assert OCSF_CLASS_CROSSWALK["agent_activity"]["ocsf_category_uid"] == 9
        assert OCSF_CLASS_CROSSWALK["agent_activity"]["ocsf_class"] == "agent_activity"
        assert OCSF_CLASS_CROSSWALK["delegation_activity"]["ocsf_class"] == "delegation_activity"


class TestComplianceMapper:
    def setup_method(self):
        self.mapper = ComplianceMapper()

    def test_map_model_inference(self):
        compliance = self.mapper.map_event("model_inference")
        assert compliance.nist_ai_rmf is not None
        assert compliance.eu_ai_act is not None
        assert compliance.mitre_atlas is not None
        assert compliance.csa_aicm is not None

    def test_map_security_finding(self):
        compliance = self.mapper.map_event("security_finding")
        assert compliance.nist_ai_rmf is not None
        assert "MANAGE-2.4" in compliance.nist_ai_rmf["controls"]

    def test_map_csa_aicm(self):
        compliance = self.mapper.map_event("model_inference")
        assert compliance.csa_aicm is not None
        assert "MDS-01" in compliance.csa_aicm["controls"]
        assert "AIS-04" in compliance.csa_aicm["controls"]
        assert "AIS-08" in compliance.csa_aicm["controls"]
        assert "LOG-14" in compliance.csa_aicm["controls"]
        assert "GRC-13" in compliance.csa_aicm["controls"]
        assert "TVM-11" in compliance.csa_aicm["controls"]
        assert compliance.csa_aicm["domain"] == "Model Security"
        assert len(compliance.csa_aicm["controls"]) == 32

    def test_map_csa_aicm_all_event_types(self):
        event_types = [
            "model_inference", "agent_activity", "tool_execution",
            "data_retrieval", "security_finding", "supply_chain",
            "governance", "identity",
        ]
        for event_type in event_types:
            compliance = self.mapper.map_event(event_type)
            assert compliance.csa_aicm is not None, f"CSA AICM missing for {event_type}"
            assert "controls" in compliance.csa_aicm, f"controls missing for {event_type}"
            assert "domain" in compliance.csa_aicm, f"domain missing for {event_type}"
            assert len(compliance.csa_aicm["controls"]) >= 12, (
                f"Expected >= 12 AICM controls for {event_type}, "
                f"got {len(compliance.csa_aicm['controls'])}"
            )

    def test_map_csa_aicm_comprehensive_coverage(self):
        """Verify comprehensive AICM coverage across all event types."""
        all_controls = set()
        event_types = [
            "model_inference", "agent_activity", "tool_execution",
            "data_retrieval", "security_finding", "supply_chain",
            "governance", "identity",
        ]
        for event_type in event_types:
            compliance = self.mapper.map_event(event_type)
            all_controls.update(compliance.csa_aicm["controls"])

        # Verify coverage of all 18 AICM domains
        domains_covered = set()
        for ctrl in all_controls:
            prefix = ctrl.split("-")[0]
            domains_covered.add(prefix)

        expected_domains = {
            "MDS", "AIS", "LOG", "GRC", "TVM", "DSP", "IAM", "CEK",
            "SEF", "STA", "CCC", "DCS", "IPY", "BCR", "HRS", "A&A",
            "UEM", "I&S",
        }
        assert expected_domains.issubset(domains_covered), (
            f"Missing domains: {expected_domains - domains_covered}"
        )
        # Should cover all 243 AICM controls across all event types
        assert len(all_controls) >= 230, (
            f"Expected >= 230 unique AICM controls, got {len(all_controls)}"
        )

    def test_coverage_matrix(self):
        matrix = self.mapper.get_coverage_matrix()
        assert len(matrix) == 8  # All 8 event types
        assert "model_inference" in matrix
        assert "nist_ai_rmf" in matrix["model_inference"]
        assert "csa_aicm" in matrix["model_inference"]

    def test_audit_record(self):
        record = self.mapper.generate_audit_record(
            event_type="model_inference",
            actor="analyst@example.com",
            model="gpt-4o",
        )
        assert record["event_type"] == "model_inference"
        assert record["frameworks_mapped"] > 0
        assert record["audit_id"].startswith("aud-")

    def test_filtered_frameworks(self):
        mapper = ComplianceMapper(frameworks=["eu_ai_act"])
        compliance = mapper.map_event("model_inference")
        assert compliance.eu_ai_act is not None
        assert compliance.nist_ai_rmf is None
        assert compliance.csa_aicm is None

    def test_filtered_csa_aicm_only(self):
        mapper = ComplianceMapper(frameworks=["csa_aicm"])
        compliance = mapper.map_event("model_inference")
        assert compliance.csa_aicm is not None
        assert compliance.nist_ai_rmf is None
        assert "MDS-01" in compliance.csa_aicm["controls"]
        assert "AIS-04" in compliance.csa_aicm["controls"]

    def test_enrich_event(self):
        event = AIModelInferenceEvent(
            model=AIModelInfo(model_id="gpt-4o", provider="openai"),
            finish_reason="stop",
        )
        enriched = self.mapper.enrich_event(event, "model_inference")
        assert enriched.compliance is not None
        assert enriched.compliance.nist_ai_rmf is not None
