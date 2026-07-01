"""Tests for unified A2A / ACP / ANP agent-communication -> OCSF mapping."""

from unittest.mock import MagicMock

from aitf.ocsf import (
    AgentProtocolID,
    build_agent_message,
    canonical_comm_status,
    normalize_agent_protocol_id,
)
from aitf.ocsf.mapper import OCSFMapper
from aitf.semantic_conventions.attributes import (
    A2AAttributes,
    ACPAttributes,
    ANPAttributes,
    AgentCommAttributes,
)


def _span(name, attrs):
    s = MagicMock()
    s.name = name
    s.attributes = attrs
    s.start_time = 1700000000_000000000
    return s


class TestProtocolNormalization:
    def test_protocol_id(self):
        assert normalize_agent_protocol_id("a2a") == AgentProtocolID.A2A
        assert normalize_agent_protocol_id("ACP") == AgentProtocolID.ACP
        assert normalize_agent_protocol_id("anp") == AgentProtocolID.ANP
        assert normalize_agent_protocol_id("mcp") == AgentProtocolID.MCP
        assert normalize_agent_protocol_id("something") == AgentProtocolID.OTHER
        assert normalize_agent_protocol_id(None) == AgentProtocolID.UNKNOWN

    def test_canonical_status(self):
        assert canonical_comm_status(AgentProtocolID.A2A, "input-required") == "input_required"
        assert canonical_comm_status(AgentProtocolID.A2A, "rejected") == "failed"
        assert canonical_comm_status(AgentProtocolID.ACP, "in-progress") == "working"
        assert canonical_comm_status(AgentProtocolID.ACP, "cancelled") == "canceled"


class TestBuildAgentMessage:
    def test_a2a(self):
        msg = build_agent_message({
            A2AAttributes.PROTOCOL_VERSION: "0.2",
            A2AAttributes.TRANSPORT: "jsonrpc",
            A2AAttributes.METHOD: "message/send",
            A2AAttributes.TASK_ID: "task_1",
            A2AAttributes.TASK_STATE: "working",
            A2AAttributes.MESSAGE_PARTS_COUNT: 2,
            A2AAttributes.INTERACTION_MODE: "stream",
            A2AAttributes.AGENT_NAME: "planner",
            A2AAttributes.AGENT_URL: "https://p.example/a2a",
        })
        assert msg is not None
        assert msg.protocol_id == AgentProtocolID.A2A
        assert msg.unit_type == "task" and msg.unit_uid == "task_1"
        assert msg.status == "working"
        assert msg.direction == "stream"
        assert msg.transport == "jsonrpc"
        assert msg.dst_agent.name == "planner"
        assert msg.peer_endpoint == "https://p.example/a2a"

    def test_acp(self):
        msg = build_agent_message({
            ACPAttributes.RUN_ID: "run_9",
            ACPAttributes.RUN_STATUS: "in-progress",
            ACPAttributes.RUN_MODE: "async",
            ACPAttributes.OPERATION: "runs.create",
            ACPAttributes.HTTP_URL: "https://acp.example/runs",
        })
        assert msg.protocol_id == AgentProtocolID.ACP
        assert msg.unit_type == "run" and msg.unit_uid == "run_9"
        assert msg.status == "working"        # in-progress -> working
        assert msg.transport == "http"
        assert msg.endpoint == "https://acp.example/runs"

    def test_anp(self):
        msg = build_agent_message({
            ANPAttributes.PROTOCOL_VERSION: "1.0",
            ANPAttributes.TRANSPORT: "ws",
            ANPAttributes.PEER_DID: "did:wba:peer",
            ANPAttributes.META_PROTOCOL_NAME: "negotiate",
            ANPAttributes.MESSAGE_ID: "m1",
            ANPAttributes.CROSS_DOMAIN: True,
        })
        assert msg.protocol_id == AgentProtocolID.ANP
        assert msg.peer_did == "did:wba:peer"
        assert msg.operation == "negotiate"
        assert msg.cross_domain is True

    def test_canonical_overrides(self):
        msg = build_agent_message({
            AgentCommAttributes.PROTOCOL: "custom",
            AgentCommAttributes.UNIT_ID: "u1",
            AgentCommAttributes.STATUS: "completed",
            AgentCommAttributes.PEER_AGENT_NAME: "peer-x",
        })
        assert msg.protocol_id == AgentProtocolID.OTHER
        assert msg.status == "completed"
        assert msg.dst_agent.name == "peer-x"

    def test_none_when_no_comm(self):
        assert build_agent_message({"http.method": "GET"}) is None


class TestMapperAgentComm:
    def setup_method(self):
        self.mapper = OCSFMapper()

    def test_all_protocols_map_to_one_class(self):
        for name, attrs in [
            ("a2a.message.send", {A2AAttributes.TASK_ID: "t1", A2AAttributes.TASK_STATE: "working"}),
            ("acp.run.create", {ACPAttributes.RUN_ID: "r1", ACPAttributes.RUN_STATUS: "completed"}),
            ("anp.message", {ANPAttributes.MESSAGE_ID: "m1"}),
        ]:
            event = self.mapper.map_span(_span(name, attrs))
            assert event is not None, name
            assert event.category_uid == 9
            assert event.class_uid == 9003  # one generic agent_communication class

    def test_failure_status(self):
        event = self.mapper.map_span(_span("a2a.message.send", {
            A2AAttributes.TASK_ID: "t1",
            A2AAttributes.TASK_STATE: "failed",
            A2AAttributes.JSONRPC_ERROR_CODE: "-32000",
        }))
        assert event.status_id == 2  # Failure
        assert event.agent_message.error_code == "-32000"
