"""Tests for AITF Agentic Log instrumentation (Table 10.1 minimal fields)."""

import json
from typing import Sequence

from opentelemetry.sdk.trace import TracerProvider, ReadableSpan
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.trace import StatusCode

from aitf.instrumentation.agentic_log import AgenticLogInstrumentor
from aitf.semantic_conventions.attributes import AgenticLogAttributes


class _InMemoryExporter(SpanExporter):
    """Simple in-memory span exporter for tests."""

    def __init__(self):
        self._spans: list[ReadableSpan] = []

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self._spans.extend(spans)
        return SpanExportResult.SUCCESS

    def get_finished_spans(self) -> list[ReadableSpan]:
        return list(self._spans)

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


def _make_instrumentor():
    exporter = _InMemoryExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    instrumentor = AgenticLogInstrumentor(tracer_provider=provider)
    return instrumentor, exporter


class TestAgenticLogAttributes:
    """Test that all Table 10.1 attribute constants are properly defined."""

    def test_event_id_attribute(self):
        assert AgenticLogAttributes.EVENT_ID == "aitf.agentic_log.event_id"

    def test_timestamp_attribute(self):
        assert AgenticLogAttributes.TIMESTAMP == "aitf.agentic_log.timestamp"

    def test_agent_id_attribute(self):
        assert AgenticLogAttributes.AGENT_ID == "aitf.agentic_log.agent_id"

    def test_session_id_attribute(self):
        assert AgenticLogAttributes.SESSION_ID == "aitf.agentic_log.session_id"

    def test_goal_id_attribute(self):
        assert AgenticLogAttributes.GOAL_ID == "aitf.agentic_log.goal_id"

    def test_sub_task_id_attribute(self):
        assert AgenticLogAttributes.SUB_TASK_ID == "aitf.agentic_log.sub_task_id"

    def test_tool_used_attribute(self):
        assert AgenticLogAttributes.TOOL_USED == "aitf.agentic_log.tool_used"

    def test_tool_parameters_attribute(self):
        assert AgenticLogAttributes.TOOL_PARAMETERS == "aitf.agentic_log.tool_parameters"

    def test_outcome_attribute(self):
        assert AgenticLogAttributes.OUTCOME == "aitf.agentic_log.outcome"

    def test_confidence_score_attribute(self):
        assert AgenticLogAttributes.CONFIDENCE_SCORE == "aitf.agentic_log.confidence_score"

    def test_anomaly_score_attribute(self):
        assert AgenticLogAttributes.ANOMALY_SCORE == "aitf.agentic_log.anomaly_score"

    def test_policy_evaluation_attribute(self):
        assert AgenticLogAttributes.POLICY_EVALUATION == "aitf.agentic_log.policy_evaluation"

    def test_outcome_values(self):
        assert AgenticLogAttributes.Outcome.SUCCESS == "SUCCESS"
        assert AgenticLogAttributes.Outcome.FAILURE == "FAILURE"
        assert AgenticLogAttributes.Outcome.ERROR == "ERROR"
        assert AgenticLogAttributes.Outcome.DENIED == "DENIED"
        assert AgenticLogAttributes.Outcome.TIMEOUT == "TIMEOUT"
        assert AgenticLogAttributes.Outcome.PARTIAL == "PARTIAL"

    def test_policy_result_values(self):
        assert AgenticLogAttributes.PolicyResult.PASS == "PASS"
        assert AgenticLogAttributes.PolicyResult.FAIL == "FAIL"
        assert AgenticLogAttributes.PolicyResult.WARN == "WARN"
        assert AgenticLogAttributes.PolicyResult.SKIP == "SKIP"

    def test_all_attributes_in_aitf_namespace(self):
        for attr_name in [
            "EVENT_ID", "TIMESTAMP", "AGENT_ID", "SESSION_ID",
            "GOAL_ID", "SUB_TASK_ID", "TOOL_USED", "TOOL_PARAMETERS",
            "OUTCOME", "CONFIDENCE_SCORE", "ANOMALY_SCORE",
            "POLICY_EVALUATION",
        ]:
            value = getattr(AgenticLogAttributes, attr_name)
            assert value.startswith("aitf.agentic_log."), (
                f"{attr_name} = {value!r} does not start with 'aitf.agentic_log.'"
            )


class TestAgenticLogInstrumentor:
    """Test the AgenticLogInstrumentor log_action context manager."""

    def test_basic_log_action(self):
        instrumentor, exporter = _make_instrumentor()
        with instrumentor.log_action(
            agent_id="agent-test-001",
            session_id="sess-abc123",
        ) as entry:
            entry.set_goal_id("goal-test")
            entry.set_sub_task_id("task-test")
            entry.set_tool_used("test.tool")
            entry.set_tool_parameters({"key": "value"})
            entry.set_outcome("SUCCESS")
            entry.set_confidence_score(0.95)
            entry.set_anomaly_score(0.10)
            entry.set_policy_evaluation({"policy": "test", "result": "PASS"})

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        attrs = dict(span.attributes)

        assert attrs[AgenticLogAttributes.AGENT_ID] == "agent-test-001"
        assert attrs[AgenticLogAttributes.SESSION_ID] == "sess-abc123"
        assert attrs[AgenticLogAttributes.GOAL_ID] == "goal-test"
        assert attrs[AgenticLogAttributes.SUB_TASK_ID] == "task-test"
        assert attrs[AgenticLogAttributes.TOOL_USED] == "test.tool"
        assert json.loads(attrs[AgenticLogAttributes.TOOL_PARAMETERS]) == {"key": "value"}
        assert attrs[AgenticLogAttributes.OUTCOME] == "SUCCESS"
        assert attrs[AgenticLogAttributes.CONFIDENCE_SCORE] == 0.95
        assert attrs[AgenticLogAttributes.ANOMALY_SCORE] == 0.10

        policy = json.loads(attrs[AgenticLogAttributes.POLICY_EVALUATION])
        assert policy == {"policy": "test", "result": "PASS"}

    def test_auto_generated_event_id(self):
        instrumentor, exporter = _make_instrumentor()
        with instrumentor.log_action(
            agent_id="agent-test", session_id="sess-test"
        ) as entry:
            assert entry.event_id.startswith("e-")
            assert len(entry.event_id) == 10  # "e-" + 8 hex chars

        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes)
        assert attrs[AgenticLogAttributes.EVENT_ID].startswith("e-")

    def test_custom_event_id(self):
        instrumentor, exporter = _make_instrumentor()
        with instrumentor.log_action(
            agent_id="agent-test",
            session_id="sess-test",
            event_id="e-custom123",
        ) as entry:
            assert entry.event_id == "e-custom123"

        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes)
        assert attrs[AgenticLogAttributes.EVENT_ID] == "e-custom123"

    def test_timestamp_is_iso8601(self):
        instrumentor, exporter = _make_instrumentor()
        with instrumentor.log_action(
            agent_id="agent-test", session_id="sess-test"
        ) as entry:
            ts = entry.timestamp
            # Verify ISO 8601 format with milliseconds
            assert ts.endswith("Z")
            assert "T" in ts
            # Should have millisecond precision (3 decimal places)
            parts = ts.split(".")
            assert len(parts) == 2
            ms_part = parts[1].rstrip("Z")
            assert len(ms_part) == 3

    def test_kwargs_at_creation(self):
        instrumentor, exporter = _make_instrumentor()
        with instrumentor.log_action(
            agent_id="agent-test",
            session_id="sess-test",
            goal_id="goal-kwarg",
            sub_task_id="task-kwarg",
            tool_used="kwarg.tool",
            tool_parameters={"from": "kwargs"},
            confidence_score=0.88,
            anomaly_score=0.22,
        ):
            pass

        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes)
        assert attrs[AgenticLogAttributes.GOAL_ID] == "goal-kwarg"
        assert attrs[AgenticLogAttributes.SUB_TASK_ID] == "task-kwarg"
        assert attrs[AgenticLogAttributes.TOOL_USED] == "kwarg.tool"
        assert json.loads(attrs[AgenticLogAttributes.TOOL_PARAMETERS]) == {"from": "kwargs"}
        assert attrs[AgenticLogAttributes.CONFIDENCE_SCORE] == 0.88
        assert attrs[AgenticLogAttributes.ANOMALY_SCORE] == 0.22

    def test_tool_parameters_as_string(self):
        instrumentor, exporter = _make_instrumentor()
        with instrumentor.log_action(
            agent_id="agent-test",
            session_id="sess-test",
        ) as entry:
            entry.set_tool_parameters('{"raw": "json"}')

        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes)
        assert attrs[AgenticLogAttributes.TOOL_PARAMETERS] == '{"raw": "json"}'

    def test_policy_evaluation_as_string(self):
        instrumentor, exporter = _make_instrumentor()
        with instrumentor.log_action(
            agent_id="agent-test",
            session_id="sess-test",
        ) as entry:
            entry.set_policy_evaluation('{"policy": "raw", "result": "PASS"}')

        spans = exporter.get_finished_spans()
        attrs = dict(spans[0].attributes)
        assert '"policy": "raw"' in attrs[AgenticLogAttributes.POLICY_EVALUATION]

    def test_error_sets_outcome_and_status(self):
        instrumentor, exporter = _make_instrumentor()
        try:
            with instrumentor.log_action(
                agent_id="agent-test", session_id="sess-test"
            ):
                raise ValueError("test error")
        except ValueError:
            pass

        spans = exporter.get_finished_spans()
        span = spans[0]
        assert span.status.status_code == StatusCode.ERROR
        attrs = dict(span.attributes)
        assert attrs[AgenticLogAttributes.OUTCOME] == "ERROR"

    def test_outcome_success_sets_ok_status(self):
        instrumentor, exporter = _make_instrumentor()
        with instrumentor.log_action(
            agent_id="agent-test", session_id="sess-test"
        ) as entry:
            entry.set_outcome("SUCCESS")

        spans = exporter.get_finished_spans()
        assert spans[0].status.status_code == StatusCode.OK

    def test_outcome_failure_sets_error_status(self):
        instrumentor, exporter = _make_instrumentor()
        with instrumentor.log_action(
            agent_id="agent-test", session_id="sess-test"
        ) as entry:
            entry.set_outcome("FAILURE")

        spans = exporter.get_finished_spans()
        assert spans[0].status.status_code == StatusCode.ERROR

    def test_span_name_includes_agent_id(self):
        instrumentor, exporter = _make_instrumentor()
        with instrumentor.log_action(
            agent_id="agent-innovacorp-prod-042",
            session_id="sess-test",
        ):
            pass

        spans = exporter.get_finished_spans()
        assert "agent-innovacorp-prod-042" in spans[0].name

    def test_instrument_uninstrument(self):
        instrumentor, _ = _make_instrumentor()
        instrumentor.instrument()
        assert instrumentor._instrumented
        instrumentor.uninstrument()
        assert not instrumentor._instrumented

    def test_full_table_10_1_example(self):
        """Test the complete Logi-Agent example from Table 10.1."""
        instrumentor, exporter = _make_instrumentor()
        with instrumentor.log_action(
            agent_id="agent-innovacorp-logicore-prod-042",
            session_id="sess-f0a1b2",
            event_id="e-44b1c8f0",
        ) as entry:
            entry.set_goal_id("goal-resolve-port-congestion-sg")
            entry.set_sub_task_id("task-find-all-trucking-vendor")
            entry.set_tool_used("mcp.server.github.list_tools")
            entry.set_tool_parameters({"repo": "innovacorp logistics-tools"})
            entry.set_outcome("SUCCESS")
            entry.set_confidence_score(0.92)
            entry.set_anomaly_score(0.15)
            entry.set_policy_evaluation({
                "policy": "max_spend",
                "shipment": True,
                "result": "PASS",
            })

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        attrs = dict(spans[0].attributes)

        # Verify all 12 Table 10.1 fields are present
        assert attrs[AgenticLogAttributes.EVENT_ID] == "e-44b1c8f0"
        assert AgenticLogAttributes.TIMESTAMP in attrs
        assert attrs[AgenticLogAttributes.AGENT_ID] == "agent-innovacorp-logicore-prod-042"
        assert attrs[AgenticLogAttributes.SESSION_ID] == "sess-f0a1b2"
        assert attrs[AgenticLogAttributes.GOAL_ID] == "goal-resolve-port-congestion-sg"
        assert attrs[AgenticLogAttributes.SUB_TASK_ID] == "task-find-all-trucking-vendor"
        assert attrs[AgenticLogAttributes.TOOL_USED] == "mcp.server.github.list_tools"
        assert json.loads(attrs[AgenticLogAttributes.TOOL_PARAMETERS]) == {
            "repo": "innovacorp logistics-tools"
        }
        assert attrs[AgenticLogAttributes.OUTCOME] == "SUCCESS"
        assert attrs[AgenticLogAttributes.CONFIDENCE_SCORE] == 0.92
        assert attrs[AgenticLogAttributes.ANOMALY_SCORE] == 0.15

        policy = json.loads(attrs[AgenticLogAttributes.POLICY_EVALUATION])
        assert policy["policy"] == "max_spend"
        assert policy["result"] == "PASS"
