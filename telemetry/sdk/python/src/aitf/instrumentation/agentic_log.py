"""AITF Agentic Log Instrumentation.

Provides structured logging for AI agent actions based on Table 10.1:
Agentic log with minimum fields. Each log entry captures the essential
security-relevant context for every action taken by an AI agent,
including event correlation, goal tracking, tool usage, confidence
assessment, anomaly detection, and policy evaluation.
"""

from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import AgenticLogAttributes

_TRACER_NAME = "instrumentation.agentic_log"


class AgenticLogEntry:
    """A single agentic log entry conforming to Table 10.1 minimal fields.

    Wraps an OTel span and provides typed setters for all 12 mandatory
    fields from the agentic log specification.
    """

    def __init__(self, span: trace.Span, event_id: str, timestamp: str):
        self._span = span
        self._event_id = event_id
        self._timestamp = timestamp

    @property
    def span(self) -> trace.Span:
        return self._span

    @property
    def event_id(self) -> str:
        return self._event_id

    @property
    def timestamp(self) -> str:
        return self._timestamp

    def set_goal_id(self, goal_id: str) -> None:
        """Set the high-level goal the agent is pursuing.

        This is the single most important field for security context.
        """
        self._span.set_attribute(AgenticLogAttributes.GOAL_ID, goal_id)

    def set_sub_task_id(self, sub_task_id: str) -> None:
        """Set the specific, immediate task the agent is performing."""
        self._span.set_attribute(AgenticLogAttributes.SUB_TASK_ID, sub_task_id)

    def set_tool_used(self, tool_used: str) -> None:
        """Set the specific tool, function, or API being invoked."""
        self._span.set_attribute(AgenticLogAttributes.TOOL_USED, tool_used)

    def set_tool_parameters(self, parameters: dict[str, Any] | str) -> None:
        """Set the sanitized tool parameters.

        Crucially, this must redact PII, credentials, and other sensitive data.
        If a dict is provided, it is JSON-serialized.
        """
        if isinstance(parameters, dict):
            parameters = json.dumps(parameters, default=str)
        self._span.set_attribute(AgenticLogAttributes.TOOL_PARAMETERS, parameters)

    def set_outcome(self, outcome: str) -> None:
        """Set the result of the action (e.g., SUCCESS, FAILURE, ERROR)."""
        self._span.set_attribute(AgenticLogAttributes.OUTCOME, outcome)
        if outcome == AgenticLogAttributes.Outcome.SUCCESS:
            self._span.set_status(StatusCode.OK)
        elif outcome in (
            AgenticLogAttributes.Outcome.FAILURE,
            AgenticLogAttributes.Outcome.ERROR,
        ):
            self._span.set_status(StatusCode.ERROR, f"Outcome: {outcome}")

    def set_confidence_score(self, score: float) -> None:
        """Set the agent's own assessment of how likely this action is to succeed.

        A sudden drop can indicate a poisoned environment.
        Value is clamped to [0.0, 1.0].
        """
        score = max(0.0, min(1.0, float(score)))
        self._span.set_attribute(AgenticLogAttributes.CONFIDENCE_SCORE, score)

    def set_anomaly_score(self, score: float) -> None:
        """Set the anomaly score from a real-time model.

        Indicates how unusual this action is, even for this goal.
        This is the primary input for automated alerting.
        Value is clamped to [0.0, 1.0].
        """
        score = max(0.0, min(1.0, float(score)))
        self._span.set_attribute(AgenticLogAttributes.ANOMALY_SCORE, score)

    def set_policy_evaluation(self, evaluation: dict[str, Any] | str) -> None:
        """Set the record of a check against a security policy engine (e.g., OPA).

        Example: {"policy": "max_spend", "result": "PASS"}
        """
        if isinstance(evaluation, dict):
            evaluation = json.dumps(evaluation, default=str)
        self._span.set_attribute(
            AgenticLogAttributes.POLICY_EVALUATION, evaluation
        )


class AgenticLogInstrumentor:
    """Instrumentor for agentic log entries (Table 10.1 minimal fields).

    Usage:
        logger = AgenticLogInstrumentor()
        with logger.log_action(
            agent_id="agent-innovacorp-logicore-prod-042",
            session_id="sess-f0a1b2",
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
                "result": "PASS",
            })
    """

    def __init__(self, tracer_provider: TracerProvider | None = None):
        self._tracer_provider = tracer_provider
        self._tracer: trace.Tracer | None = None
        self._instrumented = False

    def instrument(self) -> None:
        tp = self._tracer_provider or trace.get_tracer_provider()
        self._tracer = tp.get_tracer(_TRACER_NAME)
        self._instrumented = True

    def uninstrument(self) -> None:
        self._tracer = None
        self._instrumented = False

    def get_tracer(self) -> trace.Tracer:
        if self._tracer is None:
            tp = self._tracer_provider or trace.get_tracer_provider()
            self._tracer = tp.get_tracer(_TRACER_NAME)
        return self._tracer

    @contextmanager
    def log_action(
        self,
        agent_id: str,
        session_id: str,
        *,
        event_id: str | None = None,
        goal_id: str | None = None,
        sub_task_id: str | None = None,
        tool_used: str | None = None,
        tool_parameters: dict[str, Any] | str | None = None,
        confidence_score: float | None = None,
        anomaly_score: float | None = None,
    ) -> Generator[AgenticLogEntry, None, None]:
        """Context manager for creating an agentic log entry span.

        Automatically populates EventID and Timestamp. AgentID and
        SessionID are required; all other fields can be set on the
        returned AgenticLogEntry object or passed as keyword arguments.

        Args:
            agent_id: The unique, cryptographically verifiable agent identity.
            session_id: The unique session/thought-process ID.
            event_id: Optional custom event ID (auto-generated if omitted).
            goal_id: The high-level goal identifier.
            sub_task_id: The specific immediate task identifier.
            tool_used: The tool/function/API being invoked.
            tool_parameters: Sanitized parameters (dict or JSON string).
            confidence_score: Agent's success likelihood assessment (0.0-1.0).
            anomaly_score: How unusual this action is (0.0-1.0).
        """
        tracer = self.get_tracer()
        event_id = event_id or f"e-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        attributes: dict[str, Any] = {
            AgenticLogAttributes.EVENT_ID: event_id,
            AgenticLogAttributes.TIMESTAMP: timestamp,
            AgenticLogAttributes.AGENT_ID: agent_id,
            AgenticLogAttributes.SESSION_ID: session_id,
        }

        if goal_id is not None:
            attributes[AgenticLogAttributes.GOAL_ID] = goal_id
        if sub_task_id is not None:
            attributes[AgenticLogAttributes.SUB_TASK_ID] = sub_task_id
        if tool_used is not None:
            attributes[AgenticLogAttributes.TOOL_USED] = tool_used
        if tool_parameters is not None:
            if isinstance(tool_parameters, dict):
                tool_parameters = json.dumps(tool_parameters, default=str)
            attributes[AgenticLogAttributes.TOOL_PARAMETERS] = tool_parameters
        if confidence_score is not None:
            attributes[AgenticLogAttributes.CONFIDENCE_SCORE] = max(
                0.0, min(1.0, float(confidence_score))
            )
        if anomaly_score is not None:
            attributes[AgenticLogAttributes.ANOMALY_SCORE] = max(
                0.0, min(1.0, float(anomaly_score))
            )

        with tracer.start_as_current_span(
            name=f"agentic_log {agent_id}",
            kind=SpanKind.INTERNAL,
            attributes=attributes,
        ) as span:
            entry = AgenticLogEntry(span, event_id, timestamp)
            try:
                yield entry
                if span.status.status_code == StatusCode.UNSET:
                    span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                entry.set_outcome(AgenticLogAttributes.Outcome.ERROR)
                raise
