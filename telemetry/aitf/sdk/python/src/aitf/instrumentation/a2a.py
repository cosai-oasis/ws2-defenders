"""AITF A2A (Agent-to-Agent Protocol) Instrumentation.

Provides tracing for Google A2A protocol operations: agent discovery,
message send/stream, task lifecycle, and push notifications.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import A2AAttributes

_TRACER_NAME = "instrumentation.a2a"


class A2AInstrumentor:
    """Instrumentor for A2A protocol operations."""

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
    def trace_discover(
        self,
        agent_url: str,
    ) -> Generator[A2AAgentCard, None, None]:
        """Trace fetching an A2A Agent Card."""
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            A2AAttributes.AGENT_URL: agent_url,
            A2AAttributes.METHOD: "agent_card",
        }
        with tracer.start_as_current_span(
            name=f"a2a.agent.discover",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            card = A2AAgentCard(span)
            try:
                yield card
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_message_send(
        self,
        agent_name: str,
        agent_url: str | None = None,
        context_id: str | None = None,
    ) -> Generator[A2ATask, None, None]:
        """Trace an A2A message/send operation."""
        tracer = self.get_tracer()
        start = time.monotonic()
        attributes: dict[str, Any] = {
            A2AAttributes.AGENT_NAME: agent_name,
            A2AAttributes.METHOD: "message/send",
            A2AAttributes.INTERACTION_MODE: A2AAttributes.InteractionMode.SYNC,
        }
        if agent_url:
            attributes[A2AAttributes.AGENT_URL] = agent_url
        if context_id:
            attributes[A2AAttributes.TASK_CONTEXT_ID] = context_id

        with tracer.start_as_current_span(
            name=f"a2a.message.send {agent_name}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            task = A2ATask(span, start)
            try:
                yield task
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_message_stream(
        self,
        agent_name: str,
        agent_url: str | None = None,
        context_id: str | None = None,
    ) -> Generator[A2AStreamTask, None, None]:
        """Trace an A2A message/stream operation."""
        tracer = self.get_tracer()
        start = time.monotonic()
        attributes: dict[str, Any] = {
            A2AAttributes.AGENT_NAME: agent_name,
            A2AAttributes.METHOD: "message/stream",
            A2AAttributes.INTERACTION_MODE: A2AAttributes.InteractionMode.STREAM,
        }
        if agent_url:
            attributes[A2AAttributes.AGENT_URL] = agent_url
        if context_id:
            attributes[A2AAttributes.TASK_CONTEXT_ID] = context_id

        with tracer.start_as_current_span(
            name=f"a2a.message.stream {agent_name}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            task = A2AStreamTask(span, start)
            try:
                yield task
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_task_get(
        self,
        task_id: str,
    ) -> Generator[trace.Span, None, None]:
        """Trace an A2A tasks/get poll operation."""
        tracer = self.get_tracer()
        with tracer.start_as_current_span(
            name=f"a2a.task.get {task_id}",
            kind=SpanKind.CLIENT,
            attributes={
                A2AAttributes.TASK_ID: task_id,
                A2AAttributes.METHOD: "tasks/get",
            },
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_task_cancel(
        self,
        task_id: str,
    ) -> Generator[trace.Span, None, None]:
        """Trace an A2A tasks/cancel operation."""
        tracer = self.get_tracer()
        with tracer.start_as_current_span(
            name=f"a2a.task.cancel {task_id}",
            kind=SpanKind.CLIENT,
            attributes={
                A2AAttributes.TASK_ID: task_id,
                A2AAttributes.METHOD: "tasks/cancel",
            },
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


class A2AAgentCard:
    """Helper for A2A agent card discovery span."""

    def __init__(self, span: trace.Span):
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_agent_info(
        self,
        name: str,
        version: str | None = None,
        provider_org: str | None = None,
        skills: list[str] | None = None,
        streaming: bool = False,
        push_notifications: bool = False,
        protocol_version: str | None = None,
    ) -> None:
        """Set discovered agent card attributes."""
        self._span.set_attribute(A2AAttributes.AGENT_NAME, name)
        if version:
            self._span.set_attribute(A2AAttributes.AGENT_VERSION, version)
        if provider_org:
            self._span.set_attribute(A2AAttributes.AGENT_PROVIDER_ORG, provider_org)
        if skills:
            self._span.set_attribute(A2AAttributes.AGENT_SKILLS, skills)
        self._span.set_attribute(A2AAttributes.AGENT_CAPABILITIES_STREAMING, streaming)
        self._span.set_attribute(A2AAttributes.AGENT_CAPABILITIES_PUSH, push_notifications)
        if protocol_version:
            self._span.set_attribute(A2AAttributes.PROTOCOL_VERSION, protocol_version)


class A2ATask:
    """Helper for A2A task span attributes."""

    def __init__(self, span: trace.Span, start_time: float):
        self._span = span
        self._start_time = start_time

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_task(self, task_id: str, context_id: str | None = None) -> None:
        self._span.set_attribute(A2AAttributes.TASK_ID, task_id)
        if context_id:
            self._span.set_attribute(A2AAttributes.TASK_CONTEXT_ID, context_id)

    def set_state(self, state: str, previous_state: str | None = None) -> None:
        self._span.set_attribute(A2AAttributes.TASK_STATE, state)
        if previous_state:
            self._span.set_attribute(A2AAttributes.TASK_PREVIOUS_STATE, previous_state)
        self._span.add_event(
            "a2a.task.state_change",
            attributes={"a2a.task.state": state},
        )

    def set_message(
        self,
        message_id: str,
        role: str,
        parts_count: int = 0,
        part_types: list[str] | None = None,
    ) -> None:
        self._span.add_event(
            "a2a.message",
            attributes={
                A2AAttributes.MESSAGE_ID: message_id,
                A2AAttributes.MESSAGE_ROLE: role,
                A2AAttributes.MESSAGE_PARTS_COUNT: parts_count,
                **(
                    {A2AAttributes.MESSAGE_PART_TYPES: part_types}
                    if part_types
                    else {}
                ),
            },
        )

    def set_artifacts(self, count: int) -> None:
        self._span.set_attribute(A2AAttributes.TASK_ARTIFACTS_COUNT, count)

    def set_error(self, code: int, message: str) -> None:
        self._span.set_attribute(A2AAttributes.JSONRPC_ERROR_CODE, code)
        self._span.set_attribute(A2AAttributes.JSONRPC_ERROR_MESSAGE, message)


class A2AStreamTask(A2ATask):
    """Helper for A2A streaming task span attributes."""

    def __init__(self, span: trace.Span, start_time: float):
        super().__init__(span, start_time)
        self._events_count = 0

    def record_stream_event(
        self,
        event_type: str,
        is_final: bool = False,
    ) -> None:
        self._events_count += 1
        self._span.add_event(
            "a2a.stream.event",
            attributes={
                A2AAttributes.STREAM_EVENT_TYPE: event_type,
                A2AAttributes.STREAM_IS_FINAL: is_final,
            },
        )
        self._span.set_attribute(A2AAttributes.STREAM_EVENTS_COUNT, self._events_count)
