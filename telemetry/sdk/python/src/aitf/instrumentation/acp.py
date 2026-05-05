"""AITF ACP (Agent Communication Protocol) Instrumentation.

Provides tracing for ACP protocol operations: agent discovery,
run create/get/cancel/resume, and streaming.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import ACPAttributes

_TRACER_NAME = "instrumentation.acp"


class ACPInstrumentor:
    """Instrumentor for ACP protocol operations."""

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
        base_url: str | None = None,
        agent_name: str | None = None,
    ) -> Generator[ACPAgentDiscovery, None, None]:
        """Trace ACP agent discovery (GET /agents or GET /agents/{name})."""
        tracer = self.get_tracer()
        operation = "get_agent" if agent_name else "list_agents"
        span_name = f"acp.agent.discover {agent_name}" if agent_name else "acp.agent.discover"
        attributes: dict[str, Any] = {
            ACPAttributes.OPERATION: operation,
            ACPAttributes.HTTP_METHOD: "GET",
        }
        if base_url:
            url = f"{base_url}/agents/{agent_name}" if agent_name else f"{base_url}/agents"
            attributes[ACPAttributes.HTTP_URL] = url
        if agent_name:
            attributes[ACPAttributes.AGENT_NAME] = agent_name

        with tracer.start_as_current_span(
            name=span_name,
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            discovery = ACPAgentDiscovery(span)
            try:
                yield discovery
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_run_create(
        self,
        agent_name: str,
        mode: str = "sync",
        session_id: str | None = None,
        input_message_count: int = 0,
    ) -> Generator[ACPRun, None, None]:
        """Trace creating an ACP run (POST /runs)."""
        tracer = self.get_tracer()
        start = time.monotonic()
        attributes: dict[str, Any] = {
            ACPAttributes.RUN_AGENT_NAME: agent_name,
            ACPAttributes.RUN_MODE: mode,
            ACPAttributes.OPERATION: "create_run",
            ACPAttributes.HTTP_METHOD: "POST",
            ACPAttributes.INPUT_MESSAGE_COUNT: input_message_count,
        }
        if session_id:
            attributes[ACPAttributes.RUN_SESSION_ID] = session_id

        with tracer.start_as_current_span(
            name=f"acp.run.create {agent_name}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            run = ACPRun(span, start)
            try:
                yield run
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_run_get(
        self,
        run_id: str,
    ) -> Generator[trace.Span, None, None]:
        """Trace polling an ACP run (GET /runs/{run_id})."""
        tracer = self.get_tracer()
        with tracer.start_as_current_span(
            name=f"acp.run.get {run_id}",
            kind=SpanKind.CLIENT,
            attributes={
                ACPAttributes.RUN_ID: run_id,
                ACPAttributes.OPERATION: "get_run",
                ACPAttributes.HTTP_METHOD: "GET",
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
    def trace_run_cancel(
        self,
        run_id: str,
    ) -> Generator[trace.Span, None, None]:
        """Trace canceling an ACP run (POST /runs/{run_id}/cancel)."""
        tracer = self.get_tracer()
        with tracer.start_as_current_span(
            name=f"acp.run.cancel {run_id}",
            kind=SpanKind.CLIENT,
            attributes={
                ACPAttributes.RUN_ID: run_id,
                ACPAttributes.OPERATION: "cancel_run",
                ACPAttributes.HTTP_METHOD: "POST",
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
    def trace_run_resume(
        self,
        run_id: str,
    ) -> Generator[ACPRun, None, None]:
        """Trace resuming an awaiting ACP run (POST /runs/{run_id}/resume)."""
        tracer = self.get_tracer()
        start = time.monotonic()
        with tracer.start_as_current_span(
            name=f"acp.run.resume {run_id}",
            kind=SpanKind.CLIENT,
            attributes={
                ACPAttributes.RUN_ID: run_id,
                ACPAttributes.OPERATION: "resume_run",
                ACPAttributes.HTTP_METHOD: "POST",
            },
        ) as span:
            run = ACPRun(span, start)
            try:
                yield run
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


class ACPAgentDiscovery:
    """Helper for ACP agent discovery span."""

    def __init__(self, span: trace.Span):
        self._span = span

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_agent_info(
        self,
        name: str,
        description: str | None = None,
        input_content_types: list[str] | None = None,
        output_content_types: list[str] | None = None,
        framework: str | None = None,
        success_rate: float | None = None,
    ) -> None:
        self._span.set_attribute(ACPAttributes.AGENT_NAME, name)
        if description:
            self._span.set_attribute(ACPAttributes.AGENT_DESCRIPTION, description)
        if input_content_types:
            self._span.set_attribute(ACPAttributes.AGENT_INPUT_CONTENT_TYPES, input_content_types)
        if output_content_types:
            self._span.set_attribute(ACPAttributes.AGENT_OUTPUT_CONTENT_TYPES, output_content_types)
        if framework:
            self._span.set_attribute(ACPAttributes.AGENT_FRAMEWORK, framework)
        if success_rate is not None:
            self._span.set_attribute(ACPAttributes.AGENT_SUCCESS_RATE, success_rate)

    def set_http_status(self, status_code: int) -> None:
        self._span.set_attribute(ACPAttributes.HTTP_STATUS_CODE, status_code)


class ACPRun:
    """Helper for ACP run span attributes."""

    def __init__(self, span: trace.Span, start_time: float):
        self._span = span
        self._start_time = start_time
        self._await_count = 0

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_run_id(self, run_id: str) -> None:
        self._span.set_attribute(ACPAttributes.RUN_ID, run_id)

    def set_status(self, status: str, previous_status: str | None = None) -> None:
        self._span.set_attribute(ACPAttributes.RUN_STATUS, status)
        if previous_status:
            self._span.set_attribute(ACPAttributes.RUN_PREVIOUS_STATUS, previous_status)
        self._span.add_event(
            "acp.run.status_change",
            attributes={"acp.run.status": status},
        )

    def set_output(self, message_count: int) -> None:
        self._span.set_attribute(ACPAttributes.OUTPUT_MESSAGE_COUNT, message_count)

    def set_error(self, code: str, message: str) -> None:
        self._span.set_attribute(ACPAttributes.RUN_ERROR_CODE, code)
        self._span.set_attribute(ACPAttributes.RUN_ERROR_MESSAGE, message)

    def record_await(self) -> None:
        """Record an await/resume cycle."""
        self._await_count += 1
        self._span.set_attribute(ACPAttributes.AWAIT_ACTIVE, True)
        self._span.set_attribute(ACPAttributes.AWAIT_COUNT, self._await_count)
        self._span.add_event("acp.run.await")

    def record_resume(self) -> None:
        self._span.set_attribute(ACPAttributes.AWAIT_ACTIVE, False)
        self._span.add_event("acp.run.resume")

    def set_duration(self) -> None:
        duration_ms = (time.monotonic() - self._start_time) * 1000
        self._span.set_attribute(ACPAttributes.RUN_DURATION_MS, duration_ms)

    def set_http_status(self, status_code: int) -> None:
        self._span.set_attribute(ACPAttributes.HTTP_STATUS_CODE, status_code)
