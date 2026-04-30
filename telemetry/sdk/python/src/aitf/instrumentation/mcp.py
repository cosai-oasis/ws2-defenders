"""AITF MCP (Model Context Protocol) Instrumentation.

Provides tracing for MCP server connections, tool discovery and invocation,
resource access, prompt management, and sampling operations.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Generator

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import SpanKind, StatusCode

from aitf.semantic_conventions.attributes import GenAIAttributes, MCPAttributes

_TRACER_NAME = "instrumentation.mcp"


class MCPInstrumentor:
    """Instrumentor for MCP protocol operations."""

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
    def trace_server_connect(
        self,
        server_name: str,
        transport: str = "stdio",
        server_version: str | None = None,
        server_url: str | None = None,
        protocol_version: str = "2025-03-26",
        connection_id: str | None = None,
    ) -> Generator[MCPServerConnection, None, None]:
        """Trace an MCP server connection lifecycle."""
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            MCPAttributes.SERVER_NAME: server_name,
            MCPAttributes.SERVER_TRANSPORT: transport,
            MCPAttributes.PROTOCOL_VERSION: protocol_version,
        }
        if server_version:
            attributes[MCPAttributes.SERVER_VERSION] = server_version
        if server_url:
            attributes[MCPAttributes.SERVER_URL] = server_url
        if connection_id:
            attributes[MCPAttributes.CONNECTION_ID] = connection_id

        with tracer.start_as_current_span(
            name=f"mcp.server.connect {server_name}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            conn = MCPServerConnection(span, tracer, server_name)
            try:
                yield conn
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_tool_invoke(
        self,
        tool_name: str,
        server_name: str,
        tool_input: str | None = None,
        approval_required: bool = False,
    ) -> Generator[MCPToolInvocation, None, None]:
        """Trace an MCP tool invocation."""
        tracer = self.get_tracer()
        start = time.monotonic()
        attributes: dict[str, Any] = {
            GenAIAttributes.TOOL_NAME: tool_name,
            MCPAttributes.TOOL_SERVER: server_name,
        }
        if tool_input is not None:
            attributes[GenAIAttributes.TOOL_CALL_ARGUMENTS] = tool_input
        if approval_required:
            attributes[MCPAttributes.TOOL_APPROVAL_REQUIRED] = True

        with tracer.start_as_current_span(
            name=f"mcp.tool.invoke {tool_name}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            invocation = MCPToolInvocation(span, start)
            try:
                yield invocation
                duration_ms = (time.monotonic() - start) * 1000
                span.set_attribute(MCPAttributes.TOOL_DURATION_MS, duration_ms)
                if not invocation._error_set:
                    span.set_attribute(MCPAttributes.TOOL_IS_ERROR, False)
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_attribute(MCPAttributes.TOOL_IS_ERROR, True)
                duration_ms = (time.monotonic() - start) * 1000
                span.set_attribute(MCPAttributes.TOOL_DURATION_MS, duration_ms)
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_resource_read(
        self,
        resource_uri: str,
        server_name: str,
        resource_name: str | None = None,
        mime_type: str | None = None,
    ) -> Generator[trace.Span, None, None]:
        """Trace an MCP resource read operation."""
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            MCPAttributes.RESOURCE_URI: resource_uri,
            MCPAttributes.SERVER_NAME: server_name,
        }
        if resource_name:
            attributes[MCPAttributes.RESOURCE_NAME] = resource_name
        if mime_type:
            attributes[MCPAttributes.RESOURCE_MIME_TYPE] = mime_type

        with tracer.start_as_current_span(
            name=f"mcp.resource.read {resource_uri}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_prompt_get(
        self,
        prompt_name: str,
        server_name: str,
        arguments: str | None = None,
    ) -> Generator[trace.Span, None, None]:
        """Trace an MCP prompt retrieval."""
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            MCPAttributes.PROMPT_NAME: prompt_name,
            MCPAttributes.SERVER_NAME: server_name,
        }
        if arguments:
            attributes[MCPAttributes.PROMPT_ARGUMENTS] = arguments

        with tracer.start_as_current_span(
            name=f"mcp.prompt.get {prompt_name}",
            kind=SpanKind.CLIENT,
            attributes=attributes,
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise

    @contextmanager
    def trace_sampling_request(
        self,
        server_name: str,
        model: str | None = None,
        max_tokens: int | None = None,
    ) -> Generator[trace.Span, None, None]:
        """Trace an MCP sampling (server-initiated LLM) request."""
        tracer = self.get_tracer()
        attributes: dict[str, Any] = {
            MCPAttributes.SERVER_NAME: server_name,
        }
        if model:
            attributes[MCPAttributes.SAMPLING_MODEL] = model
        if max_tokens:
            attributes[MCPAttributes.SAMPLING_MAX_TOKENS] = max_tokens

        with tracer.start_as_current_span(
            name=f"mcp.sampling.request {server_name}",
            kind=SpanKind.SERVER,
            attributes=attributes,
        ) as span:
            try:
                yield span
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                span.record_exception(exc)
                raise


class MCPServerConnection:
    """Helper for managing MCP server connection spans."""

    def __init__(self, span: trace.Span, tracer: trace.Tracer, server_name: str):
        self._span = span
        self._tracer = tracer
        self._server_name = server_name

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_capabilities(
        self,
        tools: bool = False,
        resources: bool = False,
        prompts: bool = False,
        sampling: bool = False,
        roots: bool = False,
    ) -> None:
        """Record server capabilities event."""
        self._span.add_event(
            "mcp.server.capabilities",
            attributes={
                "mcp.capabilities.tools": tools,
                "mcp.capabilities.resources": resources,
                "mcp.capabilities.prompts": prompts,
                "mcp.capabilities.sampling": sampling,
                "mcp.capabilities.roots": roots,
            },
        )

    @contextmanager
    def discover_tools(self) -> Generator[MCPToolDiscovery, None, None]:
        """Trace tool discovery on this server."""
        with self._tracer.start_as_current_span(
            name=f"mcp.tool.discover {self._server_name}",
            kind=SpanKind.CLIENT,
            attributes={MCPAttributes.SERVER_NAME: self._server_name},
        ) as span:
            discovery = MCPToolDiscovery(span)
            try:
                yield discovery
                span.set_status(StatusCode.OK)
            except Exception as exc:
                span.set_status(StatusCode.ERROR, str(exc))
                raise


class MCPToolDiscovery:
    """Helper for MCP tool discovery results."""

    def __init__(self, span: trace.Span):
        self._span = span

    def set_tools(self, tool_names: list[str]) -> None:
        self._span.set_attribute(MCPAttributes.TOOL_COUNT, len(tool_names))
        self._span.set_attribute(MCPAttributes.TOOL_NAMES, tool_names)


class MCPToolInvocation:
    """Helper for MCP tool invocation spans."""

    def __init__(self, span: trace.Span, start_time: float):
        self._span = span
        self._start_time = start_time
        self._error_set = False

    @property
    def span(self) -> trace.Span:
        return self._span

    def set_output(self, output: str, output_type: str = "text") -> None:
        self._span.set_attribute(GenAIAttributes.TOOL_CALL_RESULT, output)
        self._span.add_event(
            "mcp.tool.output",
            attributes={
                "mcp.tool.output.content": output,
                "mcp.tool.output.type": output_type,
            },
        )

    def set_error(self, error: str) -> None:
        self._span.set_attribute(MCPAttributes.TOOL_IS_ERROR, True)
        self._span.set_attribute(MCPAttributes.RESPONSE_ERROR, error)
        self._error_set = True
        self._span.add_event(
            "mcp.tool.error",
            attributes={"mcp.tool.error.message": error},
        )

    def set_approved(self, approved: bool, approver: str | None = None) -> None:
        self._span.set_attribute(MCPAttributes.TOOL_APPROVED, approved)
        attrs: dict[str, Any] = {
            "mcp.tool.approval.status": "approved" if approved else "denied",
        }
        if approver:
            attrs["mcp.tool.approval.approver"] = approver
        self._span.add_event("mcp.tool.approval", attributes=attrs)
