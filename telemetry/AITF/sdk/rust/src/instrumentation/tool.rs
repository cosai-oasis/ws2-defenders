//! Tool / MCP instrumentation mirroring the Go `instrumentation/mcp.go`.

use std::time::Instant;

use opentelemetry::global::{self, BoxedTracer};
use opentelemetry::trace::{Span, SpanKind, Status, Tracer};
use opentelemetry::KeyValue;

use crate::semconv::mcp;

const TRACER_NAME: &str = "instrumentation.mcp";

/// Traces MCP protocol operations.
pub struct McpInstrumentor<T = BoxedTracer> {
    tracer: T,
}

impl McpInstrumentor<BoxedTracer> {
    /// Creates an instrumentor using the global tracer provider.
    pub fn new() -> Self {
        Self {
            tracer: global::tracer(TRACER_NAME),
        }
    }
}

impl Default for McpInstrumentor<BoxedTracer> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Tracer> McpInstrumentor<T> {
    /// Creates an instrumentor from an explicit tracer.
    pub fn with_tracer(tracer: T) -> Self {
        Self { tracer }
    }

    /// Starts an MCP server-connection span.
    pub fn trace_server_connect(
        &self,
        server_name: &str,
        transport: &str,
        protocol_version: &str,
    ) -> McpServerConnection<T::Span> {
        let attrs = vec![
            KeyValue::new(mcp::SERVER_NAME, server_name.to_string()),
            KeyValue::new(mcp::SERVER_TRANSPORT, transport.to_string()),
            KeyValue::new(mcp::PROTOCOL_VERSION, protocol_version.to_string()),
        ];
        let span = self
            .tracer
            .span_builder(format!("mcp.server.connect {server_name}"))
            .with_kind(SpanKind::Client)
            .with_attributes(attrs)
            .start(&self.tracer);
        McpServerConnection { span }
    }

    /// Starts an MCP tool-invocation span.
    pub fn trace_tool_invoke(
        &self,
        tool_name: &str,
        server_name: &str,
        input: &str,
    ) -> McpToolInvocation<T::Span> {
        let mut attrs = vec![
            KeyValue::new(mcp::TOOL_NAME, tool_name.to_string()),
            KeyValue::new(mcp::TOOL_SERVER, server_name.to_string()),
        ];
        if !input.is_empty() {
            attrs.push(KeyValue::new(mcp::TOOL_INPUT, input.to_string()));
        }
        let span = self
            .tracer
            .span_builder(format!("mcp.tool.invoke {tool_name}"))
            .with_kind(SpanKind::Client)
            .with_attributes(attrs)
            .start(&self.tracer);
        McpToolInvocation {
            span,
            start: Instant::now(),
            error_set: false,
        }
    }

    /// Starts an MCP resource-read span.
    pub fn trace_resource_read(&self, uri: &str, server_name: &str) -> T::Span {
        self.tracer
            .span_builder(format!("mcp.resource.read {uri}"))
            .with_kind(SpanKind::Client)
            .with_attributes(vec![
                KeyValue::new(mcp::RESOURCE_URI, uri.to_string()),
                KeyValue::new(mcp::SERVER_NAME, server_name.to_string()),
            ])
            .start(&self.tracer)
    }
}

/// Manages an MCP server-connection span.
pub struct McpServerConnection<S: Span> {
    span: S,
}

impl<S: Span> McpServerConnection<S> {
    /// Records server capabilities as an event.
    pub fn set_capabilities(&mut self, tools: bool, resources: bool, prompts: bool, sampling: bool) {
        self.span.add_event(
            "mcp.server.capabilities",
            vec![
                KeyValue::new("mcp.capabilities.tools", tools),
                KeyValue::new("mcp.capabilities.resources", resources),
                KeyValue::new("mcp.capabilities.prompts", prompts),
                KeyValue::new("mcp.capabilities.sampling", sampling),
            ],
        );
    }

    /// Completes the connection span.
    pub fn end<E: std::fmt::Display>(mut self, result: Result<(), E>) {
        match result {
            Ok(()) => self.span.set_status(Status::Ok),
            Err(e) => self.span.set_status(Status::error(e.to_string())),
        }
        self.span.end();
    }

    /// Returns a mutable reference to the underlying span.
    pub fn span_mut(&mut self) -> &mut S {
        &mut self.span
    }
}

/// Manages an MCP tool-invocation span.
pub struct McpToolInvocation<S: Span> {
    span: S,
    start: Instant,
    error_set: bool,
}

impl<S: Span> McpToolInvocation<S> {
    /// Sets the tool output.
    pub fn set_output(&mut self, output: &str, output_type: &str) {
        self.span
            .set_attribute(KeyValue::new(mcp::TOOL_OUTPUT, output.to_string()));
        self.span.add_event(
            "mcp.tool.output",
            vec![
                KeyValue::new("mcp.tool.output.content", output.to_string()),
                KeyValue::new("mcp.tool.output.type", output_type.to_string()),
            ],
        );
    }

    /// Marks the tool invocation as an error.
    pub fn set_error(&mut self, err_msg: &str) {
        self.span.set_attribute(KeyValue::new(mcp::TOOL_IS_ERROR, true));
        self.error_set = true;
        self.span.add_event(
            "mcp.tool.error",
            vec![KeyValue::new("mcp.tool.error.message", err_msg.to_string())],
        );
    }

    /// Records approval status.
    pub fn set_approved(&mut self, approved: bool, approver: &str) {
        self.span
            .set_attribute(KeyValue::new(mcp::TOOL_APPROVED, approved));
        let status = if approved { "approved" } else { "denied" };
        let mut attrs = vec![KeyValue::new("mcp.tool.approval.status", status)];
        if !approver.is_empty() {
            attrs.push(KeyValue::new(
                "mcp.tool.approval.approver",
                approver.to_string(),
            ));
        }
        self.span.add_event("mcp.tool.approval", attrs);
    }

    /// Completes the tool-invocation span, recording duration and status.
    pub fn end<E: std::fmt::Display>(mut self, result: Result<(), E>) {
        let duration = self.start.elapsed().as_millis() as f64;
        self.span
            .set_attribute(KeyValue::new(mcp::TOOL_DURATION_MS, duration));
        if !self.error_set {
            self.span
                .set_attribute(KeyValue::new(mcp::TOOL_IS_ERROR, false));
        }
        match result {
            Ok(()) => self.span.set_status(Status::Ok),
            Err(e) => self.span.set_status(Status::error(e.to_string())),
        }
        self.span.end();
    }

    /// Returns a mutable reference to the underlying span.
    pub fn span_mut(&mut self) -> &mut S {
        &mut self.span
    }
}
