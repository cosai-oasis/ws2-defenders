package instrumentation

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

const mcpTracerName = "instrumentation.mcp"

// MCPInstrumentor traces MCP protocol operations.
type MCPInstrumentor struct {
	tracer trace.Tracer
}

// NewMCPInstrumentor creates a new MCP instrumentor.
func NewMCPInstrumentor(tp trace.TracerProvider) *MCPInstrumentor {
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	return &MCPInstrumentor{tracer: tp.Tracer(mcpTracerName)}
}

// TraceServerConnect starts an MCP server connection span.
func (m *MCPInstrumentor) TraceServerConnect(ctx context.Context, serverName, transport, protocolVersion string) (context.Context, *MCPServerConnection) {
	attrs := []attribute.KeyValue{
		semconv.MCPServerNameKey.String(serverName),
		semconv.MCPServerTransportKey.String(transport),
		semconv.MCPProtocolVersionKey.String(protocolVersion),
	}

	ctx, span := m.tracer.Start(ctx,
		fmt.Sprintf("mcp.server.connect %s", serverName),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)

	return ctx, &MCPServerConnection{span: span, tracer: m.tracer, serverName: serverName}
}

// TraceToolInvoke starts an MCP tool invocation span.
func (m *MCPInstrumentor) TraceToolInvoke(ctx context.Context, toolName, serverName string, input string) (context.Context, *MCPToolInvocation) {
	attrs := []attribute.KeyValue{
		semconv.MCPToolNameKey.String(toolName),
		semconv.MCPToolServerKey.String(serverName),
	}
	if input != "" {
		attrs = append(attrs, semconv.MCPToolInputKey.String(input))
	}

	ctx, span := m.tracer.Start(ctx,
		fmt.Sprintf("mcp.tool.invoke %s", toolName),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)

	return ctx, &MCPToolInvocation{span: span, startTime: time.Now()}
}

// TraceResourceRead starts an MCP resource read span.
func (m *MCPInstrumentor) TraceResourceRead(ctx context.Context, uri, serverName string) (context.Context, trace.Span) {
	ctx, span := m.tracer.Start(ctx,
		fmt.Sprintf("mcp.resource.read %s", uri),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.MCPResourceURIKey.String(uri),
			semconv.MCPServerNameKey.String(serverName),
		),
	)
	return ctx, span
}

// TracePromptGet starts an MCP prompt retrieval span.
func (m *MCPInstrumentor) TracePromptGet(ctx context.Context, promptName, serverName string) (context.Context, trace.Span) {
	ctx, span := m.tracer.Start(ctx,
		fmt.Sprintf("mcp.prompt.get %s", promptName),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.MCPPromptNameKey.String(promptName),
			semconv.MCPServerNameKey.String(serverName),
		),
	)
	return ctx, span
}

// MCPServerConnection manages an MCP server connection span.
type MCPServerConnection struct {
	span       trace.Span
	tracer     trace.Tracer
	serverName string
}

// SetCapabilities records server capabilities.
func (c *MCPServerConnection) SetCapabilities(tools, resources, prompts, sampling bool) {
	c.span.AddEvent("mcp.server.capabilities", trace.WithAttributes(
		attribute.Bool("mcp.capabilities.tools", tools),
		attribute.Bool("mcp.capabilities.resources", resources),
		attribute.Bool("mcp.capabilities.prompts", prompts),
		attribute.Bool("mcp.capabilities.sampling", sampling),
	))
}

// End completes the connection span.
func (c *MCPServerConnection) End(err error) {
	if err != nil {
		c.span.SetStatus(codes.Error, err.Error())
	} else {
		c.span.SetStatus(codes.Ok, "")
	}
	c.span.End()
}

// Span returns the underlying OTel span.
func (c *MCPServerConnection) Span() trace.Span { return c.span }

// MCPToolInvocation manages an MCP tool invocation span.
type MCPToolInvocation struct {
	span      trace.Span
	startTime time.Time
	errorSet  bool
}

// SetOutput sets the tool output.
func (t *MCPToolInvocation) SetOutput(output, outputType string) {
	t.span.SetAttributes(semconv.MCPToolOutputKey.String(output))
	t.span.AddEvent("mcp.tool.output", trace.WithAttributes(
		attribute.String("mcp.tool.output.content", output),
		attribute.String("mcp.tool.output.type", outputType),
	))
}

// SetError marks the tool invocation as an error.
func (t *MCPToolInvocation) SetError(errMsg string) {
	t.span.SetAttributes(semconv.MCPToolIsErrorKey.Bool(true))
	t.errorSet = true
	t.span.AddEvent("mcp.tool.error", trace.WithAttributes(
		attribute.String("mcp.tool.error.message", errMsg),
	))
}

// SetApproved records approval status.
func (t *MCPToolInvocation) SetApproved(approved bool, approver string) {
	t.span.SetAttributes(semconv.MCPToolApprovedKey.Bool(approved))
	status := "approved"
	if !approved {
		status = "denied"
	}
	attrs := []attribute.KeyValue{attribute.String("mcp.tool.approval.status", status)}
	if approver != "" {
		attrs = append(attrs, attribute.String("mcp.tool.approval.approver", approver))
	}
	t.span.AddEvent("mcp.tool.approval", trace.WithAttributes(attrs...))
}

// End completes the tool invocation span.
func (t *MCPToolInvocation) End(err error) {
	duration := float64(time.Since(t.startTime).Milliseconds())
	t.span.SetAttributes(semconv.MCPToolDurationMsKey.Float64(duration))
	if !t.errorSet {
		t.span.SetAttributes(semconv.MCPToolIsErrorKey.Bool(false))
	}
	if err != nil {
		t.span.SetStatus(codes.Error, err.Error())
		t.span.RecordError(err)
	} else {
		t.span.SetStatus(codes.Ok, "")
	}
	t.span.End()
}

// Span returns the underlying OTel span.
func (t *MCPToolInvocation) Span() trace.Span { return t.span }
