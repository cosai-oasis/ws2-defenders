// Package instrumentation provides AITF instrumentation for AI operations.
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

const llmTracerName = "instrumentation.llm"

// LLMInstrumentor traces LLM inference operations.
type LLMInstrumentor struct {
	tracer trace.Tracer
}

// NewLLMInstrumentor creates a new LLM instrumentor.
func NewLLMInstrumentor(tp trace.TracerProvider) *LLMInstrumentor {
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	return &LLMInstrumentor{
		tracer: tp.Tracer(llmTracerName),
	}
}

// InferenceConfig holds configuration for an inference span.
type InferenceConfig struct {
	Model       string
	System      string
	Operation   string
	Temperature *float64
	MaxTokens   *int
	Stream      bool
	Tools       []string
}

// InferenceSpan provides methods for recording inference attributes.
type InferenceSpan struct {
	span      trace.Span
	startTime time.Time
}

// TraceInference starts a new inference span. The caller must call End() when done.
func (l *LLMInstrumentor) TraceInference(ctx context.Context, cfg InferenceConfig) (context.Context, *InferenceSpan) {
	if cfg.Operation == "" {
		cfg.Operation = semconv.GenAIOperationChat
	}
	if cfg.System == "" {
		cfg.System = semconv.GenAISystemOpenAI
	}

	spanName := fmt.Sprintf("%s %s", cfg.Operation, cfg.Model)
	attrs := []attribute.KeyValue{
		semconv.GenAISystemKey.String(cfg.System),
		semconv.GenAIOperationNameKey.String(cfg.Operation),
		semconv.GenAIRequestModelKey.String(cfg.Model),
	}
	if cfg.Temperature != nil {
		attrs = append(attrs, semconv.GenAIRequestTemperatureKey.Float64(*cfg.Temperature))
	}
	if cfg.MaxTokens != nil {
		attrs = append(attrs, semconv.GenAIRequestMaxTokensKey.Int(*cfg.MaxTokens))
	}
	if cfg.Stream {
		attrs = append(attrs, semconv.GenAIRequestStreamKey.Bool(true))
	}

	ctx, span := l.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)

	return ctx, &InferenceSpan{span: span, startTime: time.Now()}
}

// SetPrompt records the prompt content as an event.
func (s *InferenceSpan) SetPrompt(prompt string) {
	s.span.AddEvent("gen_ai.content.prompt",
		trace.WithAttributes(semconv.GenAIPromptKey.String(prompt)),
	)
}

// SetCompletion records the completion content as an event.
func (s *InferenceSpan) SetCompletion(completion string) {
	s.span.AddEvent("gen_ai.content.completion",
		trace.WithAttributes(semconv.GenAICompletionKey.String(completion)),
	)
}

// SetUsage sets token usage attributes.
func (s *InferenceSpan) SetUsage(inputTokens, outputTokens int) {
	s.span.SetAttributes(
		semconv.GenAIUsageInputTokensKey.Int(inputTokens),
		semconv.GenAIUsageOutputTokensKey.Int(outputTokens),
	)
}

// SetResponse sets response attributes.
func (s *InferenceSpan) SetResponse(id, model string, finishReasons []string) {
	if id != "" {
		s.span.SetAttributes(semconv.GenAIResponseIDKey.String(id))
	}
	if model != "" {
		s.span.SetAttributes(semconv.GenAIResponseModelKey.String(model))
	}
}

// SetCost sets cost attributes.
func (s *InferenceSpan) SetCost(inputCost, outputCost, totalCost float64) {
	s.span.SetAttributes(
		semconv.CostInputCostKey.Float64(inputCost),
		semconv.CostOutputCostKey.Float64(outputCost),
		semconv.CostTotalCostKey.Float64(totalCost),
	)
}

// SetLatency sets latency metrics.
func (s *InferenceSpan) SetLatency(totalMs float64, tokensPerSecond *float64) {
	s.span.SetAttributes(semconv.LatencyTotalMsKey.Float64(totalMs))
	if tokensPerSecond != nil {
		s.span.SetAttributes(semconv.LatencyTokensPerSecondKey.Float64(*tokensPerSecond))
	}
}

// MarkFirstToken records the time-to-first-token.
func (s *InferenceSpan) MarkFirstToken() {
	ttft := float64(time.Since(s.startTime).Milliseconds())
	s.span.SetAttributes(semconv.LatencyTimeToFirstTokenMsKey.Float64(ttft))
}

// SetToolCall records a tool call event.
func (s *InferenceSpan) SetToolCall(name, callID, arguments string) {
	s.span.AddEvent("gen_ai.tool.call", trace.WithAttributes(
		semconv.GenAIToolNameKey.String(name),
		semconv.GenAIToolCallIDKey.String(callID),
		semconv.GenAIToolArgumentsKey.String(arguments),
	))
}

// End completes the inference span.
func (s *InferenceSpan) End(err error) {
	if err != nil {
		s.span.SetStatus(codes.Error, err.Error())
		s.span.RecordError(err)
	} else {
		s.span.SetStatus(codes.Ok, "")
	}
	totalMs := float64(time.Since(s.startTime).Milliseconds())
	s.span.SetAttributes(semconv.LatencyTotalMsKey.Float64(totalMs))
	s.span.End()
}

// Span returns the underlying OTel span.
func (s *InferenceSpan) Span() trace.Span { return s.span }
