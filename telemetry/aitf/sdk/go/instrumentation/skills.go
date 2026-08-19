package instrumentation

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

const skillsTracerName = "instrumentation.skills"

// SkillInstrumentor traces skill operations.
type SkillInstrumentor struct {
	tracer trace.Tracer
}

// NewSkillInstrumentor creates a new skill instrumentor.
func NewSkillInstrumentor(tp trace.TracerProvider) *SkillInstrumentor {
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	return &SkillInstrumentor{tracer: tp.Tracer(skillsTracerName)}
}

// SkillConfig holds configuration for a skill invocation.
type SkillConfig struct {
	Name        string
	Version     string
	ID          string
	Provider    string
	Category    string
	Description string
	Input       string
	Source      string
}

// SkillInvocation manages a skill invocation span.
type SkillInvocation struct {
	span      trace.Span
	startTime time.Time
	statusSet bool
}

// TraceInvoke starts a skill invocation span.
func (s *SkillInstrumentor) TraceInvoke(ctx context.Context, cfg SkillConfig) (context.Context, *SkillInvocation) {
	if cfg.Version == "" {
		cfg.Version = "1.0.0"
	}
	if cfg.Provider == "" {
		cfg.Provider = "custom"
	}

	attrs := []trace.SpanStartOption{
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			semconv.SkillNameKey.String(cfg.Name),
			semconv.SkillVersionKey.String(cfg.Version),
			semconv.SkillProviderKey.String(cfg.Provider),
		),
	}

	if cfg.ID != "" {
		attrs = append(attrs, trace.WithAttributes(semconv.SkillIDKey.String(cfg.ID)))
	}
	if cfg.Category != "" {
		attrs = append(attrs, trace.WithAttributes(semconv.SkillCategoryKey.String(cfg.Category)))
	}
	if cfg.Input != "" {
		attrs = append(attrs, trace.WithAttributes(semconv.SkillInputKey.String(cfg.Input)))
	}
	if cfg.Source != "" {
		attrs = append(attrs, trace.WithAttributes(semconv.SkillSourceKey.String(cfg.Source)))
	}

	ctx, span := s.tracer.Start(ctx, fmt.Sprintf("skill.invoke %s", cfg.Name), attrs...)
	return ctx, &SkillInvocation{span: span, startTime: time.Now()}
}

// TraceDiscover starts a skill discovery span.
func (s *SkillInstrumentor) TraceDiscover(ctx context.Context, source string) (context.Context, trace.Span) {
	ctx, span := s.tracer.Start(ctx,
		fmt.Sprintf("skill.discover %s", source),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.SkillSourceKey.String(source)),
	)
	return ctx, span
}

// SetOutput sets the skill output.
func (si *SkillInvocation) SetOutput(output string) {
	si.span.SetAttributes(semconv.SkillOutputKey.String(output))
	si.span.AddEvent("skill.output", trace.WithAttributes(
		semconv.SkillOutputKey.String(output),
	))
}

// SetStatus sets the skill execution status.
func (si *SkillInvocation) SetStatus(status string) {
	si.span.SetAttributes(semconv.SkillStatusKey.String(status))
	si.statusSet = true
}

// End completes the skill invocation span.
func (si *SkillInvocation) End(err error) {
	duration := float64(time.Since(si.startTime).Milliseconds())
	si.span.SetAttributes(semconv.SkillDurationMsKey.Float64(duration))
	if !si.statusSet {
		if err != nil {
			si.span.SetAttributes(semconv.SkillStatusKey.String(semconv.SkillStatusError))
		} else {
			si.span.SetAttributes(semconv.SkillStatusKey.String(semconv.SkillStatusSuccess))
		}
	}
	if err != nil {
		si.span.SetStatus(codes.Error, err.Error())
		si.span.RecordError(err)
	} else {
		si.span.SetStatus(codes.Ok, "")
	}
	si.span.End()
}

// Span returns the underlying OTel span.
func (si *SkillInvocation) Span() trace.Span { return si.span }
