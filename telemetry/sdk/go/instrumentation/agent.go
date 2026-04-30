package instrumentation

import (
	"context"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

const agentTracerName = "instrumentation.agent"

// AgentInstrumentor traces AI agent operations.
type AgentInstrumentor struct {
	tracer trace.Tracer
}

// NewAgentInstrumentor creates a new agent instrumentor.
func NewAgentInstrumentor(tp trace.TracerProvider) *AgentInstrumentor {
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	return &AgentInstrumentor{tracer: tp.Tracer(agentTracerName)}
}

// SessionConfig configures an agent session span.
type SessionConfig struct {
	AgentName   string
	AgentID     string
	AgentType   string
	Framework   string
	Version     string
	Description string
	SessionID   string
	TeamName    string
}

// AgentSession manages spans within an agent session.
type AgentSession struct {
	span      trace.Span
	tracer    trace.Tracer
	agentName string
	sessionID string
	stepCount int
	mu        sync.Mutex
}

// TraceSession starts an agent session span.
func (a *AgentInstrumentor) TraceSession(ctx context.Context, cfg SessionConfig) (context.Context, *AgentSession) {
	if cfg.AgentType == "" {
		cfg.AgentType = semconv.AgentTypeAutonomous
	}
	if cfg.Framework == "" {
		cfg.Framework = semconv.AgentFrameworkCustom
	}

	attrs := []attribute.KeyValue{
		semconv.AgentNameKey.String(cfg.AgentName),
		semconv.AgentIDKey.String(cfg.AgentID),
		semconv.AgentTypeKey.String(cfg.AgentType),
		semconv.AgentFrameworkKey.String(cfg.Framework),
		semconv.AgentSessionIDKey.String(cfg.SessionID),
	}
	if cfg.Version != "" {
		attrs = append(attrs, semconv.AgentVersionKey.String(cfg.Version))
	}
	if cfg.Description != "" {
		attrs = append(attrs, semconv.AgentDescriptionKey.String(cfg.Description))
	}
	if cfg.TeamName != "" {
		attrs = append(attrs, semconv.AgentTeamNameKey.String(cfg.TeamName))
	}

	ctx, span := a.tracer.Start(ctx,
		fmt.Sprintf("agent.session %s", cfg.AgentName),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)

	return ctx, &AgentSession{
		span:      span,
		tracer:    a.tracer,
		agentName: cfg.AgentName,
		sessionID: cfg.SessionID,
	}
}

// Step starts an agent step span as a child of the session.
func (s *AgentSession) Step(ctx context.Context, stepType string) (context.Context, *AgentStep) {
	s.mu.Lock()
	s.stepCount++
	currentStep := s.stepCount
	s.mu.Unlock()

	attrs := []attribute.KeyValue{
		semconv.AgentNameKey.String(s.agentName),
		semconv.AgentStepTypeKey.String(stepType),
		semconv.AgentStepIndexKey.Int(currentStep),
	}

	ctx, span := s.tracer.Start(ctx,
		fmt.Sprintf("agent.step.%s %s", stepType, s.agentName),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)

	return ctx, &AgentStep{span: span}
}

// Delegate starts a delegation span.
func (s *AgentSession) Delegate(ctx context.Context, targetAgent, targetAgentID, reason, strategy string) (context.Context, trace.Span) {
	s.mu.Lock()
	s.stepCount++
	currentStep := s.stepCount
	s.mu.Unlock()

	attrs := []attribute.KeyValue{
		semconv.AgentNameKey.String(s.agentName),
		semconv.AgentStepTypeKey.String(semconv.AgentStepDelegation),
		semconv.AgentStepIndexKey.Int(currentStep),
		semconv.AgentDelegationTargetAgentKey.String(targetAgent),
		semconv.AgentDelegationTargetAgentIDKey.String(targetAgentID),
		semconv.AgentDelegationStrategyKey.String(strategy),
	}
	if reason != "" {
		attrs = append(attrs, semconv.AgentDelegationReasonKey.String(reason))
	}

	ctx, span := s.tracer.Start(ctx,
		fmt.Sprintf("agent.delegate %s -> %s", s.agentName, targetAgent),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)
	return ctx, span
}

// End completes the session span.
func (s *AgentSession) End(err error) {
	s.mu.Lock()
	steps := s.stepCount
	s.mu.Unlock()

	s.span.SetAttributes(semconv.AgentSessionTurnCountKey.Int(steps))
	if err != nil {
		s.span.SetStatus(codes.Error, err.Error())
		s.span.RecordError(err)
	} else {
		s.span.SetStatus(codes.Ok, "")
	}
	s.span.End()
}

// Span returns the underlying OTel span.
func (s *AgentSession) Span() trace.Span { return s.span }

// AgentStep provides methods for setting step attributes.
type AgentStep struct {
	span trace.Span
}

// SetThought sets the agent's reasoning.
func (s *AgentStep) SetThought(thought string) {
	s.span.SetAttributes(semconv.AgentStepThoughtKey.String(thought))
}

// SetAction sets the planned action.
func (s *AgentStep) SetAction(action string) {
	s.span.SetAttributes(semconv.AgentStepActionKey.String(action))
}

// SetObservation sets the observation result.
func (s *AgentStep) SetObservation(observation string) {
	s.span.SetAttributes(semconv.AgentStepObservationKey.String(observation))
}

// End completes the step span.
func (s *AgentStep) End(err error) {
	if err != nil {
		s.span.SetStatus(codes.Error, err.Error())
		s.span.RecordError(err)
	} else {
		s.span.SetStatus(codes.Ok, "")
	}
	s.span.End()
}

// Span returns the underlying OTel span.
func (s *AgentStep) Span() trace.Span { return s.span }
