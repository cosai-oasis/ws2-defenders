package instrumentation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

const agenticLogTracerName = "instrumentation.agentic_log"

// AgenticLogInstrumentor traces agentic log entries (Table 10.1 minimal fields).
type AgenticLogInstrumentor struct {
	tracer trace.Tracer
}

// NewAgenticLogInstrumentor creates a new agentic log instrumentor.
func NewAgenticLogInstrumentor(tp trace.TracerProvider) *AgenticLogInstrumentor {
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	return &AgenticLogInstrumentor{tracer: tp.Tracer(agenticLogTracerName)}
}

// AgenticLogConfig configures an agentic log entry span.
type AgenticLogConfig struct {
	// Required fields
	AgentID   string
	SessionID string

	// Optional fields (auto-generated if empty)
	EventID string

	// Optional fields set at creation time
	GoalID          string
	SubTaskID       string
	ToolUsed        string
	ToolParameters  string
	ConfidenceScore *float64
	AnomalyScore    *float64
}

// AgenticLogEntry provides methods for setting agentic log attributes on a span.
type AgenticLogEntry struct {
	span      trace.Span
	eventID   string
	timestamp string
}

// LogAction starts an agentic log entry span.
func (a *AgenticLogInstrumentor) LogAction(ctx context.Context, cfg AgenticLogConfig) (context.Context, *AgenticLogEntry) {
	eventID := cfg.EventID
	if eventID == "" {
		eventID = fmt.Sprintf("e-%s", generateShortID())
	}
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	attrs := []attribute.KeyValue{
		semconv.AgenticLogEventIDKey.String(eventID),
		semconv.AgenticLogTimestampKey.String(timestamp),
		semconv.AgenticLogAgentIDKey.String(cfg.AgentID),
		semconv.AgenticLogSessionIDKey.String(cfg.SessionID),
	}

	if cfg.GoalID != "" {
		attrs = append(attrs, semconv.AgenticLogGoalIDKey.String(cfg.GoalID))
	}
	if cfg.SubTaskID != "" {
		attrs = append(attrs, semconv.AgenticLogSubTaskIDKey.String(cfg.SubTaskID))
	}
	if cfg.ToolUsed != "" {
		attrs = append(attrs, semconv.AgenticLogToolUsedKey.String(cfg.ToolUsed))
	}
	if cfg.ToolParameters != "" {
		attrs = append(attrs, semconv.AgenticLogToolParametersKey.String(cfg.ToolParameters))
	}
	if cfg.ConfidenceScore != nil {
		attrs = append(attrs, semconv.AgenticLogConfidenceScoreKey.Float64(*cfg.ConfidenceScore))
	}
	if cfg.AnomalyScore != nil {
		attrs = append(attrs, semconv.AgenticLogAnomalyScoreKey.Float64(*cfg.AnomalyScore))
	}

	ctx, span := a.tracer.Start(ctx,
		fmt.Sprintf("agentic_log %s", cfg.AgentID),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attrs...),
	)

	return ctx, &AgenticLogEntry{
		span:      span,
		eventID:   eventID,
		timestamp: timestamp,
	}
}

// SetGoalID sets the high-level goal the agent is pursuing.
func (e *AgenticLogEntry) SetGoalID(goalID string) {
	e.span.SetAttributes(semconv.AgenticLogGoalIDKey.String(goalID))
}

// SetSubTaskID sets the specific, immediate task the agent is performing.
func (e *AgenticLogEntry) SetSubTaskID(subTaskID string) {
	e.span.SetAttributes(semconv.AgenticLogSubTaskIDKey.String(subTaskID))
}

// SetToolUsed sets the specific tool, function, or API being invoked.
func (e *AgenticLogEntry) SetToolUsed(toolUsed string) {
	e.span.SetAttributes(semconv.AgenticLogToolUsedKey.String(toolUsed))
}

// SetToolParameters sets the sanitized tool parameters as a JSON string.
func (e *AgenticLogEntry) SetToolParameters(parameters string) {
	e.span.SetAttributes(semconv.AgenticLogToolParametersKey.String(parameters))
}

// SetToolParametersMap sets the sanitized tool parameters from a map.
func (e *AgenticLogEntry) SetToolParametersMap(parameters map[string]interface{}) {
	data, err := json.Marshal(parameters)
	if err != nil {
		e.span.SetAttributes(semconv.AgenticLogToolParametersKey.String(fmt.Sprintf("%v", parameters)))
		return
	}
	e.span.SetAttributes(semconv.AgenticLogToolParametersKey.String(string(data)))
}

// SetOutcome sets the result of the action.
func (e *AgenticLogEntry) SetOutcome(outcome string) {
	e.span.SetAttributes(semconv.AgenticLogOutcomeKey.String(outcome))
}

// SetConfidenceScore sets the agent's success likelihood assessment (0.0-1.0).
func (e *AgenticLogEntry) SetConfidenceScore(score float64) {
	e.span.SetAttributes(semconv.AgenticLogConfidenceScoreKey.Float64(score))
}

// SetAnomalyScore sets the anomaly score (0.0-1.0).
func (e *AgenticLogEntry) SetAnomalyScore(score float64) {
	e.span.SetAttributes(semconv.AgenticLogAnomalyScoreKey.Float64(score))
}

// SetPolicyEvaluation sets the policy evaluation record as a JSON string.
func (e *AgenticLogEntry) SetPolicyEvaluation(evaluation string) {
	e.span.SetAttributes(semconv.AgenticLogPolicyEvaluationKey.String(evaluation))
}

// SetPolicyEvaluationMap sets the policy evaluation record from a map.
func (e *AgenticLogEntry) SetPolicyEvaluationMap(evaluation map[string]interface{}) {
	data, err := json.Marshal(evaluation)
	if err != nil {
		e.span.SetAttributes(semconv.AgenticLogPolicyEvaluationKey.String(fmt.Sprintf("%v", evaluation)))
		return
	}
	e.span.SetAttributes(semconv.AgenticLogPolicyEvaluationKey.String(string(data)))
}

// EventID returns the event ID for this log entry.
func (e *AgenticLogEntry) EventID() string { return e.eventID }

// Timestamp returns the timestamp for this log entry.
func (e *AgenticLogEntry) Timestamp() string { return e.timestamp }

// Span returns the underlying OTel span.
func (e *AgenticLogEntry) Span() trace.Span { return e.span }

// End completes the agentic log entry span.
func (e *AgenticLogEntry) End(err error) {
	if err != nil {
		e.span.SetStatus(codes.Error, err.Error())
		e.span.RecordError(err)
		e.span.SetAttributes(semconv.AgenticLogOutcomeKey.String(semconv.AgenticLogOutcomeError))
	} else {
		e.span.SetStatus(codes.Ok, "")
	}
	e.span.End()
}

// generateShortID generates an 8-character hex ID.
func generateShortID() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("%08x", now&0xFFFFFFFF)
}
