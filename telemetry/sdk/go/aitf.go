// Package aitf provides the AI Telemetry Framework SDK for Go.
//
// AITF is a comprehensive, security-first telemetry framework for AI systems
// built on OpenTelemetry and OCSF. It supports dual-pipeline export where the
// same spans flow to OTel backends (via OTLP) and SIEM/XDR (via OCSF)
// simultaneously.
//
// Dual Pipeline (recommended for production):
//
//	provider, _ := aitf.NewDualPipelineProvider(
//	    aitf.WithOTLPEndpoint("localhost:4317"),        // → Jaeger/Tempo
//	    aitf.WithOCSFOutputFile("/var/log/aitf.jsonl"), // → SIEM
//	)
//	defer provider.Shutdown(context.Background())
//
//	instrumentor := aitf.NewInstrumentor(
//	    aitf.WithTracerProvider(provider.TracerProvider()),
//	)
//	instrumentor.InstrumentAll()
//
// OTel-Only:
//
//	provider, _ := aitf.NewOTelOnlyProvider("localhost:4317")
//
// OCSF-Only:
//
//	provider, _ := aitf.NewOCSFOnlyProvider("/var/log/aitf.jsonl")
package aitf

import (
	"go.opentelemetry.io/otel/trace"
)

const Version = "1.0.0"

// Instrumentor manages all AITF sub-instrumentors.
type Instrumentor struct {
	tp     trace.TracerProvider
	LLM    *LLMInstrumentor
	Agent  *AgentInstrumentor
	MCP    *MCPInstrumentor
	RAG    *RAGInstrumentor
	Skills *SkillInstrumentor
}

// NewInstrumentor creates a new AITF instrumentor.
// If tp is nil, the global TracerProvider is used.
func NewInstrumentor(opts ...Option) *Instrumentor {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt.apply(&cfg)
	}

	return &Instrumentor{
		tp:     cfg.TracerProvider,
		LLM:    NewLLMInstrumentor(cfg.TracerProvider),
		Agent:  NewAgentInstrumentor(cfg.TracerProvider),
		MCP:    NewMCPInstrumentor(cfg.TracerProvider),
		RAG:    NewRAGInstrumentor(cfg.TracerProvider),
		Skills: NewSkillInstrumentor(cfg.TracerProvider),
	}
}

// InstrumentAll enables all AITF instrumentors.
func (i *Instrumentor) InstrumentAll() {
	i.LLM.Instrument()
	i.Agent.Instrument()
	i.MCP.Instrument()
	i.RAG.Instrument()
	i.Skills.Instrument()
}

// config holds instrumentor configuration.
type config struct {
	TracerProvider trace.TracerProvider
}

func defaultConfig() config {
	return config{}
}

// Option applies configuration to an Instrumentor.
type Option interface {
	apply(*config)
}

type optionFunc func(*config)

func (f optionFunc) apply(c *config) { f(c) }

// WithTracerProvider sets the TracerProvider.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return optionFunc(func(c *config) {
		c.TracerProvider = tp
	})
}
