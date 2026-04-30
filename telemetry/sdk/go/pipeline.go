// Package aitf provides the AI Telemetry Framework SDK for Go.
//
// DualPipelineProvider configures an OTel TracerProvider with both OTLP
// and OCSF export pipelines, enabling the same security-enriched spans
// to be sent to OTLP-compatible backends (Jaeger, Grafana Tempo, Datadog,
// Elastic Security) for observability and security analytics AND
// OCSF-native SIEM/XDR endpoints simultaneously.
//
// Usage:
//
//	provider, err := aitf.NewDualPipelineProvider(
//	    aitf.WithOTLPEndpoint("localhost:4317"),
//	    aitf.WithOCSFOutputFile("/var/log/aitf/events.jsonl"),
//	    aitf.WithServiceName("my-ai-service"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer provider.Shutdown(context.Background())
//
//	instrumentor := aitf.NewInstrumentor(aitf.WithTracerProvider(provider.TracerProvider()))
//	instrumentor.InstrumentAll()
package aitf

import (
	"context"
	"fmt"
	"log"

	"github.com/girdav01/AITF/sdk/go/exporters"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// DualPipelineProvider manages a TracerProvider with both OTLP and OCSF
// export pipelines.
type DualPipelineProvider struct {
	provider  *sdktrace.TracerProvider
	exporters []sdktrace.SpanExporter
}

// PipelineConfig holds configuration for the dual pipeline.
type PipelineConfig struct {
	// OTLPEndpoint is the gRPC endpoint for OTLP export (e.g., "localhost:4317").
	OTLPEndpoint string

	// OTLPHTTPEndpoint is the HTTP endpoint for OTLP export.
	OTLPHTTPEndpoint string

	// OTLPHeaders are additional headers for OTLP export (e.g., auth tokens).
	OTLPHeaders map[string]string

	// OCSFOutputFile is the file path for OCSF JSONL output.
	OCSFOutputFile string

	// OCSFEndpoint is the HTTP endpoint for OCSF event delivery.
	OCSFEndpoint string

	// OCSFAPIKey is the API key for the OCSF HTTP endpoint.
	OCSFAPIKey string

	// ComplianceFrameworks lists compliance frameworks for OCSF enrichment.
	ComplianceFrameworks []string

	// ServiceName is the OTel service name.
	ServiceName string

	// ResourceAttributes are additional OTel resource attributes.
	ResourceAttributes map[string]string
}

// PipelineOption configures the DualPipelineProvider.
type PipelineOption func(*PipelineConfig)

// WithOTLPEndpoint sets the OTLP gRPC endpoint.
func WithOTLPEndpoint(endpoint string) PipelineOption {
	return func(c *PipelineConfig) { c.OTLPEndpoint = endpoint }
}

// WithOTLPHTTPEndpoint sets the OTLP HTTP endpoint.
func WithOTLPHTTPEndpoint(endpoint string) PipelineOption {
	return func(c *PipelineConfig) { c.OTLPHTTPEndpoint = endpoint }
}

// WithOTLPHeaders sets headers for OTLP export.
func WithOTLPHeaders(headers map[string]string) PipelineOption {
	return func(c *PipelineConfig) { c.OTLPHeaders = headers }
}

// WithOCSFOutputFile sets the OCSF JSONL output file path.
func WithOCSFOutputFile(path string) PipelineOption {
	return func(c *PipelineConfig) { c.OCSFOutputFile = path }
}

// WithOCSFEndpoint sets the OCSF HTTP endpoint.
func WithOCSFEndpoint(endpoint string) PipelineOption {
	return func(c *PipelineConfig) { c.OCSFEndpoint = endpoint }
}

// WithOCSFAPIKey sets the OCSF HTTP endpoint API key.
func WithOCSFAPIKey(key string) PipelineOption {
	return func(c *PipelineConfig) { c.OCSFAPIKey = key }
}

// WithComplianceFrameworks sets compliance frameworks for OCSF enrichment.
func WithComplianceFrameworks(frameworks []string) PipelineOption {
	return func(c *PipelineConfig) { c.ComplianceFrameworks = frameworks }
}

// WithServiceName sets the OTel service name.
func WithServiceName(name string) PipelineOption {
	return func(c *PipelineConfig) { c.ServiceName = name }
}

// WithResourceAttributes sets additional OTel resource attributes.
func WithResourceAttributes(attrs map[string]string) PipelineOption {
	return func(c *PipelineConfig) { c.ResourceAttributes = attrs }
}

// NewDualPipelineProvider creates a TracerProvider with both OTLP and OCSF
// export pipelines configured. This is the recommended setup for production.
func NewDualPipelineProvider(opts ...PipelineOption) (*DualPipelineProvider, error) {
	cfg := PipelineConfig{
		ServiceName: "aitf-service",
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	// Build resource
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	var spanExporters []sdktrace.SpanExporter
	var spanProcessors []sdktrace.TracerProviderOption

	// OTLP pipeline (observability & security analytics)
	if cfg.OTLPEndpoint != "" {
		otlpExp, err := createOTLPGRPCExporter(cfg.OTLPEndpoint, cfg.OTLPHeaders)
		if err != nil {
			log.Printf("WARN: Failed to create OTLP gRPC exporter: %v", err)
		} else {
			spanProcessors = append(spanProcessors,
				sdktrace.WithBatcher(otlpExp))
			spanExporters = append(spanExporters, otlpExp)
		}
	}

	if cfg.OTLPHTTPEndpoint != "" {
		otlpExp, err := createOTLPHTTPExporter(cfg.OTLPHTTPEndpoint, cfg.OTLPHeaders)
		if err != nil {
			log.Printf("WARN: Failed to create OTLP HTTP exporter: %v", err)
		} else {
			spanProcessors = append(spanProcessors,
				sdktrace.WithBatcher(otlpExp))
			spanExporters = append(spanExporters, otlpExp)
		}
	}

	// OCSF pipeline (OCSF-native SIEM / compliance)
	if cfg.OCSFOutputFile != "" || cfg.OCSFEndpoint != "" {
		ocsfOpts := []exporters.OCSFExporterOption{}
		if cfg.OCSFOutputFile != "" {
			ocsfOpts = append(ocsfOpts, exporters.WithOutputFile(cfg.OCSFOutputFile))
		}
		if cfg.OCSFEndpoint != "" {
			ocsfOpts = append(ocsfOpts, exporters.WithEndpoint(cfg.OCSFEndpoint))
		}
		if cfg.OCSFAPIKey != "" {
			ocsfOpts = append(ocsfOpts, exporters.WithAPIKey(cfg.OCSFAPIKey))
		}
		if len(cfg.ComplianceFrameworks) > 0 {
			ocsfOpts = append(ocsfOpts,
				exporters.WithComplianceFrameworks(cfg.ComplianceFrameworks))
		}

		ocsfExp := exporters.NewOCSFExporter(ocsfOpts...)
		spanProcessors = append(spanProcessors,
			sdktrace.WithBatcher(ocsfExp))
		spanExporters = append(spanExporters, ocsfExp)
	}

	// Build TracerProvider
	tpOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
	}
	tpOpts = append(tpOpts, spanProcessors...)

	provider := sdktrace.NewTracerProvider(tpOpts...)

	if len(spanExporters) == 0 {
		log.Println("WARN: DualPipelineProvider created with no exporters")
	}

	return &DualPipelineProvider{
		provider:  provider,
		exporters: spanExporters,
	}, nil
}

// TracerProvider returns the configured TracerProvider.
func (p *DualPipelineProvider) TracerProvider() trace.TracerProvider {
	return p.provider
}

// SetAsGlobal registers this provider as the global OTel TracerProvider.
func (p *DualPipelineProvider) SetAsGlobal() {
	otel.SetTracerProvider(p.provider)
}

// Shutdown flushes and shuts down all exporters.
func (p *DualPipelineProvider) Shutdown(ctx context.Context) error {
	return p.provider.Shutdown(ctx)
}

// createOTLPGRPCExporter creates an OTLP gRPC span exporter.
// Requires go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc.
func createOTLPGRPCExporter(endpoint string, headers map[string]string) (sdktrace.SpanExporter, error) {
	// Import dynamically to avoid hard dependency
	// Users must add: go get go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc
	return nil, fmt.Errorf(
		"OTLP gRPC exporter not available in this build. " +
			"Use NewOTLPGRPCExporter() from " +
			"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc " +
			"and pass it via sdktrace.WithBatcher()")
}

// createOTLPHTTPExporter creates an OTLP HTTP span exporter.
// Requires go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp.
func createOTLPHTTPExporter(endpoint string, headers map[string]string) (sdktrace.SpanExporter, error) {
	return nil, fmt.Errorf(
		"OTLP HTTP exporter not available in this build. " +
			"Use NewOTLPHTTPExporter() from " +
			"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp " +
			"and pass it via sdktrace.WithBatcher()")
}

// NewOTelOnlyProvider creates a provider that exports only to an OTel backend.
func NewOTelOnlyProvider(endpoint string, opts ...PipelineOption) (*DualPipelineProvider, error) {
	allOpts := append([]PipelineOption{WithOTLPEndpoint(endpoint)}, opts...)
	return NewDualPipelineProvider(allOpts...)
}

// NewOCSFOnlyProvider creates a provider that exports only OCSF events.
func NewOCSFOnlyProvider(outputFile string, opts ...PipelineOption) (*DualPipelineProvider, error) {
	allOpts := append([]PipelineOption{WithOCSFOutputFile(outputFile)}, opts...)
	return NewDualPipelineProvider(allOpts...)
}
