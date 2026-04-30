// Package exporters provides AITF span exporters for Go.
//
// The OCSFExporter converts OTel spans to OCSF Category 7 AI events
// and exports them to SIEM/XDR endpoints or local JSONL files.
package exporters

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/girdav01/AITF/sdk/go/ocsf"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// devHosts are localhost addresses where HTTP is allowed for development.
var devHosts = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"::1":       true,
}

// OCSFExporter exports OTel spans as OCSF Category 7 AI events.
// Implements the sdktrace.SpanExporter interface.
type OCSFExporter struct {
	endpoint       string
	outputFile     string
	includeRawSpan bool
	apiKey         string
	mapper         *ocsf.OCSFMapper
	compliance     *ocsf.ComplianceMapper
	eventCount     int
	mu             sync.Mutex
	client         *http.Client
}

// OCSFExporterOption configures the OCSFExporter.
type OCSFExporterOption func(*OCSFExporter)

// WithEndpoint sets the HTTP endpoint for OCSF event export.
func WithEndpoint(endpoint string) OCSFExporterOption {
	return func(e *OCSFExporter) { e.endpoint = endpoint }
}

// WithOutputFile sets the JSONL file path for OCSF event export.
func WithOutputFile(path string) OCSFExporterOption {
	return func(e *OCSFExporter) { e.outputFile = path }
}

// WithComplianceFrameworks sets the compliance frameworks for enrichment.
func WithComplianceFrameworks(frameworks []string) OCSFExporterOption {
	return func(e *OCSFExporter) {
		e.compliance = ocsf.NewComplianceMapper(frameworks)
	}
}

// WithIncludeRawSpan includes the raw OTel span data in the export.
func WithIncludeRawSpan(include bool) OCSFExporterOption {
	return func(e *OCSFExporter) { e.includeRawSpan = include }
}

// WithAPIKey sets the API key for authenticated HTTP export.
func WithAPIKey(key string) OCSFExporterOption {
	return func(e *OCSFExporter) { e.apiKey = key }
}

// validateEndpoint validates the endpoint URL for security.
// Enforces HTTPS when API key is present and not localhost.
func validateEndpoint(endpoint, apiKey string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme '%s'; only http and https are allowed", u.Scheme)
	}

	hostname := u.Hostname()
	isDev := devHosts[hostname]

	// Enforce HTTPS when API key is present and not localhost
	if apiKey != "" && u.Scheme != "https" && !isDev {
		return fmt.Errorf("HTTPS is required when using API key authentication; use https:// or localhost for development")
	}

	return nil
}

// validateOutputPath validates the output file path to prevent path traversal.
func validateOutputPath(outputFile string) (string, error) {
	// Check for path traversal
	if strings.Contains(outputFile, "..") {
		return "", fmt.Errorf("path traversal detected in output path: %s", outputFile)
	}
	absPath, err := filepath.Abs(outputFile)
	if err != nil {
		return "", fmt.Errorf("failed to resolve output path: %w", err)
	}
	return absPath, nil
}

// NewOCSFExporter creates a new OCSF exporter.
func NewOCSFExporter(opts ...OCSFExporterOption) (*OCSFExporter, error) {
	e := &OCSFExporter{
		mapper:     ocsf.NewOCSFMapper(),
		compliance: ocsf.NewComplianceMapper(nil),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}
	for _, opt := range opts {
		opt(e)
	}

	// Validate endpoint URL
	if e.endpoint != "" {
		if err := validateEndpoint(e.endpoint, e.apiKey); err != nil {
			return nil, err
		}
	}

	// Validate and create output file path
	if e.outputFile != "" {
		absPath, err := validateOutputPath(e.outputFile)
		if err != nil {
			return nil, err
		}
		e.outputFile = absPath

		dir := filepath.Dir(e.outputFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory %s: %w", dir, err)
		}
	}

	return e, nil
}

// ExportSpans converts spans to OCSF events and exports them.
// Implements sdktrace.SpanExporter.
func (e *OCSFExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	var events []map[string]interface{}

	for _, span := range spans {
		ocsfEvent := e.mapper.MapSpan(span)
		if ocsfEvent == nil {
			continue
		}

		// Enrich with compliance metadata
		eventType := e.mapper.ClassifySpan(span)
		if eventType != "" {
			e.enrichCompliance(ocsfEvent, eventType)
		}

		// Serialize to map
		eventBytes, err := json.Marshal(ocsfEvent)
		if err != nil {
			log.Printf("ocsf: failed to marshal event: %v", err)
			continue
		}

		var eventMap map[string]interface{}
		if err := json.Unmarshal(eventBytes, &eventMap); err != nil {
			log.Printf("ocsf: failed to unmarshal event: %v", err)
			continue
		}

		events = append(events, eventMap)
		e.mu.Lock()
		e.eventCount++
		e.mu.Unlock()
	}

	if len(events) == 0 {
		return nil
	}

	// Export to configured destinations
	var exportErr error

	if e.outputFile != "" {
		if err := e.exportToFile(events); err != nil {
			log.Printf("ocsf: file export failed: %v", err)
			exportErr = err
		}
	}

	if e.endpoint != "" {
		if err := e.exportToEndpoint(ctx, events); err != nil {
			log.Printf("ocsf: endpoint export failed: %v", err)
			exportErr = err
		}
	}

	return exportErr
}

// Shutdown performs any cleanup. Implements sdktrace.SpanExporter.
func (e *OCSFExporter) Shutdown(ctx context.Context) error {
	return nil
}

// EventCount returns the total number of OCSF events exported.
func (e *OCSFExporter) EventCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.eventCount
}

// enrichCompliance adds compliance metadata to an OCSF event.
func (e *OCSFExporter) enrichCompliance(event interface{}, eventType string) {
	// Each concrete event type embeds AIBaseEvent. We handle the known types.
	switch ev := event.(type) {
	case *ocsf.AIModelInferenceEvent:
		e.compliance.EnrichEvent(&ev.AIBaseEvent, eventType)
	case *ocsf.AIAgentActivityEvent:
		e.compliance.EnrichEvent(&ev.AIBaseEvent, eventType)
	case *ocsf.AIToolExecutionEvent:
		e.compliance.EnrichEvent(&ev.AIBaseEvent, eventType)
	case *ocsf.AIDataRetrievalEvent:
		e.compliance.EnrichEvent(&ev.AIBaseEvent, eventType)
	case *ocsf.AISecurityFindingEvent:
		e.compliance.EnrichEvent(&ev.AIBaseEvent, eventType)
	case *ocsf.AISupplyChainEvent:
		e.compliance.EnrichEvent(&ev.AIBaseEvent, eventType)
	case *ocsf.AIGovernanceEvent:
		e.compliance.EnrichEvent(&ev.AIBaseEvent, eventType)
	case *ocsf.AIIdentityEvent:
		e.compliance.EnrichEvent(&ev.AIBaseEvent, eventType)
	}
}

// exportToFile writes OCSF events to a JSONL file.
func (e *OCSFExporter) exportToFile(events []map[string]interface{}) error {
	// Use restrictive file permissions (owner read/write only)
	f, err := os.OpenFile(e.outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}
	defer f.Close()

	for _, event := range events {
		line, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("failed to marshal event: %w", err)
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("failed to write event: %w", err)
		}
	}

	return nil
}

// exportToEndpoint sends OCSF events to an HTTP endpoint.
func (e *OCSFExporter) exportToEndpoint(ctx context.Context, events []map[string]interface{}) error {
	payload, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("failed to marshal events: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send to endpoint: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ocsf endpoint returned status %d", resp.StatusCode)
	}

	return nil
}

// Compile-time check that OCSFExporter implements SpanExporter.
var _ sdktrace.SpanExporter = (*OCSFExporter)(nil)
