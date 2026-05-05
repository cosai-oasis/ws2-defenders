// Package exporters provides AITF span exporters for Go.
//
// CEFSyslogExporter converts OTel spans to CEF (Common Event Format)
// syslog messages and sends them to any SIEM that supports CEF ingestion,
// including vendors that do not support OCSF natively (ArcSight, QRadar,
// LogRhythm, Elastic Security, etc.).
package exporters

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/girdav01/AITF/sdk/go/ocsf"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// CEF severity mapping from OCSF severity_id.
var ocsfToCEFSeverity = map[int]int{
	0: 0,  // Unknown
	1: 1,  // Informational
	2: 3,  // Low
	3: 5,  // Medium
	4: 7,  // High
	5: 9,  // Critical
	6: 10, // Fatal
}

var classUIDToName = map[int]string{
	7001: "AI Model Inference",
	7002: "AI Agent Activity",
	7003: "AI Tool Execution",
	7004: "AI Data Retrieval",
	7005: "AI Security Finding",
	7006: "AI Supply Chain Event",
	7007: "AI Governance Event",
	7008: "AI Identity Event",
	7009: "AI Model Operations Event",
	7010: "AI Asset Inventory Event",
}

// sanitizeCEFValue escapes special characters in CEF extension values.
func sanitizeCEFValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `|`, `\|`)
	value = strings.ReplaceAll(value, `=`, `\=`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, "\r", `\r`)
	return value
}

// sanitizeCEFHeader escapes special characters in CEF header fields.
func sanitizeCEFHeader(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `|`, `\|`)
	return value
}

// OCSFEventToCEF converts an OCSF event map to a CEF syslog message string.
func OCSFEventToCEF(event map[string]interface{}, vendor, product, version string) string {
	classUID := getInt(event, "class_uid", 0)
	activityID := getInt(event, "activity_id", 0)
	typeUID := getInt(event, "type_uid", classUID*100+activityID)
	severityID := getInt(event, "severity_id", 1)

	signatureID := fmt.Sprintf("%d", typeUID)
	name, ok := classUIDToName[classUID]
	if !ok {
		name = fmt.Sprintf("OCSF-%d", classUID)
	}
	cefSeverity := ocsfToCEFSeverity[severityID]

	var ext []string

	// Timestamp
	eventTime := getString(event, "time", time.Now().UTC().Format(time.RFC3339))
	ext = append(ext, fmt.Sprintf("rt=%s", sanitizeCEFValue(eventTime)))

	// Message
	if msg := getString(event, "message", ""); msg != "" {
		ext = append(ext, fmt.Sprintf("msg=%s", sanitizeCEFValue(msg)))
	}

	// OCSF identifiers
	ext = append(ext, fmt.Sprintf("cs1=%d", classUID))
	ext = append(ext, "cs1Label=ocsf_class_uid")
	ext = append(ext, fmt.Sprintf("cs2=%d", activityID))
	ext = append(ext, "cs2Label=ocsf_activity_id")
	ext = append(ext, fmt.Sprintf("cs3=%d", getInt(event, "category_uid", 7)))
	ext = append(ext, "cs3Label=ocsf_category_uid")

	// Model information
	if modelInfo, ok := event["model"].(map[string]interface{}); ok {
		if modelID := getString(modelInfo, "model_id", ""); modelID != "" {
			ext = append(ext, fmt.Sprintf("cs4=%s", sanitizeCEFValue(modelID)))
			ext = append(ext, "cs4Label=ai_model_id")
		}
		if provider := getString(modelInfo, "provider", ""); provider != "" {
			ext = append(ext, fmt.Sprintf("cs5=%s", sanitizeCEFValue(provider)))
			ext = append(ext, "cs5Label=ai_provider")
		}
	}

	// Agent name
	if agentName := getString(event, "agent_name", ""); agentName != "" {
		ext = append(ext, fmt.Sprintf("suser=%s", sanitizeCEFValue(agentName)))
	}

	// Tool name
	if toolName := getString(event, "tool_name", ""); toolName != "" {
		ext = append(ext, fmt.Sprintf("cs6=%s", sanitizeCEFValue(toolName)))
		ext = append(ext, "cs6Label=ai_tool_name")
	}

	// Security finding
	if finding, ok := event["finding"].(map[string]interface{}); ok {
		if ft := getString(finding, "finding_type", ""); ft != "" {
			ext = append(ext, fmt.Sprintf("cat=%s", sanitizeCEFValue(ft)))
		}
		if rs, ok := finding["risk_score"]; ok {
			ext = append(ext, fmt.Sprintf("cn1=%v", rs))
			ext = append(ext, "cn1Label=risk_score")
		}
		if owasp := getString(finding, "owasp_category", ""); owasp != "" {
			ext = append(ext, fmt.Sprintf("flexString1=%s", sanitizeCEFValue(owasp)))
			ext = append(ext, "flexString1Label=owasp_category")
		}
	}

	// Token usage
	if usage, ok := event["usage"].(map[string]interface{}); ok {
		if it, ok := usage["input_tokens"]; ok {
			ext = append(ext, fmt.Sprintf("cn2=%v", it))
			ext = append(ext, "cn2Label=input_tokens")
		}
		if ot, ok := usage["output_tokens"]; ok {
			ext = append(ext, fmt.Sprintf("cn3=%v", ot))
			ext = append(ext, "cn3Label=output_tokens")
		}
	}

	// Cost
	if cost, ok := event["cost"].(map[string]interface{}); ok {
		if tc, ok := cost["total_cost_usd"]; ok {
			ext = append(ext, fmt.Sprintf("cfp1=%v", tc))
			ext = append(ext, "cfp1Label=total_cost_usd")
		}
	}

	extensionStr := strings.Join(ext, " ")

	return fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
		sanitizeCEFHeader(vendor),
		sanitizeCEFHeader(product),
		sanitizeCEFHeader(version),
		signatureID,
		sanitizeCEFHeader(name),
		cefSeverity,
		extensionStr,
	)
}

// CEFSyslogExporter exports OTel spans as CEF syslog messages.
type CEFSyslogExporter struct {
	host          string
	port          int
	protocol      string
	useTLS        bool
	tlsConfig     *tls.Config
	vendor        string
	product       string
	version       string
	batchSize     int
	mapper        *ocsf.OCSFMapper
	conn          net.Conn
	connected     bool
	totalExported int
	mu            sync.Mutex
}

// CEFSyslogOption configures the CEFSyslogExporter.
type CEFSyslogOption func(*CEFSyslogExporter)

// WithCEFHost sets the syslog receiver host.
func WithCEFHost(host string) CEFSyslogOption {
	return func(e *CEFSyslogExporter) { e.host = host }
}

// WithCEFPort sets the syslog receiver port.
func WithCEFPort(port int) CEFSyslogOption {
	return func(e *CEFSyslogExporter) { e.port = port }
}

// WithCEFProtocol sets the transport protocol ("tcp" or "udp").
func WithCEFProtocol(protocol string) CEFSyslogOption {
	return func(e *CEFSyslogExporter) { e.protocol = strings.ToLower(protocol) }
}

// WithCEFTLS enables TLS for TCP connections.
func WithCEFTLS(enabled bool) CEFSyslogOption {
	return func(e *CEFSyslogExporter) { e.useTLS = enabled }
}

// WithCEFVendor sets the CEF DeviceVendor header field.
func WithCEFVendor(vendor string) CEFSyslogOption {
	return func(e *CEFSyslogExporter) { e.vendor = vendor }
}

// WithCEFProduct sets the CEF DeviceProduct header field.
func WithCEFProduct(product string) CEFSyslogOption {
	return func(e *CEFSyslogExporter) { e.product = product }
}

// NewCEFSyslogExporter creates a new CEF syslog exporter.
func NewCEFSyslogExporter(opts ...CEFSyslogOption) (*CEFSyslogExporter, error) {
	e := &CEFSyslogExporter{
		host:     "localhost",
		port:     514,
		protocol: "tcp",
		useTLS:   true,
		vendor:   "AITF",
		product:  "AI-Telemetry-Framework",
		version:  "1.0.0",
		mapper:   ocsf.NewOCSFMapper(),
	}
	for _, opt := range opts {
		opt(e)
	}

	if e.useTLS {
		e.tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	return e, nil
}

func (e *CEFSyslogExporter) connect() error {
	addr := fmt.Sprintf("%s:%d", e.host, e.port)

	switch e.protocol {
	case "tcp":
		if e.useTLS {
			conn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: 10 * time.Second},
				"tcp", addr, e.tlsConfig,
			)
			if err != nil {
				return fmt.Errorf("TLS connect to %s failed: %w", addr, err)
			}
			e.conn = conn
		} else {
			conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err != nil {
				return fmt.Errorf("TCP connect to %s failed: %w", addr, err)
			}
			e.conn = conn
		}
	case "udp":
		conn, err := net.DialTimeout("udp", addr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("UDP dial to %s failed: %w", addr, err)
		}
		e.conn = conn
	default:
		return fmt.Errorf("unsupported protocol: %q", e.protocol)
	}

	e.connected = true
	log.Printf("cef_syslog: connected to %s via %s%s",
		addr, strings.ToUpper(e.protocol),
		map[bool]string{true: "+TLS", false: ""}[e.useTLS && e.protocol == "tcp"],
	)
	return nil
}

func (e *CEFSyslogExporter) send(msg string) error {
	if !e.connected || e.conn == nil {
		if err := e.connect(); err != nil {
			return err
		}
	}

	data := []byte(msg)

	if e.protocol == "tcp" {
		// RFC 5425 octet-counting framing
		framed := fmt.Sprintf("%d %s", len(data), msg)
		_, err := e.conn.Write([]byte(framed))
		return err
	}
	// UDP: each datagram is one message
	_, err := e.conn.Write(data)
	return err
}

// ExportSpans converts spans to CEF and sends via syslog.
func (e *CEFSyslogExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	var messages []string

	for _, span := range spans {
		ocsfEvent := e.mapper.MapSpan(span)
		if ocsfEvent == nil {
			continue
		}

		eventBytes, err := json.Marshal(ocsfEvent)
		if err != nil {
			continue
		}

		var eventMap map[string]interface{}
		if err := json.Unmarshal(eventBytes, &eventMap); err != nil {
			continue
		}

		cefMsg := OCSFEventToCEF(eventMap, e.vendor, e.product, e.version)
		messages = append(messages, cefMsg)
	}

	if len(messages) == 0 {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, msg := range messages {
		if err := e.send(msg); err != nil {
			// Try reconnect once
			e.connected = false
			if err := e.connect(); err != nil {
				return fmt.Errorf("cef_syslog: send failed: %w", err)
			}
			if err := e.send(msg); err != nil {
				return fmt.Errorf("cef_syslog: send retry failed: %w", err)
			}
		}
		e.totalExported++
	}

	return nil
}

// Shutdown closes the syslog connection.
func (e *CEFSyslogExporter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}

// TotalExported returns the number of CEF messages sent.
func (e *CEFSyslogExporter) TotalExported() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.totalExported
}

// helper to extract string from map
func getString(m map[string]interface{}, key, defaultVal string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return defaultVal
}

// helper to extract int from map
func getInt(m map[string]interface{}, key string, defaultVal int) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case int64:
			return int(n)
		}
	}
	return defaultVal
}

// Compile-time check that CEFSyslogExporter implements SpanExporter.
var _ sdktrace.SpanExporter = (*CEFSyslogExporter)(nil)
