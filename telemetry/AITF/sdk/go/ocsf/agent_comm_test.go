package ocsf

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

// makeSpan creates a real ReadOnlySpan with the given name and attributes by
// recording it through an SDK tracer.
func makeSpan(t *testing.T, name string, attrs map[string]interface{}) sdktrace.ReadOnlySpan {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	tr := tp.Tracer("test")

	kvs := make([]attribute.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		switch val := v.(type) {
		case string:
			kvs = append(kvs, attribute.String(k, val))
		case int:
			kvs = append(kvs, attribute.Int(k, val))
		case int64:
			kvs = append(kvs, attribute.Int64(k, val))
		case float64:
			kvs = append(kvs, attribute.Float64(k, val))
		case bool:
			kvs = append(kvs, attribute.Bool(k, val))
		case []string:
			kvs = append(kvs, attribute.StringSlice(k, val))
		default:
			t.Fatalf("unsupported attr type for %q", k)
		}
	}

	_, span := tr.Start(context.Background(), name)
	span.SetAttributes(kvs...)
	span.End()

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected 1 ended span, got %d", len(ended))
	}
	return ended[0]
}

// --- Protocol normalization & canonical status ---

func TestNormalizeAgentProtocolID(t *testing.T) {
	cases := []struct {
		protocol string
		want     int
	}{
		{"a2a", AgentProtocolIDA2A},
		{"ACP", AgentProtocolIDACP},
		{"anp", AgentProtocolIDANP},
		{"mcp", AgentProtocolIDMCP},
		{"something", AgentProtocolIDOther},
		{"", AgentProtocolIDUnknown},
	}
	for _, c := range cases {
		if got := NormalizeAgentProtocolID(c.protocol); got != c.want {
			t.Errorf("NormalizeAgentProtocolID(%q) = %d, want %d", c.protocol, got, c.want)
		}
	}
}

func TestCanonicalCommStatus(t *testing.T) {
	if got := CanonicalCommStatus(AgentProtocolIDA2A, "input-required"); got != "input_required" {
		t.Errorf("A2A input-required = %q, want input_required", got)
	}
	if got := CanonicalCommStatus(AgentProtocolIDA2A, "rejected"); got != "failed" {
		t.Errorf("A2A rejected = %q, want failed", got)
	}
	if got := CanonicalCommStatus(AgentProtocolIDACP, "in-progress"); got != "working" {
		t.Errorf("ACP in-progress = %q, want working", got)
	}
	if got := CanonicalCommStatus(AgentProtocolIDACP, "cancelled"); got != "canceled" {
		t.Errorf("ACP cancelled = %q, want canceled", got)
	}
}

// --- BuildAgentMessage ---

func TestBuildAgentMessageA2A(t *testing.T) {
	msg := BuildAgentMessage(map[string]interface{}{
		string(semconv.A2AProtocolVersionKey):   "0.2",
		string(semconv.A2ATransportKey):         "jsonrpc",
		string(semconv.A2AMethodKey):            "message/send",
		string(semconv.A2ATaskIDKey):            "task_1",
		string(semconv.A2ATaskStateKey):         "working",
		string(semconv.A2AMessagePartsCountKey): 2,
		string(semconv.A2AInteractionModeKey):   "stream",
		string(semconv.A2AAgentNameKey):         "planner",
		string(semconv.A2AAgentURLKey):          "https://p.example/a2a",
	})
	if msg == nil {
		t.Fatal("BuildAgentMessage returned nil")
	}
	if msg.ProtocolID != AgentProtocolIDA2A {
		t.Errorf("ProtocolID = %d, want %d", msg.ProtocolID, AgentProtocolIDA2A)
	}
	if msg.UnitType != "task" || msg.UnitUID != "task_1" {
		t.Errorf("unit = %q/%q, want task/task_1", msg.UnitType, msg.UnitUID)
	}
	if msg.Status != "working" {
		t.Errorf("Status = %q, want working", msg.Status)
	}
	if msg.Direction != "stream" {
		t.Errorf("Direction = %q, want stream", msg.Direction)
	}
	if msg.Transport != "jsonrpc" {
		t.Errorf("Transport = %q, want jsonrpc", msg.Transport)
	}
	if msg.DstAgent == nil || msg.DstAgent.Name != "planner" {
		t.Errorf("DstAgent = %+v, want name planner", msg.DstAgent)
	}
	if msg.PeerEndpoint != "https://p.example/a2a" {
		t.Errorf("PeerEndpoint = %q", msg.PeerEndpoint)
	}
}

func TestBuildAgentMessageACP(t *testing.T) {
	msg := BuildAgentMessage(map[string]interface{}{
		string(semconv.ACPRunIDKey):     "run_9",
		string(semconv.ACPRunStatusKey): "in-progress",
		string(semconv.ACPRunModeKey):   "async",
		string(semconv.ACPOperationKey): "runs.create",
		string(semconv.ACPHTTPURLKey):   "https://acp.example/runs",
	})
	if msg == nil {
		t.Fatal("BuildAgentMessage returned nil")
	}
	if msg.ProtocolID != AgentProtocolIDACP {
		t.Errorf("ProtocolID = %d, want %d", msg.ProtocolID, AgentProtocolIDACP)
	}
	if msg.UnitType != "run" || msg.UnitUID != "run_9" {
		t.Errorf("unit = %q/%q, want run/run_9", msg.UnitType, msg.UnitUID)
	}
	if msg.Status != "working" { // in-progress -> working
		t.Errorf("Status = %q, want working", msg.Status)
	}
	if msg.Transport != "http" {
		t.Errorf("Transport = %q, want http", msg.Transport)
	}
	if msg.Endpoint != "https://acp.example/runs" {
		t.Errorf("Endpoint = %q", msg.Endpoint)
	}
}

func TestBuildAgentMessageANP(t *testing.T) {
	msg := BuildAgentMessage(map[string]interface{}{
		string(semconv.ANPProtocolVersionKey): "1.0",
		string(semconv.ANPTransportKey):       "ws",
		string(semconv.ANPPeerDIDKey):         "did:wba:peer",
		string(semconv.ANPMetaProtocolNameKey): "negotiate",
		string(semconv.ANPMessageIDKey):       "m1",
		string(semconv.ANPCrossDomainKey):     true,
	})
	if msg == nil {
		t.Fatal("BuildAgentMessage returned nil")
	}
	if msg.ProtocolID != AgentProtocolIDANP {
		t.Errorf("ProtocolID = %d, want %d", msg.ProtocolID, AgentProtocolIDANP)
	}
	if msg.PeerDID != "did:wba:peer" {
		t.Errorf("PeerDID = %q", msg.PeerDID)
	}
	if msg.Operation != "negotiate" {
		t.Errorf("Operation = %q, want negotiate", msg.Operation)
	}
	if msg.CrossDomain == nil || *msg.CrossDomain != true {
		t.Errorf("CrossDomain = %v, want true", msg.CrossDomain)
	}
}

func TestBuildAgentMessageCanonicalOverrides(t *testing.T) {
	msg := BuildAgentMessage(map[string]interface{}{
		string(semconv.AgentCommProtocolKey):      "custom",
		string(semconv.AgentCommUnitIDKey):        "u1",
		string(semconv.AgentCommStatusKey):        "completed",
		string(semconv.AgentCommPeerAgentNameKey): "peer-x",
	})
	if msg == nil {
		t.Fatal("BuildAgentMessage returned nil")
	}
	if msg.ProtocolID != AgentProtocolIDOther {
		t.Errorf("ProtocolID = %d, want %d", msg.ProtocolID, AgentProtocolIDOther)
	}
	if msg.Status != "completed" {
		t.Errorf("Status = %q, want completed", msg.Status)
	}
	if msg.DstAgent == nil || msg.DstAgent.Name != "peer-x" {
		t.Errorf("DstAgent = %+v, want name peer-x", msg.DstAgent)
	}
}

func TestBuildAgentMessageNoneWhenNoComm(t *testing.T) {
	if msg := BuildAgentMessage(map[string]interface{}{"http.method": "GET"}); msg != nil {
		t.Errorf("expected nil, got %+v", msg)
	}
}

// --- Mapper integration ---

func TestMapperAllProtocolsMapToOneClass(t *testing.T) {
	mapper := NewOCSFMapper()
	cases := []struct {
		name  string
		attrs map[string]interface{}
	}{
		{"a2a.message.send", map[string]interface{}{
			string(semconv.A2ATaskIDKey):    "t1",
			string(semconv.A2ATaskStateKey): "working",
		}},
		{"acp.run.create", map[string]interface{}{
			string(semconv.ACPRunIDKey):     "r1",
			string(semconv.ACPRunStatusKey): "completed",
		}},
		{"anp.message", map[string]interface{}{
			string(semconv.ANPMessageIDKey): "m1",
		}},
	}
	for _, c := range cases {
		span := makeSpan(t, c.name, c.attrs)
		result := mapper.MapSpan(span)
		if result == nil {
			t.Fatalf("%s: MapSpan returned nil", c.name)
		}
		event, ok := result.(*AIAgentCommunicationEvent)
		if !ok {
			t.Fatalf("%s: expected *AIAgentCommunicationEvent, got %T", c.name, result)
		}
		if event.CategoryUID != 9 {
			t.Errorf("%s: CategoryUID = %d, want 9", c.name, event.CategoryUID)
		}
		if event.ClassUID != 9003 {
			t.Errorf("%s: ClassUID = %d, want 9003", c.name, event.ClassUID)
		}
	}
}

func TestMapperFailureStatus(t *testing.T) {
	mapper := NewOCSFMapper()
	span := makeSpan(t, "a2a.message.send", map[string]interface{}{
		string(semconv.A2ATaskIDKey):           "t1",
		string(semconv.A2ATaskStateKey):        "failed",
		string(semconv.A2AJSONRPCErrorCodeKey): "-32000",
	})
	result := mapper.MapSpan(span)
	event, ok := result.(*AIAgentCommunicationEvent)
	if !ok {
		t.Fatalf("expected *AIAgentCommunicationEvent, got %T", result)
	}
	if event.StatusID != StatusFailure {
		t.Errorf("StatusID = %d, want %d (Failure)", event.StatusID, StatusFailure)
	}
	if event.AgentMessage.ErrorCode != "-32000" {
		t.Errorf("ErrorCode = %q, want -32000", event.AgentMessage.ErrorCode)
	}
}
