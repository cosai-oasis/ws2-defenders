package ocsf

import (
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

// OCSFMapper maps OTel spans to OCSF Category 7 AI events.
type OCSFMapper struct{}

// NewOCSFMapper creates a new OCSF mapper.
func NewOCSFMapper() *OCSFMapper {
	return &OCSFMapper{}
}

// MapSpan maps an OTel ReadOnlySpan to an OCSF event.
// Returns nil if the span is not an AI-related span.
func (m *OCSFMapper) MapSpan(span sdktrace.ReadOnlySpan) interface{} {
	name := span.Name()
	attrs := spanAttrs(span)

	if m.isInferenceSpan(name, attrs) {
		return m.mapInference(span, attrs)
	}
	if m.isAgentSpan(name, attrs) {
		return m.mapAgentActivity(span, attrs)
	}
	if m.isToolSpan(name, attrs) {
		return m.mapToolExecution(span, attrs)
	}
	if m.isRAGSpan(name, attrs) {
		return m.mapDataRetrieval(span, attrs)
	}
	if m.isSecuritySpan(name, attrs) {
		return m.mapSecurityFinding(span, attrs)
	}

	return nil
}

// ClassifySpan returns the OCSF event type string for a span, or "" if unrecognized.
func (m *OCSFMapper) ClassifySpan(span sdktrace.ReadOnlySpan) string {
	name := span.Name()
	attrs := spanAttrs(span)

	if m.isInferenceSpan(name, attrs) {
		return "model_inference"
	}
	if m.isAgentSpan(name, attrs) {
		return "agent_activity"
	}
	if m.isToolSpan(name, attrs) {
		return "tool_execution"
	}
	if m.isRAGSpan(name, attrs) {
		return "data_retrieval"
	}
	if m.isSecuritySpan(name, attrs) {
		return "security_finding"
	}
	return ""
}

// --- Classification Methods ---

func (m *OCSFMapper) isInferenceSpan(name string, attrs map[string]interface{}) bool {
	if strings.HasPrefix(name, "chat ") ||
		strings.HasPrefix(name, "embeddings ") ||
		strings.HasPrefix(name, "text_completion ") {
		return true
	}
	_, ok := attrs[string(semconv.GenAISystemKey)]
	return ok
}

func (m *OCSFMapper) isAgentSpan(name string, attrs map[string]interface{}) bool {
	if strings.HasPrefix(name, "agent.") {
		return true
	}
	_, ok := attrs[string(semconv.AgentNameKey)]
	return ok
}

func (m *OCSFMapper) isToolSpan(name string, attrs map[string]interface{}) bool {
	if strings.HasPrefix(name, "mcp.tool.") || strings.HasPrefix(name, "skill.invoke") {
		return true
	}
	if _, ok := attrs[string(semconv.MCPToolNameKey)]; ok {
		return true
	}
	if _, ok := attrs[string(semconv.SkillNameKey)]; ok {
		return true
	}
	return false
}

func (m *OCSFMapper) isRAGSpan(name string, attrs map[string]interface{}) bool {
	if strings.HasPrefix(name, "rag.") {
		return true
	}
	_, ok := attrs[string(semconv.RAGRetrieveDatabaseKey)]
	return ok
}

func (m *OCSFMapper) isSecuritySpan(_ string, attrs map[string]interface{}) bool {
	_, ok := attrs[string(semconv.SecurityThreatDetectedKey)]
	return ok
}

// --- Mapping Methods ---

func (m *OCSFMapper) mapInference(span sdktrace.ReadOnlySpan, attrs map[string]interface{}) *AIModelInferenceEvent {
	modelID := attrStr(attrs, string(semconv.GenAIRequestModelKey), "unknown")
	system := attrStr(attrs, string(semconv.GenAISystemKey), "unknown")
	operation := attrStr(attrs, string(semconv.GenAIOperationNameKey), "chat")

	activityMap := map[string]int{
		"chat":            1,
		"text_completion": 2,
		"embeddings":      3,
	}
	activityID := activityMap[operation]
	if activityID == 0 {
		activityID = ActivityOther
	}

	modelType := "llm"
	if operation == "embeddings" {
		modelType = "embedding"
	}

	// Build parameters from gen_ai.request.* attributes
	params := make(map[string]interface{})
	for k, v := range attrs {
		if strings.HasPrefix(k, "gen_ai.request.") && k != string(semconv.GenAIRequestModelKey) {
			paramName := strings.TrimPrefix(k, "gen_ai.request.")
			params[paramName] = v
		}
	}
	var paramsPtr map[string]interface{}
	if len(params) > 0 {
		paramsPtr = params
	}

	model := AIModelInfo{
		ModelID:    modelID,
		Name:       modelID,
		Provider:   system,
		Type:       modelType,
		Parameters: paramsPtr,
	}

	tokenUsage := AITokenUsage{
		InputTokens:     attrInt(attrs, string(semconv.GenAIUsageInputTokensKey), 0),
		OutputTokens:    attrInt(attrs, string(semconv.GenAIUsageOutputTokensKey), 0),
		CachedTokens:    attrInt(attrs, string(semconv.GenAIUsageCachedTokensKey), 0),
		ReasoningTokens: attrInt(attrs, string(semconv.GenAIUsageReasoningTokensKey), 0),
	}
	tokenUsage.ComputeTotal()

	var latency *AILatencyMetrics
	if _, ok := attrs[string(semconv.LatencyTotalMsKey)]; ok {
		lat := AILatencyMetrics{
			TotalMs: attrFloat(attrs, string(semconv.LatencyTotalMsKey), 0),
		}
		if v, ok := attrs[string(semconv.LatencyTimeToFirstTokenMsKey)]; ok {
			f := toFloat64(v)
			lat.TimeToFirstTokenMs = &f
		}
		if v, ok := attrs[string(semconv.LatencyTokensPerSecondKey)]; ok {
			f := toFloat64(v)
			lat.TokensPerSecond = &f
		}
		latency = &lat
	}

	var cost *AICostInfo
	if _, ok := attrs[string(semconv.CostTotalCostKey)]; ok {
		cost = &AICostInfo{
			InputCostUSD:  attrFloat(attrs, string(semconv.CostInputCostKey), 0),
			OutputCostUSD: attrFloat(attrs, string(semconv.CostOutputCostKey), 0),
			TotalCostUSD:  attrFloat(attrs, string(semconv.CostTotalCostKey), 0),
			Currency:      "USD",
		}
	}

	finishReason := "stop"
	if v, ok := attrs[string(semconv.GenAIResponseFinishReasonsKey)]; ok {
		finishReason = fmt.Sprintf("%v", v)
	}

	event := NewAIModelInferenceEvent(model, activityID)
	event.TokenUsage = tokenUsage
	event.Latency = latency
	event.Cost = cost
	event.FinishReason = finishReason
	event.Streaming = attrBool(attrs, string(semconv.GenAIRequestStreamKey), false)
	event.Message = fmt.Sprintf("%s %s", operation, modelID)
	event.Time = spanTime(span)

	return event
}

func (m *OCSFMapper) mapAgentActivity(span sdktrace.ReadOnlySpan, attrs map[string]interface{}) *AIAgentActivityEvent {
	name := span.Name()
	agentName := attrStr(attrs, string(semconv.AgentNameKey), "unknown")
	agentID := attrStr(attrs, string(semconv.AgentIDKey), "unknown")
	sessionID := attrStr(attrs, string(semconv.AgentSessionIDKey), "unknown")

	// Determine activity from span name
	activityID := 3 // Step Execute
	if strings.Contains(name, "session") {
		activityID = 1 // Session Start
	} else if strings.Contains(name, "delegation") || strings.Contains(name, "delegate") {
		activityID = 4 // Delegation
	} else if strings.Contains(name, "memory") {
		activityID = 5 // Memory Access
	}

	event := NewAIAgentActivityEvent(agentName, agentID, sessionID, activityID)
	event.AgentType = attrStr(attrs, string(semconv.AgentTypeKey), "autonomous")
	event.Framework = attrStr(attrs, string(semconv.AgentFrameworkKey), "")
	event.StepType = attrStr(attrs, string(semconv.AgentStepTypeKey), "")
	event.Thought = attrStr(attrs, string(semconv.AgentStepThoughtKey), "")
	event.Action = attrStr(attrs, string(semconv.AgentStepActionKey), "")
	event.Observation = attrStr(attrs, string(semconv.AgentStepObservationKey), "")
	event.DelegationTarget = attrStr(attrs, string(semconv.AgentDelegationTargetAgentKey), "")

	if v, ok := attrs[string(semconv.AgentStepIndexKey)]; ok {
		idx := toInt(v)
		event.StepIndex = &idx
	}

	event.Message = name
	event.Time = spanTime(span)

	return event
}

func (m *OCSFMapper) mapToolExecution(span sdktrace.ReadOnlySpan, attrs map[string]interface{}) *AIToolExecutionEvent {
	var toolName, toolType string
	var activityID int

	if _, ok := attrs[string(semconv.MCPToolNameKey)]; ok {
		toolName = attrStr(attrs, string(semconv.MCPToolNameKey), "unknown")
		toolType = "mcp_tool"
		activityID = 2 // MCP Tool Invoke
	} else if _, ok := attrs[string(semconv.SkillNameKey)]; ok {
		toolName = attrStr(attrs, string(semconv.SkillNameKey), "unknown")
		toolType = "skill"
		activityID = 3 // Skill Invoke
	} else {
		toolName = attrStr(attrs, string(semconv.GenAIToolNameKey), "unknown")
		toolType = "function"
		activityID = 1 // Function Call
	}

	event := NewAIToolExecutionEvent(toolName, toolType, activityID)

	// Tool input/output (prefer MCP, fall back to skill)
	event.ToolInput = firstNonEmpty(
		attrStr(attrs, string(semconv.MCPToolInputKey), ""),
		attrStr(attrs, string(semconv.SkillInputKey), ""),
	)
	event.ToolOutput = firstNonEmpty(
		attrStr(attrs, string(semconv.MCPToolOutputKey), ""),
		attrStr(attrs, string(semconv.SkillOutputKey), ""),
	)

	event.IsError = attrBool(attrs, string(semconv.MCPToolIsErrorKey), false)

	// Duration (prefer MCP, fall back to skill)
	durationKey := string(semconv.MCPToolDurationMsKey)
	if _, ok := attrs[durationKey]; !ok {
		durationKey = string(semconv.SkillDurationMsKey)
	}
	if v, ok := attrs[durationKey]; ok {
		f := toFloat64(v)
		event.DurationMs = &f
	}

	event.MCPServer = attrStr(attrs, string(semconv.MCPToolServerKey), "")
	event.MCPTransport = attrStr(attrs, string(semconv.MCPServerTransportKey), "")
	event.SkillCategory = attrStr(attrs, string(semconv.SkillCategoryKey), "")
	event.SkillVersion = attrStr(attrs, string(semconv.SkillVersionKey), "")
	event.ApprovalRequired = attrBool(attrs, string(semconv.MCPToolApprovalRequiredKey), false)

	if v, ok := attrs[string(semconv.MCPToolApprovedKey)]; ok {
		b := toBool(v)
		event.Approved = &b
	}

	spanName := span.Name()
	if spanName != "" {
		event.Message = spanName
	} else {
		event.Message = fmt.Sprintf("tool.execute %s", toolName)
	}
	event.Time = spanTime(span)

	return event
}

func (m *OCSFMapper) mapDataRetrieval(span sdktrace.ReadOnlySpan, attrs map[string]interface{}) *AIDataRetrievalEvent {
	database := attrStr(attrs, string(semconv.RAGRetrieveDatabaseKey), "unknown")
	stage := attrStr(attrs, string(semconv.RAGPipelineStageKey), "retrieve")

	activityMap := map[string]int{
		"retrieve": 1,
		"rerank":   5,
		"generate": ActivityOther,
		"evaluate": ActivityOther,
	}
	activityID := activityMap[stage]
	if activityID == 0 {
		activityID = ActivityOther
	}

	event := NewAIDataRetrievalEvent(database, database, activityID)
	event.Query = attrStr(attrs, string(semconv.RAGQueryKey), "")
	event.ResultsCount = attrInt(attrs, string(semconv.RAGRetrieveResultsCountKey), 0)
	event.PipelineName = attrStr(attrs, string(semconv.RAGPipelineNameKey), "")
	event.PipelineStage = stage

	if v, ok := attrs[string(semconv.RAGRetrieveTopKKey)]; ok {
		i := toInt(v)
		event.TopK = &i
	}
	if v, ok := attrs[string(semconv.RAGRetrieveMinScoreKey)]; ok {
		f := toFloat64(v)
		event.MinScore = &f
	}
	if v, ok := attrs[string(semconv.RAGRetrieveMaxScoreKey)]; ok {
		f := toFloat64(v)
		event.MaxScore = &f
	}
	event.Filter = attrStr(attrs, string(semconv.RAGRetrieveFilterKey), "")

	spanName := span.Name()
	if spanName != "" {
		event.Message = spanName
	} else {
		event.Message = fmt.Sprintf("rag.%s %s", stage, database)
	}
	event.Time = spanTime(span)

	return event
}

func (m *OCSFMapper) mapSecurityFinding(span sdktrace.ReadOnlySpan, attrs map[string]interface{}) *AISecurityFindingEvent {
	finding := AISecurityFinding{
		FindingType:     attrStr(attrs, string(semconv.SecurityThreatTypeKey), "unknown"),
		OWASPCategory:   attrStr(attrs, string(semconv.SecurityOWASPCategoryKey), ""),
		RiskLevel:       attrStr(attrs, string(semconv.SecurityRiskLevelKey), "medium"),
		RiskScore:       attrFloat(attrs, string(semconv.SecurityRiskScoreKey), 50.0),
		Confidence:      attrFloat(attrs, string(semconv.SecurityConfidenceKey), 0.5),
		DetectionMethod: attrStr(attrs, string(semconv.SecurityDetectionMethodKey), "pattern"),
		Blocked:         attrBool(attrs, string(semconv.SecurityBlockedKey), false),
	}

	severityMap := map[string]int{
		"critical": SeverityCritical,
		"high":     SeverityHigh,
		"medium":   SeverityMedium,
		"low":      SeverityLow,
		"info":     SeverityInformational,
	}

	event := NewAISecurityFindingEvent(finding, 1) // Threat Detection
	sev, ok := severityMap[finding.RiskLevel]
	if !ok {
		sev = SeverityMedium
	}
	event.SeverityID = sev

	spanName := span.Name()
	if spanName != "" {
		event.Message = spanName
	} else {
		event.Message = fmt.Sprintf("security.%s", finding.FindingType)
	}
	event.Time = spanTime(span)

	return event
}

// --- Utility Functions ---

// spanAttrs extracts span attributes into a string-keyed map.
func spanAttrs(span sdktrace.ReadOnlySpan) map[string]interface{} {
	result := make(map[string]interface{})
	for _, kv := range span.Attributes() {
		result[string(kv.Key)] = attrValue(kv.Value)
	}
	return result
}

// attrValue converts an attribute.Value to a Go interface{}.
func attrValue(v attribute.Value) interface{} {
	switch v.Type() {
	case attribute.STRING:
		return v.AsString()
	case attribute.INT64:
		return v.AsInt64()
	case attribute.FLOAT64:
		return v.AsFloat64()
	case attribute.BOOL:
		return v.AsBool()
	default:
		return v.Emit()
	}
}

// spanTime returns the span start time as an ISO 8601 string.
func spanTime(span sdktrace.ReadOnlySpan) string {
	t := span.StartTime()
	if !t.IsZero() {
		return t.UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}

// attrStr extracts a string attribute with a default value.
func attrStr(attrs map[string]interface{}, key, defaultVal string) string {
	if v, ok := attrs[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return defaultVal
}

// attrInt extracts an integer attribute with a default value.
func attrInt(attrs map[string]interface{}, key string, defaultVal int) int {
	if v, ok := attrs[key]; ok {
		return toInt(v)
	}
	return defaultVal
}

// attrFloat extracts a float attribute with a default value.
func attrFloat(attrs map[string]interface{}, key string, defaultVal float64) float64 {
	if v, ok := attrs[key]; ok {
		return toFloat64(v)
	}
	return defaultVal
}

// attrBool extracts a boolean attribute with a default value.
func attrBool(attrs map[string]interface{}, key string, defaultVal bool) bool {
	if v, ok := attrs[key]; ok {
		return toBool(v)
	}
	return defaultVal
}

func toInt(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	default:
		return 0
	}
}

func toFloat64(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case int64:
		return float64(val)
	case int:
		return float64(val)
	default:
		return 0
	}
}

func toBool(v interface{}) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
