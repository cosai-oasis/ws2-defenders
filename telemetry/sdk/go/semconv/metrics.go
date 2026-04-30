// Package semconv provides AITF metric name constants.
package semconv

// Metric names for AITF telemetry.
const (
	// OTel GenAI metrics (preserved)
	MetricGenAITokenUsage       = "gen_ai.client.token.usage"
	MetricGenAIOperationDuration = "gen_ai.client.operation.duration"

	// Inference metrics
	MetricInferenceRequests = "inference.requests"
	MetricInferenceErrors   = "inference.errors"
	MetricInferenceTTFT     = "inference.time_to_first_token"
	MetricInferenceTPS      = "inference.tokens_per_second"

	// Agent metrics
	MetricAgentSessions        = "agent.sessions"
	MetricAgentSteps           = "agent.steps"
	MetricAgentSessionDuration = "agent.session.duration"
	MetricAgentDelegations     = "agent.delegations"

	// MCP metrics
	MetricMCPToolInvocations   = "mcp.tool.invocations"
	MetricMCPToolDuration      = "mcp.tool.duration"
	MetricMCPServerConnections = "mcp.server.connections"
	MetricMCPToolApprovals     = "mcp.tool.approvals"

	// Skill metrics
	MetricSkillInvocations = "skill.invocations"
	MetricSkillDuration    = "skill.duration"

	// Cost metrics
	MetricCostTotal             = "cost.total"
	MetricCostBudgetUtilization = "cost.budget.utilization"

	// Security metrics
	MetricSecurityThreats    = "security.threats_detected"
	MetricSecurityBlocked    = "security.requests_blocked"
	MetricSecurityPII        = "security.pii_detected"
	MetricSecurityGuardrails = "security.guardrail.checks"

	// RAG metrics
	MetricRAGRetrievals       = "rag.retrievals"
	MetricRAGRetrievalDuration = "rag.retrieval.duration"

	// Quality metrics
	MetricQualityHallucination = "quality.hallucination"
	MetricQualityUserRating    = "quality.user_rating"
)
