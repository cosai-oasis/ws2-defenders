/**
 * AITF Metric name constants.
 */

/** All AITF metric names. */
export const AITFMetrics = {
  // OTel GenAI metrics (preserved)
  GEN_AI_TOKEN_USAGE: "gen_ai.client.token.usage",
  GEN_AI_OPERATION_DURATION: "gen_ai.client.operation.duration",

  // Inference metrics
  INFERENCE_REQUESTS: "inference.requests",
  INFERENCE_ERRORS: "inference.errors",
  INFERENCE_TTFT: "inference.time_to_first_token",
  INFERENCE_TPS: "inference.tokens_per_second",

  // Agent metrics
  AGENT_SESSIONS: "agent.sessions",
  AGENT_STEPS: "agent.steps",
  AGENT_SESSION_DURATION: "agent.session.duration",
  AGENT_STEPS_PER_SESSION: "agent.steps_per_session",
  AGENT_DELEGATIONS: "agent.delegations",

  // MCP metrics
  MCP_TOOL_INVOCATIONS: "mcp.tool.invocations",
  MCP_TOOL_DURATION: "mcp.tool.duration",
  MCP_SERVER_CONNECTIONS: "mcp.server.connections",
  MCP_TOOL_APPROVALS: "mcp.tool.approvals",

  // Skill metrics
  SKILL_INVOCATIONS: "skill.invocations",
  SKILL_DURATION: "skill.duration",

  // Cost metrics
  COST_TOTAL: "cost.total",
  COST_BUDGET_UTILIZATION: "cost.budget.utilization",

  // Security metrics
  SECURITY_THREATS_DETECTED: "security.threats_detected",
  SECURITY_REQUESTS_BLOCKED: "security.requests_blocked",
  SECURITY_PII_DETECTED: "security.pii_detected",
  SECURITY_GUARDRAIL_CHECKS: "security.guardrail.checks",

  // RAG metrics
  RAG_RETRIEVALS: "rag.retrievals",
  RAG_RETRIEVAL_DURATION: "rag.retrieval.duration",
  RAG_RETRIEVAL_RESULTS: "rag.retrieval.results",

  // Quality metrics
  QUALITY_HALLUCINATION: "quality.hallucination",
  QUALITY_USER_RATING: "quality.user_rating",
} as const;
