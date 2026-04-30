# Agentic Log Spans

Status: **Experimental**

## Overview

Agentic log spans capture the essential security-relevant context for every action taken by an AI agent. They implement the minimum fields defined in **Table 10.1: Agentic log with minimum fields**, providing the baseline telemetry required for security monitoring, anomaly detection, policy enforcement, and forensic investigation of agentic AI systems.

## Span: `agentic_log {agent_id}`

This span is created for each logged agent action.

### Required Attributes

| Attribute | Type | Description | Example |
|---|---|---|---|
| `agentic_log.event_id` | string | A unique identifier for the specific log entry | `e-44b1c8f0` |
| `agentic_log.timestamp` | string | ISO 8601 formatted timestamp with millisecond precision | `2025-10-26T14:30:05.122Z` |
| `agentic_log.agent_id` | string | The unique, cryptographically verifiable identity of the agent | `agent-innovacorp-logicore-prod-042` |
| `agentic_log.session_id` | string | A unique ID for the agent's current operational session or "thought process" | `sess-f0a1b2` |

### Recommended Attributes

| Attribute | Type | Description | Security Relevance |
|---|---|---|---|
| `agentic_log.goal_id` | string | An identifier for the high-level goal the agent is currently pursuing | The single most important field for security context |
| `agentic_log.sub_task_id` | string | The specific, immediate task the agent is performing | Granular context for a specific action |
| `agentic_log.tool_used` | string | The specific tool, function, or API being invoked | Pinpointing the exact capability being used |
| `agentic_log.tool_parameters` | string | A sanitized JSON log of the parameters passed to the tool. Must redact PII, credentials, and other sensitive data | Understanding the specifics of the action |
| `agentic_log.outcome` | string | The result of the action (e.g., `SUCCESS`, `FAILURE`, `ERROR`, `DENIED`, `TIMEOUT`, `PARTIAL`) | Basic operational monitoring |
| `agentic_log.confidence_score` | double | The agent's own assessment of how likely this action is to succeed (0.0-1.0) | A sudden drop can indicate a poisoned environment |
| `agentic_log.anomaly_score` | double | Score from a real-time model indicating how unusual this action is, even for this goal (0.0-1.0) | The primary input for automated alerting |
| `agentic_log.policy_evaluation` | string | JSON record of a check against a security policy engine (e.g., OPA) | Proactive compliance and guardrail enforcement |

### Outcome Values

| Value | Description |
|---|---|
| `SUCCESS` | The action completed successfully |
| `FAILURE` | The action failed due to an operational issue |
| `ERROR` | The action encountered an unexpected error |
| `DENIED` | The action was blocked by a policy or authorization check |
| `TIMEOUT` | The action timed out before completion |
| `PARTIAL` | The action partially completed |

### Policy Evaluation Result Values

| Value | Description |
|---|---|
| `PASS` | The action passed the policy check |
| `FAIL` | The action failed the policy check |
| `WARN` | The action triggered a warning but was allowed |
| `SKIP` | The policy check was skipped |

## Security Considerations

### ToolParameters Sanitization

The `tool_parameters` field **MUST** redact:
- Personally Identifiable Information (PII)
- Credentials (API keys, tokens, passwords)
- Sensitive business data as defined by organizational policy

Implementations SHOULD use the AITF PII processor to automatically sanitize tool parameters before logging.

### ConfidenceScore Monitoring

A sudden, unexplained drop in the `confidence_score` across consecutive actions within the same session can indicate:
- A poisoned or manipulated environment
- Prompt injection affecting the agent's reasoning
- Environmental drift requiring investigation

Security monitoring systems SHOULD alert when confidence scores drop below a configured threshold within a session.

### AnomalyScore Alerting

The `anomaly_score` is the primary input for automated security alerting. Values above a configured threshold (e.g., 0.7) SHOULD trigger automated investigation workflows.

### GoalID as Security Context

The `goal_id` is described as "the single most important field for security context." It enables:
- Correlating all actions within a goal to detect goal-hijacking attacks
- Verifying that tool usage and parameters are consistent with the stated goal
- Detecting when an agent deviates from its assigned objectives

## Usage Examples

### Python

```python
from aitf.instrumentation.agentic_log import AgenticLogInstrumentor

logger = AgenticLogInstrumentor()

with logger.log_action(
    agent_id="agent-innovacorp-logicore-prod-042",
    session_id="sess-f0a1b2",
) as entry:
    entry.set_goal_id("goal-resolve-port-congestion-sg")
    entry.set_sub_task_id("task-find-all-trucking-vendor")
    entry.set_tool_used("mcp.server.github.list_tools")
    entry.set_tool_parameters({"repo": "innovacorp logistics-tools"})
    entry.set_outcome("SUCCESS")
    entry.set_confidence_score(0.92)
    entry.set_anomaly_score(0.15)
    entry.set_policy_evaluation({"policy": "max_spend", "result": "PASS"})
```

### Go

```go
instrumentor := instrumentation.NewAgenticLogInstrumentor(tp)
ctx, entry := instrumentor.LogAction(ctx, instrumentation.AgenticLogConfig{
    AgentID:   "agent-innovacorp-logicore-prod-042",
    SessionID: "sess-f0a1b2",
    GoalID:    "goal-resolve-port-congestion-sg",
    SubTaskID: "task-find-all-trucking-vendor",
    ToolUsed:  "mcp.server.github.list_tools",
})
entry.SetToolParametersMap(map[string]interface{}{"repo": "innovacorp logistics-tools"})
entry.SetOutcome(semconv.AgenticLogOutcomeSuccess)
entry.SetConfidenceScore(0.92)
entry.SetAnomalyScore(0.15)
entry.End(nil)
```

### TypeScript

```typescript
const logger = new AgenticLogInstrumentor(tracerProvider);

logger.logAction({
  agentId: "agent-innovacorp-logicore-prod-042",
  sessionId: "sess-f0a1b2",
}, (entry) => {
  entry.setGoalId("goal-resolve-port-congestion-sg");
  entry.setSubTaskId("task-find-all-trucking-vendor");
  entry.setToolUsed("mcp.server.github.list_tools");
  entry.setToolParameters({ repo: "innovacorp logistics-tools" });
  entry.setOutcome("SUCCESS");
  entry.setConfidenceScore(0.92);
  entry.setAnomalyScore(0.15);
  entry.setPolicyEvaluation({ policy: "max_spend", result: "PASS" });
});
```
