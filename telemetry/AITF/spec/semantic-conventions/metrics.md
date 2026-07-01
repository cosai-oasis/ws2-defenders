# AITF Metrics Conventions

AITF defines metrics for monitoring AI system performance, cost, security, and quality.

## OTel GenAI Metrics (Preserved)

These metrics follow OpenTelemetry GenAI semantic conventions.

### `gen_ai.client.token.usage`

**Type:** Histogram
**Unit:** `{token}`
**Description:** Number of tokens used per request.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.provider.name` | string | Provider (OTel standard) |
| `gen_ai.request.model` | string | Model ID |
| `gen_ai.token.type` | string | `"input"`, `"output"` |
| `gen_ai.operation.name` | string | Operation name |

### `gen_ai.client.operation.duration`

**Type:** Histogram
**Unit:** `s`
**Description:** Duration of GenAI operations.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.provider.name` | string | Provider (OTel standard) |
| `gen_ai.request.model` | string | Model ID |
| `gen_ai.operation.name` | string | Operation name |
| `gen_ai.response.finish_reasons` | string[] | Finish reasons |
| `error.type` | string | Error type (if error) |

---

## AITF Extended Metrics

### Inference Metrics

#### `inference.requests`

**Type:** Counter
**Unit:** `{request}`
**Description:** Total number of inference requests.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.provider.name` | string | Provider (OTel standard) |
| `gen_ai.request.model` | string | Model ID |
| `gen_ai.operation.name` | string | Operation name |
| `cost.attribution.user` | string | User ID |
| `cost.attribution.project` | string | Project ID |

#### `inference.errors`

**Type:** Counter
**Unit:** `{error}`
**Description:** Total inference errors.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.provider.name` | string | Provider (OTel standard) |
| `gen_ai.request.model` | string | Model ID |
| `error.type` | string | Error type |

#### `inference.time_to_first_token`

**Type:** Histogram
**Unit:** `ms`
**Description:** Time to first token in streaming responses.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.provider.name` | string | Provider (OTel standard) |
| `gen_ai.request.model` | string | Model ID |

#### `inference.tokens_per_second`

**Type:** Histogram
**Unit:** `{token}/s`
**Description:** Token generation rate.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.provider.name` | string | Provider (OTel standard) |
| `gen_ai.request.model` | string | Model ID |

---

### Agent Metrics

#### `agent.sessions`

**Type:** Counter
**Unit:** `{session}`
**Description:** Total agent sessions started.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.agent.name` | string | Agent name |
| `agent.framework` | string | Framework |

#### `agent.steps`

**Type:** Counter
**Unit:** `{step}`
**Description:** Total agent steps executed.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.agent.name` | string | Agent name |
| `agent.step.type` | string | Step type |

#### `agent.session.duration`

**Type:** Histogram
**Unit:** `s`
**Description:** Duration of agent sessions.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.agent.name` | string | Agent name |
| `agent.framework` | string | Framework |

#### `agent.steps_per_session`

**Type:** Histogram
**Unit:** `{step}`
**Description:** Number of steps per agent session.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.agent.name` | string | Agent name |

#### `agent.delegations`

**Type:** Counter
**Unit:** `{delegation}`
**Description:** Total agent delegations.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.agent.name` | string | Delegating agent |
| `agent.delegation.target_agent` | string | Target agent |
| `agent.delegation.strategy` | string | Strategy |

---

### MCP Metrics

#### `mcp.tool.invocations`

**Type:** Counter
**Unit:** `{invocation}`
**Description:** Total MCP tool invocations.

| Attribute | Type | Notes |
|-----------|------|-------|
| `mcp.tool.name` | string | Tool name |
| `mcp.tool.server` | string | Server name |
| `mcp.tool.is_error` | boolean | Error status |

#### `mcp.tool.duration`

**Type:** Histogram
**Unit:** `ms`
**Description:** MCP tool invocation duration.

| Attribute | Type | Notes |
|-----------|------|-------|
| `mcp.tool.name` | string | Tool name |
| `mcp.tool.server` | string | Server name |

#### `mcp.server.connections`

**Type:** UpDownCounter
**Unit:** `{connection}`
**Description:** Active MCP server connections.

| Attribute | Type | Notes |
|-----------|------|-------|
| `mcp.server.name` | string | Server name |
| `mcp.server.transport` | string | Transport type |

#### `mcp.tool.approvals`

**Type:** Counter
**Unit:** `{approval}`
**Description:** MCP tool approval requests.

| Attribute | Type | Notes |
|-----------|------|-------|
| `mcp.tool.name` | string | Tool name |
| `mcp.tool.approved` | boolean | Whether approved |

---

### Skill Metrics

#### `skill.invocations`

**Type:** Counter
**Unit:** `{invocation}`
**Description:** Total skill invocations.

| Attribute | Type | Notes |
|-----------|------|-------|
| `skill.name` | string | Skill name |
| `skill.category` | string | Skill category |
| `skill.status` | string | Execution status |

#### `skill.duration`

**Type:** Histogram
**Unit:** `ms`
**Description:** Skill execution duration.

| Attribute | Type | Notes |
|-----------|------|-------|
| `skill.name` | string | Skill name |
| `skill.category` | string | Skill category |

---

### Cost Metrics

#### `cost.total`

**Type:** Counter
**Unit:** `USD`
**Description:** Cumulative cost of AI operations.

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.provider.name` | string | Provider (OTel standard) |
| `gen_ai.request.model` | string | Model ID |
| `cost.attribution.user` | string | User ID |
| `cost.attribution.team` | string | Team ID |
| `cost.attribution.project` | string | Project ID |

#### `cost.budget.utilization`

**Type:** Gauge
**Unit:** `%`
**Description:** Budget utilization percentage.

| Attribute | Type | Notes |
|-----------|------|-------|
| `cost.attribution.project` | string | Project ID |
| `cost.attribution.team` | string | Team ID |

---

### Security Metrics

#### `security.threats_detected`

**Type:** Counter
**Unit:** `{threat}`
**Description:** Total threats detected.

| Attribute | Type | Notes |
|-----------|------|-------|
| `security.threat_type` | string | Threat type |
| `security.owasp_category` | string | OWASP category |
| `security.risk_level` | string | Risk level |

#### `security.requests_blocked`

**Type:** Counter
**Unit:** `{request}`
**Description:** Total requests blocked by security.

| Attribute | Type | Notes |
|-----------|------|-------|
| `security.threat_type` | string | Threat type |

#### `security.pii_detected`

**Type:** Counter
**Unit:** `{detection}`
**Description:** Total PII detections.

| Attribute | Type | Notes |
|-----------|------|-------|
| `security.pii.types` | string[] | PII types |
| `security.pii.action` | string | Action taken |

#### `security.guardrail.checks`

**Type:** Counter
**Unit:** `{check}`
**Description:** Total guardrail checks.

| Attribute | Type | Notes |
|-----------|------|-------|
| `security.guardrail.name` | string | Guardrail name |
| `security.guardrail.result` | string | Result |

---

### RAG Metrics

#### `rag.retrievals`

**Type:** Counter
**Unit:** `{retrieval}`
**Description:** Total RAG retrieval operations.

| Attribute | Type | Notes |
|-----------|------|-------|
| `rag.retrieve.database` | string | Vector DB |
| `rag.pipeline.name` | string | Pipeline name |

#### `rag.retrieval.duration`

**Type:** Histogram
**Unit:** `ms`
**Description:** RAG retrieval duration.

| Attribute | Type | Notes |
|-----------|------|-------|
| `rag.retrieve.database` | string | Vector DB |

#### `rag.retrieval.results`

**Type:** Histogram
**Unit:** `{document}`
**Description:** Number of documents retrieved.

| Attribute | Type | Notes |
|-----------|------|-------|
| `rag.retrieve.database` | string | Vector DB |
| `rag.pipeline.name` | string | Pipeline name |

---

### Quality Metrics

#### `quality.hallucination`

**Type:** Histogram
**Unit:** `1`
**Description:** Hallucination scores (0-1 scale, lower is better).

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.request.model` | string | Model ID |

#### `quality.user_rating`

**Type:** Histogram
**Unit:** `{rating}`
**Description:** User rating scores (1-5).

| Attribute | Type | Notes |
|-----------|------|-------|
| `gen_ai.request.model` | string | Model ID |
| `gen_ai.agent.name` | string | Agent name (if applicable) |

---

### Model Operations (LLMOps/MLOps) Metrics

#### `model_ops.training.runs`

**Type:** Counter
**Unit:** `{run}`
**Description:** Total training/fine-tuning runs.

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.training.type` | string | Training type |
| `model_ops.training.status` | string | Run status |
| `model_ops.training.base_model` | string | Base model |

#### `model_ops.training.duration`

**Type:** Histogram
**Unit:** `s`
**Description:** Training run duration.

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.training.type` | string | Training type |
| `model_ops.training.base_model` | string | Base model |

#### `model_ops.training.gpu_hours`

**Type:** Counter
**Unit:** `h`
**Description:** Cumulative GPU hours consumed by training.

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.training.compute.gpu_type` | string | GPU type |
| `model_ops.training.type` | string | Training type |

#### `model_ops.evaluation.runs`

**Type:** Counter
**Unit:** `{run}`
**Description:** Total evaluation runs.

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.evaluation.type` | string | Evaluation type |
| `model_ops.evaluation.pass` | boolean | Pass/fail |

#### `model_ops.evaluation.score`

**Type:** Histogram
**Unit:** `1`
**Description:** Evaluation metric scores (0-1 normalized).

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.evaluation.model_id` | string | Model evaluated |
| `model_ops.evaluation.type` | string | Evaluation type |
| `model_ops.monitoring.metric_name` | string | Metric name |

#### `model_ops.registry.operations`

**Type:** Counter
**Unit:** `{operation}`
**Description:** Total model registry operations.

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.registry.operation` | string | Operation type |
| `model_ops.registry.stage` | string | Target stage |

#### `model_ops.deployment.count`

**Type:** Counter
**Unit:** `{deployment}`
**Description:** Total model deployments.

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.deployment.strategy` | string | Deployment strategy |
| `model_ops.deployment.environment` | string | Target environment |
| `model_ops.deployment.status` | string | Deployment status |

#### `model_ops.serving.cache_hit_rate`

**Type:** Gauge
**Unit:** `%`
**Description:** Serving cache hit rate.

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.serving.cache.type` | string | Cache type |

#### `model_ops.serving.fallback.count`

**Type:** Counter
**Unit:** `{fallback}`
**Description:** Total fallback events.

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.serving.fallback.trigger` | string | Trigger reason |

#### `model_ops.serving.circuit_breaker.transitions`

**Type:** Counter
**Unit:** `{transition}`
**Description:** Circuit breaker state transitions.

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.serving.circuit_breaker.state` | string | New state |
| `model_ops.serving.circuit_breaker.model` | string | Affected model |

#### `model_ops.monitoring.drift_score`

**Type:** Histogram
**Unit:** `1`
**Description:** Drift detection scores (0-1).

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.monitoring.model_id` | string | Monitored model |
| `model_ops.monitoring.drift_type` | string | Drift type |

#### `model_ops.monitoring.alerts`

**Type:** Counter
**Unit:** `{alert}`
**Description:** Total monitoring alerts triggered.

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.monitoring.check_type` | string | Check type |
| `model_ops.monitoring.result` | string | Alert level |
| `model_ops.monitoring.action_triggered` | string | Action taken |

#### `model_ops.prompt.versions`

**Type:** Counter
**Unit:** `{version}`
**Description:** Total prompt versions created.

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.prompt.name` | string | Prompt name |
| `model_ops.prompt.operation` | string | Operation type |

---

### Identity Metrics

#### `identity.authentications`

**Type:** Counter
**Unit:** `{authentication}`
**Description:** Total agent authentication attempts.

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.auth.method` | string | Auth method |
| `identity.auth.result` | string | Auth result |
| `identity.provider` | string | Identity provider |

#### `identity.authentication.duration`

**Type:** Histogram
**Unit:** `ms`
**Description:** Authentication operation duration.

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.auth.method` | string | Auth method |
| `identity.provider` | string | Identity provider |

#### `identity.authorizations`

**Type:** Counter
**Unit:** `{authorization}`
**Description:** Total authorization decisions.

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.authz.decision` | string | Decision |
| `identity.authz.policy_engine` | string | Policy engine |

#### `identity.delegations`

**Type:** Counter
**Unit:** `{delegation}`
**Description:** Total credential delegations.

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.delegation.type` | string | Delegation type |
| `identity.delegation.result` | string | Delegation result |

#### `identity.delegation.chain_depth`

**Type:** Histogram
**Unit:** `{depth}`
**Description:** Delegation chain depth distribution.

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.delegation.type` | string | Delegation type |

#### `identity.active_sessions`

**Type:** UpDownCounter
**Unit:** `{session}`
**Description:** Active identity sessions.

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.type` | string | Identity type |
| `identity.provider` | string | Provider |

#### `identity.lifecycle.events`

**Type:** Counter
**Unit:** `{event}`
**Description:** Total identity lifecycle events.

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.lifecycle.operation` | string | Lifecycle operation |
| `identity.type` | string | Identity type |

#### `identity.trust.establishments`

**Type:** Counter
**Unit:** `{trust}`
**Description:** Total trust establishment attempts.

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.trust.method` | string | Trust method |
| `identity.trust.result` | string | Trust result |
| `identity.trust.cross_domain` | boolean | Cross-domain |

#### `identity.auth_failures`

**Type:** Counter
**Unit:** `{failure}`
**Description:** Total authentication and authorization failures (security signal).

| Attribute | Type | Notes |
|-----------|------|-------|
| `identity.agent_name` | string | Agent name |
| `identity.auth.method` | string | Auth method |
| `identity.auth.failure_reason` | string | Failure reason |

---

### Asset Inventory Metrics

#### `asset.registered`

**Type:** Counter
**Unit:** `{asset}`
**Description:** Total assets registered in inventory.

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.type` | string | Asset type |
| `asset.deployment_environment` | string | Environment |
| `asset.risk_classification` | string | Risk level |

#### `asset.discovery.scans`

**Type:** Counter
**Unit:** `{scan}`
**Description:** Total asset discovery scans performed.

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.discovery.scope` | string | Discovery scope |
| `asset.discovery.method` | string | Discovery method |

#### `asset.discovery.shadow_assets`

**Type:** Counter
**Unit:** `{asset}`
**Description:** Cumulative shadow (unregistered) AI assets detected.

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.discovery.scope` | string | Discovery scope |

#### `asset.audit.runs`

**Type:** Counter
**Unit:** `{audit}`
**Description:** Total asset audits performed.

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.audit.type` | string | Audit type |
| `asset.audit.result` | string | Audit result |
| `asset.audit.framework` | string | Compliance framework |

#### `asset.audit.risk_score`

**Type:** Histogram
**Unit:** `1`
**Description:** Distribution of asset audit risk scores (0-100).

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.type` | string | Asset type |
| `asset.audit.framework` | string | Framework |

#### `asset.classification.changes`

**Type:** Counter
**Unit:** `{change}`
**Description:** Total risk classification changes.

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.risk_classification` | string | New classification |
| `asset.classification.previous` | string | Previous classification |
| `asset.classification.framework` | string | Framework |

#### `asset.audit.overdue`

**Type:** Gauge
**Unit:** `{asset}`
**Description:** Number of assets with overdue audits.

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.type` | string | Asset type |
| `asset.deployment_environment` | string | Environment |

---

### Drift Detection Metrics

#### `drift.detections`

**Type:** Counter
**Unit:** `{detection}`
**Description:** Total drift detections performed.

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.type` | string | Drift type |
| `drift.result` | string | Detection result |
| `drift.detection_method` | string | Statistical method |

#### `drift.score`

**Type:** Histogram
**Unit:** `1`
**Description:** Distribution of drift scores (0.0–1.0).

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.model_id` | string | Monitored model |
| `drift.type` | string | Drift type |

#### `drift.alerts`

**Type:** Counter
**Unit:** `{alert}`
**Description:** Total drift alerts triggered (warning, alert, critical).

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.type` | string | Drift type |
| `drift.result` | string | Alert level |
| `drift.action_triggered` | string | Action taken |

#### `drift.remediations`

**Type:** Counter
**Unit:** `{remediation}`
**Description:** Total drift remediation actions taken.

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.remediation.action` | string | Action type |
| `drift.remediation.automated` | boolean | Was automated |
| `drift.remediation.status` | string | Outcome |

#### `drift.time_to_detect`

**Type:** Histogram
**Unit:** `s`
**Description:** Time from drift onset to detection.

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.type` | string | Drift type |
| `drift.detection_method` | string | Detection method |

#### `drift.time_to_remediate`

**Type:** Histogram
**Unit:** `s`
**Description:** Time from drift detection to completed remediation.

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.remediation.action` | string | Remediation action |
| `drift.remediation.automated` | boolean | Was automated |

---

### Memory Security Metrics

#### `memory.security.mutations`

**Type:** Counter
**Unit:** `{mutation}`
**Description:** Total memory mutations tracked.

| Attribute | Type | Notes |
|-----------|------|-------|
| `memory.operation` | string | Operation type |
| `memory.store` | string | Memory store |

#### `memory.security.poisoning_detections`

**Type:** Counter
**Unit:** `{detection}`
**Description:** Total memory poisoning detections.

| Attribute | Type | Notes |
|-----------|------|-------|
| `memory.store` | string | Memory store |
| `memory.provenance` | string | Content provenance |

#### `memory.security.integrity_violations`

**Type:** Counter
**Unit:** `{violation}`
**Description:** Total memory integrity hash mismatches.

| Attribute | Type | Notes |
|-----------|------|-------|
| `memory.store` | string | Memory store |

#### `memory.security.cross_session_accesses`

**Type:** Counter
**Unit:** `{access}`
**Description:** Total cross-session memory access attempts.

| Attribute | Type | Notes |
|-----------|------|-------|
| `memory.store` | string | Memory store |

#### `memory.security.session_size`

**Type:** Histogram
**Unit:** `By`
**Description:** Memory size per session (bytes).

| Attribute | Type | Notes |
|-----------|------|-------|
| `memory.store` | string | Memory store |
