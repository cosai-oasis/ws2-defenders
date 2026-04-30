# AITF Event Conventions

AITF defines events for security findings, compliance actions, and other discrete occurrences that need to be captured alongside trace spans.

## Security Events

### `security.threat_detected`

Emitted when a security threat is detected in AI input or output.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `security.threat_type` | string | Type of threat | Yes |
| `security.owasp_category` | string | OWASP LLM category | Yes |
| `security.risk_level` | string | Risk level | Yes |
| `security.risk_score` | double | Risk score (0-100) | Yes |
| `security.confidence` | double | Detection confidence (0-1) | Yes |
| `security.detection_method` | string | How detected | Recommended |
| `security.blocked` | boolean | Whether blocked | Recommended |
| `security.details` | string | Threat details (JSON) | Recommended |

#### Threat Types

| Value | OWASP | Description |
|-------|-------|-------------|
| `prompt_injection` | LLM01 | Direct or indirect prompt injection |
| `sensitive_data_exposure` | LLM02 | Sensitive information disclosure |
| `supply_chain` | LLM03 | Compromised training data or models |
| `data_poisoning` | LLM04 | Data poisoning attempts |
| `improper_output` | LLM05 | Improper output handling |
| `excessive_agency` | LLM06 | Excessive autonomy or permissions |
| `system_prompt_leak` | LLM07 | System prompt leakage |
| `vector_data_weakness` | LLM08 | Vector/embedding weaknesses |
| `misinformation` | LLM09 | Generated misinformation |
| `unbounded_consumption` | LLM10 | Resource exhaustion / DoS |
| `jailbreak` | LLM01 | Jailbreak attempt |
| `data_exfiltration` | LLM02 | Data exfiltration attempt |
| `model_theft` | LLM03 | Model extraction attempt |

### `security.pii_detected`

Emitted when PII is detected in content.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `security.pii.types` | string[] | Types of PII found | Yes |
| `security.pii.count` | int | Number of instances | Yes |
| `security.pii.action` | string | Action taken | Yes |
| `security.pii.location` | string | `"input"`, `"output"`, `"tool_result"` | Recommended |

#### PII Types

| Value | Description |
|-------|-------------|
| `email` | Email addresses |
| `phone` | Phone numbers |
| `ssn` | Social Security Numbers |
| `credit_card` | Credit card numbers |
| `api_key` | API keys and tokens |
| `password` | Passwords |
| `address` | Physical addresses |
| `ip_address` | IP addresses |
| `name` | Personal names |
| `dob` | Dates of birth |
| `passport` | Passport numbers |
| `driver_license` | Driver's license numbers |
| `jwt` | JWT tokens |

### `security.guardrail_triggered`

Emitted when a guardrail check produces a result.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `security.guardrail.name` | string | Guardrail name | Yes |
| `security.guardrail.type` | string | `"input"`, `"output"`, `"both"` | Yes |
| `security.guardrail.result` | string | `"pass"`, `"fail"`, `"warn"` | Yes |
| `security.guardrail.provider` | string | Guardrail provider | Recommended |
| `security.guardrail.policy` | string | Policy name | Recommended |
| `security.guardrail.details` | string | Details (JSON) | Recommended |

---

## Compliance Events

### `compliance.control_mapped`

Emitted when an AI event is mapped to compliance controls.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `compliance.frameworks` | string[] | Mapped frameworks | Yes |
| `compliance.event_type` | string | Type of AI event | Yes |
| `compliance.controls` | string | All controls (JSON) | Recommended |

### `compliance.violation_detected`

Emitted when a potential compliance violation is detected.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `compliance.framework` | string | Framework | Yes |
| `compliance.control` | string | Violated control | Yes |
| `compliance.severity` | string | Violation severity | Yes |
| `compliance.details` | string | Violation details | Recommended |
| `compliance.remediation` | string | Suggested remediation | Recommended |

---

## Cost Events

### `cost.budget_warning`

Emitted when budget utilization reaches a threshold.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `cost.budget.limit` | double | Budget limit (USD) | Yes |
| `cost.budget.used` | double | Budget used (USD) | Yes |
| `cost.budget.remaining` | double | Budget remaining (USD) | Yes |
| `cost.budget.utilization_pct` | double | Utilization percentage | Yes |
| `cost.budget.threshold` | string | `"75%"`, `"90%"`, `"100%"` | Yes |
| `cost.attribution.project` | string | Project | Recommended |

### `cost.budget_exceeded`

Emitted when a budget limit is exceeded.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `cost.budget.limit` | double | Budget limit (USD) | Yes |
| `cost.budget.used` | double | Budget used (USD) | Yes |
| `cost.budget.overage` | double | Amount over budget (USD) | Yes |
| `cost.attribution.project` | string | Project | Recommended |
| `cost.action` | string | `"warn"`, `"throttle"`, `"block"` | Recommended |

---

## Quality Events

### `quality.low_confidence`

Emitted when model confidence is below threshold.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `quality.confidence` | double | Confidence score (0-1) | Yes |
| `quality.threshold` | double | Threshold value | Yes |
| `gen_ai.request.model` | string | Model ID | Recommended |

### `quality.hallucination_detected`

Emitted when potential hallucination is detected.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `quality.hallucination_score` | double | Score (0-1) | Yes |
| `quality.threshold` | double | Threshold value | Yes |
| `quality.details` | string | Details (JSON) | Recommended |

### `quality.user_feedback`

Emitted when user provides feedback.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `quality.feedback.rating` | double | Rating (1-5) | Conditional |
| `quality.feedback.thumbs` | string | `"up"`, `"down"` | Conditional |
| `quality.feedback.comment` | string | Free-text comment | Recommended |

---

## Agent Events

### `gen_ai.agent.error_recovery`

Emitted when an agent encounters and recovers from an error.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `gen_ai.agent.name` | string | Agent name | Yes |
| `gen_ai.agent.error.type` | string | Error type | Yes |
| `gen_ai.agent.error.message` | string | Error message | Yes |
| `gen_ai.agent.error.recovery_action` | string | Recovery action taken | Recommended |
| `gen_ai.agent.error.retry_count` | int | Retry count | Recommended |

### `gen_ai.agent.human_approval`

Emitted when agent requests/receives human approval.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `gen_ai.agent.name` | string | Agent name | Yes |
| `gen_ai.agent.approval.action` | string | Action requiring approval | Yes |
| `gen_ai.agent.approval.status` | string | `"requested"`, `"approved"`, `"denied"` | Yes |
| `gen_ai.agent.approval.approver` | string | Approver identity | Recommended |
| `gen_ai.agent.approval.reason` | string | Reason for decision | Recommended |

---

## Model Operations (LLMOps/MLOps) Events

### `model_ops.training_completed`

Emitted when a training or fine-tuning run completes.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `model_ops.training.run_id` | string | Training run ID | Yes |
| `model_ops.training.type` | string | Training type | Yes |
| `model_ops.training.base_model` | string | Base model | Yes |
| `model_ops.training.status` | string | `"completed"`, `"failed"`, `"cancelled"` | Yes |
| `model_ops.training.loss_final` | double | Final training loss | Recommended |
| `model_ops.training.output_model.id` | string | Output model ID | Recommended |
| `model_ops.training.compute.gpu_hours` | double | GPU hours consumed | Recommended |

### `model_ops.evaluation_completed`

Emitted when a model evaluation run completes.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `model_ops.evaluation.run_id` | string | Evaluation run ID | Yes |
| `model_ops.evaluation.model_id` | string | Model evaluated | Yes |
| `model_ops.evaluation.type` | string | Evaluation type | Yes |
| `model_ops.evaluation.pass` | boolean | Passed quality gates | Yes |
| `model_ops.evaluation.metrics` | string | JSON metric results | Recommended |
| `model_ops.evaluation.regression_detected` | boolean | Regression found | Recommended |

### `model_ops.model_promoted`

Emitted when a model is promoted through lifecycle stages.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `model_ops.registry.model_id` | string | Model ID | Yes |
| `model_ops.registry.stage` | string | New stage | Yes |
| `model_ops.registry.previous_stage` | string | Previous stage | Yes |
| `model_ops.registry.model_alias` | string | Alias assigned | Recommended |
| `model_ops.registry.approval.approver` | string | Approver | Recommended |

### `model_ops.deployment_completed`

Emitted when a model deployment completes (success or failure).

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `model_ops.deployment.id` | string | Deployment ID | Yes |
| `model_ops.deployment.model_id` | string | Model deployed | Yes |
| `model_ops.deployment.strategy` | string | Deployment strategy | Yes |
| `model_ops.deployment.status` | string | `"completed"`, `"failed"`, `"rolled_back"` | Yes |
| `model_ops.deployment.environment` | string | Target environment | Recommended |
| `model_ops.deployment.canary_percent` | double | Canary traffic % | Recommended |

### `model_ops.drift_detected`

Emitted when model monitoring detects drift above threshold.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `model_ops.monitoring.model_id` | string | Monitored model | Yes |
| `model_ops.monitoring.drift_type` | string | Type of drift | Yes |
| `model_ops.monitoring.drift_score` | double | Drift magnitude (0-1) | Yes |
| `model_ops.monitoring.result` | string | Alert level | Yes |
| `model_ops.monitoring.baseline_value` | double | Baseline value | Recommended |
| `model_ops.monitoring.metric_value` | double | Current value | Recommended |
| `model_ops.monitoring.action_triggered` | string | Automated action | Recommended |

### `model_ops.fallback_triggered`

Emitted when a model serving fallback occurs.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `model_ops.serving.fallback.original_model` | string | Original model | Yes |
| `model_ops.serving.fallback.final_model` | string | Fallback model used | Yes |
| `model_ops.serving.fallback.trigger` | string | Trigger reason | Yes |
| `model_ops.serving.fallback.depth` | int | Fallback depth | Recommended |
| `model_ops.serving.cache.cost_saved_usd` | double | Cost saved by cache | Recommended |

### `model_ops.prompt_promoted`

Emitted when a prompt version is promoted to a deployment label.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `model_ops.prompt.name` | string | Prompt name | Yes |
| `model_ops.prompt.version` | string | Promoted version | Yes |
| `model_ops.prompt.label` | string | Target label | Yes |
| `model_ops.prompt.previous_version` | string | Previous version at label | Recommended |
| `model_ops.prompt.evaluation.score` | double | Evaluation score | Recommended |

---

## Identity Events

### `identity.created`

Emitted when a new agent identity is created.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `identity.agent_id` | string | Agent identity ID | Yes |
| `identity.agent_name` | string | Agent name | Yes |
| `identity.type` | string | Identity type | Yes |
| `identity.provider` | string | Identity provider | Recommended |
| `identity.owner` | string | Identity owner | Recommended |
| `identity.credential_type` | string | Credential type | Recommended |
| `identity.ttl_seconds` | int | TTL | Recommended |

### `identity.auth_failed`

Emitted when agent authentication fails.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `identity.agent_id` | string | Agent identity ID | Yes |
| `identity.agent_name` | string | Agent name | Yes |
| `identity.auth.method` | string | Auth method used | Yes |
| `identity.auth.result` | string | Failure type | Yes |
| `identity.auth.failure_reason` | string | Failure reason | Yes |
| `identity.auth.target_service` | string | Target service | Recommended |

### `identity.authz_denied`

Emitted when an authorization request is denied.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `identity.agent_id` | string | Agent identity ID | Yes |
| `identity.agent_name` | string | Agent name | Yes |
| `identity.authz.resource` | string | Resource requested | Yes |
| `identity.authz.action` | string | Action requested | Yes |
| `identity.authz.deny_reason` | string | Denial reason | Yes |
| `identity.authz.policy_id` | string | Policy that denied | Recommended |

### `identity.delegation_created`

Emitted when credentials are delegated between agents.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `identity.delegation.delegator` | string | Delegating agent | Yes |
| `identity.delegation.delegatee` | string | Receiving agent | Yes |
| `identity.delegation.type` | string | Delegation type | Yes |
| `identity.delegation.scope_delegated` | string[] | Delegated scopes | Yes |
| `identity.delegation.chain_depth` | int | Chain depth | Recommended |
| `identity.delegation.scope_attenuated` | boolean | Scope was reduced | Recommended |
| `identity.delegation.ttl_seconds` | int | Delegation TTL | Recommended |

### `identity.privilege_escalation`

Emitted when potential privilege escalation is detected — an agent attempts to access resources beyond its delegated scope.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `identity.agent_id` | string | Agent identity ID | Yes |
| `identity.agent_name` | string | Agent name | Yes |
| `identity.authz.resource` | string | Resource attempted | Yes |
| `identity.authz.action` | string | Action attempted | Yes |
| `identity.authz.scope_required` | string[] | Scopes required | Yes |
| `identity.authz.scope_present` | string[] | Scopes present | Yes |
| `identity.delegation.chain` | string[] | Delegation chain | Recommended |

### `identity.credential_rotated`

Emitted when agent credentials are rotated.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `identity.agent_id` | string | Agent identity ID | Yes |
| `identity.credential_type` | string | Credential type | Yes |
| `identity.auto_rotate` | boolean | Was auto-rotation | Yes |
| `identity.expires_at` | string | New expiration | Recommended |

### `identity.revoked`

Emitted when an agent identity is revoked.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `identity.agent_id` | string | Agent identity ID | Yes |
| `identity.agent_name` | string | Agent name | Yes |
| `identity.status` | string | New status (`"revoked"`) | Yes |
| `identity.previous_status` | string | Previous status | Yes |
| `identity.lifecycle.operation` | string | `"revoke"` | Yes |

### `identity.trust_established`

Emitted when trust is established between two agents.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `identity.agent_name` | string | This agent | Yes |
| `identity.trust.peer_agent` | string | Peer agent | Yes |
| `identity.trust.method` | string | Trust method | Yes |
| `identity.trust.result` | string | Trust result | Yes |
| `identity.trust.trust_level` | string | Trust level | Recommended |
| `identity.trust.cross_domain` | boolean | Cross-domain | Recommended |

### `identity.session_hijack_detected`

Emitted when potential session hijacking is detected.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `identity.agent_id` | string | Agent identity ID | Yes |
| `identity.session.id` | string | Session ID | Yes |
| `identity.session.ip_address` | string | Anomalous source IP | Recommended |
| `identity.session.user_agent` | string | Anomalous user agent | Recommended |

---

## Asset Inventory Events

### `asset.registered`

Emitted when a new AI asset is registered in the inventory.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `asset.id` | string | Asset identifier | Yes |
| `asset.name` | string | Asset name | Yes |
| `asset.type` | string | Asset type | Yes |
| `asset.owner` | string | Asset owner | Yes |
| `asset.deployment_environment` | string | Environment | Recommended |
| `asset.risk_classification` | string | Risk classification | Recommended |

### `asset.shadow_detected`

Emitted when a shadow (unregistered) AI asset is discovered during a scan.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `asset.type` | string | Discovered asset type | Yes |
| `asset.discovery.scope` | string | Discovery scope | Yes |
| `asset.discovery.method` | string | Discovery method | Yes |
| `asset.name` | string | Discovered asset name | Recommended |
| `asset.deployment_environment` | string | Where found | Recommended |

### `asset.audit_failed`

Emitted when an AI asset fails a compliance or integrity audit.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `asset.id` | string | Asset identifier | Yes |
| `asset.audit.type` | string | Audit type | Yes |
| `asset.audit.result` | string | `"fail"` | Yes |
| `asset.audit.framework` | string | Framework | Recommended |
| `asset.audit.findings` | string | JSON findings | Recommended |
| `asset.audit.risk_score` | double | Risk score | Recommended |

### `asset.risk_reclassified`

Emitted when an asset's risk classification changes.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `asset.id` | string | Asset identifier | Yes |
| `asset.risk_classification` | string | New classification | Yes |
| `asset.classification.previous` | string | Previous classification | Yes |
| `asset.classification.framework` | string | Framework | Yes |
| `asset.classification.reason` | string | Reason for change | Recommended |

### `asset.decommissioned`

Emitted when an AI asset is decommissioned.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `asset.id` | string | Asset identifier | Yes |
| `asset.type` | string | Asset type | Yes |
| `asset.decommission.reason` | string | Decommission reason | Yes |
| `asset.decommission.replacement_id` | string | Replacement asset | Recommended |

### `asset.audit_overdue`

Emitted when an asset's audit is overdue.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `asset.id` | string | Asset identifier | Yes |
| `asset.audit.next_audit_due` | string | Overdue audit date | Yes |
| `asset.risk_classification` | string | Risk level | Recommended |
| `asset.deployment_environment` | string | Environment | Recommended |

---

## Drift Detection Events

### `drift.detected`

Emitted when model drift is detected above threshold. Provides structured forensic-quality drift analysis beyond the basic `model_ops.drift_detected`.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `drift.model_id` | string | Monitored model | Yes |
| `drift.type` | string | Drift type | Yes |
| `drift.score` | double | Drift magnitude (0–1) | Yes |
| `drift.result` | string | Alert level | Yes |
| `drift.detection_method` | string | Statistical method | Yes |
| `drift.baseline_metric` | double | Baseline value | Recommended |
| `drift.current_metric` | double | Current value | Recommended |
| `drift.p_value` | double | Statistical significance | Recommended |
| `drift.affected_segments` | string[] | Impacted segments | Recommended |
| `drift.reference_dataset` | string | Reference dataset | Recommended |
| `drift.action_triggered` | string | Automated action | Recommended |

### `drift.baseline_updated`

Emitted when a drift baseline is created or refreshed.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `drift.model_id` | string | Model | Yes |
| `drift.baseline.operation` | string | `"create"` or `"refresh"` | Yes |
| `drift.baseline.id` | string | Baseline identifier | Yes |
| `drift.baseline.dataset` | string | Baseline dataset | Recommended |
| `drift.baseline.sample_size` | int | Sample size | Recommended |

### `drift.investigation_completed`

Emitted when a drift investigation completes with root cause analysis.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `drift.model_id` | string | Model investigated | Yes |
| `drift.investigation.root_cause_category` | string | Root cause category | Yes |
| `drift.investigation.severity` | string | Severity | Yes |
| `drift.investigation.blast_radius` | string | Impact scope | Yes |
| `drift.investigation.affected_users_estimate` | int | Affected users | Recommended |
| `drift.investigation.recommendation` | string | Recommendation | Recommended |

### `drift.remediation_completed`

Emitted when a drift remediation action completes.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `drift.model_id` | string | Model remediated | Yes |
| `drift.remediation.action` | string | Action taken | Yes |
| `drift.remediation.status` | string | Outcome status | Yes |
| `drift.remediation.automated` | boolean | Was automated | Yes |
| `drift.remediation.validation_passed` | boolean | Post-validation passed | Recommended |

---

## Memory Security Events

### `memory.poisoning_detected`

Emitted when memory poisoning is detected (unexpected content injection).

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `memory.key` | string | Affected memory key | Yes |
| `memory.store` | string | Memory store | Yes |
| `memory.security.poisoning_score` | double | Poisoning score (0-1) | Yes |
| `memory.provenance` | string | Content provenance | Yes |
| `gen_ai.conversation.id` | string | Session ID | Recommended |

### `memory.integrity_violation`

Emitted when memory content hash does not match expected integrity hash.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `memory.key` | string | Affected memory key | Yes |
| `memory.store` | string | Memory store | Yes |
| `memory.security.integrity_hash` | string | Expected hash | Yes |
| `memory.security.content_hash` | string | Actual hash | Yes |
| `gen_ai.conversation.id` | string | Session ID | Recommended |

### `memory.cross_session_access`

Emitted when a session accesses memory belonging to another session.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `memory.key` | string | Accessed memory key | Yes |
| `memory.store` | string | Memory store | Yes |
| `gen_ai.conversation.id` | string | Accessing session | Yes |

### `memory.growth_anomaly`

Emitted when session memory growth exceeds configured thresholds.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `gen_ai.conversation.id` | string | Session ID | Yes |
| `memory.security.mutation_count` | int | Current entry count | Yes |
| `memory.security.content_size` | int | Current total size | Recommended |

### `memory.untrusted_provenance`

Emitted when memory is written from an untrusted provenance source.

| Attribute | Type | Description | Required |
|-----------|------|-------------|----------|
| `memory.key` | string | Memory key | Yes |
| `memory.store` | string | Memory store | Yes |
| `memory.provenance` | string | Untrusted provenance | Yes |
| `gen_ai.conversation.id` | string | Session ID | Recommended |
