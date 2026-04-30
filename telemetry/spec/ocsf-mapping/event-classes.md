# OCSF Category 7: AI Event Classes

AITF defines OCSF event classes for AI-specific security telemetry, enabling SIEM/XDR integration.

## Overview

These event classes extend the OCSF v1.1.0 specification with a new Category 7 for AI systems. They enable AI telemetry to be consumed by security tools using the same schema as traditional security events.

### Category: AI System Activity (7)

| Class UID | Event Class | Description |
|-----------|-------------|-------------|
| 7001 | AI Model Inference | LLM/model inference requests and responses |
| 7002 | AI Agent Activity | Agent lifecycle, reasoning, delegation |
| 7003 | AI Tool Execution | Tool/function calls including MCP tools |
| 7004 | AI Data Retrieval | RAG, vector search, knowledge retrieval |
| 7005 | AI Security Finding | Security events, guardrails, policy violations |
| 7006 | AI Supply Chain | Model provenance, AI-BOM, integrity |
| 7007 | AI Governance | Compliance, audit, regulatory events |
| 7008 | AI Identity | Agent identity, authentication, authorization, delegation, trust |
| 7009 | AI Model Operations | Model lifecycle: training, evaluation, deployment, monitoring, serving |
| 7010 | AI Asset Inventory | Asset registration, discovery, audit, risk classification, drift detection |

---

## Class 7001: AI Model Inference

Represents an AI model inference operation (request + response).

### Type UIDs

| type_uid | Activity | Description |
|----------|----------|-------------|
| 700101 | Chat Completion | Chat/conversation inference |
| 700102 | Text Completion | Text generation inference |
| 700103 | Embedding Generation | Embedding computation |
| 700104 | Image Generation | Image creation/editing |
| 700105 | Audio Processing | Speech-to-text, text-to-speech |
| 700199 | Other | Other inference types |

### Fields

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `model` | `AIModelInfo` | Required | Model information |
| `token_usage` | `AITokenUsage` | Required | Token usage statistics |
| `latency` | `AILatencyMetrics` | Recommended | Latency metrics |
| `request_content` | string | Optional | Request content (may be redacted) |
| `response_content` | string | Optional | Response content (may be redacted) |
| `streaming` | boolean | Optional | Whether streaming mode |
| `tools_provided` | int | Optional | Number of tools provided |
| `finish_reason` | string | Required | Completion finish reason |
| `cost` | `AICostInfo` | Recommended | Cost information |
| `error` | `AIErrorInfo` | Conditional | Error details (if failed) |

### Objects

#### `AIModelInfo`

| Field | Type | Description |
|-------|------|-------------|
| `model_id` | string | Model identifier |
| `name` | string | Model display name |
| `version` | string | Model version |
| `provider` | string | Model provider (openai, anthropic, etc.) |
| `type` | string | Model type (llm, embedding, image, audio) |
| `parameters` | object | Model parameters (temperature, etc.) |

#### `AITokenUsage`

| Field | Type | Description |
|-------|------|-------------|
| `input_tokens` | int | Input/prompt tokens |
| `output_tokens` | int | Output/completion tokens |
| `total_tokens` | int | Total tokens |
| `cached_tokens` | int | Cached/prefix tokens |
| `reasoning_tokens` | int | Reasoning/thinking tokens |
| `estimated_cost_usd` | double | Estimated cost in USD |

#### `AILatencyMetrics`

| Field | Type | Description |
|-------|------|-------------|
| `total_ms` | double | Total latency (ms) |
| `time_to_first_token_ms` | double | Time to first token (ms) |
| `tokens_per_second` | double | Token generation rate |
| `queue_time_ms` | double | Time in queue (ms) |
| `inference_time_ms` | double | Inference processing time (ms) |

#### `AICostInfo`

| Field | Type | Description |
|-------|------|-------------|
| `input_cost_usd` | double | Input token cost |
| `output_cost_usd` | double | Output token cost |
| `total_cost_usd` | double | Total cost |
| `currency` | string | Currency code |

---

## Class 7002: AI Agent Activity

Represents an AI agent lifecycle event.

### Type UIDs

| type_uid | Activity | Description |
|----------|----------|-------------|
| 700201 | Session Start | Agent session begins |
| 700202 | Session End | Agent session ends |
| 700203 | Step Execute | Agent executes a step |
| 700204 | Delegation | Agent delegates to another |
| 700205 | Memory Access | Agent accesses memory |
| 700206 | Error Recovery | Agent recovers from error |
| 700207 | Human Approval | Agent requests human input |
| 700299 | Other | Other agent activity |

### Fields

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `agent_name` | string | Required | Agent name |
| `agent_id` | string | Required | Agent instance ID |
| `agent_type` | string | Required | Agent type |
| `framework` | string | Recommended | Agent framework |
| `session_id` | string | Required | Session ID |
| `step_type` | string | Conditional | Step type (for step events) |
| `step_index` | int | Conditional | Step index |
| `thought` | string | Optional | Agent reasoning |
| `action` | string | Optional | Planned/executed action |
| `observation` | string | Optional | Observation result |
| `delegation_target` | string | Conditional | Target agent (for delegation) |
| `team_info` | `AITeamInfo` | Optional | Team information |

#### `AITeamInfo`

| Field | Type | Description |
|-------|------|-------------|
| `team_name` | string | Team name |
| `team_id` | string | Team ID |
| `topology` | string | Team topology |
| `members` | string[] | Member agent names |
| `coordinator` | string | Coordinator agent |

---

## Class 7003: AI Tool Execution

Represents a tool/function execution, including MCP tools and skills.

### Type UIDs

| type_uid | Activity | Description |
|----------|----------|-------------|
| 700301 | Function Call | LLM function/tool call |
| 700302 | MCP Tool Invoke | MCP tool invocation |
| 700303 | Skill Invoke | Skill invocation |
| 700304 | API Call | External API call |
| 700305 | Code Execute | Code execution |
| 700399 | Other | Other tool execution |

### Fields

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `tool_name` | string | Required | Tool/function name |
| `tool_type` | string | Required | `"function"`, `"mcp_tool"`, `"skill"`, `"api"` |
| `tool_input` | string | Recommended | Input parameters (JSON) |
| `tool_output` | string | Optional | Output (may be redacted) |
| `is_error` | boolean | Required | Whether tool returned error |
| `duration_ms` | double | Recommended | Execution duration |
| `mcp_server` | string | Conditional | MCP server (for MCP tools) |
| `mcp_transport` | string | Conditional | MCP transport type |
| `skill_category` | string | Conditional | Skill category |
| `skill_version` | string | Conditional | Skill version |
| `approval_required` | boolean | Optional | Whether human approval needed |
| `approved` | boolean | Conditional | Whether approved |

---

## Class 7004: AI Data Retrieval

Represents RAG and vector search operations.

### Type UIDs

| type_uid | Activity | Description |
|----------|----------|-------------|
| 700401 | Vector Search | Vector similarity search |
| 700402 | Document Retrieval | Document retrieval |
| 700403 | Knowledge Graph Query | Knowledge graph query |
| 700404 | Embedding Generation | Embedding creation for retrieval |
| 700405 | Reranking | Result reranking |
| 700499 | Other | Other retrieval |

### Fields

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `database_name` | string | Required | Database/index name |
| `database_type` | string | Required | `"pinecone"`, `"chromadb"`, `"weaviate"`, etc. |
| `query` | string | Optional | Query text (may be redacted) |
| `top_k` | int | Recommended | Results requested |
| `results_count` | int | Required | Results returned |
| `min_score` | double | Recommended | Minimum similarity score |
| `max_score` | double | Recommended | Maximum similarity score |
| `filter` | string | Optional | Metadata filter (JSON) |
| `embedding_model` | string | Recommended | Embedding model used |
| `embedding_dimensions` | int | Optional | Embedding dimensions |
| `pipeline_name` | string | Optional | RAG pipeline name |
| `pipeline_stage` | string | Optional | Pipeline stage |
| `quality_scores` | `AIQualityScores` | Optional | Quality metrics |

---

## Class 7005: AI Security Finding

Represents a security finding in AI operations.

### Type UIDs

| type_uid | Activity | Description |
|----------|----------|-------------|
| 700501 | Threat Detection | Threat detected |
| 700502 | PII Detection | PII found in content |
| 700503 | Guardrail Trigger | Guardrail check result |
| 700504 | Policy Violation | Policy violation |
| 700505 | Anomaly Detection | Anomalous behavior |
| 700599 | Other | Other security finding |

### Fields

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `finding_type` | string | Required | Type of finding |
| `owasp_category` | string | Conditional | OWASP LLM category |
| `risk_level` | string | Required | `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"` |
| `risk_score` | double | Required | Risk score (0-100) |
| `confidence` | double | Required | Detection confidence (0-1) |
| `detection_method` | string | Required | `"pattern"`, `"ml_model"`, `"guardrail"`, `"policy"` |
| `blocked` | boolean | Required | Whether action was blocked |
| `details` | string | Recommended | Finding details (JSON) |
| `remediation` | string | Optional | Suggested remediation |
| `guardrail_name` | string | Conditional | Guardrail name |
| `guardrail_provider` | string | Conditional | Guardrail provider |
| `pii_types` | string[] | Conditional | PII types found |
| `pii_count` | int | Conditional | PII instance count |
| `matched_patterns` | string[] | Optional | Matched detection patterns |

---

## Class 7006: AI Supply Chain

Represents AI supply chain events (model provenance, integrity).

### Type UIDs

| type_uid | Activity | Description |
|----------|----------|-------------|
| 700601 | Model Registration | New model registered |
| 700602 | Model Verification | Model integrity check |
| 700603 | AI-BOM Generation | AI Bill of Materials created |
| 700604 | Dependency Check | Dependency security check |
| 700699 | Other | Other supply chain event |

### Fields

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `model_source` | string | Required | Model source |
| `model_hash` | string | Recommended | Model hash |
| `model_license` | string | Recommended | Model license |
| `model_signed` | boolean | Recommended | Whether signed |
| `model_signer` | string | Conditional | Signer identity |
| `verification_result` | string | Conditional | `"pass"`, `"fail"`, `"unknown"` |
| `ai_bom_id` | string | Conditional | AI-BOM ID |
| `ai_bom_components` | string | Conditional | Components (JSON) |

---

## Class 7007: AI Governance

Represents compliance and governance events.

### Type UIDs

| type_uid | Activity | Description |
|----------|----------|-------------|
| 700701 | Compliance Check | Compliance verification |
| 700702 | Audit Record | Audit trail entry |
| 700703 | Policy Evaluation | Policy evaluation |
| 700704 | Risk Assessment | Risk assessment |
| 700799 | Other | Other governance event |

### Fields

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `frameworks` | string[] | Required | Compliance frameworks |
| `controls` | string | Required | Mapped controls (JSON) |
| `event_type` | string | Required | Source event type |
| `violation_detected` | boolean | Required | Whether violation found |
| `severity` | string | Conditional | Violation severity |
| `remediation` | string | Optional | Suggested remediation |
| `audit_id` | string | Recommended | Audit record ID |

---

## Class 7008: AI Identity

Represents agent identity, authentication, authorization, delegation, and trust events.

### Type UIDs

| type_uid | Activity | Description |
|----------|----------|-------------|
| 700801 | Agent Authentication | Agent authenticates to a service |
| 700802 | Credential Delegation | Credentials delegated between agents |
| 700803 | Permission Check | Authorization decision evaluated |
| 700804 | Token Issuance | Auth token issued or exchanged |
| 700805 | Identity Lifecycle | Identity created, rotated, suspended, revoked |
| 700806 | Trust Establishment | Agent-to-agent trust established or revoked |
| 700807 | Session Management | Identity session created, refreshed, terminated |
| 700808 | Privilege Escalation | Potential privilege escalation detected |
| 700899 | Other | Other identity event |

### Fields

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `agent_name` | string | Required | Agent name |
| `agent_id` | string | Required | Agent identity ID |
| `identity_type` | string | Required | `"persistent"`, `"ephemeral"`, `"delegated"`, `"federated"`, `"workload"` |
| `auth_method` | string | Required | `"api_key"`, `"oauth2"`, `"oauth2_pkce"`, `"mtls"`, `"spiffe_svid"`, `"jwt_bearer"`, `"did_vc"`, `"http_signature"` |
| `auth_result` | string | Required | `"success"`, `"failure"`, `"denied"`, `"expired"`, `"revoked"` |
| `identity_provider` | string | Recommended | Identity provider name |
| `credential_type` | string | Recommended | Credential type issued or used |
| `permissions` | string[] | Recommended | Granted/checked permissions |
| `scope_requested` | string[] | Conditional | Scopes requested |
| `scope_granted` | string[] | Conditional | Scopes actually granted |
| `delegation_info` | `AIDelegationInfo` | Conditional | Delegation details (for delegation events) |
| `trust_info` | `AITrustInfo` | Conditional | Trust details (for trust events) |
| `session_info` | `AIIdentitySessionInfo` | Conditional | Session details |
| `policy_engine` | string | Conditional | `"opa"`, `"cedar"`, `"casbin"`, `"custom"` |
| `policy_id` | string | Conditional | Matched policy ID |
| `risk_score` | double | Optional | Risk-based authorization score (0-100) |
| `identity_status` | string | Conditional | `"active"`, `"suspended"`, `"revoked"`, `"expired"` |
| `owner` | string | Optional | Identity owner |
| `failure_reason` | string | Conditional | Authentication/authorization failure reason |

### Objects

#### `AIDelegationInfo`

| Field | Type | Description |
|-------|------|-------------|
| `delegator` | string | Agent/user delegating authority |
| `delegator_id` | string | Delegator identity ID |
| `delegatee` | string | Agent receiving authority |
| `delegatee_id` | string | Delegatee identity ID |
| `delegation_type` | string | `"on_behalf_of"`, `"token_exchange"`, `"capability_grant"`, `"impersonation"` |
| `delegation_chain` | string[] | Full delegation chain from origin |
| `chain_depth` | int | Depth of delegation chain |
| `scope_delegated` | string[] | Scopes being delegated |
| `scope_attenuated` | boolean | Whether scope was reduced |
| `proof_type` | string | `"dpop"`, `"mtls_binding"`, `"signed_assertion"` |
| `ttl_seconds` | int | Delegation time to live |

#### `AITrustInfo`

| Field | Type | Description |
|-------|------|-------------|
| `peer_agent` | string | Peer agent name |
| `peer_agent_id` | string | Peer agent identity ID |
| `trust_method` | string | `"mtls"`, `"spiffe"`, `"did_vc"`, `"http_signature"`, `"pki"` |
| `trust_result` | string | `"established"`, `"failed"`, `"rejected"`, `"revoked"` |
| `trust_domain` | string | Trust domain |
| `peer_trust_domain` | string | Peer's trust domain |
| `cross_domain` | boolean | Whether cross-domain |
| `trust_level` | string | `"none"`, `"basic"`, `"verified"`, `"high"`, `"full"` |
| `protocol` | string | `"mcp"`, `"a2a"`, `"custom"` |

#### `AIIdentitySessionInfo`

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | Identity session ID |
| `operation` | string | `"create"`, `"refresh"`, `"validate"`, `"terminate"`, `"hijack_detected"` |
| `scope` | string[] | Active session scopes |
| `expires_at` | string | Session expiration timestamp |
| `actions_count` | int | Actions performed in session |
| `termination_reason` | string | `"completed"`, `"timeout"`, `"revoked"`, `"error"` |

---

## Class 7009: AI Model Operations

Represents model lifecycle events — training, evaluation, deployment, monitoring, and serving operations.

### Type UIDs

| type_uid | Activity | Description |
|----------|----------|-------------|
| 700901 | Training Run | Model training or fine-tuning run |
| 700902 | Evaluation Run | Model evaluation or benchmarking |
| 700903 | Model Registration | Model registered in registry |
| 700904 | Model Promotion | Model promoted through lifecycle stages |
| 700905 | Model Deployment | Model deployed to environment |
| 700906 | Model Rollback | Model rolled back to previous version |
| 700907 | Drift Detection | Model drift detected |
| 700908 | Serving Fallback | Model serving fallback triggered |
| 700909 | Prompt Version | Prompt version lifecycle event |
| 700999 | Other | Other model operations event |

### Fields

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `model_id` | string | Required | Model identifier |
| `model_version` | string | Recommended | Model version |
| `operation_type` | string | Required | Operation category (see below) |
| `training_info` | `AITrainingInfo` | Conditional | Training details (for training events) |
| `evaluation_info` | `AIEvaluationInfo` | Conditional | Evaluation details |
| `registry_info` | `AIRegistryInfo` | Conditional | Registry operation details |
| `deployment_info` | `AIDeploymentInfo` | Conditional | Deployment details |
| `monitoring_info` | `AIMonitoringInfo` | Conditional | Monitoring/drift details |
| `serving_info` | `AIServingInfo` | Conditional | Serving/routing details |
| `prompt_info` | `AIPromptInfo` | Conditional | Prompt lifecycle details |
| `lineage` | `AIModelLineage` | Recommended | Model lineage/provenance |

### Operation Categories

| Value | Description |
|-------|-------------|
| `training` | Training or fine-tuning operation |
| `evaluation` | Model evaluation or benchmarking |
| `registry` | Model registry operation |
| `deployment` | Model deployment operation |
| `monitoring` | Model monitoring event |
| `serving` | Model serving operation |
| `prompt` | Prompt lifecycle operation |

### Objects

#### `AITrainingInfo`

| Field | Type | Description |
|-------|------|-------------|
| `run_id` | string | Training run identifier |
| `training_type` | string | `"fine_tuning"`, `"lora"`, `"rlhf"`, `"dpo"`, `"distillation"` |
| `base_model` | string | Foundation model ID |
| `framework` | string | Training framework |
| `dataset_id` | string | Training dataset identifier |
| `dataset_version` | string | Dataset version |
| `dataset_size` | int | Number of training examples |
| `hyperparameters` | string | JSON-encoded hyperparameters |
| `epochs` | int | Training epochs |
| `loss_final` | double | Final training loss |
| `val_loss_final` | double | Final validation loss |
| `gpu_type` | string | GPU type |
| `gpu_count` | int | Number of GPUs |
| `gpu_hours` | double | GPU hours consumed |
| `output_model_id` | string | Output model artifact ID |
| `output_model_hash` | string | Output model hash |
| `code_commit` | string | Code commit SHA |
| `status` | string | `"running"`, `"completed"`, `"failed"`, `"cancelled"` |

#### `AIEvaluationInfo`

| Field | Type | Description |
|-------|------|-------------|
| `run_id` | string | Evaluation run identifier |
| `eval_type` | string | `"benchmark"`, `"llm_judge"`, `"safety"`, `"regression"`, `"red_team"` |
| `dataset_id` | string | Evaluation dataset ID |
| `dataset_size` | int | Evaluation examples count |
| `metrics` | string | JSON-encoded metric results |
| `judge_model` | string | LLM-as-judge model |
| `baseline_model` | string | Baseline model for comparison |
| `regression_detected` | boolean | Whether regression detected |
| `pass` | boolean | Passed quality gates |
| `gate_criteria` | string | JSON quality gate criteria |

#### `AIRegistryInfo`

| Field | Type | Description |
|-------|------|-------------|
| `operation` | string | `"register"`, `"promote"`, `"demote"`, `"archive"`, `"rollback"` |
| `model_alias` | string | Model alias (e.g., `"@champion"`) |
| `stage` | string | `"experimental"`, `"staging"`, `"production"`, `"archived"` |
| `previous_stage` | string | Previous lifecycle stage |
| `owner` | string | Model owner |
| `approval_required` | boolean | Whether approval was needed |
| `approver` | string | Approver identity |

#### `AIDeploymentInfo`

| Field | Type | Description |
|-------|------|-------------|
| `deployment_id` | string | Deployment identifier |
| `strategy` | string | `"rolling"`, `"canary"`, `"blue_green"`, `"shadow"`, `"a_b_test"` |
| `environment` | string | `"development"`, `"staging"`, `"production"` |
| `endpoint` | string | Serving endpoint |
| `infrastructure_provider` | string | Cloud/infra provider |
| `gpu_type` | string | GPU type |
| `replicas` | int | Number of replicas |
| `canary_percent` | double | Canary traffic percentage |
| `previous_model_id` | string | Model being replaced |
| `status` | string | `"pending"`, `"in_progress"`, `"completed"`, `"failed"`, `"rolled_back"` |
| `health_check_status` | string | `"healthy"`, `"degraded"`, `"unhealthy"` |

#### `AIMonitoringInfo`

| Field | Type | Description |
|-------|------|-------------|
| `check_type` | string | `"data_drift"`, `"embedding_drift"`, `"performance_degradation"`, `"cost_anomaly"` |
| `result` | string | `"normal"`, `"warning"`, `"alert"`, `"critical"` |
| `metric_name` | string | Metric being checked |
| `metric_value` | double | Current metric value |
| `baseline_value` | double | Baseline/expected value |
| `threshold` | double | Alert threshold |
| `drift_score` | double | Drift magnitude (0-1) |
| `drift_type` | string | `"data"`, `"prediction"`, `"concept"`, `"embedding"` |
| `action_triggered` | string | `"none"`, `"alert"`, `"retrain"`, `"rollback"` |

#### `AIServingInfo`

| Field | Type | Description |
|-------|------|-------------|
| `operation` | string | `"route"`, `"fallback"`, `"cache_lookup"`, `"circuit_breaker"` |
| `selected_model` | string | Model selected by router |
| `route_reason` | string | Routing reason |
| `fallback_chain` | string[] | Ordered fallback chain |
| `fallback_depth` | int | Fallback chain depth used |
| `fallback_trigger` | string | `"error"`, `"timeout"`, `"rate_limit"`, `"circuit_breaker"` |
| `cache_hit` | boolean | Whether cache was hit |
| `cache_type` | string | `"exact"`, `"semantic"`, `"hybrid"` |
| `cost_saved_usd` | double | Cost saved by cache hit |
| `circuit_breaker_state` | string | `"closed"`, `"open"`, `"half_open"` |

#### `AIPromptInfo`

| Field | Type | Description |
|-------|------|-------------|
| `prompt_name` | string | Prompt template name |
| `operation` | string | `"create"`, `"promote"`, `"rollback"`, `"evaluate"`, `"a_b_test_start"` |
| `version` | string | Prompt version (SemVer) |
| `previous_version` | string | Previous version |
| `content_hash` | string | Template content hash |
| `label` | string | Deployment label |
| `model_target` | string | Target model |
| `eval_score` | double | Evaluation score (0-1) |
| `eval_pass` | boolean | Passed quality gate |
| `ab_test_id` | string | A/B experiment ID |
| `ab_test_variant` | string | Variant name |

#### `AIModelLineage`

| Field | Type | Description |
|-------|------|-------------|
| `training_run_id` | string | Training run that produced this model |
| `parent_model_id` | string | Parent model (for fine-tuned models) |
| `dataset_id` | string | Training dataset |
| `code_commit` | string | Code commit SHA |
| `experiment_id` | string | Experiment tracker ID |

---

## Class 7010: AI Asset Inventory

Represents AI asset lifecycle events — registration, discovery, audit, risk classification, drift detection, and decommissioning. Enables organizations to maintain a complete, auditable inventory of all AI system components as required by CoSAI AI Incident Response preparation guidance.

### Type UIDs

| type_uid | Activity | Description |
|----------|----------|-------------|
| 701001 | Asset Registration | New AI asset registered in inventory |
| 701002 | Asset Discovery | Automated asset discovery scan |
| 701003 | Asset Audit | Periodic audit or compliance check |
| 701004 | Risk Classification | EU AI Act or internal risk classification |
| 701005 | Dependency Mapping | Dependency graph resolution |
| 701006 | Decommission | Asset retirement or decommissioning |
| 701007 | Shadow Asset Detected | Unregistered AI asset discovered |
| 701008 | Audit Overdue | Asset audit past due date |
| 701009 | Drift Detection | Structured model drift analysis |
| 701010 | Drift Baseline | Drift baseline create/refresh |
| 701011 | Drift Investigation | Root cause investigation |
| 701012 | Drift Remediation | Remediation action for drift |
| 701013 | Memory Security Event | Memory poisoning, integrity, or isolation event |
| 701099 | Other | Other asset inventory events |

### Fields

| Field | Type | Requirement | Description |
|-------|------|-------------|-------------|
| `asset_info` | `AIAssetInfo` | Required | Asset information |
| `audit_info` | `AIAuditInfo` | Conditional | Audit details (for audit events) |
| `classification_info` | `AIClassificationInfo` | Conditional | Risk classification details |
| `drift_info` | `AIDriftInfo` | Conditional | Drift detection details |
| `memory_security_info` | `AIMemorySecurityInfo` | Conditional | Memory security details |

### OCSF Objects

#### `AIAssetInfo`

| Field | Type | Description |
|-------|------|-------------|
| `asset_id` | string | Unique asset identifier |
| `name` | string | Human-readable name |
| `type` | string | `"model"`, `"dataset"`, `"prompt_template"`, `"vector_db"`, `"mcp_server"`, `"agent"`, `"pipeline"`, `"guardrail"` |
| `version` | string | Asset version |
| `hash` | string | Content integrity hash |
| `owner` | string | Asset owner |
| `deployment_environment` | string | `"production"`, `"staging"`, `"development"`, `"shadow"` |
| `risk_classification` | string | `"unacceptable"`, `"high_risk"`, `"limited_risk"`, `"minimal_risk"`, `"systemic"`, `"not_classified"` |
| `source_repository` | string | Source repository URL |
| `tags` | string[] | Searchable tags |
| `created_at` | timestamp | Registration timestamp |

#### `AIAuditInfo`

| Field | Type | Description |
|-------|------|-------------|
| `audit_type` | string | `"integrity"`, `"compliance"`, `"access_review"`, `"security"`, `"drift"`, `"lineage"`, `"full"` |
| `result` | string | `"pass"`, `"fail"`, `"warning"`, `"not_applicable"` |
| `auditor` | string | Auditor identity |
| `framework` | string | Compliance framework |
| `findings` | string | JSON audit findings |
| `risk_score` | double | Calculated risk score (0-100) |
| `integrity_verified` | boolean | Integrity hash verified |
| `compliance_status` | string | `"compliant"`, `"non_compliant"`, `"partially_compliant"` |
| `last_audit_time` | timestamp | Previous audit time |
| `next_audit_due` | timestamp | Next scheduled audit |

#### `AIClassificationInfo`

| Field | Type | Description |
|-------|------|-------------|
| `framework` | string | Classification framework (`"eu_ai_act"`, `"nist_ai_rmf"`, `"internal"`) |
| `previous_classification` | string | Previous risk level |
| `reason` | string | Reason for classification |
| `assessor` | string | Assessor identity |
| `use_case` | string | Intended use case |
| `affected_persons` | string | Population affected |
| `sector` | string | Deployment sector |
| `biometric` | boolean | Uses biometric data |
| `autonomous_decision` | boolean | Makes autonomous decisions affecting rights |

#### `AIDriftInfo`

| Field | Type | Description |
|-------|------|-------------|
| `model_id` | string | Model being monitored |
| `drift_type` | string | `"data_distribution"`, `"concept"`, `"performance"`, `"calibration"`, `"embedding"`, `"feature"`, `"prediction"` |
| `score` | double | Drift magnitude (0.0–1.0) |
| `result` | string | `"normal"`, `"warning"`, `"alert"`, `"critical"` |
| `detection_method` | string | Statistical method used |
| `baseline_metric` | double | Baseline metric value |
| `current_metric` | double | Current metric value |
| `metric_name` | string | Metric name |
| `p_value` | double | Statistical significance |
| `reference_dataset` | string | Reference dataset ID |
| `reference_period` | string | Reference time period |
| `affected_segments` | string[] | Impacted user/data segments |
| `action_triggered` | string | Automated action taken |
| `investigation` | `AIDriftInvestigation` | Investigation details (if applicable) |
| `remediation` | `AIDriftRemediation` | Remediation details (if applicable) |

#### `AIDriftInvestigation`

| Field | Type | Description |
|-------|------|-------------|
| `trigger_id` | string | Detection event that triggered investigation |
| `root_cause` | string | Identified root cause |
| `root_cause_category` | string | `"data_quality"`, `"upstream_change"`, `"seasonal"`, `"adversarial"`, `"model_degradation"`, `"unknown"` |
| `affected_users_estimate` | int | Estimated affected users |
| `blast_radius` | string | `"isolated"`, `"segment"`, `"widespread"`, `"global"` |
| `severity` | string | `"low"`, `"medium"`, `"high"`, `"critical"` |
| `recommendation` | string | Recommended action |

#### `AIDriftRemediation`

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | `"retrain"`, `"rollback"`, `"recalibrate"`, `"feature_gate"`, `"traffic_shift"`, `"quarantine"` |
| `automated` | boolean | Whether automatically triggered |
| `initiated_by` | string | Initiator identity |
| `status` | string | `"pending"`, `"in_progress"`, `"completed"`, `"failed"` |
| `rollback_to` | string | Rollback target version |
| `validation_passed` | boolean | Post-remediation validation |

#### `AIMemorySecurityInfo`

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | string | `"poisoning_detected"`, `"integrity_violation"`, `"cross_session_access"`, `"growth_anomaly"`, `"untrusted_provenance"` |
| `memory_key` | string | Affected memory key |
| `memory_store` | string | Memory store type |
| `session_id` | string | Session identifier |
| `content_hash` | string | Content hash |
| `integrity_hash` | string | Expected integrity hash |
| `poisoning_score` | double | Poisoning anomaly score (0–1) |
| `provenance` | string | Content provenance source |
| `mutation_count` | int | Total mutations in session |

---

## Common OCSF Fields

All AI event classes inherit standard OCSF base fields:

| Field | Type | Description |
|-------|------|-------------|
| `activity_id` | int | Activity type identifier |
| `category_uid` | int | Category UID (7 for AI) |
| `class_uid` | int | Event class UID |
| `type_uid` | int | `class_uid * 100 + activity_id` |
| `time` | timestamp | Event timestamp |
| `severity_id` | int | 0-6 (Unknown to Fatal) |
| `status_id` | int | 0-99 (Unknown, Success, Failure, Other) |
| `message` | string | Human-readable description |
| `metadata` | `OCSFMetadata` | Event metadata |
| `actor` | `OCSFActor` | Actor information |
| `device` | `OCSFDevice` | Device/host information |
| `observables` | `OCSFObservable[]` | Observable values |
| `enrichments` | `OCSFEnrichment[]` | Enrichment data |
| `compliance` | `ComplianceMetadata` | Compliance mappings |
