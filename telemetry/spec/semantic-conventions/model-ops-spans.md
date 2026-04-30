# Model Operations (LLMOps/MLOps) Span Conventions

AITF defines semantic conventions for the complete AI model lifecycle — from training through deployment, serving, monitoring, and maintenance. These conventions bridge the gap between traditional MLOps observability and LLM-specific operational concerns.

## Overview

The `model_ops.*` namespace covers seven lifecycle stages:

| Stage | Span Name | Description |
|-------|-----------|-------------|
| Training | `model_ops.training` | Model training and fine-tuning runs |
| Evaluation | `model_ops.evaluation` | Model evaluation and benchmarking |
| Registry | `model_ops.registry` | Model registration, versioning, promotion |
| Deployment | `model_ops.deployment` | Model deployment and rollout |
| Serving | `model_ops.serving` | Inference routing, fallback, caching |
| Monitoring | `model_ops.monitoring` | Drift detection, performance tracking |
| Prompt Lifecycle | `model_ops.prompt` | Prompt versioning, testing, rollout |

---

## Span: `model_ops.training`

Represents a model training or fine-tuning run.

### Span Name

Format: `model_ops.training {model_ops.training.run_id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.training.run_id` | string | Unique training run identifier |
| `model_ops.training.type` | string | Training type (see below) |
| `model_ops.training.base_model` | string | Base/foundation model ID |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.training.framework` | string | Training framework (`"pytorch"`, `"tensorflow"`, `"jax"`, `"transformers"`) |
| `model_ops.training.dataset.id` | string | Training dataset identifier |
| `model_ops.training.dataset.version` | string | Dataset version hash |
| `model_ops.training.dataset.size` | int | Number of training examples |
| `model_ops.training.hyperparameters` | string | JSON-encoded hyperparameters |
| `model_ops.training.epochs` | int | Number of training epochs |
| `model_ops.training.batch_size` | int | Training batch size |
| `model_ops.training.learning_rate` | double | Learning rate |
| `model_ops.training.loss_final` | double | Final training loss |
| `model_ops.training.val_loss_final` | double | Final validation loss |
| `model_ops.training.compute.gpu_type` | string | GPU type (`"A100"`, `"H100"`, `"TPUv5"`) |
| `model_ops.training.compute.gpu_count` | int | Number of GPUs |
| `model_ops.training.compute.gpu_hours` | double | Total GPU hours consumed |
| `model_ops.training.output_model.id` | string | Output model artifact ID |
| `model_ops.training.output_model.hash` | string | Output model hash |
| `model_ops.training.code_commit` | string | Code commit SHA |
| `model_ops.training.experiment.id` | string | Experiment tracker ID |
| `model_ops.training.experiment.name` | string | Experiment name |
| `model_ops.training.status` | string | `"running"`, `"completed"`, `"failed"`, `"cancelled"` |

### Training Types

| Value | Description |
|-------|-------------|
| `pre_training` | Training from scratch |
| `fine_tuning` | Fine-tuning a pre-trained model |
| `rlhf` | Reinforcement Learning from Human Feedback |
| `dpo` | Direct Preference Optimization |
| `lora` | Low-Rank Adaptation fine-tuning |
| `qlora` | Quantized LoRA fine-tuning |
| `distillation` | Knowledge distillation |
| `continued_pre_training` | Continued pre-training on domain data |

---

## Span: `model_ops.evaluation`

Represents a model evaluation or benchmarking run.

### Span Name

Format: `model_ops.evaluation {model_ops.evaluation.run_id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.evaluation.run_id` | string | Evaluation run identifier |
| `model_ops.evaluation.model_id` | string | Model being evaluated |
| `model_ops.evaluation.type` | string | Evaluation type (see below) |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.evaluation.dataset.id` | string | Evaluation dataset ID |
| `model_ops.evaluation.dataset.version` | string | Dataset version |
| `model_ops.evaluation.dataset.size` | int | Number of evaluation examples |
| `model_ops.evaluation.metrics` | string | JSON-encoded metric results |
| `model_ops.evaluation.judge_model` | string | LLM-as-judge model ID (if applicable) |
| `model_ops.evaluation.baseline_model` | string | Baseline model for comparison |
| `model_ops.evaluation.baseline_metrics` | string | JSON baseline metrics for comparison |
| `model_ops.evaluation.regression_detected` | boolean | Whether regression was detected |
| `model_ops.evaluation.pass` | boolean | Whether evaluation passed quality gates |
| `model_ops.evaluation.gate_criteria` | string | JSON quality gate criteria |

### Evaluation Types

| Value | Description |
|-------|-------------|
| `benchmark` | Standard benchmark evaluation (MMLU, HumanEval, etc.) |
| `llm_judge` | LLM-as-judge automated evaluation |
| `human_eval` | Human evaluation/annotation |
| `safety` | Safety and alignment evaluation |
| `regression` | Regression test against baseline |
| `a_b_test` | A/B test comparison |
| `red_team` | Red team adversarial evaluation |
| `rag_eval` | RAG-specific evaluation (faithfulness, relevance) |

---

## Span: `model_ops.registry`

Represents a model registry operation (registration, promotion, deprecation).

### Span Name

Format: `model_ops.registry.{model_ops.registry.operation} {model_ops.registry.model_id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.registry.operation` | string | Registry operation (see below) |
| `model_ops.registry.model_id` | string | Model identifier |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.registry.model_version` | string | Model version |
| `model_ops.registry.model_alias` | string | Model alias (e.g., `"@champion"`, `"@challenger"`) |
| `model_ops.registry.previous_version` | string | Previous model version (for promotion/rollback) |
| `model_ops.registry.stage` | string | `"experimental"`, `"staging"`, `"production"`, `"archived"` |
| `model_ops.registry.previous_stage` | string | Previous stage (for transitions) |
| `model_ops.registry.owner` | string | Model owner (user or team) |
| `model_ops.registry.tags` | string | JSON-encoded metadata tags |
| `model_ops.registry.lineage.training_run_id` | string | Training run that produced this model |
| `model_ops.registry.lineage.parent_model_id` | string | Parent model (for fine-tuned models) |
| `model_ops.registry.approval.required` | boolean | Whether approval was needed |
| `model_ops.registry.approval.approver` | string | Who approved (if applicable) |

### Registry Operations

| Value | Description |
|-------|-------------|
| `register` | Register new model version |
| `promote` | Promote model to next stage |
| `demote` | Demote model to previous stage |
| `archive` | Archive a model version |
| `rollback` | Rollback to a previous version |
| `alias_set` | Set or change a model alias |
| `alias_remove` | Remove a model alias |
| `delete` | Delete a model version |

---

## Span: `model_ops.deployment`

Represents a model deployment or rollout operation.

### Span Name

Format: `model_ops.deployment {model_ops.deployment.id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.deployment.id` | string | Deployment identifier |
| `model_ops.deployment.model_id` | string | Model being deployed |
| `model_ops.deployment.strategy` | string | Deployment strategy (see below) |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.deployment.model_version` | string | Model version |
| `model_ops.deployment.environment` | string | `"development"`, `"staging"`, `"production"` |
| `model_ops.deployment.endpoint` | string | Serving endpoint URL or ID |
| `model_ops.deployment.infrastructure.provider` | string | `"aws"`, `"gcp"`, `"azure"`, `"on_prem"` |
| `model_ops.deployment.infrastructure.instance_type` | string | Instance type (e.g., `"p4d.24xlarge"`) |
| `model_ops.deployment.infrastructure.gpu_type` | string | GPU type |
| `model_ops.deployment.infrastructure.replicas` | int | Number of replicas |
| `model_ops.deployment.canary_percent` | double | Canary traffic percentage (0-100) |
| `model_ops.deployment.previous_model_id` | string | Previous model being replaced |
| `model_ops.deployment.rollback_model_id` | string | Rollback target (if rollback) |
| `model_ops.deployment.health_check.status` | string | `"healthy"`, `"degraded"`, `"unhealthy"` |
| `model_ops.deployment.health_check.latency_ms` | double | Health check latency |
| `model_ops.deployment.status` | string | `"pending"`, `"in_progress"`, `"completed"`, `"failed"`, `"rolled_back"` |
| `model_ops.deployment.guardrails_configured` | boolean | Whether guardrails were set up |
| `model_ops.deployment.auto_scaling.min_replicas` | int | Minimum replicas |
| `model_ops.deployment.auto_scaling.max_replicas` | int | Maximum replicas |

### Deployment Strategies

| Value | Description |
|-------|-------------|
| `rolling` | Rolling update (gradual replacement) |
| `canary` | Canary deployment (percentage-based rollout) |
| `blue_green` | Blue-green deployment (full swap) |
| `shadow` | Shadow deployment (duplicate traffic, no serving) |
| `a_b_test` | A/B test deployment (split traffic for comparison) |
| `immediate` | Immediate replacement |

---

## Span: `model_ops.serving`

Represents model serving infrastructure operations — routing, fallback chains, and caching.

### Span Name

Format: `model_ops.serving.{model_ops.serving.operation}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.serving.operation` | string | Serving operation (see below) |

### Recommended Attributes (Routing)

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.serving.route.selected_model` | string | Model selected by router |
| `model_ops.serving.route.reason` | string | Routing reason (`"cost"`, `"latency"`, `"capability"`, `"load"`) |
| `model_ops.serving.route.candidates` | string[] | Candidate models considered |
| `model_ops.serving.route.rule` | string | Routing rule matched |

### Recommended Attributes (Fallback)

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.serving.fallback.chain` | string[] | Ordered fallback chain |
| `model_ops.serving.fallback.depth` | int | How many fallbacks were needed |
| `model_ops.serving.fallback.trigger` | string | `"error"`, `"timeout"`, `"rate_limit"`, `"circuit_breaker"` |
| `model_ops.serving.fallback.original_model` | string | Originally requested model |
| `model_ops.serving.fallback.final_model` | string | Model that actually served the request |

### Recommended Attributes (Caching)

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.serving.cache.hit` | boolean | Whether cache was hit |
| `model_ops.serving.cache.type` | string | `"exact"`, `"semantic"`, `"hybrid"` |
| `model_ops.serving.cache.similarity_score` | double | Semantic similarity (for semantic cache) |
| `model_ops.serving.cache.ttl_seconds` | int | Cache entry TTL |
| `model_ops.serving.cache.cost_saved_usd` | double | Cost saved by cache hit |

### Recommended Attributes (Circuit Breaker)

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.serving.circuit_breaker.state` | string | `"closed"`, `"open"`, `"half_open"` |
| `model_ops.serving.circuit_breaker.model` | string | Model the breaker applies to |
| `model_ops.serving.circuit_breaker.failure_count` | int | Consecutive failures |
| `model_ops.serving.circuit_breaker.recovery_time_ms` | double | Time until next probe |

### Serving Operations

| Value | Description |
|-------|-------------|
| `route` | Model selection/routing decision |
| `fallback` | Fallback to alternative model |
| `cache_lookup` | Cache lookup (hit or miss) |
| `cache_store` | Store response in cache |
| `circuit_breaker` | Circuit breaker state change |
| `load_balance` | Load balancing across replicas |
| `rate_limit` | Rate limiting enforcement |

---

## Span: `model_ops.monitoring`

Represents model monitoring operations — drift detection, performance tracking, alerting.

### Span Name

Format: `model_ops.monitoring.{model_ops.monitoring.check_type}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.monitoring.check_type` | string | Monitoring check type (see below) |
| `model_ops.monitoring.model_id` | string | Monitored model |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.monitoring.result` | string | `"normal"`, `"warning"`, `"alert"`, `"critical"` |
| `model_ops.monitoring.metric_name` | string | Metric being checked |
| `model_ops.monitoring.metric_value` | double | Current metric value |
| `model_ops.monitoring.baseline_value` | double | Baseline/expected value |
| `model_ops.monitoring.threshold` | double | Alert threshold |
| `model_ops.monitoring.drift_score` | double | Drift magnitude (0-1) |
| `model_ops.monitoring.drift_type` | string | `"data"`, `"prediction"`, `"concept"`, `"embedding"`, `"feature"` |
| `model_ops.monitoring.window` | string | Monitoring window (`"1h"`, `"24h"`, `"7d"`) |
| `model_ops.monitoring.samples_evaluated` | int | Number of samples evaluated |
| `model_ops.monitoring.action_triggered` | string | `"none"`, `"alert"`, `"retrain"`, `"rollback"`, `"scale"` |

### Monitoring Check Types

| Value | Description |
|-------|-------------|
| `data_drift` | Input data distribution drift |
| `prediction_drift` | Output distribution drift |
| `concept_drift` | Concept/relationship drift |
| `embedding_drift` | Embedding space drift |
| `feature_drift` | Feature distribution drift |
| `performance_degradation` | Accuracy/quality degradation |
| `latency_regression` | Latency regression detection |
| `error_rate` | Error rate spike detection |
| `cost_anomaly` | Cost anomaly detection |
| `throughput` | Throughput deviation |
| `sla_compliance` | SLA compliance check |

---

## Span: `model_ops.prompt`

Represents prompt lifecycle operations — versioning, testing, and rollout.

### Span Name

Format: `model_ops.prompt.{model_ops.prompt.operation} {model_ops.prompt.name}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.prompt.name` | string | Prompt template name |
| `model_ops.prompt.operation` | string | Prompt operation (see below) |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `model_ops.prompt.version` | string | Prompt version (SemVer) |
| `model_ops.prompt.previous_version` | string | Previous version (for rollback/promotion) |
| `model_ops.prompt.content_hash` | string | Hash of prompt template content |
| `model_ops.prompt.label` | string | Deployment label (`"staging"`, `"production"`, `"latest"`) |
| `model_ops.prompt.model_target` | string | Target model for this prompt |
| `model_ops.prompt.variables` | string[] | Template variable names |
| `model_ops.prompt.evaluation.score` | double | Evaluation score (0-1) |
| `model_ops.prompt.evaluation.baseline_score` | double | Baseline score for comparison |
| `model_ops.prompt.evaluation.pass` | boolean | Whether prompt passed quality gate |
| `model_ops.prompt.a_b_test.id` | string | A/B experiment ID |
| `model_ops.prompt.a_b_test.variant` | string | Variant name (`"control"`, `"treatment_a"`, etc.) |
| `model_ops.prompt.a_b_test.traffic_pct` | double | Traffic percentage for this variant |

### Prompt Operations

| Value | Description |
|-------|-------------|
| `create` | Create new prompt version |
| `update` | Update prompt content |
| `promote` | Promote prompt to label (e.g., staging -> production) |
| `rollback` | Rollback to previous version |
| `evaluate` | Evaluate prompt against benchmarks |
| `a_b_test_start` | Start A/B test between prompt versions |
| `a_b_test_end` | End A/B test with results |
| `deprecate` | Deprecate a prompt version |

---

## Example: Fine-Tuning Pipeline

```
Span: model_ops.training run-ft-20260215
  model_ops.training.type: "lora"
  model_ops.training.base_model: "meta-llama/Llama-3.1-70B"
  model_ops.training.dataset.id: "customer-support-v3"
  model_ops.training.epochs: 3
  model_ops.training.loss_final: 0.42
  │
  └─ Span: model_ops.evaluation eval-20260215
       model_ops.evaluation.type: "benchmark"
       model_ops.evaluation.model_id: "cs-llama-70b-lora-v3"
       model_ops.evaluation.pass: true
       │
       └─ Span: model_ops.registry.register cs-llama-70b-lora-v3
            model_ops.registry.stage: "staging"
            model_ops.registry.lineage.training_run_id: "run-ft-20260215"
            │
            └─ Span: model_ops.deployment deploy-cs-canary
                 model_ops.deployment.strategy: "canary"
                 model_ops.deployment.canary_percent: 10.0
                 model_ops.deployment.environment: "production"
                 │
                 └─ Span: model_ops.monitoring.performance_degradation
                      model_ops.monitoring.result: "normal"
                      model_ops.monitoring.metric_name: "accuracy"
                      model_ops.monitoring.metric_value: 0.94
```

## Example: Serving with Routing and Fallback

```
Span: model_ops.serving.route
  model_ops.serving.route.selected_model: "claude-opus-4-6"
  model_ops.serving.route.reason: "capability"
  model_ops.serving.route.candidates: ["claude-opus-4-6", "gpt-4o", "llama-70b"]
  │
  ├─ Span: model_ops.serving.cache_lookup
  │    model_ops.serving.cache.hit: false
  │    model_ops.serving.cache.type: "semantic"
  │
  ├─ Span: chat claude-opus-4-6
  │    (gen_ai.inference span — fails with timeout)
  │
  └─ Span: model_ops.serving.fallback
       model_ops.serving.fallback.trigger: "timeout"
       model_ops.serving.fallback.original_model: "claude-opus-4-6"
       model_ops.serving.fallback.final_model: "gpt-4o"
       model_ops.serving.fallback.depth: 1
       │
       └─ Span: chat gpt-4o
            (gen_ai.inference span — succeeds)
```
