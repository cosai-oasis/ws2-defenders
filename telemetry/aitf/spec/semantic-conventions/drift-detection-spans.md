# Model Drift Detection Span Conventions

AITF defines structured semantic conventions for model drift detection — covering data distribution drift, concept drift, performance degradation, and calibration drift. These conventions align with CoSAI's identification of model drift as a top-level AI incident category requiring dedicated telemetry.

## Overview

The `drift.*` namespace provides structured drift telemetry distinct from the basic monitoring checks in `model_ops.monitoring`. While `model_ops.monitoring` captures routine health checks, `drift.*` provides deep, forensic-quality drift analysis with segment-level granularity, reference dataset comparisons, and statistical test results.

| Stage | Span Name | Description |
|-------|-----------|-------------|
| Detection | `drift.detect` | Run drift detection analysis |
| Baseline | `drift.baseline` | Establish or update drift baseline |
| Investigation | `drift.investigate` | Deep-dive investigation of detected drift |
| Remediation | `drift.remediate` | Remediation action (retrain, rollback, etc.) |

---

## Span: `drift.detect`

Represents a drift detection analysis — comparing current model behavior against an established baseline.

### Span Name

Format: `drift.detect {drift.type} {drift.model_id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.model_id` | string | Model being monitored |
| `drift.type` | string | Drift type (see below) |
| `drift.score` | double | Drift magnitude (0.0–1.0) |
| `drift.result` | string | `"normal"`, `"warning"`, `"alert"`, `"critical"` |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.detection_method` | string | Statistical method used (see below) |
| `drift.baseline_metric` | double | Baseline metric value |
| `drift.current_metric` | double | Current metric value |
| `drift.metric_name` | string | Name of metric being tracked |
| `drift.threshold` | double | Alert threshold |
| `drift.p_value` | double | Statistical significance (p-value) |
| `drift.reference_dataset` | string | Reference dataset identifier |
| `drift.reference_period` | string | Reference time period (`"2026-01-01/2026-01-31"`) |
| `drift.evaluation_window` | string | Current evaluation window |
| `drift.sample_size` | int | Number of samples in evaluation |
| `drift.affected_segments` | string[] | Impacted user/data segments |
| `drift.feature_name` | string | Specific feature exhibiting drift (for feature drift) |
| `drift.feature_importance` | double | Importance of drifted feature (0–1) |
| `drift.action_triggered` | string | Automated action (`"none"`, `"alert"`, `"retrain"`, `"rollback"`, `"quarantine"`) |

### Drift Types

| Value | Description |
|-------|-------------|
| `data_distribution` | Input data distribution shift (covariate shift) |
| `concept` | Concept drift — relationship between inputs and outputs changes |
| `performance` | Model performance degradation (accuracy, latency, etc.) |
| `calibration` | Prediction confidence calibration drift |
| `embedding` | Embedding space drift |
| `feature` | Individual feature distribution shift |
| `prediction` | Prediction distribution shift (prior probability shift) |
| `label` | Label distribution shift in supervised feedback |

### Detection Methods

| Value | Description |
|-------|-------------|
| `psi` | Population Stability Index |
| `ks_test` | Kolmogorov-Smirnov test |
| `chi_squared` | Chi-squared test |
| `js_divergence` | Jensen-Shannon divergence |
| `kl_divergence` | Kullback-Leibler divergence |
| `wasserstein` | Wasserstein distance (Earth Mover's Distance) |
| `mmd` | Maximum Mean Discrepancy |
| `adwin` | ADWIN adaptive windowing |
| `ddm` | Drift Detection Method |
| `page_hinkley` | Page-Hinkley test |
| `custom` | Custom detection method |

---

## Span: `drift.baseline`

Represents baseline establishment or refresh — capturing the reference distribution or performance profile against which drift is measured.

### Span Name

Format: `drift.baseline {drift.baseline.operation} {drift.model_id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.model_id` | string | Model for baseline |
| `drift.baseline.operation` | string | `"create"`, `"refresh"`, `"validate"` |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.baseline.id` | string | Baseline identifier |
| `drift.baseline.dataset` | string | Dataset used for baseline |
| `drift.baseline.sample_size` | int | Number of samples |
| `drift.baseline.period` | string | Time period covered |
| `drift.baseline.metrics` | string | JSON of baseline metric values |
| `drift.baseline.features` | string[] | Features tracked |
| `drift.baseline.previous_id` | string | Previous baseline ID (for refresh) |

---

## Span: `drift.investigate`

Represents a deep-dive investigation triggered by drift detection — analyzing root causes, affected segments, and impact scope.

### Span Name

Format: `drift.investigate {drift.type} {drift.model_id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.model_id` | string | Model under investigation |
| `drift.investigation.trigger_id` | string | Detection span ID that triggered investigation |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.investigation.root_cause` | string | Identified root cause |
| `drift.investigation.root_cause_category` | string | `"data_quality"`, `"upstream_change"`, `"seasonal"`, `"adversarial"`, `"model_degradation"`, `"unknown"` |
| `drift.investigation.affected_segments` | string[] | Impacted segments with details |
| `drift.investigation.affected_users_estimate` | int | Estimated affected users |
| `drift.investigation.blast_radius` | string | `"isolated"`, `"segment"`, `"widespread"`, `"global"` |
| `drift.investigation.severity` | string | `"low"`, `"medium"`, `"high"`, `"critical"` |
| `drift.investigation.recommendation` | string | Recommended remediation |

---

## Span: `drift.remediate`

Represents a remediation action taken in response to detected drift.

### Span Name

Format: `drift.remediate {drift.remediation.action} {drift.model_id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.model_id` | string | Model being remediated |
| `drift.remediation.action` | string | Action type (see below) |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `drift.remediation.trigger_id` | string | Detection/investigation span that triggered this |
| `drift.remediation.automated` | boolean | Whether automatically triggered |
| `drift.remediation.initiated_by` | string | Identity that initiated remediation |
| `drift.remediation.status` | string | `"pending"`, `"in_progress"`, `"completed"`, `"failed"` |
| `drift.remediation.rollback_to` | string | Model version rolled back to |
| `drift.remediation.retrain_dataset` | string | New training dataset |
| `drift.remediation.validation_passed` | boolean | Whether post-remediation validation passed |

### Remediation Actions

| Value | Description |
|-------|-------------|
| `retrain` | Retrain model on updated data |
| `rollback` | Roll back to previous model version |
| `recalibrate` | Recalibrate model predictions |
| `feature_gate` | Gate drifted features |
| `traffic_shift` | Shift traffic to stable model |
| `alert_only` | Alert without automated action |
| `quarantine` | Quarantine model from serving |

---

## Examples

### Example 1: Data distribution drift detected

```
Span: drift.detect data_distribution customer-support-llama-70b
  drift.model_id: "customer-support-llama-70b"
  drift.type: "data_distribution"
  drift.score: 0.73
  drift.result: "alert"
  drift.detection_method: "psi"
  drift.baseline_metric: 0.12
  drift.current_metric: 0.73
  drift.metric_name: "psi_score"
  drift.threshold: 0.25
  drift.reference_dataset: "prod-baseline-jan-2026"
  drift.reference_period: "2026-01-01/2026-01-31"
  drift.evaluation_window: "2026-02-10/2026-02-16"
  drift.sample_size: 50000
  drift.affected_segments: ["enterprise_customers", "apac_region"]
  drift.action_triggered: "alert"
```

### Example 2: Concept drift with auto-retrain

```
Span: drift.detect concept fraud-detection-v2
  drift.model_id: "fraud-detection-v2"
  drift.type: "concept"
  drift.score: 0.85
  drift.result: "critical"
  drift.detection_method: "adwin"
  drift.baseline_metric: 0.94
  drift.current_metric: 0.78
  drift.metric_name: "precision"
  drift.p_value: 0.001
  drift.affected_segments: ["crypto_transactions", "new_account_holders"]
  drift.action_triggered: "retrain"

  └─ Span: drift.remediate retrain fraud-detection-v2
       drift.model_id: "fraud-detection-v2"
       drift.remediation.action: "retrain"
       drift.remediation.automated: true
       drift.remediation.retrain_dataset: "fraud-data-feb-2026"
       drift.remediation.status: "completed"
       drift.remediation.validation_passed: true
```

### Example 3: Feature-level drift investigation

```
Span: drift.investigate feature customer-churn-model
  drift.model_id: "customer-churn-model"
  drift.investigation.trigger_id: "span-drift-det-001"
  drift.investigation.root_cause: "Upstream CRM data pipeline changed field encoding"
  drift.investigation.root_cause_category: "upstream_change"
  drift.investigation.affected_segments: ["premium_tier", "monthly_subscribers"]
  drift.investigation.affected_users_estimate: 12500
  drift.investigation.blast_radius: "segment"
  drift.investigation.severity: "high"
  drift.investigation.recommendation: "Rollback model and coordinate with data engineering on field encoding fix"
```
