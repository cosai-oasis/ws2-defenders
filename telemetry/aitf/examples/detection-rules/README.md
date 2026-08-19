# AITF Detection Rules & Anomaly Detection

Security detection rules and anomaly detection examples built on top of AITF telemetry. These rules detect threats specific to AI/LLM systems including prompt injection, agent abuse, MCP server compromise, and data exfiltration.

## Overview

| Component | Description |
|---|---|
| `aitf_detection_rules.py` | 14 Python detection rules with real-time and batch evaluation |
| `anomaly_detector.py` | Statistical anomaly detection engine (z-score, IQR, adaptive) |
| `sigma_rules/` | 5 Sigma-format YAML rules for SIEM integration |
| `splunk_queries/` | Splunk SPL queries for dashboards and alerting |

## Detection Rules Reference

### Inference Anomalies

| Rule ID | Name | Severity | OWASP | MITRE ATLAS |
|---|---|---|---|---|
| AITF-DET-001 | Unusual Token Usage | Medium | LLM10 | AML.T0040 |
| AITF-DET-002 | Model Switching Attack | High | LLM01 | AML.T0042 |
| AITF-DET-003 | Prompt Injection Attempt | High | LLM01 | AML.T0051 |
| AITF-DET-004 | Excessive Cost Spike | Medium | LLM10 | AML.T0034 |

**AITF-DET-001: Unusual Token Usage** -- Tracks per-model rolling averages of token counts using exponential moving average (EMA). Triggers when the z-score of a request's total token count exceeds the configured threshold (default: 3.0 standard deviations). Requires a minimum of 20 observations before activating.

**AITF-DET-002: Model Switching Attack** -- Monitors session-level model usage within a sliding time window. Triggers when a single session uses 4 or more distinct models within 60 seconds, which may indicate adversarial probing for weak model endpoints.

**AITF-DET-003: Prompt Injection Attempt** -- Pattern-based detection using the OWASP LLM01 prompt injection patterns from the AITF SecurityProcessor plus additional indirect injection patterns targeting tool outputs and retrieval contexts. Scans prompt text, MCP tool inputs, and tool outputs.

**AITF-DET-004: Excessive Cost Spike** -- Compares per-request cost against a rolling average within a configurable time window (default: 300s). Triggers when cost exceeds 5x the rolling average or surpasses an absolute threshold of $1.00.

### Agent Anomalies

| Rule ID | Name | Severity | OWASP | MITRE ATLAS |
|---|---|---|---|---|
| AITF-DET-005 | Agent Loop Detection | High | LLM06 | AML.T0048 |
| AITF-DET-006 | Unauthorized Agent Delegation | High | LLM06 | AML.T0050 |
| AITF-DET-007 | Agent Session Hijack | Critical | LLM06 | AML.T0024 |
| AITF-DET-008 | Excessive Tool Calls | Medium | LLM06 | AML.T0048 |

**AITF-DET-005: Agent Loop Detection** -- Tracks action sequences per agent session. Detects both consecutive identical tool calls (default threshold: 5) and cyclic patterns (same sequence repeating 3+ times with cycle length up to 3).

**AITF-DET-006: Unauthorized Agent Delegation** -- Validates delegation targets against a pre-configured allow-list or the team member roster from the event. Triggers when an agent delegates to an agent not in the team.

**AITF-DET-007: Agent Session Hijack** -- Monitors session continuity by tracking agent name, framework, and turn count across events. Detects identity changes, turn-count resets, impossible turn jumps, and sessions resuming after abnormal idle periods (default: 1 hour).

**AITF-DET-008: Excessive Tool Calls** -- Counts cumulative tool invocations per session. Produces a warning at 30 calls and a high-severity alert at 50 calls (both configurable).

### MCP/Tool Anomalies

| Rule ID | Name | Severity | OWASP | MITRE ATLAS |
|---|---|---|---|---|
| AITF-DET-009 | MCP Server Impersonation | Critical | LLM03 | AML.T0050 |
| AITF-DET-010 | Tool Permission Bypass | High | LLM06 | AML.T0048.002 |
| AITF-DET-011 | Data Exfiltration via Tools | Critical | LLM02 | AML.T0024 |

**AITF-DET-009: MCP Server Impersonation** -- Validates MCP server connections against an allow-list of approved server names, URLs, and transports. Triggers on unknown servers or configuration mismatches that could indicate server impersonation.

**AITF-DET-010: Tool Permission Bypass** -- Checks that tools requiring human approval have valid approval status. Maintains a configurable list of tools that always require approval (e.g. `write_file`, `execute_command`, `send_email`).

**AITF-DET-011: Data Exfiltration via Tools** -- Detects read-then-send patterns where data is read from internal sources and then sent externally. Also scans tool I/O for exfiltration patterns (URLs, encoding commands) and tracks per-session data volume.

### Security Anomalies

| Rule ID | Name | Severity | OWASP | MITRE ATLAS |
|---|---|---|---|---|
| AITF-DET-012 | PII Exfiltration Chain | High | LLM02 | AML.T0024 |
| AITF-DET-013 | Jailbreak Escalation | Critical | LLM01 | AML.T0051.001 |
| AITF-DET-014 | Supply Chain Compromise | Critical | LLM03 | AML.T0010 |

**AITF-DET-012: PII Exfiltration Chain** -- Tracks accumulation of distinct PII types across a session. Each PII type has a sensitivity weight; the rule triggers when either the distinct type count or cumulative sensitivity score crosses the threshold.

**AITF-DET-013: Jailbreak Escalation** -- Detects escalating jailbreak campaigns by tracking injection/jailbreak attempts per session within a time window (default: 600s). Triggers after 3 attempts, with higher confidence when multiple technique types are observed.

**AITF-DET-014: Supply Chain Compromise** -- Compares model provenance metadata (hash, source, signer) against a known-good baseline. Supports both explicit baselines and auto-baseline from first observation.

## Anomaly Detection Engine

The `anomaly_detector.py` module provides a statistical foundation for detection rules.

### BaselineTracker

Maintains rolling statistics for any named metric:

```python
from anomaly_detector import BaselineTracker

tracker = BaselineTracker(window_size=1000, ema_alpha=0.05)

# Record observations
for tokens in token_counts:
    tracker.update("input_tokens", tokens)

# Query statistics
stats = tracker.get_stats("input_tokens")
# Returns: mean, std, count, min, max, q1, q3, iqr, p50, p90, p95, p99
```

### AnomalyDetector

Four detection methods with configurable sensitivity:

| Method | Description | Best For |
|---|---|---|
| `Z_SCORE` | Standard z-score against EMA | Normally distributed metrics |
| `IQR` | Interquartile range fences | Skewed distributions, outliers |
| `ADAPTIVE` | Z-score with CV-adjusted threshold | Metrics with varying volatility |
| `PERCENTILE` | P1/P99 boundary detection | Heavy-tailed distributions |

```python
from anomaly_detector import AnomalyDetector, AnomalyMethod

detector = AnomalyDetector(
    z_score_threshold=3.0,
    iqr_multiplier=1.5,
    min_samples=20,
    sensitivity=1.0,  # 0.5=lenient, 2.0=strict
)

result = detector.check("latency_ms", 1500.0, method=AnomalyMethod.Z_SCORE)
if result.is_anomaly:
    print(f"Anomaly: {result.details}")
```

### TimeSeriesAnomalyDetector

Processes AITF events and automatically extracts token, latency, and cost metrics:

```python
from anomaly_detector import TimeSeriesAnomalyDetector

ts = TimeSeriesAnomalyDetector()
results = ts.process_event(aitf_event)  # Returns list of AnomalyResult
summary = ts.get_model_summary("gpt-4o")
```

### BehavioralAnomalyDetector

Learns Markov-chain transition models from agent action sequences:

```python
from anomaly_detector import BehavioralAnomalyDetector

bd = BehavioralAnomalyDetector(min_sessions=10)

# Train on normal sessions
for action in session_actions:
    bd.record_action(session_id, action)
bd.end_session(session_id)

# Inspect learned model
probs = bd.get_transition_probabilities()
```

### Visualization Hooks

Every anomaly check produces `VisualizationPoint` objects that can be exported to:

- **Grafana** via `point.to_grafana_annotation()`
- **Prometheus** via `point.to_prometheus_metric()`
- **matplotlib** via the `visualization_points` list on the detector

## Deployment Guide

### 1. Real-Time Detection with AITF SDK

Integrate rules directly into your AITF pipeline:

```python
from opentelemetry.sdk.trace import TracerProvider
from aitf.processors.security_processor import SecurityProcessor
from aitf_detection_rules import DetectionEngine

# Standard AITF setup
provider = TracerProvider()
provider.add_span_processor(SecurityProcessor())

# Initialize detection engine
engine = DetectionEngine()
engine.load_all_rules(
    allowed_servers={
        "filesystem": {"urls": ["stdio://local"], "transports": ["stdio"]},
        "postgres": {"urls": ["http://localhost:3001/mcp"], "transports": ["streamable_http"]},
    },
    allowed_agents={
        "research-team": ["manager", "researcher", "writer"],
    },
    known_models={
        "gpt-4o": {"hash": "sha256:abc123", "source": "openai", "signer": "openai-v1"},
    },
)

# In your span processor or exporter callback:
def on_span_end(span):
    event = dict(span.attributes)
    results = engine.evaluate(event)
    alerts = engine.get_triggered(results, min_severity=Severity.MEDIUM)
    for alert in alerts:
        send_to_siem(alert.to_dict())
```

### 2. Batch Analysis

Process historical telemetry for retrospective threat hunting:

```python
import json

with open("/tmp/aitf_ocsf_events.jsonl") as f:
    events = [json.loads(line) for line in f]

results = engine.evaluate_batch(events)
for r in results:
    print(f"[{r.severity.value}] {r.rule_id}: {r.details}")
```

### 3. SIEM Integration

#### Splunk

1. Index AITF OCSF events using the HEC (HTTP Event Collector):
   ```
   curl -k https://splunk:8088/services/collector/event \
     -H "Authorization: Splunk <token>" \
     -d '{"index":"aitf","sourcetype":"aitf:ocsf","event":<ocsf_event>}'
   ```

2. Import the SPL queries from `splunk_queries/` into Splunk dashboards.

3. Configure scheduled alerts using the alert queries at the bottom of each SPL file.

#### Sigma Rule Deployment

Sigma rules can be converted to any SIEM platform using `sigmac` or `sigma-cli`:

```bash
# Convert to Splunk
sigma convert -t splunk sigma_rules/aitf_prompt_injection.yml

# Convert to Elastic/OpenSearch
sigma convert -t elasticsearch sigma_rules/aitf_prompt_injection.yml

# Convert to Microsoft Sentinel (KQL)
sigma convert -t microsoft365defender sigma_rules/aitf_prompt_injection.yml

# Convert to QRadar (AQL)
sigma convert -t qradar sigma_rules/aitf_prompt_injection.yml
```

#### Elastic Security

For Elastic SIEM, convert Sigma rules to Elasticsearch queries and create detection rules:

```bash
sigma convert -t elasticsearch -p ecs_windows \
  sigma_rules/aitf_prompt_injection.yml > elastic_rule.json
```

## Threshold Tuning Guide

### General Principles

1. **Start permissive, tighten gradually.** Begin with high thresholds to avoid alert fatigue, then lower them as you establish baselines.

2. **Use the warm-up period.** Most rules require a minimum number of observations (default: 20) before activating. During this period, the system learns normal patterns.

3. **Tune per-model.** Different models have vastly different token profiles. The `UnusualTokenUsage` rule maintains per-model baselines automatically.

4. **Adjust sensitivity globally.** The `AnomalyDetector.sensitivity` parameter scales all thresholds. Start at `1.0` and adjust:
   - `0.5` -- Very lenient, only extreme outliers
   - `1.0` -- Default, balanced
   - `1.5` -- Strict, catches more subtle anomalies
   - `2.0` -- Very strict, expect more false positives

### Per-Rule Tuning

| Rule | Key Parameter | Default | Increase to Reduce FPs | Decrease for More Sensitivity |
|---|---|---|---|---|
| DET-001 | `z_score_threshold` | 3.0 | 4.0-5.0 | 2.0-2.5 |
| DET-002 | `model_threshold` | 4 models | 5-6 | 3 |
| DET-002 | `window_seconds` | 60s | 30s | 120s |
| DET-004 | `spike_factor` | 5.0x | 8.0-10.0x | 3.0x |
| DET-004 | `absolute_threshold` | $1.00 | $5.00 | $0.50 |
| DET-005 | `max_consecutive_same_tool` | 5 | 8-10 | 3 |
| DET-007 | `max_idle_seconds` | 3600s | 7200s | 1800s |
| DET-008 | `max_tools_per_session` | 50 | 100 | 25 |
| DET-012 | `max_pii_types_per_session` | 3 | 5 | 2 |
| DET-013 | `max_attempts_per_session` | 3 | 5 | 2 |

### Environment-Specific Recommendations

**Development/Testing:**
```python
engine.load_all_rules()
for rule in engine._rules:
    if isinstance(rule, UnusualTokenUsage):
        rule._z_threshold = 5.0  # Very lenient
    if isinstance(rule, ExcessiveToolCalls):
        rule._max_tools = 200  # Developers use many tools
```

**Production (standard):**
```python
engine.load_all_rules(
    allowed_servers=PROD_MCP_SERVERS,
    allowed_agents=PROD_AGENT_TEAMS,
    known_models=PROD_MODEL_HASHES,
)
# Use defaults
```

**Production (high-security):**
```python
engine.load_all_rules(...)
for rule in engine._rules:
    if isinstance(rule, ExcessiveCostSpike):
        rule._spike_factor = 3.0
        rule._absolute_threshold = 0.50
    if isinstance(rule, ExcessiveToolCalls):
        rule._max_tools = 25
        rule._warning_threshold = 15
```

## File Structure

```
examples/detection-rules/
  aitf_detection_rules.py          # 14 Python detection rules
  anomaly_detector.py              # Statistical anomaly engine
  README.md                        # This file
  sigma_rules/
    aitf_prompt_injection.yml      # Sigma: prompt injection
    aitf_agent_loop.yml            # Sigma: agent loops
    aitf_data_exfiltration.yml     # Sigma: data exfiltration
    aitf_cost_anomaly.yml          # Sigma: cost anomalies
    aitf_mcp_server_anomaly.yml    # Sigma: MCP server anomalies
  splunk_queries/
    ai_threat_dashboard.spl        # Splunk: AI threat dashboard
    agent_behavioral_analysis.spl  # Splunk: agent behavior analysis
```

## Dependencies

- Python 3.10+
- `aitf` SDK (`pip install aitf`)
- `opentelemetry-sdk` (transitive via aitf)

Optional for visualization:
- `matplotlib` for local plotting
- `prometheus_client` for Prometheus push gateway
- Grafana with annotation API access
