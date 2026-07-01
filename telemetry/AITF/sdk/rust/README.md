# AITF Rust SDK (`aitf`)

An idiomatic Rust port of the core of the AITF Go/Python SDKs. It implements the
OCSF **class-reuse** model (OCSF PR #1641 / issue #1640): AI telemetry is emitted
under existing OCSF classes enriched with the `ai_operation` profile, and only
the new agent / delegation control-plane lifecycle uses the proposed "ai"
category (uid 9).

What's included:

- **`semconv`** — attribute-key string constants (GenAI, Agent, MCP, RAG,
  Security, Identity, Cost, ModelOps, AssetInventory, Quality, A2A, ACP, ANP,
  canonical AgentComm, Claude Compliance), grouped by namespace module.
- **`ocsf::schema`** — OCSF severity/status/activity/category/class UIDs, the
  `ai_agent` / `delegation` / `delegation_lineage` / `agent_message` objects, the
  AI extension models, and `AIBaseEvent`.
- **`ocsf::crosswalk`** — `build_ai_agent`, `build_delegation`,
  `build_delegation_lineage`, `build_agent_message`, `canonical_comm_status`, the
  event-name → OCSF class table, and the control-plane activity crosswalks.
- **`ocsf::mapper`** — `OcsfMapper::map_span` mapping `SpanData` to OCSF events
  with the same dispatch order as the Go/Python SDKs, enriching every event with
  the `ai_operation` profile.
- **`ocsf::claude_compliance`** — the Anthropic Claude Compliance Activity Feed
  mapper (`classify`, `ClaudeComplianceMapper::map_activity`).
- **`ocsf::compliance`** — the compliance-framework mapper (`ComplianceMapper`)
  covering NIST AI RMF, MITRE ATLAS, ISO/IEC 42001, EU AI Act, SOC 2, GDPR, CCPA,
  and CSA AICM; `map_event`, `enrich_event`, `get_coverage_matrix`, and optional
  framework filtering. Control IDs match the Go/Python SDKs exactly.
- **`exporters`** — `OcsfExporter` (OCSF JSON Lines, file append, and — with the
  `client` feature — HTTP POST), `CefSyslogExporter` (CEF syslog message
  strings for non-OCSF SIEMs), and `ImmutableLogExporter` (append-only, SHA-256
  hash-chained, tamper-evident audit log with `verify_immutable_log`). The Rust
  exporters consume already-mapped `AIBaseEvent` values (the crate has no OTel
  dependency).
- **`semconv::metrics`** — AITF metric-name constants (ported from Go
  `semconv/metrics.go`).
- **`instrumentation`** *(feature `otel`)* — OpenTelemetry-backed
  auto-instrumentation helpers mirroring the Go `instrumentation` package:
  `LlmInstrumentor`, `AgentInstrumentor`, `McpInstrumentor`, `RagInstrumentor`,
  and `IdentityInstrumentor`. Each wraps an OTel tracer and yields a span
  wrapper with typed setters that emit AITF-semconv attributes plus
  `end(result)`. Requires the `opentelemetry` crate.
- **`ocsf::claude_compliance_client`** *(feature `client`)* — the Activity Feed
  HTTP poller (`for_each_activity`, `collect_activities_as_events`) with cursor
  pagination, array-bracket repeatable filters, and limit validation.

## Feature flags

- `default` — dependency-light: `serde`, `serde_json`, `sha2` only.
- `client` — enables HTTP (`ureq`): the OCSF exporter's `post_to_endpoint` and
  the Claude Compliance Activity Feed poller.
- `otel` — enables the OpenTelemetry-backed auto-instrumentation helpers
  (`aitf::instrumentation`); adds the `opentelemetry` crate. No OTel is pulled
  unless this feature is on.

## Install

This is a standalone crate (no workspace). Add it as a path dependency:

```toml
[dependencies]
aitf = { path = "../AITF/sdk/rust" }
```

Runtime dependencies are limited to `serde`, `serde_json`, and `sha2` by
default. The optional `client` feature adds `ureq` for HTTP. To enable it:

```toml
[dependencies]
aitf = { path = "../AITF/sdk/rust", features = ["client"] }
```

## Usage

```rust
use aitf::ocsf::{OcsfMapper, SpanData};
use aitf::semconv;

fn main() {
    // Build a span (e.g. from an OTel ReadableSpan).
    let span = SpanData::new("chat gpt-4o")
        .with_attr(semconv::gen_ai::SYSTEM, "openai")
        .with_attr(semconv::gen_ai::REQUEST_MODEL, "gpt-4o")
        .with_attr(semconv::gen_ai::OPERATION_NAME, "chat")
        .with_attr(semconv::gen_ai::USAGE_INPUT_TOKENS, 100_i64)
        .with_attr(semconv::gen_ai::USAGE_OUTPUT_TOKENS, 50_i64)
        // agent identity attaches the ai_operation profile
        .with_attr(semconv::agent::ID, "agent-001")
        .with_attr(semconv::agent::NAME, "orchestrator")
        .with_attr(semconv::agent::FRAMEWORK, "crewai");

    let event = OcsfMapper::new().map_span(&span).expect("AI span");
    assert_eq!(event.class_uid, 6003); // OCSF API Activity (reuse model)
    assert_eq!(event.ai_agent.as_ref().unwrap().type_id, Some(4)); // CrewAI

    // Serialize to OCSF JSON for a SIEM/XDR.
    let json = event.to_json().unwrap();
    println!("{json}");
}
```

Mapping Claude Compliance Activity Feed records:

```rust
use aitf::ocsf::ClaudeComplianceMapper;
use serde_json::json;

let mapper = ClaudeComplianceMapper::new();
let event = mapper.map_activity(&json!({
    "type": "claude_chat_created",
    "actor": {"type": "user_actor", "user_id": "user_1"},
}));
assert_eq!(event.class_uid, 6001); // Web Resources Activity
```

## Scope / not yet ported

The schema, mappers, exporters (OCSF / CEF / immutable log), compliance-framework
mapper, metric-name constants, the Claude Compliance Activity Feed poller
(feature `client`), the **dual-pipeline helper** (`pipeline::DualPipeline` —
map → compliance-enrich → fan out to the configured sinks), and the
OpenTelemetry-backed **auto-instrumentation helpers** (feature `otel`) are all
supported. The following remain present in the Go/Python SDKs but **not** ported
here yet:

- The vendor mapper (Python-only across the SDKs; not a parity gap).

### Auto-instrumentation (feature `otel`)

Rust can't monkey-patch, so these are manual-but-ergonomic helpers (exactly like
Go's): a per-domain instrumentor wraps an OTel tracer and produces a span
wrapper with typed setters that emit AITF-semconv attributes, plus `end(result)`.

```rust
use aitf::instrumentation::{LlmInstrumentor, InferenceConfig};

let llm = LlmInstrumentor::new(); // uses the global tracer; or with_tracer(t)
let mut span = llm.trace_inference(InferenceConfig::new("gpt-4o"));
span.set_usage(100, 50);
span.end(Ok::<_, std::io::Error>(()));
```

Enable it with the `opentelemetry` crate:

```toml
[dependencies]
aitf = { path = "../AITF/sdk/rust", features = ["otel"] }
```

> The dual pipeline covers AITF's OCSF/SIEM side; because this crate has no
> OpenTelemetry dependency, the **OTLP** side stays your own OTel setup — the
> same span attributes feed both.

Timestamps and metadata UIDs use a dependency-free placeholder scheme in v0
(no `chrono`/`uuid`); mappers overwrite `time` from the span start time.
```
