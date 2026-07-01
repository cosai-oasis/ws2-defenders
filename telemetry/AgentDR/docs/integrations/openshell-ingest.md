# Integrating NVIDIA OpenShell with AgentDR

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) is a secure-by-design
runtime for autonomous AI agents (part of the NVIDIA Agent Toolkit). It runs
agents such as OpenClaw, Claude Code, and Codex **unmodified** inside per-agent
sandboxes, enforces a declarative YAML policy across the filesystem / network /
process layers, and routes every action through a **Gateway** that emits an
audit trail of each allow / deny decision.

That audit stream is exactly the kind of signal AgentDR normalizes. OpenShell
*enforces*; AgentDR *detects, normalizes, and forwards to the SIEM*. The two are
complementary — AgentDR should **consume** OpenShell telemetry rather than
duplicate its enforcement.

## Two levels of support

### 1. Detection (already supported — rule pack only)

OpenShell and the agents it hosts are detected by the standard signature pack:

- `nvidia-openshell` signature in `cosai-community/rules/agent-signatures.json`
  (category `workflow`) identifies the runtime / Gateway process.
- Agents running *inside* a sandbox still match their own signatures
  (`claude-code`, `codex-cli`, `openclaw`, …), so per-agent attribution is
  preserved.

No code change is required for this level.

### 2. Telemetry ingest (implemented — `src/ingest/openshell.rs`)

AgentDR tails OpenShell's OCSF JSON export and maps each Gateway decision onto
the AITF OCSF Class-Reuse Model so it flows through the same `EventRecord`
pipeline, detectors, policies, and exporters as everything else AgentDR
observes. Enable it in config:

```toml
[openshell]
enabled = true
# Newest matching file is tailed; OpenShell rotates daily.
log_glob = "/var/log/openshell-ocsf*.log"
poll_interval_seconds = 5
```

(Set `ocsf_json_enabled` on the OpenShell side so the JSON export is written.)

The ingest reads only newly-appended complete lines, follows daily rotation,
attributes each decision to the sandboxed agent (via the signature pack), and
preserves OpenShell's `metadata.correlation_uid` as the AITF `trace_id`. The
mapping it applies:

| OpenShell Gateway decision | AgentDR `ai_operation` | Reused OCSF `class_uid` | `status_id` |
|---|---|---|---|
| `allow` — filesystem / process action | `tool_execution` | API Activity `6003` | Success (1) |
| `allow` — network egress to an AI endpoint | `inference` | API Activity `6003` | Success (1) |
| `deny` / `block` — policy refusal | `compliance_violation` | Compliance Finding `2003` | Blocked (3) |
| `deny` — unreviewed binary / unverified skill | `supply_chain` | Vulnerability Finding `2002` | Blocked (3) |
| skill install / verification event | `asset_inventory` | Inventory Info `5001` | Success (1) |

Carry OpenShell's own fields into the AITF namespaces: sandbox / agent id →
`identity.*` and `actor`; policy rule id → `compliance.*`; resource path or host
→ `details`. Preserve the Gateway's correlation id as the AITF `trace_id` so a
multi-step agent task can be reconstructed end-to-end.

#### Implementation

`src/ingest/openshell.rs` polls the newest `*.log` matching the configured glob,
reads only newly-appended complete lines (handling daily rotation and
truncation), parses each as OCSF JSON, and builds an `EventRecord` via
`EventRecord::set_op(AiOperation::…, activity_id)` following the table above. It
is spawned from the engine when `[openshell] enabled = true`.

If OpenShell is additionally configured to export OpenTelemetry, AgentDR's
existing loopback OTLP server (`src/ingest/otlp.rs`) is an alternative path.

### Policy alignment

OpenShell's declarative YAML policy and AgentDR's `policies.yaml` express the
same allow / deny intent. They can be kept in sync (or generated from a shared
source) so that AgentDR's detections and OpenShell's enforcement agree on the
trust boundary — without AgentDR's inline proxy and OpenShell's Gateway
double-enforcing the same rule.
