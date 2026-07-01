# AgentDR — Agent Detection & Response Prototype

> An open-source prototype for detecting, monitoring, and responding to AI agent activity on endpoints, aligned with the **CoSAI AI Telemetry Framework (AITF)** and the [`girdav01/AITF`](https://github.com/girdav01/AITF) reference spec.

AgentDR is an early-stage research prototype that demonstrates what an *Endpoint Detection & Response* product looks like when the threat model expands to include autonomous AI agents — coding assistants, browser-use agents, multi-agent orchestrators, enterprise copilots, and rogue general-purpose agents (OpenClaw, AutoGPT, etc.). It captures rich AI-aware telemetry from monitored endpoints, classifies activity against community-maintained signature rules, and surfaces alerts through a Next.js analyst dashboard. It can also **actively guard** AI traffic with two opt-in proxies — an outbound forward proxy and the **LLM Guard** reverse proxy that fronts local model backends (Ollama, LM Studio, llama.cpp), inspecting prompts/responses for prompt-injection & PII and tracking token usage.

The project is organized into two cooperating components plus a shared, pluggable rule pack:

```
AgentDR/
├── adr_system/
│   ├── rust_agent/              ← Endpoint monitoring agent (Rust) — reference impl
│   │   ├── src/                 ← Monitors, ingest, exporters, policy, proxy, CLI
│   │   └── Cargo.toml
│   └── cosai-community/         ← Shared CoSAI/AITF rule pack (signatures, endpoints, policies)
├── adr_dashboard/
│   └── nextjs_space/            ← Analyst dashboard (Next.js 14 + Prisma + Postgres)
├── packaging/                   ← Signed installers: macOS .pkg, Windows MSI, Linux deb/rpm
├── mdm/                         ← MDM templates: Jamf, Intune, Kandji, Fleet
└── docs/                        ← Test plans, marketing, blog, conference deck
```

> **Note on the Python agent.** AgentDR began as a Python prototype. The
> endpoint agent has since been rewritten in **Rust** — it is faster,
> uses < 40 MB resident, has no interpreter dependency, and is the only
> agent. The original Python prototype has been removed; its history remains
> available in the git log.

---

## Goals of the prototype

1. **Make AI agent activity observable.** Most EDRs can detect a process and a network connection, but cannot tell you that the process *is* Claude Code, that it just called the OpenAI API 47 times in 60 seconds, or that it dropped a Python skill file into `~/.openclaw/skills/`. AgentDR fills that gap.
2. **Demonstrate an AITF OCSF Class-Reuse telemetry pipeline.** Every event the agent emits reuses a standard OCSF class and carries an `ai_operation` profile (per the CoSAI/AITF schema) so downstream SIEMs can consume it without a translation layer.
3. **Provide a reference rule pack.** The `cosai-community/` directory is a self-contained, JSON-driven, checksum-verified pack of agent signatures, AI endpoint patterns, messaging endpoints, and 20 detection rules — designed to be edited and extended without recompiling the agent.
4. **Show the analyst side.** The Next.js dashboard provides activity, alerts, analytics, logs, and policy management views over the captured events.

---

## Components

### 1. `adr_system/rust_agent/` — Endpoint Monitoring Agent

A cross-platform **Rust** agent (Windows, macOS, Linux) that runs on the monitored host. It is built around an async event bus: every monitor, ingest path and detector produces `EventRecord`s into a single channel; storage, the legacy server-push, the vendor exporters and the policy engine all consume from it.

**Monitors** (`src/monitors/`) — `file` (via `notify`), `process` (via `sysinfo`), `network`, `browser` (Chrome DevTools Protocol) and `kernel` (Linux NETLINK_AUDIT). See *[How AgentDR turns behavior into telemetry](#how-agentdr-turns-behavior-into-telemetry)* below for the full technique inventory.

**Ingest** (`src/ingest/`) — A loopback OTLP/HTTP server that decodes OpenTelemetry `gen_ai.*` semantic conventions straight into the AITF schema.

**MCP** (`src/mcp/`) — Model Context Protocol server inventory plus an stdio-proxy that captures every JSON-RPC message.

**Detection engine** (`src/detectors.rs`) — Stateful pattern detection implementing all 20 rules (`AITF-DET-001` → `AITF-DET-020`), plus credential-use attribution.

**Policy & response** (`src/policy/`, `src/proxy/`) — A YAML policy-as-code engine and two proxies that can *block* agent traffic, not just observe it:

- **Forward CONNECT proxy** (`src/proxy/mod.rs`) — controls *outbound* egress from agents to remote LLM/API hosts. Beyond the host allow-list / policy engine it now records caller **provenance** (which local PID / executable / known AI agent opened the connection), enforces optional **API-key / HS256-JWT auth** (`407`), and applies optional per-caller **rate limiting** (`429`).
- **LLM Guard reverse proxy** (`src/proxy/reverse.rs`, `[llm_guard]`, opt-in) — sits *in front of* local model backends (Ollama, LM Studio, llama.cpp). Point your model clients at it instead of the backend. It routes by path prefix (longest match wins), authenticates + rate-limits callers, applies a **process access-control list** (allow/deny which local process or attributed AI agent may call the models — with curated presets), inspects request bodies for **prompt-injection & PII**, tracks **token usage** from upstream responses, runs upstream **health checks** (`GET /healthz`), and emits OCSF findings (`2004`) for blocked/suspicious requests. `block_on_*` defaults to alert-only. Run it inside `adr-agent start` or standalone via `adr-agent llm-guard`. See [docs/integrations/llm-guard-reverse-proxy.md](docs/integrations/llm-guard-reverse-proxy.md).

**Exporters** (`src/exporters/`) — Ten SIEM/observability backends (Splunk, Datadog, Elastic, Chronicle, XSIAM, Snowflake, Sentinel, Wazuh, syslog, generic OCSF).

**CLI** (`src/main.rs`):

```
adr-agent start --watch ~/Projects      # foreground with live event stream
adr-agent verify                        # verify SHA-256 checksums of rule files
adr-agent update                        # refresh community rule pack
adr-agent hooks install all             # wire Claude Code / Cursor / Codex / Aider / OpenCode to OTLP
adr-agent agents list                   # multi-tool inventory: hooks, MCP, running PIDs per agent
adr-agent discovery scan                # auto-discover AI agents on this host
adr-agent discovery scan --apply        # ...and install hooks per [discovery].mode
adr-agent discovery prompt              # interactive: ask the user about each new agent
adr-agent mcp inventory                 # enumerate MCP server configs
adr-agent mcp wrap --name x -- <cmd>    # stdio-proxy + record an MCP server
adr-agent otlp                          # standalone OTLP collector
adr-agent policy list | policy test     # inspect / dry-run the policy pack
adr-agent proxy --allow anthropic.com   # standalone inline blocking proxy
adr-agent llm-guard                     # reverse proxy fronting local models ([llm_guard])
adr-agent shell wrap --name s -- <cmd>  # record an agent shell session
```

Build it with `cd adr_system/rust_agent && cargo build --release`; the binary is `target/release/adr-agent`. Pre-built signed packages for all three OSes are produced by the release workflow in `.github/workflows/release.yml`.

### 2. `adr_dashboard/nextjs_space/` — Analyst Dashboard

A Next.js 14 (App Router) + TypeScript + Tailwind + shadcn/ui application backed by Prisma and PostgreSQL. It provides:

- **Dashboard** — risk summary, agent-activity heatmap, recent high-severity events.
- **Activity / Logs** — searchable, filterable raw event timeline.
- **Alerts** — triage view of detection rule firings.
- **Analytics** — timeline charts, agent distribution, event-type distribution (Recharts/Plotly).
- **Policies** — enable/disable detection rules and adjust thresholds per organization.
- **LLM Guard** — monitor the reverse-proxy in front of local models: backend health, blocked/flagged requests, prompt-injection & PII findings, token usage, and active callers; plus a settings page to configure backends, auth, rate limits, and content inspection. See [docs/integrations/llm-guard-reverse-proxy.md](docs/integrations/llm-guard-reverse-proxy.md).
- **Settings** — storage retention, archival, multi-tenant org configuration.
- **Auth** — NextAuth with Prisma adapter (org/role: owner / admin / analyst / viewer).

The Prisma schema (`prisma/schema.prisma`) carries the full AITF OCSF Class-Reuse field set on the `Event` model (`classUid`, `aiOperation`, `typeUid`, `activityId`, `severityId`, `provider`, `model`, `agentName`, `agentFramework`, `toolName`, `mcpServer`, `actor`, `compliance`, `securityFinding`, `tokenUsage`, `costInfo`, `traceId`, `spanId`).

Events are ingested by the agent's `server_push` POSTing to `/api/sync`. Alerts are exposed at `/api/alerts`, recent events at `/api/events/recent`.

### 3. `adr_system/cosai-community/` — Shared CoSAI Rule Pack

A versioned, JSON-only, checksum-verified rule pack consumed by the agent at runtime. Operators can patch new agent signatures or AI endpoints without redeploying binaries.

```
cosai-community/
├── rules/
│   ├── agent-signatures.json      # process patterns → agent name/framework/category/risk
│   ├── ai-endpoints.json          # hostname patterns → AI provider/model
│   └── messaging-endpoints.json   # hostname patterns → messaging platform
├── policies/
│   └── detection-rules.json       # 20 default detection rules with severity/category
├── scripts/generate-checksums.sh
├── checksums.sha256               # SHA-256 manifest verified by `agent verify`
└── docs/CONTRIBUTING.md
```

---

## How AgentDR turns behavior into telemetry

AgentDR's job is to take *raw endpoint behavior* — a file opened, a syscall
made, an HTTP request attempted, a JSON-RPC frame sent to an MCP server —
and convert it into **normalized, SIEM-ready telemetry**: one `EventRecord`
per observed behavior, shaped against the AITF OCSF Class-Reuse Model. Every technique below
feeds the **same async event bus**; the bus is what makes a credential read
from the file monitor, an OTLP span from Claude Code, and a blocked
connection from the inline proxy all come out the other end with the same
fields, the same `trace_id` discipline, and the same compliance mappings.

### The pipeline

```
 observation techniques            normalization              fan-out
 ─────────────────────             ─────────────              ───────
 file / process / network  ┐
 OTLP gen_ai.* ingest      │
 MCP inventory + stdio     ├──►  EventRecord  ──►  detection  ──►  JSONL store
 kernel audit              │     (OCSF reuse)      engine +       server push
 shell / TTY wrap          │     ai_operation,     policy         10 exporters
 browser CDP               │     class_uid,        engine         inline proxy
 inline proxy              ┘     trace_id …                        decisions
```

Nothing downstream needs to know *which* technique produced an event — the
detector, the policy engine and every exporter operate purely on the
normalized `EventRecord`.

### Technique inventory

| # | Technique | What it observes | OS mechanism | Becomes |
|---|-----------|------------------|--------------|---------|
| 1 | **File-system watch** | create / modify / delete / move under watched dirs; writes to agent-skill paths and credential files | `inotify` (Linux), `FSEvents` (macOS), `ReadDirectoryChangesW` (Windows) via the `notify` crate | `ai_operation tool_execution` (API Activity `6003`); credential paths raise a `data_exfiltration` Detection Finding (`2004`) |
| 2 | **Process-table polling** | process start / stop; names, exe paths and command lines matched to AI-agent signatures | `/proc` (Linux), `libproc` (macOS), `ToolHelp` (Windows) via `sysinfo` | `ai_operation agent_action` (`agent_activity 9001`); `agent_name` / `agent_framework` populated from `agent-signatures.json` |
| 3 | **Network observation** | outbound connections to AI provider & messaging hosts | mitm-style HTTP proxy *or* socket sampling + DNS | `inference` (API Activity `6003`, AI API) / `permission_escalation` (Detection Finding `2004`, messaging) |
| 4 | **OTLP `gen_ai.*` ingest** | prompts, tool calls, token usage, approvals — emitted by the agents themselves | loopback OTLP/HTTP server; OpenTelemetry GenAI semantic conventions | `inference` / `tool_execution` / `mcp_operation` (API Activity `6003`), `permission_escalation` (`2004`) approval |
| 5 | **Runtime hooks** | wires Claude Code / Cursor / Codex / Aider / OpenCode to emit (4) in the first place | edits each agent's own config (`settings.json`, `mcp.json`, `config.toml`, `opencode.json`) | enables technique 4 with semantic certainty (no guessing) |
| 6 | **MCP inventory** | which MCP servers are declared, where, with which transport and which secret env keys | scans 8 known config locations across every runtime | `ai_operation mcp_operation` (API Activity `6003`), `activity_id 2 (Read)` |
| 7 | **MCP stdio interception** | every JSON-RPC request/response to a wrapped MCP server | `adr-agent mcp wrap` re-execs the server and proxies stdin/stdout | `ai_operation mcp_operation` (`6003`); `tool_name` = JSON-RPC method |
| 8 | **Kernel audit** | syscall / path records from the OS audit subsystem | `NETLINK_AUDIT` multicast (Linux); EndpointSecurity / ETW posture on macOS / Windows | `ai_operation agent_action` (`9001`), `activity_id 6 (Detect)` |
| 9 | **Shell / TTY wrap** | every command an agent shell-execs, plus its stdout / stderr | `adr-agent shell wrap` pipes stdin/stdout/stderr | `ai_operation tool_execution` (`6003`); input = medium risk, output = low |
| 10 | **Browser CDP attach** | page open / navigate / close by browser-use agents | polls the Chrome DevTools `/json` endpoint | `ai_operation agent_action` (`9001`) with destination URL |
| 11 | **Inline proxy decisions** | every CONNECT an agent attempts, allowed or denied | loopback HTTP CONNECT proxy consulted by `HTTPS_PROXY` | `inference`/`agent_action` (`6003`/`9001`) on allow, `compliance_violation` (`2003`) BLOCKED on deny |
| 12 | **Credential attribution** | joins a credential-file read to the agent process responsible | 10-minute rolling window of agent `process_started` events | enriches the `AITF-DET-018` alert with a `candidate_agents` list |
| 13 | **Self-protection / watchdog** | hashes AgentDR's own config, the rule pack, the binary, and every installed runtime-hook config; fires when an AgentDR marker is removed or a tracked file disappears | periodic SHA-256 + marker presence check | `ai_operation compliance_violation` (Compliance Finding `2003`, critical) on evasion, optional self-heal that re-installs the hook |
| 14 | **Auto-discovery** | finds every AI agent on the host (PATH, install locations, hook configs, MCP entries, running PIDs) and decides what to monitor per `[discovery].mode` (interactive / policy / automatic / off) | runs on install, on startup, on schedule, on demand | hook installs + `ai_operation agent_action` (`9001`) `discovery_scan_completed` events |
| 15 | **LLM Guard reverse proxy** | every request to a fronted local model backend (Ollama, LM Studio, llama.cpp): caller process identity, prompt-injection / PII matches in the body, upstream status, and token usage | terminating HTTP reverse proxy (`[llm_guard]`, or `adr-agent llm-guard`) that routes by `route_prefix`, authenticates + rate-limits callers, applies a process allow/deny ACL, and reads request/response bodies | `inference` (API Activity `6003`) per request; a denied caller process or prompt-injection / PII raises an `identity` / `prompt_injection` / `data_exfiltration` Detection Finding (`2004`); blocked calls carry `status_id` BLOCKED |

### From observation to a normalized event

Each technique constructs an `EventRecord` and fills the AITF OCSF Class-Reuse
fields it can attest to:

* **`class_uid` / `type_uid` / `activity_id`** — *what kind of behavior*
  this is (LLM inference, tool execution, MCP operation, data
  exfiltration …) and the verb (Create / Read / Update / Delete /
  Execute / Detect / Block).
* **`severity_id` / `risk_level` / `status_id`** — *how dangerous* and
  whether it succeeded, failed, or was **blocked**.
* **AI-specific identity** — `provider`, `model`, `agent_name`,
  `agent_framework`, `tool_name`, `mcp_server`, `token_usage`,
  `actor` (`{user, host, pid}`).
* **`trace_id` / `span_id`** — OpenTelemetry-style IDs. Techniques that
  see a real trace (OTLP, MCP) carry it through verbatim; the rest
  generate one. Detections inherit the `trace_id` of the event that
  triggered them, so a multi-step agent run reconstructs end-to-end.
* **`compliance` / `security_finding`** — OWASP LLM Top-10 and
  NIST AI-RMF mappings attached to every detection and policy hit.

### From a normalized event to a decision

Once an event is on the bus it is, in order:

1. **persisted** to a rotating JSONL store;
2. run through the **detection engine** — 20 stateful rules over sliding
   time windows (e.g. *rapid file modification*, *unusual API volume*,
   *credential access*) — each match emitting its own alert event;
3. run through the **policy engine** — YAML policy-as-code; each match
   emits a Compliance Finding (`class_uid 2003`, `ai_operation compliance_violation`) and can escalate to a
   **block**;
4. **fanned out** to the legacy server-push and to every enabled vendor
   exporter (Splunk, Datadog, Elastic, Chronicle, XSIAM, Snowflake,
   Sentinel, Wazuh, syslog, OCSF).

The result: behavior observed by *any* technique becomes a standardized
AITF OCSF Class-Reuse record that lands in the analyst's SIEM — and, when a
policy says so, gets blocked at the proxy in the same pass.

---

## Self-protection and multi-tool monitoring

### Self-protection (watchdog)

AgentDR ships a built-in watchdog that defends its own footprint on the
endpoint — and in particular detects when a monitored AI agent tries to
*escape surveillance* by removing AgentDR's marker from its config.

What it tracks:

* The agent's own `config.toml`
* The AgentDR binary on disk
* The community rule pack (`cosai-community/rules/*.json`,
  `policies/*.json`, `policies/policies.yaml`)
* Every installed runtime-hook config (Claude Code, Cursor, Codex, Aider,
  OpenCode)

What it detects (per tick, default 30 s):

| Observation | Severity | Event |
|---|---|---|
| Hook config hash changed, AgentDR marker still present | `low` | `watchdog_config_changed` — likely operator edit |
| Hook config hash changed, marker MISSING (was present) | `critical` | **`watchdog_evasion_detected`** — class_uid 2003 (Compliance Finding), status=BLOCKED |
| Tracked file deleted | `critical` | `watchdog_file_missing` |
| Agent config edited | `medium` | `watchdog_config_changed` |
| Rule / policy pack edited | `high` | `watchdog_rule_pack_changed` |
| Binary on disk replaced | `critical` | `watchdog_binary_changed` |

Configure under `[watchdog]`:

```toml
[watchdog]
enabled          = true
interval_seconds = 30
self_heal        = true   # on evasion, automatically re-install the missing hook
```

When `self_heal = true`, an evasion detection triggers an immediate
re-run of the matching `hooks install <agent>` so the marker (and the
OTLP wiring it carries) is restored within one tick.

### Multi-tool monitoring on a single host

Developers and AI engineers routinely run **several coding agents
side by side** — Claude Code in one terminal, Cursor in the IDE,
OpenCode for a quick session, Codex CLI in CI. AgentDR is designed for
this from the bus down:

* The process monitor matches every running process against every
  signature; no rule limits AgentDR to one agent at a time.
* Each runtime hook sets a distinct `OTEL_SERVICE_NAME`
  (`claude-code`, `cursor`, `codex`, `aider`, `opencode`), so the
  single loopback OTLP collector trivially demuxes per-agent.
* Every event carries `agent_name` + `agent_framework`, every UEBA
  baseline is keyed by `(host, user, agent)`, and the Sessions
  dashboard joins activity across multiple agents through `trace_id`.

To see the live picture for the current host:

```bash
adr-agent agents list                 # human-readable table
adr-agent agents list --json          # machine-readable for ops automation
```

The table shows, per agent: whether its binary is on `$PATH`, whether
AgentDR's hook is installed (and to what endpoint), which MCP servers
it has configured, and which PIDs (if any) are running right now.

### Auto-discovery (Tier 8)

Personal endpoints, developer laptops, CI runners and managed
enterprise fleets each want a different policy for "*which* AI agents
on this host should AgentDR actually monitor?" The discovery subsystem
answers that question one of four ways, set under `[discovery].mode`:

| mode | Behaviour |
|---|---|
| `off`         | Scan and report only; never install hooks automatically |
| `interactive` | Prompt the local user via stdin for each newly-found agent (TTY required) |
| `policy`      | Apply `cosai-community/policies/discovery.yaml` (default) |
| `automatic`   | Install hooks for every supported agent that's found |

Triggers:

* **On install** — the macOS `.pkg` postinstall and Linux `.deb` postinst
  both run `adr-agent discovery scan --apply` so the agent self-configures
  during fleet rollout.
* **On startup** — the engine runs a scan at start when
  `[discovery].scan_on_start = true` (default).
* **On schedule** — periodic re-scan every `[discovery].scan_interval_hours`
  (default 24 h), so an agent that gets installed *after* AgentDR is
  picked up automatically.
* **On demand** — `adr-agent discovery scan [--apply]` from the shell.

Evidence sources per agent: `$PATH` binary, well-known install locations
(macOS `.app`, `/opt/`, `~/.local/bin/`, Windows `Program Files`), hook
config presence (including the unmanaged case — "user has Aider's
`~/.aider.conf.yml` but no AgentDR hook"), MCP entries in
runtime-specific configs, and currently-running matched PIDs. Confidence
scores aggregate across sources.

User decisions are persisted to `<root>/runtime/discovery-state.json`
so the user is never asked twice. Operators inspect / override with:

```bash
adr-agent discovery status              # show recorded decisions
adr-agent discovery prompt              # interactive prompt loop
```

The default policy ships with safe choices: monitor every coding agent
(Claude Code, Cursor, Codex, Aider, OpenCode); prompt before monitoring
browser-use agents (Computer Use, Operator, Browser Use); skip enterprise
copilots (M365 Copilot et al.) until an admin opts them in.

---

## Target agents supported

The agent rule pack ships with detectors for five categories. Each entry below shows the **agent name** → **framework** → **default risk** assigned by the CoSAI signature.

### Coding assistants (low-risk by default)

| Agent | Framework | Process patterns |
|---|---|---|
| Cursor | Cursor IDE | `cursor` |
| Claude Code | Anthropic CLI | `claude`, `claude_desktop` |
| Codex CLI | OpenAI CLI | `codex` |
| GitHub Copilot | VSCode Extension | `copilot` |
| Aider | Aider | `aider` |
| Devin | Cognition | `devin` |
| Windsurf | Codeium | `windsurf` |
| Cline | VSCode Extension | `cline` |
| Augment Code | VSCode Extension | `augment` |
| Continue.dev | VSCode Extension | `continue` |
| OpenCode | OpenCode CLI | `opencode` |

### General-purpose autonomous agents (medium / high risk)

| Agent | Framework | Risk |
|---|---|---|
| OpenClaw | OpenClaw Runtime | high |
| NemoClaw | NVIDIA NemoClaw | medium |
| AutoGPT | AutoGPT | high |
| BabyAGI | BabyAGI | medium |
| SuperAGI | SuperAGI | medium |
| ChatGPT (desktop) | OpenAI | medium |
| Hermes Agent | Nous Research | high |

### Workflow / orchestration frameworks

LangChain, CrewAI, Microsoft AutoGen, LlamaIndex, HuggingFace SmolAgents, NVIDIA OpenShell.

### Enterprise / productivity copilots

M365 Copilot, Edge Copilot, Windows Copilot, Copilot Studio (high), Bing Copilot, ServiceNow CLI / MID Server / Now Assist / Virtual Agent, SAP GUI, SAP BTP CLI, SAP Joule, SAP Integration Agent.

### Browser-automation agents (high-risk by default)

Claude Computer Use, OpenAI Operator, Browser Use, Browserbase, Stagehand.

To extend coverage, edit `adr_system/cosai-community/rules/agent-signatures.json`, then regenerate `checksums.sha256` with `scripts/generate-checksums.sh`. Run `adr-agent verify` to confirm the agent will accept the update.

#### Hermes Agent (Nous Research)

Hermes — a self-improving agent with persistent memory, agent-created skills (agentskills.io), and egress to Telegram / Discord / Slack / WhatsApp / **Signal / Email** — is detected via the `hermes-agent` signature and monitored through existing techniques: its messaging endpoints (Signal + SendGrid/Mailgun/Resend/Postmark/Gmail) raise `AITF-DET-016`, its skill drops (`.hermes/skills`, `.nous/skills`, `agentskills`) trip `AITF-DET-015`/`020`, and its OpenAI-compatible providers (OpenRouter, Nous Research) are classified by the AI-endpoint pack.

#### NVIDIA OpenShell

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) — a secure-by-design sandbox/runtime + policy Gateway for autonomous agents — is supported two ways: the `nvidia-openshell` signature detects the runtime (and sandboxed agents still self-attribute), and AgentDR can **ingest OpenShell's OCSF v1.7.0 Gateway audit log** (`[openshell] enabled = true`), normalizing every allow/deny decision into the AITF schema so it flows through the same detectors, policies, and exporters. AgentDR is the detection/SIEM layer *over* OpenShell's enforcement layer. See **[docs/integrations/openshell-ingest.md](docs/integrations/openshell-ingest.md)**.

---

## AI Telemetry: CoSAI / AITF schema

AgentDR's telemetry follows the **CoSAI AI Telemetry Framework (AITF), v0.2** as described in [`girdav01/AITF`](https://github.com/girdav01/AITF). Following AITF 0.2, AgentDR has **dropped the bespoke "Category 7"** (whose `uid 7` collided with OCSF's released *Remediation* category) in favour of AITF's **OCSF Class-Reuse Model**: every AI event reuses an *existing* OCSF class and carries an **`ai_operation` profile** that holds the AI-specific semantic. (This mirrors the OCSF principle of reusing classes rather than minting bespoke AI event classes — see OCSF issue [#1640](https://github.com/ocsf/ocsf-schema/issues/1640) for the proposed control-plane classes.) Every `EventRecord` (see `adr_system/rust_agent/src/models.rs`) is shaped against this schema so that events are SIEM-ready without a translation layer.

### OCSF Class-Reuse Model (`ai_operation` → reused `class_uid`)

Data-plane events flow through the standard OCSF categories (2–6); only the control-plane agent/delegation lifecycle uses the proposed Category 9 (provisional, pending OCSF ratification).

| `ai_operation` | Reused OCSF class (`class_uid`) | What AgentDR emits here |
|---|---|---|
| `inference` | API Activity (`6003`) | Decoded LLM request/response metadata (provider, model, token counts, cost) |
| `tool_execution` | API Activity (`6003`) | Shell commands and tool calls invoked by an agent |
| `mcp_operation` | API Activity (`6003`) | MCP server interactions, plugin/skill loads |
| `data_retrieval` | Datastore Activity (`6005`) | RAG / vector-store retrieval |
| `model_ops` | Application Lifecycle (`6002`) | Model lifecycle / LLMOps operations |
| `agent_action` | `agent_activity` (`9001`, proposed) | Process start/stop, file & browser activity, agent lifecycle |
| `delegation` | `delegation_activity` (`9002`, proposed) | Agent-to-agent authorization grants/revocations |
| `prompt_injection`, `data_exfiltration`, `permission_escalation`, `guardrail`, `cost_anomaly` | Detection Finding (`2004`) | Security findings raised by the detection engine |
| `compliance_violation` | Compliance Finding (`2003`) | Drift from configured policy / framework requirements |
| `supply_chain` | Vulnerability Finding (`2002`) | Malicious/unvetted skills & plugins, supply-chain compromise |
| `identity` | Authentication (`3002`) | Agent authentication / delegation auth |
| `asset_inventory` | Inventory Info (`5001`) | Discovered agents and MCP-server inventory |

### Semantic-convention namespaces

AITF extends the OpenTelemetry GenAI conventions with dedicated namespaces; AgentDR emits attributes under: `gen_ai.*`, `agent.*`, `mcp.*`, `skill.*`, `rag.*`, `security.*`, `compliance.*`, `cost.*`, `quality.*`, `supply_chain.*`, `identity.*`, `model_ops.*`, `asset.*`, `drift.*`, `guardrail.*`, `memory.*`, and `memory.security.*` (memory poisoning / integrity) — the full AITF 0.2 namespace set.

### `ai_agent` object (AITF 0.2)

Every AI-attributable event carries a structured **`ai_agent` object** (AITF 0.2 / provisional OCSF PR [#1641](https://github.com/ocsf/ocsf-schema/pull/1641)) grouping the agent's identity: `uid` (**required** — stable logical agent id), `instance_uid` (running instance / conversation id), `name`, `type` + `type_id` (framework caption + normalized enum), `ai_model` (backing model), `version`, and `charter`. AgentDR builds it from the flat `agent_name` / `agent_framework` / `model` fields (kept alongside for backward compatibility): the `uid` comes from `gen_ai.agent.id` when present, else a deterministic FNV-1a hash of the agent identity so the same agent keeps a stable id across restarts and hosts. The OTLP ingest sources `instance_uid` from `gen_ai.conversation.id` / `gen_ai.thread.id` / `session.id`; the reverse proxy uses the caller PID.

### Delegation object (AITF 0.2)

Agent-to-agent authorization is captured both as the `delegation` `ai_operation` (proposed OCSF class `9002`) and as a structured **`delegation` object** on the event — `grantor`, `grantee`, `scope`, `action` (grant/revoke), and `ttl_seconds` — populated from `delegation.*` / `gen_ai.delegation.*` span attributes by the OTLP ingest.

### Common OCSF fields on every event

`timestamp`, `class_uid` (reused OCSF class), `ai_operation` (AITF profile string), `type_uid` (= `class_uid * 100 + activity_id`), `activity_id` (Create=1, Read=2, Update=3, Delete=4, Execute=5, Detect=6, Block=7), `severity_id` (Informational=1 → Critical=5, mapped from `risk_level`), `status_id` (Success/Failure/Blocked/Unknown), `message`.

### AI-specific fields

`provider` (OpenAI, Anthropic, Google, Azure OpenAI, DeepSeek, Mistral, Ollama, Microsoft Copilot, ServiceNow, SAP AI, Browserbase, ...), `model`, `agent_name`, `agent_framework`, `ai_agent` (the AITF 0.2 structured agent-identity object — see above), `tool_name`, `mcp_server`, `actor` (`{user, pid}`), `token_usage`, `cost_info`.

### Compliance / security finding fields

`security_finding` (`{rule_id, title, severity, owasp_llm}`), `compliance` (frameworks list — OWASP LLM Top-10 and NIST AI-RMF — plus the rule's specific OWASP mapping).

### Distributed tracing

Every event carries an OpenTelemetry-style `trace_id` (32 hex) and `span_id` (16 hex). Detection alerts inherit the `trace_id` of the triggering event so a multi-step agent workflow can be reconstructed end-to-end.

### Detection rule catalog (`AITF-DET-001` → `AITF-DET-020`)

Defined in `adr_system/cosai-community/policies/detection-rules.json` and wired into the engine via `adr_system/rust_agent/src/models.rs::detection_rules()`:

Rules 001–014 are the canonical AITF built-ins; 015–020 are AgentDR endpoint-specific extensions.

| ID | Rule | Category | OWASP | `ai_operation` | OCSF Class |
|---|---|---|---|---|---:|
| AITF-DET-001 | Unusual Token Usage | Inference | LLM01 | `cost_anomaly` | 2004 |
| AITF-DET-002 | Model Switching Attack | Inference | LLM02 | `prompt_injection` | 2004 |
| AITF-DET-003 | Prompt Injection Attempt | Inference | LLM04 | `prompt_injection` | 2004 |
| AITF-DET-004 | Excessive Cost Spike | Inference | LLM05 | `cost_anomaly` | 2004 |
| AITF-DET-005 | Agent Loop Detection | Agent | LLM08 | `guardrail` | 2004 |
| AITF-DET-006 | Unauthorized Agent Delegation | Agent | LLM03 | `permission_escalation` | 2004 |
| AITF-DET-007 | Agent Session Hijack | Agent | LLM02 | `permission_escalation` | 2004 |
| AITF-DET-008 | Excessive Tool Calls | Agent | LLM04 | `guardrail` | 2004 |
| AITF-DET-009 | MCP Server Impersonation | MCP/Tool | LLM08 | `permission_escalation` | 2004 |
| AITF-DET-010 | Tool Permission Bypass | MCP/Tool | LLM06 | `permission_escalation` | 2004 |
| AITF-DET-011 | Data Exfiltration via Tools | MCP/Tool | LLM05 | `data_exfiltration` | 2004 |
| AITF-DET-012 | PII Exfiltration Chain | Security | LLM04 | `data_exfiltration` | 2004 |
| AITF-DET-013 | Jailbreak Escalation | Security | LLM05 | `guardrail` | 2004 |
| AITF-DET-014 | Supply Chain Compromise | Security | LLM09 | `supply_chain` | 2002 |
| AITF-DET-015 | Malicious Skill / Plugin Loaded | Agent/Plugin | LLM03 | `supply_chain` | 2002 |
| AITF-DET-016 | Unauthorized Messaging Channel | Agent/Comms | LLM05 | `data_exfiltration` | 2004 |
| AITF-DET-017 | Shell Command Execution | Agent/System | LLM08 | `permission_escalation` | 2004 |
| AITF-DET-018 | Credential / Secret Access | Security | LLM06 | `data_exfiltration` | 2004 |
| AITF-DET-019 | Cross-Platform Data Relay | Security | LLM02 | `data_exfiltration` | 2004 |
| AITF-DET-020 | Unvetted Skill Installation | Agent/Plugin | LLM03 | `supply_chain` | 2002 |

### Sample event (JSONL)

```json
{
  "timestamp": "2026-05-01T14:22:08.421+00:00",
  "event_type": "process_started",
  "class_uid": 9001,
  "ai_operation": "agent_action",
  "type_uid": 900101,
  "activity_id": 1,
  "severity_id": 3,
  "status_id": 1,
  "risk_level": "medium",
  "message": "Process started: openclaw",
  "agent_name": "OpenClaw",
  "agent_framework": "OpenClaw Runtime",
  "agent_detected": "OpenClaw",
  "actor": {"user": "david", "pid": 28471},
  "details": {"pid": 28471, "name": "openclaw", "exe": "/usr/local/bin/openclaw"},
  "trace_id": "9b7f0c8d2e1a4f5b6c7d8e9f0a1b2c3d",
  "span_id": "1a2b3c4d5e6f7a8b",
  "source": "process_monitor"
}
```

### Sample alert (JSONL)

```json
{
  "timestamp": "2026-05-01T14:22:14.902+00:00",
  "event_type": "alert_credential_access",
  "class_uid": 2004,
  "ai_operation": "data_exfiltration",
  "type_uid": 200406,
  "activity_id": 6,
  "severity_id": 5,
  "risk_level": "critical",
  "message": "[AITF-DET-018] Credential / Secret Access",
  "agent_detected": "credential_harvesting",
  "details": {
    "path": "/Users/david/.aws/credentials",
    "event_type": "file_read",
    "rule_id": "AITF-DET-018",
    "rule_name": "Credential / Secret Access",
    "owasp_category": "LLM06"
  },
  "security_finding": {
    "rule_id": "AITF-DET-018",
    "title": "Credential / Secret Access",
    "severity": "critical",
    "owasp_llm": "LLM06"
  },
  "compliance": {
    "frameworks": ["OWASP-LLM-Top10", "NIST-AI-RMF"],
    "mappings": {"OWASP-LLM-Top10": "LLM06"}
  },
  "trace_id": "9b7f0c8d2e1a4f5b6c7d8e9f0a1b2c3d",
  "span_id": "f0e1d2c3b4a59687",
  "source": "detector"
}
```

---

## How to use it

### 1. Run the agent locally

```bash
cd adr_system/rust_agent
cargo build --release
./target/release/adr-agent start --watch ~/Documents
```

Or install a pre-built signed package — `brew install agentdr` (macOS),
`scoop install agentdr` (Windows), or the `.deb` / `.rpm` (Linux). Then
wire your coding agents to the loopback OTLP collector in one command:

```bash
adr-agent hooks install all --endpoint http://127.0.0.1:4318
```

Step-by-step demo walkthroughs for each OS live in
[`docs/test-plans/`](docs/test-plans/).

### 2. Run the dashboard locally

```bash
cd adr_dashboard/nextjs_space
yarn install
# set DATABASE_URL and NEXTAUTH_SECRET in .env (Postgres)
npx prisma migrate deploy
yarn dev
```

The dashboard runs on `http://localhost:3000`. Sign up to create an organization, then set the agent's `server_push.endpoint` to `http://localhost:3000/api/sync` so events flow through.

### 3. Push agent events to the dashboard

Add a `server_push` block to `config.toml` (next to the agent's `--root`),
or enable any of the ten vendor exporters under `[exporters.*]`:

```toml
[server_push]
enabled  = true
endpoint = "http://localhost:3000/api/sync"
api_key  = "<org api key from dashboard>"
```

### 4. Refresh and verify the rule pack

```bash
adr-agent update    # pull latest cosai-community rules
adr-agent verify    # SHA-256 integrity check
```

---

## Status & limitations

AgentDR is **research-grade software**, not a hardened commercial EDR.
Current state and known caveats:

- **Tool / MCP execution events** are captured directly via the OTLP
  ingest path (technique 4) and the MCP stdio-proxy (technique 7) when
  the runtime hooks are installed; without hooks, AgentDR still infers
  them from process and file-system signals, but with lower fidelity.
- **Token / cost fields** are populated from OTLP `gen_ai.usage.*`
  attributes; agents that don't emit them leave those fields empty.
- **macOS / Windows kernel telemetry** ships as a documented posture
  (EndpointSecurity sidecar / ETW providers) rather than a built-in
  collector — only Linux `NETLINK_AUDIT` runs in-process today.
- **Prompt-injection scoring (`ai_operation prompt_injection`, Detection Finding 2004)** emits events but does not yet
  classify prompt content — AgentDR observes and forwards; correlation
  is left to the SIEM.
- **Inline TLS** is hostname-level (CONNECT SNI) only; AgentDR does not
  ship an MITM CA.

Multi-host correlation, per-agent UEBA baselining, kill-chain replay,
the ten vendor exporters, and inline policy blocking are all implemented
— see the technique inventory above.

Contributions to the rule pack — especially new agent signatures, AI
endpoint patterns, and policy-as-code rules — are welcome via the
[`cosai-community/docs/CONTRIBUTING.md`](adr_system/cosai-community/docs/CONTRIBUTING.md) guide.

## License

Apache-2.0, aligned with CoSAI open-source governance.
