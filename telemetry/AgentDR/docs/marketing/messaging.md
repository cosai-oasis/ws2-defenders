# AgentDR — Messaging & Sales One-Pagers

## Elevator pitches

* **5-second:** "Open-source EDR built for AI agents."
* **15-second:** "AgentDR captures, classifies and governs every AI agent
  action on the endpoint — Claude Code, Cursor, OpenClaw, the lot — on
  open standards, with inline policy enforcement."
* **45-second:** "Local AI agents have moved the security boundary from
  the gateway to the endpoint. Existing EDRs see *the process* but not
  *which model called which tool with which file*. AgentDR fills that
  gap. It installs alongside CrowdStrike or SentinelOne, captures
  OpenTelemetry signals straight from the coding agents, inventories
  and intercepts MCP traffic, applies YAML policy-as-code, and ships
  CoSAI AITF events (standard OCSF classes + an `ai_operation` profile)
  to whatever SIEM you already pay for. Apache 2.0, three OSes, ten
  exporters, no SaaS dependency."

## One-pager — CISO

```
┌─────────────────────────────────────────────────────────────────────┐
│ AgentDR — defensible AI policy for the endpoint                     │
│                                                                     │
│ THE PROBLEM                                                         │
│ Coding agents (Claude Code, Cursor, Codex) now run on every dev     │
│ laptop. They read code, modify files, hit APIs, install MCP servers.│
│ Existing EDR can't tell which agent did what — only that "node.exe" │
│ ran. Boards and regulators are starting to ask.                     │
│                                                                     │
│ WHAT AGENTDR PROVIDES                                               │
│ • Per-agent visibility (30+ signatures; standard OCSF classes +     │
│   AITF ai_operation profile)                                        │
│ • Inline blocking proxy with YAML policy-as-code                    │
│ • UEBA baselines per-(host, user, agent) and per-metric             │
│ • Auditable approval-flow capture (user approve/deny inside agents) │
│ • Compliance mappings: OWASP LLM Top-10 + NIST AI-RMF on every event│
│                                                                     │
│ DEPLOYMENT                                                          │
│ • Apache 2.0, no SaaS lock-in                                       │
│ • Signed packages for macOS, Linux, Windows                         │
│ • Sits ALONGSIDE existing EDR. <40 MB resident.                     │
│ • MDM templates ship for Jamf, Intune, Kandji, Fleet                │
│                                                                     │
│ STANDARDS                                                           │
│ • CoSAI AI Telemetry Framework (Cisco/Google/IBM/NVIDIA backed)     │
│ • AITF OCSF Class-Reuse — standard OCSF classes + ai_operation      │
│   profile (the SIEM-portable AI event schema)                       │
│ • OpenTelemetry gen_ai semantic conventions                         │
│                                                                     │
│ CTA: pilot in 30 days. agentdr.dev/pilot                            │
└─────────────────────────────────────────────────────────────────────┘
```

## One-pager — SOC Lead

```
┌─────────────────────────────────────────────────────────────────────┐
│ AgentDR — AI agent detection content for your SIEM                  │
│                                                                     │
│ WHAT YOU GET IN YOUR SIEM, DAY ONE                                  │
│ • 20 detection rules (AITF-DET-001..020) mapped to OWASP LLM Top-10 │
│ • Standard OCSF classes + ai_operation profile — no parsing required│
│ • Per-event trace_id + span_id so you can reconstruct sessions      │
│ • OpenTelemetry-native — events arrive < 1 s from the endpoint      │
│                                                                     │
│ EXPORTERS (pick one, ten, or all):                                  │
│   Splunk HEC, Datadog Logs, Elasticsearch _bulk, Google Chronicle,  │
│   Palo Alto XSIAM, Snowflake, Microsoft Sentinel, Wazuh, syslog,    │
│   generic OCSF webhook.                                             │
│                                                                     │
│ WHAT YOU CAN BUILD                                                  │
│ • "Agent X read credentials file Y at time Z" — with PID & user     │
│ • "Trace-grouped sessions across multiple hosts" (Tier 4 dashboard) │
│ • "UEBA outliers" — z-score against per-(user, agent) baselines     │
│ • "Inline block" — declarative YAML policy → 403 at the proxy       │
│                                                                     │
│ NO LOCK-IN                                                          │
│ Every event reuses a standard OCSF class + ai_operation profile.    │
│ Switch SIEMs without re-parsing.                                    │
│                                                                     │
│ CTA: install the .deb / Homebrew today; first events in 5 minutes.  │
└─────────────────────────────────────────────────────────────────────┘
```

## One-pager — AI Platform Team

```
┌─────────────────────────────────────────────────────────────────────┐
│ AgentDR — telemetry for your internal coding-agent platform         │
│                                                                     │
│ THE QUESTION YOU'LL BE ASKED                                        │
│ "When something goes wrong with an agent, can you tell us           │
│  what happened?"                                                    │
│                                                                     │
│ WHAT AGENTDR ADDS                                                   │
│ • Loopback OTLP collector — no app changes required                 │
│ • Hooks installer (`adr-agent hooks install all`) wires every       │
│   supported agent to your collector in one command                  │
│ • MCP server inventory + per-RPC capture (stdio + sse + http)       │
│ • Ships the events to YOUR existing observability backend           │
│ • Doesn't require an account, an API key, or an internet link       │
│                                                                     │
│ INTEGRATES WITH                                                     │
│ • Claude Code (native OTLP env vars)                                │
│ • Cursor (mcp.json recorder)                                        │
│ • Codex CLI (config.toml + wrapper)                                 │
│ • Aider (yaml config + wrapper)                                     │
│ • OpenTelemetry SDK / gen_ai semconv producers                      │
│                                                                     │
│ CI                                                                  │
│ The agentdr-policy-gate GitHub Action runs every PR's events        │
│ through your policy pack and fails the build on violations.         │
│                                                                     │
│ CTA: 5-minute setup → docs/test-plans/macos.md                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Boilerplate (for press / sponsorships)

> AgentDR is the open-source endpoint detection and response platform
> for the era of local AI agents. Built on the CoSAI AI Telemetry
> Framework (standard OCSF classes enriched with an `ai_operation`
> profile), AgentDR captures every prompt, tool
> call, MCP message and approval decision from coding agents on macOS,
> Linux and Windows endpoints — and ships the normalised events to ten
> SIEM and observability backends. Inline policy-as-code and an
> HTTP-CONNECT blocking proxy turn visibility into governance. Apache
> 2.0, no SaaS dependency.

## FAQ

**Q: Is this a fork of another OSS AI-telemetry project?**
No. AgentDR is independently built. We share the threat model that
several other open-source efforts in this space have articulated —
local agents move the security boundary to the endpoint — but we
extend that model in three directions: cross-platform (macOS / Linux /
Windows), cross-SIEM (ten exporters), and from visibility into
governance (inline blocking proxy + policy-as-code). The broader OSS
movement validated the category; AgentDR is the next step.

**Q: Why CoSAI AITF / OCSF and not your own schema?**
Because in 2027 every AI-aware SIEM will speak standard OCSF classes
enriched with an `ai_operation` profile — AITF dropped its bespoke
Category 7 and now reuses existing OCSF classes rather than minting new
ones. AgentDR is the reference implementation. Operators who deploy us
today won't have to re-parse their telemetry tomorrow.

**Q: Does AgentDR replace my EDR?**
No. AgentDR runs alongside CrowdStrike / SentinelOne / Defender. We see
the agent-shaped events those EDRs miss; they see the OS-level events we
defer to.

**Q: Do you collect any data from my endpoints?**
None. AgentDR runs entirely on the endpoint. The only outbound traffic
is to the SIEM / observability destinations you configure.

**Q: Why Rust?**
Resident memory under 40 MB, no GC pauses inside the policy/proxy hot
path, native cross-compilation for the three target OSes, and no
interpreter dependency on customer endpoints.

**Q: Who's behind this?**
Built by the CoSAI community as a reference implementation of the
AI Telemetry Framework (AITF). Apache 2.0, governed openly on GitHub.
