# Beyond visibility: the case for agentic endpoint defense

*Published 2026-05-17 · CoSAI / AgentDR contributors · ~12 minute read*

A growing wave of open-source projects has converged on a thesis that's
right enough to take seriously: *the AI security stack is looking in
the wrong place.* When the user on your endpoint is a coding agent —
Claude Code, Cursor, Codex, Aider, OpenClaw — your gateways and your
inference firewalls can tell you what a model **said**, but they can't
tell you what an agent **did**: which file it read, which tool it
called, which MCP server it just installed, which API endpoint it tried
to hit after the user explicitly told it not to.

These projects deserve credit for naming the gap and for showing that
endpoint-side AI telemetry is the right place to start. The category is
real. The thesis is right.

But the first wave of OSS efforts in this space stops one step short of
the place this story has to go: they ship visibility, then hand the
problem off. AgentDR is what happens when you decide that visibility is
the prerequisite, not the goal.

We've been quietly building **AgentDR** — an open-source endpoint
detection *and response* platform on the same threat model — for the
last few months. Today we're putting the full thing in the open.

## What "the user on your endpoint is an agent" actually means

Five years ago, the security boundary on a developer laptop was: the
user, sitting at the keyboard, was a human. When that human ran `git
push`, your CI pipeline picked it up. When they hit `cat
~/.aws/credentials`, that was either Friday-afternoon panic or a
specific incident, and you had logs of which window was focused at the
time.

Today, on the same developer laptop, the user is a Claude Code session
that started 14 minutes ago and is in the middle of a multi-step trace.
It is iterating against `~/Documents/repo-x/`, reading files,
running shell commands, talking to a half-dozen MCP servers, and
hitting `api.anthropic.com` 90 times a minute. The human at the keyboard
is reviewing summaries.

Every assumption built into 2010-vintage endpoint security — "an active
process is a deliberate human action" — quietly stops being true.

The hard part isn't building the rules. The hard part is reconstructing
the **subject** behind the activity:

* Was this `cat ~/.aws/credentials` triggered by the human, or by
  Claude Code five seconds after the human typed "fix the deploy"?
* Was this network connection to `api.openai.com` a deliberate API
  call by the codebase, or by an MCP server that got installed last
  Tuesday?
* Was this file modification an intentional refactor, or was it an
  agent loop running away with itself?

The shape of the answer is the shape of the product.

## Where current OSS efforts in this space stop

The shape of most first-wave OSS AI-telemetry projects looks like
**OpenTelemetry collector + per-agent runtime hooks + normalised JSON
output to one or two SIEMs.** That's a cleanly executed collector — and
we share two of those three primitives.

Where most of those projects stop:

* **Visibility only.** Their READMEs are typically explicit: no inline
  enforcement, no policy engine, no blocking. SOC sees the event, then
  has to act elsewhere.
* **One platform.** Usually macOS-first; Linux and Windows often
  aren't on the roadmap.
* **One or two destinations.** A Splunk HEC sink and a JSON-file
  output. The marketing diagrams promise Datadog, Elastic, Chronicle,
  XSIAM — but those rarely exist in the source tree yet.
* **No MCP capture.** Often listed as an explicit non-goal.
* **No kernel layer, no shell capture, no browser, no credential
  attribution.** All explicit non-goals in the projects we've surveyed.
* **Custom JSON shapes.** Not OCSF. Not AITF. Operators who
  deploy today will have to re-parse their telemetry in 2027 once the
  industry settles on a standard.

These aren't criticisms — they're scope choices appropriate to early-
stage projects. They are also exactly the surface area an agentic-EDR
has to cover.

## What we built instead

AgentDR is a **Rust** endpoint agent and a **Next.js** analyst dashboard
with six tiers of capability. Every tier is opt-in. Together they cover
the surface a 2026-era endpoint actually requires.

### Tier 1 — accurate telemetry

A loopback OTLP/HTTP collector with the OpenTelemetry `gen_ai.*`
semantic conventions wired directly into the CoSAI AITF schema. A
runtime-hook installer that knows how to wire Claude Code,
Cursor, Codex CLI and Aider in one command:

```bash
adr-agent hooks install all --endpoint http://127.0.0.1:4318
```

An MCP server inventory that finds every config file across every
supported runtime (Cursor, Claude Code, Claude Desktop, Windsurf,
Continue.dev, VS Code, project-level, operator-supplied). An MCP
stdio-proxy that captures every JSON-RPC message on the way in and
out of a wrapped server.

Following the latest AITF spec, we don't mint a bespoke event class.
AITF dropped its Category 7 and now **reuses standard OCSF classes
enriched with an `ai_operation` profile** — the same principle OCSF
itself follows: reuse existing classes rather than invent new ones for
every domain. Each AgentDR event reuses an OCSF class and carries the
AI-specific semantic in `ai_operation`: inference (API Activity 6003),
agent_action (agent_activity 9001, proposed), tool_execution (6003),
mcp_operation (6003), prompt_injection (Detection Finding 2004),
data_exfiltration (2004), permission_escalation (2004),
compliance_violation (Compliance Finding 2003), guardrail (2004), and
cost_anomaly (2004). Control-plane agent and delegation lifecycle uses
the proposed OCSF Category 9 (issue #1640). Each event carries an
OpenTelemetry trace_id and span_id, so multi-step agent activity
reconstructs end-to-end.

### Tier 2 — actually deployable

Signed `.pkg` for macOS (Jamf-ready), MSI for Windows (Intune-ready),
`.deb` and `.rpm` for Linux (with a hardened systemd unit:
`ProtectSystem=strict`, `NoNewPrivileges=true`,
`MemoryDenyWriteExecute=true`). Homebrew tap. Scoop manifest. MDM
templates for Jamf, Intune, Kandji, and Fleet. A GitHub Action
(`agentdr-policy-gate`) that fails CI builds when AgentDR events
exceed a configurable severity.

### Tier 3 — every SIEM, not just two

Ten exporters: Splunk HEC, Datadog Logs, Elasticsearch _bulk with ECS
mapping, Google Chronicle UDM, Cortex XSIAM, Snowflake REST,
Microsoft Sentinel (HMAC-SHA256 signed), Wazuh JSONL, RFC 5424
syslog (UDP and TCP), and a generic OCSF webhook. Each runs in its
own tokio task with per-backend batching and exponential-backoff
retries; they share a single broadcast bus from the engine so a slow
backend can't starve a fast one.

### Tier 4 — UEBA for agents

Most behavioural-analytics products baseline humans. AgentDR baselines
the *agent acting on behalf of* the human — rolling per-(host, user,
agent) statistics on five behavioural metrics: tokens/hour, files-
touched/hour, MCP tool diversity, off-hours share, and API call rate.
Each event gets scored against the matching baseline with a z-score, so
anomalies attributable to a specific runtime surface even when the
human owner's overall activity looks normal. The dashboard exposes the
outliers, and the session view reconstructs the kill chain across hosts
by trace_id.

### Tier 5 — governance, not just visibility

This is the line between an observability tool and an EDR. AgentDR
ships a **policy-as-code** engine: Sigma/Falco-shaped YAML that loads
at startup, runs against every event the engine sees, and emits OCSF
Compliance Finding events (class 2003, `ai_operation=compliance_violation`)
on matches. The same engine
backs an inline blocking **HTTP CONNECT proxy** that sits on a loopback
port. Configure your coding agents to use it as `HTTPS_PROXY`, declare a
policy like:

```yaml
- id: AGENTDR-POL-001
  name: "Block agent reads of AWS credentials"
  action: block
  when:
    all:
      - field: event_type
        eq: file_read
      - field: details.path
        regex: "\\.aws/credentials"
```

…and the next time *any* agent egress matches, the proxy returns 403,
the event ships with `class_uid=2003` (`ai_operation=compliance_violation`)
and `status_id=BLOCKED`, and your SOC sees the policy ID and the source
event in one record. We also detect OpenTelemetry `gen_ai.approval.*`
attributes and emit permission-escalation findings (Detection Finding
2004, `ai_operation=permission_escalation`) whenever a human approves or
denies an in-agent tool call.

### Tier 6 — the things everyone else skips

* **Linux NETLINK_AUDIT** kernel telemetry, native. No eBPF compile
  step. The systemd unit ships with the right capability bracket.
* **macOS and Windows kernel** posture documented — EndpointSecurity
  sidecar and ETW provider integration, with a fallback path that
  consumes those events through the syslog exporter.
* **Shell / TTY capture** via `adr-agent shell wrap` — every agent
  shell-exec becomes an API Activity 6003 event
  (`ai_operation=tool_execution`) with stdin asymmetry
  (input=medium risk; output=low).
* **Browser CDP attach** for Chrome / Edge running with
  `--remote-debugging-port=9222` — captures every page open,
  navigation and close from browser-use agents (Computer Use,
  Operator, Stagehand, Browser Use).
* **Credential-use attribution** — every credential file event is now
  enriched with a 10-minute window of active agent processes, so the
  AITF-DET-018 alert says "Claude Code (pid 12345, user david, started
  47s ago)" instead of just "credentials were read."

## What it looks like at the keyboard

A Claude Code session that drifts into a credential read produces, in
order:

1. `gen_ai.inference` (API Activity 6003, ai_operation=inference) when
   the model is consulted
2. `gen_ai.tool` (6003, tool_execution) when Claude calls its `shell`
   tool
3. `shell_input` and `shell_stdout` (6003, tool_execution) from
   `adr-agent shell wrap`
4. `file_read` from the file monitor
5. `alert_credential_access` (Detection Finding 2004, data_exfiltration)
   from the detector — *with* the list of candidate agent processes
6. `proxy_block` (Compliance Finding 2003, compliance_violation) when
   Claude's next request to `api.openai.com` hits an allow-list-deny rule

All six events share a trace_id, all six show up in the Sessions view,
all six ship to your SIEM with the right OCSF shape, all six count
toward Claude's UEBA baseline for tomorrow.

That's the difference between *seeing* and *responding*.

## What we owe the standards

AgentDR is the reference implementation of the [CoSAI AI Telemetry
Framework](https://github.com/girdav01/aitf). Every event reuses a
standard OCSF class enriched with an AITF `ai_operation` profile — we
follow OCSF's own principle of reusing classes rather than minting
bespoke AI event classes; control-plane agent and delegation lifecycle
uses the proposed OCSF Category 9 (issue #1640). Every detection carries
an OWASP LLM Top-10 mapping and a NIST AI-RMF reference. We didn't invent
a schema. We followed the open ones, because operators who deploy us
today shouldn't have to re-parse their telemetry the next time the
industry consolidates.

If you're working on OCSF, MITRE ATLAS, OWASP LLM Top-10, or
OpenTelemetry `gen_ai`, we'd like your review.

## What's next

We ship today with:

* the Rust agent, three OSes, signed packages, ten exporters
* the Next.js dashboard with sessions, kill-chain replay, and UEBA
  baselining
* an opinionated default policy pack
* test plans and 25-minute live demos for every platform (see
  `docs/test-plans/`)
* the GitHub Action for CI gating

What's next on the roadmap:

* eBPF coverage on Linux for syscall-level tool execution
* an EndpointSecurity sidecar (Developer ID signed)
* an OTLP/gRPC ingest path
* a CEL backend for policies (in addition to the YAML matcher)
* signed snapshots of the rule pack with a public transparency log

## Coda

The AI security industry is going to spend the next 18 months catching
up to the threat model that local coding agents make obvious every day.
Some of that catch-up will look like marketing diagrams; some of it will
look like vendors retrofitting their existing EDRs with an "AI module"
that bolts onto a kernel collector.

Some of it should look like open-source software, built on open
standards, that anyone can read, fork, harden, deploy, and not have to
re-parse three years from now. That's what AgentDR is trying to be.

If that resonates, we'd love your help.

— *the AgentDR contributors*

---

**Get started:** [`docs/test-plans/`](../test-plans/) ·
**Source:** github.com/girdav01/agentdr ·
**Standards:** [CoSAI AITF](https://github.com/girdav01/aitf), OCSF
(Class-Reuse Model + `ai_operation` profile), OpenTelemetry `gen_ai.*`.
