# DEF CON 34 — AI Village (August 2026)

> **Title:** *Beyond the Gateway: Endpoint Detection & Response for the
> Agents on Your Endpoints*
> **Speaker(s):** AgentDR / CoSAI contributors
> **Track:** AI Village main stage
> **Format:** 40-minute talk + 5-minute Q&A
> **Slides:** Markdown-driven, renders with Marp / Slidev / reveal.js.
> Use `---` as slide separator. Speaker notes follow each slide under
> `note:`.

## Abstract (for the CFP)

Local AI agents — Claude Code, Cursor, Codex, OpenClaw, Computer Use,
Browser Use — have moved the security boundary on the developer
endpoint. Existing EDRs see processes and connections. Gateways see
prompts and completions. Neither sees *which model called which tool
against which file with which approval*. We'll show how to fill that
gap with open source: a Rust endpoint agent that captures OpenTelemetry
`gen_ai.*` signals, inventories and proxies MCP traffic, applies
inline policy-as-code, and emits CoSAI AITF events (standard OCSF
classes + an `ai_operation` profile) to ten SIEM backends. Live demos on macOS and Linux include a credential-read
that names the agent that did it and a 403 from an inline blocking
proxy when a coding agent reaches for a non-allow-listed AI provider.

## Pre-talk checklist (T-24h)

- [ ] Two laptops staged: macOS (primary), Linux VM (secondary for kernel demo)
- [ ] Both agents running `adr-agent --version` → 0.2.0
- [ ] Demo root cleaned (`rm -rf ~/agentdr-demo`)
- [ ] Hotspot tested; venue Wi-Fi backup
- [ ] OBS scenes set: terminal-only, terminal+dashboard split, slides
- [ ] Pre-load three browser tabs:
  * `localhost:3000/dashboard`
  * `localhost:3000/sessions`
  * `localhost:3000/ueba`
- [ ] Pre-fire one OTLP event so the dashboard isn't empty on first cut
- [ ] Have the [macOS test plan](../test-plans/macos.md) open on the
      confidence monitor
- [ ] CTF flag file ready (Tier 5 demo)

---

# Slides

---

## Title

```
Beyond the Gateway
Endpoint Detection & Response for the Agents on Your Endpoints

AgentDR / CoSAI — DEF CON AI Village 2026
```

note:
Open by reading the title slowly. Pause. *"This talk is about an
assumption that quietly stopped being true in the last 18 months —
that the user running on your endpoint is a human."*

---

## The thesis (one slide)

```
The user on your endpoint is not a human any more.

  Claude Code · Cursor · Codex CLI · Aider · OpenClaw
  Computer Use · Operator · Browser Use · Devin

Every endpoint security assumption built into the last 15 years
is built around "an active process is a deliberate human action."

That assumption is wrong now.
```

note:
*"This is the only slide that matters. If you remember nothing else,
remember this. Every existing tool is calibrated to the old assumption.
Some of them are starting to bolt on AI modules. We're going to spend
the next 38 minutes on what happens if you start from scratch with the
new assumption."*

---

## What an agent endpoint actually looks like

```
14:22:08  claude-code      open() ~/repo/src/auth.py
14:22:08  claude-code      POST api.anthropic.com (1240 tokens)
14:22:11  claude-code      tools/call: shell — "git status"
14:22:11  claude-code      tools/call: shell — "rg -n 'TODO'"
14:22:12  claude-code      tools/call: read_file ~/repo/src/auth.py
14:22:15  claude-code      open() ~/.aws/credentials              ← uh
14:22:16  claude-code      tools/call: shell — "curl -F file=@... slack.com"
14:22:17  user             approval = "allow"                     ← uh oh
```

note:
Walk through line by line. *"Existing EDR sees node.exe doing
syscalls. Gateway sees a prompt and a completion. Nobody sees which
model called which tool against which file with which approval. That's
the gap."*

---

## What it looks like to the SOC today

```
process_started: node.exe pid=14322
process_started: node.exe pid=14401
process_started: node.exe pid=14802
network: 192.168.1.42 → 104.18.36.x:443
network: 192.168.1.42 → 13.107.42.x:443
file_modified: /home/u/repo/src/auth.py
file_modified: /home/u/repo/src/auth.py
file_modified: /home/u/repo/src/auth.py
file_read: /home/u/.aws/credentials             ← buried in the noise
```

note:
*"Same incident. This is what the SOC analyst sees on the existing
EDR. The credential read is in there — but reconstructing what touched
it, when, and why is forensics work that takes hours."*

---

## Two camps, one gap

```
   ┌─────────────────────┐     ┌─────────────────────┐
   │  AI security 1.0    │     │   Endpoint 1.0      │
   │                     │     │                     │
   │  Prompt firewalls   │     │  CrowdStrike        │
   │  Inference gateways │     │  SentinelOne        │
   │  Model guardrails   │     │  Defender for E.    │
   └─────────────────────┘     └─────────────────────┘
              │                          │
              ▼                          ▼
   What the model said          What the process did
              │                          │
              └────────┬─────────────────┘
                       ▼
        ✗ Who the subject is when an agent acts
        ✗ Which tool it called against which file
        ✗ Which approval was granted, by whom
        ✗ Which MCP server it just installed
```

note:
*"Two camps, one gap right in the middle. This talk is about the open
source software that fills the gap."*

---

## The first OSS wave (early 2026)

```
  A growing set of open-source AI-telemetry collectors

  ✓  Validated the category
  ✓  Open-sourced the framing
  ✓  OTLP-based collectors targeting one OS (usually macOS)

  ✗  Visibility only — no inline enforcement
  ✗  Single platform
  ✗  1–2 destinations (typically Splunk HEC + a JSON file sink)
  ✗  Custom JSON shapes (not OCSF / AITF)
  ✗  Explicit non-goals: MCP capture, kernel, browser,
     credential attribution, …
```

note:
*"Credit where it's due — this OSS wave named the gap and proved the
category. We share two of their three primitives. What we're going to
show is what happens when you go six steps further."*

---

## AgentDR — what we built

```
┌──────────────────────────────────────────────────────────────────┐
│  Rust endpoint agent           ·   Next.js analyst dashboard      │
│                                                                   │
│  Tier 1  OTLP + MCP capture + runtime hooks                       │
│  Tier 2  Signed pkgs for macOS / Linux / Windows + MDM templates  │
│  Tier 3  10 SIEM exporters (Splunk → Datadog → Sentinel → Wazuh)  │
│  Tier 4  UEBA baselines per-(host, user, agent) + kill-chain UI   │
│  Tier 5  Inline blocking proxy + YAML policy-as-code              │
│  Tier 6  Kernel telemetry + shell capture + browser CDP +         │
│          credential attribution                                   │
│                                                                   │
│  Apache 2.0 · CoSAI AITF reference impl · github.com/girdav01/agentdr │
└──────────────────────────────────────────────────────────────────┘
```

note:
*"Six tiers. Every tier is opt-in. We're going to demo Tiers 1, 5 and 6
live; the rest will appear in supporting slides. Let me drop into a
terminal."*

---

## Live demo segment A — Tier 1: capture (5 min)

**Action:** Switch to terminal. Run `macos.md` steps T1.1 → T1.3.

**Beats to hit:**

1. `adr-agent hooks install all` — one command wires Claude Code,
   Cursor, Codex, Aider. *"This is OpenTelemetry hooks installed in
   the agents themselves. We don't sniff the network. We capture
   semantically."*
2. Show the resulting `~/.claude/settings.json` — *"AgentDR-managed
   keys, marker block, reversible with `hooks uninstall`."*
3. Fire the OTel curl. Show the JSONL line — *"API Activity 6003 with
   ai_operation=inference for the inference, 6003 / tool_execution for
   the tool call, trace_id propagated."*
4. `adr-agent mcp inventory --jsonl` — *"Most comparable OSS efforts
   list MCP inventory as an explicit non-goal. Here it is across eight
   known config locations."*

note:
Keep this demo TIGHT. 5 minutes max. The audience needs to see one
command produce one named result. Don't deep-dive the JSON.

---

## Wire format — why we picked AITF OCSF Class-Reuse

```
{
  "timestamp":    "2026-08-08T17:22:08.421Z",
  "event_type":   "gen_ai.tool",
  "class_uid":    6003,            ← OCSF API Activity (reused)
  "ai_operation": "tool_execution",← AITF profile semantic
  "type_uid":     600305,          ← class * 100 + activity
  "activity_id":  5,               ← Execute
  "severity_id":  3,
  "provider":     "anthropic",
  "model":        "claude-sonnet-4-5",
  "tool_name":    "read_file",
  "trace_id":     "9b7f0c8d2e1a4f5b6c7d8e9f0a1b2c3d",
  "actor":        {"user":"david","host":"laptop-david"},
  "compliance":   {"frameworks":["OWASP-LLM-Top10","NIST-AI-RMF"]}
}
```

note:
*"AITF dropped its bespoke Category 7 — every event now reuses a
standard OCSF class (here, API Activity 6003) enriched with an
`ai_operation` profile. Same principle OCSF itself follows: reuse
classes, don't mint new ones per domain. Same shape your other AI-aware
tools will speak in two years. We didn't invent a schema — we're the
reference implementation of one Cisco, Google, IBM and NVIDIA all
signed up to."*

---

## Live demo segment B — Tier 5: govern (8 min)

**Action:** Run `macos.md` steps T5.1 → T5.5.

**Beats to hit:**

1. `adr-agent policy list` → "8 rules loaded from
   cosai-community/policies/policies.yaml."
2. `adr-agent policy test` on a synthetic AWS-credentials file_read.
   Show the JSON output: *"action: block, matched POL-001."*
3. Open the YAML file. *"This is Sigma-shaped. Operators familiar with
   Falco rules will read it on first try."*
4. Start the inline proxy:
   `adr-agent proxy --bind 127.0.0.1:18080 --allow anthropic.com`
5. With `HTTPS_PROXY` set, `curl https://api.openai.com` — show the
   403 in real time, then tail the JSONL to show the Compliance Finding
   (`class_uid=2003`, `ai_operation=compliance_violation`),
   `status_id=3` Block event.
6. With the same proxy, `curl https://api.anthropic.com` — show 200,
   then the `class_uid=6003` (`ai_operation=inference`) `proxy_allow`
   event.
7. Fire the OTel `gen_ai.approval.decision=deny` span. Show the
   Detection Finding (`class_uid=2004`,
   `ai_operation=permission_escalation`) event. *"Comparable collectors
   don't capture approvals at all. We map them straight to a
   permission-escalation finding."*

note:
This is the headline demo. Make sure the proxy logs are scrolling on a
second pane so the block event lands at the exact moment the 403 hits
curl. The audience should see both at once. **If the demo gods are
kind, this is the moment of the talk.**

---

## Policy-as-code (one slide)

```yaml
- id:       AGENTDR-POL-001
  name:     "Block agent reads of AWS credentials"
  severity: critical
  action:   block
  reason:   "Coding agents must not read ~/.aws/credentials"
  compliance: ["OWASP-LLM-Top10:LLM06", "NIST-AI-RMF:GOVERN-1.5"]
  when:
    all:
      - field: event_type
        eq: file_read
      - field: details.path
        regex: "\\.aws/credentials|\\.aws/config"
```

note:
*"YAML, not CEL, not Rego. We tried, the matcher is 150 lines, four
unit tests, and operators ship a PR-shaped policy bundle. Same engine
backs the inline blocking proxy. Same engine fires Compliance Finding
(class_uid 2003, ai_operation=compliance_violation) events into your
SIEM."*

---

## Live demo segment C — Tier 6: things others skip (6 min)

**Action:** Switch to the Linux VM. Run `linux.md` steps T6.1, T6.2,
T6.5.

**Beats to hit:**

1. `journalctl -u agentdr | grep NETLINK_AUDIT` →
   `subscribed to NETLINK_AUDIT multicast`. *"No eBPF compile, no
   kernel module install, no daemon dependency. This is plain Linux
   audit on a multicast netlink group."*
2. `auditctl -w /tmp/secret -p rwa`, then write to it. Show the
   `kernel_audit` event appearing in JSONL within a second.
3. Trigger the credential read on macOS (back to laptop one). Show
   the AITF-DET-018 alert with the `candidate_agents` array — pid,
   agent name, framework, user, exe, age_seconds. *"Most AI-telemetry
   tools stop at 'a credential file was read.' We tell the analyst
   **who**."*

note:
This is where you sell the "open source + cross-platform" angle.
*"All of this — every byte you've seen — is Apache 2.0, on GitHub,
running today. No vendor account required."*

---

## What the dashboard sees

(Show the dashboard `/sessions/<traceId>` page live.)

```
Session deadbeefcafef00d
─────────────────────────
Kill-chain phases: agent_launch(1) · inference(2) · tool_exec(4) · data_access(1) · privilege_change(1)
Hosts: laptop-david · ci-runner-7
Users: david
Agents: claude-code

Timeline:
  14:22:08 [9001] process_started   claude-code (low)
  14:22:08 [6003] gen_ai.inference  anthropic/claude-sonnet-4-5 (low)
  14:22:11 [6003] gen_ai.tool       shell — "git status" (medium)
  14:22:15 [2004] alert_credential_access  candidates=[claude-code pid=14322 user=david] (critical)
  14:22:16 [2003] policy_block      AGENTDR-POL-001 (critical, BLOCKED)
```

note:
*"That's the agent-shaped kill chain. Six events, one trace_id, one
incident. The session view reconstructs across hosts; the UEBA view
scores every event against the per-agent baseline."*

---

## UEBA for agents

```
metric: tokens_per_hour

  host           user    agent          n   μ      σ      p95
  ──────────────────────────────────────────────────────────────
  laptop-david   david   claude-code   336  2 871   1 240  6 414
  laptop-david   david   cursor         92    487     156    822
  ci-runner-7    ci      claude-code  1842    301     104    498

Observed event:  tokens=14 880 (z=9.7)   ← outlier
```

note:
*"Most behavioural-analytics products baseline humans. We baseline the
agent that ran on behalf of the human — per-(host, user, agent) rolling
baselines, a z-score on every event. Outliers surface in Sessions and
stream into your SIEM as-is."*

---

## How it actually deploys

```
Endpoint                          Where the data goes
──────────────────────────────────────────────────────────────
  macOS  → signed .pkg  + LaunchDaemon         Splunk HEC
  Linux  → .deb / .rpm  + systemd (hardened)   Datadog Logs
  Windows → signed .msi + Windows service      Elastic _bulk
                                               Google Chronicle UDM
  + Homebrew tap                               Cortex XSIAM
  + Scoop manifest                             Snowflake REST
  + MDM templates: Jamf, Intune, Kandji, Fleet Microsoft Sentinel (HMAC)
  + GitHub Action: agentdr-policy-gate         Wazuh JSONL
                                               RFC 5424 syslog
                                               Generic OCSF webhook
```

note:
*"Sits alongside your existing EDR. <40 MB resident. Apache 2.0. No
SaaS dependency. Ten exporters. Three OSes. MDM-ready. CI-ready."*

---

## A note on threat modelling

```
Things that ARE in scope:
  • Coding agents (Claude Code, Cursor, Codex, Aider, ...)
  • Browser-use agents (Computer Use, Operator, Browser Use, ...)
  • Autonomous agents (OpenClaw, AutoGPT, BabyAGI, ...)
  • Enterprise copilots (M365, ServiceNow, SAP Joule, ...)
  • MCP servers (catalogued + proxied)
  • Approval flows (gen_ai.approval.* semconv)

Things explicitly OUT of scope:
  • Replacing your EDR (we run alongside)
  • Prompt-firewalling (we observe; gateway products block)
  • Adversarial prompt-injection detection (we emit, you correlate)
  • Model-evals / red-team scoring (separate workflow)
```

note:
*"AgentDR is the **D&R** layer. We don't try to be a gateway. We don't
try to be a kernel EDR. We don't try to be a model evaluator. We do
agent-aware endpoint capture and response, and we hand off the rest to
tools that already do it well."*

---

## Standards

```
CoSAI AITF                        — AI Telemetry Framework (reference impl)
AITF OCSF Class-Reuse             — reuses standard OCSF classes + ai_operation profile
OpenTelemetry gen_ai.* semconv    — collector + hook installer + Otel mapping
OWASP LLM Top-10                  — on every event under compliance.mappings
NIST AI RMF                       — on every event under compliance.frameworks
```

note:
*"If you're in OWASP, OCSF, CoSAI, MITRE ATLAS — we'd like your review.
We don't want to be a snowflake; we want to be the canonical Linux
collector for the AI-activity category."*

---

## What you can do today

```
1.  Try it (5 min):       brew install agentdr && adr-agent hooks install all
2.  Read the spec:        github.com/girdav01/aitf
3.  Run the policy gate:  uses: girdav01/agentdr/.github/actions/agentdr-policy-gate
4.  Bring a signature:    cosai-community/rules/agent-signatures.json
5.  Bring a policy:       cosai-community/policies/policies.yaml
6.  Bring an exporter:    src/exporters/<your-siem>.rs
7.  Bring a hook:         src/hooks/<your-agent>.rs
```

note:
*"This is meant to be community software. If your favourite agent isn't
in the signatures list, a PR is two strings. If your favourite SIEM
isn't in the exporters, the trait is six methods. Show up."*

---

## Q&A

```
github.com/girdav01/agentdr

@girdav01
#cosai-aitf
```

note:
Take questions. Stretch goals if there's time:
* CTF: throw an OpenClaw container at a deliberately-permissive
  AgentDR config and watch what it does.
* Live edit: write a new YAML policy on-stage and re-run the demo.

---

# Appendices

## A. Demo failure handlers

| If… | Then… |
|-----|------|
| OTLP curl fails | switch to the second laptop's prerecorded JSONL tail |
| Proxy 403 doesn't fire | swap to `adr-agent policy test` instead — same point, no network |
| Dashboard tab times out | screenshot fallback is in `slides/fallback/` |
| Linux VM unreachable | use the prerecorded asciinema cast in `slides/asciinema/linux-kernel.cast` |

## B. Length variants

* 20-minute version: cut Tier 1 to 2 minutes (one OTLP curl), drop the
  dashboard tour, keep Tier 5 + Tier 6.
* 45-minute version: add a live `policy edit → re-run` segment after
  Tier 5; add a 5-minute live audience CTF.
* 60-minute version: append the CoSAI AITF spec walkthrough as a
  second half.

## C. Speaker bios

> *Bio template:* "X has been working on endpoint security and AI
> infrastructure since YYYY. X contributes to the CoSAI AI Telemetry
> Framework and maintains AgentDR, the Apache-2.0 reference
> implementation. Previously: ZZZ."

## D. Useful one-liners during Q&A

* *"A whole OSS wave validated the category last spring. AgentDR is
  the next step — visibility plus governance, on standards,
  cross-platform."*
* *"No, we don't replace CrowdStrike. We run alongside it. Different
  layer."*
* *"Yes, the same engine backs the SIEM exporters and the inline
  proxy. That's the whole point — one event model, two consumers."*
* *"Standard OCSF classes plus an AITF ai_operation profile is the only
  schema that's going to matter in 2027. Why pay parsing tax twice?"*

## E. References

* [CoSAI AI Telemetry Framework](https://github.com/girdav01/aitf)
* [OCSF — Open Cybersecurity Schema Framework](https://schema.ocsf.io)
* [OpenTelemetry — gen_ai semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
* [OWASP LLM Top-10 (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
* [NIST AI Risk Management Framework 1.0](https://www.nist.gov/itl/ai-risk-management-framework)
* Other OSS endpoint AI-telemetry projects — search GitHub for
  `topic:ai-agent topic:telemetry license:mit` (an active and growing
  space we draw threat-model motivation from).
