# AgentDR Marketing Plan — 2026

> **One-sentence pitch:** AgentDR is the open-source endpoint detection &
> response platform built for the era when the user running on your
> endpoint is an AI agent — not a human.

## 1. Market context (mid-2026)

* Local coding agents (Claude Code, Cursor, Codex CLI, Aider, Windsurf,
  Cline) have crossed the chasm into mainstream developer use.
  Enterprises now ask **the same governance questions** they asked about
  laptops in 2010: who has them, what do they do, can we block what we
  don't want?
* The first wave of OSS efforts in this space framed the problem as
  *visibility* — a telemetry collector for one platform, shipping to
  one or two SIEMs. The next wave will be defined by *governance +
  response* — the "R" in EDR. AgentDR ships both today.
* Standards momentum: CoSAI AITF, OCSF, and OTel `gen_ai.*`
  semantic conventions all converged in early 2026. AITF now reuses
  standard OCSF classes enriched with an `ai_operation` profile. We are
  the reference implementation of all three on the endpoint side.

## 2. Positioning

|                       | **AgentDR (CoSAI)**                          | Other OSS AI-telemetry collectors          | Commercial EDRs (CrowdStrike, SentinelOne) |
|-----------------------|----------------------------------------------|--------------------------------------------|--------------------------------------------|
| License               | Apache-2.0                                   | MIT / Apache-2.0 (varies)                  | Closed                                     |
| Platforms             | macOS / Linux / Windows                      | typically single-OS (often macOS)          | All                                        |
| AI-aware              | First-class (standard OCSF classes + ai_operation profile, 20 rules)| First-class                                | Bolt-on (mid-2026)                         |
| Telemetry path        | OTLP hooks + MCP capture + kernel + browser  | OTLP collector only                        | Kernel-only                                |
| Destinations          | 10 SIEM/observability exporters              | usually 1–2 (Splunk/Wazuh-style)           | Vendor's own backend                       |
| Governance / blocking | Inline proxy + policy-as-code                | None                                       | Limited                                    |
| UEBA for agents       | Per-(host, user, agent) baselines            | None                                       | Human-only UEBA                            |
| Standards alignment   | CoSAI AITF, OCSF, OWASP-LLM, NIST AI-RMF     | Custom JSON shapes                         | None                                       |

**Tagline candidates:**

1. *"AgentDR — endpoint detection & response for the agents on your endpoints."*
2. *"Observe, govern, and respond to AI agent activity. Open source."*
3. *"Beyond visibility: agentic endpoint defense, on standards."*

Use #1 in technical channels; #2 for buyer/CISO audiences; #3 in
side-by-side comparisons against other OSS efforts in the same space.

## 3. Personas

### P1 — Platform Security Engineer ("Priya")
* Owns the dev-tools security posture for an org with 500–5000
  engineers.
* Cares about: rolling out coding agents safely, getting them through
  AppSec review, demonstrating board-ready risk metrics.
* Top objections: "we already have CrowdStrike", "another agent on
  every endpoint?"
* Counter: AgentDR runs *next to* the existing EDR — same data, AI-aware
  shape; no kernel module conflict; <40 MB resident.

### P2 — SOC Lead / Detection Engineer ("Marcus")
* Owns SIEM content and incident response.
* Cares about: getting standardised telemetry he can write rules
  against; baseline detection content; sub-minute MTTD on AI-specific
  incidents.
* Top objections: "Splunk already costs us a fortune", "yet another
  schema to learn".
* Counter: standard OCSF classes plus the AITF `ai_operation` profile is
  the schema all his other AI-aware tooling will speak by 2027. AgentDR
  is the cheapest way to start producing AITF-shaped OCSF events today.

### P3 — CISO / VP Security ("Janet")
* Buyer / approver, board-facing.
* Cares about: defensible AI policy, board-ready metrics on AI risk,
  audit narrative.
* Top objections: "is this serious or a project?"
* Counter: built on CoSAI (Google + IBM + NVIDIA + Cisco + ...), Apache
  2.0, multi-deployment-vendor support; we're a reference
  implementation of a Cisco-backed standard.

### P4 — AI Platform Team ("Alex")
* Builds internal AI platforms / Agents As A Service.
* Cares about: not getting blamed for shadow agent usage, providing safe
  defaults to internal devs.
* Top objections: "I want this in our internal portal, not as a
  separate UI."
* Counter: every event ships to whatever observability backend Alex
  already uses. AgentDR is the collector + policy gate; he keeps
  ownership of the UX.

## 4. Key messages (use in this order)

1. **"AI agents are users now."** Frame the threat model.
2. **"Visibility is not enough."** Distinguish from telemetry-only
   collectors. Show the inline-block demo or a policy-violation event.
3. **"Built on open standards, on day one."** CoSAI AITF (standard OCSF
   classes + `ai_operation` profile), OpenTelemetry `gen_ai.*`. We
   didn't invent another schema.
4. **"Cross-platform, cross-SIEM, cross-agent."** macOS+Linux+Windows,
   10 exporters, 30+ agent signatures.
5. **"Own your data."** No SaaS lock-in. Loopback OTLP. Local-first.

## 5. Launch sequence (12-week plan)

| Week | Activity | Channel | Owner |
|------|----------|---------|-------|
| W-2  | Polish README + reference architecture diagram | repo | Eng |
| W-1  | Pre-brief 3 friendly journalists + 3 analyst contacts | DM | Marketing |
| W0   | Public launch post on Hacker News + LinkedIn | community | All-hands |
| W0   | Blog: *"Beyond visibility — the case for agentic EDR"* (see `blog/2026-launch-post.md`) | blog | Marketing |
| W1   | Reddit r/netsec + r/devops technical AMA | community | Eng founder |
| W2   | "5-minute setup" YouTube screencast (macOS + Linux) | YouTube | DevRel |
| W3   | Webinar w/ 1 design-partner enterprise: deployment story | webinar | Sales |
| W4   | OWASP LLM Top-10 working group: contribute mapping | standards | Eng |
| W5   | DEF CON AI Village CFP submission (see `presentations/`) | conference | Eng |
| W6   | Cisco / CoSAI co-marketing: "CoSAI AITF in production" | community | Eng + CoSAI |
| W8   | First major exporter case study (Splunk or Sentinel) | blog | Marketing |
| W10  | First-of-its-kind capture-the-flag at BSides (AgentDR-vs-rogue-agent CTF) | conference | DevRel |
| W12  | First public security advisory + responsible disclosure process | repo | Eng |

## 6. Content calendar — perennial themes

| Frequency | Theme | Examples |
|-----------|-------|----------|
| Weekly | "What did agents do this week?" — anonymised aggregate stats from opt-in telemetry | "OpenClaw usage up 40% WoW; 12% of installs trigger AITF-DET-018." |
| Bi-weekly | "Rule pack release notes" | New agent signature: Devin Slack integration. New policy: messaging-exfil-V2. |
| Monthly | Deep-dive technical post | "How we capture MCP traffic without an MITM CA." |
| Quarterly | "State of agentic endpoint security" report | Free PDF, gated by email; co-published with CoSAI. |
| Annually | DEF CON / Black Hat talk + AgentDR-vs-rogue-agent CTF | See `presentations/`. |

## 7. Distribution channels

* **GitHub** is the primary brand surface. Star count, contributor
  count, time-to-first-PR-merge are the marketing dashboard.
* **CoSAI co-marketing.** AgentDR is the reference impl. Every CoSAI
  AITF blog post should link to AgentDR, every AgentDR release should
  link to CoSAI.
* **Conferences:**
  - DEF CON AI Village (primary)
  - BSides (regional CTFs)
  - Black Hat USA arsenal (tool demo)
  - KubeCon Cloud Native AI day (OTel/OCSF angle)
  - SANS AI Summit
  - Gartner Security & Risk Management
* **Standards bodies:** OWASP LLM Top-10 working group, CoSAI AITF,
  OCSF AI Activity working group, MITRE ATLAS contribution.
* **Open-source ecosystem:** Splunkbase / Datadog Marketplace /
  Elastic Integrations contributions for each exporter, with the
  AgentDR-side credentials guide.

## 8. Differentiation framing

When someone asks **"how is this different from other OSS AI-telemetry
projects?"** use these three sentences, in this order:

1. *"Most of them make agent activity observable. AgentDR makes it
   observable **and** governable — the same broadcast bus drives the
   SIEM exporters and an inline HTTP CONNECT proxy with policy-as-code."*
2. *"Most of them support one platform and one or two destinations.
   AgentDR supports all three OSes and ten destinations on day one."*
3. *"Most of them ship their own JSON shape. AgentDR is the reference
   implementation of CoSAI AITF — standard OCSF classes (API Activity,
   Detection Finding, …) enriched with an `ai_operation` profile, the
   same schema your other AI-aware tools will speak by 2027."*

Never punch down at individual projects. Always frame the broader OSS
movement as having proven the category and AgentDR as taking the next
step.

## 9. Metrics / KPIs

| Layer | Metric | Target (90 days post-launch) |
|-------|--------|------------------------------|
| Awareness | GitHub stars | 1,500 |
| Awareness | Twitter / LinkedIn impressions on launch post | 200k |
| Adoption | Distinct CI runs reporting via the GH Action | 250 |
| Adoption | Distinct hostnames in opt-in usage ping | 2,000 |
| Adoption | Homebrew / Scoop install pulls | 5,000 |
| Community | External contributors | 25 |
| Community | New agent signatures contributed | 15 |
| Sales | Discovery calls scheduled from inbound | 40 |
| Sales | Design-partner closed-won | 3 |
| Standards | OCSF + AITF working-group participation | continuous |

## 10. Risk register

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Cloud-EDR vendor ships an AI module and FUDs us | High | Lean into open-source angle; show side-by-side deployment story |
| A peer OSS project adds paid enforcement | Medium | We have a head start on governance; keep widening the gap, stay Apache-2.0 |
| OCSF AI Activity category fragments | Medium | Co-author the next OCSF AI proposal so AgentDR shapes the schema |
| Agent vendors revoke OTLP hooks | Low | We capture via MCP and process telemetry as well; redundant paths |
| "Yet another agent" fatigue | Medium | <40 MB resident, no kernel module, clear "alongside CrowdStrike" story |

## 11. One-pagers — for sales

See `messaging.md` for the printable one-pagers (CISO, SOC, platform-team).

## 12. Visual identity

* **Logo:** the shield + waveform mark in `public/agentdr-logo.svg`
  (existing).
* **Color palette:** matches the dashboard (blue primary, OCSF class
  colors for accents).
* **Voice:** technical, opinionated, never breathless. We do not say
  "AI-powered" anywhere. We say "agent-aware" — it's about who the
  user is, not what tech we use.
