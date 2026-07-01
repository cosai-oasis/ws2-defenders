# Why AITF? — Attack Detection Demo

**Traditional monitoring is blind to AI-specific threats.**

This demo simulates 7 real-world attack scenarios against AI/LLM systems and shows, side by side, what traditional infrastructure monitoring sees versus what AITF telemetry reveals. In every case, the attack succeeds silently under conventional observability — but is caught by AITF.

## The Problem

Standard APM and infrastructure monitoring tools track HTTP status codes, latency, CPU, memory, and error rates. They were designed for web services, not AI systems. When an attacker:

- Injects a prompt to exfiltrate data → **HTTP 200 OK**, latency normal
- Poisons a RAG knowledge base → **HTTP 200 OK**, latency normal
- Hijacks an agent to delegate to a rogue peer → **HTTP 200 OK**, latency normal
- Swaps a model for a backdoored version → **HTTP 200 OK**, latency normal

Traditional monitoring sees a perfectly healthy system. No alerts fire. No dashboards turn red. The attack succeeds in complete silence.

**AITF changes this** by instrumenting the AI-specific semantics — prompts, token flows, agent reasoning chains, tool permissions, RAG retrieval provenance, model supply chain hashes, and cross-agent delegation — and emitting structured telemetry (OCSF events under reused classes enriched with the `ai_operation` profile, plus the proposed `ai` category (uid 9) for agent/delegation lifecycle) that security tools can reason about.

## Attack Scenarios

| # | Attack | MITRE ATLAS | OWASP LLM | Traditional Monitoring | AITF Detection |
|---|--------|-------------|-----------|----------------------|----------------|
| 1 | **Indirect Prompt Injection via RAG** | [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) | LLM01 | HTTP 200, normal latency | System prompt hash change + injection pattern in `rag.doc.provenance` |
| 2 | **Slow Data Exfiltration via Tool Chaining** | [AML.T0024](https://atlas.mitre.org/techniques/AML.T0024) | LLM06 | HTTP 200, API calls look normal | Cross-tool read→send correlation in `mcp.tool.*` spans with PII accumulation tracking |
| 3 | **Agent Infinite Loop / Resource Exhaustion** | [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) | LLM06 | CPU spike (but why?) | Cyclic pattern in `agent.step.action` sequence with `agent.state` stuck in `"executing"` |
| 4 | **Model Supply Chain Swap** | [AML.T0010](https://atlas.mitre.org/techniques/AML.T0010) | LLM03 | HTTP 200, same endpoint | `supply_chain.model.hash` mismatch against baseline, unsigned model detected |
| 5 | **Multi-Turn Jailbreak Escalation** | [AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) | LLM01 | Each request HTTP 200 | Accumulating `security.threat_type` events with escalating `security.risk_score` across session |
| 6 | **Unauthorized Agent Delegation (Privilege Escalation)** | [AML.T0050](https://atlas.mitre.org/techniques/AML.T0050) | LLM06 | Inter-service calls look normal | `agent.delegation.target_agent` not in team roster + `identity.authz.decision=deny` bypass |
| 7 | **RAG Poisoning via Document Injection** | [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) | LLM08 | Document ingestion API 200 OK | `rag.doc.provenance` from untrusted source + `rag.quality.faithfulness` score drop + `memory.security.poisoning_score` anomaly |

## Running the Demo

```bash
# From the repo root
cd examples/attack-detection-demo

# Run all 7 scenarios
python attack_scenarios.py

# Run a specific scenario
python attack_scenarios.py --scenario 3

# Export OCSF events for SIEM ingestion
python attack_scenarios.py --output attacks_ocsf.jsonl

# Verbose mode — show full telemetry diff
python attack_scenarios.py --verbose
```

## Output Format

For each scenario, the demo prints:

```
╔══════════════════════════════════════════════════════════════════════╗
║  SCENARIO 1: Indirect Prompt Injection via RAG                     ║
║  MITRE ATLAS: AML.T0051.001 | OWASP: LLM01                       ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  TRADITIONAL MONITORING:                                           ║
║  ┌──────────────────────────────────────────────────────────────┐  ║
║  │ HTTP Status:  200 OK                                        │  ║
║  │ Latency:      342ms (within P99)                            │  ║
║  │ Error Rate:   0%                                            │  ║
║  │ CPU/Memory:   Normal                                        │  ║
║  │ Verdict:      ✅ ALL HEALTHY — No alerts                    │  ║
║  └──────────────────────────────────────────────────────────────┘  ║
║                                                                    ║
║  AITF TELEMETRY:                                                   ║
║  ┌──────────────────────────────────────────────────────────────┐  ║
║  │ ⚠ gen_ai.system_prompt.hash CHANGED (prev: sha256:a1b2...)  │  ║
║  │ ⚠ rag.doc.provenance: "https://evil.com/payload.md"        │  ║
║  │ ⚠ rag.doc.score: 0.91 (adversarial high-relevance)         │  ║
║  │ ⚠ security.threat_type: "prompt_injection"                  │  ║
║  │ ⚠ security.detection_method: "pattern"                      │  ║
║  │ ⚠ security.owasp_category: "LLM01"                         │  ║
║  │ Verdict:      🚨 ATTACK DETECTED — 3 findings               │  ║
║  └──────────────────────────────────────────────────────────────┘  ║
║                                                                    ║
║  WHY TRADITIONAL MONITORING MISSED IT:                             ║
║  The RAG pipeline returned documents normally, the LLM generated   ║
║  a valid response, and the HTTP layer saw only success. The        ║
║  injected instruction was embedded inside a retrieved document     ║
║  that scored 0.91 relevance — high enough to influence the model   ║
║  but invisible to network-level monitoring. Only AITF's per-       ║
║  document provenance tracking and prompt hash monitoring could     ║
║  detect the content-level manipulation.                            ║
╚══════════════════════════════════════════════════════════════════════╝
```

## Architecture

```
                    ┌─────────────────┐
                    │   Attack Sim    │  ← Simulates malicious actions
                    └────────┬────────┘
                             │
                   ┌─────────▼─────────┐
                   │   AITF SDK        │  ← Instruments AI semantics
                   │  (Python SDK)     │
                   └─────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼───┐  ┌──────▼─────┐ ┌──────▼──────┐
     │  Security  │  │    PII     │ │ Compliance  │
     │ Processor  │  │ Processor  │ │  Processor  │
     └────────┬───┘  └──────┬─────┘ └──────┬──────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                   ┌─────────▼─────────┐
                   │  Detection Rules  │  ← 14 rules evaluate spans
                   │  (Real-Time)      │
                   └─────────┬─────────┘
                             │
                   ┌─────────▼─────────┐
                   │  OCSF Exporter    │  ← Structured events for SIEM
                   └───────────────────┘
```

## Key Takeaway

> **Without AI-specific telemetry, your SOC is flying blind.** Every one of these attacks produces HTTP 200 responses, normal latency, and zero infrastructure errors. Traditional APM, WAFs, and network monitoring cannot distinguish a jailbroken LLM from a normally-functioning one. AITF provides the semantic layer that makes AI threats observable, detectable, and actionable.

## Files

| File | Description |
|------|-------------|
| `attack_scenarios.py` | Main demo script — runs all 7 scenarios |
| `README.md` | This file |

## References

- [MITRE ATLAS](https://atlas.mitre.org/) — Adversarial Threat Landscape for AI Systems
- [OWASP LLM Top 10](https://genai.owasp.org/) — Top 10 for LLM Applications
- [CoSAI WS2](https://www.cosai.dev/) — Coalition for Secure AI
- [OCSF AI Activity Events](https://schema.ocsf.io/) — reused classes (API Activity 6003, Datastore Activity 6005, Findings 2002/2003/2004, Authentication 3002, Inventory Info 5001) + `ai_operation` profile, plus proposed `ai` category (uid 9)
