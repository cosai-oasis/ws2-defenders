# OCSF Issue — ready to post

**Title:**

```
[Proposal] Extend the ai_operation profile with inference, tool, and finding telemetry
```

---

**Body:**

### Summary

Following the `ai_agent` object + `ai_operation` profile in #1641 and the
`delegation` / control-plane work in #1640, I'd like to propose adding the
**substance of an AI operation** to the `ai_operation` profile: token usage,
cost, latency, request parameters, tool/MCP invocation, and AI-specific finding
context. These are **optional objects and profile attributes on existing
classes** — no new category, no new required fields.

Opening this as a discussion to agree on placement and naming before I submit
the schema PR.

### Gap

#1641 / #1640 capture *who* acted (`ai_agent`) and *under what authority*
(`delegation`), and route agent/delegation lifecycle into the `ai` category.
They do not yet capture what the operation consumed or did:

| Gap (not in OCSF today) | Why it matters |
|---|---|
| **Token usage** | quota/abuse detection, cost attribution |
| **Cost** | FinOps, runaway-spend / exfiltration-by-volume detection |
| **Latency** (TTFT, tokens/sec, queue time) | DoS / "Unbounded Consumption" (OWASP LLM10) detection, SLOs |
| **Request parameters** (temperature, top_p, max_tokens) | reproducibility, jailbreak-tuning detection, governance |
| **Tool / function / MCP invocation** | the agent's *action* — where tool-abuse, RCE, and data-access detections attach |
| **AI finding context** (OWASP LLM Top 10, guardrail, PII) | triage of prompt injection / leakage, and distinguishing an AI Detection Finding from a non-AI one on the same class |

### Proposed (high level)

Riding on existing classes (API Activity `6003`, Datastore Activity `6005`,
Detection Finding `2004`):

1. **`ai_token_usage` object** — `input_tokens`, `output_tokens`,
   `cached_tokens`, `reasoning_tokens`, `total_tokens`.
2. **`ai_cost` object** — `input_cost`, `output_cost`, `total_cost`, `currency`.
3. **`ai_request_parameters` object** — `temperature`, `top_p`, `max_tokens`.
4. **`ai_latency` object** — `total_time_ms`, `time_to_first_token_ms`,
   `tokens_per_second`, `queue_time_ms`.
5. **`ai_tool` object** — `name`, `type_id` (Function / MCP Tool / Skill / API
   / Other), `server`, `transport`, `approval_required`, `is_approved`.
6. **`ai_operation` profile additions** — `token_usage`, `cost`, `latency`,
   `request_parameters`, `ai_tool`, `finish_reason`, `is_streaming`.
7. **`ai_finding` profile** — `owasp_llm_id` (OWASP LLM Top 10 2025),
   `detection_method`, `guardrail_name`, `is_blocked`, `pii_types`.

### Out of scope (potential follow-ups)

Each closes a gap where an AI event reuses an OCSF class that lacks the fields:

- **RAG / vector retrieval** (`ai_retrieval` object) on Datastore Activity
  `6005` — top_k, similarity scores, embedding model/dims, reranking,
  retrieved-chunk scores, pipeline stage.
- **AI supply-chain / provenance** (model hash/signature/signer, AI-BOM) on
  Vulnerability Finding `2002`.
- **MLOps lifecycle** — a new `ai_model_activity` class in the `ai` category
  (training / evaluation / deployment / drift).
- **Agentic identity enrichment** on Authentication `3002` — SPIFFE/DID/DPoP
  auth methods, trust establishment, scope request/grant/attenuation.
- **MITRE ATLAS** technique mapping on findings (OCSF `attacks` is ATT&CK only).
- **EU AI Act risk classification** (`risk_level` enum) on Compliance Finding
  `2003` / asset inventory.
- **Agent reasoning & multi-agent** objects (`ai_reasoning`, `ai_team`) on
  `agent_activity`; **AI quality metrics** (`ai_quality`) on `ai_operation`.
- **Agent-to-agent communication** — ONE generic `agent_message` object with a
  `protocol_id` discriminator (A2A / ACP / ANP / MCP / Other), **not** a
  per-protocol object. Same conceptual core for every protocol (peer agents +
  delegation, unit-of-work + canonical lifecycle status, operation, transport,
  trust/DID). Per-protocol objects would fragment cross-protocol detection and
  chase fast schema churn; mirror OCSF's "generic class + protocol id" pattern
  (`network_activity` + `tls`/`dns_query`).

### Backwards compatibility

All additions are optional; nothing existing changes; no category is added.

### Prior art

Drawn from the AI Telemetry Framework (AITF), which already implements these as
OCSF-mapped output. I have a complete schema PR (object JSON, profile diffs,
`dictionary.json` entries) ready to open once placement is agreed.

Would maintainers prefer these as `ai_operation` profile extensions, or as a
separate profile? Happy to align with whatever fits the roadmap from #1640.
