# OCSF PR — ready to post

**Title:**

```
Add AI inference, tool & finding telemetry to the ai_operation profile (token usage, cost, latency, parameters, ai_tool, ai_finding)
```

---

**Body:**

## Description

This PR extends the `ai_operation` profile introduced in #1641 so that AI
operations carried on existing event classes (e.g. API Activity `6003`,
Datastore Activity `6005`) can record the **substance of the operation** —
token usage, cost, latency, request parameters, tool/MCP invocation, and
AI-specific finding context.

It complements #1641 (the `ai_agent` object — *who* acted) and #1640 (the
`delegation` object — *under what authority*) by adding *what the operation
consumed and did*. All additions are **optional objects and profile
attributes on existing classes** — consistent with OCSF's reuse model. **No
new category and no new required fields.**

Closes part of the gap discussed in #1640.

## Motivation

#1641 and #1640 establish agent identity, delegated authority, and
agent/delegation control-plane lifecycle. They do not yet capture what a SOC,
FinOps team, or AI-governance reviewer needs from the operation itself:

| Gap (not in OCSF today) | Why it matters |
|---|---|
| **Token usage** | quota/abuse detection, cost attribution |
| **Cost** | FinOps, runaway-spend / exfiltration-by-volume detection |
| **Latency** (TTFT, tokens/sec, queue time) | DoS / "Unbounded Consumption" (OWASP LLM10) detection, SLOs |
| **Request parameters** (temperature, top_p, max_tokens) | reproducibility, jailbreak-tuning detection, governance |
| **Tool / function / MCP invocation** | the agent's *action* — where RCE, data-access, and tool-abuse detections attach |
| **AI finding context** (OWASP LLM Top 10, guardrail, PII) | triage of prompt injection / leakage, and distinguishing an AI Detection Finding from a non-AI one on the same class |

## Proposed changes

### New object — `objects/ai_token_usage.json`

```json
{
  "caption": "AI Token Usage",
  "name": "ai_token_usage",
  "description": "The token consumption of an AI model invocation.",
  "extends": "object",
  "attributes": {
    "input_tokens":     { "requirement": "recommended" },
    "output_tokens":    { "requirement": "recommended" },
    "cached_tokens":    { "requirement": "optional" },
    "reasoning_tokens": { "requirement": "optional" },
    "total_tokens":     { "requirement": "recommended" }
  }
}
```

### New object — `objects/ai_cost.json`

```json
{
  "caption": "AI Cost",
  "name": "ai_cost",
  "description": "The monetary cost of an AI model invocation.",
  "extends": "object",
  "attributes": {
    "input_cost":  { "requirement": "optional", "description": "Cost attributed to input tokens." },
    "output_cost": { "requirement": "optional", "description": "Cost attributed to output tokens." },
    "total_cost":  { "requirement": "recommended", "description": "Total cost of the invocation." },
    "currency":    { "requirement": "recommended", "description": "ISO 4217 currency code, e.g. USD." }
  }
}
```

### New object — `objects/ai_request_parameters.json`

```json
{
  "caption": "AI Request Parameters",
  "name": "ai_request_parameters",
  "description": "The decoding/sampling parameters of an AI model request.",
  "extends": "object",
  "attributes": {
    "temperature": { "requirement": "optional" },
    "top_p":       { "requirement": "optional" },
    "max_tokens":  { "requirement": "optional" }
  }
}
```

### New object — `objects/ai_latency.json`

```json
{
  "caption": "AI Latency",
  "name": "ai_latency",
  "description": "Latency metrics of an AI model invocation.",
  "extends": "object",
  "attributes": {
    "total_time_ms":           { "requirement": "optional", "description": "End-to-end duration in milliseconds." },
    "time_to_first_token_ms":  { "requirement": "optional", "description": "Time to first streamed token." },
    "tokens_per_second":       { "requirement": "optional", "description": "Output token generation rate." },
    "queue_time_ms":           { "requirement": "optional", "description": "Time queued before processing." }
  }
}
```

### New object — `objects/ai_tool.json`

```json
{
  "caption": "AI Tool",
  "name": "ai_tool",
  "description": "A tool, function, skill, or MCP capability invoked by an AI agent. This is the agent's action and the primary attachment point for tool-use security controls.",
  "extends": "object",
  "attributes": {
    "name":     { "requirement": "required" },
    "type":     { "requirement": "optional" },
    "type_id": {
      "requirement": "recommended",
      "enum": {
        "0":  { "caption": "Unknown" },
        "1":  { "caption": "Function" },
        "2":  { "caption": "MCP Tool" },
        "3":  { "caption": "Skill" },
        "4":  { "caption": "API" },
        "99": { "caption": "Other" }
      }
    },
    "server":            { "requirement": "optional", "description": "MCP / remote server identifier." },
    "transport":         { "requirement": "optional", "description": "MCP transport, e.g. stdio, sse, http." },
    "approval_required": { "requirement": "optional" },
    "is_approved":       { "requirement": "optional" }
  }
}
```

### Profile update — `profiles/ai_operation.json`

Add to the existing profile (alongside `ai_agent` / `ai_model` from #1641):

```json
{
  "attributes": {
    "token_usage":       { "requirement": "optional", "description": "Token consumption of this AI operation." },
    "cost":              { "requirement": "optional", "description": "Monetary cost of this AI operation." },
    "latency":           { "requirement": "optional", "description": "Latency metrics of this AI operation." },
    "request_parameters":{ "requirement": "optional", "description": "Decoding/sampling parameters of the request." },
    "ai_tool":           { "requirement": "optional", "description": "The tool, function, or MCP capability invoked." },
    "finish_reason":     { "requirement": "optional", "description": "The reason the model stopped generating." },
    "is_streaming":      { "requirement": "optional", "description": "Whether the response was streamed." }
  }
}
```

### New profile — `profiles/ai_finding.json`

Applied to Detection Finding (`2004`) / Compliance Finding (`2003`) so AI
findings are queryable and distinguishable from non-AI findings on the same
class.

```json
{
  "caption": "AI Finding",
  "name": "ai_finding",
  "meta": "profile",
  "description": "AI-specific risk context for findings raised on AI operations.",
  "attributes": {
    "owasp_llm_id": {
      "requirement": "recommended",
      "enum": {
        "0":  { "caption": "Unknown" },
        "1":  { "caption": "Prompt Injection" },
        "2":  { "caption": "Sensitive Information Disclosure" },
        "3":  { "caption": "Supply Chain" },
        "4":  { "caption": "Data and Model Poisoning" },
        "5":  { "caption": "Improper Output Handling" },
        "6":  { "caption": "Excessive Agency" },
        "7":  { "caption": "System Prompt Leakage" },
        "8":  { "caption": "Vector and Embedding Weaknesses" },
        "9":  { "caption": "Misinformation" },
        "10": { "caption": "Unbounded Consumption" },
        "99": { "caption": "Other" }
      },
      "description": "OWASP Top 10 for LLM Applications (2025) category."
    },
    "detection_method": { "requirement": "recommended", "description": "pattern, ml_model, guardrail, or policy." },
    "guardrail_name":   { "requirement": "optional", "description": "Name of the guardrail/control that fired." },
    "is_blocked":       { "requirement": "optional", "description": "Whether the offending action was blocked." },
    "pii_types":        { "requirement": "optional", "description": "Categories of PII detected." }
  }
}
```

### Dictionary additions — `dictionary.json`

```json
{
  "attributes": {
    "input_tokens":          { "caption": "Input Tokens",          "description": "Number of prompt/input tokens.",          "type": "long_t" },
    "output_tokens":         { "caption": "Output Tokens",         "description": "Number of completion/output tokens.",     "type": "long_t" },
    "cached_tokens":         { "caption": "Cached Tokens",         "description": "Prompt tokens served from cache.",        "type": "long_t" },
    "reasoning_tokens":      { "caption": "Reasoning Tokens",      "description": "Reasoning/thinking tokens.",              "type": "long_t" },
    "total_tokens":          { "caption": "Total Tokens",          "description": "Total tokens billed.",                    "type": "long_t" },
    "token_usage":           { "caption": "Token Usage",           "description": "AI model token consumption.",             "type": "ai_token_usage" },
    "input_cost":            { "caption": "Input Cost",            "description": "Cost attributed to input tokens.",        "type": "float_t" },
    "output_cost":           { "caption": "Output Cost",           "description": "Cost attributed to output tokens.",       "type": "float_t" },
    "total_cost":            { "caption": "Total Cost",            "description": "Total cost of the invocation.",           "type": "float_t" },
    "cost":                  { "caption": "Cost",                  "description": "Monetary cost of an AI operation.",       "type": "ai_cost" },
    "temperature":           { "caption": "Temperature",           "description": "Sampling temperature.",                   "type": "float_t" },
    "top_p":                 { "caption": "Top P",                 "description": "Nucleus sampling probability mass.",      "type": "float_t" },
    "max_tokens":            { "caption": "Max Tokens",            "description": "Requested maximum output tokens.",        "type": "integer_t" },
    "request_parameters":    { "caption": "Request Parameters",    "description": "AI request decoding/sampling params.",    "type": "ai_request_parameters" },
    "total_time_ms":         { "caption": "Total Time (ms)",       "description": "End-to-end duration in milliseconds.",    "type": "float_t" },
    "time_to_first_token_ms":{ "caption": "Time To First Token (ms)","description": "Time to first streamed token.",        "type": "float_t" },
    "tokens_per_second":     { "caption": "Tokens Per Second",     "description": "Output token generation rate.",           "type": "float_t" },
    "queue_time_ms":         { "caption": "Queue Time (ms)",       "description": "Time queued before processing.",          "type": "float_t" },
    "latency":               { "caption": "Latency",               "description": "AI invocation latency metrics.",          "type": "ai_latency" },
    "ai_tool":               { "caption": "AI Tool",               "description": "A tool/function/skill/MCP capability.",   "type": "ai_tool" },
    "approval_required":     { "caption": "Approval Required",     "description": "Whether human approval was required.",    "type": "boolean_t" },
    "is_approved":           { "caption": "Approved",              "description": "Whether approval was granted.",           "type": "boolean_t" },
    "finish_reason":         { "caption": "Finish Reason",         "description": "Reason the model stopped generating.",    "type": "string_t" },
    "is_streaming":          { "caption": "Streaming",             "description": "Whether the response was streamed.",      "type": "boolean_t" },
    "owasp_llm_id":          { "caption": "OWASP LLM ID",          "description": "OWASP Top 10 for LLM Applications id.",    "type": "integer_t" },
    "guardrail_name":        { "caption": "Guardrail Name",        "description": "Guardrail/control that fired.",           "type": "string_t" },
    "is_blocked":            { "caption": "Blocked",               "description": "Whether the action was blocked.",         "type": "boolean_t" },
    "pii_types":             { "caption": "PII Types",             "description": "Categories of PII detected.",             "type": "string_t", "is_array": true }
  }
}
```

> `name`, `type`, `type_id`, `server`, `transport`, `currency`, and
> `detection_method` reuse existing dictionary attributes where present; only
> add the entries above that are not already defined on `main`.

## Out of scope (proposed as follow-on PRs)

To keep this PR reviewable, the following are deliberately deferred. Each
closes a gap where an AI event reuses an OCSF class that lacks the relevant
fields:

1. **RAG / vector retrieval** — an `ai_retrieval` object on Datastore Activity
   `6005`: `top_k`, similarity score thresholds, embedding model + dimensions,
   reranking, retrieved-chunk count/scores, pipeline stage. (Datastore Activity
   has no vector-search semantics today.)
2. **AI supply-chain / provenance** — an `ai_provenance` object (model `hash`,
   `signature`, `signer`, license, AI-BOM reference) for Vulnerability Finding
   `2002`. (AI-BOM does not map to package CVEs.)
3. **MLOps lifecycle** — a new `ai_model_activity` class in the `ai` category
   (uid 9): training, evaluation, deployment, drift. (Application Lifecycle
   `6002` cannot represent training/eval/drift — the one item that genuinely
   warrants a new class.)
4. **Agentic identity enrichment** — on Authentication `3002`: agent-specific
   auth methods (SPIFFE SVID, DID-VC, DPoP, mTLS, HTTP-signature), trust
   establishment (peer agent, trust domain, cross-domain, level), and scope
   request/grant/attenuation.
5. **MITRE ATLAS** — AI-adversary technique mapping on findings (OCSF `attacks`
   covers MITRE ATT&CK, not ATLAS).
6. **EU AI Act risk classification** — a typed `risk_level` enum
   (unacceptable / high / limited / minimal / systemic) for Compliance Finding
   `2003` and asset inventory.
7. **Agent reasoning & multi-agent** — optional `ai_reasoning`
   (`thought`/`action`/`observation`) and `ai_team` (topology, members) objects
   on `agent_activity`.
8. **AI quality metrics** — an `ai_quality` object (hallucination score,
   confidence, factuality) on `ai_operation`.
9. **Agent-to-agent communication** — ONE generic `agent_message` object with a
   `protocol_id` discriminator (A2A / ACP / ANP / MCP / Other), not a separate
   object per protocol. Carries the shared core of every agentic exchange:
   `src_agent`/`dst_agent` (`ai_agent`), `delegation`, unit-of-work
   (task/run/message) `uid` + a canonical lifecycle `status`, `operation`,
   `transport`, parts/artifacts counts, trust (domain/cross-domain/DID), and
   error. Carried on a new `agent_communication` class (or `agent_activity`)
   in the `ai` category. **Rationale:** OCSF gives SMTP/SMB/DNS/SSH dedicated
   objects because they are mature, ubiquitous, and semantically distinct;
   agentic protocols are nascent, fast-churning, and converging on one
   conceptual model — a per-protocol object would fragment cross-protocol
   detection (e.g. "agent contacted an untrusted peer") and chase schema
   churn. Mirror OCSF's own "generic class + protocol id" pattern
   (`network_activity` + `tls`/`dns_query`); keep per-protocol detail in a
   `metadata` escape hatch. **Fully specified as a standalone PR:**
   [`ocsf-agent-message-pr-draft.md`](./ocsf-agent-message-pr-draft.md)
   (sequenced after the `ai` category from #1640 lands).

## Backwards compatibility

All additions are optional objects/profile attributes on existing classes — no
existing attribute is changed, no field becomes required, and no category is
added. Producers that do not emit them are unaffected.

## Testing

- [ ] `make test` / schema validation passes with the new objects and profiles.
- [ ] Server renders the new objects, profiles, and enums.
- [ ] `dictionary.json` references resolve for all added attributes.

## Checklist

- [ ] New objects added under `objects/` (`ai_token_usage`, `ai_cost`,
      `ai_request_parameters`, `ai_latency`, `ai_tool`).
- [ ] Profile updated (`ai_operation`) and added (`ai_finding`) under `profiles/`.
- [ ] `dictionary.json` updated.
- [ ] `CHANGELOG.md` updated.
- [ ] Linked to #1640 and #1641.
