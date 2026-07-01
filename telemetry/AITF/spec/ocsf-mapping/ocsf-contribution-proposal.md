# Proposed OCSF Contribution: AI Inference, Tool & Risk Telemetry on the `ai_operation` Profile

> **Draft PR proposal for [ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema).**
> Complements OCSF [PR #1641](https://github.com/ocsf/ocsf-schema/pull/1641)
> (`ai_agent` object + `ai_operation` profile) and
> [issue #1640](https://github.com/ocsf/ocsf-schema/issues/1640) (the `ai`
> category, `delegation` object, `agent_activity` / `delegation_activity`).
> Source of the proposed schema: the AI Telemetry Framework (AITF).

## Motivation

PR #1641 and issue #1640 establish *who* acted (the `ai_agent` object) and
*under what authority* (the `delegation` object), and route agent/delegation
**control-plane** lifecycle into the new `ai` category. What they do **not**
yet capture is the **substance of the AI operation itself** — the data a SOC,
FinOps team, or AI-governance reviewer needs to detect abuse, attribute cost,
and prove compliance:

| Gap (not in OCSF today) | Why it matters | AITF coverage |
|---|---|---|
| LLM **token usage & cost** | FinOps, abuse/exfiltration detection, quota | `ai_token_usage`, cost fields |
| **Tool / MCP / function invocation** | The agent's *actions* (RCE, data access) ride here | `mcp.*`, `skill.*`, tool spans |
| **AI-specific finding context** (OWASP LLM Top 10, guardrails, PII) | Triage of prompt injection, jailbreak, leakage | OWASP LLM mapping, guardrail/PII |
| **Model provenance / supply chain** | Model integrity, AI-BOM, signing | model hash/signer, AI-BOM |
| **Model lifecycle (MLOps)** | Train/eval/deploy/drift as security events | ModelOps spans |

These are all **object + profile** additions that ride on existing classes —
fully consistent with OCSF's "reuse objects and profiles" model. None require a
new category.

This document proposes a **focused lead PR** (§1–§3, the highest-value and
lowest-risk additions) plus a **roadmap** of follow-on PRs (§4).

---

## Lead PR — Scope

Extend the `ai_operation` profile so AI inference and tool-use activity carried
on existing classes (API Activity 6003, Datastore Activity 6005, …) records
token usage, request parameters, and tool-invocation detail; and add an
`ai_finding` profile for AI-specific risk context reusable on Detection
Finding (2004).

### 1. New object: `ai_token_usage`

`objects/ai_token_usage.json` — consumption of an AI model invocation.

| Attribute | Req. | Type | Description |
|---|---|---|---|
| `input_tokens` | Recommended | integer | Prompt / input tokens |
| `output_tokens` | Recommended | integer | Completion / output tokens |
| `cached_tokens` | Optional | integer | Prompt tokens served from cache |
| `reasoning_tokens` | Optional | integer | Reasoning / "thinking" tokens |
| `total_tokens` | Recommended | integer | Total tokens billed |

```json
{
  "caption": "AI Token Usage",
  "name": "ai_token_usage",
  "description": "Token consumption of an AI model invocation.",
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

### 2. New object: `ai_tool` (and `ai_tool_invocation` context)

`objects/ai_tool.json` — a tool/function/skill/MCP capability an agent invokes.
The tool call is the agent's **action** and is the primary place security
controls and detections attach.

| Attribute | Req. | Type | Description |
|---|---|---|---|
| `name` | Required | string | Tool / function name |
| `type_id` | Recommended | integer | `0` Unknown · `1` Function · `2` MCP Tool · `3` Skill · `4` API · `99` Other |
| `type` | Optional | string | Caption of `type_id` |
| `server` | Optional | string | MCP / remote server identifier |
| `transport` | Optional | string | MCP transport (`stdio`, `sse`, `http`) |
| `approval_required` | Optional | boolean | Whether human approval was required |
| `is_approved` | Optional | boolean | Whether approval was granted |

### 3. `ai_operation` profile additions

Add to `profiles/ai_operation.json` (alongside the existing `ai_agent` /
`ai_model` from PR #1641):

| Attribute | Req. | Type | Description |
|---|---|---|---|
| `token_usage` | Optional | `ai_token_usage` | Token consumption (§1) |
| `ai_tool` | Optional | `ai_tool` | Tool invoked (§2) |
| `finish_reason` | Optional | string | Model stop reason |
| `is_streaming` | Optional | boolean | Streaming response |

This lets a single API Activity (6003) event for an LLM call or tool
invocation carry the agent, the model, token usage, and the tool — with no new
class.

### `ai_finding` profile (AI risk context for Detection Finding 2004)

`profiles/ai_finding.json` — applied to Detection/Compliance Finding so AI
findings are queryable and triageable.

| Attribute | Req. | Type | Description |
|---|---|---|---|
| `owasp_llm_id` | Recommended | integer | OWASP LLM Top 10 (2025) id (`1`=Prompt Injection … `10`=Unbounded Consumption) |
| `detection_method` | Recommended | string | `pattern`, `ml_model`, `guardrail`, `policy` |
| `guardrail_name` | Optional | string | Guardrail/control that fired |
| `is_blocked` | Optional | boolean | Whether the action was blocked |
| `pii_types` | Optional | string[] | PII categories detected |

---

## 4. Roadmap — follow-on PRs

Kept separate so each PR stays focused and reviewable:

1. **AI supply-chain / provenance** — an `ai_model` object enrichment or
   `ai_provenance` object (model `hash`, `signature`, `signer`, AI-BOM ref) for
   reuse on Vulnerability Finding (2002).
2. **Model lifecycle (MLOps)** — an `ai_model_activity` class in the `ai`
   category (uid 9): training, evaluation, deployment, drift — the only item
   here that genuinely warrants a new class.
3. **Agent reasoning & multi-agent orchestration** — optional `ai_reasoning`
   (step `thought`/`action`/`observation`) and `ai_team` (topology, members)
   objects on `agent_activity`, for ReAct-style and multi-agent traces.
4. **Quality metrics** — `ai_quality` object (hallucination score, confidence,
   factuality) on `ai_operation`.

## Backwards compatibility

All additions are **optional** objects/profile attributes on existing classes —
no breaking changes, no new required fields, no category changes (except the
roadmap MLOps class, which is additive). Producers that don't emit them are
unaffected.

## Reference mapping (AITF → proposed OCSF)

| AITF | Proposed OCSF |
|---|---|
| `AITokenUsage` | `ai_token_usage` object |
| `mcp.tool.*` / `skill.*` | `ai_tool` object + `ai_operation.ai_tool` |
| `gen_ai.usage.*`, cost | `ai_operation.token_usage` |
| OWASP LLM category, guardrail, PII | `ai_finding` profile |
| Supply chain (hash/signer/AI-BOM) | roadmap #1 |
| ModelOps (train/eval/deploy/drift) | roadmap #2 (`ai_model_activity`) |
| Agent step/team telemetry | roadmap #3 |

## How to file

1. Open a discussion/issue referencing #1640 and #1641 with §1–§3 (lead PR
   scope) to get maintainer buy-in on placement before coding the schema.
2. Submit the lead PR (`ai_token_usage`, `ai_tool`, `ai_operation` additions,
   `ai_finding` profile) with `dictionary.json` entries and a `CHANGELOG` note.
3. File the roadmap items as separate PRs once the lead lands.
