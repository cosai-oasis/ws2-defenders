# AITF ↔ OCSF Agentic AI Alignment

> **Status:** Alignment proposal — tracks OCSF
> [PR #1641](https://github.com/ocsf/ocsf-schema/pull/1641) and
> [issue #1640](https://github.com/ocsf/ocsf-schema/issues/1640).

This document describes how AITF aligns with OCSF's agentic-AI direction.
The guiding principle, from OCSF itself, is **reuse existing objects and
profiles** rather than minting bespoke AI event classes:

- **Data-plane AI activity** (inference, tool/function calls, retrieval, model
  lifecycle, findings, identity, inventory) is emitted under the **existing
  OCSF event classes** it naturally belongs to, **enriched with the
  `ai_operation` profile** (the `ai_agent` object + `ai_model`) and, where
  relevant, the `delegation` object.
- Only **genuinely new control-plane lifecycle** — agent and delegation
  lifecycle — uses the **proposed `ai` category (`uid 9`)** from issue #1640.

AITF previously defined a bespoke **Category 7** with classes 7001–7010. That
collided with released OCSF (`uid 7` = *Remediation*, `uid 8` = *Unmanned
Systems*) and, more importantly, ran against OCSF's reuse philosophy. AITF has
therefore **dropped Category 7** and now maps onto existing OCSF classes.

## 1. Class mapping (what AITF emits)

| AITF event | OCSF category | OCSF class | `class_uid` |
|---|---|---|---|
| Model Inference | 6 Application Activity | API Activity | 6003 |
| Tool / MCP / Function Execution | 6 Application Activity | API Activity | 6003 |
| Data Retrieval (RAG / vector) | 6 Application Activity | Datastore Activity | 6005 |
| Model Operations (train/eval/deploy) | 6 Application Activity | Application Lifecycle | 6002 |
| Security Finding | 2 Findings | Detection Finding | 2004 |
| Supply Chain | 2 Findings | Vulnerability Finding | 2002 |
| Governance / Compliance | 2 Findings | Compliance Finding | 2003 |
| Identity / Authentication | 3 IAM | Authentication | 3002 |
| Asset Inventory | 5 Discovery | Inventory Info | 5001 |
| **Agent lifecycle** | **9 AI (proposed)** | **agent_activity** | **9001\*** |
| **Delegation lifecycle** | **9 AI (proposed)** | **delegation_activity** | **9002\*** |
| **Agent-to-agent comms (A2A/ACP/ANP)** | **9 AI (proposed)** | **agent_communication** | **9003\*** |

\* The `ai` category and its control-plane class UIDs are **provisional** —
they will be reconciled with the final numbers once OCSF issue #1640 is
ratified. Inference and tool execution intentionally share API Activity
(6003); they are distinguished by `activity_id` and the `ai_operation`
profile.

> **Implication for detection content.** Because AI events reuse shared OCSF
> classes, downstream rules/dashboards must filter on **`class_uid` *plus* the
> presence of the `ai_operation` profile** (e.g. `ai_agent` is set), not on a
> dedicated AI class UID. A non-AI Detection Finding and an AI Detection
> Finding share `class_uid 2004`; the `ai_agent`/`ai_model`/`delegation`
> fields are what mark the latter as AI.

## 2. The `ai_agent` object (OCSF PR #1641)

Carried on the `ai_operation` profile of every agent-attributable event.
Distinct from the OCSF `agent` object (security sensors).

| OCSF `ai_agent` field | Req. | AITF source attribute | Notes |
|---|---|---|---|
| `uid` | Required | `gen_ai.agent.id` ∥ `identity.agent_id` ∥ `agent.workflow_id` | Stable logical agent id |
| `instance_uid` | Recommended | `gen_ai.conversation.id` | Restart-sensitive running instance |
| `name` | Recommended | `gen_ai.agent.name` ∥ `identity.agent_name` | |
| `type` | Optional | caption of `type_id` | e.g. `LangChain` |
| `type_id` | Recommended | normalized from `agent.framework` | enum below |
| `ai_model` | Recommended | `gen_ai.request.model` ∥ `gen_ai.response.model` | Backing model |
| `version` | Recommended | `gen_ai.agent.version` | Agent code/config revision |
| `charter` | Optional | `gen_ai.agent.description` | Role / operating boundaries |

### `type_id` enum (framework normalization)

Matches OCSF PR #1641 exactly. Frameworks without a dedicated OCSF member
normalize to `Other (99)`.

| `type_id` | Caption | AITF `agent.framework` values |
|---|---|---|
| 0 | Unknown | *(absent)* |
| 1 | Native | `native` |
| 2 | LangChain | `langchain`, `langgraph` |
| 3 | AutoGen | `autogen` |
| 4 | CrewAI | `crewai` |
| 99 | Other | `semantic_kernel`, `custom`, … |

## 3. The `ai_operation` profile (OCSF PR #1641)

PR #1641 adds `ai_agent` and `ai_model` to the `ai_operation` profile so that
existing event classes become agent-attributable. AITF applies this profile to
**every** event it emits. Profile fields on the AITF base event:

| Field | Type | Source |
|---|---|---|
| `ai_agent` | `ai_agent` object | §2 |
| `ai_model` | string | `gen_ai.request.model` |
| `delegation` | `delegation` object | §4 |
| `delegation_lineage` | `delegation_lineage` object | §4 |

## 4. The `delegation` object & lineage (OCSF issue #1640)

A **durable** authorization context plus a `delegation_lineage` /
`delegation_node` directed graph for ancestry queries.

| OCSF `delegation` field | AITF source attribute |
|---|---|
| `uid` (required) | `identity.delegation.delegatee_id` ∥ `agent.delegation.target_agent_id` ∥ last node of chain |
| `parent_uid` | `identity.delegation.delegator_id` |
| `issuer_uid` | `identity.provider` |
| `delegator` | `identity.delegation.delegator` |
| `delegatee` | `identity.delegation.delegatee` |
| `type` | `identity.delegation.type` |
| `scope` | `identity.delegation.scope_delegated` |
| `proof_type` | `identity.delegation.proof_type` |
| `ttl_seconds` | `identity.delegation.ttl_seconds` |

`delegation_lineage` is materialized from `identity.delegation.chain` (ordered
origin→current); each entry becomes a `delegation_node` with `uid`,
`parent_uid`, `agent_uid`, and `depth`.

## 5. Control-plane activities (OCSF issue #1640)

The new `ai`-category classes carry lifecycle activities. UIDs for the classes
are provisional, but the activity-name mapping is stable.

### Agent lifecycle → `agent_activity`

| AITF `activity_id` | AITF activity | OCSF `agent_activity` |
|---|---|---|
| 1 | Session Start | Spawn |
| 2 | Session End | Terminate |
| 3 | Step Execute | Update |
| 4 | Delegation | Register |
| 5 | Memory Access | Resume |
| 6 | Error Recovery | Resume |
| 7 | Human Approval | Suspend |
| 99 | Other | Unknown |

### Delegation lifecycle → `delegation_activity`

| AITF delegation op | OCSF `delegation_activity` |
|---|---|
| `create` / `grant` | Create |
| `revoke` | Revoke |
| `expire` | Expire |
| `complete` | Complete |

## 6. `hosted_ai_agent_list` on `process` (OCSF PR #1641)

PR #1641 adds `hosted_ai_agent_list` to the OCSF `process` object (multiple
agents hosted by one OS process). When AITF emits an event with host/process
context **and** an `ai_agent`, exporters that populate the OCSF `process`
object SHOULD append the `ai_agent` to `process.hosted_ai_agent_list`.

## 7. Reference implementation

| SDK | Objects, profile & class mapping | Builders & crosswalk tables |
|---|---|---|
| Python | `aitf/ocsf/schema.py`, `event_classes.py` | `aitf/ocsf/crosswalk.py` |
| TypeScript | `src/ocsf/schema.ts`, `event-classes.ts` | `src/ocsf/crosswalk.ts` |
| Go | `ocsf/schema.go`, `events.go` | `ocsf/crosswalk.go` |

Each event class declares its reused OCSF `category_uid` + `class_uid`, and the
`OCSFMapper` enriches every event with the `ai_operation` profile
(`ai_agent`, `ai_model`, `delegation`, `delegation_lineage`) automatically.
The authoritative AITF→OCSF class table lives in `OCSF_CLASS_CROSSWALK`.
