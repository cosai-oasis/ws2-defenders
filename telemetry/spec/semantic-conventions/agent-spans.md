# Agent Span Conventions (AGENT_TRACE)

> **OTel Alignment Note:** This spec adopts OTel GenAI agent attributes (`gen_ai.agent.{name,id,description,version}`,
> `gen_ai.conversation.id`) where OTel now defines them. Extension attributes for step reasoning, delegation,
> team orchestration, and memory use short namespaces (e.g., `agent.step.*`, `agent.team.*`, `memory.*`).

Status: **Normative** | CoSAI WS2 Alignment: **AGENT_TRACE** | OCSF Class: **7002 Agent Activity**

AITF defines comprehensive semantic conventions for AI agent telemetry, supporting single agents, multi-agent orchestration, delegation, and agent memory. This specification defines the normative field requirements aligned with CoSAI Working Stream 2 (Telemetry for AI) and mapped to applicable compliance and threat frameworks.

Key words "MUST", "SHOULD", "MAY" follow [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Span: `agent.session`

Represents a complete agent session from start to finish.

### Span Name

Format: `agent.session {gen_ai.agent.name}`

### Span Kind

`INTERNAL`

### Normative Field Table

Instrumentors MUST emit all Required fields. Instrumentors SHOULD emit Recommended fields when the data is available. Optional fields MAY be emitted for enhanced observability.

#### Agent Identity

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.agent.name` | string | **Required** | Human-readable agent name | OWASP LLM06 (Excessive Agency), MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `gen_ai.agent.id` | string | **Required** | Unique agent instance identifier | OWASP LLM06, MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048), EU AI Act Art.12 |
| `gen_ai.conversation.id` | string | **Required** | Session identifier | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `agent.workflow_id` | string | **Recommended** | Workflow/DAG identifier linking related agent sessions | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |

#### Agent Configuration

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `agent.type` | string | **Recommended** | Agent type: `"conversational"`, `"autonomous"`, `"reactive"`, `"proactive"` | EU AI Act Art.13 (Transparency) |
| `agent.framework` | string | **Recommended** | Agent framework: `"langchain"`, `"crewai"`, `"autogen"`, `"semantic_kernel"`, `"custom"` | NIST AI RMF MAP-1.1 |
| `gen_ai.agent.version` | string | **Optional** | Agent version string | NIST AI RMF MAP-1.1 |
| `gen_ai.agent.description` | string | **Optional** | Agent role/purpose description | EU AI Act Art.13 |

#### Session State (CoSAI WS2)

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `agent.state` | string | **Recommended** | Current agent lifecycle state: `"initializing"`, `"planning"`, `"executing"`, `"waiting"`, `"completed"`, `"failed"`, `"suspended"` | OWASP LLM06 (Excessive Agency), MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `agent.session.turn_count` | int | **Recommended** | Total turns completed in session | OWASP LLM10 (Unbounded Consumption) |
| `agent.session.start_time` | string | **Optional** | Session start timestamp (ISO 8601) | EU AI Act Art.12 |

#### Team Affiliation

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `agent.team.name` | string | **Optional** | Team name (if part of a multi-agent team) | NIST AI RMF MAP-1.1 |
| `agent.team.id` | string | **Optional** | Team identifier | NIST AI RMF GOVERN-1.2 |

---

## Span: `agent.step`

Represents a single step in the agent's execution loop (think-act-observe).

### Span Name

Format: `agent.step.{agent.step.type} {gen_ai.agent.name}`

### Span Kind

`INTERNAL`

### Normative Field Table

#### Step Identification

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.agent.name` | string | **Required** | Agent name | OWASP LLM06, MITRE ATLAS AML.T0048 |
| `agent.step.type` | string | **Required** | Step type (see Step Types table below) | OWASP LLM06, NIST AI RMF MEASURE-2.5 |
| `agent.step.index` | int | **Required** | Step sequence number (0-indexed) | NIST AI RMF GOVERN-1.2 |

#### ReAct / Chain-of-Thought (CoSAI WS2)

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `agent.step.thought` | string | **Recommended** | Agent's internal reasoning (ReAct "thought") | NIST AI RMF MAP-1.1, EU AI Act Art.13 (Transparency), MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `agent.step.action` | string | **Recommended** | Planned/executed action | OWASP LLM06 (Excessive Agency) |
| `agent.step.observation` | string | **Recommended** | Result/observation from action | NIST AI RMF MEASURE-2.5 |
| `agent.scratchpad` | string | **Optional** | Accumulated agent scratchpad / working memory state (JSON) | OWASP LLM02 (Sensitive Info Disclosure), MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `agent.next_action` | string | **Recommended** | Next planned action (forward-looking intent) | OWASP LLM06 (Excessive Agency), MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `agent.step.status` | string | **Recommended** | Step outcome: `"success"`, `"error"`, `"retry"`, `"skipped"` | NIST AI RMF MEASURE-2.5 |

### Step Types

| Value | Description | Compliance |
|---|---|---|
| `planning` | Agent is planning next actions | EU AI Act Art.13 |
| `reasoning` | Agent is reasoning about observations | EU AI Act Art.13, NIST AI RMF MAP-1.1 |
| `tool_use` | Agent is calling a tool/function | OWASP LLM06, MITRE ATLAS AML.T0048 |
| `delegation` | Agent is delegating to another agent | OWASP LLM06, NIST AI RMF GOVERN-1.7 |
| `response` | Agent is generating final response | OWASP LLM05 |
| `reflection` | Agent is reflecting on its performance | NIST AI RMF MEASURE-2.5 |
| `memory_access` | Agent is accessing memory | OWASP LLM02 |
| `guardrail_check` | Agent is checking guardrails | OWASP LLM01–LLM10 |
| `human_in_loop` | Agent is waiting for human input | EU AI Act Art.14 (Human Oversight) |
| `error_recovery` | Agent is recovering from an error | NIST AI RMF MEASURE-2.5 |

---

## Span: `agent.delegation`

Represents agent-to-agent delegation within a multi-agent system.

### Span Name

Format: `agent.delegate {gen_ai.agent.name} -> {agent.delegation.target_agent}`

### Span Kind

`INTERNAL`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.agent.name` | string | **Required** | Delegating agent name | OWASP LLM06, MITRE ATLAS AML.T0048 |
| `agent.delegation.target_agent` | string | **Required** | Target agent name | OWASP LLM06, MITRE ATLAS AML.T0048 |
| `agent.delegation.target_agent_id` | string | **Required** | Target agent instance ID | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `agent.delegation.reason` | string | **Recommended** | Why delegation occurred | EU AI Act Art.13 (Transparency) |
| `agent.delegation.strategy` | string | **Recommended** | Strategy: `"round_robin"`, `"capability"`, `"hierarchical"`, `"vote"` | NIST AI RMF GOVERN-1.7 |
| `agent.delegation.task` | string | **Recommended** | Delegated task description | OWASP LLM06 |
| `agent.delegation.result` | string | **Optional** | Result from delegated agent | NIST AI RMF MEASURE-2.5 |
| `agent.delegation.timeout_ms` | double | **Optional** | Delegation timeout in milliseconds | OWASP LLM10 |

---

## Span: `agent.team.orchestrate`

Represents a multi-agent team orchestration operation.

### Span Name

Format: `agent.team.orchestrate {agent.team.name}`

### Span Kind

`INTERNAL`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `agent.team.name` | string | **Required** | Team name | NIST AI RMF MAP-1.1 |
| `agent.team.id` | string | **Required** | Team identifier | NIST AI RMF GOVERN-1.2 |
| `agent.team.topology` | string | **Required** | Team topology (see table below) | NIST AI RMF GOVERN-1.7 |
| `agent.team.members` | string[] | **Recommended** | Member agent names | OWASP LLM06 |
| `agent.team.coordinator` | string | **Recommended** | Coordinator agent name | OWASP LLM06 |
| `agent.team.task` | string | **Optional** | Team task description | EU AI Act Art.13 |
| `agent.team.consensus_method` | string | **Optional** | `"majority"`, `"unanimous"`, `"coordinator"` | NIST AI RMF GOVERN-1.7 |
| `agent.team.rounds` | int | **Optional** | Number of interaction rounds | OWASP LLM10 |

### Team Topologies

| Value | Description | Compliance |
|---|---|---|
| `hierarchical` | Manager/supervisor delegates to workers | NIST AI RMF GOVERN-1.7 |
| `peer` | Agents collaborate as equals | NIST AI RMF GOVERN-1.7 |
| `pipeline` | Sequential processing chain | — |
| `consensus` | Agents vote or reach consensus | EU AI Act Art.14 |
| `debate` | Agents debate to reach conclusion | NIST AI RMF MEASURE-2.5 |
| `swarm` | Dynamic self-organizing agents | OWASP LLM06 |

---

## Span: `agent.memory`

Represents an agent memory operation.

### Span Name

Format: `agent.memory.{memory.operation} {gen_ai.agent.name}`

### Span Kind

`INTERNAL`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.agent.name` | string | **Required** | Agent name | OWASP LLM06 |
| `memory.operation` | string | **Required** | Operation: `"store"`, `"retrieve"`, `"update"`, `"delete"`, `"search"` | OWASP LLM02 (Sensitive Info) |
| `memory.store` | string | **Required** | Store type: `"short_term"`, `"long_term"`, `"episodic"`, `"semantic"`, `"procedural"` | NIST AI RMF MAP-1.5 |
| `memory.key` | string | **Recommended** | Memory key/identifier | OWASP LLM02 |
| `memory.hit` | boolean | **Recommended** | Whether memory was found (for retrieve) | NIST AI RMF MEASURE-2.5 |
| `memory.ttl_seconds` | int | **Optional** | Time to live in seconds | — |
| `memory.provenance` | string | **Optional** | Origin of memory entry | NIST AI RMF MAP-1.5 |

---

## CoSAI WS2 Field Mapping

Cross-reference between CoSAI WS2 `AGENT_TRACE` field names and AITF attribute keys:

| CoSAI WS2 Field | AITF Attribute | Notes |
|---|---|---|
| `agent.id` | `gen_ai.agent.id` | Direct match |
| `agent.workflow_id` | `agent.workflow_id` | New in CoSAI WS2 alignment |
| `agent.state` | `agent.state` | New in CoSAI WS2 alignment |
| `agent.thought` | `agent.step.thought` | Set on step spans |
| `agent.scratchpad` | `agent.scratchpad` | New in CoSAI WS2 alignment |
| `agent.next_action` | `agent.next_action` | New in CoSAI WS2 alignment |

---

## Example: Multi-Agent Research System

```
Span: agent.team.orchestrate research-team
  agent.team.topology: "hierarchical"
  agent.team.members: ["manager", "researcher", "writer"]
  |
  +- Span: agent.session manager
  |    gen_ai.agent.id: "agent-mgr-001"
  |    agent.type: "autonomous"
  |    agent.framework: "crewai"
  |    agent.workflow_id: "wf-research-abc123"
  |    agent.state: "executing"
  |    |
  |    +- Span: agent.step.planning manager
  |    |    agent.step.thought: "Need to research AI telemetry"
  |    |    agent.next_action: "delegate to researcher"
  |    |    +- Span: chat gpt-4o
  |    |
  |    +- Span: agent.step.delegation manager
  |    |    agent.delegation.target_agent: "researcher"
  |    |    agent.delegation.reason: "Research expertise needed"
  |    |    |
  |    |    +- Span: agent.session researcher
  |    |         agent.workflow_id: "wf-research-abc123"
  |    |         +- Span: agent.step.tool_use researcher
  |    |         |    +- Span: mcp.tool.invoke read_file
  |    |         +- Span: agent.step.reasoning researcher
  |    |              agent.scratchpad: "{\"findings\": [...]}"
  |    |              +- Span: chat claude-sonnet-4-5-20250929
  |    |
  |    +- Span: agent.step.delegation manager
  |         agent.delegation.target_agent: "writer"
  |         |
  |         +- Span: agent.session writer
  |              agent.workflow_id: "wf-research-abc123"
  |              +- Span: agent.step.response writer
  |                   +- Span: chat gpt-4o
```
