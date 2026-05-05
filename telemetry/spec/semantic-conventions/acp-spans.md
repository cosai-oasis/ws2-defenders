# ACP Span Conventions (Agent Communication Protocol)

Status: **Normative** | OCSF Class: **7002 Agent Activity**

AITF defines semantic conventions for the [ACP (Agent Communication Protocol)](https://agentcommunicationprotocol.dev/), a REST-based protocol for agent discovery, run execution, and human-in-the-loop interactions. ACP supports synchronous, asynchronous (polling), and streaming (SSE) execution modes with explicit await/resume semantics for interactive agent workflows.

> **Note:** ACP has been merged into the A2A project under the Linux Foundation. Existing ACP deployments continue to use this API surface. New deployments should evaluate A2A.

Key words "MUST", "SHOULD", "MAY" follow [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Overview

```
ACP Protocol Flow:
  GET /agents           -> discover agents
  POST /runs            -> create run (sync, async, or stream)
  GET /runs/{id}        -> poll run status (async mode)
  POST /runs/{id}/cancel -> cancel running
  POST /runs/{id}/resume -> resume awaiting run

Spans:
  acp.agent.discover       (list/get agents)
  acp.run.create           (create and execute a run)
  acp.run.get              (poll run status)
  acp.run.cancel           (cancel running)
  acp.run.resume           (resume awaiting run)
```

---

## Span: `acp.agent.discover`

Represents agent discovery via `GET /agents` or `GET /agents/{name}`.

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `acp.operation` | string | **Required** | `"list_agents"` or `"get_agent"` | NIST AI RMF MAP-1.1 |
| `acp.http.method` | string | **Required** | `"GET"` | — |
| `acp.http.url` | string | **Recommended** | Request URL | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `acp.agent.name` | string | **Recommended** | Agent name (if fetching specific agent) | OWASP LLM06 (Excessive Agency) |
| `acp.agent.description` | string | **Optional** | Agent description from manifest | EU AI Act Art.13 (Transparency) |
| `acp.agent.input_content_types` | string[] | **Optional** | Supported input MIME types | — |
| `acp.agent.output_content_types` | string[] | **Optional** | Supported output MIME types | — |
| `acp.agent.framework` | string | **Optional** | Agent framework from metadata | NIST AI RMF MAP-1.1 |
| `acp.agent.status.success_rate` | double | **Optional** | Agent success rate (0–100) | NIST AI RMF MEASURE-2.5 |
| `acp.agent.status.avg_run_time_seconds` | double | **Optional** | Average run time in seconds | NIST AI RMF MEASURE-2.5 |
| `acp.http.status_code` | int | **Recommended** | HTTP response status code | — |

---

## Span: `acp.run.create`

Represents creating and executing an agent run via `POST /runs`.

### Span Kind

`CLIENT`

### Normative Field Table

#### Run Identification

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `acp.run.agent_name` | string | **Required** | Agent name to execute | OWASP LLM06 (Excessive Agency), MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `acp.run.id` | string | **Recommended** | Server-assigned run UUID | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `acp.run.session_id` | string | **Recommended** | Session ID for stateful conversations | NIST AI RMF GOVERN-1.2 |
| `acp.operation` | string | **Required** | `"create_run"` | — |
| `acp.http.method` | string | **Required** | `"POST"` | — |

#### Execution Configuration

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `acp.run.mode` | string | **Required** | `"sync"`, `"async"`, or `"stream"` | NIST AI RMF MEASURE-2.5 |
| `acp.input.message_count` | int | **Recommended** | Number of input messages | — |
| `acp.run.status` | string | **Recommended** | Final run status (see Run States below) | NIST AI RMF MEASURE-2.5 |
| `acp.run.duration_ms` | double | **Recommended** | Total run duration in milliseconds | NIST AI RMF MEASURE-2.5, OWASP LLM10 |
| `acp.output.message_count` | int | **Recommended** | Number of output messages | — |

#### Error Handling

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `acp.run.error.code` | string | **Recommended** | Error code if failed: `"server_error"`, `"invalid_input"`, `"not_found"` | NIST AI RMF MEASURE-2.5 |
| `acp.run.error.message` | string | **Recommended** | Error message if failed | NIST AI RMF MEASURE-2.5 |
| `acp.http.status_code` | int | **Recommended** | HTTP response status code | — |

#### Await/Resume (Human-in-the-Loop)

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `acp.await.active` | boolean | **Recommended** | Whether the run is currently awaiting client input | EU AI Act Art.14 (Human Oversight) |
| `acp.await.count` | int | **Optional** | Number of await/resume cycles in this run | EU AI Act Art.14 |
| `acp.await.duration_ms` | double | **Optional** | Total time spent in awaiting state | — |

### Events

#### `acp.run.status_change`

Emitted when the run transitions to a new state.

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `acp.run.status` | string | **Required** | New status value | NIST AI RMF MEASURE-2.5 |

#### `acp.run.await`

Emitted when the run enters the `awaiting` state.

#### `acp.run.resume`

Emitted when the run is resumed from `awaiting`.

---

## Span: `acp.run.get`

Represents polling a run's status via `GET /runs/{run_id}`.

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `acp.run.id` | string | **Required** | Run UUID | NIST AI RMF GOVERN-1.2 |
| `acp.operation` | string | **Required** | `"get_run"` | — |
| `acp.http.method` | string | **Required** | `"GET"` | — |
| `acp.run.status` | string | **Recommended** | Current run status | NIST AI RMF MEASURE-2.5 |
| `acp.http.status_code` | int | **Recommended** | HTTP response status code | — |

---

## Span: `acp.run.cancel`

Represents canceling a running agent via `POST /runs/{run_id}/cancel`.

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `acp.run.id` | string | **Required** | Run UUID | NIST AI RMF GOVERN-1.2 |
| `acp.operation` | string | **Required** | `"cancel_run"` | — |
| `acp.http.method` | string | **Required** | `"POST"` | — |
| `acp.run.status` | string | **Recommended** | Status after cancel | OWASP LLM06 |
| `acp.http.status_code` | int | **Recommended** | HTTP response status code | — |

---

## Span: `acp.run.resume`

Represents resuming an awaiting run via `POST /runs/{run_id}/resume`.

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `acp.run.id` | string | **Required** | Run UUID | NIST AI RMF GOVERN-1.2 |
| `acp.operation` | string | **Required** | `"resume_run"` | — |
| `acp.http.method` | string | **Required** | `"POST"` | — |
| `acp.run.status` | string | **Recommended** | Status after resume | EU AI Act Art.14 |
| `acp.http.status_code` | int | **Recommended** | HTTP response status code | — |

---

## Run States

| Value | Description | Compliance |
|---|---|---|
| `created` | Run accepted, processing not started | — |
| `in-progress` | Agent is actively processing | — |
| `awaiting` | Paused, waiting for client input via await/resume | EU AI Act Art.14 (Human Oversight) |
| `cancelling` | Cancellation requested, being processed | — |
| `cancelled` | Successfully cancelled (terminal) | — |
| `completed` | Successfully finished (terminal) | — |
| `failed` | Error occurred (terminal) | NIST AI RMF MEASURE-2.5 |

---

## Example: ACP Run with Await/Resume

```
Span: acp.agent.discover research-agent
  acp.operation: "get_agent"
  acp.http.method: "GET"
  acp.agent.name: "research-agent"
  acp.agent.framework: "beeai"
  acp.agent.status.success_rate: 94.5
  acp.http.status_code: 200

Span: acp.run.create research-agent
  acp.run.agent_name: "research-agent"
  acp.run.mode: "async"
  acp.input.message_count: 1
  acp.run.id: "run-abc123"
  acp.run.session_id: "sess-xyz789"
  acp.run.status: "completed"
  acp.run.duration_ms: 5200.0
  acp.output.message_count: 2
  acp.await.count: 1
  Events:
    acp.run.status_change: {status: "created"}
    acp.run.status_change: {status: "in-progress"}
    acp.run.status_change: {status: "awaiting"}
    acp.run.await
    |
    +-- Span: acp.run.resume run-abc123
    |     acp.run.status: "in-progress"
    |     acp.run.resume
    |
    acp.run.status_change: {status: "completed"}
```

---

## References

- [ACP Official Documentation](https://agentcommunicationprotocol.dev/)
- [ACP GitHub Repository](https://github.com/i-am-bee/acp)
- [ACP OpenAPI Specification](https://github.com/i-am-bee/acp/blob/main/docs/spec/openapi.yaml)
- [ACP Agent Run Lifecycle](https://agentcommunicationprotocol.dev/core-concepts/agent-run-lifecycle)
