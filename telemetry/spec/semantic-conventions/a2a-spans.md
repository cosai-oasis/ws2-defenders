# A2A Span Conventions (Agent-to-Agent Protocol)

Status: **Normative** | OCSF Class: **7002 Agent Activity** / **7003 Tool Execution**

AITF defines semantic conventions for the [Google A2A (Agent-to-Agent) protocol](https://a2a-protocol.org/), covering agent discovery via Agent Cards, task lifecycle (create, poll, cancel), message exchange (synchronous and streaming), and push notifications. A2A uses JSON-RPC 2.0 over HTTP(S) and enables cross-platform agent interoperability.

Key words "MUST", "SHOULD", "MAY" follow [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Overview

```
A2A Protocol Flow:
  discover (Agent Card) -> message/send or message/stream -> tasks/get (poll) -> tasks/cancel

Spans:
  a2a.agent.discover       (fetch Agent Card)
  a2a.message.send         (synchronous message)
  a2a.message.stream       (SSE streaming)
  a2a.task.get             (poll task status)
  a2a.task.cancel          (cancel running task)
```

---

## Span: `a2a.agent.discover`

Represents fetching and parsing an A2A Agent Card from `/.well-known/agent.json`.

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `a2a.agent.url` | string | **Required** | Agent service endpoint URL | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040), NIST AI RMF MAP-1.5 |
| `a2a.agent.name` | string | **Recommended** | Discovered agent name | OWASP LLM06 (Excessive Agency) |
| `a2a.agent.version` | string | **Recommended** | Agent version | NIST AI RMF MAP-1.1 |
| `a2a.agent.provider.organization` | string | **Optional** | Provider organization | EU AI Act Art.13 (Transparency) |
| `a2a.agent.skills` | string[] | **Recommended** | Skill IDs available | OWASP LLM06, NIST AI RMF MAP-1.1 |
| `a2a.agent.capabilities.streaming` | boolean | **Recommended** | Whether streaming is supported | — |
| `a2a.agent.capabilities.push_notifications` | boolean | **Optional** | Whether push notifications are supported | — |
| `a2a.protocol.version` | string | **Recommended** | A2A protocol version | NIST AI RMF MAP-1.1 |
| `a2a.transport` | string | **Recommended** | Transport: `"jsonrpc"`, `"grpc"`, `"http_json"` | MITRE ATLAS AML.T0040 |

---

## Span: `a2a.message.send`

Represents a synchronous `message/send` JSON-RPC call to a remote agent.

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `a2a.agent.name` | string | **Required** | Target agent name | OWASP LLM06, MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `a2a.method` | string | **Required** | `"message/send"` | NIST AI RMF GOVERN-1.2 |
| `a2a.interaction_mode` | string | **Required** | `"sync"` | — |
| `a2a.task.id` | string | **Recommended** | Server-assigned task ID | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `a2a.task.context_id` | string | **Recommended** | Context ID grouping related tasks | NIST AI RMF GOVERN-1.2 |
| `a2a.task.state` | string | **Recommended** | Final task state (see Task States below) | OWASP LLM06, NIST AI RMF MEASURE-2.5 |
| `a2a.agent.url` | string | **Optional** | Agent endpoint URL | MITRE ATLAS AML.T0040 |
| `a2a.message.id` | string | **Recommended** | Outgoing message ID | NIST AI RMF GOVERN-1.2 |
| `a2a.message.role` | string | **Recommended** | `"user"` (for outgoing) | — |
| `a2a.message.parts_count` | int | **Optional** | Number of message parts | — |
| `a2a.task.artifacts_count` | int | **Optional** | Number of artifacts produced | — |
| `a2a.jsonrpc.error_code` | int | **Recommended** | JSON-RPC error code (if error) | NIST AI RMF MEASURE-2.5 |
| `a2a.jsonrpc.error_message` | string | **Recommended** | JSON-RPC error message (if error) | NIST AI RMF MEASURE-2.5 |

---

## Span: `a2a.message.stream`

Represents a streaming `message/stream` JSON-RPC call with SSE response.

### Span Kind

`CLIENT`

### Normative Field Table

Same as `a2a.message.send` plus:

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `a2a.interaction_mode` | string | **Required** | `"stream"` | — |
| `a2a.stream.events_count` | int | **Recommended** | Total SSE events received | NIST AI RMF MEASURE-2.5 |

### Events

#### `a2a.stream.event`

Emitted for each SSE event received.

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `a2a.stream.event_type` | string | **Required** | `"status-update"` or `"artifact-update"` | — |
| `a2a.stream.is_final` | boolean | **Required** | Whether this is the terminal event | — |

---

## Span: `a2a.task.get`

Represents polling a task's status via `tasks/get`.

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `a2a.task.id` | string | **Required** | Task ID | NIST AI RMF GOVERN-1.2 |
| `a2a.method` | string | **Required** | `"tasks/get"` | — |
| `a2a.task.state` | string | **Recommended** | Current task state | NIST AI RMF MEASURE-2.5 |

---

## Span: `a2a.task.cancel`

Represents canceling a running task via `tasks/cancel`.

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `a2a.task.id` | string | **Required** | Task ID | NIST AI RMF GOVERN-1.2 |
| `a2a.method` | string | **Required** | `"tasks/cancel"` | — |
| `a2a.task.state` | string | **Recommended** | Task state after cancel | OWASP LLM06 |

---

## Task States

| Value | Description | Compliance |
|---|---|---|
| `submitted` | Task received, not yet started | — |
| `working` | Agent is actively processing | — |
| `input-required` | Agent needs additional input from client | EU AI Act Art.14 (Human Oversight) |
| `completed` | Successfully finished | — |
| `canceled` | Canceled by request | — |
| `failed` | Processing failed | NIST AI RMF MEASURE-2.5 |
| `rejected` | Agent refused the task | OWASP LLM06 |
| `auth-required` | Agent needs additional authentication | — |

---

## Example: A2A Agent Discovery + Message Send

```
Span: a2a.agent.discover
  a2a.agent.url: "https://research-agent.example.com"
  a2a.agent.name: "research-assistant"
  a2a.agent.version: "1.2.0"
  a2a.agent.skills: ["web_search", "summarize", "translate"]
  a2a.agent.capabilities.streaming: true
  a2a.protocol.version: "0.2.5"
  a2a.transport: "jsonrpc"

Span: a2a.message.send research-assistant
  a2a.method: "message/send"
  a2a.interaction_mode: "sync"
  a2a.task.id: "task-abc123"
  a2a.task.context_id: "ctx-xyz789"
  a2a.task.state: "completed"
  a2a.task.artifacts_count: 1
  Events:
    a2a.task.state_change: {a2a.task.state: "submitted"}
    a2a.message: {message_id: "msg-001", role: "user", parts_count: 1}
    a2a.task.state_change: {a2a.task.state: "completed"}
```

---

## References

- [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [A2A GitHub Repository](https://github.com/a2aproject/A2A)
- [A2A Protocol Definitions](https://a2a-protocol.org/latest/definitions/)
