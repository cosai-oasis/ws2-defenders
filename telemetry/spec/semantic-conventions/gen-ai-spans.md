# GenAI Span Conventions (AI_INTERACTION)

Status: **Normative** | CoSAI WS2 Alignment: **AI_INTERACTION** | OCSF Class: **7001 Model Inference**

AITF preserves and extends OpenTelemetry GenAI span conventions for LLM inference operations. This specification defines the normative field requirements for AI interaction telemetry, aligned with CoSAI Working Stream 2 (Telemetry for AI) and mapped to applicable compliance and threat frameworks.

> **OTel Alignment Note:** This spec aligns with OpenTelemetry GenAI Semantic Conventions v1.38+.
> The following attributes are deprecated and replaced: `gen_ai.system` → `gen_ai.provider.name`,
> `gen_ai.prompt` → `gen_ai.input.messages`, `gen_ai.completion` → `gen_ai.output.messages`.
> Extension attributes use short namespaces (e.g., `cost.*`, `latency.*`, `security.*`) without the `aitf.` prefix.

Key words "MUST", "SHOULD", "MAY" follow [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Span: `gen_ai.inference`

Represents a single LLM inference request (chat completion, text completion, embedding).

### Span Name

Format: `{gen_ai.operation.name} {gen_ai.request.model}`

Examples:
- `chat gpt-4o`
- `chat claude-sonnet-4-5-20250929`
- `embeddings text-embedding-3-small`

### Span Kind

`CLIENT`

---

## Normative Field Table

Instrumentors MUST emit all Required fields. Instrumentors SHOULD emit Recommended fields when the data is available. Optional fields MAY be emitted for enhanced observability.

### Core Identification

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.provider.name` | string | **Required** | AI system provider identifier (e.g. `"openai"`, `"anthropic"`, `"bedrock"`) | MITRE ATLAS [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044), NIST AI RMF MAP-1.1 |
| `gen_ai.operation.name` | string | **Required** | Operation type: `"chat"`, `"text_completion"`, `"embeddings"` | NIST AI RMF MAP-1.1 |
| `gen_ai.request.model` | string | **Required** | Requested model identifier (e.g. `"gpt-4o"`, `"claude-sonnet-4-5-20250929"`) | MITRE ATLAS [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044), EU AI Act Art.13 |
| `gen_ai.conversation.id` | string | **Recommended** | Conversation or session identifier | NIST AI RMF GOVERN-1.2 |
| `server.address` | string | **Recommended** | API endpoint hostname | MITRE ATLAS [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044), NIST AI RMF MAP-1.5 |
| `server.port` | int | **Optional** | API endpoint port | NIST AI RMF MAP-1.5 |

### Request Configuration

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.request.max_tokens` | int | **Recommended** | Maximum tokens to generate | OWASP LLM10 (Unbounded Consumption) |
| `gen_ai.request.temperature` | double | **Recommended** | Sampling temperature (0.0–2.0) | NIST AI RMF MEASURE-2.5 |
| `gen_ai.request.top_p` | double | **Recommended** | Nucleus sampling parameter (0.0–1.0) | NIST AI RMF MEASURE-2.5 |
| `gen_ai.request.top_k` | int | **Optional** | Top-k sampling parameter | NIST AI RMF MEASURE-2.5 |
| `gen_ai.request.stop_sequences` | string[] | **Optional** | Stop sequences | — |
| `gen_ai.request.frequency_penalty` | double | **Optional** | Frequency penalty | NIST AI RMF MEASURE-2.5 |
| `gen_ai.request.presence_penalty` | double | **Optional** | Presence penalty | NIST AI RMF MEASURE-2.5 |
| `gen_ai.request.seed` | int | **Optional** | Random seed for reproducibility | NIST AI RMF MEASURE-2.5, EU AI Act Art.12 |
| `gen_ai.request.stream` | boolean | **Recommended** | Whether streaming is enabled | — |
| `gen_ai.tool.definitions` | string | **Recommended** | Tool/function definitions (JSON) | OWASP LLM06 (Excessive Agency) |
| `gen_ai.request.tool_choice` | string | **Optional** | Tool selection mode (`"auto"`, `"required"`, `"none"`) | OWASP LLM06 (Excessive Agency) |
| `gen_ai.request.response_format` | string | **Optional** | Expected response format (`"json_object"`, `"text"`) | — |
| `gen_ai.output.type` | string | **Optional** | Output type (e.g. `"text"`, `"json"`, `"tool_calls"`) | — |

### Prompt & Completion Content

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.input.messages` | string | **Recommended** | Input messages content (emitted as event `gen_ai.content.prompt`) | OWASP LLM01 (Prompt Injection), MITRE ATLAS [AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) |
| `gen_ai.system_prompt.hash` | string | **Recommended** | SHA-256 hash of system prompt (enables leak detection without storing content) | OWASP LLM07 (System Prompt Leakage), MITRE ATLAS [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051) |
| `gen_ai.output.messages` | string | **Recommended** | Output completion content (emitted as event `gen_ai.content.completion`) | OWASP LLM05 (Improper Output), OWASP LLM02 (Sensitive Info Disclosure) |

### Response Metadata

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.response.id` | string | **Recommended** | Provider-assigned response identifier | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `gen_ai.response.model` | string | **Recommended** | Actual model used (may differ from requested) | MITRE ATLAS [AML.T0044](https://atlas.mitre.org/techniques/AML.T0044), EU AI Act Art.13 |
| `gen_ai.response.finish_reasons` | string[] | **Recommended** | Finish reasons (`"stop"`, `"length"`, `"tool_calls"`, `"content_filter"`) | NIST AI RMF MEASURE-2.5 |

### Token Usage

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.usage.input_tokens` | int | **Required** | Input/prompt token count | OWASP LLM10 (Unbounded Consumption), NIST AI RMF MEASURE-2.5 |
| `gen_ai.usage.output_tokens` | int | **Required** | Output/completion token count | OWASP LLM10 (Unbounded Consumption), NIST AI RMF MEASURE-2.5 |
| `gen_ai.usage.cache_read.input_tokens` | int | **Optional** | Cached/prefix input tokens read | — |
| `gen_ai.usage.cache_creation.input_tokens` | int | **Optional** | Input tokens used to create cache entries | — |

### Latency & Performance

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `latency.total_ms` | double | **Required** | Total request latency in milliseconds | NIST AI RMF MEASURE-2.5, OWASP LLM10 |
| `latency.time_to_first_token_ms` | double | **Recommended** | Time to first token (streaming) in milliseconds | NIST AI RMF MEASURE-2.5 |
| `latency.tokens_per_second` | double | **Optional** | Token generation throughput | NIST AI RMF MEASURE-2.5 |
| `latency.queue_time_ms` | double | **Optional** | Time spent in request queue | — |
| `latency.inference_time_ms` | double | **Optional** | Pure inference time (excluding queue) | — |

### Cost Attribution

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `cost.total_cost` | double | **Recommended** | Total request cost in USD | OWASP LLM10 (Unbounded Consumption), NIST AI RMF GOVERN-1.5 |
| `cost.input_cost` | double | **Optional** | Input token cost in USD | OWASP LLM10 |
| `cost.output_cost` | double | **Optional** | Output token cost in USD | OWASP LLM10 |

### Security Enrichment

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `security.risk_score` | double | **Optional** | Security risk score (0–100) | OWASP LLM01–LLM10 |
| `quality.confidence` | double | **Optional** | Response confidence score (0.0–1.0) | NIST AI RMF MEASURE-2.5 |

---

## Tool Call Events

### Event: `gen_ai.tool.call`

Emitted when the model requests a tool/function call.

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.tool.name` | string | **Required** | Tool/function name | OWASP LLM06 (Excessive Agency) |
| `gen_ai.tool.call.id` | string | **Required** | Tool call identifier | NIST AI RMF GOVERN-1.2 |
| `gen_ai.tool.call.arguments` | string | **Recommended** | Tool arguments (JSON) | OWASP LLM01 (Prompt Injection) |
| `gen_ai.tool.type` | string | **Optional** | Tool type (`"function"`, `"extension"`, `"datastore"`) | OWASP LLM06 (Excessive Agency) |
| `gen_ai.tool.description` | string | **Optional** | Human-readable tool description | — |

### Event: `gen_ai.tool.result`

Emitted when a tool/function returns its result.

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.tool.name` | string | **Required** | Tool/function name | OWASP LLM06 |
| `gen_ai.tool.call.id` | string | **Required** | Tool call identifier | NIST AI RMF GOVERN-1.2 |
| `gen_ai.tool.call.result` | string | **Recommended** | Tool result content | OWASP LLM05 (Improper Output) |
| `gen_ai.operation.name` | string | **Recommended** | `"execute_tool"` for tool execution spans | NIST AI RMF MAP-1.1 |

---

## Span Status

- `OK` — Inference completed successfully
- `ERROR` — Inference failed (with error description in span status)

---

## CoSAI WS2 Field Mapping

Cross-reference between CoSAI WS2 `AI_INTERACTION` field names and AITF attribute keys:

| CoSAI WS2 Field | AITF Attribute | Notes |
|---|---|---|
| `ai.model.vendor` | `gen_ai.provider.name` | OTel GenAI convention |
| `ai.model.name` | `gen_ai.request.model` | OTel GenAI convention |
| `ai.model.endpoint` | `server.address` | OTel standard |
| `ai.input.prompt` | `gen_ai.input.messages` | Emitted as span event |
| `ai.system_prompt.hash` | `gen_ai.system_prompt.hash` | SHA-256 hash |
| `ai.output.completion` | `gen_ai.output.messages` | Emitted as span event |
| `ai.config.temperature` | `gen_ai.request.temperature` | OTel GenAI convention |
| `ai.config.top_p` | `gen_ai.request.top_p` | OTel GenAI convention |
| `ai.usage.prompt_tokens` | `gen_ai.usage.input_tokens` | OTel GenAI convention |
| `ai.usage.completion_tokens` | `gen_ai.usage.output_tokens` | OTel GenAI convention |
| `ai.latency_ms` | `latency.total_ms` | Extension attribute |
| `ai.finish_reason` | `gen_ai.response.finish_reasons` | Array of reasons |

---

## Example

```
Span: chat claude-sonnet-4-5-20250929
  Kind: CLIENT
  Status: OK
  Attributes:
    gen_ai.provider.name: "anthropic"
    gen_ai.operation.name: "chat"
    gen_ai.request.model: "claude-sonnet-4-5-20250929"
    gen_ai.request.max_tokens: 4096
    gen_ai.request.temperature: 0.7
    gen_ai.system_prompt.hash: "sha256:a3f2b8..."
    gen_ai.response.id: "msg_abc123"
    gen_ai.response.model: "claude-sonnet-4-5-20250929"
    gen_ai.response.finish_reasons: ["end_turn"]
    gen_ai.usage.input_tokens: 150
    gen_ai.usage.output_tokens: 500
    latency.total_ms: 1250.0
    cost.total_cost: 0.0075
  Events:
    gen_ai.content.prompt: {gen_ai.input.messages: "Explain AITF"}
    gen_ai.content.completion: {gen_ai.output.messages: "AITF is..."}
```

## Span: `gen_ai.embeddings`

Represents an embedding generation request.

### Span Name

Format: `embeddings {gen_ai.request.model}`

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.provider.name` | string | **Required** | Provider identifier | MITRE ATLAS AML.T0044 |
| `gen_ai.operation.name` | string | **Required** | `"embeddings"` | NIST AI RMF MAP-1.1 |
| `gen_ai.request.model` | string | **Required** | Embedding model identifier | MITRE ATLAS AML.T0044, EU AI Act Art.13 |
| `gen_ai.request.encoding_formats` | string[] | **Optional** | Encoding formats (e.g. `["float"]`, `["base64"]`) | — |
| `gen_ai.embeddings.dimension.count` | int | **Optional** | Embedding dimensions | — |
| `gen_ai.usage.input_tokens` | int | **Required** | Tokens processed | OWASP LLM10, NIST AI RMF MEASURE-2.5 |
| `latency.total_ms` | double | **Required** | Total latency in milliseconds | NIST AI RMF MEASURE-2.5 |
| `cost.total_cost` | double | **Recommended** | Cost in USD | OWASP LLM10 |
