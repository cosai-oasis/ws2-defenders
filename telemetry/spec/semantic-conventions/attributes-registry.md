# AITF Attributes Registry

Complete registry of all AITF semantic convention attributes. Organized by namespace.

All tables use normative requirement levels per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119):

- **Required**: Implementations MUST populate this attribute.
- **Recommended**: Implementations SHOULD populate this attribute when available.
- **Optional**: Implementations MAY populate this attribute.

The **Mapping** column maps each attribute to applicable frameworks: MITRE ATLAS, OWASP LLM Top 10, NIST AI RMF, EU AI Act. A dash (`—`) indicates no specific framework mapping.

---

## GenAI Attributes

### `gen_ai.provider.name`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.provider.name` | string | **Required** | AI system provider | NIST AI RMF MAP-1.1 |
| `gen_ai.operation.name` | string | **Required** | Operation being performed: `"chat"`, `"text_completion"`, `"embeddings"` | NIST AI RMF MAP-1.1 |

### `gen_ai.request.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.request.model` | string | **Required** | Model identifier | NIST AI RMF MAP-1.1, EU AI Act Art.13 |
| `gen_ai.request.max_tokens` | int | **Recommended** | Max tokens to generate | NIST AI RMF MEASURE-2.5 |
| `gen_ai.request.temperature` | double | **Recommended** | Sampling temperature | NIST AI RMF MEASURE-2.5 |
| `gen_ai.request.top_p` | double | **Optional** | Nucleus sampling parameter | NIST AI RMF MEASURE-2.5 |
| `gen_ai.request.top_k` | int | **Optional** | Top-k sampling parameter | — |
| `gen_ai.request.stop_sequences` | string[] | **Optional** | Stop sequences | — |
| `gen_ai.request.frequency_penalty` | double | **Optional** | Frequency penalty | — |
| `gen_ai.request.presence_penalty` | double | **Optional** | Presence penalty | — |
| `gen_ai.request.seed` | int | **Optional** | Random seed for reproducibility | NIST AI RMF MEASURE-2.5 |
| `gen_ai.request.tools` | string | **Recommended** | JSON-encoded tools/functions | OWASP LLM06 (Excessive Agency) |
| `gen_ai.request.tool_choice` | string | **Recommended** | Tool choice mode: `"auto"`, `"required"`, `"none"` | OWASP LLM06 (Excessive Agency) |
| `gen_ai.request.response_format` | string | **Optional** | Response format: `"json_object"`, `"text"` | — |
| `gen_ai.request.stream` | boolean | **Optional** | Whether streaming is enabled | — |

### `gen_ai.system_prompt.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.system_prompt.hash` | string | **Recommended** | SHA-256 hash of system prompt (enables leak detection without storing content) | OWASP LLM07 (System Prompt Leakage), MITRE ATLAS [AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) |

### `gen_ai.response.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.response.id` | string | **Recommended** | Provider response ID | NIST AI RMF GOVERN-1.2 |
| `gen_ai.response.model` | string | **Recommended** | Actual model used (may differ from requested) | NIST AI RMF MAP-1.1, EU AI Act Art.13 |
| `gen_ai.response.finish_reasons` | string[] | **Recommended** | Finish reasons: `"stop"`, `"tool_calls"`, `"length"` | NIST AI RMF MEASURE-2.5 |

### `gen_ai.usage.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.usage.input_tokens` | int | **Recommended** | Input/prompt token count | NIST AI RMF MEASURE-2.5 |
| `gen_ai.usage.output_tokens` | int | **Recommended** | Output/completion token count | NIST AI RMF MEASURE-2.5 |
| `gen_ai.usage.cached_tokens` | int | **Optional** | Cached/prefix token count | — |
| `gen_ai.usage.reasoning_tokens` | int | **Optional** | Reasoning/thinking token count | — |

### `gen_ai.token.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.token.type` | string | **Optional** | Token type: `"input"`, `"output"` | — |

---

## Agent Attributes (OTel gen_ai.agent.*)

### `gen_ai.agent.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.agent.name` | string | **Required** | Agent name | NIST AI RMF MAP-1.1 |
| `gen_ai.agent.id` | string | **Required** | Unique agent instance ID | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `gen_ai.agent.type` | string | **Recommended** | Agent type: `"conversational"`, `"autonomous"`, `"reactive"` | NIST AI RMF MAP-1.1 |
| `gen_ai.agent.framework` | string | **Recommended** | Agent framework: `"langchain"`, `"crewai"`, `"autogen"`, `"semantic_kernel"` | NIST AI RMF MAP-1.1 |
| `gen_ai.agent.version` | string | **Recommended** | Agent version | NIST AI RMF MAP-1.1 |
| `gen_ai.agent.description` | string | **Optional** | Agent description/role | EU AI Act Art.13 (Transparency) |
| `gen_ai.agent.workflow_id` | string | **Recommended** | Workflow/DAG identifier linking related agent sessions | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `gen_ai.agent.state` | string | **Recommended** | Agent lifecycle state: `"initializing"`, `"planning"`, `"executing"`, `"waiting"`, `"completed"`, `"failed"`, `"suspended"` | OWASP LLM06, MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `gen_ai.agent.scratchpad` | string | **Optional** | Accumulated agent scratchpad/working memory (JSON) | OWASP LLM02, MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `gen_ai.agent.next_action` | string | **Recommended** | Next planned action (forward-looking intent) | OWASP LLM06, MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |

### `gen_ai.agent.session.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.conversation.id` | string | **Required** | Agent session ID | NIST AI RMF GOVERN-1.2 |
| `gen_ai.agent.session.turn_count` | int | **Recommended** | Number of turns in session | NIST AI RMF MEASURE-2.5 |
| `gen_ai.agent.session.start_time` | string | **Recommended** | Session start ISO 8601 timestamp | EU AI Act Art.12 |

### `gen_ai.agent.step.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.agent.step.type` | string | **Required** | Step type: `"planning"`, `"reasoning"`, `"tool_use"`, `"delegation"`, `"response"` | NIST AI RMF MAP-1.1 |
| `gen_ai.agent.step.index` | int | **Required** | Step index in sequence | NIST AI RMF GOVERN-1.2 |
| `gen_ai.agent.step.thought` | string | **Recommended** | Agent's reasoning/chain-of-thought | OWASP LLM01 (Prompt Injection) |
| `gen_ai.agent.step.action` | string | **Recommended** | Planned action | OWASP LLM06 (Excessive Agency), MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `gen_ai.agent.step.observation` | string | **Optional** | Observation from action execution | NIST AI RMF MEASURE-2.5 |

### `gen_ai.agent.delegation.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.agent.delegation.target_agent` | string | **Required** | Delegated-to agent name | OWASP LLM06 (Excessive Agency) |
| `gen_ai.agent.delegation.target_agent_id` | string | **Recommended** | Delegated-to agent ID | NIST AI RMF GOVERN-1.2 |
| `gen_ai.agent.delegation.reason` | string | **Recommended** | Why delegation occurred | EU AI Act Art.13 (Transparency) |
| `gen_ai.agent.delegation.strategy` | string | **Optional** | Delegation strategy: `"round_robin"`, `"capability"`, `"hierarchical"` | NIST AI RMF MAP-1.1 |

### `gen_ai.agent.team.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.agent.team.name` | string | **Required** | Team name | NIST AI RMF MAP-1.1 |
| `gen_ai.agent.team.id` | string | **Recommended** | Team ID | NIST AI RMF GOVERN-1.2 |
| `gen_ai.agent.team.topology` | string | **Recommended** | Team topology: `"hierarchical"`, `"peer"`, `"pipeline"`, `"consensus"` | NIST AI RMF MAP-1.1 |
| `gen_ai.agent.team.members` | string[] | **Recommended** | Member agent names | OWASP LLM06 (Excessive Agency) |
| `gen_ai.agent.team.coordinator` | string | **Recommended** | Coordinator agent name | OWASP LLM06 (Excessive Agency) |

---

## MCP Attributes

### `mcp.server.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `mcp.server.name` | string | **Required** | MCP server name | NIST AI RMF MAP-1.1 |
| `mcp.server.version` | string | **Recommended** | MCP server version | NIST AI RMF MAP-1.1 |
| `mcp.server.transport` | string | **Required** | Transport type: `"stdio"`, `"sse"`, `"streamable_http"` | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `mcp.server.url` | string | **Recommended** | Server URL (if network transport) | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `mcp.protocol.version` | string | **Recommended** | MCP protocol version | NIST AI RMF MAP-1.1 |
| `mcp.connection.id` | string | **Recommended** | Unique connection identifier for session correlation | NIST AI RMF GOVERN-1.2 |

### `mcp.tool.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.tool.name` | string | **Required** | Tool name | OWASP LLM06 (Excessive Agency) |
| `mcp.tool.server` | string | **Required** | Source MCP server | OWASP LLM06 (Excessive Agency) |
| `gen_ai.tool.call.arguments` | string | **Recommended** | JSON input parameters | OWASP LLM06, MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `gen_ai.tool.call.result` | string | **Optional** | Tool output (may be redacted) | OWASP LLM06 |
| `mcp.tool.is_error` | boolean | **Recommended** | Whether tool returned error | NIST AI RMF MEASURE-2.5 |
| `mcp.tool.response_error` | string | **Recommended** | Error message content when tool execution fails | NIST AI RMF MEASURE-2.5 |
| `mcp.tool.duration_ms` | double | **Recommended** | Tool execution time in milliseconds | NIST AI RMF MEASURE-2.5 |
| `mcp.tool.approval_required` | boolean | **Recommended** | Whether human approval is needed | EU AI Act Art.14 (Human Oversight) |
| `mcp.tool.approved` | boolean | **Recommended** | Whether approved (if required) | EU AI Act Art.14 (Human Oversight) |

### `mcp.resource.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `mcp.resource.uri` | string | **Required** | Resource URI | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `mcp.resource.name` | string | **Recommended** | Resource name | — |
| `mcp.resource.mime_type` | string | **Recommended** | MIME type | — |
| `mcp.resource.size_bytes` | int | **Optional** | Size in bytes | — |

### `mcp.prompt.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `mcp.prompt.name` | string | **Required** | Prompt template name | OWASP LLM01 (Prompt Injection) |
| `mcp.prompt.arguments` | string | **Recommended** | JSON prompt arguments | OWASP LLM01 |
| `mcp.prompt.description` | string | **Optional** | Prompt description | — |

### `mcp.sampling.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `mcp.sampling.model` | string | **Recommended** | Requested model for sampling | NIST AI RMF MAP-1.1 |
| `mcp.sampling.max_tokens` | int | **Recommended** | Max tokens requested | NIST AI RMF MEASURE-2.5 |
| `mcp.sampling.include_context` | string | **Optional** | Context inclusion: `"thisServer"`, `"allServers"` | — |

---

## AITF Skills Attributes

### `skill.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `skill.name` | string | **Required** | Skill name | NIST AI RMF MAP-1.1 |
| `skill.id` | string | **Required** | Unique skill ID | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `skill.version` | string | **Recommended** | Skill version | NIST AI RMF MAP-1.1 |
| `skill.provider` | string | **Recommended** | Skill provider: `"builtin"`, `"marketplace"`, `"custom"` | NIST AI RMF MAP-1.5 |
| `skill.category` | string | **Recommended** | Skill category: `"search"`, `"code"`, `"data"`, `"communication"` | NIST AI RMF MAP-1.1 |
| `skill.description` | string | **Optional** | Skill description | EU AI Act Art.13 (Transparency) |
| `skill.input` | string | **Recommended** | Skill input (JSON) | OWASP LLM06 (Excessive Agency), MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `skill.output` | string | **Optional** | Skill output (may be redacted) | OWASP LLM06 |
| `skill.status` | string | **Recommended** | Execution status: `"success"`, `"error"`, `"timeout"`, `"denied"` | NIST AI RMF MEASURE-2.5 |
| `skill.duration_ms` | double | **Recommended** | Execution time in milliseconds | NIST AI RMF MEASURE-2.5 |
| `skill.retry_count` | int | **Optional** | Number of retries | NIST AI RMF MEASURE-2.5 |
| `skill.source` | string | **Optional** | Where skill was sourced: `"mcp:filesystem"`, `"api:openai"`, `"local"` | NIST AI RMF MAP-1.5, MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `skill.permissions` | string[] | **Recommended** | Required permissions | OWASP LLM06 (Excessive Agency), EU AI Act Art.14 |
| `skill.hash` | string | **Optional** | Content hash (SHA-256) for change detection | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040), NIST AI RMF GOVERN-1.2 |
| `skill.authors` | string[] | **Optional** | Skill authors/maintainers | EU AI Act Art.13 (Transparency), NIST AI RMF MAP-1.5 |

---

## RAG Attributes

### `rag.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `rag.pipeline.name` | string | **Required** | Pipeline name | NIST AI RMF MAP-1.1 |
| `rag.pipeline.stage` | string | **Required** | Current stage: `"retrieve"`, `"rerank"`, `"generate"`, `"evaluate"` | NIST AI RMF MAP-1.1 |
| `gen_ai.retrieval.query.text` | string | **Recommended** | User query | OWASP LLM01 (Prompt Injection) |
| `rag.query.embedding_model` | string | **Recommended** | Embedding model used | NIST AI RMF MAP-1.1 |
| `rag.query.embedding_dimensions` | int | **Optional** | Embedding dimensions | — |

### `rag.retrieve.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `gen_ai.data_source.id` | string | **Required** | Vector database name | NIST AI RMF MAP-1.5 |
| `rag.retrieve.index` | string | **Recommended** | Index/collection name | — |
| `rag.retrieve.top_k` | int | **Recommended** | Number of results requested | NIST AI RMF MEASURE-2.5 |
| `rag.retrieve.results_count` | int | **Recommended** | Actual results returned | NIST AI RMF MEASURE-2.5 |
| `rag.retrieve.min_score` | double | **Optional** | Minimum similarity score | NIST AI RMF MEASURE-2.5 |
| `rag.retrieve.max_score` | double | **Optional** | Maximum similarity score | NIST AI RMF MEASURE-2.5 |
| `rag.retrieve.filter` | string | **Optional** | Metadata filter (JSON) | — |

### `rag.doc.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `rag.doc.id` | string | **Recommended** | Document/chunk identifier | NIST AI RMF MAP-1.5, EU AI Act Art.12 |
| `rag.doc.score` | double | **Recommended** | Similarity/relevance score (0.0–1.0) | OWASP LLM08 (Data Leakage), NIST AI RMF MEASURE-2.5 |
| `rag.doc.provenance` | string | **Recommended** | Document source/origin URL or identifier | OWASP LLM09, EU AI Act Art.13 (Transparency) |
| `rag.retrieval.docs` | string | **Recommended** | JSON array of retrieved document summaries | OWASP LLM08, MITRE ATLAS [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043) |

### `rag.rerank.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `rag.rerank.model` | string | **Recommended** | Reranking model | NIST AI RMF MAP-1.1 |
| `rag.rerank.input_count` | int | **Recommended** | Documents before rerank | NIST AI RMF MEASURE-2.5 |
| `rag.rerank.output_count` | int | **Recommended** | Documents after rerank | NIST AI RMF MEASURE-2.5 |

### `rag.quality.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `rag.quality.context_relevance` | double | **Optional** | Context relevance score (0–1) | NIST AI RMF MEASURE-2.5 |
| `rag.quality.answer_relevance` | double | **Optional** | Answer relevance score (0–1) | NIST AI RMF MEASURE-2.5 |
| `rag.quality.faithfulness` | double | **Optional** | Answer faithfulness to context (0–1) | OWASP LLM03, NIST AI RMF MEASURE-2.5 |
| `rag.quality.groundedness` | double | **Optional** | How grounded in sources (0–1) | OWASP LLM03, NIST AI RMF MEASURE-2.5 |

---

## Security Attributes

### `security.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `security.risk_score` | double | **Recommended** | Overall risk score (0–100) | NIST AI RMF MEASURE-2.5, MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `security.risk_level` | string | **Recommended** | Risk level: `"critical"`, `"high"`, `"medium"`, `"low"`, `"info"` | NIST AI RMF MEASURE-2.5 |
| `security.threat_detected` | boolean | **Required** | Whether threat detected | OWASP LLM01–LLM10, MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `security.threat_type` | string | **Recommended** | Type of threat: `"prompt_injection"`, `"data_exfiltration"`, `"jailbreak"` | OWASP LLM01, MITRE ATLAS [AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) |
| `security.owasp_category` | string | **Recommended** | OWASP LLM category: `"LLM01"` through `"LLM10"` | OWASP LLM01–LLM10 |
| `security.blocked` | boolean | **Recommended** | Whether request was blocked | EU AI Act Art.14 (Human Oversight) |
| `security.detection_method` | string | **Recommended** | How threat was detected: `"pattern"`, `"ml_model"`, `"guardrail"`, `"policy"` | NIST AI RMF MEASURE-2.5 |
| `security.confidence` | double | **Recommended** | Detection confidence (0–1) | NIST AI RMF MEASURE-2.5 |

### `security.guardrail.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `security.guardrail.name` | string | **Required** | Guardrail name | NIST AI RMF GOVERN-1.2 |
| `security.guardrail.type` | string | **Required** | Guardrail type: `"input"`, `"output"`, `"both"` | OWASP LLM01, OWASP LLM02 |
| `security.guardrail.result` | string | **Required** | Guardrail result: `"pass"`, `"fail"`, `"warn"` | NIST AI RMF MEASURE-2.5 |
| `security.guardrail.provider` | string | **Recommended** | Guardrail provider: `"nemo"`, `"guardrails_ai"`, `"llm_guard"`, `"bedrock"` | NIST AI RMF MAP-1.5 |
| `security.guardrail.policy` | string | **Recommended** | Policy violated (if any) | NIST AI RMF GOVERN-1.2 |

### `security.pii.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `security.pii.detected` | boolean | **Required** | Whether PII found | OWASP LLM06, EU AI Act Art.10 |
| `security.pii.types` | string[] | **Recommended** | Types of PII found: `"email"`, `"phone"`, `"ssn"` | OWASP LLM06, EU AI Act Art.10 |
| `security.pii.count` | int | **Recommended** | Number of PII instances | NIST AI RMF MEASURE-2.5 |
| `security.pii.action` | string | **Recommended** | Action taken: `"redacted"`, `"flagged"`, `"hashed"`, `"allowed"` | EU AI Act Art.10, NIST AI RMF GOVERN-1.2 |

---

## Compliance Attributes

### `compliance.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `compliance.frameworks` | string[] | **Recommended** | Mapped compliance frameworks | NIST AI RMF GOVERN-1.2, EU AI Act Art.9 |
| `compliance.nist_ai_rmf.controls` | string[] | **Optional** | NIST AI RMF controls | NIST AI RMF GOVERN-1.2 |
| `compliance.mitre_atlas.techniques` | string[] | **Optional** | MITRE ATLAS techniques | MITRE ATLAS |
| `compliance.iso_42001.controls` | string[] | **Optional** | ISO 42001 controls | ISO 42001 |
| `compliance.eu_ai_act.articles` | string[] | **Optional** | EU AI Act articles | EU AI Act Art.9 |
| `compliance.soc2.controls` | string[] | **Optional** | SOC 2 controls | SOC 2 |
| `compliance.gdpr.articles` | string[] | **Optional** | GDPR articles | GDPR Art.5, Art.22 |
| `compliance.ccpa.sections` | string[] | **Optional** | CCPA sections | CCPA |
| `compliance.csa_aicm.controls` | string[] | **Optional** | CSA AI Controls Matrix controls | CSA AICM |

---

## Cost Attributes

### `cost.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `cost.input_cost` | double | **Recommended** | Cost for input tokens (USD) | NIST AI RMF MEASURE-2.5 |
| `cost.output_cost` | double | **Recommended** | Cost for output tokens (USD) | NIST AI RMF MEASURE-2.5 |
| `cost.total_cost` | double | **Recommended** | Total cost (USD) | NIST AI RMF MEASURE-2.5, OWASP LLM10 (Unbounded Consumption) |
| `cost.currency` | string | **Recommended** | Currency code (ISO 4217) | — |
| `cost.model_pricing.input_per_1m` | double | **Optional** | Input price per 1M tokens | — |
| `cost.model_pricing.output_per_1m` | double | **Optional** | Output price per 1M tokens | — |
| `cost.budget.limit` | double | **Optional** | Budget limit (USD) | OWASP LLM10 (Unbounded Consumption) |
| `cost.budget.used` | double | **Optional** | Budget used (USD) | OWASP LLM10 (Unbounded Consumption) |
| `cost.budget.remaining` | double | **Optional** | Budget remaining (USD) | OWASP LLM10 (Unbounded Consumption) |
| `cost.attribution.user` | string | **Optional** | User for cost attribution | NIST AI RMF GOVERN-1.2 |
| `cost.attribution.team` | string | **Optional** | Team for cost attribution | NIST AI RMF GOVERN-1.2 |
| `cost.attribution.project` | string | **Optional** | Project for cost attribution | NIST AI RMF GOVERN-1.2 |

---

## Quality Attributes

### `quality.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `quality.hallucination_score` | double | **Optional** | Hallucination score (0–1, lower = better) | OWASP LLM03, NIST AI RMF MEASURE-2.5 |
| `quality.confidence` | double | **Optional** | Confidence score (0–1) | NIST AI RMF MEASURE-2.5 |
| `quality.factuality` | double | **Optional** | Factual accuracy (0–1) | OWASP LLM03, NIST AI RMF MEASURE-2.5 |
| `quality.coherence` | double | **Optional** | Response coherence (0–1) | NIST AI RMF MEASURE-2.5 |
| `quality.toxicity_score` | double | **Optional** | Toxicity score (0–1, lower = better) | OWASP LLM05, NIST AI RMF MEASURE-2.5 |
| `quality.bias_score` | double | **Optional** | Bias score (0–1, lower = better) | NIST AI RMF MEASURE-2.5, EU AI Act Art.10 |
| `quality.feedback.rating` | double | **Optional** | User rating (1–5) | NIST AI RMF MEASURE-2.5 |
| `quality.feedback.thumbs` | string | **Optional** | User feedback: `"up"`, `"down"` | NIST AI RMF MEASURE-2.5 |

---

## Supply Chain Attributes

### `supply_chain.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `supply_chain.model.source` | string | **Recommended** | Model source: `"huggingface"`, `"openai"`, `"custom"` | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040), NIST AI RMF MAP-1.5 |
| `supply_chain.model.hash` | string | **Recommended** | Model file hash (SHA-256) | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040), NIST AI RMF GOVERN-1.2 |
| `supply_chain.model.license` | string | **Recommended** | Model license | EU AI Act Art.13 (Transparency) |
| `supply_chain.model.training_data` | string | **Optional** | Training data description | EU AI Act Art.10, NIST AI RMF MAP-1.1 |
| `supply_chain.model.signed` | boolean | **Optional** | Whether model is cryptographically signed | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `supply_chain.model.signer` | string | **Optional** | Model signer identity | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `supply_chain.ai_bom.id` | string | **Optional** | AI Bill of Materials ID | EU AI Act Art.13, NIST AI RMF MAP-1.5 |
| `supply_chain.ai_bom.components` | string | **Optional** | JSON list of AI BOM components | EU AI Act Art.13, NIST AI RMF MAP-1.5 |

---

## AITF Memory Attributes

### `memory.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `memory.operation` | string | **Required** | Memory operation: `"store"`, `"retrieve"`, `"update"`, `"delete"` | NIST AI RMF GOVERN-1.2 |
| `memory.store` | string | **Recommended** | Memory store type: `"short_term"`, `"long_term"`, `"episodic"`, `"semantic"` | NIST AI RMF MAP-1.1 |
| `memory.key` | string | **Recommended** | Memory key | NIST AI RMF GOVERN-1.2 |
| `memory.ttl_seconds` | int | **Optional** | Time to live in seconds | — |
| `memory.hit` | boolean | **Recommended** | Whether memory was found | NIST AI RMF MEASURE-2.5 |
| `memory.provenance` | string | **Recommended** | Origin of memory entry: `"conversation"`, `"tool_result"`, `"imported"` | OWASP LLM03, MITRE ATLAS [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) |

---

## AITF Model Operations (LLMOps/MLOps) Attributes

### `model_ops.training.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `model_ops.training.run_id` | string | **Required** | Training run identifier | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `model_ops.training.type` | string | **Required** | Training type: `"fine_tuning"`, `"lora"`, `"rlhf"`, `"dpo"` | NIST AI RMF MAP-1.1 |
| `model_ops.training.base_model` | string | **Required** | Base/foundation model | NIST AI RMF MAP-1.1, EU AI Act Art.13 |
| `model_ops.training.framework` | string | **Recommended** | Training framework: `"pytorch"`, `"transformers"`, `"jax"` | NIST AI RMF MAP-1.1 |
| `model_ops.training.dataset.id` | string | **Required** | Training dataset ID | NIST AI RMF MAP-1.5, EU AI Act Art.10 |
| `model_ops.training.dataset.version` | string | **Recommended** | Dataset version hash | NIST AI RMF GOVERN-1.2 |
| `model_ops.training.dataset.size` | int | **Recommended** | Training examples count | EU AI Act Art.10 |
| `model_ops.training.hyperparameters` | string | **Recommended** | JSON hyperparameters | NIST AI RMF MEASURE-2.5 |
| `model_ops.training.epochs` | int | **Recommended** | Training epochs | NIST AI RMF MEASURE-2.5 |
| `model_ops.training.batch_size` | int | **Optional** | Batch size | — |
| `model_ops.training.learning_rate` | double | **Recommended** | Learning rate | NIST AI RMF MEASURE-2.5 |
| `model_ops.training.loss_final` | double | **Recommended** | Final training loss | NIST AI RMF MEASURE-2.5 |
| `model_ops.training.val_loss_final` | double | **Recommended** | Final validation loss | NIST AI RMF MEASURE-2.5 |
| `model_ops.training.compute.gpu_type` | string | **Optional** | GPU type: `"H100"`, `"A100"` | — |
| `model_ops.training.compute.gpu_count` | int | **Optional** | GPU count | — |
| `model_ops.training.compute.gpu_hours` | double | **Optional** | Total GPU hours | — |
| `model_ops.training.output_model.id` | string | **Required** | Output model ID | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `model_ops.training.output_model.hash` | string | **Recommended** | Output model hash (SHA-256) | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `model_ops.training.code_commit` | string | **Recommended** | Code commit SHA | NIST AI RMF GOVERN-1.2 |
| `model_ops.training.experiment.id` | string | **Optional** | Experiment tracker ID | NIST AI RMF GOVERN-1.2 |
| `model_ops.training.experiment.name` | string | **Optional** | Experiment name | — |
| `model_ops.training.status` | string | **Required** | Run status: `"running"`, `"completed"`, `"failed"` | NIST AI RMF MEASURE-2.5 |

### `model_ops.evaluation.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `model_ops.evaluation.run_id` | string | **Required** | Evaluation run ID | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `model_ops.evaluation.model_id` | string | **Required** | Model being evaluated | NIST AI RMF GOVERN-1.2 |
| `model_ops.evaluation.type` | string | **Required** | Evaluation type: `"benchmark"`, `"llm_judge"`, `"safety"` | NIST AI RMF MEASURE-2.5 |
| `model_ops.evaluation.dataset.id` | string | **Required** | Eval dataset ID | NIST AI RMF MAP-1.5, EU AI Act Art.10 |
| `model_ops.evaluation.dataset.version` | string | **Recommended** | Dataset version | NIST AI RMF GOVERN-1.2 |
| `model_ops.evaluation.dataset.size` | int | **Recommended** | Eval examples count | EU AI Act Art.10 |
| `model_ops.evaluation.metrics` | string | **Recommended** | JSON metric results | NIST AI RMF MEASURE-2.5 |
| `model_ops.evaluation.judge_model` | string | **Optional** | LLM-as-judge model | NIST AI RMF MEASURE-2.5 |
| `model_ops.evaluation.baseline_model` | string | **Optional** | Baseline model for comparison | NIST AI RMF MEASURE-2.5 |
| `model_ops.evaluation.regression_detected` | boolean | **Recommended** | Regression detected | NIST AI RMF MEASURE-2.5 |
| `model_ops.evaluation.pass` | boolean | **Recommended** | Passed quality gates | NIST AI RMF MEASURE-2.5 |

### `model_ops.registry.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `model_ops.registry.operation` | string | **Required** | Registry operation: `"register"`, `"promote"`, `"rollback"` | NIST AI RMF GOVERN-1.2 |
| `model_ops.registry.model_id` | string | **Required** | Model identifier | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `model_ops.registry.model_version` | string | **Required** | Model version | NIST AI RMF GOVERN-1.2 |
| `model_ops.registry.model_alias` | string | **Optional** | Model alias | — |
| `model_ops.registry.stage` | string | **Required** | Lifecycle stage: `"staging"`, `"production"`, `"archived"` | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `model_ops.registry.previous_stage` | string | **Recommended** | Previous lifecycle stage | NIST AI RMF GOVERN-1.2 |
| `model_ops.registry.owner` | string | **Recommended** | Model owner | NIST AI RMF GOVERN-1.2 |
| `model_ops.registry.lineage.training_run_id` | string | **Recommended** | Producing training run ID | NIST AI RMF MAP-1.5, EU AI Act Art.12 |
| `model_ops.registry.lineage.parent_model_id` | string | **Recommended** | Parent model ID | NIST AI RMF MAP-1.5, EU AI Act Art.13 |

### `model_ops.deployment.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `model_ops.deployment.id` | string | **Required** | Deployment identifier | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `model_ops.deployment.model_id` | string | **Required** | Model being deployed | NIST AI RMF GOVERN-1.2 |
| `model_ops.deployment.strategy` | string | **Recommended** | Deployment strategy: `"canary"`, `"blue_green"`, `"rolling"` | NIST AI RMF GOVERN-1.2 |
| `model_ops.deployment.model_version` | string | **Required** | Model version | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `model_ops.deployment.environment` | string | **Required** | Target environment: `"production"`, `"staging"` | NIST AI RMF GOVERN-1.2 |
| `model_ops.deployment.endpoint` | string | **Recommended** | Serving endpoint URL | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `model_ops.deployment.canary_percent` | double | **Optional** | Canary traffic percentage | NIST AI RMF MEASURE-2.5 |
| `model_ops.deployment.infrastructure.provider` | string | **Optional** | Infrastructure provider: `"aws"`, `"gcp"` | — |
| `model_ops.deployment.infrastructure.gpu_type` | string | **Optional** | GPU type | — |
| `model_ops.deployment.infrastructure.replicas` | int | **Optional** | Replica count | — |
| `model_ops.deployment.status` | string | **Required** | Deployment status: `"completed"`, `"failed"`, `"rolled_back"` | NIST AI RMF MEASURE-2.5 |
| `model_ops.deployment.health_check.status` | string | **Recommended** | Health status: `"healthy"`, `"degraded"` | NIST AI RMF MEASURE-2.5 |

### `model_ops.serving.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `model_ops.serving.operation` | string | **Required** | Serving operation: `"route"`, `"fallback"`, `"cache_lookup"` | NIST AI RMF MAP-1.1 |
| `model_ops.serving.route.selected_model` | string | **Recommended** | Model selected by router | NIST AI RMF MAP-1.1, EU AI Act Art.13 |
| `model_ops.serving.route.reason` | string | **Recommended** | Routing reason: `"cost"`, `"capability"`, `"latency"` | EU AI Act Art.13 (Transparency) |
| `model_ops.serving.route.candidates` | string[] | **Optional** | Candidate models | — |
| `model_ops.serving.fallback.chain` | string[] | **Optional** | Fallback chain | NIST AI RMF MEASURE-2.5 |
| `model_ops.serving.fallback.depth` | int | **Optional** | Fallback depth | NIST AI RMF MEASURE-2.5 |
| `model_ops.serving.fallback.trigger` | string | **Optional** | Fallback trigger: `"timeout"`, `"error"`, `"rate_limit"` | NIST AI RMF MEASURE-2.5 |
| `model_ops.serving.cache.hit` | boolean | **Recommended** | Cache hit | NIST AI RMF MEASURE-2.5 |
| `model_ops.serving.cache.type` | string | **Optional** | Cache type: `"exact"`, `"semantic"` | — |
| `model_ops.serving.cache.similarity_score` | double | **Optional** | Semantic similarity score | — |
| `model_ops.serving.cache.cost_saved_usd` | double | **Optional** | Cost saved by cache (USD) | OWASP LLM10 (Unbounded Consumption) |
| `model_ops.serving.circuit_breaker.state` | string | **Optional** | Circuit breaker state: `"closed"`, `"open"`, `"half_open"` | NIST AI RMF MEASURE-2.5 |

### `model_ops.monitoring.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `model_ops.monitoring.check_type` | string | **Required** | Monitoring check type: `"data_drift"`, `"embedding_drift"` | NIST AI RMF MEASURE-2.5 |
| `model_ops.monitoring.model_id` | string | **Required** | Monitored model | NIST AI RMF GOVERN-1.2 |
| `model_ops.monitoring.result` | string | **Required** | Check result: `"normal"`, `"warning"`, `"alert"` | NIST AI RMF MEASURE-2.5 |
| `model_ops.monitoring.metric_name` | string | **Recommended** | Metric being checked | NIST AI RMF MEASURE-2.5 |
| `model_ops.monitoring.metric_value` | double | **Recommended** | Current metric value | NIST AI RMF MEASURE-2.5 |
| `model_ops.monitoring.baseline_value` | double | **Recommended** | Baseline metric value | NIST AI RMF MEASURE-2.5 |
| `model_ops.monitoring.drift_score` | double | **Recommended** | Drift magnitude (0–1) | NIST AI RMF MEASURE-2.5 |
| `model_ops.monitoring.drift_type` | string | **Optional** | Drift type: `"data"`, `"embedding"`, `"concept"` | NIST AI RMF MEASURE-2.5 |
| `model_ops.monitoring.action_triggered` | string | **Recommended** | Action taken: `"alert"`, `"retrain"`, `"rollback"` | NIST AI RMF MEASURE-2.5 |

### `model_ops.prompt.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `model_ops.prompt.name` | string | **Required** | Prompt template name | NIST AI RMF GOVERN-1.2 |
| `model_ops.prompt.operation` | string | **Required** | Prompt operation: `"create"`, `"promote"`, `"rollback"` | NIST AI RMF GOVERN-1.2 |
| `model_ops.prompt.version` | string | **Required** | Prompt version (SemVer) | NIST AI RMF GOVERN-1.2 |
| `model_ops.prompt.content_hash` | string | **Recommended** | Template content hash (SHA-256) | OWASP LLM07, MITRE ATLAS [AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) |
| `model_ops.prompt.label` | string | **Recommended** | Deployment label: `"production"`, `"staging"` | NIST AI RMF GOVERN-1.2 |
| `model_ops.prompt.model_target` | string | **Recommended** | Target model | NIST AI RMF MAP-1.1 |
| `model_ops.prompt.evaluation.score` | double | **Optional** | Evaluation score (0–1) | NIST AI RMF MEASURE-2.5 |
| `model_ops.prompt.evaluation.pass` | boolean | **Optional** | Passed quality gate | NIST AI RMF MEASURE-2.5 |
| `model_ops.prompt.a_b_test.id` | string | **Optional** | A/B experiment ID | NIST AI RMF MEASURE-2.5 |
| `model_ops.prompt.a_b_test.variant` | string | **Optional** | Variant name | NIST AI RMF MEASURE-2.5 |

---

## Identity Attributes

### `identity.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `identity.agent_id` | string | **Required** | Agent identity identifier | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `identity.agent_name` | string | **Required** | Agent name | NIST AI RMF MAP-1.1 |
| `identity.type` | string | **Required** | Identity type: `"persistent"`, `"ephemeral"`, `"delegated"`, `"workload"` | NIST AI RMF GOVERN-1.2 |
| `identity.provider` | string | **Recommended** | Identity provider: `"okta"`, `"entra_id"`, `"spiffe"`, `"auth0"` | NIST AI RMF MAP-1.5 |
| `identity.owner` | string | **Recommended** | Identity owner | NIST AI RMF GOVERN-1.2 |
| `identity.owner_type` | string | **Recommended** | Owner type: `"human"`, `"service"`, `"organization"` | NIST AI RMF GOVERN-1.2 |
| `identity.credential_type` | string | **Recommended** | Credential type: `"oauth_token"`, `"spiffe_svid"`, `"jwt"`, `"mtls_cert"` | MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `identity.credential_id` | string | **Recommended** | Credential identifier | NIST AI RMF GOVERN-1.2 |
| `identity.status` | string | **Required** | Identity status: `"active"`, `"suspended"`, `"revoked"`, `"expired"` | NIST AI RMF GOVERN-1.2 |
| `identity.scope` | string[] | **Recommended** | Granted scopes | OWASP LLM06 (Excessive Agency) |
| `identity.expires_at` | string | **Recommended** | Expiration timestamp (ISO 8601) | NIST AI RMF GOVERN-1.2 |
| `identity.ttl_seconds` | int | **Optional** | Time to live in seconds | — |

### `identity.lifecycle.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `identity.lifecycle.operation` | string | **Required** | Lifecycle operation: `"create"`, `"rotate"`, `"revoke"`, `"suspend"` | NIST AI RMF GOVERN-1.2 |
| `identity.previous_status` | string | **Recommended** | Previous identity status | NIST AI RMF GOVERN-1.2 |
| `identity.auto_rotate` | boolean | **Optional** | Auto-rotation enabled | NIST AI RMF GOVERN-1.2 |
| `identity.rotation_interval_seconds` | int | **Optional** | Rotation interval in seconds | — |

### `identity.auth.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `identity.auth.method` | string | **Required** | Auth method: `"oauth2_pkce"`, `"spiffe_svid"`, `"mtls"`, `"jwt_bearer"` | MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `identity.auth.result` | string | **Required** | Auth result: `"success"`, `"failure"`, `"denied"`, `"expired"` | NIST AI RMF GOVERN-1.2 |
| `identity.auth.provider` | string | **Recommended** | Auth provider service | NIST AI RMF MAP-1.5 |
| `identity.auth.target_service` | string | **Recommended** | Service authenticated to | OWASP LLM06 (Excessive Agency) |
| `identity.auth.failure_reason` | string | **Recommended** | Failure reason | NIST AI RMF MEASURE-2.5 |
| `identity.auth.token_type` | string | **Optional** | Token type: `"bearer"`, `"dpop"`, `"mtls_bound"` | — |
| `identity.auth.scope_requested` | string[] | **Recommended** | Scopes requested | OWASP LLM06 (Excessive Agency) |
| `identity.auth.scope_granted` | string[] | **Recommended** | Scopes granted | OWASP LLM06 (Excessive Agency) |
| `identity.auth.continuous` | boolean | **Optional** | Continuous re-auth enabled | NIST AI RMF GOVERN-1.2 |
| `identity.auth.pkce_used` | boolean | **Optional** | PKCE was used | — |
| `identity.auth.dpop_used` | boolean | **Optional** | DPoP proof included | — |

### `identity.authz.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `identity.authz.decision` | string | **Required** | Authorization decision: `"allow"`, `"deny"`, `"conditional"` | OWASP LLM06 (Excessive Agency), NIST AI RMF GOVERN-1.2 |
| `identity.authz.resource` | string | **Required** | Resource accessed | OWASP LLM06 |
| `identity.authz.action` | string | **Required** | Action performed: `"read"`, `"write"`, `"execute"` | OWASP LLM06 |
| `identity.authz.policy_engine` | string | **Recommended** | Policy engine: `"opa"`, `"cedar"`, `"casbin"` | NIST AI RMF MAP-1.5 |
| `identity.authz.policy_id` | string | **Recommended** | Matched policy ID | NIST AI RMF GOVERN-1.2 |
| `identity.authz.deny_reason` | string | **Recommended** | Denial reason | NIST AI RMF MEASURE-2.5 |
| `identity.authz.risk_score` | double | **Optional** | Risk-based score (0–100) | NIST AI RMF MEASURE-2.5 |
| `identity.authz.privilege_level` | string | **Optional** | Privilege level: `"standard"`, `"elevated"`, `"admin"` | OWASP LLM06 |
| `identity.authz.jea` | boolean | **Optional** | Just-Enough-Access applied | OWASP LLM06, NIST AI RMF GOVERN-1.2 |
| `identity.authz.time_limited` | boolean | **Optional** | Time-limited permission | NIST AI RMF GOVERN-1.2 |

### `identity.delegation.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `identity.delegation.delegator` | string | **Required** | Agent delegating authority | OWASP LLM06 (Excessive Agency), NIST AI RMF GOVERN-1.2 |
| `identity.delegation.delegator_id` | string | **Required** | Delegator identity ID | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `identity.delegation.delegatee` | string | **Required** | Agent receiving authority | OWASP LLM06, NIST AI RMF GOVERN-1.2 |
| `identity.delegation.delegatee_id` | string | **Required** | Delegatee identity ID | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `identity.delegation.type` | string | **Required** | Delegation type: `"on_behalf_of"`, `"token_exchange"`, `"capability_grant"` | NIST AI RMF GOVERN-1.2 |
| `identity.delegation.chain` | string[] | **Recommended** | Full delegation chain | OWASP LLM06, EU AI Act Art.14 |
| `identity.delegation.chain_depth` | int | **Recommended** | Delegation depth | OWASP LLM06 |
| `identity.delegation.scope_delegated` | string[] | **Recommended** | Scopes delegated | OWASP LLM06 (Excessive Agency) |
| `identity.delegation.scope_attenuated` | boolean | **Optional** | Scope was reduced | OWASP LLM06 |
| `identity.delegation.result` | string | **Required** | Delegation result: `"success"`, `"failure"`, `"denied"` | NIST AI RMF GOVERN-1.2 |
| `identity.delegation.proof_type` | string | **Optional** | Proof type: `"dpop"`, `"mtls_binding"` | — |
| `identity.delegation.ttl_seconds` | int | **Optional** | Delegation TTL in seconds | — |

### `identity.trust.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `identity.trust.operation` | string | **Required** | Trust operation: `"establish"`, `"verify"`, `"revoke_trust"` | NIST AI RMF GOVERN-1.2 |
| `identity.trust.peer_agent` | string | **Required** | Peer agent name | OWASP LLM06 |
| `identity.trust.peer_agent_id` | string | **Recommended** | Peer agent ID | NIST AI RMF GOVERN-1.2 |
| `identity.trust.result` | string | **Required** | Trust result: `"established"`, `"failed"`, `"rejected"` | NIST AI RMF GOVERN-1.2 |
| `identity.trust.method` | string | **Recommended** | Trust method: `"mtls"`, `"spiffe"`, `"did_vc"` | MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `identity.trust.trust_domain` | string | **Recommended** | Trust domain | NIST AI RMF GOVERN-1.2 |
| `identity.trust.cross_domain` | boolean | **Optional** | Cross-domain operation | — |
| `identity.trust.trust_level` | string | **Recommended** | Trust level: `"basic"`, `"verified"`, `"high"`, `"full"` | NIST AI RMF GOVERN-1.2 |
| `identity.trust.protocol` | string | **Recommended** | Trust protocol: `"mcp"`, `"a2a"`, `"custom"` | — |

### `identity.session.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `identity.session.id` | string | **Required** | Identity session ID | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `identity.session.operation` | string | **Required** | Session operation: `"create"`, `"refresh"`, `"terminate"` | NIST AI RMF GOVERN-1.2 |
| `identity.session.scope` | string[] | **Recommended** | Active session scopes | OWASP LLM06 (Excessive Agency) |
| `identity.session.expires_at` | string | **Recommended** | Session expiration (ISO 8601) | NIST AI RMF GOVERN-1.2 |
| `identity.session.actions_count` | int | **Optional** | Actions performed in session | NIST AI RMF MEASURE-2.5 |
| `identity.session.delegations_count` | int | **Optional** | Delegations from session | OWASP LLM06 |
| `identity.session.termination_reason` | string | **Recommended** | Termination reason: `"completed"`, `"timeout"`, `"revoked"` | NIST AI RMF GOVERN-1.2 |

---

## Asset Inventory Attributes

### `asset.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `asset.id` | string | **Required** | Unique asset identifier | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `asset.name` | string | **Required** | Human-readable asset name | NIST AI RMF MAP-1.1 |
| `asset.type` | string | **Required** | Asset type: `"model"`, `"dataset"`, `"prompt_template"`, `"vector_db"`, `"mcp_server"`, `"agent"`, `"pipeline"`, `"guardrail"` | NIST AI RMF MAP-1.1, EU AI Act Art.13 |
| `asset.version` | string | **Recommended** | Asset version | NIST AI RMF GOVERN-1.2 |
| `asset.hash` | string | **Recommended** | Content hash for integrity (SHA-256) | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040), NIST AI RMF GOVERN-1.2 |
| `asset.owner` | string | **Recommended** | Asset owner | NIST AI RMF GOVERN-1.2 |
| `asset.owner_type` | string | **Optional** | Owner type: `"team"`, `"individual"`, `"organization"` | NIST AI RMF GOVERN-1.2 |
| `asset.deployment_environment` | string | **Recommended** | Deployment environment: `"production"`, `"staging"`, `"development"`, `"shadow"` | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `asset.risk_classification` | string | **Recommended** | EU AI Act risk level: `"high_risk"`, `"limited_risk"`, `"minimal_risk"`, `"systemic"` | EU AI Act Art.6, EU AI Act Art.9 |
| `asset.description` | string | **Optional** | Asset description | EU AI Act Art.13 (Transparency) |
| `asset.tags` | string[] | **Optional** | Searchable tags | — |
| `asset.source_repository` | string | **Recommended** | Source repository URL | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040), NIST AI RMF MAP-1.5 |
| `asset.created_at` | string | **Recommended** | Creation timestamp (ISO 8601) | EU AI Act Art.12 |

### `asset.discovery.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `asset.discovery.scope` | string | **Required** | Discovery scope: `"cluster"`, `"namespace"`, `"environment"`, `"organization"` | NIST AI RMF MAP-1.5 |
| `asset.discovery.method` | string | **Required** | Discovery method: `"api_scan"`, `"network_scan"`, `"registry_sync"`, `"log_analysis"` | NIST AI RMF MAP-1.5 |
| `asset.discovery.assets_found` | int | **Recommended** | Total assets discovered | NIST AI RMF MAP-1.5 |
| `asset.discovery.new_assets` | int | **Recommended** | Previously unknown assets | NIST AI RMF MAP-1.5 |
| `asset.discovery.shadow_assets` | int | **Recommended** | Unregistered shadow AI assets | NIST AI RMF MAP-1.5, EU AI Act Art.9 |
| `asset.discovery.status` | string | **Required** | Discovery status: `"completed"`, `"partial"`, `"failed"` | NIST AI RMF MEASURE-2.5 |

### `asset.audit.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `asset.audit.type` | string | **Required** | Audit type: `"integrity"`, `"compliance"`, `"access_review"`, `"security"`, `"full"` | NIST AI RMF GOVERN-1.2, EU AI Act Art.9 |
| `asset.audit.result` | string | **Required** | Audit result: `"pass"`, `"fail"`, `"warning"`, `"not_applicable"` | NIST AI RMF MEASURE-2.5, EU AI Act Art.9 |
| `asset.audit.auditor` | string | **Recommended** | Auditor identity | NIST AI RMF GOVERN-1.2 |
| `asset.audit.framework` | string | **Recommended** | Compliance framework: `"eu_ai_act"`, `"nist_ai_rmf"`, `"iso_42001"`, `"soc2"` | EU AI Act Art.9, NIST AI RMF GOVERN-1.2 |
| `asset.audit.findings` | string | **Recommended** | JSON array of findings | NIST AI RMF MEASURE-2.5 |
| `asset.audit.last_audit_time` | string | **Optional** | Previous audit timestamp (ISO 8601) | EU AI Act Art.9 |
| `asset.audit.next_audit_due` | string | **Optional** | Next scheduled audit (ISO 8601) | EU AI Act Art.9 |
| `asset.audit.risk_score` | double | **Recommended** | Calculated risk score (0–100) | NIST AI RMF MEASURE-2.5 |
| `asset.audit.integrity_verified` | boolean | **Recommended** | Integrity hash matches | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `asset.audit.compliance_status` | string | **Recommended** | Compliance status: `"compliant"`, `"non_compliant"`, `"partially_compliant"` | EU AI Act Art.9, NIST AI RMF GOVERN-1.2 |

### `asset.classification.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `asset.classification.framework` | string | **Required** | Classification framework: `"eu_ai_act"`, `"nist_ai_rmf"`, `"internal"` | EU AI Act Art.6, NIST AI RMF MAP-1.1 |
| `asset.classification.previous` | string | **Recommended** | Previous risk classification | EU AI Act Art.9 |
| `asset.classification.reason` | string | **Recommended** | Classification reason | EU AI Act Art.13 (Transparency) |
| `asset.classification.assessor` | string | **Recommended** | Assessor identity | NIST AI RMF GOVERN-1.2 |
| `asset.classification.use_case` | string | **Recommended** | Intended use case | EU AI Act Art.9, EU AI Act Art.13 |
| `asset.classification.affected_persons` | string | **Recommended** | Affected persons: `"employees"`, `"consumers"`, `"public"`, `"children"` | EU AI Act Art.9 |
| `asset.classification.sector` | string | **Optional** | Deployment sector: `"healthcare"`, `"finance"`, `"hr_recruitment"` | EU AI Act Art.6 |
| `asset.classification.biometric` | boolean | **Recommended** | Uses biometric data | EU AI Act Art.5, EU AI Act Art.6 |
| `asset.classification.autonomous_decision` | boolean | **Recommended** | Autonomous decisions affecting rights | EU AI Act Art.14 (Human Oversight) |

### `asset.decommission.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `asset.decommission.reason` | string | **Required** | Decommission reason: `"replaced"`, `"deprecated"`, `"security_risk"`, `"compliance"` | NIST AI RMF GOVERN-1.2, EU AI Act Art.12 |
| `asset.decommission.replacement_id` | string | **Recommended** | Replacement asset ID | NIST AI RMF GOVERN-1.2 |
| `asset.decommission.data_retention` | string | **Recommended** | Data retention policy: `"purge"`, `"archive"`, `"retain"` | EU AI Act Art.12, NIST AI RMF GOVERN-1.2 |
| `asset.decommission.approved_by` | string | **Recommended** | Approver identity | NIST AI RMF GOVERN-1.2 |

---

## Drift Detection Attributes

### `drift.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `drift.model_id` | string | **Required** | Model being monitored | NIST AI RMF GOVERN-1.2 |
| `drift.type` | string | **Required** | Drift type: `"data_distribution"`, `"concept"`, `"performance"`, `"calibration"`, `"embedding"`, `"feature"` | NIST AI RMF MEASURE-2.5 |
| `drift.score` | double | **Required** | Drift magnitude (0.0–1.0) | NIST AI RMF MEASURE-2.5 |
| `drift.result` | string | **Required** | Detection result: `"normal"`, `"warning"`, `"alert"`, `"critical"` | NIST AI RMF MEASURE-2.5, EU AI Act Art.9 |
| `drift.detection_method` | string | **Recommended** | Statistical method: `"psi"`, `"ks_test"`, `"js_divergence"`, `"wasserstein"`, `"adwin"` | NIST AI RMF MEASURE-2.5 |
| `drift.baseline_metric` | double | **Recommended** | Baseline metric value | NIST AI RMF MEASURE-2.5 |
| `drift.current_metric` | double | **Recommended** | Current metric value | NIST AI RMF MEASURE-2.5 |
| `drift.metric_name` | string | **Recommended** | Metric being tracked: `"psi_score"`, `"accuracy"`, `"precision"` | NIST AI RMF MEASURE-2.5 |
| `drift.threshold` | double | **Recommended** | Alert threshold | NIST AI RMF MEASURE-2.5 |
| `drift.p_value` | double | **Optional** | Statistical significance | NIST AI RMF MEASURE-2.5 |
| `drift.reference_dataset` | string | **Recommended** | Reference dataset ID | NIST AI RMF MAP-1.5 |
| `drift.reference_period` | string | **Recommended** | Reference time period | NIST AI RMF MEASURE-2.5 |
| `drift.evaluation_window` | string | **Recommended** | Current evaluation window | NIST AI RMF MEASURE-2.5 |
| `drift.sample_size` | int | **Optional** | Evaluation sample size | NIST AI RMF MEASURE-2.5 |
| `drift.affected_segments` | string[] | **Optional** | Impacted segments | NIST AI RMF MEASURE-2.5 |
| `drift.feature_name` | string | **Optional** | Feature exhibiting drift | NIST AI RMF MEASURE-2.5 |
| `drift.feature_importance` | double | **Optional** | Feature importance (0–1) | NIST AI RMF MEASURE-2.5 |
| `drift.action_triggered` | string | **Recommended** | Automated action: `"none"`, `"alert"`, `"retrain"`, `"rollback"`, `"quarantine"` | NIST AI RMF MEASURE-2.5 |

### `drift.baseline.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `drift.baseline.operation` | string | **Required** | Baseline operation: `"create"`, `"refresh"`, `"validate"` | NIST AI RMF GOVERN-1.2 |
| `drift.baseline.id` | string | **Required** | Baseline identifier | NIST AI RMF GOVERN-1.2 |
| `drift.baseline.dataset` | string | **Recommended** | Baseline dataset | NIST AI RMF MAP-1.5 |
| `drift.baseline.sample_size` | int | **Recommended** | Baseline sample count | NIST AI RMF MEASURE-2.5 |
| `drift.baseline.period` | string | **Recommended** | Time period covered | NIST AI RMF MEASURE-2.5 |
| `drift.baseline.metrics` | string | **Recommended** | JSON of baseline metrics | NIST AI RMF MEASURE-2.5 |
| `drift.baseline.features` | string[] | **Optional** | Features tracked | NIST AI RMF MEASURE-2.5 |

### `drift.investigation.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `drift.investigation.trigger_id` | string | **Required** | Detection span that triggered investigation | NIST AI RMF GOVERN-1.2 |
| `drift.investigation.root_cause` | string | **Recommended** | Identified root cause | NIST AI RMF MEASURE-2.5 |
| `drift.investigation.root_cause_category` | string | **Recommended** | Root cause category: `"data_quality"`, `"upstream_change"`, `"seasonal"`, `"adversarial"` | NIST AI RMF MEASURE-2.5, MITRE ATLAS [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) |
| `drift.investigation.affected_segments` | string[] | **Optional** | Impacted segments | NIST AI RMF MEASURE-2.5 |
| `drift.investigation.affected_users_estimate` | int | **Optional** | Estimated affected users | NIST AI RMF MEASURE-2.5, EU AI Act Art.9 |
| `drift.investigation.blast_radius` | string | **Recommended** | Impact scope: `"isolated"`, `"segment"`, `"widespread"`, `"global"` | NIST AI RMF MEASURE-2.5 |
| `drift.investigation.severity` | string | **Required** | Investigation severity: `"low"`, `"medium"`, `"high"`, `"critical"` | NIST AI RMF MEASURE-2.5, EU AI Act Art.9 |
| `drift.investigation.recommendation` | string | **Recommended** | Remediation recommendation | NIST AI RMF MEASURE-2.5 |

### `drift.remediation.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `drift.remediation.action` | string | **Required** | Remediation action: `"retrain"`, `"rollback"`, `"recalibrate"`, `"quarantine"` | NIST AI RMF MEASURE-2.5 |
| `drift.remediation.trigger_id` | string | **Required** | Trigger span ID | NIST AI RMF GOVERN-1.2 |
| `drift.remediation.automated` | boolean | **Recommended** | Automatically triggered | EU AI Act Art.14 (Human Oversight) |
| `drift.remediation.initiated_by` | string | **Recommended** | Initiator identity | NIST AI RMF GOVERN-1.2 |
| `drift.remediation.status` | string | **Required** | Remediation status: `"pending"`, `"in_progress"`, `"completed"`, `"failed"` | NIST AI RMF MEASURE-2.5 |
| `drift.remediation.rollback_to` | string | **Optional** | Rollback target version | NIST AI RMF GOVERN-1.2 |
| `drift.remediation.retrain_dataset` | string | **Optional** | Retraining dataset | NIST AI RMF MAP-1.5 |
| `drift.remediation.validation_passed` | boolean | **Recommended** | Post-remediation validation passed | NIST AI RMF MEASURE-2.5 |

---

## Memory Security Attributes

### `memory.security.*`

| Attribute | Type | Requirement | Description | Mapping |
|-----------|------|-------------|-------------|---------|
| `memory.security.content_hash` | string | **Recommended** | Content hash for tamper detection (SHA-256) | MITRE ATLAS [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020), NIST AI RMF GOVERN-1.2 |
| `memory.security.content_size` | int | **Optional** | Content size in bytes | — |
| `memory.security.integrity_hash` | string | **Recommended** | Expected integrity hash | MITRE ATLAS [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) |
| `memory.security.provenance_verified` | boolean | **Recommended** | Provenance was verified | OWASP LLM03, MITRE ATLAS [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) |
| `memory.security.poisoning_score` | double | **Recommended** | Poisoning anomaly score (0–1) | OWASP LLM03, MITRE ATLAS [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) |
| `memory.security.cross_session` | boolean | **Recommended** | Cross-session memory access | OWASP LLM06, NIST AI RMF GOVERN-1.2 |
| `memory.security.isolation_verified` | boolean | **Recommended** | Session isolation verified | NIST AI RMF GOVERN-1.2 |
| `memory.security.mutation_count` | int | **Optional** | Total mutations in session | NIST AI RMF MEASURE-2.5 |
| `memory.security.snapshot_before` | string | **Optional** | Content hash before mutation | MITRE ATLAS [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) |
| `memory.security.snapshot_after` | string | **Optional** | Content hash after mutation | MITRE ATLAS [AML.T0020](https://atlas.mitre.org/techniques/AML.T0020) |
