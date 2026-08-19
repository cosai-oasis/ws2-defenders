# MCP Span Conventions (MCP_ACTIVITY)

> **OTel Alignment Note:** MCP tool invocations adopt OTel GenAI tool attributes (`gen_ai.tool.{name,type,call.id,call.arguments,call.result}`)
> where OTel defines them. MCP-specific extension attributes (server lifecycle, resources, prompts, sampling) use the `mcp.*` namespace.

Status: **Normative** | CoSAI WS2 Alignment: **MCP_ACTIVITY** | OCSF Class: **7003 Tool Execution**

AITF defines semantic conventions for the Model Context Protocol (MCP), covering server lifecycle, tool discovery and invocation, resource access, prompt management, and sampling. This specification defines the normative field requirements aligned with CoSAI Working Stream 2 (Telemetry for AI) and mapped to applicable compliance and threat frameworks.

Key words "MUST", "SHOULD", "MAY" follow [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Overview

MCP is a protocol that enables AI models to interact with external systems through a standardized interface. AITF provides first-class telemetry for all MCP operations:

```
MCP Server Lifecycle:
  connect -> initialize -> discover (tools/resources/prompts) -> use -> disconnect

MCP Operations:
  - Tool Discovery & Invocation
  - Resource Read & Subscribe
  - Prompt Get & Execute
  - Sampling (server-initiated LLM requests)
  - Root Management
```

---

## Span: `mcp.server.connect`

Represents establishing a connection to an MCP server.

### Span Name

Format: `mcp.server.connect {mcp.server.name}`

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.server.name` | string | **Required** | MCP server name | OWASP LLM06 (Excessive Agency), MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `mcp.server.transport` | string | **Required** | Transport type: `"stdio"`, `"sse"`, `"streamable_http"` | MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) (ML Supply Chain) |
| `mcp.connection.id` | string | **Recommended** | Unique connection identifier for session correlation | NIST AI RMF GOVERN-1.2 |
| `mcp.server.version` | string | **Recommended** | MCP server version | NIST AI RMF MAP-1.1 |
| `mcp.server.url` | string | **Recommended** | Server URL (if network transport) | MITRE ATLAS AML.T0040 |
| `mcp.protocol.version` | string | **Recommended** | MCP protocol version (e.g. `"2025-03-26"`) | NIST AI RMF MAP-1.1 |

### Events

#### `mcp.server.capabilities`

Emitted after successful initialization.

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.capabilities.tools` | boolean | **Recommended** | Server supports tools | OWASP LLM06 |
| `mcp.capabilities.resources` | boolean | **Recommended** | Server supports resources | — |
| `mcp.capabilities.prompts` | boolean | **Optional** | Server supports prompts | — |
| `mcp.capabilities.sampling` | boolean | **Optional** | Server supports sampling | — |
| `mcp.capabilities.roots` | boolean | **Optional** | Server supports roots | — |

---

## Span: `mcp.server.disconnect`

Represents disconnecting from an MCP server.

### Span Name

Format: `mcp.server.disconnect {mcp.server.name}`

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.server.name` | string | **Required** | Server name | OWASP LLM06 |
| `mcp.connection.id` | string | **Recommended** | Connection identifier | NIST AI RMF GOVERN-1.2 |

---

## Span: `mcp.tool.discover`

Represents discovering available tools from an MCP server.

### Span Name

Format: `mcp.tool.discover {mcp.server.name}`

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.server.name` | string | **Required** | Server name | OWASP LLM06 |
| `mcp.tool.count` | int | **Recommended** | Number of tools discovered | OWASP LLM06 |
| `mcp.tool.names` | string[] | **Recommended** | Names of discovered tools | OWASP LLM06, MITRE ATLAS AML.T0048 |
| `mcp.connection.id` | string | **Optional** | Connection identifier | NIST AI RMF GOVERN-1.2 |

---

## Span: `mcp.tool.invoke`

Represents invoking a tool on an MCP server. This is the primary MCP telemetry span.

### Span Name

Format: `execute_tool {gen_ai.tool.name}`

### Span Kind

`CLIENT`

### Normative Field Table

#### Tool Identification

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.tool.name` | string | **Required** | Tool name | OWASP LLM06 (Excessive Agency), MITRE ATLAS [AML.T0048](https://atlas.mitre.org/techniques/AML.T0048) |
| `gen_ai.tool.type` | string | **Recommended** | Tool type (value: `"extension"` for MCP tools) | OWASP LLM06 |
| `gen_ai.tool.call.id` | string | **Recommended** | Unique identifier for this tool call | NIST AI RMF GOVERN-1.2 |
| `gen_ai.tool.description` | string | **Optional** | Human-readable tool description | EU AI Act Art.13 |
| `mcp.tool.server` | string | **Required** | Source MCP server name | OWASP LLM06, MITRE ATLAS [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) |
| `mcp.connection.id` | string | **Recommended** | Connection identifier for session correlation | NIST AI RMF GOVERN-1.2 |

#### Request & Response (CoSAI WS2)

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `gen_ai.tool.call.arguments` | string | **Recommended** | Input parameters (JSON) | OWASP LLM01 (Prompt Injection via tools), MITRE ATLAS [AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) |
| `gen_ai.tool.call.result` | string | **Recommended** | Tool output (may be redacted for sensitive content) | OWASP LLM05 (Improper Output), OWASP LLM02 (Sensitive Info) |
| `mcp.tool.response_error` | string | **Recommended** | Error message content when tool execution fails | NIST AI RMF MEASURE-2.5 |
| `mcp.tool.is_error` | boolean | **Recommended** | Whether tool returned an error | NIST AI RMF MEASURE-2.5 |

#### Execution Metadata

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.tool.duration_ms` | double | **Recommended** | Execution duration in milliseconds | NIST AI RMF MEASURE-2.5, OWASP LLM10 |
| `mcp.server.transport` | string | **Recommended** | Transport type | MITRE ATLAS AML.T0040 |

#### Human Approval

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.tool.approval_required` | boolean | **Recommended** | Whether human approval was needed | EU AI Act Art.14 (Human Oversight) |
| `mcp.tool.approved` | boolean | **Recommended** | Whether the tool was approved (if required) | EU AI Act Art.14 |

### Events

#### `mcp.tool.input`

Emitted with tool input (can be sampled/redacted for sensitive inputs).

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.tool.input.content` | string | **Optional** | Full input content | OWASP LLM01 |

#### `mcp.tool.output`

Emitted with tool output (can be sampled/redacted).

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.tool.output.content` | string | **Optional** | Full output content | OWASP LLM05, OWASP LLM02 |
| `mcp.tool.output.type` | string | **Optional** | Output type: `"text"`, `"image"`, `"resource"` | — |

#### `mcp.tool.approval`

Emitted when human approval is requested/granted.

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.tool.approval.status` | string | **Required** | `"requested"`, `"approved"`, `"denied"` | EU AI Act Art.14 |
| `mcp.tool.approval.approver` | string | **Recommended** | Who approved (if applicable) | EU AI Act Art.14, NIST AI RMF GOVERN-1.7 |

---

## Span: `mcp.resource.read`

Represents reading a resource from an MCP server.

### Span Name

Format: `mcp.resource.read {mcp.resource.uri}`

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.resource.uri` | string | **Required** | Resource URI | OWASP LLM02 (Sensitive Info) |
| `mcp.server.name` | string | **Required** | Server name | OWASP LLM06 |
| `mcp.connection.id` | string | **Optional** | Connection identifier | NIST AI RMF GOVERN-1.2 |
| `mcp.resource.name` | string | **Recommended** | Resource display name | — |
| `mcp.resource.mime_type` | string | **Recommended** | Content MIME type | — |
| `mcp.resource.size_bytes` | int | **Optional** | Content size in bytes | OWASP LLM10 |

---

## Span: `mcp.resource.subscribe`

Represents subscribing to resource updates from an MCP server.

### Span Name

Format: `mcp.resource.subscribe {mcp.resource.uri}`

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.resource.uri` | string | **Required** | Resource URI | OWASP LLM02 |
| `mcp.server.name` | string | **Required** | Server name | OWASP LLM06 |
| `mcp.connection.id` | string | **Optional** | Connection identifier | NIST AI RMF GOVERN-1.2 |

---

## Span: `mcp.prompt.get`

Represents retrieving a prompt template from an MCP server.

### Span Name

Format: `mcp.prompt.get {mcp.prompt.name}`

### Span Kind

`CLIENT`

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.prompt.name` | string | **Required** | Prompt template name | OWASP LLM01 (Prompt Injection) |
| `mcp.server.name` | string | **Required** | Server name | OWASP LLM06 |
| `mcp.prompt.arguments` | string | **Recommended** | Prompt arguments (JSON) | OWASP LLM01 |
| `mcp.prompt.description` | string | **Optional** | Prompt description | EU AI Act Art.13 |

---

## Span: `mcp.sampling.request`

Represents a server-initiated sampling (LLM) request via MCP.

### Span Name

Format: `mcp.sampling.request {mcp.server.name}`

### Span Kind

`SERVER` (server is requesting from the client)

### Normative Field Table

| Field Name | Type | Requirement | Description | Compliance |
|---|---|---|---|---|
| `mcp.server.name` | string | **Required** | Requesting server name | OWASP LLM06, MITRE ATLAS AML.T0048 |
| `mcp.sampling.model` | string | **Required** | Requested model hint | MITRE ATLAS AML.T0044 |
| `mcp.sampling.max_tokens` | int | **Recommended** | Max tokens | OWASP LLM10 |
| `mcp.sampling.include_context` | string | **Optional** | Context scope: `"thisServer"`, `"allServers"` | OWASP LLM02 |
| `gen_ai.usage.input_tokens` | int | **Recommended** | Input tokens used | OWASP LLM10 |
| `gen_ai.usage.output_tokens` | int | **Recommended** | Output tokens used | OWASP LLM10 |

---

## CoSAI WS2 Field Mapping

Cross-reference between CoSAI WS2 `MCP_ACTIVITY` field names and AITF attribute keys:

| CoSAI WS2 Field | AITF Attribute | Notes |
|---|---|---|
| `mcp.server.name` | `mcp.server.name` | Direct match |
| `mcp.tool.name` | `gen_ai.tool.name` | OTel GenAI tool attribute |
| `mcp.request.args` | `gen_ai.tool.call.arguments` | OTel GenAI tool attribute; JSON-encoded input parameters |
| `mcp.response.result` | `gen_ai.tool.call.result` | OTel GenAI tool attribute; may be redacted |
| `mcp.response.error` | `mcp.tool.response_error` | New in CoSAI WS2 alignment |
| `mcp.transport` | `mcp.server.transport` | On server/tool spans |
| `mcp.connection.id` | `mcp.connection.id` | New in CoSAI WS2 alignment |

---

## Security Considerations

MCP tool invocations should be monitored for:

1. **Unauthorized file access** -- Tools accessing files outside allowed paths
2. **Command injection** -- Malicious input parameters
3. **Data exfiltration** -- Tools sending sensitive data to external systems
4. **Privilege escalation** -- Tools operating beyond granted permissions

AITF's Security Processor automatically flags suspicious MCP tool invocations based on configurable policies.

---

## Example: MCP Tool Discovery and Invocation

```
Span: mcp.server.connect filesystem
  mcp.server.transport: "stdio"
  mcp.protocol.version: "2025-03-26"
  mcp.connection.id: "conn-fs-abc123"
  |
  +- Event: mcp.server.capabilities
  |    mcp.capabilities.tools: true
  |    mcp.capabilities.resources: true
  |
  +- Span: mcp.tool.discover filesystem
  |    mcp.tool.count: 5
  |    mcp.tool.names: ["read_file", "write_file", "list_dir", "search", "move_file"]
  |
  +- Span: execute_tool read_file
  |    gen_ai.tool.name: "read_file"
  |    gen_ai.tool.type: "extension"
  |    mcp.tool.server: "filesystem"
  |    gen_ai.tool.call.arguments: "{\"path\":\"/data/config.yaml\"}"
  |    mcp.tool.is_error: false
  |    mcp.tool.response_error: ""
  |    mcp.tool.duration_ms: 12.5
  |    mcp.connection.id: "conn-fs-abc123"
  |    Events:
  |      mcp.tool.input: {content: "{\"path\":\"/data/config.yaml\"}"}
  |      mcp.tool.output: {content: "server:\n  port: 8080\n...", type: "text"}
  |
  +- Span: execute_tool write_file
       gen_ai.tool.name: "write_file"
       gen_ai.tool.type: "extension"
       mcp.tool.server: "filesystem"
       mcp.tool.approval_required: true
       mcp.tool.approved: true
       mcp.tool.duration_ms: 25.0
       mcp.connection.id: "conn-fs-abc123"
       Events:
         mcp.tool.approval: {status: "approved", approver: "user@example.com"}
         mcp.tool.input: {content: "{\"path\":\"/data/output.txt\",\"content\":\"...\"}"}
         mcp.tool.output: {content: "File written successfully", type: "text"}
```
