# Skills Semantic Conventions

AITF defines semantic conventions for AI Skills — modular, reusable capabilities that agents can discover, invoke, and compose.

## Overview

Skills represent a higher-level abstraction over tools: while tools are protocol-level primitives (MCP tools, function calls), Skills are discoverable capabilities with versioning, permissions, and composition semantics.

```
Skill Lifecycle:
  register → discover → negotiate_version → invoke → evaluate

Skill Sources:
  - MCP Server tools
  - Native function calls
  - API endpoints
  - Other agent capabilities
  - Marketplace/registry
```

---

## Span: `skill.discover`

Represents discovering available skills from a registry or source.

### Span Name

Format: `skill.discover {source}`

### Span Kind

`CLIENT`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `skill.source` | string | Discovery source (`"mcp:server"`, `"registry"`, `"local"`) |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `skill.count` | int | Number of skills discovered |
| `skill.names` | string[] | Names of discovered skills |
| `skill.filter.category` | string | Category filter applied |
| `skill.filter.capabilities` | string[] | Capability filter applied |

---

## Span: `skill.invoke`

Represents a skill invocation. This is the primary skills telemetry span.

### Span Name

Format: `skill.invoke {skill.name}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `skill.name` | string | Skill name |
| `skill.version` | string | Skill version |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `skill.id` | string | Unique skill ID |
| `skill.provider` | string | `"builtin"`, `"marketplace"`, `"custom"`, `"mcp"` |
| `skill.category` | string | Skill category |
| `skill.description` | string | Skill description |
| `skill.input` | string | Input parameters (JSON) |
| `skill.output` | string | Output (may be redacted) |
| `skill.status` | string | `"success"`, `"error"`, `"timeout"`, `"denied"`, `"retry"` |
| `skill.duration_ms` | double | Execution time (ms) |
| `skill.retry_count` | int | Number of retries |
| `skill.source` | string | Where skill was sourced |
| `skill.permissions` | string[] | Required permissions |

### Events

#### `skill.input`

Emitted with skill input (can be sampled/redacted).

| Attribute | Type | Description |
|-----------|------|-------------|
| `skill.input.content` | string | Full input content |

#### `skill.output`

Emitted with skill output (can be sampled/redacted).

| Attribute | Type | Description |
|-----------|------|-------------|
| `skill.output.content` | string | Full output content |
| `skill.output.type` | string | Output content type |

#### `skill.error`

Emitted when a skill encounters an error.

| Attribute | Type | Description |
|-----------|------|-------------|
| `skill.error.type` | string | Error type |
| `skill.error.message` | string | Error message |
| `skill.error.retryable` | boolean | Whether error is retryable |

---

## Span: `skill.compose`

Represents composing multiple skills into a workflow.

### Span Name

Format: `skill.compose {workflow_name}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `skill.compose.name` | string | Workflow/composition name |
| `skill.compose.skills` | string[] | Skills in composition |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `skill.compose.pattern` | string | `"sequential"`, `"parallel"`, `"conditional"`, `"iterative"` |
| `skill.compose.total_skills` | int | Total skills in composition |
| `skill.compose.completed_skills` | int | Successfully completed skills |

---

## Skill Categories

Standard skill categories:

| Category | Description | Examples |
|----------|-------------|---------|
| `search` | Information retrieval | Web search, code search, document search |
| `code` | Code operations | Read file, write file, execute code, refactor |
| `data` | Data processing | Parse CSV, query database, transform JSON |
| `communication` | External communication | Send email, post to Slack, create issue |
| `analysis` | Analysis and reasoning | Summarize, classify, extract entities |
| `generation` | Content generation | Write document, create image, generate code |
| `knowledge` | Knowledge management | Store memory, retrieve context, update KB |
| `security` | Security operations | Check permissions, validate input, audit |
| `integration` | External integrations | API calls, webhook triggers, service calls |
| `workflow` | Workflow management | Create task, update status, assign work |

---

## Skill Resolution

When an agent needs a capability, AITF traces the skill resolution process:

```
1. Agent requests capability: "I need to search the web"
2. Skill resolver searches available sources:
   a. Local registered skills
   b. MCP server tools
   c. Skill registry/marketplace
3. Version negotiation (if multiple versions available)
4. Permission check
5. Skill invocation
```

### Span: `skill.resolve`

| Attribute | Type | Notes |
|-----------|------|-------|
| `skill.resolve.capability` | string | Requested capability |
| `skill.resolve.candidates` | int | Number of candidates found |
| `skill.resolve.selected` | string | Selected skill name |
| `skill.resolve.reason` | string | Why this skill was selected |

---

## Example: Skill Discovery and Invocation

```
Span: agent.step.tool_use research-agent
  │
  ├─ Span: skill.discover mcp:filesystem
  │    skill.source: "mcp:filesystem"
  │    skill.count: 5
  │    skill.names: ["read_file", "write_file", "list_dir", "search", "move_file"]
  │
  ├─ Span: skill.invoke web-search
  │    skill.name: "web-search"
  │    skill.version: "2.1.0"
  │    skill.provider: "builtin"
  │    skill.category: "search"
  │    skill.input: "{\"query\": \"AITF framework\", \"max_results\": 5}"
  │    skill.output: "[{\"title\": \"AI Telemetry Framework\", ...}]"
  │    skill.status: "success"
  │    skill.duration_ms: 850.0
  │    skill.source: "api:search"
  │    Events:
  │      skill.input: {content: "{\"query\": \"AITF framework\"}"}
  │      skill.output: {content: "[{\"title\": ...}]", type: "application/json"}
  │
  └─ Span: skill.invoke read_file
       skill.name: "read_file"
       skill.version: "1.0.0"
       skill.provider: "mcp"
       skill.category: "code"
       skill.source: "mcp:filesystem"
       skill.permissions: ["file_read"]
       │
       └─ Span: mcp.tool.invoke read_file    (underlying MCP call)
            mcp.tool.server: "filesystem"
```

## Example: Skill Composition

```
Span: skill.compose research-and-write
  skill.compose.pattern: "sequential"
  skill.compose.skills: ["web-search", "summarize", "write-doc"]
  skill.compose.total_skills: 3
  │
  ├─ Span: skill.invoke web-search
  │    skill.status: "success"
  │    skill.duration_ms: 850.0
  │
  ├─ Span: skill.invoke summarize
  │    skill.status: "success"
  │    skill.duration_ms: 1200.0
  │    └─ Span: chat gpt-4o    (LLM call within skill)
  │
  └─ Span: skill.invoke write-doc
       skill.status: "success"
       skill.duration_ms: 350.0
       └─ Span: mcp.tool.invoke write_file
```
