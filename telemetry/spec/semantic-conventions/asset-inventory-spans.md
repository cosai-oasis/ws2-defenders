# AI Asset Inventory Span Conventions

AITF defines semantic conventions for AI asset inventory management — covering the registration, discovery, audit, and risk classification of all AI system components. These conventions align with CoSAI's AI Incident Response requirement for maintaining complete inventories of models, datasets, prompts, and infrastructure dependencies.

## Overview

The `asset.*` namespace covers the complete AI asset lifecycle:

| Stage | Span Name | Description |
|-------|-----------|-------------|
| Registration | `asset.register` | Asset registration into inventory |
| Discovery | `asset.discover` | Automated asset discovery and scanning |
| Audit | `asset.audit` | Periodic audit and compliance verification |
| Risk Classification | `asset.classify` | Risk classification (EU AI Act, internal policy) |
| Dependency Mapping | `asset.dependency` | Dependency graph resolution |
| Decommission | `asset.decommission` | Asset retirement and decommissioning |

---

## Span: `asset.register`

Represents the registration of an AI asset (model, dataset, prompt template, vector DB, MCP server, agent) into the organization's AI asset inventory.

### Span Name

Format: `asset.register {asset.type} {asset.name}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.id` | string | Unique asset identifier |
| `asset.name` | string | Human-readable asset name |
| `asset.type` | string | Asset type (see below) |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.version` | string | Asset version (SemVer or hash) |
| `asset.hash` | string | Content hash for integrity verification |
| `asset.owner` | string | Asset owner (team or individual) |
| `asset.owner_type` | string | `"team"`, `"individual"`, `"organization"` |
| `asset.deployment_environment` | string | Deployment environment |
| `asset.risk_classification` | string | Risk classification |
| `asset.description` | string | Asset description |
| `asset.tags` | string[] | Searchable tags |
| `asset.source_repository` | string | Source code/model repository URL |
| `asset.created_at` | string | Creation timestamp (ISO 8601) |

### Asset Types

| Value | Description |
|-------|-------------|
| `model` | ML/LLM model artifact |
| `dataset` | Training, evaluation, or reference dataset |
| `prompt_template` | Prompt template or system prompt |
| `vector_db` | Vector database or embedding index |
| `mcp_server` | MCP server or tool provider |
| `agent` | Autonomous AI agent |
| `pipeline` | ML/data pipeline definition |
| `guardrail` | Safety guardrail configuration |
| `embedding_model` | Embedding model (distinct from inference model) |
| `knowledge_base` | RAG knowledge base or document collection |

### Deployment Environments

| Value | Description |
|-------|-------------|
| `production` | Production environment |
| `staging` | Pre-production staging |
| `development` | Development/testing |
| `shadow` | Shadow/dark-launch environment |

### Risk Classifications (EU AI Act aligned)

| Value | Description |
|-------|-------------|
| `unacceptable` | Unacceptable risk — prohibited under EU AI Act |
| `high_risk` | High risk — subject to conformity assessment |
| `limited_risk` | Limited risk — transparency obligations |
| `minimal_risk` | Minimal risk — no specific obligations |
| `systemic` | Systemic risk — GPAI models with systemic risk |
| `not_classified` | Not yet classified |

---

## Span: `asset.discover`

Represents automated asset discovery — scanning infrastructure for unregistered or shadow AI assets.

### Span Name

Format: `asset.discover {asset.discovery.scope}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.discovery.scope` | string | Discovery scope (`"cluster"`, `"namespace"`, `"environment"`, `"organization"`) |
| `asset.discovery.method` | string | `"api_scan"`, `"network_scan"`, `"registry_sync"`, `"log_analysis"`, `"manual"` |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.discovery.assets_found` | int | Number of assets discovered |
| `asset.discovery.new_assets` | int | Number of previously unknown assets |
| `asset.discovery.shadow_assets` | int | Number of unregistered (shadow) AI assets |
| `asset.discovery.status` | string | `"completed"`, `"partial"`, `"failed"` |

---

## Span: `asset.audit`

Represents a periodic audit of an AI asset — verifying integrity, compliance, and operational status.

### Span Name

Format: `asset.audit {asset.type} {asset.id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.id` | string | Asset being audited |
| `asset.audit.type` | string | Audit type (see below) |
| `asset.audit.result` | string | `"pass"`, `"fail"`, `"warning"`, `"not_applicable"` |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.audit.auditor` | string | Auditor identity (human or automated) |
| `asset.audit.framework` | string | Compliance framework (`"eu_ai_act"`, `"nist_ai_rmf"`, `"iso_42001"`, `"soc2"`) |
| `asset.audit.findings` | string | JSON array of audit findings |
| `asset.audit.last_audit_time` | string | Previous audit timestamp |
| `asset.audit.next_audit_due` | string | Next scheduled audit timestamp |
| `asset.audit.risk_score` | double | Calculated risk score (0-100) |
| `asset.audit.integrity_verified` | boolean | Whether integrity hash matches |
| `asset.audit.compliance_status` | string | `"compliant"`, `"non_compliant"`, `"partially_compliant"` |

### Audit Types

| Value | Description |
|-------|-------------|
| `integrity` | Hash/signature verification |
| `compliance` | Regulatory compliance check |
| `access_review` | Access control and permission audit |
| `drift` | Model drift and performance audit |
| `security` | Security vulnerability assessment |
| `lineage` | Data/model lineage verification |
| `full` | Comprehensive full audit |

---

## Span: `asset.classify`

Represents risk classification of an AI asset — assigning regulatory risk levels per EU AI Act, internal policy, or other frameworks.

### Span Name

Format: `asset.classify {asset.id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.id` | string | Asset being classified |
| `asset.risk_classification` | string | Assigned risk level (see Risk Classifications above) |
| `asset.classification.framework` | string | Framework used for classification |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.classification.previous` | string | Previous risk classification |
| `asset.classification.reason` | string | Reason for classification |
| `asset.classification.assessor` | string | Person/system performing classification |
| `asset.classification.use_case` | string | Intended use case (affects risk level) |
| `asset.classification.affected_persons` | string | `"employees"`, `"consumers"`, `"public"`, `"children"` |
| `asset.classification.sector` | string | Deployment sector (affects risk — healthcare, finance, etc.) |
| `asset.classification.biometric` | boolean | Uses biometric data |
| `asset.classification.autonomous_decision` | boolean | Makes autonomous decisions affecting rights |

---

## Span: `asset.dependency`

Represents dependency mapping — resolving the dependency graph of an AI asset.

### Span Name

Format: `asset.dependency {asset.id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.id` | string | Asset whose dependencies are being resolved |
| `asset.dependency.operation` | string | `"resolve"`, `"update"`, `"validate"` |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.dependency.count` | int | Total dependency count |
| `asset.dependency.direct_count` | int | Direct dependency count |
| `asset.dependency.transitive_count` | int | Transitive dependency count |
| `asset.dependency.vulnerable_count` | int | Dependencies with known vulnerabilities |
| `asset.dependency.graph` | string | JSON dependency graph |

---

## Span: `asset.decommission`

Represents the decommissioning/retirement of an AI asset.

### Span Name

Format: `asset.decommission {asset.type} {asset.id}`

### Span Kind

`INTERNAL`

### Required Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.id` | string | Asset being decommissioned |
| `asset.decommission.reason` | string | `"replaced"`, `"deprecated"`, `"security_risk"`, `"compliance"`, `"end_of_life"` |

### Recommended Attributes

| Attribute | Type | Notes |
|-----------|------|-------|
| `asset.decommission.replacement_id` | string | Replacement asset ID (if applicable) |
| `asset.decommission.data_retention` | string | `"purge"`, `"archive"`, `"retain"` |
| `asset.decommission.approved_by` | string | Approver identity |
| `asset.decommission.effective_date` | string | Effective decommission date |

---

## Examples

### Example 1: Registering a production model

```
Span: asset.register model customer-support-llama-70b
  asset.id: "model-cs-llama70b-v3"
  asset.name: "customer-support-llama-70b"
  asset.type: "model"
  asset.version: "3.1.0"
  asset.hash: "sha256:abc123def456"
  asset.owner: "ml-platform-team"
  asset.owner_type: "team"
  asset.deployment_environment: "production"
  asset.risk_classification: "high_risk"
  asset.source_repository: "https://registry.internal/models/cs-llama70b"
  asset.tags: ["customer-support", "llama", "fine-tuned"]
```

### Example 2: Shadow AI discovery scan

```
Span: asset.discover organization
  asset.discovery.scope: "organization"
  asset.discovery.method: "api_scan"
  asset.discovery.assets_found: 47
  asset.discovery.new_assets: 3
  asset.discovery.shadow_assets: 2
  asset.discovery.status: "completed"
```

### Example 3: EU AI Act risk classification

```
Span: asset.classify model-hiring-screener-v1
  asset.id: "model-hiring-screener-v1"
  asset.risk_classification: "high_risk"
  asset.classification.framework: "eu_ai_act"
  asset.classification.reason: "Employment context — CV screening affects natural persons"
  asset.classification.use_case: "automated resume screening"
  asset.classification.affected_persons: "consumers"
  asset.classification.sector: "hr_recruitment"
  asset.classification.autonomous_decision: true
```

### Example 4: Periodic compliance audit

```
Span: asset.audit model model-cs-llama70b-v3
  asset.id: "model-cs-llama70b-v3"
  asset.audit.type: "compliance"
  asset.audit.result: "warning"
  asset.audit.framework: "eu_ai_act"
  asset.audit.risk_score: 72.5
  asset.audit.integrity_verified: true
  asset.audit.compliance_status: "partially_compliant"
  asset.audit.last_audit_time: "2026-01-15T10:00:00Z"
  asset.audit.next_audit_due: "2026-04-15T10:00:00Z"
  asset.audit.findings: "[{\"finding\": \"Missing bias evaluation for protected groups\", \"severity\": \"high\"}]"
```
