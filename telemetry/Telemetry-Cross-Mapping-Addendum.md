# Telemetry for AI Security: Cross-Mapping Addendum {**Working Draft v0.6**}

**Status:** Request for Comments, revision 0.6
**Origin:** Coalition for Secure AI (CoSAI), Workstream 2 (Defenders)
**Companion to:** [Telemetry for AI Security](CoSAI-AI-Telemetry-RFC.md) (cited as RFC); see also the [Attack Detection Addendum](Telemetry-Attack-Detection-Addendum.md) (cited as AD).
**Normative status:** Informative.

---

## How this addendum is organized

This addendum maps the field set onto the specifications that carry security telemetry, and states what each would need to carry the rest. **OCSF** and **OpenTelemetry** are its two target audiences, in that order: OCSF is how a SIEM consumes the telemetry, OpenTelemetry how instrumentation emits it. **AITF** is the bridge: it carries the fields today and stages the changes proposed to the other two. The remaining sections are cross references, included for completeness.

Every section answers the same questions, under the same headings, and skips one only where it does not apply:

1. **What it is, and the version mapped.** Each mapping is pinned to a commit or a published version.
2. **Correspondence.** Which construct carries each field, and how fully: *covered*, *partial*, *none*, or *out of scope*. Coverage says the publication can carry the field at the pin, not that any producer emits it.
3. **Gaps.** What the publication cannot express, and what a defender loses as a result.
4. **Asks.** What CoSAI proposes, each ask tied to the fields it would close and the evidence for them.
5. **What it contributes.** What this field set takes from it.
6. **Divergences and open items.**

For OCSF, OpenTelemetry, AITF and ODIS the correspondence and the asks are generated from the field data, and every construct named resolves at the pinned version.

**The pins.**

<!-- BEGIN GENERATED: xm pins -->
| Publication | Pinned at | Reference | Mapping checked against the pin |
| :------------------ | :------------------ | :--- | :------------------ |
| Open Cybersecurity Schema Framework | 1.9.0 (2026-08-03) | [[37]](#standards--frameworks) | yes, 2026-10-02 |
| OpenTelemetry GenAI semantic conventions | commit `e07f4eb` (2026-10-02) | [[35]](#standards--frameworks) | yes, 2026-10-02 |
| OpenTelemetry semantic conventions (core) | v1.44.0 (2026-08-04) | [[35]](#standards--frameworks) | yes, 2026-10-02 |
| AI Telemetry Framework | commit `e17c514` (2026-09-07) | [[25]](#standards--frameworks) | yes, 2026-10-02 |
| Open Delegation & Identity Standard | commit `148dc41` (2026-09-08) | [[26]](#standards--frameworks) | yes, 2026-10-02 |
| OWASP Agent Observability Standard | 0.1.0 (2025-12-30) | [[38]](#standards--frameworks) | yes, 2026-10-02 |
| NIST Cybersecurity Framework | 2.0 (2024-02-26) | [[31]](#standards--frameworks) | yes, 2026-10-02 |
| NIST AI Risk Management Framework | 1.0 (2023-01-26) | [[30]](#standards--frameworks) | yes, 2026-10-02 |
| ISO/IEC 42001 | 2023 | [[33]](#standards--frameworks) | not yet |
<!-- END GENERATED: xm pins -->

**Coverage and asks, by publication.**

<!-- BEGIN GENERATED: xm summary -->
| Publication | Covered | Partial | None | Out of scope | Asks |
| :------------------ | ---: | ---: | ---: | ---: | :------------------ |
| OCSF | 9 | 32 | 60 | 0 | 36: 8 open, 28 proposed |
| OpenTelemetry | 22 | 19 | 41 | 19 | 30: 1 open, 29 proposed |
| AITF | 92 | 8 | 1 | 0 | none |
| ODIS | 44 | 3 | 0 | 54 | none |
<!-- END GENERATED: xm summary -->

- **The proposals follow the tiers of [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers).** Every MUST field a publication cannot carry has an ask. A SHOULD field gets one where a deployment running its modality would need the publication to carry it. MAY fields appear only inside an ask that a MUST or SHOULD field already needs.
- **Emission and consumption move together.** A field OpenTelemetry emits but OCSF cannot represent arrives at the SIEM as unstructured overflow; a field OCSF defines but no instrumentation produces stays theoretical. Paired asks are the intent.

CoSAI is engaging the **OpenTelemetry** and **OCSF** communities directly on this work, and welcomes input from the wider open source security community in turn. What is wanted in return: corrections to the mappings, and attacks the corpus is missing.

---

## 1. OCSF

### 1.1 What it is, and the version mapped

OCSF, the Open Cybersecurity Schema Framework [[37]](#standards--frameworks), is the vendor-neutral schema SIEMs normalize security events into: event classes with typed attributes, extended by profiles. The mapping is against release 1.9.0 (3 August 2026).

OCSF 1.9.0 already carries an `ai_operation` profile on API Activity (6003): `ai_agent`, `ai_model`, `delegation` and `message_context`. Record integrity is a separate profile, `record_integrity`, attached to the base event. The correspondence below is against that release; constructs proposed in open pull requests are asks, not coverage.

### 1.2 Correspondence

<!-- BEGIN GENERATED: xm correspondence ocsf -->
**RFC §6.1 Identifiers, trace context and model identity**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Agent Name](Telemetry-Attack-Detection-Addendum.md#f-agent-name) | MUST | covered | `profile:ai_operation`, `object:ai_agent` |  |  |
| [Agent (Runtime) Instance ID](Telemetry-Attack-Detection-Addendum.md#f-agent-runtime-instance-id) | MUST | covered | `object:ai_agent`, `attribute:instance_uid` |  |  |
| [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#f-workflow-run-id) | MUST | none |  | No workflow or run identifier. | [ocsf_ai_operation_identifiers](#ask-ocsf-ai-operation-identifiers) |
| [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#f-session-turn-step-ids) | MUST | partial | `object:message_context` | A session identifier only; no turn or step. | [ocsf_ai_operation_identifiers](#ask-ocsf-ai-operation-identifiers) |
| [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#f-trigger-type-source-event) | MUST | none |  | No trigger type. | [ocsf_ai_operation_identifiers](#ask-ocsf-ai-operation-identifiers) |
| [Action Type](Telemetry-Attack-Detection-Addendum.md#f-action-type) | MUST | none |  | No action type. | [ocsf_ai_operation_identifiers](#ask-ocsf-ai-operation-identifiers) |
| [Execution Status](Telemetry-Attack-Detection-Addendum.md#f-execution-status) | MUST | covered | `attribute:status_id`, `attribute:duration` | Outcome and duration on the base event. |  |
| [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) | MUST | partial | `object:actor`, `attribute:app_name` | An application name; no entry-point type and no internal or external flag. | [ocsf_entry_point](#ask-ocsf-entry-point) |
| [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) | MUST | none |  | No system prompt in message_context. | [ocsf_message_context_content](#ask-ocsf-message-context-content) |
| [Model Name + Version](Telemetry-Attack-Detection-Addendum.md#f-model-name-version) | MUST | covered | `profile:ai_operation`, `object:ai_model` |  |  |
| [Inference Parameters](Telemetry-Attack-Detection-Addendum.md#f-inference-parameters) | MUST | none |  | No decoding parameters or context window on ai_model or message_context. | [ocsf_inference_parameters](#ask-ocsf-inference-parameters) |
| [Input / Output Token Counts](Telemetry-Attack-Detection-Addendum.md#f-input-output-token-counts) | MUST | covered | `object:message_context` |  |  |
| [LLM Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-llm-error-exception) | MUST | partial | `attribute:status_id`, `attribute:status_detail` | A generic outcome; no AI-specific error type. | [ocsf_ai_error](#ask-ocsf-ai-error) |
| [Trace Context (propagated)](Telemetry-Attack-Detection-Addendum.md#f-trace-context-propagated) | MUST | covered | `profile:trace`, `object:trace` | The trace profile carries the trace and span identifiers. |  |
| [Stop Reason](Telemetry-Attack-Detection-Addendum.md#f-stop-reason) | MUST | none |  | ai_status.stop_reason_id is proposed in. | [ocsf_stop_reason](#ask-ocsf-stop-reason) |
| [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) | SHOULD | none |  | No autonomy level. | [ocsf_autonomy_level](#ask-ocsf-autonomy-level) |
| [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) | SHOULD | none |  | Provenance and signing not standardized in the profile. | [ocsf_model_provenance](#ask-ocsf-model-provenance) |
| [Organization / Tenant ID](Telemetry-Attack-Detection-Addendum.md#f-organization-tenant-id) | SHOULD | partial | `object:metadata`, `attribute:tenant_uid` | One tenant per event (metadata.tenant_uid), not the tenant of the agent, the session and the invoking user separately. | [ocsf_tenant_scopes](#ask-ocsf-tenant-scopes) |
| [Provider / Endpoint Identity](Telemetry-Attack-Detection-Addendum.md#f-provider-endpoint-identity) | MAY | covered | `object:ai_model`, `attribute:ai_provider` |  |  |
| [Pre-Forward-Pass State Digest/Vector](Telemetry-Attack-Detection-Addendum.md#f-pre-forward-pass-state-digest-vector) | MAY | none |  | No forward-pass digest. A MAY research-grade signal; no ask. |  |
| [Token Malformation / Context-Corruption Indicator](Telemetry-Attack-Detection-Addendum.md#f-token-malformation-context-corruption-indicator) | MAY | none |  | No token-entropy signal. A MAY research-grade signal; no ask. |  |

**RFC §6.2 Content, trust, verdicts and their availability**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Model Input](Telemetry-Attack-Detection-Addendum.md#f-model-input) | MUST | partial | `object:message_context`, `attribute:prompt_text` | No content hash or redaction flag. | [ocsf_message_context_content](#ask-ocsf-message-context-content) |
| [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#f-input-source-channel) | MUST | none |  | No per-segment input source on message_context. | [ocsf_input_segment_source](#ask-ocsf-input-segment-source) |
| [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification) | MUST | partial | `class:2004` | No trust-provenance enum. | [ocsf_trust_level](#ask-ocsf-trust-level) |
| [Source host / IP + request metadata](Telemetry-Attack-Detection-Addendum.md#f-source-host-ip-request-metadata) | MUST | covered | `attribute:src_endpoint` |  |  |
| [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-input-verdict) | MUST | partial | `class:2004` | No guardrail-verdict object. | [ocsf_ai_guardrail](#ask-ocsf-ai-guardrail) |
| [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#f-response-model-output) | MUST | partial | `object:message_context`, `attribute:response_text` | No content hash or redaction flag. | [ocsf_message_context_content](#ask-ocsf-message-context-content) |
| [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination) | MUST | partial | `class:http_activity`, `class:network_activity` | No link from model output to the egress channel or recipient. | [ocsf_egress_correlation](#ask-ocsf-egress-correlation) |
| [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#f-citations-source-attribution) | MUST | none |  | No citation, and no resolution of a citation against retrieval. | [ocsf_citations](#ask-ocsf-citations) |
| [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-output-verdict) | MUST | partial | `class:2004` | No guardrail-verdict object. | [ocsf_ai_guardrail](#ask-ocsf-ai-guardrail) |
| [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) | MUST | none |  | No refusal status or reason; the Content Filter stop reason proposed in. | [ocsf_stop_reason](#ask-ocsf-stop-reason) |
| [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) | MUST | none |  | No attachment identity. | [ocsf_message_context_content](#ask-ocsf-message-context-content) |
| [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) | MUST | none |  | No attribute-provenance marking. | [ocsf_attribute_source](#ask-ocsf-attribute-source) |
| [Instrumentation Coverage / Hook Status](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) | MUST | none |  | No hook-coverage representation. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode) | MUST | none |  | No enforcement availability or fail-open representation. | [ocsf_ai_guardrail](#ask-ocsf-ai-guardrail) |
| [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) | MUST | none |  | No record that an enforcement point rewrote a payload. | [ocsf_ai_guardrail](#ask-ocsf-ai-guardrail), [ocsf_message_context_content](#ask-ocsf-message-context-content) |
| [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) | MUST | none |  | No obfuscation flag or decoded form. | [ocsf_obfuscation](#ask-ocsf-obfuscation) |
| [Observation / Thought (reasoning trace)](Telemetry-Attack-Detection-Addendum.md#f-observation-thought-reasoning-trace) | SHOULD | none |  | No reasoning trace. No ask proposed. |  |
| [Threat Classification / ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#f-threat-classification-atlas-technique-tag) | MAY | covered | `class:2004`, `attribute:attacks` | No schema change: populate attacks[].technique.uid with AML.Txxxx, the tactic, and attacks[].version with the ATLAS matrix version. |  |

**RFC §6.3 Tool calls and policy decisions**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#f-execution-environment-sandbox) | MUST | partial | `object:process`, `attribute:sandbox`, `object:container` | A sandbox name on a process, and container identity; no isolation mode, timeout or egress policy for a tool execution. | [ocsf_tool_execution_environment](#ask-ocsf-tool-execution-environment) |
| [Tool Call I/O](Telemetry-Attack-Detection-Addendum.md#f-tool-call-io) | MUST | partial | `class:6003` | No tool object. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [Tool Name](Telemetry-Attack-Detection-Addendum.md#f-tool-name) | MUST | none |  | No tool object. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#f-tool-type-trust-boundary) | MUST | none |  | No tool trust-boundary enum. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [Tool Execution ID](Telemetry-Attack-Detection-Addendum.md#f-tool-execution-id) | MUST | none |  | No tool-call join key. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#f-tool-definition-digest) | MUST | none |  | No tool-definition digest. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive) | MUST | none |  | No MCP object or primitive axis. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) | MUST | partial | `class:3003` | No authorization-decision object for AI operations. | [ocsf_ai_authorization](#ask-ocsf-ai-authorization) |
| [Tool Selection Rationale](Telemetry-Attack-Detection-Addendum.md#f-tool-selection-rationale) | SHOULD | none |  | No self-asserted rationale. No ask proposed. |  |
| [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#f-human-approval-elicitation-event) | SHOULD | none |  | No human-approval lifecycle. | [ocsf_ai_approval](#ask-ocsf-ai-approval) |
| [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#f-tool-acl-required-scope) | SHOULD | none |  | No tool scope attribute. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#f-session-taint-labels-information-flow-decisions) | SHOULD | none |  | No information-flow or taint labels. | [ocsf_ai_taint](#ask-ocsf-ai-taint) |
| [Backend / Route Restriction Decision](Telemetry-Attack-Detection-Addendum.md#f-backend-route-restriction-decision) | SHOULD | none |  | No routing constraint or candidate backends. | [ocsf_backend_route](#ask-ocsf-backend-route) |
| [Mediation Coverage & Bypass Path](Telemetry-Attack-Detection-Addendum.md#f-mediation-coverage-bypass-path) | SHOULD | none |  | No mediation-coverage representation. | [ocsf_mediation_coverage](#ask-ocsf-mediation-coverage) |
| [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-tool-error-exception) | MAY | partial | `attribute:status_id`, `attribute:status_detail` | An outcome on API Activity, not tied to a tool call. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [Tool ID](Telemetry-Attack-Detection-Addendum.md#f-tool-id) | MAY | none |  | No tool object. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [Tool Privacy Classification](Telemetry-Attack-Detection-Addendum.md#f-tool-privacy-classification) | MAY | partial | `profile:data_classification`, `object:data_classification`, `attribute:confidentiality` | Classification attaches to data, not to the tool that touches it. No ask proposed. |  |
| [Policy Reason Code](Telemetry-Attack-Detection-Addendum.md#f-policy-reason-code) | MAY | none |  | No machine-readable enforcement reason code. | [ocsf_ai_authorization](#ask-ocsf-ai-authorization) |

**RFC §6.4 Memory and retrieval**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Memory Write Event](Telemetry-Attack-Detection-Addendum.md#f-memory-write-event) | MUST | partial | `class:6005` | Datastore Activity fits loosely; no memory-operation object. | [ocsf_ai_memory](#ask-ocsf-ai-memory) |
| [Memory Read / Injection Event](Telemetry-Attack-Detection-Addendum.md#f-memory-read-injection-event) | MUST | partial | `class:6005` | Datastore Activity fits loosely; no memory-operation object. | [ocsf_ai_memory](#ask-ocsf-ai-memory) |
| [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#f-memory-provenance-source) | MUST | none |  | No memory provenance. | [ocsf_ai_memory](#ask-ocsf-ai-memory) |
| [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#f-memory-footprint-growth) | MUST | none |  | No memory footprint. | [ocsf_ai_memory](#ask-ocsf-ai-memory) |
| [Retrieval Event](Telemetry-Attack-Detection-Addendum.md#f-retrieval-event) | MUST | partial | `class:6005` | No retrieval object. | [ocsf_ai_retrieval](#ask-ocsf-ai-retrieval) |
| [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-source-provenance) | MUST | none |  | No retrieved-content source or provenance. | [ocsf_ai_retrieval](#ask-ocsf-ai-retrieval) |
| [Memory Integrity / Poisoning Signal](Telemetry-Attack-Detection-Addendum.md#f-memory-integrity-poisoning-signal) | SHOULD | none |  | No poisoning or isolation signal. | [ocsf_ai_memory](#ask-ocsf-ai-memory) |
| [Memory Write Rationale](Telemetry-Attack-Detection-Addendum.md#f-memory-write-rationale) | SHOULD | none |  | No self-asserted rationale. No ask proposed. |  |
| [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) | SHOULD | none |  | No retrieved-content integrity signal. | [ocsf_ai_retrieval](#ask-ocsf-ai-retrieval) |
| [Declared Memory Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-memory-configuration) | MAY | none |  | No memory-store declaration. No ask proposed. |  |
| [Declared Knowledge-Source Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-knowledge-source-configuration) | MAY | none |  | No knowledge-source declaration. No ask proposed. |  |

**RFC §6.5 Orchestration**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) | MUST | none |  | No inter-agent message. | [ocsf_ai_agent_activity](#ask-ocsf-ai-agent-activity) |
| [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) | MUST | none |  | No background-task event. | [ocsf_ai_agent_activity](#ask-ocsf-ai-agent-activity) |
| [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) | MUST | none |  | No loop or step signal. | [ocsf_ai_agent_activity](#ask-ocsf-ai-agent-activity) |
| [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) | MUST | none |  | No resource aggregate, and no budget accounting on the consuming action. | [ocsf_ai_agent_activity](#ask-ocsf-ai-agent-activity), [ocsf_ai_authorization](#ask-ocsf-ai-authorization) |
| [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#f-task-intent-declaration) | SHOULD | partial | `object:ai_agent`, `attribute:charter` | A charter defines the agent's role, scope and operating bounds, not the purpose declared for this run. | [ocsf_task_intent](#ask-ocsf-task-intent) |
| [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) | SHOULD | none |  | No delegated-task lifecycle. | [ocsf_ai_delegation_activity](#ask-ocsf-ai-delegation-activity) |
| [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#f-peer-agent-card-descriptor) | SHOULD | partial | `object:ai_agent` | ai_agent can describe a counterparty; no descriptor change or verification outcome. | [ocsf_peer_agent_descriptor](#ask-ocsf-peer-agent-descriptor) |
| [Protocol Envelope Capture](Telemetry-Attack-Detection-Addendum.md#f-protocol-envelope-capture) | MAY | partial | `attribute:raw_data` | raw_data holds the source record before normalization, not the envelope of each MCP or A2A message. No ask proposed. |  |

**RFC §6.6 Identity, provenance and inventory**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) | MUST | none |  | No capability-change event. | [ocsf_ai_bom](#ask-ocsf-ai-bom), [ocsf_ai_agent_activity](#ask-ocsf-ai-agent-activity) |
| [Identities Used (per hop)](Telemetry-Attack-Detection-Addendum.md#f-identities-used-per-hop) | MUST | partial | `class:3002`, `object:delegation` | Credential events and the delegation context exist; per-hop identity is not tied to the AI operation. | [ocsf_delegation_lineage](#ask-ocsf-delegation-lineage) |
| [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#f-verified-vs-displayed-identity) | MUST | partial | `object:actor`, `object:user` | A user identifier and name both exist; no record of which one authorized. | [ocsf_identity_verification](#ask-ocsf-identity-verification) |
| [Originating Principal (on-behalf-of)](Telemetry-Attack-Detection-Addendum.md#f-originating-principal-on-behalf-of) | SHOULD | none |  | delegation records its issuer and lineage, not the originating principal. | [ocsf_delegation_lineage](#ask-ocsf-delegation-lineage) |
| [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) | SHOULD | partial | `object:delegation`, `attribute:parent_uid` | parent_uid is optional, so one record without it breaks the walk; no root or subtree identifier. | [ocsf_delegation_lineage](#ask-ocsf-delegation-lineage), [ocsf_ai_delegation_activity](#ask-ocsf-ai-delegation-activity) |
| [Granted Authorizations / Scope](Telemetry-Attack-Detection-Addendum.md#f-granted-authorizations-scope) | SHOULD | none |  | No granted scope on delegation. | [ocsf_delegation_lineage](#ask-ocsf-delegation-lineage) |
| [Resource Indicators + Constraints](Telemetry-Attack-Detection-Addendum.md#f-resource-indicators-constraints) | SHOULD | none |  | No constraints on delegation. | [ocsf_delegation_lineage](#ask-ocsf-delegation-lineage) |
| [Token Exchange & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#f-credential-minting-scope-narrowing-check) | SHOULD | partial | `class:3002` | No requested-versus-granted scope. | [ocsf_delegation_lineage](#ask-ocsf-delegation-lineage) |
| [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#f-trust-domain-crossing-delegation-depth) | SHOULD | none |  | No trust-domain crossing; depth derivable only if every hop carries parent_uid. | [ocsf_delegation_lineage](#ask-ocsf-delegation-lineage) |
| [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#f-runtime-credential-attestation) | SHOULD | none |  | No runtime attestation (OCSF attestation means record integrity). | [ocsf_runtime_attestation](#ask-ocsf-runtime-attestation) |
| [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#f-lifecycle-state) | SHOULD | none |  | No lifecycle state on delegation. | [ocsf_delegation_lineage](#ask-ocsf-delegation-lineage) |
| [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) | SHOULD | partial | `class:inventory_info` | No AI-asset object. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) | SHOULD | partial | `class:inventory_info` | No AI-asset object. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) | SHOULD | none |  | No agent-composition BOM. | [ocsf_ai_bom](#ask-ocsf-ai-bom) |
| [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) | SHOULD | none |  | No dependency graph. | [ocsf_ai_bom](#ask-ocsf-ai-bom) |
| [Inventory Integrity Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) | SHOULD | none |  | No BOM signature. | [ocsf_ai_bom](#ask-ocsf-ai-bom) |
| [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#f-event-sequence-continuity) | SHOULD | partial | `profile:record_integrity`, `object:attestation`, `attribute:prev_event`, `attribute:chain_uid`, `attribute:sequence` | No end-of-chain marker, so a truncated chain reads as an open one. `attestation.prev_event` and `chain_uid` link the records and `metadata.sequence` counts them. Scoping the count to a producer epoch and stream is a producer convention, not schema (AID-EMIT-1 section 7 [[87]](#other-sources)). | [ocsf_chain_end](#ask-ocsf-chain-end) |
| [Tool Description](Telemetry-Attack-Detection-Addendum.md#f-tool-description) | MAY | partial | `class:inventory_info` | No AI-asset object. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [Tool Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#f-tool-status) | MAY | partial | `class:inventory_info` | No AI-asset object. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#f-creator-id-oncall-creation-update-dates) | MAY | partial | `class:inventory_info` | No AI-asset object. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [Surfaces Supported](Telemetry-Attack-Detection-Addendum.md#f-surfaces-supported) | MAY | none |  | No per-tool exposure map. A MAY field; no ask. |  |
| [Fleet counts](Telemetry-Attack-Detection-Addendum.md#f-fleet-counts) | MAY | none |  | Fleet aggregates are derived. No ask proposed. |  |

**RFC §6.7 Training data and training infrastructure**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Training-Data Item Digest](Telemetry-Attack-Detection-Addendum.md#f-training-data-item-digest) | SHOULD | none |  | No training-time objects. | [ocsf_training_provenance](#ask-ocsf-training-provenance) |
| [Training-Data Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-training-data-source-provenance) | SHOULD | none |  | No training-time objects. | [ocsf_training_provenance](#ask-ocsf-training-provenance) |
| [Compute Job Submission](Telemetry-Attack-Detection-Addendum.md#f-compute-job-submission-event) | SHOULD | partial | `class:api_activity`, `attribute:actor`, `attribute:src_endpoint` | Generic API activity carries the caller and source; no job entrypoint or resources. | [ocsf_training_provenance](#ask-ocsf-training-provenance) |
<!-- END GENERATED: xm correspondence ocsf -->

### 1.3 Gaps

The table states each gap. Two need more than a cell.

**Delegation lineage.** No granted scope / constraints, runtime credential attestation, trust-domain crossing, lifecycle state. Depth is derivable **only if every hop carries `parent_uid`, which is optional today** ([ocsf-schema#1739](https://github.com/ocsf/ocsf-schema/issues/1739)): a fully conformant producer can emit a re-delegated action with no parent link, and one such record anywhere in the chain breaks the walk without anyone violating the schema. A walk is also not a join, so reconstructing a subtree means resolving every intermediate delegation out of band, which an aggregate check evaluated at the consuming action (**Resource-Consumption Aggregate**, AD §1.5, MUST) cannot afford at request latency.

**Authorization and accounting.** No authorization-decision object for AI operations; no information-flow/taint labels; no human-approval lifecycle; no attribute-provenance marking; no mediation-coverage representation. No carrier for the **accounting decision** either: the aggregate consumed and remaining against the *principal's* budget, recorded on the action that consumed it. A dictionary search (2026-08-25) found no attributes in that family, and a metric cannot testify because it does not survive with the action record.

### 1.4 Asks

<!-- BEGIN GENERATED: xm asks ocsf -->
<a id="ask-ocsf-ai-tool"></a>**`ocsf_ai_tool`** (open; [ocsf-schema#1729](https://github.com/ocsf/ocsf-schema/pull/1729)). Land the ai_capability object: name, kind (type_id), serving system and transport, the transaction_uid join key, and fingerprints of the description and schemas with an approved baseline. At the pull request's head (`b6e44ac`, 2026-09-29) type_id has Tool, Resource and Prompt Template: extend it to the client-side MCP primitives (sampling, elicitation, roots), and add a trust-boundary value set and a required-scope attribute. *Closes:* [Tool Call I/O](Telemetry-Attack-Detection-Addendum.md#f-tool-call-io) (MUST, 19 instances), [Tool Name](Telemetry-Attack-Detection-Addendum.md#f-tool-name) (MUST, 6 instances), [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#f-tool-type-trust-boundary) (MUST, 2 instances), [Tool Execution ID](Telemetry-Attack-Detection-Addendum.md#f-tool-execution-id) (MUST, 2 instances), [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#f-tool-definition-digest) (MUST, 2 instances), [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive) (MUST, 5 instances), [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#f-tool-acl-required-scope) (SHOULD, 6 instances), [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-tool-error-exception) (MAY, 0 instances) and [Tool ID](Telemetry-Attack-Detection-Addendum.md#f-tool-id) (MAY, 0 instances). Its fingerprints reuse the `fingerprint` object, which declares `serialization_id`, so this ask already meets the canonicalization rule stated after the asks.

<a id="ask-ocsf-delegation-lineage"></a>**`ocsf_delegation_lineage`** (open; [ocsf-schema#1739](https://github.com/ocsf/ocsf-schema/issues/1739) [ocsf-schema#1756](https://github.com/ocsf/ocsf-schema/issues/1756)). Extend delegation with scope, constraints and lifecycle state; require parent_uid where a parent exists; add a root or subtree identifier. *Closes:* [Identities Used (per hop)](Telemetry-Attack-Detection-Addendum.md#f-identities-used-per-hop) (MUST, 18 instances), [Originating Principal (on-behalf-of)](Telemetry-Attack-Detection-Addendum.md#f-originating-principal-on-behalf-of) (SHOULD, 3 instances), [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) (SHOULD, 2 instances), [Granted Authorizations / Scope](Telemetry-Attack-Detection-Addendum.md#f-granted-authorizations-scope) (SHOULD, 3 instances), [Resource Indicators + Constraints](Telemetry-Attack-Detection-Addendum.md#f-resource-indicators-constraints) (SHOULD, 0 instances), [Token Exchange & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#f-credential-minting-scope-narrowing-check) (SHOULD, 1 instance), [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#f-trust-domain-crossing-delegation-depth) (SHOULD, 1 instance) and [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#f-lifecycle-state) (SHOULD, 2 instances). ocsf-schema#1756 proposes the constraints as a `constraint` object. Enforcement points already hold per-hop subject, audience, granted scopes and TTL; the schema has no place for them.

<a id="ask-ocsf-ai-agent-activity"></a>**`ocsf_ai_agent_activity`** (open; [ocsf-schema#1640](https://github.com/ocsf/ocsf-schema/issues/1640)). Ratify an AI Agent Activity class (9001) for agent-originated control-plane events: inter-agent messages, background tasks, loop and resource aggregates, capability changes. *Closes:* [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) (MUST, 6 instances), [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) (MUST, 3 instances), [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) (MUST, 5 instances), [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) (MUST, 4 instances) and [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) (MUST, 4 instances). Draft ocsf-schema#1754 adds an AI Agent Activity class as 6009 in Application Activity, not 9001. Its nine activities follow agent hook points, and it carries none of the five fields: Subagent Start and Stop have no attributes, so they record no sender, receiver, content, channel or step count, and no activity covers scheduled tasks, resource totals or capability changes.

<a id="ask-ocsf-ai-authorization"></a>**`ocsf_ai_authorization`** (open; [ocsf-schema#1756](https://github.com/ocsf/ocsf-schema/issues/1756)). Add an ai_authorization object (decision, reason, code, deciding authority, rule, obligations, budget accounting and the principal or subtree join key). *Closes:* [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) (MUST, 9 instances), [Policy Reason Code](Telemetry-Attack-Detection-Addendum.md#f-policy-reason-code) (MAY, 0 instances) and [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) (MUST, 4 instances). The budget accounting is the consumption side of the `constraint` object ocsf-schema#1756 proposes on delegation.

<a id="ask-ocsf-stop-reason"></a>**`ocsf_stop_reason`** (open; [ocsf-schema#1704](https://github.com/ocsf/ocsf-schema/pull/1704)). Merge the ai_status object on the ai_operation profile; its stop_reason_id carries End of Turn, Token Limit, Tool Use, Session Stop and Content Filter. *Closes:* [Stop Reason](Telemetry-Attack-Detection-Addendum.md#f-stop-reason) (MUST, 3 instances) and [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) (MUST, 9 instances).

<a id="ask-ocsf-ai-bom"></a>**`ocsf_ai_bom`** (open; [ocsf-schema#1724](https://github.com/ocsf/ocsf-schema/issues/1724)). Add an ai_bom object (BOM reference, format, signature, dependency edges) and a capability-change activity on Agent Activity. *Closes:* [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) (MUST, 4 instances), [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) (SHOULD, 2 instances), [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) (SHOULD, 1 instance) and [Inventory Integrity Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) (SHOULD, 0 instances). A [draft class](https://github.com/Levaj2000/AI-Identity/tree/main/docs/ocsf-1724-class-draft) for #1724, AI Agent Trust Inventory, has `agent_artifact` with a `fingerprint`, `agent_config_declaration`, `agent_execution_params` and `agent_credential`. It carries Inventory Integrity Signature as `record_integrity` on the inventory event, with one `chain_uid` per instance, so a gap in the chain is an unrecorded change.

<a id="ask-ocsf-ai-asset"></a>**`ocsf_ai_asset`** (open; [ocsf-schema#1724](https://github.com/ocsf/ocsf-schema/issues/1724)). Add an ai_asset object (version, software reference, ownership, status, instrumentation coverage). *Closes:* [Instrumentation Coverage / Hook Status](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) (MUST, on a dependency), [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) (SHOULD, 2 instances), [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) (SHOULD, 2 instances), [Tool Description](Telemetry-Attack-Detection-Addendum.md#f-tool-description) (MAY, 0 instances), [Tool Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#f-tool-status) (MAY, 0 instances) and [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#f-creator-id-oncall-creation-update-dates) (MAY, 0 instances). Shape it against the #1724 draft class under [`ocsf_ai_bom`](#ask-ocsf-ai-bom).

<a id="ask-ocsf-ai-delegation-activity"></a>**`ocsf_ai_delegation_activity`** (open; [ocsf-schema#1640](https://github.com/ocsf/ocsf-schema/issues/1640)). Ratify an AI Delegation Activity class (9002) for the delegation lifecycle. *Closes:* [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) (SHOULD, 0 instances) and [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) (SHOULD, 2 instances).

<a id="ask-ocsf-message-context-content"></a>**`ocsf_message_context_content`** (proposed). Extend message_context with prompt and response hashes, a redaction flag, the system prompt and its hash, and attachment identity. Each hash declares its canonicalization and may be a keyed digest with a key identifier; an absent hash means not digested, never unchanged. *Closes:* [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) (MUST, 4 instances), [Model Input](Telemetry-Attack-Detection-Addendum.md#f-model-input) (MUST, 18 instances), [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#f-response-model-output) (MUST, 12 instances), [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) (MUST, 3 instances) and [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) (MUST, on a dependency). The AID-EMIT-1 record format [[87]](#other-sources) carries digests in that form today, `hmac-sha256:<key_id>:<hex>` or `sha256:<hex>`, taken at pipeline entry and at emission. Equal digests under one key identifier mean the content passed unchanged.

<a id="ask-ocsf-ai-memory"></a>**`ocsf_ai_memory`** (proposed). Add an ai_memory object (operation, provenance, footprint, poisoning score, isolation verified). *Closes:* [Memory Write Event](Telemetry-Attack-Detection-Addendum.md#f-memory-write-event) (MUST, 7 instances), [Memory Read / Injection Event](Telemetry-Attack-Detection-Addendum.md#f-memory-read-injection-event) (MUST, 6 instances), [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#f-memory-provenance-source) (MUST, 4 instances), [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#f-memory-footprint-growth) (MUST, 2 instances) and [Memory Integrity / Poisoning Signal](Telemetry-Attack-Detection-Addendum.md#f-memory-integrity-poisoning-signal) (SHOULD, 3 instances).

<a id="ask-ocsf-ai-retrieval"></a>**`ocsf_ai_retrieval`** (proposed). Add an ai_retrieval object (query, items, source and provenance, integrity signal). *Closes:* [Retrieval Event](Telemetry-Attack-Detection-Addendum.md#f-retrieval-event) (MUST, 9 instances), [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-source-provenance) (MUST, 7 instances) and [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) (SHOULD, 2 instances).

<a id="ask-ocsf-ai-operation-identifiers"></a>**`ocsf_ai_operation_identifiers`** (proposed). Extend the ai_operation profile with run, turn and step identifiers, action type and trigger type. *Closes:* [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#f-workflow-run-id) (MUST, on a dependency), [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#f-session-turn-step-ids) (MUST, 5 instances), [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#f-trigger-type-source-event) (MUST, 5 instances) and [Action Type](Telemetry-Attack-Detection-Addendum.md#f-action-type) (MUST, 6 instances).

<a id="ask-ocsf-ai-guardrail"></a>**`ocsf_ai_guardrail`** (proposed). Add an ai_guardrail object (type, verdict, score, blocked flag, threat reference), with enforcement availability and failure-mode attributes. *Closes:* [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-input-verdict) (MUST, 8 instances), [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-output-verdict) (MUST, 5 instances), [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode) (MUST, on a dependency) and [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) (MUST, on a dependency). A Guardrail Modification Record needs no content. Three facts on one record carry it: a modifying step naming the enforcement point, an allow-after-modification verdict, and entry and emission digests that differ under one key. The AID-EMIT-1 record format [[87]](#other-sources) carries that composition, and codes a fail-closed failure as a deny distinct from a policy deny. Whether the enforcement point was reached at all has no carrier yet.

<a id="ask-ocsf-trust-level"></a>**`ocsf_trust_level`** (proposed). Add a trust_level enum usable on content and message objects. *Closes:* [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification) (MUST, 12 instances).

<a id="ask-ocsf-egress-correlation"></a>**`ocsf_egress_correlation`** (proposed). Add an egress correlation attribute linking model output to its destination, recipient or URL. *Closes:* [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination) (MUST, 11 instances).

<a id="ask-ocsf-input-segment-source"></a>**`ocsf_input_segment_source`** (proposed). Add a per-segment source to message_context: the surface, tool, agent or document each input segment came from, beside the proposed trust_level. *Closes:* [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#f-input-source-channel) (MUST, 7 instances).

<a id="ask-ocsf-attribute-source"></a>**`ocsf_attribute_source`** (proposed). Add an attribute_source enum (idp, pdp, enforcement-state, platform, self-asserted) usable on identity, authorization and agent-state attributes. *Closes:* [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) (MUST, 6 instances).

<a id="ask-ocsf-identity-verification"></a>**`ocsf_identity_verification`** (proposed). Record which identity authorized an operation (a verified identifier or a display name) and the verification outcome, on actor or ai_authorization. *Closes:* [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#f-verified-vs-displayed-identity) (MUST, 4 instances).

<a id="ask-ocsf-citations"></a>**`ocsf_citations`** (proposed). Add citations to message_context, each with its source and whether it resolves to an item an ai_retrieval record returned, aligned with AITF rag.citation.*. *Closes:* [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#f-citations-source-attribution) (MUST, 3 instances).

<a id="ask-ocsf-entry-point"></a>**`ocsf_entry_point`** (proposed). Add an entry point to ai_operation: the surface an operation arrived through (CLI, web, IDE, email, chat, scheduler) and whether it is internal or external. *Closes:* [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) (MUST, 3 instances).

<a id="ask-ocsf-obfuscation"></a>**`ocsf_obfuscation`** (proposed). Add an obfuscation finding (detected, encodings, decoded form or its hash) to ai_guardrail or Detection Finding, aligned with AITF security.obfuscation.*. *Closes:* [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) (MUST, 3 instances).

<a id="ask-ocsf-tool-execution-environment"></a>**`ocsf_tool_execution_environment`** (proposed). Add the execution environment of a tool call (isolation mode, runtime, timeout and egress policy) beside ai_capability, aligned with AITF supply_chain.runtime.*. *Closes:* [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#f-execution-environment-sandbox) (MUST, 3 instances).

<a id="ask-ocsf-ai-error"></a>**`ocsf_ai_error`** (proposed). Add an AI error type to ai_operation beside status_id: provider error, context overflow, rate limit, content filter, silent truncation. *Closes:* [LLM Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-llm-error-exception) (MUST, 2 instances).

<a id="ask-ocsf-inference-parameters"></a>**`ocsf_inference_parameters`** (proposed). Add the decoding parameters in force for a call (temperature, top_p, max_tokens, stop sequences, seed) and the declared context window to ai_model or message_context. *Closes:* [Inference Parameters](Telemetry-Attack-Detection-Addendum.md#f-inference-parameters) (MUST, 2 instances).

<a id="ask-ocsf-ai-approval"></a>**`ocsf_ai_approval`** (proposed). Add an ai_approval object (correlation ID, status, identity-provider-verified approver, channel, scope-binding result). *Closes:* [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#f-human-approval-elicitation-event) (SHOULD, 7 instances).

<a id="ask-ocsf-task-intent"></a>**`ocsf_task_intent`** (proposed). Add the purpose declared for a run to ai_operation, distinct from the agent charter on ai_agent. *Closes:* [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#f-task-intent-declaration) (SHOULD, 4 instances).

<a id="ask-ocsf-training-provenance"></a>**`ocsf_training_provenance`** (proposed). Add training-time records: a training-data item with its digest and its source or provenance (origin, license, acquisition time), and a compute job submission (submitter, entrypoint, image, requested resources). *Closes:* [Training-Data Item Digest](Telemetry-Attack-Detection-Addendum.md#f-training-data-item-digest) (SHOULD, 1 instance), [Training-Data Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-training-data-source-provenance) (SHOULD, 2 instances) and [Compute Job Submission](Telemetry-Attack-Detection-Addendum.md#f-compute-job-submission-event) (SHOULD, 1 instance).

<a id="ask-ocsf-ai-taint"></a>**`ocsf_ai_taint`** (proposed). Add an ai_taint object: the label set at entry and the final label set, so the labels an operation added are their difference; scope; origin; and taint-caused denial. *Closes:* [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#f-session-taint-labels-information-flow-decisions) (SHOULD, 3 instances). Records in the AID-EMIT-1 format [[87]](#other-sources) carry both sets today, outside the schema.

<a id="ask-ocsf-tenant-scopes"></a>**`ocsf_tenant_scopes`** (proposed). Carry the tenant of the agent, of the session and of the invoking user as separate attributes, beside metadata.tenant_uid. *Closes:* [Organization / Tenant ID](Telemetry-Attack-Detection-Addendum.md#f-organization-tenant-id) (SHOULD, 3 instances).

<a id="ask-ocsf-autonomy-level"></a>**`ocsf_autonomy_level`** (proposed). Add an autonomy_level enum. *Closes:* [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) (SHOULD, 2 instances).

<a id="ask-ocsf-mediation-coverage"></a>**`ocsf_mediation_coverage`** (proposed). Record whether a reference monitor mediated an operation and, where none did, the path that bypassed it. *Closes:* [Mediation Coverage & Bypass Path](Telemetry-Attack-Detection-Addendum.md#f-mediation-coverage-bypass-path) (SHOULD, 1 instance).

<a id="ask-ocsf-peer-agent-descriptor"></a>**`ocsf_peer_agent_descriptor`** (proposed). Record a counterparty agent descriptor at contact: its digest, whether it changed since the last contact, and the verification outcome. *Closes:* [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#f-peer-agent-card-descriptor) (SHOULD, 1 instance).

<a id="ask-ocsf-backend-route"></a>**`ocsf_backend_route`** (proposed). Add the routing constraint in force, the candidate backends and the backend chosen to ai_operation. *Closes:* [Backend / Route Restriction Decision](Telemetry-Attack-Detection-Addendum.md#f-backend-route-restriction-decision) (SHOULD, 0 instances).

<a id="ask-ocsf-chain-end"></a>**`ocsf_chain_end`** (proposed). Add an end-of-chain marker to attestation, so a verifier can tell a closed chain from a truncated one. The signature bytes on digital_signature, merged as ocsf-schema#1709 after 1.9.0, complete the signed chain head. *Closes:* [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#f-event-sequence-continuity) (SHOULD, 0 instances). The OpenTelemetry Audit Logging data model already carries the marker as `audit.sequence.end` [[88]](#other-sources).

<a id="ask-ocsf-model-provenance"></a>**`ocsf_model_provenance`** (proposed). Standardize model provider and provenance or signing attributes in ai_operation. *Closes:* [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) (SHOULD, 0 instances).

<a id="ask-ocsf-runtime-attestation"></a>**`ocsf_runtime_attestation`** (proposed). Add a runtime_attestation object carrying independently issued evidence objects and an explicit not-available status with a reason. *Closes:* [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#f-runtime-credential-attestation) (SHOULD, 0 instances). The field needs both halves, each its own evidence object: the runtime workload credential with its attestor and freshness, and the software evidence of what ran. The #1724 draft class under [`ocsf_ai_bom`](#ask-ocsf-ai-bom) carries the second as `agent_artifact.fingerprint`.
<!-- END GENERATED: xm asks ocsf -->

**How the asks fit together.**

1. **Promote the two proposed AI event classes to ratified:** **AI Agent Activity (9001)** and **AI Delegation Activity (9002)** ([ocsf-schema#1640](https://github.com/ocsf/ocsf-schema/issues/1640); the OCSF working group agreed 2026-09-04 that Application Lifecycle is not the home for 9001). **The boundary against tool invocation, stated so that adjacent proposals arrive reconciled rather than adjudicated at OCSF:** a per-invocation tool record rides **API Activity (6003) with `ai_capability`** ([ocsf-schema#1729](https://github.com/ocsf/ocsf-schema/pull/1729)), while **9001** carries agent-originated **control-plane lifecycle** events. Draft [ocsf-schema#1754](https://github.com/ocsf/ocsf-schema/pull/1754) crosses that line: its Tool Use activity carries `ai_agent_tool_use_info` (`name`, `ai_tool_input`, `ai_tool_response`), a per-invocation record with no `transaction_uid`. It fits the split if Tool Use joins on `ai_capability`'s `transaction_uid` and does not restate the tool's identity. Likewise, a dedicated per-invocation class, proposed separately from CoSAI WS4's containment work, is compatible with that split provided it joins on `ai_capability`'s `transaction_uid` rather than restating its fields; three artifacts adjacent to "what the agent did" otherwise read as overlapping asks.
2. **Extend the existing `ai_operation` profile** (which already carries `ai_agent`, `ai_model`, `delegation`, `message_context`, and, once ocsf-schema#1704 merges, `ai_status`) so that it represents the [field catalog](CoSAI-AI-Telemetry-RFC.md#6-field-catalog) using **class- and activity-specific applicability**: common correlation attributes are required at profile level, while the remaining MUST fields are required when their defining operation or event applies. SHOULD/MAY fields remain recommended/optional within the same applicable scope.
3. **Add or extend AI-specific objects:** extend `message_context` (content hashes, redaction flags, system prompt) and `delegation` (scope, constraints, lifecycle state); land `ai_capability` (ocsf-schema#1729); add `ai_guardrail`, `ai_memory`, `ai_retrieval`, `runtime_attestation`, `ai_asset`, `ai_bom`, `ai_authorization`, `ai_taint`, `ai_approval`. **Every hash-bearing attribute proposed here carries or references a canonicalization declaration, per [§2.8](#28-context-propagation-sampling-privacy-and-canonicalization)**: the content hashes on `message_context`, the tool-definition digest, attachment hashes, and the `ai_bom` signature, not only `attestation.fingerprint`. Without it the same silent degradation from "verify" to "trust the producer" reappears one field over.
4. **Add AI-specific enums:** `trust_level`, `autonomy_level` (L1 to L5), `tool_trust_boundary`, `memory_provenance`, `enforcement_decision` (allow / deny, the terminal verdict, with an `is_modified` flag for allow-after-modification and a machine-readable code on deny; a fail-closed enforcement failure is a deny coded as such, and **budget-exceeded / aggregate-threshold** is a deny code of its own, so that a denial on accumulated consumption is queryable as distinct from one on the operation's own payload), `enforcement_step_action` (allowed / denied / modified_payload / modified_extensions / deny_ignored / aborted / error, one per plugin or rule that ran; `deny_ignored` is not `allowed`, so that a suppressed deny is queryable, and `aborted` is not `error`, so that a cancellation does not read as a crash; a denying step names the violation that produced it), `enforcement_failure_mode` (fail-open / fail-closed). The verdict and step vocabularies are running code in the AID-EMIT-1 record format [[87]](#other-sources), section 9, with conformance vectors for every case. Further enums: the client-side MCP primitives (sampling / elicitation / roots) on `ai_capability.type_id`, which #1729 defines for tool, resource and prompt, `trigger_type` (user-initiated / autonomous), **`attribute_source`** (idp / pdp / enforcement-state / platform / self-asserted), **`taint_scope`** (session / message), **`approval_status`** (pending / resolved / expired / bypassed).

### 1.5 What it contributes

**ATLAS technique tagging needs no OCSF change.** Detection Finding's `attacks[]` is already documented as compatible with MITRE ATLAS [[1]](#primary-sources-attack-corpus--taxonomy) tactics, techniques and sub-techniques, and `attack.version` carries the matrix version. The [ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping) is portable today; this document supplies the producer guidance (populate `attacks[].technique.uid` with `AML.Txxxx`) rather than an ask.

For **Event Sequence Continuity**, `metadata.sequence` counts records and the `attestation` object of the `record_integrity` profile links them (`prev_event`, `chain_uid`); only an end-of-chain marker is missing ([`ocsf_chain_end`](#ask-ocsf-chain-end)). `ai_agent` already separates a stable agent identifier from a restart-sensitive instance identifier.

### 1.6 Divergences and open items

**Agent attribution rides `ai_agent`, not an actor type.** OWASP AOS's OCSF binding currently represents the agent through the `actor.user` type enum with an "Other" override and a free-text `"AI Agent"`: a documented workaround, and one that types the agent as a kind of user. The OCSF `actor` object has no type of its own. The correct representation exists: `ai_agent` on the `ai_operation` profile for which agent acted, and `delegation` for whose authority it acted under. The change is on the AOS side (see [§4.4](#44-asks)): migrate the binding to `ai_agent` + `delegation`.

---

## 2. OpenTelemetry

### 2.1 What it is, and the version mapped

The OpenTelemetry and OCSF proposals should be sequenced together, with AITF carrying the interim binding ([§3](#3-aitf)).

**Scope of the ask.** OpenTelemetry is not a security telemetry framework and should not become one. Its GenAI conventions are shaped by observability concerns, latency, cost, token accounting, evaluation quality, and that is the right center of gravity. The argument here is narrower: **OTel's ubiquity means it is where AI instrumentation is being written**, so the subset of security-relevant fields that map cleanly onto its existing model should be added to the specification, so that deployments already running OTel get them by default rather than by bespoke effort. Fields that do not map cleanly, such as authorization decisions, delegation chains, and information-flow labels, are noted as such and left to OCSF. **This section asks OTel to cover what OTel is already shaped to cover, and no more.**

> **Convention status.** The GenAI conventions **moved** out of the main `open-telemetry/semantic-conventions` repository into a dedicated **`open-telemetry/semantic-conventions-genai`** repository; the attributes still listed in the main registry are marked *Deprecated*, mostly to reflect the relocation; some were renamed or withdrawn in the move [[35]](#standards--frameworks). Every convention cited below carries **Status: Development**: none is stable, which is precisely why this is the moment to contribute.

The conventions are richer than is commonly assumed, and several fields in fact have a natural OTel home already.

- **Spans.** `chat`, `text_completion`, `embeddings`, `generate_content`, `execute_tool`, `create_agent`, `invoke_agent` (client and internal variants), `invoke_workflow`, and a **`plan`** span, discriminated by `gen_ai.operation.name`.
- **Core attributes.** `gen_ai.provider.name`; `gen_ai.agent.id` / `.name` / `.description` / `.version`; `gen_ai.conversation.id`; `gen_ai.workflow.name`; `gen_ai.request.model` and the full decoding set (`temperature`, `top_p`, `top_k`, `max_tokens`, `stop_sequences`, `seed`, `frequency_penalty`, `presence_penalty`, `choice.count`, `stream`); `gen_ai.response.id` / `.model` / `.finish_reasons`; `gen_ai.usage.input_tokens` / `.output_tokens` / `.reasoning.output_tokens` / `.cache_read.input_tokens` / `.cache_write.input_tokens`.
- **Content and definitions.** `gen_ai.input.messages`, `gen_ai.output.messages`, **`gen_ai.system_instructions`**, **`gen_ai.tool.definitions`**, `gen_ai.tool.name` / `.description` / `.type` / `.call.id` / `.call.arguments` / `.call.result`, `gen_ai.output.type`, `gen_ai.prompt.name`.
- **Retrieval.** **`gen_ai.retrieval.query.text`**, **`gen_ai.retrieval.documents`**, `gen_ai.data_source.id`, `gen_ai.embeddings.dimension.count`.
- **Memory.** A **`gen_ai.memory.*`** namespace: `store.id`, `record.id`, `record.count`, `query.text`, `records`, with a `MemoryRecord` schema (`content`, `id`, `metadata`, `score`); seven memory operations on `gen_ai.operation.name` (`create_memory`, `create_memory_store`, `delete_memory`, `delete_memory_store`, `search_memory`, `update_memory`, `upsert_memory`); and a **`gen_ai.memory.client`** span, already implemented by `aws-bedrock-agentcore` and `google-adk`.
- **Evaluation.** A `gen_ai.evaluation.result` event with `gen_ai.evaluation.name`, `.score.value`, `.score.label`, `.explanation`.
- **Metrics.** `gen_ai.client.operation.duration`, `gen_ai.client.token.usage`, `gen_ai.client.operation.time_to_first_chunk` / `.time_per_output_chunk`, `gen_ai.execute_tool.duration`, **`gen_ai.invoke_agent.duration` / `.inference_calls` / `.tool_calls`**, `gen_ai.invoke_workflow.duration`, `gen_ai.server.request.duration` / `.time_to_first_token` / `.time_per_output_token`.
- **MCP.** For the Model Context Protocol [[39]](#standards--frameworks), a distinct **`mcp.*`** namespace: `mcp.method.name`, `mcp.protocol.version`, `mcp.resource.uri`, `mcp.session.id`, plus `mcp.client.operation.duration`, `mcp.server.operation.duration`, and client/server `session.duration` metrics.

### 2.2 Correspondence

<!-- BEGIN GENERATED: xm correspondence otel -->
**RFC §6.1 Identifiers, trace context and model identity**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Agent Name](Telemetry-Attack-Detection-Addendum.md#f-agent-name) | MUST | covered | `gen_ai.agent.name` |  |  |
| [Agent (Runtime) Instance ID](Telemetry-Attack-Detection-Addendum.md#f-agent-runtime-instance-id) | MUST | covered | `gen_ai.agent.id` |  |  |
| [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#f-workflow-run-id) | MUST | partial | `gen_ai.workflow.name` | A workflow name, not a run identifier; the run maps to the trace ID. | [otel_run_id](#ask-otel-run-id) |
| [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#f-session-turn-step-ids) | MUST | partial | `gen_ai.conversation.id` | No turn or step identifier. | [otel_turn_step_ids](#ask-otel-turn-step-ids) |
| [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#f-trigger-type-source-event) | MUST | none |  | No trigger type or source event. | [otel_trigger](#ask-otel-trigger) |
| [Action Type](Telemetry-Attack-Detection-Addendum.md#f-action-type) | MUST | partial | `gen_ai.operation.name` | Operations include chat, execute_tool, invoke_agent and the memory operations; no inter-agent message send. | [otel_inter_agent_messaging](#ask-otel-inter-agent-messaging) |
| [Execution Status](Telemetry-Attack-Detection-Addendum.md#f-execution-status) | MUST | covered | `error.type` | With the span status. |  |
| [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) | MUST | none |  | No surface attribute. | [otel_entry_point](#ask-otel-entry-point) |
| [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) | MUST | covered | `gen_ai.system_instructions` | Gated behind content-capture opt-in. | [otel_hash_only_capture](#ask-otel-hash-only-capture) |
| [Model Name + Version](Telemetry-Attack-Detection-Addendum.md#f-model-name-version) | MUST | covered | `gen_ai.request.model`, `gen_ai.response.model` |  |  |
| [Inference Parameters](Telemetry-Attack-Detection-Addendum.md#f-inference-parameters) | MUST | covered | `gen_ai.request.temperature`, `gen_ai.request.top_p`, `gen_ai.request.max_tokens`, `gen_ai.request.stop_sequences`, `gen_ai.request.seed` |  |  |
| [Input / Output Token Counts](Telemetry-Attack-Detection-Addendum.md#f-input-output-token-counts) | MUST | covered | `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.client.token.usage` |  |  |
| [LLM Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-llm-error-exception) | MUST | covered | `error.type` |  |  |
| [Trace Context (propagated)](Telemetry-Attack-Detection-Addendum.md#f-trace-context-propagated) | MUST | covered |  | OpenTelemetry trace context (W3C traceparent) is core to the specification. |  |
| [Stop Reason](Telemetry-Attack-Detection-Addendum.md#f-stop-reason) | MUST | covered | `gen_ai.response.finish_reasons` |  |  |
| [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) | SHOULD | none |  | No autonomy level. | [otel_autonomy_level](#ask-otel-autonomy-level) |
| [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) | SHOULD | none |  | No model provenance or signing. | [otel_model_provenance](#ask-otel-model-provenance) |
| [Organization / Tenant ID](Telemetry-Attack-Detection-Addendum.md#f-organization-tenant-id) | SHOULD | none |  | No tenant attribute in the GenAI conventions. XM recommends adopting existing tenant and resource attributes rather than an ask. |  |
| [Provider / Endpoint Identity](Telemetry-Attack-Detection-Addendum.md#f-provider-endpoint-identity) | MAY | covered | `gen_ai.provider.name` |  |  |
| [Pre-Forward-Pass State Digest/Vector](Telemetry-Attack-Detection-Addendum.md#f-pre-forward-pass-state-digest-vector) | MAY | none |  | No forward-pass digest. A MAY research-grade signal; no ask. |  |
| [Token Malformation / Context-Corruption Indicator](Telemetry-Attack-Detection-Addendum.md#f-token-malformation-context-corruption-indicator) | MAY | none |  | No token-entropy signal. A MAY research-grade signal; no ask. |  |

**RFC §6.2 Content, trust, verdicts and their availability**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Model Input](Telemetry-Attack-Detection-Addendum.md#f-model-input) | MUST | covered | `gen_ai.input.messages` | Gated behind content-capture opt-in. | [otel_hash_only_capture](#ask-otel-hash-only-capture) |
| [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#f-input-source-channel) | MUST | none |  | No per-part input source. | [otel_input_part_source](#ask-otel-input-part-source) |
| [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification) | MUST | none |  | No trust-provenance concept. | [otel_trust_level](#ask-otel-trust-level) |
| [Source host / IP + request metadata](Telemetry-Attack-Detection-Addendum.md#f-source-host-ip-request-metadata) | MUST | covered | `client.address`, `network.peer.address`, `user_agent.original` |  |  |
| [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-input-verdict) | MUST | partial | `gen_ai.evaluation.score.value` | The evaluation event is quality-oriented: no blocked flag, guardrail type or threat technique. | [otel_security_guardrail](#ask-otel-security-guardrail) |
| [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#f-response-model-output) | MUST | covered | `gen_ai.output.messages` | Gated behind content-capture opt-in. | [otel_hash_only_capture](#ask-otel-hash-only-capture) |
| [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination) | MUST | none |  | No link from model output to its destination. | [otel_egress_pattern](#ask-otel-egress-pattern) |
| [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#f-citations-source-attribution) | MUST | partial | `gen_ai.retrieval.documents` | Output-side citations are not linked to retrieved items. | [otel_citations](#ask-otel-citations) |
| [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-output-verdict) | MUST | partial | `gen_ai.evaluation.score.value` | The evaluation event is quality-oriented. | [otel_security_guardrail](#ask-otel-security-guardrail) |
| [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) | MUST | partial | `gen_ai.response.finish_reasons` | A content-filter finish reason where the provider returns one; no refusal status or reason. | [otel_refusal](#ask-otel-refusal) |
| [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) | MUST | partial |  | Message parts carry types; no attachment name, size or hash. | [otel_attachment_identity](#ask-otel-attachment-identity) |
| [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) | MUST | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Instrumentation Coverage / Hook Status](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) | MUST | none |  | No instrumentation-coverage representation. | [otel_hook_coverage](#ask-otel-hook-coverage) |
| [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode) | MUST | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) | MUST | none |  | No record that an enforcement point rewrote a payload. | [otel_security_guardrail](#ask-otel-security-guardrail) |
| [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) | MUST | none |  | No obfuscation flag or decoded form. | [otel_obfuscation](#ask-otel-obfuscation) |
| [Observation / Thought (reasoning trace)](Telemetry-Attack-Detection-Addendum.md#f-observation-thought-reasoning-trace) | SHOULD | partial | `gen_ai.usage.reasoning.output_tokens` | A count of reasoning tokens, not the trace. No ask proposed. |  |
| [Threat Classification / ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#f-threat-classification-atlas-technique-tag) | MAY | none |  | No threat-technique reference. | [otel_security_guardrail](#ask-otel-security-guardrail) |

**RFC §6.3 Tool calls and policy decisions**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#f-execution-environment-sandbox) | MUST | none |  | No sandbox or isolation attributes. | [otel_execution_environment](#ask-otel-execution-environment) |
| [Tool Call I/O](Telemetry-Attack-Detection-Addendum.md#f-tool-call-io) | MUST | covered | `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result` |  |  |
| [Tool Name](Telemetry-Attack-Detection-Addendum.md#f-tool-name) | MUST | covered | `gen_ai.tool.name` |  |  |
| [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#f-tool-type-trust-boundary) | MUST | partial | `gen_ai.tool.type` | function, extension or datastore; no MCP, direct-storage or code-execution boundary. | [otel_tool_trust_boundary](#ask-otel-tool-trust-boundary) |
| [Tool Execution ID](Telemetry-Attack-Detection-Addendum.md#f-tool-execution-id) | MUST | covered | `gen_ai.tool.call.id` |  |  |
| [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#f-tool-definition-digest) | MUST | partial | `gen_ai.tool.definitions` | The definitions, not a stable digest of them. | [otel_tool_digest_mcp_primitive](#ask-otel-tool-digest-mcp-primitive) |
| [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive) | MUST | partial | `mcp.method.name`, `mcp.protocol.version`, `mcp.session.id` | No primitive discriminator; mcp.method.name partly serves. | [otel_tool_digest_mcp_primitive](#ask-otel-tool-digest-mcp-primitive) |
| [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) | MUST | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). | [otel_authorization_reference](#ask-otel-authorization-reference) |
| [Tool Selection Rationale](Telemetry-Attack-Detection-Addendum.md#f-tool-selection-rationale) | SHOULD | none |  | No self-asserted rationale. No ask proposed. |  |
| [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#f-human-approval-elicitation-event) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#f-tool-acl-required-scope) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#f-session-taint-labels-information-flow-decisions) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Backend / Route Restriction Decision](Telemetry-Attack-Detection-Addendum.md#f-backend-route-restriction-decision) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Mediation Coverage & Bypass Path](Telemetry-Attack-Detection-Addendum.md#f-mediation-coverage-bypass-path) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-tool-error-exception) | MAY | covered | `error.type` |  |  |
| [Tool ID](Telemetry-Attack-Detection-Addendum.md#f-tool-id) | MAY | none |  | Tool name and call ID only; no implementation ID across servers. A MAY field; no ask. |  |
| [Tool Privacy Classification](Telemetry-Attack-Detection-Addendum.md#f-tool-privacy-classification) | MAY | none |  | No data classification for a tool. A MAY field; no ask. |  |
| [Policy Reason Code](Telemetry-Attack-Detection-Addendum.md#f-policy-reason-code) | MAY | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |

**RFC §6.4 Memory and retrieval**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Memory Write Event](Telemetry-Attack-Detection-Addendum.md#f-memory-write-event) | MUST | covered | `gen_ai.memory.store.id`, `gen_ai.memory.record.id`, `gen_ai.operation.name` |  |  |
| [Memory Read / Injection Event](Telemetry-Attack-Detection-Addendum.md#f-memory-read-injection-event) | MUST | covered | `gen_ai.memory.query.text`, `gen_ai.memory.records` |  |  |
| [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#f-memory-provenance-source) | MUST | none |  | No provenance attribute in the gen_ai registry. | [otel_memory_provenance_footprint](#ask-otel-memory-provenance-footprint) |
| [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#f-memory-footprint-growth) | MUST | none |  | No footprint attribute in the gen_ai registry. | [otel_memory_provenance_footprint](#ask-otel-memory-provenance-footprint) |
| [Retrieval Event](Telemetry-Attack-Detection-Addendum.md#f-retrieval-event) | MUST | covered | `gen_ai.retrieval.query.text`, `gen_ai.retrieval.documents`, `gen_ai.data_source.id` |  |  |
| [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-source-provenance) | MUST | none |  | No per-item source or provenance. | [otel_retrieval_provenance](#ask-otel-retrieval-provenance) |
| [Memory Integrity / Poisoning Signal](Telemetry-Attack-Detection-Addendum.md#f-memory-integrity-poisoning-signal) | SHOULD | none |  | No integrity or poisoning signal. No ask proposed. |  |
| [Memory Write Rationale](Telemetry-Attack-Detection-Addendum.md#f-memory-write-rationale) | SHOULD | none |  | No self-asserted rationale. No ask proposed. |  |
| [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) | SHOULD | none |  | No per-item integrity signal or freshness. | [otel_retrieval_provenance](#ask-otel-retrieval-provenance) |
| [Declared Memory Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-memory-configuration) | MAY | partial | `gen_ai.memory.store.id` | Store identity only; no limits or retrieval settings. No ask proposed. |  |
| [Declared Knowledge-Source Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-knowledge-source-configuration) | MAY | partial | `gen_ai.data_source.id` | Data-source identity only; no schema or search parameters. No ask proposed. |  |

**RFC §6.5 Orchestration**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) | MUST | none |  | No inter-agent message attributes. | [otel_inter_agent_messaging](#ask-otel-inter-agent-messaging) |
| [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) | MUST | none |  | No background-task or termination-condition signal. | [otel_trigger](#ask-otel-trigger) |
| [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) | MUST | partial |  | Agent metrics count calls; no limit or termination semantics. | [otel_run_budget](#ask-otel-run-budget) |
| [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) | MUST | partial | `gen_ai.client.token.usage` | No per-run budget or threshold. | [otel_run_budget](#ask-otel-run-budget) |
| [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#f-task-intent-declaration) | SHOULD | none |  | No declared purpose for the run. | [otel_task_intent](#ask-otel-task-intent) |
| [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) | SHOULD | none |  | No A2A conventions. | [otel_a2a](#ask-otel-a2a) |
| [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#f-peer-agent-card-descriptor) | SHOULD | partial | `gen_ai.agent.name`, `gen_ai.agent.id`, `gen_ai.agent.description`, `gen_ai.agent.version` | Describes the agent a span is about; no counterparty descriptor, change or verification. | [otel_a2a](#ask-otel-a2a) |
| [Protocol Envelope Capture](Telemetry-Attack-Detection-Addendum.md#f-protocol-envelope-capture) | MAY | none |  | No raw protocol envelope. A MAY field; no ask. |  |

**RFC §6.6 Identity, provenance and inventory**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) | MUST | none |  | No capability-change event. | [otel_capability_change](#ask-otel-capability-change) |
| [Identities Used (per hop)](Telemetry-Attack-Detection-Addendum.md#f-identities-used-per-hop) | MUST | out of scope |  | An identity-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#f-verified-vs-displayed-identity) | MUST | out of scope |  | An identity-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Originating Principal (on-behalf-of)](Telemetry-Attack-Detection-Addendum.md#f-originating-principal-on-behalf-of) | SHOULD | out of scope |  | An identity-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) | SHOULD | out of scope |  | An identity-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Granted Authorizations / Scope](Telemetry-Attack-Detection-Addendum.md#f-granted-authorizations-scope) | SHOULD | out of scope |  | An identity-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Resource Indicators + Constraints](Telemetry-Attack-Detection-Addendum.md#f-resource-indicators-constraints) | SHOULD | out of scope |  | An identity-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Token Exchange & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#f-credential-minting-scope-narrowing-check) | SHOULD | out of scope |  | An identity-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#f-trust-domain-crossing-delegation-depth) | SHOULD | out of scope |  | An identity-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#f-runtime-credential-attestation) | SHOULD | out of scope |  | An identity-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#f-lifecycle-state) | SHOULD | out of scope |  | An identity-domain concern; carried by OCSF rather than pushed into OpenTelemetry (§2.6). |  |
| [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) | SHOULD | partial | `gen_ai.agent.version` | Agent version only; no tool or framework version. | [otel_tool_code_ref](#ask-otel-tool-code-ref) |
| [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) | SHOULD | partial | `vcs.repository.url.full`, `vcs.ref.head.revision` | Version-control attributes exist for CI/CD telemetry, not for tool and agent code. | [otel_tool_code_ref](#ask-otel-tool-code-ref) |
| [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) | SHOULD | none |  | No BOM reference. | [otel_capability_change](#ask-otel-capability-change) |
| [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) | SHOULD | none |  | No dependency graph. | [otel_capability_change](#ask-otel-capability-change) |
| [Inventory Integrity Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) | SHOULD | none |  | No inventory signature. | [otel_capability_change](#ask-otel-capability-change) |
| [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#f-event-sequence-continuity) | SHOULD | none |  | No sequence number or hash chain in the GenAI or core conventions at the pin. | [otel_audit_sequence](#ask-otel-audit-sequence) |
| [Tool Description](Telemetry-Attack-Detection-Addendum.md#f-tool-description) | MAY | covered | `gen_ai.tool.description` |  |  |
| [Tool Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#f-tool-status) | MAY | none |  | No reachability status for a tool. A MAY field; no ask. |  |
| [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#f-creator-id-oncall-creation-update-dates) | MAY | none |  | No ownership or change dates. A MAY field; no ask. |  |
| [Surfaces Supported](Telemetry-Attack-Detection-Addendum.md#f-surfaces-supported) | MAY | none |  | No per-tool exposure map. A MAY field; no ask. |  |
| [Fleet counts](Telemetry-Attack-Detection-Addendum.md#f-fleet-counts) | MAY | none |  | Fleet aggregates are derived. No ask proposed. |  |

**RFC §6.7 Training data and training infrastructure**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Training-Data Item Digest](Telemetry-Attack-Detection-Addendum.md#f-training-data-item-digest) | SHOULD | none |  | No training-time conventions. | [otel_training_provenance](#ask-otel-training-provenance) |
| [Training-Data Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-training-data-source-provenance) | SHOULD | none |  | No training-time conventions. | [otel_training_provenance](#ask-otel-training-provenance) |
| [Compute Job Submission](Telemetry-Attack-Detection-Addendum.md#f-compute-job-submission-event) | SHOULD | none |  | No training-time conventions. | [otel_training_provenance](#ask-otel-training-provenance) |
<!-- END GENERATED: xm correspondence otel -->

### 2.3 Gaps

The table states each gap. The security-specific ones are where the conventions were never shaped to go: trust provenance on input, guardrail verdicts, memory and retrieval provenance, and the run, turn and step identifiers between a conversation and a span.

### 2.4 Asks

Ordered by status, then by the strongest tier each ask closes, then by the documented instances behind those fields. Every item is scoped to something OTel already models, and the two groups that are *not* a natural fit are named as such rather than pushed.

<!-- BEGIN GENERATED: xm asks otel -->
<a id="ask-otel-audit-sequence"></a>**`otel_audit_sequence`** (open; [community#2409](https://github.com/open-telemetry/community/issues/2409)). Adopt the Audit Logging data model for security records: `audit.record.id`, the `audit.sequence.*` chain (number, previous hash, previous record id, end) and `audit.integrity.*` with its canonicalization declaration. Referenced here at commit `3c5a0ff` (2026-09-18) of the `auditing` branch. *Closes:* [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#f-event-sequence-continuity) (SHOULD, 0 instances). The draft is in the Audit Logging SIG proposal, not yet the specification [[88]](#other-sources). A crosswalk maps each attribute to and from OCSF `attestation` [[89]](#other-sources).

<a id="ask-otel-hash-only-capture"></a>**`otel_hash_only_capture`** (proposed). Ensure a hash-only content-capture mode exists for message content. The digest declares its canonicalization and may be keyed with a key identifier; an absent digest means not captured. *Closes:* [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) (MUST, 4 instances), [Model Input](Telemetry-Attack-Detection-Addendum.md#f-model-input) (MUST, 18 instances) and [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#f-response-model-output) (MUST, 12 instances). The digest form under [`ocsf_message_context_content`](#ask-ocsf-message-context-content) is a worked example.

<a id="ask-otel-security-guardrail"></a>**`otel_security_guardrail`** (proposed). Extend the evaluation event for security use (blocked or allowed, guardrail type, threat technique), or add gen_ai.guardrail.*. *Closes:* [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-input-verdict) (MUST, 8 instances), [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-output-verdict) (MUST, 5 instances), [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) (MUST, on a dependency) and [Threat Classification / ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#f-threat-classification-atlas-technique-tag) (MAY, 0 instances). The evaluation event already carries name, score, label and explanation, the right shape for a classifier verdict; reusing it avoids a parallel namespace. This is what makes classifier *bypass* detectable (`TA-01`).

<a id="ask-otel-inter-agent-messaging"></a>**`otel_inter_agent_messaging`** (proposed). Add inter-agent messaging attributes. *Closes:* [Action Type](Telemetry-Attack-Detection-Addendum.md#f-action-type) (MUST, 6 instances) and [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) (MUST, 6 instances).

<a id="ask-otel-trust-level"></a>**`otel_trust_level`** (proposed). Add gen_ai.input.trust_level on message parts (trusted or untrusted, crossed with instruction or data). *Closes:* [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification) (MUST, 12 instances). The four values are trusted-instruction, trusted-data, untrusted-instruction and untrusted-data. **`untrusted-instruction` is the attack state**: `TA-01` is untrusted email content promoted to instruction. The enum carries provenance only; detector verdicts belong on the **Guardrail (Input) Verdict** (AD §1.2). No current convention has an analogue, and the addition is one enum on an existing structure.

<a id="ask-otel-egress-pattern"></a>**`otel_egress_pattern`** (proposed). Document correlating model output to its destination through the HTTP and network conventions on the child span. *Closes:* [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination) (MUST, 11 instances).

<a id="ask-otel-authorization-reference"></a>**`otel_authorization_reference`** (proposed). Let a span reference an authorization decision by the decision record's stable identifier (OCSF `metadata.uid`), so OpenTelemetry and OCSF records join at query time. *Closes:* [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) (MUST, 9 instances).

<a id="ask-otel-refusal"></a>**`otel_refusal`** (proposed). Add a refusal status and reason distinct from finish reasons, so a refusal that ends normally is still visible. *Closes:* [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) (MUST, 9 instances).

<a id="ask-otel-retrieval-provenance"></a>**`otel_retrieval_provenance`** (proposed). Add per-document source, owner, trust level and last-modified attributes to retrieval documents. *Closes:* [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-source-provenance) (MUST, 7 instances) and [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) (SHOULD, 2 instances). `gen_ai.retrieval.documents` exists; per-document **source, owner, trust level, and last-modified** do not, and `TA-09` turns specifically on recently-modified retrievable content.

<a id="ask-otel-run-budget"></a>**`otel_run_budget`** (proposed). Add per-run budget and threshold semantics; document security use of the loop metrics. *Closes:* [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) (MUST, 5 instances) and [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) (MUST, 4 instances).

<a id="ask-otel-trigger"></a>**`otel_trigger`** (proposed). Add gen_ai.trigger.type (user_initiated or autonomous) and gen_ai.trigger.event; scheduled and self-triggered runs use it. *Closes:* [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#f-trigger-type-source-event) (MUST, 5 instances) and [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) (MUST, 3 instances). `TA-01` is zero-click; this is the first filter of any injection hunt.

<a id="ask-otel-capability-change"></a>**`otel_capability_change`** (proposed). Add a capability-change event; reference an external BOM by URI or digest. *Closes:* [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) (MUST, 4 instances), [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) (SHOULD, 2 instances), [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) (SHOULD, 1 instance) and [Inventory Integrity Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) (SHOULD, 0 instances).

<a id="ask-otel-input-part-source"></a>**`otel_input_part_source`** (proposed). Add a per-part source on input messages (the surface, tool, agent or document it came from), beside the proposed gen_ai.input.trust_level. *Closes:* [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#f-input-source-channel) (MUST, 7 instances).

<a id="ask-otel-tool-digest-mcp-primitive"></a>**`otel_tool_digest_mcp_primitive`** (proposed). Add gen_ai.tool.definitions.hash and an mcp.primitive value set (tool, resource, prompt, sampling, elicitation, roots). *Closes:* [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#f-tool-definition-digest) (MUST, 2 instances) and [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive) (MUST, 5 instances). `gen_ai.tool.definitions` and `mcp.method.name` already carry the raw material; a stable hash attribute and an explicit primitive value set make definition drift and non-tool MCP surfaces queryable (AD §1.3).

<a id="ask-otel-memory-provenance-footprint"></a>**`otel_memory_provenance_footprint`** (proposed). Add provenance and footprint attributes to gen_ai.memory.*. *Closes:* [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#f-memory-provenance-source) (MUST, 4 instances) and [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#f-memory-footprint-growth) (MUST, 2 instances). `gen_ai.memory.*` carries store and record identity, query text, record count, seven memory operations and a `gen_ai.memory.client` span ([§2.1](#21-what-it-is-and-the-version-mapped)). Operation and item identity are therefore covered; **provenance** and **footprint** are not, and neither appears anywhere in the `gen_ai` registry. Memory remains MUST here (AD §1.4), with `IR-02` and `IR-05` as direct grounding and `AOC-05` for footprint.

<a id="ask-otel-turn-step-ids"></a>**`otel_turn_step_ids`** (proposed). Add gen_ai.turn.id and gen_ai.step.id. *Closes:* [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#f-session-turn-step-ids) (MUST, 5 instances). `gen_ai.conversation.id` and `gen_ai.workflow.name` exist; the intermediate levels do not. `TA-08` and `IR-01` are across-turn patterns (AD §1.1).

<a id="ask-otel-attachment-identity"></a>**`otel_attachment_identity`** (proposed). Add attachment identity (name, size, hash) on message parts. *Closes:* [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) (MUST, 3 instances). `AOC-12` is an image/OCR injection; `AOC-05` is attachment flooding.

<a id="ask-otel-citations"></a>**`otel_citations`** (proposed). Add citation attributes on output messages with a resolution flag against retrieval. *Closes:* [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#f-citations-source-attribution) (MUST, 3 instances).

<a id="ask-otel-entry-point"></a>**`otel_entry_point`** (proposed). Add an entry-point attribute: the surface a request arrived through and whether it is internal or external. *Closes:* [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) (MUST, 3 instances).

<a id="ask-otel-execution-environment"></a>**`otel_execution_environment`** (proposed). Add execution-environment attributes (sandbox, runtime, egress policy) for tool execution. *Closes:* [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#f-execution-environment-sandbox) (MUST, 3 instances).

<a id="ask-otel-obfuscation"></a>**`otel_obfuscation`** (proposed). Add obfuscation indicators on input (detected, encodings, decoded hash), aligned with AITF security.obfuscation.*. *Closes:* [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) (MUST, 3 instances).

<a id="ask-otel-hook-coverage"></a>**`otel_hook_coverage`** (proposed). Record instrumentation hook coverage as a resource attribute. *Closes:* [Instrumentation Coverage / Hook Status](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) (MUST, on a dependency).

<a id="ask-otel-tool-trust-boundary"></a>**`otel_tool_trust_boundary`** (proposed). Extend gen_ai.tool.type, or add a trust-boundary attribute, to distinguish MCP, internal, direct-storage and code-execution tools. *Closes:* [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#f-tool-type-trust-boundary) (MUST, 2 instances).

<a id="ask-otel-run-id"></a>**`otel_run_id`** (proposed). Add gen_ai.run.id, as AITF defines it; gen_ai.workflow.name names the workflow, not the run. *Closes:* [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#f-workflow-run-id) (MUST, on a dependency).

<a id="ask-otel-task-intent"></a>**`otel_task_intent`** (proposed). Add the purpose declared for an invoke_agent or invoke_workflow run. *Closes:* [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#f-task-intent-declaration) (SHOULD, 4 instances).

<a id="ask-otel-tool-code-ref"></a>**`otel_tool_code_ref`** (proposed). Add the tool and framework version and the code reference (repository, commit) on execute_tool and invoke_agent spans. *Closes:* [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) (SHOULD, 2 instances) and [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) (SHOULD, 2 instances).

<a id="ask-otel-training-provenance"></a>**`otel_training_provenance`** (proposed). Add training-time conventions: a dataset item digest and its source, and a compute job submission (submitter, entrypoint, image, requested resources). *Closes:* [Training-Data Item Digest](Telemetry-Attack-Detection-Addendum.md#f-training-data-item-digest) (SHOULD, 1 instance), [Training-Data Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-training-data-source-provenance) (SHOULD, 2 instances) and [Compute Job Submission](Telemetry-Attack-Detection-Addendum.md#f-compute-job-submission-event) (SHOULD, 1 instance).

<a id="ask-otel-autonomy-level"></a>**`otel_autonomy_level`** (proposed). Add gen_ai.agent.autonomy_level, the level of action an agent may take without human approval. *Closes:* [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) (SHOULD, 2 instances).

<a id="ask-otel-a2a"></a>**`otel_a2a`** (proposed). Add A2A conventions: task lifecycle events, including push-notification callback registration, and the counterparty agent card (URL, digest, change, verification outcome). *Closes:* [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) (SHOULD, 0 instances) and [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#f-peer-agent-card-descriptor) (SHOULD, 1 instance).

<a id="ask-otel-model-provenance"></a>**`otel_model_provenance`** (proposed). Add gen_ai.model.hash, gen_ai.model.signature and gen_ai.model.source. *Closes:* [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) (SHOULD, 0 instances). Together they complete the supply-chain record that `gen_ai.request.model` starts.
<!-- END GENERATED: xm asks otel -->

### 2.5 What it contributes

Three existing GenAI attributes already close gaps this document had left open. `gen_ai.system_instructions` gives **System Prompt** (AD §1.1) a home. `gen_ai.tool.definitions` gives **Tool Definition Digest** (AD §1.3) one; the raw material for a digest is already in scope, and only the *hash-and-compare* is missing. And `gen_ai.invoke_agent.tool_calls` / `.inference_calls` are already the shape of **Loop / Step-Count Signal** (AD §1.5) and part of **Resource-Consumption Aggregate** (AD §1.5), as metrics rather than attributes.

### 2.6 Divergences and open items

**Two groups of fields this document deliberately does *not* ask OTel to adopt.** **Identity and delegation** (AD §1.6) and **policy enforcement** (AD §1.3) are authorization-domain concerns with mature homes elsewhere, OCSF Authentication, and the proposed `ai_authorization` / `ai_taint` / `ai_approval` objects in [§1.4](#14-asks). Pushing them into OTel would duplicate schema and invite drift. The one exception worth raising is **correlation**: an OTel span should be able to reference an authorization decision by ID so the two layers join at query time, which is a single attribute rather than a namespace. The acting agent does have an OTel home and should be emitted there rather than in a private namespace: `gen_ai.agent.id` / `gen_ai.agent.name`, which transform to OCSF `ai_agent.uid`. The originating principal has none at the pin. The Audit Logging data model in draft carries it as `audit.actor.id` [[88]](#other-sources), and a crosswalk keeps the agent on `gen_ai.agent.id` and `gen_ai.agent.name` [[89]](#other-sources).

### 2.7 Signal selection: traces, events/logs, metrics


OTel has three signal types and OCSF has one event model, so this guidance has no counterpart in [§1](#1-ocsf), but getting it wrong is the most common way security telemetry becomes unusable or unaffordable.

| Signal | Use for | Fields from this document |
| :-------- | :-------------------------- | :------------------------------------------------------------------ |
| **Span attributes** | Low-cardinality identifiers and the execution skeleton | Agent/instance/run/session/turn/step IDs, action type, execution status, model and provider, tool name and type, trigger type, trust level, decision references |
| **Events / logs** | Content and anything high-cardinality, large, or privacy-bearing | Prompts, responses, system instructions, tool arguments and results, memory operations, retrieved documents, citations, guardrail verdicts, capability-change events |
| **Logs, verbatim** | Hash-chained or signed records | Event Sequence Continuity and the records it chains: the record is the log body, unchanged; record, chain and sequence identifiers ride as attributes for indexing |
| **Metrics** | Aggregates, budgets, and rate-based detections | Token usage, loop and step counts, tool-call rates, resource aggregates, guardrail block rates, deny rates |

Signal choice matters. The following rules correct mistakes that show up often when GenAI instrumentation is reused for security:

- **Never put content in span attributes.** Prompts, responses, and tool results are unbounded in size and often contain PII. OTel already models them as event bodies; keep them there. A span attribute carrying a full prompt breaks cardinality limits and leaks into every trace backend that samples the span.
- **Emit detection-relevant aggregates as metrics, not as derived queries.** Loop counts and token budgets (AD §1.5) are cheap as metrics and expensive as trace aggregations, and metrics survive sampling, which traces may not. With one qualification: a metric does not survive *with* the action record, so where an aggregate is what a decision turned on, the consumed and remaining figures belong on the decision as well (AD §§1.3 and 1.5). The metric serves detection; the record on the action is what can be audited afterwards.
- **Never re-encode a chained record.** A collector may batch and route it, but re-serializing it changes the bytes its digest and chain link were taken over.
- **Cross-reference rather than duplicate.** A guardrail verdict event should carry the span and trace IDs, not a copy of the prompt it evaluated.

### 2.8 Context propagation, sampling, privacy and canonicalization


**Propagation is solved for MCP, and the mechanism should be adopted deliberately.** The MCP conventions specify that instrumentations SHOULD inject context into the MCP request **`params._meta`** property bag, with `traceparent`, `tracestate`, and `baggage` written unprefixed per **SEP-414** [[36]](#standards--frameworks), and that the receiver uses the extracted context as the remote parent. That is exactly the mechanism **Trace Context (propagated)** (AD §1.1) requires, and it means cross-hop correlation over MCP is a matter of configuration rather than invention. Two cautions. First, HTTP-level propagation covers the HTTP request but **not** individual messages within a streaming request/response, a gap that matters for long-lived agent sessions. Second, and more important for security: **`baggage` crosses the trust boundary.** It is attacker-influenceable in exactly the way [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) (AD §1.2) describes, so baggage may carry correlation identifiers but **must never carry trust levels, authorization decisions, taint labels, or identity claims**. Those come from the enforcement point, not from the wire.

**Sampling is the trap most likely to silently defeat this entire field set.** OTel's default is head-based sampling at some fraction of traces. Applied to security telemetry, that means *most attacks are simply not recorded*. Worse, the sample is drawn without regard to whether an event is security-relevant, so a guardrail block has the same chance of being discarded as a routine completion. The three requirements that follow (100% retention of security-relevant events, security relevance as a tail-sampling predicate, and recording the sampling configuration itself) are **normative** and stated in [RFC §5.2](CoSAI-AI-Telemetry-RFC.md#52-sampling). The rationale is that discarding a block or a denial is the same failure mode as fail-open enforcement ([AD §1.2](Telemetry-Attack-Detection-Addendum.md#12-content-trust-verdicts-and-their-availability)), and deserves the same treatment.

**Privacy: content capture is opt-in, and that default is correct.** GenAI instrumentations gate message content behind an explicit capture setting, which aligns with the content-hash requirement in [RFC §5.3](CoSAI-AI-Telemetry-RFC.md#53-content-hashing). The gap is that capture is close to binary (on or off) where security work needs a **middle setting**: hashes and classifications without raw content, so that correlation (same payload across many sessions, same attachment hash) survives even where raw capture is prohibited. That is the ask [`otel_hash_only_capture`](#ask-otel-hash-only-capture), the companion of [`otel_trust_level`](#ask-otel-trust-level), and it is the OTel expression of this document's **hash-first** principle. The OTel Collector is also the correct place to run redaction, since it applies uniformly across every instrumented service rather than per-library.

**Canonicalization is a prerequisite for hash-first, and it must be declared.** A content hash or an event fingerprint correlates across producers only if every producer hashes the same logical bytes. The OpenTelemetry Audit Logging data model in draft [[88]](#other-sources) declares it in `audit.integrity.canonicalization`, JCS when absent; OCSF's `attestation.fingerprint` instead *declares* its serialization (`serialization_id` plus a free-text `serialization`) so that non-JCS producers can declare it; CPEX [[44]](#standards--frameworks) hashes, at its audit seam ([cpex#166](https://github.com/contextforge-org/cpex/pull/166)), a sorted-key JSON that is documented as not RFC 8785; the same seam in PPE [[86]](#other-sources) takes a keyed digest over the payload's canonical audit bytes. Two conformant implementations with different canonicalizations produce different digests for the same event, and the integrity claim degrades silently from "verify" to "trust the producer". [RFC §5.3](CoSAI-AI-Telemetry-RFC.md#53-content-hashing) requires a producer that emits a hash of content or of an event to declare the canonicalization used, and forbids consumers to compare digests across producers whose declared canonicalizations differ. JCS, RFC 8785 [[74]](#standards--frameworks), is the recommended default. OCSF carries the declaration on `attestation.fingerprint`; OpenTelemetry's GenAI conventions have no carrier at the pin; the Audit Logging draft has one, and [`otel_audit_sequence`](#ask-otel-audit-sequence) asks for its adoption. A transform between OCSF and OpenTelemetry that re-serializes a record carries the origin digest and its declared canonicalization rather than recomputing them [[89]](#other-sources).

---

## 3. AITF

### 3.1 What it is, and the version mapped

AITF, the AI Telemetry Framework [[25]](#standards--frameworks), was donated to CoSAI Workstream 2. It carries these fields as OpenTelemetry attributes today and emits them into OCSF ahead of formal ratification, so adopters are not blocked on either standards body. AITF v0.4 closed the 27 gaps RFC v0.4 recorded for it, adding 390 attributes ([`aitf/AITF_gaps.md`](aitf/AITF_gaps.md)).

> **Note on the identifier mapping.** AD §1.1 distinguishes five levels (instance → run → session → turn → step). AITF carries each: `gen_ai.agent.id`, `gen_ai.run.id`, `gen_ai.conversation.id`, `gen_ai.turn.id` and `gen_ai.step.id`, with `gen_ai.turn.index` and `gen_ai.agent.step.index` recording order. OpenTelemetry lacks the run, turn and step identifiers; the asks are in [§2.4](#24-asks).

### 3.2 Correspondence

<!-- BEGIN GENERATED: xm correspondence aitf -->
**RFC §6.1 Identifiers, trace context and model identity**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Agent Name](Telemetry-Attack-Detection-Addendum.md#f-agent-name) | MUST | covered | `gen_ai.agent.name`, `asset.*` |  |
| [Agent (Runtime) Instance ID](Telemetry-Attack-Detection-Addendum.md#f-agent-runtime-instance-id) | MUST | covered | `gen_ai.agent.id` |  |
| [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#f-workflow-run-id) | MUST | covered | `gen_ai.run.id` |  |
| [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#f-session-turn-step-ids) | MUST | covered | `gen_ai.conversation.id`, `gen_ai.turn.id`, `gen_ai.step.id`, `gen_ai.agent.step.index` |  |
| [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#f-trigger-type-source-event) | MUST | covered | `gen_ai.trigger.*`, `gen_ai.agent.*` |  |
| [Action Type](Telemetry-Attack-Detection-Addendum.md#f-action-type) | MUST | covered | `gen_ai.agent.step.type` |  |
| [Execution Status](Telemetry-Attack-Detection-Addendum.md#f-execution-status) | MUST | covered | `error.type` | span status + `error.type` |
| [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) | MUST | partial | `gen_ai.*` | AITF names a namespace but defines no attribute for this field at the pin. |
| [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) | MUST | covered | `gen_ai.*` | `gen_ai.*` (system message / request) |
| [Model Name + Version](Telemetry-Attack-Detection-Addendum.md#f-model-name-version) | MUST | covered | `gen_ai.request.model`, `gen_ai.provider.name` |  |
| [Inference Parameters](Telemetry-Attack-Detection-Addendum.md#f-inference-parameters) | MUST | covered | `gen_ai.request.temperature`, `gen_ai.request.top_p`, `gen_ai.request.max_tokens`, `gen_ai.request.stop_sequences`, `gen_ai.request.seed` |  |
| [Input / Output Token Counts](Telemetry-Attack-Detection-Addendum.md#f-input-output-token-counts) | MUST | covered | `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `cost.*` |  |
| [LLM Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-llm-error-exception) | MUST | partial | `gen_ai.*`, `security.*` | AITF names a namespace but defines no attribute for this field at the pin. |
| [Trace Context (propagated)](Telemetry-Attack-Detection-Addendum.md#f-trace-context-propagated) | MUST | covered |  | OTel `trace_id` and `span_id`, propagated as W3C `traceparent`. |
| [Stop Reason](Telemetry-Attack-Detection-Addendum.md#f-stop-reason) | MUST | covered | `gen_ai.response.finish_reasons` |  |
| [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) | SHOULD | covered | `gen_ai.agent.state` |  |
| [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) | SHOULD | covered | `supply_chain.model.hash`, `supply_chain.model.signed`, `supply_chain.model.source`, `supply_chain.ai_bom.*` |  |
| [Organization / Tenant ID](Telemetry-Attack-Detection-Addendum.md#f-organization-tenant-id) | SHOULD | covered | `asset.tenant.*`, `security.tenant.*`, `asset.*` |  |
| [Provider / Endpoint Identity](Telemetry-Attack-Detection-Addendum.md#f-provider-endpoint-identity) | MAY | covered | `gen_ai.provider.name` |  |
| [Pre-Forward-Pass State Digest/Vector](Telemetry-Attack-Detection-Addendum.md#f-pre-forward-pass-state-digest-vector) | MAY | covered | `drift.*` |  |
| [Token Malformation / Context-Corruption Indicator](Telemetry-Attack-Detection-Addendum.md#f-token-malformation-context-corruption-indicator) | MAY | covered | `drift.*`, `quality.*` |  |

**RFC §6.2 Content, trust, verdicts and their availability**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Model Input](Telemetry-Attack-Detection-Addendum.md#f-model-input) | MUST | covered | `gen_ai.prompt` | `gen_ai.prompt` / input events |
| [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#f-input-source-channel) | MUST | partial | `gen_ai.*`, `rag.*`, `mcp.*` | AITF names a namespace but defines no attribute for this field at the pin. |
| [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification) | MUST | covered | `security.*` | `security.*` (trust/threat) |
| [Source host / IP + request metadata](Telemetry-Attack-Detection-Addendum.md#f-source-host-ip-request-metadata) | MUST | covered | `security.*` | `security.*` / resource attrs |
| [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-input-verdict) | MUST | covered | `security.guardrail.type`, `security.blocked`, `security.threat_type` |  |
| [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#f-response-model-output) | MUST | covered | `gen_ai.completion` |  |
| [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination) | MUST | covered | `gen_ai.tool.call.arguments`, `security.pii.*` |  |
| [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#f-citations-source-attribution) | MUST | covered | `rag.citation.*`, `rag.*` |  |
| [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-output-verdict) | MUST | covered | `security.guardrail.*`, `security.pii.*` |  |
| [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) | MUST | partial | `gen_ai.response.finish_reasons`, `security.*` | AITF names a namespace but defines no attribute for this field at the pin. |
| [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) | MUST | covered | `gen_ai.content.*`, `gen_ai.*` |  |
| [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) | MUST | covered | `security.attribute_source.*` |  |
| [Instrumentation Coverage / Hook Status](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) | MUST | covered | `asset.instrumentation.*`, `asset.*` |  |
| [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode) | MUST | covered | `security.enforcement.*`, `security.guardrail.*` |  |
| [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) | MUST | covered | `security.guardrail.modification.*`, `security.guardrail.*` |  |
| [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) | MUST | covered | `security.obfuscation.*`, `security.*` |  |
| [Observation / Thought (reasoning trace)](Telemetry-Attack-Detection-Addendum.md#f-observation-thought-reasoning-trace) | SHOULD | covered | `gen_ai.agent.step.thought` |  |
| [Threat Classification / ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#f-threat-classification-atlas-technique-tag) | MAY | covered | `security.threat_type`, `compliance.framework`, `compliance.control_id` |  |

**RFC §6.3 Tool calls and policy decisions**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#f-execution-environment-sandbox) | MUST | covered | `supply_chain.runtime.*`, `supply_chain.*` |  |
| [Tool Call I/O](Telemetry-Attack-Detection-Addendum.md#f-tool-call-io) | MUST | covered | `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result`, `mcp.tool.name` |  |
| [Tool Name](Telemetry-Attack-Detection-Addendum.md#f-tool-name) | MUST | covered | `mcp.tool.name` |  |
| [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#f-tool-type-trust-boundary) | MUST | partial | `mcp.*` | AITF names a namespace but defines no attribute for this field at the pin. |
| [Tool Execution ID](Telemetry-Attack-Detection-Addendum.md#f-tool-execution-id) | MUST | covered | `gen_ai.tool.call.id` |  |
| [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#f-tool-definition-digest) | MUST | covered | `mcp.tool.definition.*`, `mcp.tool.*` |  |
| [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive) | MUST | covered | `mcp.primitive`, `mcp.server.name`, `mcp.server.version` |  |
| [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) | MUST | covered | `security.authorization.*`, `security.*`, `compliance.control_id` |  |
| [Tool Selection Rationale](Telemetry-Attack-Detection-Addendum.md#f-tool-selection-rationale) | SHOULD | covered | `gen_ai.agent.step.thought` | `gen_ai.agent.step.thought` (per-step) |
| [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#f-human-approval-elicitation-event) | SHOULD | covered | `identity.approval.*`, `identity.*` |  |
| [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#f-tool-acl-required-scope) | SHOULD | covered | `identity.auth.scope_granted` |  |
| [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#f-session-taint-labels-information-flow-decisions) | SHOULD | covered | `security.taint.*`, `security.*` |  |
| [Backend / Route Restriction Decision](Telemetry-Attack-Detection-Addendum.md#f-backend-route-restriction-decision) | SHOULD | covered | `gen_ai.route.*`, `gen_ai.provider.name` |  |
| [Mediation Coverage & Bypass Path](Telemetry-Attack-Detection-Addendum.md#f-mediation-coverage-bypass-path) | SHOULD | covered | `security.mediation.*` |  |
| [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-tool-error-exception) | MAY | covered | `mcp.*`, `security.*` | `mcp.*` error, `security.*` |
| [Tool ID](Telemetry-Attack-Detection-Addendum.md#f-tool-id) | MAY | covered | `mcp.server.name` | `mcp.server.name` + tool id |
| [Tool Privacy Classification](Telemetry-Attack-Detection-Addendum.md#f-tool-privacy-classification) | MAY | covered | `security.pii.*`, `compliance.*` |  |
| [Policy Reason Code](Telemetry-Attack-Detection-Addendum.md#f-policy-reason-code) | MAY | covered | `security.*`, `compliance.control_id` |  |

**RFC §6.4 Memory and retrieval**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Memory Write Event](Telemetry-Attack-Detection-Addendum.md#f-memory-write-event) | MUST | covered | `memory.*` |  |
| [Memory Read / Injection Event](Telemetry-Attack-Detection-Addendum.md#f-memory-read-injection-event) | MUST | covered | `memory.*` |  |
| [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#f-memory-provenance-source) | MUST | covered | `memory.provenance` |  |
| [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#f-memory-footprint-growth) | MUST | covered | `memory.*`, `cost.*` |  |
| [Retrieval Event](Telemetry-Attack-Detection-Addendum.md#f-retrieval-event) | MUST | covered | `rag.*` |  |
| [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-source-provenance) | MUST | covered | `rag.*` | `rag.*` (source) |
| [Memory Integrity / Poisoning Signal](Telemetry-Attack-Detection-Addendum.md#f-memory-integrity-poisoning-signal) | SHOULD | covered | `memory.security.poisoning_score`, `memory.security.isolation_verified`, `memory.security.cross_session` |  |
| [Memory Write Rationale](Telemetry-Attack-Detection-Addendum.md#f-memory-write-rationale) | SHOULD | covered | `gen_ai.agent.step.thought` | `gen_ai.agent.step.thought` (per-step) |
| [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) | SHOULD | covered | `rag.*`, `security.*` |  |
| [Declared Memory Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-memory-configuration) | MAY | covered | `memory.config.*`, `memory.*` |  |
| [Declared Knowledge-Source Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-knowledge-source-configuration) | MAY | covered | `rag.source.*`, `rag.*` |  |

**RFC §6.5 Orchestration**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) | MUST | covered | `gen_ai.agent.*` | `gen_ai.agent.*`, delegation activity (OCSF 9002) |
| [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) | MUST | covered | `gen_ai.agent.next_action` | `gen_ai.agent.next_action` / step events |
| [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) | MUST | covered | `gen_ai.agent.session.turn_count`, `gen_ai.agent.step.index`, `agent.steps_per_session` |  |
| [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) | MUST | covered | `cost.*`, `gen_ai.usage.*` |  |
| [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#f-task-intent-declaration) | SHOULD | covered | `gen_ai.agent.next_action` |  |
| [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) | SHOULD | covered | `a2a.task.lifecycle.*`, `a2a.push.config.*` |  |
| [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#f-peer-agent-card-descriptor) | SHOULD | covered | `gen_ai.agent.peer.*`, `gen_ai.agent.*` |  |
| [Protocol Envelope Capture](Telemetry-Attack-Detection-Addendum.md#f-protocol-envelope-capture) | MAY | covered | `mcp.envelope.*`, `mcp.*` |  |

**RFC §6.6 Identity, provenance and inventory**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) | MUST | covered | `asset.capability.*`, `asset.*` |  |
| [Identities Used (per hop)](Telemetry-Attack-Detection-Addendum.md#f-identities-used-per-hop) | MUST | covered | `identity.*` | `identity.*` (OCSF Authentication 3002) |
| [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#f-verified-vs-displayed-identity) | MUST | covered | `identity.auth.method`, `identity.auth.result` |  |
| [Originating Principal (on-behalf-of)](Telemetry-Attack-Detection-Addendum.md#f-originating-principal-on-behalf-of) | SHOULD | covered | `identity.*` |  |
| [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) | SHOULD | covered |  | delegation activity (OCSF 9002) |
| [Granted Authorizations / Scope](Telemetry-Attack-Detection-Addendum.md#f-granted-authorizations-scope) | SHOULD | covered | `identity.auth.scope_granted` |  |
| [Resource Indicators + Constraints](Telemetry-Attack-Detection-Addendum.md#f-resource-indicators-constraints) | SHOULD | covered | `identity.*`, `compliance.*` |  |
| [Token Exchange & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#f-credential-minting-scope-narrowing-check) | SHOULD | covered | `identity.credential.mint.*`, `identity.auth.scope_granted` |  |
| [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#f-trust-domain-crossing-delegation-depth) | SHOULD | covered | `identity.boundary.*`, `identity.*` |  |
| [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#f-runtime-credential-attestation) | SHOULD | covered | `identity.auth.method`, `identity.trust.method` | `identity.auth.method` (mTLS/SPIFFE/OAuth/DID-VC), `identity.trust.method` |
| [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#f-lifecycle-state) | SHOULD | covered | `identity.lifecycle.operation` |  |
| [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) | SHOULD | covered | `supply_chain.*`, `asset.*` |  |
| [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) | SHOULD | covered | `supply_chain.*`, `asset.*` |  |
| [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) | SHOULD | covered | `supply_chain.ai_bom.*` |  |
| [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) | SHOULD | covered | `supply_chain.ai_bom.*` | `supply_chain.ai_bom.*` (dependency edges) |
| [Inventory Integrity Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) | SHOULD | covered | `supply_chain.*` | `supply_chain.*` signature attrs |
| [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#f-event-sequence-continuity) | SHOULD | covered | `observability.sequence.*` |  |
| [Tool Description](Telemetry-Attack-Detection-Addendum.md#f-tool-description) | MAY | covered | `asset.*` |  |
| [Tool Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#f-tool-status) | MAY | covered | `asset.*` |  |
| [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#f-creator-id-oncall-creation-update-dates) | MAY | covered | `asset.*` |  |
| [Surfaces Supported](Telemetry-Attack-Detection-Addendum.md#f-surfaces-supported) | MAY | covered | `asset.*` |  |
| [Fleet counts](Telemetry-Attack-Detection-Addendum.md#f-fleet-counts) | MAY | none |  | (derived) |

**RFC §6.7 Training data and training infrastructure**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Training-Data Item Digest](Telemetry-Attack-Detection-Addendum.md#f-training-data-item-digest) | SHOULD | partial | `model_ops.training.dataset.version` | A dataset version hash, not a digest per item checked at fetch. |
| [Training-Data Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-training-data-source-provenance) | SHOULD | partial | `model_ops.training.dataset.id`, `supply_chain.model.training_data` | Dataset identity and a free-text description, not per-document source. |
| [Compute Job Submission](Telemetry-Attack-Detection-Addendum.md#f-compute-job-submission-event) | SHOULD | partial | `model_ops.training.*` | Records a training run, not its submission or submitter. |
<!-- END GENERATED: xm correspondence aitf -->

### 3.3 Gaps

AITF defines an attribute for every field except those the table marks *partial* or *none*. For five MUST fields (Surface / App, Input Source / Channel, LLM Error / Exception, LLM Refusal, Tool Type / Trust Boundary) an earlier mapping cited only a namespace, and AITF defines no attribute for them at the pin.

### 3.4 Path to OCSF and OpenTelemetry

AITF lets adopters emit this telemetry **before** OCSF ratifies it, and stages the upstream proposals so each is backward-compatible:

- **Phase 0, today.** AITF carries every MUST field except the five in [§3.3](#33-gaps) as OTel attributes and emits OCSF via the `ai_operation` profile on existing classes (6003/6005/2004/3002); the ATLAS tag rides on `compliance.control_id` (framework `mitre_atlas`).
- **Phase 1, profile extension (backward-compatible).** Contribute the MUST attribute set plus the `ai_guardrail` and `ai_capability` objects to the OCSF `ai_operation` profile, and the `message_context` extensions (content hashes with their canonicalization declaration, redaction flags, system prompt, attachment identity); no new classes required, and `ai_content` only if content must attach to classes other than 6003 ([§1.2](#12-correspondence)).
- **Phase 2, agentic classes.** Ratify **AI Agent Activity (9001)** plus the `ai_memory` and `ai_retrieval` objects (memory & RAG are absent from OCSF today and are MUST here).
- **Phase 3, delegated authority.** Ratify **AI Delegation Activity (9002)** and the `runtime_attestation` object (ODIS-aligned), and land the lineage asks of [ocsf-schema#1739](https://github.com/ocsf/ocsf-schema/issues/1739) on `delegation`.
- **Phase 4, inventory & analytics.** SHOULD and MAY fields (`ai_asset`, drift, quality, fleet aggregates) as they stabilize.

**Promotion from AITF.** A field AITF carries becomes an OCSF or OpenTelemetry ask under the rule in the [introduction](#how-this-addendum-is-organized).

---

## 4. OWASP AOS

### 4.1 What it is, and the version mapped

The OWASP Agent Observability Standard (AOS) [[38]](#standards--frameworks) defines how an agent exposes its runtime behavior. Its three pillars are lifecycle hooks a guardian agent can intervene on (**Instrument**), an event set with OpenTelemetry and OCSF bindings (**Trace**), and an Agent Bill of Materials returned on request (**Inspect**). It is the publication closest in scope to this field set. AOS specifies the exposure interface; this field set specifies which security fields that interface must carry, and at what tier. The mapping is against schema version 0.1.0 at commit `e4a50f6` (30 December 2025); the specification has not changed since 10 November 2025.

### 4.2 Correspondence

**Instrument.** AOS hooks cover agent triggers, messages, tool calls, memory and knowledge retrieval, and MCP traffic, and [Instrumentation Coverage / Hook Status](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) records which of them are live. A guardian's `allow` and `deny` map to the guardrail verdicts. Its `modify` decision maps to [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record), its `reasonCode` to [Policy Reason Code](Telemetry-Attack-Detection-Addendum.md#f-policy-reason-code), and a failed or timed-out callout to [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode).

**Trace.** AOS step events carry the identifiers of RFC §6.1 and the content, tool, memory and retrieval fields of RFC §§6.2 to 6.4. Their `reasoning` attributes correspond to [Tool Selection Rationale](Telemetry-Attack-Detection-Addendum.md#f-tool-selection-rationale) and [Memory Write Rationale](Telemetry-Attack-Detection-Addendum.md#f-memory-write-rationale). The MCP and A2A [[40]](#standards--frameworks) protocol events correspond to [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive), [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) and [Protocol Envelope Capture](Telemetry-Attack-Detection-Addendum.md#f-protocol-envelope-capture). Span naming is left to the OpenTelemetry binding ([§2](#2-opentelemetry)).

**Inspect.** The AgBOM corresponds to [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot), and its refresh on change to [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event). CycloneDX [[41]](#standards--frameworks) `dependencies` and `signatures` correspond to [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) and [Inventory Integrity Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature). Only the CycloneDX binding exists, as one worked example that uses CycloneDX's generic `properties` bag. The SPDX [[42]](#standards--frameworks) and SWID [[43]](#standards--frameworks) bindings are placeholders ([#20](https://github.com/OWASP/www-project-agent-observability-standard/issues/20), [#21](https://github.com/OWASP/www-project-agent-observability-standard/issues/21)).

### 4.3 Gaps

AOS has no counterpart for three MUST fields. It records a message's role but not [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification): whether content is trusted instruction or untrusted data. It traces messages and tool calls but not [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination). Its user objects and agent cards are displayed identities, with no [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#f-verified-vs-displayed-identity). For delegated authority, `A2AContext` records only the immediate hop: there is no [Originating Principal](Telemetry-Attack-Detection-Addendum.md#f-originating-principal-on-behalf-of), [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain), granted authorization or runtime attestation. AOS assigns no tiers, so it gives an implementer no order of work.

### 4.4 Asks

**Add the MUST fields of [§4.3](#43-gaps) to the event set**, and the delegation fields to `A2AContext`.

**Bind to OpenTelemetry's GenAI conventions.** The OpenTelemetry binding names `agent.*`, `llm.model.name` and `llm.provider.name`, which are not current semantic conventions. `gen_ai.*`, `gen_ai.tool.definitions` and `mcp.*` now carry much of what AOS models by hand ([§2](#2-opentelemetry)).

**Bind to OCSF's `ai_operation` profile.** The OCSF binding extends API Activity (6003) with an `unmapped.aos` namespace (`unmapped.asop` in its implementation examples) and types the agent as an `actor.user` with `type_id: 99` and type `"AI Agent"`. OCSF 1.9.0 carries the agent as `ai_agent` and its authority as `delegation` ([§1.6](#16-divergences-and-open-items)).

### 4.5 What it contributes

AOS's interventional guardian is the source of three fields: Guardrail Modification Record, Policy Reason Code, and Enforcement-Point Availability & Failure Mode. A verdict alone records what a guardrail concluded; these record whether it was enforced. The Inspect pillar is the source of the inventory fields: AgBOM / Inventory Snapshot, Capability-Set Change Event, Component Dependency Graph and Inventory Integrity Signature. AOS also supplies the inspection rule of [RFC §4.6](CoSAI-AI-Telemetry-RFC.md#46-record-your-boundary-not-their-internals).

### 4.6 Divergences and open items

This field set records enforcement *outcomes* and leaves the enforcement *protocol* (the guardian architecture, the JSON-RPC wire format) out of scope. AOS specifies the protocol. The split should be agreed by both, not assumed.

---

## 5. ODIS

### 5.1 What it is, and the version mapped

Maps each conceptual field to the relevant ODIS [[26]](#standards--frameworks) data-model field, verified against ODIS at commit `148dc41` (8 September 2026). Coverage is **selective**: it targets the delegation and identity fields relevant to detection and response, not the full ODIS specification. The ODIS column resolves **names**, not shapes: ODIS defines abstract schemas that implementations bind to a wire format, and this document is a requirements layer rather than a binding ([RFC §2.1](CoSAI-AI-Telemetry-RFC.md#21-in-scope)). Where cardinality or structure is normative for an ask, it is stated in [§1](#1-ocsf).

### 5.2 Correspondence

<!-- BEGIN GENERATED: xm correspondence odis -->
**RFC §6.1 Identifiers, trace context and model identity**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Agent Name](Telemetry-Attack-Detection-Addendum.md#f-agent-name) | MUST | covered | `agent_id`, `owner_ref` | ODIS §6.1. |
| [Agent (Runtime) Instance ID](Telemetry-Attack-Detection-Addendum.md#f-agent-runtime-instance-id) | MUST | covered | `runtime_instance_id` | ODIS §6.2. |
| [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#f-workflow-run-id) | MUST | covered | `request_trace_id` | ODIS §6.4. |
| [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#f-session-turn-step-ids) | MUST | out of scope |  |  |
| [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#f-trigger-type-source-event) | MUST | out of scope |  |  |
| [Action Type](Telemetry-Attack-Detection-Addendum.md#f-action-type) | MUST | covered | `action` | `action.{tool,method}` (6.4) |
| [Execution Status](Telemetry-Attack-Detection-Addendum.md#f-execution-status) | MUST | out of scope |  |  |
| [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) | MUST | out of scope |  | n/a (policy input) |
| [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) | MUST | out of scope |  | n/a (see note) |
| [Model Name + Version](Telemetry-Attack-Detection-Addendum.md#f-model-name-version) | MUST | covered | `approved_software_refs` | ODIS §6.1. |
| [Inference Parameters](Telemetry-Attack-Detection-Addendum.md#f-inference-parameters) | MUST | out of scope |  |  |
| [Input / Output Token Counts](Telemetry-Attack-Detection-Addendum.md#f-input-output-token-counts) | MUST | out of scope |  |  |
| [LLM Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-llm-error-exception) | MUST | out of scope |  |  |
| [Trace Context (propagated)](Telemetry-Attack-Detection-Addendum.md#f-trace-context-propagated) | MUST | covered | `request_trace_id` | ODIS §6.4. |
| [Stop Reason](Telemetry-Attack-Detection-Addendum.md#f-stop-reason) | MUST | out of scope |  |  |
| [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) | SHOULD | out of scope |  |  |
| [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) | SHOULD | covered | `software_hash`, `approved_software_refs` | ODIS §6.2, §6.1. |
| [Organization / Tenant ID](Telemetry-Attack-Detection-Addendum.md#f-organization-tenant-id) | SHOULD | covered | `trust_domain` | ODIS §6.1. |
| [Provider / Endpoint Identity](Telemetry-Attack-Detection-Addendum.md#f-provider-endpoint-identity) | MAY | out of scope |  |  |
| [Pre-Forward-Pass State Digest/Vector](Telemetry-Attack-Detection-Addendum.md#f-pre-forward-pass-state-digest-vector) | MAY | out of scope |  |  |
| [Token Malformation / Context-Corruption Indicator](Telemetry-Attack-Detection-Addendum.md#f-token-malformation-context-corruption-indicator) | MAY | out of scope |  |  |

**RFC §6.2 Content, trust, verdicts and their availability**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Model Input](Telemetry-Attack-Detection-Addendum.md#f-model-input) | MUST | covered | `action` | `action.parameters` (6.4) |
| [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#f-input-source-channel) | MUST | covered | `delegation_chain` | `delegation_chain` origin (6.3) |
| [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification) | MUST | covered | `constraints` | ODIS §6.3. |
| [Source host / IP + request metadata](Telemetry-Attack-Detection-Addendum.md#f-source-host-ip-request-metadata) | MUST | out of scope |  | n/a (policy input) |
| [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-input-verdict) | MUST | out of scope |  |  |
| [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#f-response-model-output) | MUST | out of scope |  |  |
| [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination) | MUST | covered | `resource_indicators` | ODIS §6.3. |
| [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#f-citations-source-attribution) | MUST | out of scope |  |  |
| [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-output-verdict) | MUST | covered | `constraints` | ODIS §6.3. |
| [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) | MUST | out of scope |  |  |
| [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) | MUST | out of scope |  |  |
| [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) | MUST | partial | `attestation_evidence` | `attestation_evidence` (6.2, partial) |
| [Instrumentation Coverage / Hook Status](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) | MUST | out of scope |  |  |
| [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode) | MUST | out of scope |  |  |
| [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) | MUST | out of scope |  |  |
| [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) | MUST | out of scope |  |  |
| [Observation / Thought (reasoning trace)](Telemetry-Attack-Detection-Addendum.md#f-observation-thought-reasoning-trace) | SHOULD | out of scope |  |  |
| [Threat Classification / ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#f-threat-classification-atlas-technique-tag) | MAY | out of scope |  |  |

**RFC §6.3 Tool calls and policy decisions**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#f-execution-environment-sandbox) | MUST | partial | `binding_profile` | `binding_profile` (6.2, partial) |
| [Tool Call I/O](Telemetry-Attack-Detection-Addendum.md#f-tool-call-io) | MUST | covered | `action` | ODIS §6.4. |
| [Tool Name](Telemetry-Attack-Detection-Addendum.md#f-tool-name) | MUST | out of scope |  |  |
| [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#f-tool-type-trust-boundary) | MUST | out of scope |  |  |
| [Tool Execution ID](Telemetry-Attack-Detection-Addendum.md#f-tool-execution-id) | MUST | out of scope |  |  |
| [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#f-tool-definition-digest) | MUST | covered | `approved_software_refs` | ODIS §6.1. |
| [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive) | MUST | out of scope |  |  |
| [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) | MUST | out of scope |  | n/a (see note) |
| [Tool Selection Rationale](Telemetry-Attack-Detection-Addendum.md#f-tool-selection-rationale) | SHOULD | out of scope |  |  |
| [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#f-human-approval-elicitation-event) | SHOULD | partial | `originating_principal` | `originating_principal` (6.3, partial) |
| [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#f-tool-acl-required-scope) | SHOULD | covered | `granted_authorizations` | ODIS §6.3. |
| [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#f-session-taint-labels-information-flow-decisions) | SHOULD | covered | `constraints` | ODIS §6.3. |
| [Backend / Route Restriction Decision](Telemetry-Attack-Detection-Addendum.md#f-backend-route-restriction-decision) | SHOULD | covered | `resource_indicators`, `constraints` | ODIS §6.3. |
| [Mediation Coverage & Bypass Path](Telemetry-Attack-Detection-Addendum.md#f-mediation-coverage-bypass-path) | SHOULD | out of scope |  |  |
| [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-tool-error-exception) | MAY | out of scope |  |  |
| [Tool ID](Telemetry-Attack-Detection-Addendum.md#f-tool-id) | MAY | out of scope |  |  |
| [Tool Privacy Classification](Telemetry-Attack-Detection-Addendum.md#f-tool-privacy-classification) | MAY | covered | `constraints` | ODIS §6.3. |
| [Policy Reason Code](Telemetry-Attack-Detection-Addendum.md#f-policy-reason-code) | MAY | out of scope |  |  |

**RFC §6.4 Memory and retrieval**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Memory Write Event](Telemetry-Attack-Detection-Addendum.md#f-memory-write-event) | MUST | out of scope |  |  |
| [Memory Read / Injection Event](Telemetry-Attack-Detection-Addendum.md#f-memory-read-injection-event) | MUST | out of scope |  |  |
| [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#f-memory-provenance-source) | MUST | out of scope |  |  |
| [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#f-memory-footprint-growth) | MUST | out of scope |  |  |
| [Retrieval Event](Telemetry-Attack-Detection-Addendum.md#f-retrieval-event) | MUST | out of scope |  |  |
| [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-source-provenance) | MUST | covered | `delegation_chain`, `constraints` | ODIS §6.3. |
| [Memory Integrity / Poisoning Signal](Telemetry-Attack-Detection-Addendum.md#f-memory-integrity-poisoning-signal) | SHOULD | out of scope |  |  |
| [Memory Write Rationale](Telemetry-Attack-Detection-Addendum.md#f-memory-write-rationale) | SHOULD | out of scope |  |  |
| [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) | SHOULD | out of scope |  |  |
| [Declared Memory Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-memory-configuration) | MAY | out of scope |  |  |
| [Declared Knowledge-Source Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-knowledge-source-configuration) | MAY | out of scope |  |  |

**RFC §6.5 Orchestration**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) | MUST | covered | `delegation_chain` | ODIS §6.3. |
| [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) | MUST | out of scope |  |  |
| [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) | MUST | out of scope |  |  |
| [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) | MUST | covered | `constraints` | `constraints` (rate) (6.3) |
| [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#f-task-intent-declaration) | SHOULD | covered | `task_id`, `task_description` | ODIS §6.3. |
| [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) | SHOULD | covered | `delegation_id`, `parent_delegation_ref` | ODIS §6.3. |
| [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#f-peer-agent-card-descriptor) | SHOULD | covered | `agent_id`, `approved_software_refs` | ODIS §6.1. |
| [Protocol Envelope Capture](Telemetry-Attack-Detection-Addendum.md#f-protocol-envelope-capture) | MAY | out of scope |  |  |

**RFC §6.6 Identity, provenance and inventory**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) | MUST | covered | `approved_software_refs` | ODIS §6.1. |
| [Identities Used (per hop)](Telemetry-Attack-Detection-Addendum.md#f-identities-used-per-hop) | MUST | covered | `actor` | `actor`, chain (6.3) |
| [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#f-verified-vs-displayed-identity) | MUST | covered | `originating_principal`, `actor` | ODIS §6.3. |
| [Originating Principal (on-behalf-of)](Telemetry-Attack-Detection-Addendum.md#f-originating-principal-on-behalf-of) | SHOULD | covered | `originating_principal` | ODIS §6.3. |
| [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) | SHOULD | covered | `delegation_chain`, `delegation_id`, `parent_delegation_ref` | ODIS §6.3. |
| [Granted Authorizations / Scope](Telemetry-Attack-Detection-Addendum.md#f-granted-authorizations-scope) | SHOULD | covered | `granted_authorizations`, `attenuation_profile_ref` | ODIS §6.3. |
| [Resource Indicators + Constraints](Telemetry-Attack-Detection-Addendum.md#f-resource-indicators-constraints) | SHOULD | covered | `resource_indicators`, `constraints` | ODIS §6.3. |
| [Token Exchange & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#f-credential-minting-scope-narrowing-check) | SHOULD | covered | `granted_authorizations`, `binding_profile` | `granted_authorizations`, `binding_profile` (6.2/6.3) |
| [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#f-trust-domain-crossing-delegation-depth) | SHOULD | covered | `trust_domain`, `max_depth` | ODIS §6.1, 6.2, §6.3. |
| [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#f-runtime-credential-attestation) | SHOULD | covered | `attestation_evidence`, `issuer`, `holder_key_ref`, `expires_at`, `binding_profile` | ODIS §6.2. |
| [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#f-lifecycle-state) | SHOULD | covered | `lifecycle_state` | ODIS §6.1. |
| [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) | SHOULD | covered | `approved_software_refs` | ODIS §6.1. |
| [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) | SHOULD | covered | `approved_software_refs` | ODIS §6.1. |
| [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) | SHOULD | covered | `approved_software_refs` | ODIS §6.1. |
| [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) | SHOULD | out of scope |  |  |
| [Inventory Integrity Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) | SHOULD | covered | `software_hash`, `attestation_evidence` | ODIS §6.2. |
| [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#f-event-sequence-continuity) | SHOULD | out of scope |  |  |
| [Tool Description](Telemetry-Attack-Detection-Addendum.md#f-tool-description) | MAY | covered | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` | ODIS §6.1. |
| [Tool Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#f-tool-status) | MAY | covered | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` | ODIS §6.1. |
| [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#f-creator-id-oncall-creation-update-dates) | MAY | covered | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` | ODIS §6.1. |
| [Surfaces Supported](Telemetry-Attack-Detection-Addendum.md#f-surfaces-supported) | MAY | covered | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` | ODIS §6.1. |
| [Fleet counts](Telemetry-Attack-Detection-Addendum.md#f-fleet-counts) | MAY | out of scope |  |  |

**RFC §6.7 Training data and training infrastructure**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Training-Data Item Digest](Telemetry-Attack-Detection-Addendum.md#f-training-data-item-digest) | SHOULD | out of scope |  |  |
| [Training-Data Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-training-data-source-provenance) | SHOULD | out of scope |  |  |
| [Compute Job Submission](Telemetry-Attack-Detection-Addendum.md#f-compute-job-submission-event) | SHOULD | out of scope |  |  |
<!-- END GENERATED: xm correspondence odis -->

### 5.3 Notes on the mapping

> **Policy-engine consumption and telemetry emission are orthogonal.** A field presented to a policy engine is not thereby excluded from telemetry, and the reverse also holds; AD §1.3's **Authorization Decision Record** exists to record a decision together with the attributes it turned on. Inclusion here is decided by detection and response value, not by how ODIS §6.4 classifies a field.
>
> **ODIS fields intentionally out of telemetry scope** (identity/authority mechanics rather than detection signals): `approved_runtime_issuers`, `policy_profile_ref`, `permitted_delegation_modes`, `provider_entitlements`, and the details of `binding_profile`: the token-binding method (DPoP, mTLS, or TLS session binding via `tls_exp`) together with key custody and which component is authorized to present the derived credential. These are consumed by the policy engine (ODIS §6.4 Identity Context) rather than emitted as security telemetry. `policy_profile_ref` names the policy profile in force; it is neither the content of an instruction configuration nor the record of a decision, so **System Prompt / Instruction Config** and **Authorization Decision Record** carry no ODIS mapping above.
>
> **`trust_domain` and `max_depth` are the exception and are in scope.** AD §1.6's **Trust-Domain Crossing & Delegation Depth** carries both as telemetry, because each becomes detection-grade once a delegation chain leaves the domain that issued it (see [RFC §4.6](CoSAI-AI-Telemetry-RFC.md#46-record-your-boundary-not-their-internals)). `trust_domain` appears in both the registration record (6.1) and the runtime credential descriptor (6.2).
>
> **Data classification travels as a constraint.** ODIS defines `constraints` (6.3) as time, purpose, rate, locality "or other narrowing constraints" and enumerates no keys, so the data-classification narrowing recorded by **Guardrail (Output) Verdict** (AD §1.2), **Tool Privacy Classification** (AD §1.3) and **Session Taint Labels** (AD §1.3) is an illustrative key of that object rather than an ODIS-defined field name.

---

## 6. NIST CSF, AI RMF and ISO/IEC 42001

These three are governance frameworks. They do not carry telemetry; they use it as evidence that controls operate, which places them at the **A** end of the [priority order](CoSAI-AI-Telemetry-RFC.md#41-detection-first). The field set is chosen for detection and response, and its audit value follows from that choice. No field is added to improve coverage of any of them.

### 6.1 What they are, and the versions mapped

**NIST CSF 2.0** [[31]](#standards--frameworks) (26 February 2024) organizes cybersecurity outcomes under six functions: GV, ID, PR, DE, RS and RC. The **Cyber AI Profile** [[32]](#standards--frameworks), NIST IR 8596, overlays three AI focus areas on it: securing AI systems (*Secure*), AI-enabled cyber defense (*Defend*), and thwarting AI-enabled attacks (*Thwart*). It is an initial preliminary draft (16 December 2025), and no Initial Public Draft has been published as of 2 October 2026. **NIST AI RMF 1.0** [[30]](#standards--frameworks) (January 2023) organizes AI risk management under GOVERN, MAP, MEASURE and MANAGE; it is under revision, with no draft published. **ISO/IEC 42001:2023** [[33]](#standards--frameworks) specifies a certifiable AI management system, with its controls in Annex A. It is a paid standard, and the control number below comes from public summaries rather than the text.

### 6.2 Correspondence

The MUST tier evidences CSF continuous monitoring (DE.CM) and adverse event analysis (DE.AE). The identifier, provenance and delegation fields evidence incident management and analysis (RS.MA, RS.AN). The identity and authorization fields of RFC §§6.3 and 6.6 evidence identity management and access control (PR.AA), and [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) makes asset management (ID.AM) continuous rather than periodic. RECOVER and the organizational half of GOVERN are weakly evidenced, because they are not telemetry problems.

In AI RMF terms the field set measures the security slice of MEASURE and MANAGE. Fairness, bias and the other trustworthiness characteristics are outside it.

ISO/IEC 42001 Annex A requires event logging over the AI system life cycle (A.6.2.8 in public summaries) without specifying what to log; the field set supplies that content. Certification evidence also needs retention, access control and chain of custody, which [RFC §2.2](CoSAI-AI-Telemetry-RFC.md#22-not-in-scope) leaves to a later publication.

### 6.3 Asks

**Propose the field set to NIST as content for the Cyber AI Profile's *Secure* focus area.** The Profile states outcomes for securing AI systems but not the telemetry that evidences them, and each field here rests on documented attacks. NIST takes input before the Initial Public Draft.

---

## References

### Primary sources (attack corpus & taxonomy)

1. **MITRE ATLAS**: Adversarial Threat Landscape for Artificial-Intelligence Systems (technique matrix; `AML.Txxxx` taxonomy). MITRE. <https://atlas.mitre.org/>. Citations verified against release **`v2026.08`** (1 September 2026), 197 techniques and 72 case studies; machine-readable at <https://github.com/mitre-atlas/atlas-data>.

### Standards & frameworks

25. **AITF**: AI Telemetry Framework (OTel + OCSF binding), donated to CoSAI WS2. <https://github.com/cosai-oasis/ws2-defenders/tree/main/telemetry/aitf>. Cited at version 0.4, commit `e17c514` (7 September 2026).
26. **ODIS**: Coalition for Secure AI, Workstream 4: *Open Delegation & Identity Standard*. Apache-2.0. Records defined in ODIS §6: Agent Registration Record (6.1), Agent Runtime Credential Descriptor (6.2), Delegation Record (6.3), Identity Context (Policy Engine Feed) (6.4). Cited at commit `148dc41` (8 September 2026); ODIS is a working draft, so this reference is pinned to a commit rather than to `main` to keep the section numbers and field names cited against it checkable. <https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md>

<!-- list break: reference numbers are not contiguous -->

30. **NIST AI Risk Management Framework (AI RMF 1.0)**: NIST, January 2023; **currently under revision**. GOVERN / MAP / MEASURE / MANAGE. <https://www.nist.gov/itl/ai-risk-management-framework> · companion **NIST AI 600-1, Generative AI Profile** (July 2024).
31. **NIST Cybersecurity Framework (CSF) 2.0**: GV / ID / PR / DE / RS / RC; 6 functions, 22 categories, 106 subcategories. <https://www.nist.gov/cyberframework>
32. **NIST Cyber AI Profile**: *Cybersecurity Framework Profile for Artificial Intelligence: NIST Community Profile*, **NIST IR 8596**, *initial preliminary draft* published 16 December 2025; CSF 2.0 community profile overlaying the **Secure / Defend / Thwart** AI focus areas. Comment period closed 30 January 2026; working sessions held April and May 2026; **no Initial Public Draft as of 2 October 2026**. <https://csrc.nist.gov/pubs/ir/8596/iprd> · project: <https://www.nccoe.nist.gov/projects/cyber-ai-profile>
33. **ISO/IEC 42001:2023**: *Information technology — Artificial intelligence — Management system.* Clauses 4 to 10 plus **Annex A** (38 controls under 9 objectives, A.2 to A.10) selected via a Statement of Applicability. Paid standard. <https://www.iso.org/standard/42001>.

<!-- list break: reference numbers are not contiguous -->

35. **OpenTelemetry, GenAI semantic conventions.** Now maintained in a dedicated repository: <https://github.com/open-telemetry/semantic-conventions-genai>. Spans, metrics, events, MCP, and provider-specific conventions, **all at Development status**. Attribute registry: <https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/>. Entries marked *Deprecated* there mostly reflect the relocation rather than withdrawal, but not always: some were **renamed** in the move (`gen_ai.usage.cache_creation.input_tokens` → `gen_ai.usage.cache_write.input_tokens`) and some were **withdrawn outright** (`gen_ai.prompt` and `gen_ai.completion`, both `reason: obsoleted`, "Removed, no replacement at this time"). Names therefore come from the new repository, not the deprecated registry. **Names cited from it resolve at `semantic-conventions-genai` commit `e07f4eb` (2 October 2026), which publishes no releases, and at `semantic-conventions` release v1.44.0 (4 August 2026).**
36. **OpenTelemetry, core specification.** Signals, context propagation, sampling. <https://opentelemetry.io/docs/specs/otel/> · **W3C Trace Context**: <https://www.w3.org/TR/trace-context/> · MCP context propagation via `params._meta` (Specification Enhancement Proposal **SEP-414**): <https://modelcontextprotocol.io/community/seps/414-request-meta>
37. **OCSF. Open Cybersecurity Schema Framework.** <https://ocsf.io/> · schema browser: <https://schema.ocsf.io/>. Cited at release 1.9.0 (3 August 2026).
38. **OWASP AOS, Agent Observability Standard.** OWASP. <https://aos.owasp.org/>. Three pillars (Instrument / Trace / Inspect). *Working draft.* Verified against the specification sources at commit `e4a50f6` (30 December 2025), schema version **0.1.0** (`specification/AOS/aos_schema.json` in [OWASP/www-project-agent-observability-standard](https://github.com/OWASP/www-project-agent-observability-standard)); the specification last changed on 10 November 2025.
39. **Model Context Protocol (MCP).** <https://modelcontextprotocol.io/>. Tools, resources, prompts, sampling, elicitation, roots. Cited at specification version 2026-07-28.
40. **A2A, Agent-to-Agent Protocol.** <https://a2a-protocol.org/>. Agent cards, task lifecycle, push-notification configuration. Cited at release v1.0.1 (28 May 2026).
41. **CycloneDX**: OWASP BOM standard, incl. ML-BOM. <https://cyclonedx.org/>
42. **SPDX**: Linux Foundation software bill-of-materials standard. <https://spdx.dev/>
43. **SWID**: ISO/IEC 19770-2 software identification tags. <https://csrc.nist.gov/projects/Software-Identification-SWID>
44. **CPEX**: policy-enforcement runtime and reference monitor for AI agents. <https://contextforge-org.github.io/cpex/> · threat model: <https://contextforge-org.github.io/cpex/docs/threat-model/>. Cited at release `v0.2.3` (2 October 2026), the first release to contain the threat-model document. <https://github.com/contextforge-org/cpex>

<!-- list break: reference numbers are not contiguous -->

74. **RFC 8785**: Rundgren, A., Jordan, B. & Erdtman, S. *JSON Canonicalization Scheme (JCS).* RFC 8785 (2020). <https://www.rfc-editor.org/rfc/rfc8785>

### Other sources

75. **OpenTelemetry audit logging proposal**: *Audit Logging signal*, opentelemetry-specification pull request #5059, closed unmerged as inactive 28 May 2026. <https://github.com/open-telemetry/opentelemetry-specification/pull/5059>

<!-- list break: reference numbers are not contiguous -->

86. **PPE, Praxis Policy Engine**: policy-enforcement engine of the Praxis gateway, Apache-2.0. Its audit seam, pull request #84 (*decision and effect auditing*), merged 2 October 2026 as `da22e0a`, records per dispatch the verdict, each plugin's step and the violation behind it, entry taint, and keyed content digests at entry and emission; CPEX pull request #166 is the same seam on CPEX. <https://github.com/praxis-proxy/policy/pull/84>
87. **AID-EMIT-1**: *AI Identity Evidence Emitter Format*, version 1.1.2-draft (1 October 2026), Apache-2.0. Record format for OCSF API Activity (6003) decision records under `record_integrity`: signing input, chain, stream stamps (section 7), decision vocabulary and content digest form (section 9), with conformance vectors. Cited at commit `f4ee6d5` (2 October 2026). <https://github.com/Levaj2000/AI-Identity/blob/f4ee6d5/docs/specs/aid-emit-1.md>
88. **OpenTelemetry Audit Logging data model**: draft of the Audit Logging SIG proposal (open-telemetry/community issue #2409), `specification/audit/data-model.md` on branch `auditing` of `apeirora/opentelemetry-specification`. Cited at commit `3c5a0ff` (18 September 2026). <https://github.com/apeirora/opentelemetry-specification/blob/3c5a0ff6f952846a634b9729117d853b6bad2d3a/specification/audit/data-model.md> · proposal: <https://github.com/open-telemetry/community/issues/2409>
89. **OpenTelemetry audit to OCSF crosswalk**: field-by-field mapping between the Audit Logging data model and OCSF 1.9.0 `attestation`, with vectors derived from a 236-event signed export. Cited at commit `f4ee6d5` (2 October 2026). <https://github.com/Levaj2000/AI-Identity/tree/f4ee6d5/docs/otel-ocsf-audit-crosswalk>
