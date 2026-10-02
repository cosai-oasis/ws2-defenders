# Telemetry for AI Security: Cross-Mapping Addendum {**Working Draft v0.6**}

**Status:** Request for Comments, revision 0.6
**Origin:** Coalition for Secure AI (CoSAI), Workstream 2 (Defenders)
**Companion to:** [Telemetry for AI Security](CoSAI-AI-Telemetry-RFC.md) (cited as RFC); see also the [Attack Detection Addendum](Telemetry-Attack-Detection-Addendum.md) (cited as AD).

---

### How this addendum is organized

This addendum maps the field set onto the specifications that carry security telemetry, and states what each would need to carry the rest. **OCSF** and **OpenTelemetry** are its two target audiences, in that order: OCSF is how a SIEM consumes the telemetry, OpenTelemetry how instrumentation emits it. **AITF** is the bridge: it carries the fields today and stages the changes proposed to the other two. The remaining sections are cross references, included for completeness.

Every section answers the same questions, under the same headings, and skips one only where it does not apply:

1. **What it is, and the version mapped.** Each mapping is pinned to a commit or a published version.
2. **Correspondence.** Which construct carries each field, and how fully: *covered*, *partial*, *none*, or *out of scope*.
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
| OpenTelemetry semantic conventions (core) | v1.44.0 (2026-08-04) | [[36]](#standards--frameworks) | yes, 2026-10-02 |
| AI Telemetry Framework | commit `e17c514` (2026-09-07) | [[25]](#standards--frameworks) | yes, 2026-10-02 |
| Open Delegation & Identity Standard | commit `148dc41` (2026-09-08) | [[26]](#standards--frameworks) | yes, 2026-10-02 |
| OWASP Agent Observability Standard | commit `e4a50f6` (2025-12-30) | [[38]](#standards--frameworks) | not yet |
| CPEX | commit `035012f` (2026-08-18) | [[44]](#standards--frameworks) | yes |
| Model Context Protocol | 2026-07-28 | [[39]](#standards--frameworks) | not yet |
| Agent2Agent Protocol | v1.0.1 (2026-05-28) | [[40]](#standards--frameworks) | not yet |
| NIST Cybersecurity Framework | 2.0 (2024-02-26) | [[31]](#standards--frameworks) | not yet |
| NIST AI Risk Management Framework | 1.0 (2023-01-26) | [[30]](#standards--frameworks) | not yet |
| ISO/IEC 42001 | 2023 | [[33]](#standards--frameworks) | not yet |
<!-- END GENERATED: xm pins -->

**Coverage and asks, by publication.**

<!-- BEGIN GENERATED: xm summary -->
| Publication | Covered | Partial | None | Out of scope | Asks |
| :------------------ | ---: | ---: | ---: | ---: | :------------------ |
| OCSF | 10 | 30 | 58 | 0 | 29: 1 approved, 6 open, 22 proposed |
| OpenTelemetry | 22 | 19 | 38 | 19 | 24: 24 proposed |
| AITF | 92 | 5 | 1 | 0 | none |
| ODIS | 44 | 3 | 51 | 0 | none |
<!-- END GENERATED: xm summary -->

- **The proposals are evidence-gated and therefore small.** A field becomes a standardization ask only once it is MUST under [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers). Nothing is proposed speculatively.
- **Emission and consumption move together.** A field OpenTelemetry emits but OCSF cannot represent arrives at the SIEM as unstructured overflow; a field OCSF defines but no instrumentation produces stays theoretical. Paired asks are the intent.

CoSAI is engaging the **OpenTelemetry** and **OCSF** communities directly on this work, and welcomes input from the wider open source security community in turn. What is wanted in return: corrections to the mappings, and attacks the corpus is missing.

### Agents you do not operate


[RFC §4.6](CoSAI-AI-Telemetry-RFC.md#46-record-your-boundary-not-their-internals) sets knowability tiers for counterparties the deployment does not run. Each adjacent standard supplies one of the rules behind them.

**From CPEX: the counterparty is on the hostile side of the monitor, by definition.** CPEX's boundary places the agent, the caller, and everything beyond it in the untrusted region, and admits nothing from there into policy. An external agent is simply the clearest case. The consequence for telemetry is that you instrument **your own boundary**, not their internals, and CPEX's inbound-gateway placement is the one that sees every caller. What you record is a mediated interaction, not an observed agent.

**From ODIS: authority becomes legible through presented claims, not through inspection.** You cannot audit an external agent's reasoning, but you can require it to present a verifiable delegation record: originating principal, chain, granted authorizations, constraints. This is why `trust_domain` and delegation depth are detection-grade rather than mere policy-engine inputs the moment a chain leaves your domain (see AD §1.6).

**From OWASP AOS: ask the counterparty to be inspectable, and record the answer.** AOS's *Observed Agent* is one that exposes hooks, events, and an AgBOM on request; an external agent is an **unobserved** agent until it agrees otherwise. AOS's A2A extension already distinguishes full from partial counterparty context, which is the same distinction as knowing versus not knowing who you are talking to. Whether an inspection request was answered is itself a signal.

---

---

## 1. OCSF

### 1.1 What it is, and the version mapped

<!-- BEGIN GENERATED: xm pin ocsf -->
<!-- END GENERATED: xm pin ocsf -->

This section covers the OCSF consumption side of the standards bridge; AITF carries the interim binding ([§3](#3-aitf)). OpenTelemetry coverage and emission-side proposals are in [§2](#2-opentelemetry).

OCSF 1.9.0 already carries an `ai_operation` profile on API Activity (6003): `ai_agent`, `ai_model`, `delegation` and `message_context`, with record integrity on the base event. The correspondence below is against that release; constructs proposed in open pull requests are asks, not coverage.

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
| [Stop Reason](Telemetry-Attack-Detection-Addendum.md#f-stop-reason) | MUST | none |  | ai_stop_reason_id is approved (#1704) but not in 1.9.0. | [ocsf_stop_reason](#ask-ocsf-stop-reason) |
| [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) | SHOULD | none |  | No autonomy level. | [ocsf_autonomy_level](#ask-ocsf-autonomy-level) |
| [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) | SHOULD | none |  | Provenance and signing not standardized in the profile. | [ocsf_model_provenance](#ask-ocsf-model-provenance) |
| [Organization / Tenant ID](Telemetry-Attack-Detection-Addendum.md#f-organization-tenant-id) | SHOULD | partial | `object:metadata`, `attribute:tenant_uid` | One tenant per event (metadata.tenant_uid), not the tenant of the agent, the session and the invoking user separately. No ask proposed; decide one or record why none. |  |
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
| [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) | MUST | none |  | No refusal status or reason; a content-filter stop reason (#1704) records one cause only. | [ocsf_stop_reason](#ask-ocsf-stop-reason) |
| [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) | MUST | none |  | No attachment identity. | [ocsf_message_context_content](#ask-ocsf-message-context-content) |
| [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) | MUST | none |  | No attribute-provenance marking. | [ocsf_attribute_source](#ask-ocsf-attribute-source) |
| [Instrumentation Coverage / Hook Attestation](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) | MUST | none |  | No hook-coverage representation. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode) | MUST | none |  | No enforcement availability or fail-open representation. | [ocsf_ai_guardrail](#ask-ocsf-ai-guardrail) |
| [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) | MUST | none |  | No record that an enforcement point rewrote a payload. | [ocsf_ai_guardrail](#ask-ocsf-ai-guardrail), [ocsf_message_context_content](#ask-ocsf-message-context-content) |
| [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) | MUST | none |  | No obfuscation flag or decoded form. | [ocsf_obfuscation](#ask-ocsf-obfuscation) |
| [Observation / Thought (reasoning trace)](Telemetry-Attack-Detection-Addendum.md#f-observation-thought-reasoning-trace) | SHOULD | none |  | No reasoning trace. No ask proposed; decide one or record why none. |  |
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
| [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-tool-error-exception) | MUST | partial | `attribute:status_id`, `attribute:status_detail` | An outcome on API Activity, not tied to a tool call. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) | MUST | partial | `class:3003` | No authorization-decision object for AI operations. | [ocsf_ai_authorization](#ask-ocsf-ai-authorization) |
| [Tool Selection Rationale](Telemetry-Attack-Detection-Addendum.md#f-tool-selection-rationale) | SHOULD | none |  | No self-asserted rationale. No ask proposed; decide one or record why none. |  |
| [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#f-human-approval-elicitation-event) | SHOULD | none |  | No human-approval lifecycle. | [ocsf_ai_approval](#ask-ocsf-ai-approval) |
| [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#f-tool-acl-required-scope) | SHOULD | none |  | No tool scope attribute. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#f-session-taint-labels-information-flow-decisions) | SHOULD | none |  | No information-flow or taint labels. | [ocsf_ai_taint](#ask-ocsf-ai-taint) |
| [Backend / Route Restriction Decision](Telemetry-Attack-Detection-Addendum.md#f-backend-route-restriction-decision) | SHOULD | none |  | No routing constraint or candidate backends. No ask proposed; decide one or record why none. |  |
| [Mediation Coverage & Bypass Path](Telemetry-Attack-Detection-Addendum.md#f-mediation-coverage-bypass-path) | SHOULD | none |  | No mediation-coverage representation. XM names the gap and proposes no change; decide an ask or record why none. |  |
| [Tool ID](Telemetry-Attack-Detection-Addendum.md#f-tool-id) | MAY | none |  | No tool object. | [ocsf_ai_tool](#ask-ocsf-ai-tool) |
| [Tool Privacy Classification](Telemetry-Attack-Detection-Addendum.md#f-tool-privacy-classification) | MAY | partial | `profile:data_classification`, `object:data_classification`, `attribute:confidentiality` | Classification attaches to data, not to the tool that touches it. No ask proposed; decide one or record why none. |  |
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
| [Memory Write Rationale](Telemetry-Attack-Detection-Addendum.md#f-memory-write-rationale) | SHOULD | none |  | No self-asserted rationale. No ask proposed; decide one or record why none. |  |
| [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) | SHOULD | none |  | No retrieved-content integrity signal. | [ocsf_ai_retrieval](#ask-ocsf-ai-retrieval) |
| [Declared Memory Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-memory-configuration) | MAY | none |  | No memory-store declaration. No ask proposed; decide one or record why none. |  |
| [Declared Knowledge-Source Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-knowledge-source-configuration) | MAY | none |  | No knowledge-source declaration. No ask proposed; decide one or record why none. |  |

**RFC §6.5 Orchestration**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) | MUST | none |  | No inter-agent message. | [ocsf_ai_agent_activity](#ask-ocsf-ai-agent-activity) |
| [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) | MUST | none |  | No background-task event. | [ocsf_ai_agent_activity](#ask-ocsf-ai-agent-activity) |
| [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) | MUST | none |  | No loop or step signal. | [ocsf_ai_agent_activity](#ask-ocsf-ai-agent-activity) |
| [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) | MUST | none |  | No resource aggregate, and no budget accounting on the consuming action. | [ocsf_ai_agent_activity](#ask-ocsf-ai-agent-activity), [ocsf_ai_authorization](#ask-ocsf-ai-authorization) |
| [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#f-task-intent-declaration) | SHOULD | partial | `object:ai_agent`, `attribute:charter` | A charter defines the agent's role, scope and operating bounds, not the purpose declared for this run. No ask proposed; decide one or record why none. |  |
| [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) | SHOULD | none |  | No delegated-task lifecycle. | [ocsf_ai_delegation_activity](#ask-ocsf-ai-delegation-activity) |
| [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#f-peer-agent-card-descriptor) | SHOULD | partial | `object:ai_agent` | ai_agent can describe a counterparty; no descriptor change or verification outcome. No ask proposed; decide one or record why none. |  |
| [Protocol Envelope Capture](Telemetry-Attack-Detection-Addendum.md#f-protocol-envelope-capture) | MAY | partial | `attribute:raw_data` | raw_data holds the source record before normalization, not the envelope of each MCP or A2A message. No ask proposed; decide one or record why none. |  |

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
| [Credential Minting & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#f-credential-minting-scope-narrowing-check) | SHOULD | partial | `class:3002` | No requested-versus-granted scope. | [ocsf_delegation_lineage](#ask-ocsf-delegation-lineage) |
| [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#f-trust-domain-crossing-delegation-depth) | SHOULD | none |  | No trust-domain crossing; depth derivable only if every hop carries parent_uid. | [ocsf_delegation_lineage](#ask-ocsf-delegation-lineage) |
| [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#f-runtime-credential-attestation) | SHOULD | none |  | No runtime attestation (OCSF attestation means record integrity). | [ocsf_runtime_attestation](#ask-ocsf-runtime-attestation) |
| [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#f-lifecycle-state) | SHOULD | none |  | No lifecycle state on delegation. | [ocsf_delegation_lineage](#ask-ocsf-delegation-lineage) |
| [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) | SHOULD | partial | `class:inventory_info` | No AI-asset object. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) | SHOULD | partial | `class:inventory_info` | No AI-asset object. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) | SHOULD | none |  | No agent-composition BOM. | [ocsf_ai_bom](#ask-ocsf-ai-bom) |
| [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) | SHOULD | none |  | No dependency graph. | [ocsf_ai_bom](#ask-ocsf-ai-bom) |
| [Inventory Attestation Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) | SHOULD | none |  | No BOM signature. | [ocsf_ai_bom](#ask-ocsf-ai-bom) |
| [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#f-event-sequence-continuity) | SHOULD | covered | `profile:record_integrity`, `object:attestation`, `attribute:prev_event`, `attribute:chain_uid` | No new schema: continuity maps to attestation.prev_event and attestation.chain_uid. |  |
| [Description](Telemetry-Attack-Detection-Addendum.md#f-tool-description) | MAY | partial | `class:inventory_info` | No AI-asset object. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#f-tool-status) | MAY | partial | `class:inventory_info` | No AI-asset object. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#f-creator-id-oncall-creation-update-dates) | MAY | partial | `class:inventory_info` | No AI-asset object. | [ocsf_ai_asset](#ask-ocsf-ai-asset) |
| [Surfaces Supported](Telemetry-Attack-Detection-Addendum.md#f-surfaces-supported) | MAY | none |  | No per-tool exposure map. A MAY field; no ask. |  |
| [Fleet counts](Telemetry-Attack-Detection-Addendum.md#f-fleet-counts) | MAY | none |  | Fleet aggregates are derived. Derived from per-event records; no ask. |  |
<!-- END GENERATED: xm correspondence ocsf -->

### 1.3 Gaps

The table states each gap. Two need more than a cell.

**Delegation lineage.** No granted scope / constraints, runtime credential attestation, trust-domain crossing, lifecycle state. Depth is derivable **only if every hop carries `parent_uid`, which is optional today** ([ocsf-schema#1739](https://github.com/ocsf/ocsf-schema/issues/1739)): a fully conformant producer can emit a re-delegated action with no parent link, and one such record anywhere in the chain breaks the walk without anyone violating the schema. A walk is also not a join, so reconstructing a subtree means resolving every intermediate delegation out of band, which an aggregate check evaluated at the consuming action (**Resource-Consumption Aggregate**, AD §1.5, MUST) cannot afford at request latency

**Authorization and accounting.** No authorization-decision object for AI operations; no information-flow/taint labels; no human-approval lifecycle; no attribute-provenance marking; no mediation-coverage representation. No carrier for the **accounting decision** either: the aggregate consumed and remaining against the *principal's* budget, recorded on the action that consumed it. A dictionary search (2026-08-25) found no attributes in that family, and a metric cannot testify because it does not survive with the action record

### 1.4 Asks

<!-- BEGIN GENERATED: xm asks ocsf -->
<a id="ask-ocsf-stop-reason"></a>**`ocsf_stop_reason`** (approved; [ocsf-schema#1704](https://github.com/ocsf/ocsf-schema/issues/1704)). Merge ai_stop_reason_id on the ai_operation profile (End of Turn, Token Limit, Tool Use, Session Stop, Content Filter). *Closes:* [Stop Reason](Telemetry-Attack-Detection-Addendum.md#f-stop-reason) (MUST, 3 instances) and [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) (MUST, 9 instances).

<a id="ask-ocsf-ai-tool"></a>**`ocsf_ai_tool`** (open; [ocsf-schema#1729](https://github.com/ocsf/ocsf-schema/issues/1729)). Land the ai_tool object with its mcp sub-block, primitive axis and transaction_uid join key; add a tool_trust_boundary enum and a scope attribute. *Closes:* [Tool Call I/O](Telemetry-Attack-Detection-Addendum.md#f-tool-call-io) (MUST, 19 instances), [Tool Name](Telemetry-Attack-Detection-Addendum.md#f-tool-name) (MUST, 6 instances), [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#f-tool-type-trust-boundary) (MUST, 2 instances), [Tool Execution ID](Telemetry-Attack-Detection-Addendum.md#f-tool-execution-id) (MUST, 2 instances), [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#f-tool-definition-digest) (MUST, 2 instances), [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive) (MUST, 5 instances), [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-tool-error-exception) (MUST, 2 instances), [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#f-tool-acl-required-scope) (SHOULD, 6 instances) and [Tool ID](Telemetry-Attack-Detection-Addendum.md#f-tool-id) (MAY, 0 instances).

<a id="ask-ocsf-delegation-lineage"></a>**`ocsf_delegation_lineage`** (open; [ocsf-schema#1739](https://github.com/ocsf/ocsf-schema/issues/1739)). Extend delegation with scope, constraints and lifecycle state; require parent_uid where a parent exists; add a root or subtree identifier. *Closes:* [Identities Used (per hop)](Telemetry-Attack-Detection-Addendum.md#f-identities-used-per-hop) (MUST, 18 instances), [Originating Principal (on-behalf-of)](Telemetry-Attack-Detection-Addendum.md#f-originating-principal-on-behalf-of) (SHOULD, 3 instances), [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) (SHOULD, 2 instances), [Granted Authorizations / Scope](Telemetry-Attack-Detection-Addendum.md#f-granted-authorizations-scope) (SHOULD, 3 instances), [Resource Indicators + Constraints](Telemetry-Attack-Detection-Addendum.md#f-resource-indicators-constraints) (SHOULD, 0 instances), [Credential Minting & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#f-credential-minting-scope-narrowing-check) (SHOULD, 1 instances), [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#f-trust-domain-crossing-delegation-depth) (SHOULD, 1 instances) and [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#f-lifecycle-state) (SHOULD, 2 instances).

<a id="ask-ocsf-ai-agent-activity"></a>**`ocsf_ai_agent_activity`** (open; [ocsf-schema#1640](https://github.com/ocsf/ocsf-schema/issues/1640)). Ratify an AI Agent Activity class (9001) for agent-originated control-plane events: inter-agent messages, background tasks, loop and resource aggregates, capability changes. *Closes:* [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) (MUST, 7 instances), [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) (MUST, 3 instances), [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) (MUST, 5 instances), [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) (MUST, 4 instances) and [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) (MUST, 4 instances).

<a id="ask-ocsf-ai-bom"></a>**`ocsf_ai_bom`** (open; [ocsf-schema#1724](https://github.com/ocsf/ocsf-schema/issues/1724)). Add an ai_bom object (BOM reference, format, signature, dependency edges) and a capability-change activity on Agent Activity. *Closes:* [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) (MUST, 4 instances), [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) (SHOULD, 2 instances), [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) (SHOULD, 1 instances) and [Inventory Attestation Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) (SHOULD, 0 instances).

<a id="ask-ocsf-ai-asset"></a>**`ocsf_ai_asset`** (open; [ocsf-schema#1724](https://github.com/ocsf/ocsf-schema/issues/1724)). Add an ai_asset object (version, software reference, ownership, status, instrumentation coverage). *Closes:* [Instrumentation Coverage / Hook Attestation](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) (MUST, on a dependency), [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) (SHOULD, 2 instances), [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) (SHOULD, 2 instances), [Description](Telemetry-Attack-Detection-Addendum.md#f-tool-description) (MAY, 0 instances), [Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#f-tool-status) (MAY, 0 instances) and [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#f-creator-id-oncall-creation-update-dates) (MAY, 0 instances).

<a id="ask-ocsf-ai-delegation-activity"></a>**`ocsf_ai_delegation_activity`** (open; [ocsf-schema#1640](https://github.com/ocsf/ocsf-schema/issues/1640)). Ratify an AI Delegation Activity class (9002) for the delegation lifecycle. *Closes:* [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) (SHOULD, 0 instances) and [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) (SHOULD, 2 instances).

<a id="ask-ocsf-message-context-content"></a>**`ocsf_message_context_content`** (proposed). Extend message_context with prompt and response hashes, a redaction flag, the system prompt and its hash, and attachment identity, each hash with its canonicalization declaration. *Closes:* [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) (MUST, 3 instances), [Model Input](Telemetry-Attack-Detection-Addendum.md#f-model-input) (MUST, 15 instances), [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#f-response-model-output) (MUST, 9 instances), [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) (MUST, 3 instances) and [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) (MUST, on a dependency).

<a id="ask-ocsf-ai-memory"></a>**`ocsf_ai_memory`** (proposed). Add an ai_memory object (operation, provenance, footprint, poisoning score, isolation verified). *Closes:* [Memory Write Event](Telemetry-Attack-Detection-Addendum.md#f-memory-write-event) (MUST, 7 instances), [Memory Read / Injection Event](Telemetry-Attack-Detection-Addendum.md#f-memory-read-injection-event) (MUST, 6 instances), [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#f-memory-provenance-source) (MUST, 4 instances), [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#f-memory-footprint-growth) (MUST, 2 instances) and [Memory Integrity / Poisoning Signal](Telemetry-Attack-Detection-Addendum.md#f-memory-integrity-poisoning-signal) (SHOULD, 3 instances).

<a id="ask-ocsf-ai-operation-identifiers"></a>**`ocsf_ai_operation_identifiers`** (proposed). Extend the ai_operation profile with run, turn and step identifiers, action type and trigger type. *Closes:* [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#f-workflow-run-id) (MUST, on a dependency), [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#f-session-turn-step-ids) (MUST, 5 instances), [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#f-trigger-type-source-event) (MUST, 5 instances) and [Action Type](Telemetry-Attack-Detection-Addendum.md#f-action-type) (MUST, 6 instances).

<a id="ask-ocsf-ai-retrieval"></a>**`ocsf_ai_retrieval`** (proposed). Add an ai_retrieval object (query, items, source and provenance, integrity signal). *Closes:* [Retrieval Event](Telemetry-Attack-Detection-Addendum.md#f-retrieval-event) (MUST, 8 instances), [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-source-provenance) (MUST, 6 instances) and [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) (SHOULD, 2 instances).

<a id="ask-ocsf-ai-authorization"></a>**`ocsf_ai_authorization`** (proposed). Add an ai_authorization object (decision, reason, code, deciding authority, rule, obligations, budget accounting and the principal or subtree join key). *Closes:* [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) (MUST, 9 instances), [Policy Reason Code](Telemetry-Attack-Detection-Addendum.md#f-policy-reason-code) (MAY, 0 instances) and [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) (MUST, 4 instances).

<a id="ask-ocsf-ai-guardrail"></a>**`ocsf_ai_guardrail`** (proposed). Add an ai_guardrail object (type, verdict, score, blocked flag, threat reference), with enforcement availability and failure-mode attributes. *Closes:* [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-input-verdict) (MUST, 6 instances), [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-output-verdict) (MUST, 4 instances), [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode) (MUST, on a dependency) and [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) (MUST, on a dependency).

<a id="ask-ocsf-egress-correlation"></a>**`ocsf_egress_correlation`** (proposed). Add an egress correlation attribute linking model output to its destination, recipient or URL. *Closes:* [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination) (MUST, 10 instances).

<a id="ask-ocsf-trust-level"></a>**`ocsf_trust_level`** (proposed). Add a trust_level enum usable on content and message objects. *Closes:* [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification) (MUST, 10 instances).

<a id="ask-ocsf-attribute-source"></a>**`ocsf_attribute_source`** (proposed). Add an attribute_source enum (idp, pdp, enforcement-state, platform, self-asserted) usable on identity, authorization and agent-state attributes. *Closes:* [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) (MUST, 6 instances).

<a id="ask-ocsf-input-segment-source"></a>**`ocsf_input_segment_source`** (proposed). Add a per-segment source to message_context: the surface, tool, agent or document each input segment came from, beside the proposed trust_level. *Closes:* [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#f-input-source-channel) (MUST, 6 instances).

<a id="ask-ocsf-identity-verification"></a>**`ocsf_identity_verification`** (proposed). Record which identity authorized an operation (a verified identifier or a display name) and the verification outcome, on actor or ai_authorization. *Closes:* [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#f-verified-vs-displayed-identity) (MUST, 4 instances).

<a id="ask-ocsf-citations"></a>**`ocsf_citations`** (proposed). Add citations to message_context, each with its source and whether it resolves to an item an ai_retrieval record returned, aligned with AITF rag.citation.*. *Closes:* [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#f-citations-source-attribution) (MUST, 3 instances).

<a id="ask-ocsf-entry-point"></a>**`ocsf_entry_point`** (proposed). Add an entry point to ai_operation: the surface an operation arrived through (CLI, web, IDE, email, chat, scheduler) and whether it is internal or external. *Closes:* [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) (MUST, 3 instances).

<a id="ask-ocsf-tool-execution-environment"></a>**`ocsf_tool_execution_environment`** (proposed; [ocsf-schema#1729](https://github.com/ocsf/ocsf-schema/issues/1729)). Add the execution environment of a tool call to ai_tool: isolation mode, runtime, timeout and egress policy, aligned with AITF supply_chain.runtime.*. *Closes:* [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#f-execution-environment-sandbox) (MUST, 3 instances).

<a id="ask-ocsf-ai-error"></a>**`ocsf_ai_error`** (proposed). Add an AI error type to ai_operation beside status_id: provider error, context overflow, rate limit, content filter, silent truncation. *Closes:* [LLM Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-llm-error-exception) (MUST, 2 instances).

<a id="ask-ocsf-inference-parameters"></a>**`ocsf_inference_parameters`** (proposed). Add the decoding parameters in force for a call (temperature, top_p, max_tokens, stop sequences, seed) and the declared context window to ai_model or message_context. *Closes:* [Inference Parameters](Telemetry-Attack-Detection-Addendum.md#f-inference-parameters) (MUST, 2 instances).

<a id="ask-ocsf-obfuscation"></a>**`ocsf_obfuscation`** (proposed). Add an obfuscation finding (detected, encodings, decoded form or its hash) to ai_guardrail or Detection Finding, aligned with AITF security.obfuscation.*. *Closes:* [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) (MUST, 2 instances).

<a id="ask-ocsf-ai-approval"></a>**`ocsf_ai_approval`** (proposed). Add an ai_approval object (correlation ID, status, identity-provider-verified approver, channel, scope-binding result). *Closes:* [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#f-human-approval-elicitation-event) (SHOULD, 7 instances).

<a id="ask-ocsf-ai-taint"></a>**`ocsf_ai_taint`** (proposed). Add an ai_taint object (labels, scope, origin, taint-caused denial). *Closes:* [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#f-session-taint-labels-information-flow-decisions) (SHOULD, 3 instances).

<a id="ask-ocsf-autonomy-level"></a>**`ocsf_autonomy_level`** (proposed). Add an autonomy_level enum. *Closes:* [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) (SHOULD, 2 instances).

<a id="ask-ocsf-model-provenance"></a>**`ocsf_model_provenance`** (proposed). Standardize model provider and provenance or signing attributes in ai_operation. *Closes:* [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) (SHOULD, 0 instances).

<a id="ask-ocsf-runtime-attestation"></a>**`ocsf_runtime_attestation`** (proposed). Add a runtime_attestation object carrying independently issued evidence objects and an explicit not-available status with a reason. *Closes:* [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#f-runtime-credential-attestation) (SHOULD, 0 instances).
<!-- END GENERATED: xm asks ocsf -->

**How the asks fit together.**

1. **Promote the two proposed AI event classes to ratified:** **AI Agent Activity (9001)** and **AI Delegation Activity (9002)**. **The boundary against tool invocation, stated so that adjacent proposals arrive reconciled rather than adjudicated at OCSF:** a per-invocation tool record rides **API Activity (6003) with `ai_tool`** ([ocsf-schema#1729](https://github.com/ocsf/ocsf-schema/pull/1729)), while **9001** carries agent-originated **control-plane lifecycle** events. A dedicated per-invocation class, proposed separately from CoSAI WS4's containment work, is compatible with that split provided it joins on `ai_tool`'s `transaction_uid` rather than restating its fields; three artifacts adjacent to "what the agent did" otherwise read as overlapping asks.
2. **Extend the existing `ai_operation` profile** (which already carries `ai_agent`, `ai_model`, `delegation`, `message_context`, and, once ocsf-schema#1704 merges, `ai_stop_reason_id`) so that it represents the [classification summary](CoSAI-AI-Telemetry-RFC.md#6-field-catalogue) using **class- and activity-specific applicability**: common correlation attributes are required at profile level, while the remaining MUST fields are required when their defining operation or event applies. SHOULD/MAY fields remain recommended/optional within the same applicable scope.
3. **Add or extend AI-specific objects:** extend `message_context` (content hashes, redaction flags, system prompt) and `delegation` (scope, constraints, lifecycle state); land `ai_tool`/`mcp` (ocsf-schema#1729); add `ai_guardrail`, `ai_memory`, `ai_retrieval`, `runtime_attestation`, `ai_asset`, `ai_bom`, `ai_authorization`, `ai_taint`, `ai_approval`. **Every hash-bearing attribute added by this appendix carries or references a canonicalization declaration, per [§2.8](#28-context-propagation-sampling--privacy-three-operational-traps)**: the content hashes on `message_context`, the tool-definition digest, attachment hashes, and the `ai_bom` signature, not only `attestation.fingerprint`. Without it the same silent degradation from "verify" to "trust the producer" reappears one field over.
4. **Add AI-specific enums:** `trust_level`, `autonomy_level` (L1 to L5), `tool_trust_boundary`, `memory_provenance`, `enforcement_decision` (allow / deny, the terminal verdict, with an `is_modified` flag for allow-after-modification and a machine-readable code on deny; a fail-closed enforcement failure is a deny coded as such, and **budget-exceeded / aggregate-threshold** is a deny code of its own, so that a denial on accumulated consumption is queryable as distinct from one on the operation's own payload), `enforcement_step_action` (allowed / denied / modified_payload / modified_extensions / deny_suppressed / aborted / error, one per plugin or rule that ran, so that a suppressed deny is queryable), `enforcement_failure_mode` (fail-open / fail-closed), `mcp_primitive` (tool / resource / prompt / sampling / elicitation / roots), `trigger_type` (user-initiated / autonomous), **`attribute_source`** (idp / pdp / enforcement-state / platform / self-asserted), **`taint_scope`** (session / message), **`approval_status`** (pending / resolved / expired / bypassed).

### 1.5 What it contributes

**ATLAS technique tagging needs no OCSF change.** Detection Finding's `attacks[]` is already documented as compatible with MITRE ATLAS tactics, techniques and sub-techniques, and `attack.version` carries the matrix version. The [ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping) is portable today; this document supplies the producer guidance (populate `attacks[].technique.uid` with `AML.Txxxx`) rather than an ask.

The `record_integrity` profile and the `attestation` object on the base event carry **Event Sequence Continuity** with no new schema, and `ai_agent` already separates a stable agent identifier from a restart-sensitive instance identifier.

### 1.6 Divergences and open items

**Agent attribution rides `ai_agent`, not an actor type.** OWASP AOS's OCSF binding currently represents the agent through the `actor.user` type enum with an "Other" override and a free-text `"AI Agent"`: a documented workaround, and one that types the agent as a kind of user. The OCSF `actor` object has no type of its own. The correct representation exists: `ai_agent` on the `ai_operation` profile for which agent acted, and `delegation` for whose authority it acted under. The change is on the AOS side (see [§4.5](#45-what-this-document-contributes-back-to-aos)): migrate the binding to `ai_agent` + `delegation`.

On the agentic classes: Ratify an **AI agent activity** class for agent-originated control-plane events (tracking [ocsf-schema#1640](https://github.com/ocsf/ocsf-schema/issues/1640); the OCSF working group agreed 2026-09-04 that Application Lifecycle is not the home); extend the `ai_operation` profile with the run / turn / step identifiers, action type, trigger type

---

## 2. OpenTelemetry

### 2.1 What it is, and the version mapped

<!-- BEGIN GENERATED: xm pin otel -->
<!-- END GENERATED: xm pin otel -->

This appendix covers the OpenTelemetry emission side of the standards bridge; [§1](#1-ocsf) covers OCSF consumption. AITF carries the interim binding between them, so the proposals should be sequenced together.

**Scope of the ask.** OpenTelemetry is not a security telemetry framework and should not become one. Its GenAI conventions are shaped by observability concerns, latency, cost, token accounting, evaluation quality, and that is the right centre of gravity. The argument here is narrower and, in this document's view, uncontroversial: **OTel's ubiquity means it is where AI instrumentation is being written**, so the subset of security-relevant fields that map cleanly onto its existing model should be added to the specification, so that deployments already running OTel get them by default rather than by bespoke effort. Fields that do not map cleanly, such as authorization decisions, delegation chains, and information-flow labels, are noted as such and left to OCSF and the [AOS](#4-owasp-aos-cross-reference) / [CPEX](#5-cpex-cross-reference) surfaces. **This appendix asks OTel to cover what OTel is already shaped to cover, and no more.**

> **Convention status.** The GenAI conventions **moved** out of the main `open-telemetry/semantic-conventions` repository into a dedicated **`open-telemetry/semantic-conventions-genai`** repository; the attributes still listed in the main registry are marked *Deprecated* to reflect that relocation, not abandonment. Every convention cited below carries **Status: Development**: none is stable, which is precisely why this is the moment to contribute.

The conventions are richer than is commonly assumed, and several fields in fact have a natural OTel home already.

- **Spans.** `chat`, `text_completion`, `embeddings`, `generate_content`, `execute_tool`, `create_agent`, `invoke_agent` (client and internal variants), `invoke_workflow`, and a **`plan`** span, discriminated by `gen_ai.operation.name`.
- **Core attributes.** `gen_ai.provider.name`; `gen_ai.agent.id` / `.name` / `.description` / `.version`; `gen_ai.conversation.id`; `gen_ai.workflow.name`; `gen_ai.request.model` and the full decoding set (`temperature`, `top_p`, `top_k`, `max_tokens`, `stop_sequences`, `seed`, `frequency_penalty`, `presence_penalty`, `choice.count`, `stream`); `gen_ai.response.id` / `.model` / `.finish_reasons`; `gen_ai.usage.input_tokens` / `.output_tokens` / `.reasoning.output_tokens` / `.cache_read.input_tokens` / `.cache_write.input_tokens`.
- **Content and definitions.** `gen_ai.input.messages`, `gen_ai.output.messages`, **`gen_ai.system_instructions`**, **`gen_ai.tool.definitions`**, `gen_ai.tool.name` / `.description` / `.type` / `.call.id` / `.call.arguments` / `.call.result`, `gen_ai.output.type`, `gen_ai.prompt.name`.
- **Retrieval.** **`gen_ai.retrieval.query.text`**, **`gen_ai.retrieval.documents`**, `gen_ai.data_source.id`, `gen_ai.embeddings.dimension.count`.
- **Memory.** A **`gen_ai.memory.*`** namespace: `store.id`, `record.id`, `record.count`, `query.text`, `records`, with a `MemoryRecord` schema (`content`, `id`, `metadata`, `score`); seven memory operations on `gen_ai.operation.name` (`create_memory`, `create_memory_store`, `delete_memory`, `delete_memory_store`, `search_memory`, `update_memory`, `upsert_memory`); and a **`gen_ai.memory.client`** span, already implemented by `aws-bedrock-agentcore` and `google-adk`.
- **Evaluation.** A `gen_ai.evaluation.result` event with `gen_ai.evaluation.name`, `.score.value`, `.score.label`, `.explanation`.
- **Metrics.** `gen_ai.client.operation.duration`, `gen_ai.client.token.usage`, `gen_ai.client.operation.time_to_first_chunk` / `.time_per_output_chunk`, `gen_ai.execute_tool.duration`, **`gen_ai.invoke_agent.duration` / `.inference_calls` / `.tool_calls`**, `gen_ai.invoke_workflow.duration`, `gen_ai.server.request.duration` / `.time_to_first_token` / `.time_per_output_token`.
- **MCP.** A distinct **`mcp.*`** namespace: `mcp.method.name`, `mcp.protocol.version`, `mcp.resource.uri`, `mcp.session.id`, plus `mcp.client.operation.duration`, `mcp.server.operation.duration`, and client/server `session.duration` metrics.

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
| [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) | MUST | none |  | No surface attribute. XM names the gap and proposes no change; decide an ask or record why none. | [otel_entry_point](#ask-otel-entry-point) |
| [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) | MUST | covered | `gen_ai.system_instructions` | Gated behind content-capture opt-in. | [otel_hash_only_capture](#ask-otel-hash-only-capture) |
| [Model Name + Version](Telemetry-Attack-Detection-Addendum.md#f-model-name-version) | MUST | covered | `gen_ai.request.model`, `gen_ai.response.model` |  |  |
| [Inference Parameters](Telemetry-Attack-Detection-Addendum.md#f-inference-parameters) | MUST | covered | `gen_ai.request.temperature`, `gen_ai.request.top_p`, `gen_ai.request.max_tokens`, `gen_ai.request.stop_sequences`, `gen_ai.request.seed` |  |  |
| [Input / Output Token Counts](Telemetry-Attack-Detection-Addendum.md#f-input-output-token-counts) | MUST | covered | `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.client.token.usage` |  |  |
| [LLM Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-llm-error-exception) | MUST | covered | `error.type` |  |  |
| [Trace Context (propagated)](Telemetry-Attack-Detection-Addendum.md#f-trace-context-propagated) | MUST | covered |  | OpenTelemetry trace context (W3C traceparent) is core to the specification. |  |
| [Stop Reason](Telemetry-Attack-Detection-Addendum.md#f-stop-reason) | MUST | covered | `gen_ai.response.finish_reasons` |  |  |
| [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) | SHOULD | none |  | No autonomy level. No ask proposed; decide one or record why none. |  |
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
| [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) | MUST | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Instrumentation Coverage / Hook Attestation](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) | MUST | none |  | No instrumentation-coverage representation. | [otel_hook_coverage](#ask-otel-hook-coverage) |
| [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode) | MUST | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) | MUST | none |  | No record that an enforcement point rewrote a payload. | [otel_security_guardrail](#ask-otel-security-guardrail) |
| [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) | MUST | none |  | No obfuscation flag or decoded form. | [otel_obfuscation](#ask-otel-obfuscation) |
| [Observation / Thought (reasoning trace)](Telemetry-Attack-Detection-Addendum.md#f-observation-thought-reasoning-trace) | SHOULD | partial | `gen_ai.usage.reasoning.output_tokens` | A count of reasoning tokens, not the trace. No ask proposed; decide one or record why none. |  |
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
| [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-tool-error-exception) | MUST | covered | `error.type` |  |  |
| [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) | MUST | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). | [otel_authorization_reference](#ask-otel-authorization-reference) |
| [Tool Selection Rationale](Telemetry-Attack-Detection-Addendum.md#f-tool-selection-rationale) | SHOULD | none |  | No self-asserted rationale. No ask proposed; decide one or record why none. |  |
| [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#f-human-approval-elicitation-event) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#f-tool-acl-required-scope) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#f-session-taint-labels-information-flow-decisions) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Backend / Route Restriction Decision](Telemetry-Attack-Detection-Addendum.md#f-backend-route-restriction-decision) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Mediation Coverage & Bypass Path](Telemetry-Attack-Detection-Addendum.md#f-mediation-coverage-bypass-path) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Tool ID](Telemetry-Attack-Detection-Addendum.md#f-tool-id) | MAY | none |  | Tool name and call ID only; no implementation ID across servers. A MAY field; no ask. |  |
| [Tool Privacy Classification](Telemetry-Attack-Detection-Addendum.md#f-tool-privacy-classification) | MAY | none |  | No data classification for a tool. A MAY field; no ask. |  |
| [Policy Reason Code](Telemetry-Attack-Detection-Addendum.md#f-policy-reason-code) | MAY | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |

**RFC §6.4 Memory and retrieval**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Memory Write Event](Telemetry-Attack-Detection-Addendum.md#f-memory-write-event) | MUST | covered | `gen_ai.memory.store.id`, `gen_ai.memory.record.id`, `gen_ai.operation.name` |  |  |
| [Memory Read / Injection Event](Telemetry-Attack-Detection-Addendum.md#f-memory-read-injection-event) | MUST | covered | `gen_ai.memory.query.text`, `gen_ai.memory.records` |  |  |
| [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#f-memory-provenance-source) | MUST | none |  | No provenance attribute in the gen_ai registry. | [otel_memory_provenance_footprint](#ask-otel-memory-provenance-footprint) |
| [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#f-memory-footprint-growth) | MUST | none |  | No footprint attribute in the gen_ai registry. | [otel_memory_provenance_footprint](#ask-otel-memory-provenance-footprint) |
| [Retrieval Event](Telemetry-Attack-Detection-Addendum.md#f-retrieval-event) | MUST | covered | `gen_ai.retrieval.query.text`, `gen_ai.retrieval.documents`, `gen_ai.data_source.id` |  |  |
| [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-source-provenance) | MUST | none |  | No per-item source or provenance. | [otel_retrieval_provenance](#ask-otel-retrieval-provenance) |
| [Memory Integrity / Poisoning Signal](Telemetry-Attack-Detection-Addendum.md#f-memory-integrity-poisoning-signal) | SHOULD | none |  | No integrity or poisoning signal. No ask proposed; decide one or record why none. |  |
| [Memory Write Rationale](Telemetry-Attack-Detection-Addendum.md#f-memory-write-rationale) | SHOULD | none |  | No self-asserted rationale. No ask proposed; decide one or record why none. |  |
| [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) | SHOULD | none |  | No per-item integrity signal or freshness. | [otel_retrieval_provenance](#ask-otel-retrieval-provenance) |
| [Declared Memory Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-memory-configuration) | MAY | partial | `gen_ai.memory.store.id` | Store identity only; no limits or retrieval settings. No ask proposed; decide one or record why none. |  |
| [Declared Knowledge-Source Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-knowledge-source-configuration) | MAY | partial | `gen_ai.data_source.id` | Data-source identity only; no schema or search parameters. No ask proposed; decide one or record why none. |  |

**RFC §6.5 Orchestration**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) | MUST | none |  | No inter-agent message attributes. | [otel_inter_agent_messaging](#ask-otel-inter-agent-messaging) |
| [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) | MUST | none |  | No background-task or termination-condition signal. | [otel_trigger](#ask-otel-trigger) |
| [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) | MUST | partial |  | Agent metrics count calls; no limit or termination semantics. | [otel_run_budget](#ask-otel-run-budget) |
| [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) | MUST | partial | `gen_ai.client.token.usage` | No per-run budget or threshold. | [otel_run_budget](#ask-otel-run-budget) |
| [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#f-task-intent-declaration) | SHOULD | none |  | No declared purpose for the run. No ask proposed; decide one or record why none. |  |
| [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) | SHOULD | none |  | No A2A conventions. No ask proposed; decide one or record why none. |  |
| [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#f-peer-agent-card-descriptor) | SHOULD | partial | `gen_ai.agent.name`, `gen_ai.agent.id`, `gen_ai.agent.description`, `gen_ai.agent.version` | Describes the agent a span is about; no counterparty descriptor, change or verification. No ask proposed; decide one or record why none. |  |
| [Protocol Envelope Capture](Telemetry-Attack-Detection-Addendum.md#f-protocol-envelope-capture) | MAY | none |  | No raw protocol envelope. A MAY field; no ask. |  |

**RFC §6.6 Identity, provenance and inventory**

| Field | Tier | Coverage | Carried by | Gap or note | Asks |
| :------------------ | :---- | :------- | :------------------ | :------------------ | :---------- |
| [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) | MUST | none |  | No capability-change event. | [otel_capability_change](#ask-otel-capability-change) |
| [Identities Used (per hop)](Telemetry-Attack-Detection-Addendum.md#f-identities-used-per-hop) | MUST | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#f-verified-vs-displayed-identity) | MUST | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Originating Principal (on-behalf-of)](Telemetry-Attack-Detection-Addendum.md#f-originating-principal-on-behalf-of) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Granted Authorizations / Scope](Telemetry-Attack-Detection-Addendum.md#f-granted-authorizations-scope) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Resource Indicators + Constraints](Telemetry-Attack-Detection-Addendum.md#f-resource-indicators-constraints) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Credential Minting & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#f-credential-minting-scope-narrowing-check) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#f-trust-domain-crossing-delegation-depth) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#f-runtime-credential-attestation) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#f-lifecycle-state) | SHOULD | out of scope |  | An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3). |  |
| [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) | SHOULD | partial | `gen_ai.agent.version` | Agent version only; no tool or framework version. No ask proposed; decide one or record why none. |  |
| [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) | SHOULD | partial | `vcs.repository.url.full`, `vcs.ref.head.revision` | Version-control attributes exist for CI/CD telemetry, not for tool and agent code. No ask proposed; decide one or record why none. |  |
| [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) | SHOULD | none |  | No BOM reference. | [otel_capability_change](#ask-otel-capability-change) |
| [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) | SHOULD | none |  | No dependency graph. | [otel_capability_change](#ask-otel-capability-change) |
| [Inventory Attestation Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) | SHOULD | none |  | No inventory signature. | [otel_capability_change](#ask-otel-capability-change) |
| [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#f-event-sequence-continuity) | SHOULD | none |  | No per-session sequence number or hash chain. No ask proposed; decide one or record why none. |  |
| [Description](Telemetry-Attack-Detection-Addendum.md#f-tool-description) | MAY | covered | `gen_ai.tool.description` |  |  |
| [Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#f-tool-status) | MAY | none |  | No reachability status for a tool. A MAY field; no ask. |  |
| [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#f-creator-id-oncall-creation-update-dates) | MAY | none |  | No ownership or change dates. A MAY field; no ask. |  |
| [Surfaces Supported](Telemetry-Attack-Detection-Addendum.md#f-surfaces-supported) | MAY | none |  | No per-tool exposure map. A MAY field; no ask. |  |
| [Fleet counts](Telemetry-Attack-Detection-Addendum.md#f-fleet-counts) | MAY | none |  | Fleet aggregates are derived. Derived from per-event records; no ask. |  |
<!-- END GENERATED: xm correspondence otel -->

### 2.3 Gaps

The table states each gap. The security-specific ones are where the conventions were never shaped to go: trust provenance on input, guardrail verdicts, memory and retrieval provenance, and the run, turn and step identifiers between a conversation and a span.

### 2.4 Asks

Ordered by ratio of security value to specification cost. Every item is scoped to something OTel already models, and the two clusters that are *not* a natural fit are named as such rather than pushed.

<!-- BEGIN GENERATED: xm asks otel -->
<a id="ask-otel-hash-only-capture"></a>**`otel_hash_only_capture`** (proposed). Ensure a hash-only content-capture mode exists for message content. *Closes:* [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) (MUST, 3 instances), [Model Input](Telemetry-Attack-Detection-Addendum.md#f-model-input) (MUST, 15 instances) and [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#f-response-model-output) (MUST, 9 instances).

<a id="ask-otel-inter-agent-messaging"></a>**`otel_inter_agent_messaging`** (proposed). Add inter-agent messaging attributes. *Closes:* [Action Type](Telemetry-Attack-Detection-Addendum.md#f-action-type) (MUST, 6 instances) and [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) (MUST, 7 instances).

<a id="ask-otel-security-guardrail"></a>**`otel_security_guardrail`** (proposed). Extend the evaluation event for security use (blocked or allowed, guardrail type, threat technique), or add gen_ai.guardrail.*. *Closes:* [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-input-verdict) (MUST, 6 instances), [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-output-verdict) (MUST, 4 instances), [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) (MUST, on a dependency) and [Threat Classification / ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#f-threat-classification-atlas-technique-tag) (MAY, 0 instances). The evaluation event already carries name, score, label, and explanation, the right shape for a classifier verdict. What it lacks is the security semantics: a **blocked / allowed** outcome, a guardrail **type**, and a **threat technique** reference. Reusing evaluation avoids a parallel namespace; the alternative is a dedicated `gen_ai.guardrail.*`. Either way, this is the field that makes classifier *bypass* detectable (`TA-01`).

<a id="ask-otel-egress-pattern"></a>**`otel_egress_pattern`** (proposed). Document correlating model output to its destination through the HTTP and network conventions on the child span. *Closes:* [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination) (MUST, 10 instances).

<a id="ask-otel-trust-level"></a>**`otel_trust_level`** (proposed). Add gen_ai.input.trust_level on message parts (trusted or untrusted, crossed with instruction or data). *Closes:* [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification) (MUST, 10 instances). `gen_ai.input.trust_level` (trusted-instruction / trusted-data / untrusted-instruction / untrusted-data), crossing origin authority with whether the segment was consumed as instruction or as data. **`untrusted-instruction` is the attack state**: `TA-01` is untrusted email content promoted to instruction. The enum carries provenance only; detector verdicts belong on the **Guardrail (Input) Verdict** (AD §1.2). This is the single highest-value addition and the one with no current analogue anywhere in the conventions. It is cheap (an enum on an existing structure) and it is the field the CoSAI Risk Map treats as the core agentic control (AD §1.2).

<a id="ask-otel-authorization-reference"></a>**`otel_authorization_reference`** (proposed). Let a span reference an authorization decision by ID, so OpenTelemetry and OCSF records join at query time. *Closes:* [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) (MUST, 9 instances).

<a id="ask-otel-refusal"></a>**`otel_refusal`** (proposed). Add a refusal status and reason distinct from finish reasons, so a refusal that ends normally is still visible. *Closes:* [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) (MUST, 9 instances).

<a id="ask-otel-run-budget"></a>**`otel_run_budget`** (proposed). Add per-run budget and threshold semantics; document security use of the loop metrics. *Closes:* [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) (MUST, 5 instances) and [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) (MUST, 4 instances).

<a id="ask-otel-retrieval-provenance"></a>**`otel_retrieval_provenance`** (proposed). Add per-document source, owner, trust level and last-modified attributes to retrieval documents. *Closes:* [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-source-provenance) (MUST, 6 instances) and [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) (SHOULD, 2 instances). `gen_ai.retrieval.documents` exists; per-document **source, owner, trust level, and last-modified** do not, and `TA-09` turns specifically on recently-modified retrievable content.

<a id="ask-otel-trigger"></a>**`otel_trigger`** (proposed). Add gen_ai.trigger.type (user_initiated or autonomous) and gen_ai.trigger.event; scheduled and self-triggered runs use it. *Closes:* [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#f-trigger-type-source-event) (MUST, 5 instances) and [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) (MUST, 3 instances). Whether a run was user-initiated or autonomous, and what event started it. `TA-01` is zero-click; this is the first filter of any injection hunt.

<a id="ask-otel-capability-change"></a>**`otel_capability_change`** (proposed). Add a capability-change event; reference an external BOM by URI or digest. *Closes:* [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) (MUST, 4 instances), [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) (SHOULD, 2 instances), [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) (SHOULD, 1 instances) and [Inventory Attestation Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) (SHOULD, 0 instances).

<a id="ask-otel-tool-digest-mcp-primitive"></a>**`otel_tool_digest_mcp_primitive`** (proposed). Add gen_ai.tool.definitions.hash and an mcp.primitive value set (tool, resource, prompt, sampling, elicitation, roots). *Closes:* [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#f-tool-definition-digest) (MUST, 2 instances) and [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive) (MUST, 5 instances). `gen_ai.tool.definitions` and `mcp.method.name` already carry the raw material; a stable hash attribute and an explicit primitive value set make definition drift and non-tool MCP surfaces queryable (AD §1.3).

<a id="ask-otel-input-part-source"></a>**`otel_input_part_source`** (proposed). Add a per-part source on input messages (the surface, tool, agent or document it came from), beside the proposed gen_ai.input.trust_level. *Closes:* [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#f-input-source-channel) (MUST, 6 instances).

<a id="ask-otel-memory-provenance-footprint"></a>**`otel_memory_provenance_footprint`** (proposed). Add provenance and footprint attributes to gen_ai.memory.*. *Closes:* [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#f-memory-provenance-source) (MUST, 4 instances) and [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#f-memory-footprint-growth) (MUST, 2 instances). `gen_ai.memory.*` carries store and record identity, query text, record count, seven memory operations and a `gen_ai.memory.client` span ([§2.1](#21-what-it-is-and-the-version-mapped)). Operation and item identity are therefore covered; **provenance** and **footprint** are not, and neither appears anywhere in the `gen_ai` registry. Memory remains a MUST cluster here (AD §1.4), with `IR-02` and `IR-05` as direct grounding and `AOC-05` for footprint.

<a id="ask-otel-turn-step-ids"></a>**`otel_turn_step_ids`** (proposed). Add gen_ai.turn.id and gen_ai.step.id. *Closes:* [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#f-session-turn-step-ids) (MUST, 5 instances). `gen_ai.conversation.id` and `gen_ai.workflow.name` exist; the intermediate levels do not. `TA-08` and `IR-01` are across-turn patterns (AD §1.1).

<a id="ask-otel-attachment-identity"></a>**`otel_attachment_identity`** (proposed). Add attachment identity (name, size, hash) on message parts. *Closes:* [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) (MUST, 3 instances). : name, size, and hash. `AOC-12` is an image/OCR injection; `AOC-05` is attachment flooding.

<a id="ask-otel-citations"></a>**`otel_citations`** (proposed). Add citation attributes on output messages with a resolution flag against retrieval. *Closes:* [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#f-citations-source-attribution) (MUST, 3 instances).

<a id="ask-otel-entry-point"></a>**`otel_entry_point`** (proposed). Add an entry-point attribute: the surface a request arrived through and whether it is internal or external. *Closes:* [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) (MUST, 3 instances).

<a id="ask-otel-execution-environment"></a>**`otel_execution_environment`** (proposed). Add execution-environment attributes (sandbox, runtime, egress policy) for tool execution. *Closes:* [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#f-execution-environment-sandbox) (MUST, 3 instances).

<a id="ask-otel-obfuscation"></a>**`otel_obfuscation`** (proposed). Add obfuscation indicators on input (detected, encodings, decoded hash), aligned with AITF security.obfuscation.*. *Closes:* [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) (MUST, 2 instances).

<a id="ask-otel-tool-trust-boundary"></a>**`otel_tool_trust_boundary`** (proposed). Extend gen_ai.tool.type, or add a trust-boundary attribute, to distinguish MCP, internal, direct-storage and code-execution tools. *Closes:* [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#f-tool-type-trust-boundary) (MUST, 2 instances).

<a id="ask-otel-hook-coverage"></a>**`otel_hook_coverage`** (proposed). Record instrumentation hook coverage as a resource attribute. *Closes:* [Instrumentation Coverage / Hook Attestation](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) (MUST, on a dependency).

<a id="ask-otel-run-id"></a>**`otel_run_id`** (proposed). Add gen_ai.run.id, as AITF defines it; gen_ai.workflow.name names the workflow, not the run. *Closes:* [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#f-workflow-run-id) (MUST, on a dependency).

<a id="ask-otel-model-provenance"></a>**`otel_model_provenance`** (proposed). Add gen_ai.model.hash, gen_ai.model.signature and gen_ai.model.source. *Closes:* [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) (SHOULD, 0 instances). : hash, signature, source, completing the supply-chain story that `gen_ai.request.model` starts.
<!-- END GENERATED: xm asks otel -->

### 2.5 What it contributes

Three existing GenAI attributes already close gaps this document had left open. `gen_ai.system_instructions` gives **System Prompt** (AD §1.1) a home. `gen_ai.tool.definitions` gives **Tool Definition Digest** (AD §1.3) one; the raw material for a digest is already in scope, and only the *hash-and-compare* is missing. And `gen_ai.invoke_agent.tool_calls` / `.inference_calls` are already the shape of **Loop / Step-Count Signal** (AD §1.5) and part of **Resource-Consumption Aggregate** (AD §1.5), as metrics rather than attributes.

### 2.6 Divergences and open items

**Two clusters this document deliberately does *not* ask OTel to adopt.** **Identity and delegation** (AD §1.6) and **policy enforcement** (AD §1.3) are authorization-domain concerns with mature homes elsewhere, OCSF Authentication, and the proposed `ai_authorization` / `ai_taint` / `ai_approval` objects in [§1.4](#14-asks). Pushing them into OTel would duplicate schema and invite drift. The one exception worth raising is **correlation**: an OTel span should be able to reference an authorization decision by ID so the two layers join at query time, which is a single attribute rather than a namespace. Two identity facts do have OTel homes and should be emitted there rather than in a private namespace: the originating principal as `audit.actor.id` / `audit.actor.type` (the OpenTelemetry audit data model draft, where it is MUST-level) and the acting agent as `gen_ai.agent.id` / `gen_ai.agent.name`. The OCSF transform is `actor.user.uid` and `ai_agent.uid` respectively.

### 2.7 Signal selection: traces, events/logs, metrics


OTel has three signal types and OCSF has one event model, so this guidance has no counterpart in [§1](#1-ocsf), but getting it wrong is the most common way security telemetry becomes unusable or unaffordable.

| Signal | Use for | Fields from this document |
| :-------- | :-------------------------- | :------------------------------------------------------------------ |
| **Span attributes** | Low-cardinality identifiers and the execution skeleton | Agent/instance/run/session/turn/step IDs, action type, execution status, model and provider, tool name and type, trigger type, trust level, decision references |
| **Events / logs** | Content and anything high-cardinality, large, or privacy-bearing | Prompts, responses, system instructions, tool arguments and results, memory operations, retrieved documents, citations, guardrail verdicts, capability-change events |
| **Metrics** | Aggregates, budgets, and rate-based detections | Token usage, loop and step counts, tool-call rates, resource aggregates, guardrail block rates, deny rates |

Signal choice matters. The following rules correct mistakes that show up often when GenAI instrumentation is reused for security:

- **Never put content in span attributes.** Prompts, responses, and tool results are unbounded in size and often contain PII. OTel already models them as event bodies; keep them there. A span attribute carrying a full prompt breaks cardinality limits and leaks into every trace backend that samples the span.
- **Emit detection-relevant aggregates as metrics, not as derived queries.** Loop counts and token budgets (AD §1.5) are cheap as metrics and expensive as trace aggregations, and metrics survive sampling, which traces may not. With one qualification: a metric does not survive *with* the action record, so where an aggregate is what a decision turned on, the consumed and remaining figures belong on the decision as well (AD §§1.3 and 1.5). The metric serves detection; the record on the action is what can be audited afterwards.
- **Cross-reference rather than duplicate.** A guardrail verdict event should carry the span and trace IDs, not a copy of the prompt it evaluated.

### 2.8 Context propagation, sampling & privacy: three operational traps


**Propagation is solved for MCP, and the mechanism should be adopted deliberately.** The MCP conventions specify that instrumentations SHOULD inject context into the MCP request **`params._meta`** property bag, with `traceparent`, `tracestate`, and `baggage` written unprefixed per **SEP-414**, and that the receiver uses the extracted context as the remote parent. That is exactly the mechanism **Trace Context (propagated)** (AD §1.1) requires, and it means cross-hop correlation over MCP is a matter of configuration rather than invention. Two cautions. First, HTTP-level propagation covers the HTTP request but **not** individual messages within a streaming request/response, a gap that matters for long-lived agent sessions. Second, and more important for security: **`baggage` crosses the trust boundary.** It is attacker-influenceable in exactly the way AD §1.3's provenance rule describes, so baggage may carry correlation identifiers but **must never carry trust levels, authorization decisions, taint labels, or identity claims**. Those come from the enforcement point, not from the wire.

**Sampling is the trap most likely to silently defeat this entire field set.** OTel's default is head-based sampling at some fraction of traces. Applied to security telemetry, that means *most attacks are simply not recorded*. Worse, the sample is drawn without regard to whether an event is security-relevant, so a guardrail block has the same chance of being discarded as a routine completion. The three requirements that follow (100% retention of security-relevant events, security relevance as a tail-sampling predicate, and recording the sampling configuration itself) are **normative** and stated in [RFC §5](CoSAI-AI-Telemetry-RFC.md#5-conformance). The rationale is that discarding a block or a denial is the same failure mode as fail-open enforcement ([AD §1.2](Telemetry-Attack-Detection-Addendum.md#12-content-trust-verdicts-and-their-availability)), and deserves the same treatment.

**Privacy: content capture is opt-in, and that default is correct.** GenAI instrumentations gate message content behind an explicit capture setting, which aligns with the content-hash requirement in [RFC §5](CoSAI-AI-Telemetry-RFC.md#5-conformance). The gap is that capture is close to binary (on or off) where security work needs a **middle setting**: hashes and classifications without raw content, so that correlation (same payload across many sessions, same attachment hash) survives even where raw capture is prohibited. That is the ask [`otel_hash_only_capture`](#ask-otel-hash-only-capture), the companion of [`otel_trust_level`](#ask-otel-trust-level), and it is the OTel expression of this document's **hash-first** principle. The OTel Collector is also the correct place to run redaction, since it applies uniformly across every instrumented service rather than per-library.

**Canonicalization is a prerequisite for hash-first, and it must be declared.** A content hash or an event fingerprint correlates across producers only if every producer hashes the same logical bytes. The OpenTelemetry audit data model draft mandates RFC 8785 (JCS); OCSF's `attestation.fingerprint` instead *declares* its serialization (`serialization_id` plus a free-text `serialization`) so that non-JCS producers can declare it; CPEX's audit seam ([cpex#166](https://github.com/contextforge-org/cpex/pull/166)) hashes a sorted-key JSON that is documented as not RFC 8785. Two conformant implementations with different canonicalizations produce different digests for the same event, and the integrity claim degrades silently from "verify" to "trust the producer". Requirement: a producer that emits a hash of content or of an event MUST declare the canonicalization used (JCS by default), and consumers MUST NOT compare digests across producers whose declared canonicalizations differ. OCSF carries the declaration on `attestation.fingerprint`; the OTel-side ask is a single `audit.integrity.canonicalization` attribute.

---

## 3. AITF

### 3.1 What it is, and the version mapped

<!-- BEGIN GENERATED: xm pin aitf -->
<!-- END GENERATED: xm pin aitf -->

AITF, the AI Telemetry Framework, was donated to CoSAI Workstream 2. It carries these fields as OpenTelemetry attributes today and emits them into OCSF ahead of formal ratification, so adopters are not blocked on either standards body. AITF v0.4 closed the 27 gaps RFC v0.4 recorded for it, adding 390 attributes ([`aitf/AITF_gaps.md`](aitf/AITF_gaps.md)).

> **Note on the identifier mapping.** AD §1.1 distinguishes five levels (instance → run → session → turn → step). AITF maps the runtime instance to `gen_ai.agent.id` and the session to `gen_ai.conversation.id`; the run maps to the trace ID. AITF has no dedicated turn attribute today. Step identity is the OTel `span_id`, with `gen_ai.agent.step.index` recording its order within the agent sequence; see [§4.4](#44-what-this-implies-for-opentelemetry-aitf-and-ocsf).

### 3.2 Correspondence

<!-- BEGIN GENERATED: xm correspondence aitf -->
**RFC §6.1 Identifiers, trace context and model identity**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Agent Name](Telemetry-Attack-Detection-Addendum.md#f-agent-name) | MUST | covered | `gen_ai.agent.name`, `asset.*` |  |
| [Agent (Runtime) Instance ID](Telemetry-Attack-Detection-Addendum.md#f-agent-runtime-instance-id) | MUST | covered | `gen_ai.agent.id` |  |
| [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#f-workflow-run-id) | MUST | covered |  | trace id / run attr, *see note below* |
| [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#f-session-turn-step-ids) | MUST | covered | `gen_ai.turn.*`, `gen_ai.conversation.id`, `gen_ai.agent.step.index` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `gen_ai.conversation.id`; turn attr; OTel `span_id` + `gen_ai.agent.step.index` Trace and span identifiers come from OpenTelemetry trace context (W3C traceparent). |
| [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#f-trigger-type-source-event) | MUST | covered | `gen_ai.trigger.*`, `gen_ai.agent.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `gen_ai.agent.*` trigger attrs |
| [Action Type](Telemetry-Attack-Detection-Addendum.md#f-action-type) | MUST | covered | `gen_ai.agent.step.type` |  |
| [Execution Status](Telemetry-Attack-Detection-Addendum.md#f-execution-status) | MUST | covered | `error.type` | span status + `error.type` |
| [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) | MUST | partial | `gen_ai.*` | XM §4 cites a namespace only; AITF defines no attribute for this field at the pin. `gen_ai.*` (surface attr) |
| [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) | MUST | covered | `gen_ai.*` | `gen_ai.*` (system message / request) |
| [Model Name + Version](Telemetry-Attack-Detection-Addendum.md#f-model-name-version) | MUST | covered | `gen_ai.request.model`, `gen_ai.provider.name` |  |
| [Inference Parameters](Telemetry-Attack-Detection-Addendum.md#f-inference-parameters) | MUST | covered | `gen_ai.request.temperature`, `gen_ai.request.top_p`, `gen_ai.request.max_tokens`, `gen_ai.request.stop_sequences`, `gen_ai.request.seed` |  |
| [Input / Output Token Counts](Telemetry-Attack-Detection-Addendum.md#f-input-output-token-counts) | MUST | covered | `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `cost.*` |  |
| [LLM Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-llm-error-exception) | MUST | partial | `gen_ai.*`, `security.*` | XM §4 cites a namespace only; AITF defines no attribute for this field at the pin. `gen_ai.*` error + `security.*` |
| [Trace Context (propagated)](Telemetry-Attack-Detection-Addendum.md#f-trace-context-propagated) | MUST | covered |  | OTel `trace_id`/`span_id`, W3C `traceparent` Trace and span identifiers come from OpenTelemetry trace context (W3C traceparent). |
| [Stop Reason](Telemetry-Attack-Detection-Addendum.md#f-stop-reason) | MUST | covered | `gen_ai.response.finish_reasons` |  |
| [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) | SHOULD | covered | `gen_ai.agent.state` |  |
| [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) | SHOULD | covered | `supply_chain.model.hash`, `supply_chain.model.signed`, `supply_chain.model.source`, `supply_chain.ai_bom.*` |  |
| [Organization / Tenant ID](Telemetry-Attack-Detection-Addendum.md#f-organization-tenant-id) | SHOULD | covered | `asset.tenant.*`, `security.tenant.*`, `asset.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `asset.*` / resource attrs |
| [Provider / Endpoint Identity](Telemetry-Attack-Detection-Addendum.md#f-provider-endpoint-identity) | MAY | covered | `gen_ai.provider.name` |  |
| [Pre-Forward-Pass State Digest/Vector](Telemetry-Attack-Detection-Addendum.md#f-pre-forward-pass-state-digest-vector) | MAY | covered | `drift.*` |  |
| [Token Malformation / Context-Corruption Indicator](Telemetry-Attack-Detection-Addendum.md#f-token-malformation-context-corruption-indicator) | MAY | covered | `drift.*`, `quality.*` |  |

**RFC §6.2 Content, trust, verdicts and their availability**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Model Input](Telemetry-Attack-Detection-Addendum.md#f-model-input) | MUST | covered | `gen_ai.prompt` | `gen_ai.prompt` / input events |
| [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#f-input-source-channel) | MUST | partial | `gen_ai.*`, `rag.*`, `mcp.*` | XM §4 cites a namespace only; AITF defines no attribute for this field at the pin. `gen_ai.*` / `rag.*` / `mcp.*` source |
| [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification) | MUST | covered | `security.*` | `security.*` (trust/threat) |
| [Source host / IP + request metadata](Telemetry-Attack-Detection-Addendum.md#f-source-host-ip-request-metadata) | MUST | covered | `security.*` | `security.*` / resource attrs |
| [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-input-verdict) | MUST | covered | `security.guardrail.type`, `security.blocked`, `security.threat_type` |  |
| [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#f-response-model-output) | MUST | covered | `gen_ai.completion` |  |
| [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination) | MUST | covered | `gen_ai.tool.call.arguments`, `security.pii.*` |  |
| [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#f-citations-source-attribution) | MUST | covered | `rag.citation.*`, `rag.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `rag.*` (source) + output citation attrs |
| [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-output-verdict) | MUST | covered | `security.guardrail.*`, `security.pii.*` |  |
| [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) | MUST | partial | `gen_ai.response.finish_reasons`, `security.*` | XM §4 cites a namespace only; AITF defines no attribute for this field at the pin. |
| [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) | MUST | covered | `gen_ai.content.*`, `gen_ai.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `gen_ai.*` content-part attrs |
| [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) | MUST | covered | `security.attribute_source.*` | Closed in AITF v0.4 (AITF_gaps.md). |
| [Instrumentation Coverage / Hook Attestation](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) | MUST | covered | `asset.instrumentation.*`, `asset.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `asset.*` / instrumentation attrs |
| [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode) | MUST | covered | `security.enforcement.*`, `security.guardrail.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `security.guardrail.*` availability/latency |
| [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) | MUST | covered | `security.guardrail.modification.*`, `security.guardrail.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `security.guardrail.*` + modified/redacted flags |
| [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) | MUST | covered | `security.obfuscation.*`, `security.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `security.*` obfuscation / decoded-form attrs |
| [Observation / Thought (reasoning trace)](Telemetry-Attack-Detection-Addendum.md#f-observation-thought-reasoning-trace) | SHOULD | covered | `gen_ai.agent.step.thought` |  |
| [Threat Classification / ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#f-threat-classification-atlas-technique-tag) | MAY | covered | `security.threat_type`, `compliance.framework`, `compliance.control_id` |  |

**RFC §6.3 Tool calls and policy decisions**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#f-execution-environment-sandbox) | MUST | covered | `supply_chain.runtime.*`, `supply_chain.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `supply_chain.*` + runtime/sandbox attrs |
| [Tool Call I/O](Telemetry-Attack-Detection-Addendum.md#f-tool-call-io) | MUST | covered | `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result`, `mcp.tool.name` |  |
| [Tool Name](Telemetry-Attack-Detection-Addendum.md#f-tool-name) | MUST | covered | `mcp.tool.name` |  |
| [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#f-tool-type-trust-boundary) | MUST | partial | `mcp.*` | XM §4 cites a namespace only; AITF defines no attribute for this field at the pin. `mcp.*` vs internal |
| [Tool Execution ID](Telemetry-Attack-Detection-Addendum.md#f-tool-execution-id) | MUST | covered | `gen_ai.tool.call.id` |  |
| [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#f-tool-definition-digest) | MUST | covered | `mcp.tool.definition.*`, `mcp.tool.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `mcp.tool.*` schema/description hash |
| [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive) | MUST | covered | `mcp.primitive`, `mcp.server.name`, `mcp.server.version` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `mcp.server.name/version`, primitive attr |
| [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-tool-error-exception) | MUST | covered | `mcp.*`, `security.*` | `mcp.*` error, `security.*` |
| [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) | MUST | covered | `security.authorization.*`, `security.*`, `compliance.control_id` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `security.*` decision + `compliance.control_id` |
| [Tool Selection Rationale](Telemetry-Attack-Detection-Addendum.md#f-tool-selection-rationale) | SHOULD | covered | `gen_ai.agent.step.thought` | `gen_ai.agent.step.thought` (per-step) |
| [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#f-human-approval-elicitation-event) | SHOULD | covered | `identity.approval.*`, `identity.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `identity.*` approver + approval attrs |
| [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#f-tool-acl-required-scope) | SHOULD | covered | `identity.auth.scope_granted` |  |
| [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#f-session-taint-labels-information-flow-decisions) | SHOULD | covered | `security.taint.*`, `security.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `security.*` labels |
| [Backend / Route Restriction Decision](Telemetry-Attack-Detection-Addendum.md#f-backend-route-restriction-decision) | SHOULD | covered | `gen_ai.route.*`, `gen_ai.provider.name` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `gen_ai.provider.name` + routing constraint attrs |
| [Mediation Coverage & Bypass Path](Telemetry-Attack-Detection-Addendum.md#f-mediation-coverage-bypass-path) | SHOULD | covered | `security.mediation.*` | Closed in AITF v0.4 (AITF_gaps.md). |
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
| [Declared Memory Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-memory-configuration) | MAY | covered | `memory.config.*`, `memory.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `memory.*` config attrs |
| [Declared Knowledge-Source Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-knowledge-source-configuration) | MAY | covered | `rag.source.*`, `rag.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `rag.*` config/index attrs |

**RFC §6.5 Orchestration**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) | MUST | covered | `gen_ai.agent.*` | `gen_ai.agent.*`, delegation activity (OCSF 9002) |
| [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) | MUST | covered | `gen_ai.agent.next_action` | `gen_ai.agent.next_action` / step events |
| [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) | MUST | covered | `gen_ai.agent.session.turn_count`, `gen_ai.agent.step.index`, `agent.steps_per_session` | XM §4 names gen_ai.agent.turn_count; AITF defines gen_ai.agent.session.turn_count. |
| [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) | MUST | covered | `cost.*`, `gen_ai.usage.*` |  |
| [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#f-task-intent-declaration) | SHOULD | covered | `gen_ai.agent.next_action` |  |
| [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) | SHOULD | covered | `a2a.task.lifecycle.*`, `a2a.push.config.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: delegation activity (OCSF 9002); a2a attrs |
| [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#f-peer-agent-card-descriptor) | SHOULD | covered | `gen_ai.agent.peer.*`, `gen_ai.agent.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `gen_ai.agent.*` peer attrs |
| [Protocol Envelope Capture](Telemetry-Attack-Detection-Addendum.md#f-protocol-envelope-capture) | MAY | covered | `mcp.envelope.*`, `mcp.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `mcp.*` / a2a raw payload |

**RFC §6.6 Identity, provenance and inventory**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) | MUST | covered | `asset.capability.*`, `asset.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `asset.*` change events |
| [Identities Used (per hop)](Telemetry-Attack-Detection-Addendum.md#f-identities-used-per-hop) | MUST | covered | `identity.*` | `identity.*` (OCSF Authentication 3002) |
| [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#f-verified-vs-displayed-identity) | MUST | covered | `identity.auth.method`, `identity.auth.result` |  |
| [Originating Principal (on-behalf-of)](Telemetry-Attack-Detection-Addendum.md#f-originating-principal-on-behalf-of) | SHOULD | covered | `identity.*` |  |
| [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) | SHOULD | covered |  | delegation activity (OCSF 9002) |
| [Granted Authorizations / Scope](Telemetry-Attack-Detection-Addendum.md#f-granted-authorizations-scope) | SHOULD | covered | `identity.auth.scope_granted` |  |
| [Resource Indicators + Constraints](Telemetry-Attack-Detection-Addendum.md#f-resource-indicators-constraints) | SHOULD | covered | `identity.*`, `compliance.*` |  |
| [Credential Minting & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#f-credential-minting-scope-narrowing-check) | SHOULD | covered | `identity.credential.mint.*`, `identity.auth.scope_granted` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `identity.auth.scope_granted` + token-exchange attrs |
| [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#f-trust-domain-crossing-delegation-depth) | SHOULD | covered | `identity.boundary.*`, `identity.*` | Closed in AITF v0.4 (AITF_gaps.md). XM §4: `identity.*` domain/depth attrs |
| [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#f-runtime-credential-attestation) | SHOULD | covered | `identity.auth.method`, `identity.trust.method` | `identity.auth.method` (mTLS/SPIFFE/OAuth/DID-VC), `identity.trust.method` |
| [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#f-lifecycle-state) | SHOULD | covered | `identity.lifecycle.operation` |  |
| [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) | SHOULD | covered | `supply_chain.*`, `asset.*` |  |
| [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) | SHOULD | covered | `supply_chain.*`, `asset.*` |  |
| [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) | SHOULD | covered | `supply_chain.ai_bom.*` |  |
| [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) | SHOULD | covered | `supply_chain.ai_bom.*` | `supply_chain.ai_bom.*` (dependency edges) |
| [Inventory Attestation Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) | SHOULD | covered | `supply_chain.*` | `supply_chain.*` signature attrs |
| [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#f-event-sequence-continuity) | SHOULD | covered | `observability.sequence.*` | Closed in AITF v0.4 (AITF_gaps.md). |
| [Description](Telemetry-Attack-Detection-Addendum.md#f-tool-description) | MAY | covered | `asset.*` |  |
| [Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#f-tool-status) | MAY | covered | `asset.*` |  |
| [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#f-creator-id-oncall-creation-update-dates) | MAY | covered | `asset.*` |  |
| [Surfaces Supported](Telemetry-Attack-Detection-Addendum.md#f-surfaces-supported) | MAY | covered | `asset.*` |  |
| [Fleet counts](Telemetry-Attack-Detection-Addendum.md#f-fleet-counts) | MAY | none |  | (derived) |
<!-- END GENERATED: xm correspondence aitf -->

### 3.3 Gaps

AITF defines an attribute for every field except those the table marks *partial* or *none*. For five MUST fields (Surface / App, Input Source / Channel, LLM Error / Exception, LLM Refusal, Tool Type / Trust Boundary) an earlier mapping cited only a namespace, and AITF defines no attribute for them at the pin.

### 3.4 Path to OCSF and OpenTelemetry

AITF lets adopters emit this telemetry **before** OCSF ratifies it, and stages the upstream proposals so each is backward-compatible:

- **Phase 0, today.** AITF carries every MUST field as OTel attributes and emits OCSF via the `ai_operation` profile on existing classes (6003/6005/2004/3002); the ATLAS tag rides on `compliance.control_id` (framework `mitre_atlas`).
- **Phase 1, profile extension (backward-compatible).** Contribute the MUST attribute set plus the `ai_guardrail` and `ai_tool` objects to the OCSF `ai_operation` profile, and the `message_context` extensions (content hashes with their canonicalization declaration, redaction flags, system prompt, attachment identity); no new classes required, and `ai_content` only if content must attach to classes other than 6003 ([§1.2](#12-correspondence)).
- **Phase 2, agentic classes.** Ratify **AI Agent Activity (9001)** plus the `ai_memory` and `ai_retrieval` objects (memory & RAG are absent from OCSF today and are MUST here).
- **Phase 3, delegated authority.** Ratify **AI Delegation Activity (9002)** and the `runtime_attestation` object (ODIS-aligned), and land the lineage asks of [ocsf-schema#1739](https://github.com/ocsf/ocsf-schema/issues/1739) on `delegation`.
- **Phase 4, inventory & analytics.** SHOULD/MAY clusters (`ai_asset`, drift, quality, fleet aggregates) as they stabilize.

**Governance rule for promotion:** a field graduates from AITF-proposed to an OCSF or OpenTelemetry standardization ask once it is MUST under [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers): two independent documented instances in [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory), or a MUST field that cannot be read without it. This keeps the OCSF surface minimal and evidence-driven rather than speculative.

---

## 4. OWASP AOS Cross Reference


The [OWASP Agent Observability Standard](https://aos.owasp.org/) (AOS) defines how agents expose runtime behaviour through hooks, events, and a queryable Agent Bill-of-Materials; this RFC defines which security fields are required and how they are tiered. The tables below map AOS's **Instrument**, **Trace**, and **Inspect** pillars to the field set. Status values:

| Status | Meaning |
| :----------------- | :----------------------------------------------------------------------------------- |
| **Covered** | In the field set. |
| **Partial** | Deliberately narrower coverage; the difference is explained. |
| **Out of scope** | Control-plane or wire-protocol material this document intentionally does not specify. |

### 4.1 Pillar 1: Instrument


*AOS's Instrument pillar defines lifecycle hooks that emit to, and can be intervened on by, a **Guardian Agent**: a policy decision point that returns `allow`, `deny`, or `modify` before the agent proceeds. This is the pillar that required the most additions, because a guardrail model that only records verdicts is observational (a verdict was recorded) rather than interventional (a decision was enforced, or failed to be).*

| AOS element | This document | Status |
| :-------------------------------------------------------- | :-------------------------------------- | :------ |
| Hook set (agent trigger, user message, agent response, tool call request, tool call result, memory store, memory retrieval, knowledge retrieval, MCP inbound/outbound) | Field coverage across AD §§1.1 to 1.5; **Instrumentation Coverage / Hook Attestation** (AD §1.2) records which hooks are live | **Covered** |
| Decision `allow` / `deny` | Guardrail (Input/Output) Verdict, pass / block (AD §1.2) | Covered |
| Decision `modify` + `modifiedRequest` | **Guardrail Modification Record** (AD §1.2), cross-cutting | **Covered** |
| `reasoning` (human-readable decision rationale) | Guardrail Verdict detector + score (AD §1.2) | Covered |
| `reasonCode[]` (machine-readable) | **Policy Reason Code** (AD §1.3) | **Covered** |
| Enforcement callout failure, timeout, unavailability | **Enforcement-Point Availability & Failure Mode** (AD §1.2) | **Covered** |
| `ping` / liveness | **Enforcement-Point Availability** + **Event Sequence Continuity** (AD §1.6) | **Covered** |
| `StepContext`: agent, session, turn, step, timestamp, user, organization | **Session / Turn / Step IDs**, **Organization / Tenant ID** (AD §1.1) | **Covered** |
| `Agent` object, name, id, description, version, `instructions`, provider, model, tools, mcpServers, resources | Agent Name, Instance ID, System Prompt (AD §1.1); Model fields (AD §1.1); inventory (AD §1.6) | Covered |
| `Message` object + `Part` union (TextPart / FilePart / DataPart) | **Content Modality & Attachment Identity** (AD §1.2), cross-cutting | **Covered** |
| `ToolDefinition` / `ToolArgumentDefinition` / `ToolOutputDefinition` | **Tool Definition Digest** (AD §1.3) | **Covered** |
| `ToolCallRequest`: `executionId`, `toolId`, inputs | **Tool Execution ID** (AD §1.3) + Tool Call I/O, Tool Name (AD §1.3) | **Covered** |
| `Source` union, FileSource, SiteSource | **Citations / Source Attribution** (AD §1.2) | **Covered** |
| `KnowledgeRetrievalStepParams`: query, keywords, results | Retrieval Event, Retrieved-Content Source (AD §1.4) | Covered |
| `A2AContext`: from / to, role (client / server) | **Peer Agent Card / Descriptor** (AD §1.5); Identities Used (AD §1.6) | **Covered** |
| Guardian Agent architecture; agent↔guardian authentication | Not specified, but its **outcomes** are, via AD §1.2 | Out of scope |
| JSON-RPC 2.0 over HTTP(S); error code ranges | Wire protocol not specified; error *content* covered by LLM Error (AD §1.1), Tool Error (AD §1.3) | Out of scope |

### 4.2 Pillar 2: Trace


*AOS's Trace pillar defines the event set and its bindings to OpenTelemetry and OCSF. This is the field set's strongest area; the gaps were per-step reasoning, citations, the identifier hierarchy, and protocol-level events.*

| AOS element | This document | Status |
| :------------------------------------- | :---------------------------------------- | :----------------------- |
| `steps/agentTrigger`: `trigger.type` (autonomous), `trigger.event`, content | **Trigger Type & Source Event** (AD §1.1) | **Covered** |
| `steps/message`: role, content | Model Input (AD §1.2); Response (AD §1.2); System Prompt (AD §1.1) | Covered |
| `steps/message`: `citations` | **Citations / Source Attribution** (AD §1.2) | **Covered** |
| `steps/message`: `reasoning` | Observation / Thought (AD §1.2) | Covered |
| `steps/toolCallRequest`: `reasoning` | **Tool Selection Rationale** (AD §1.3) | **Covered** |
| `steps/toolCallResult`: `executionId`, outputs, `isError` | Tool Call I/O, Tool Error (AD §1.3); **Tool Execution ID** (AD §1.3) | **Covered** |
| `steps/memoryStore`: memory, `reasoning` | Memory Write (AD §1.4); **Memory Write Rationale** (AD §1.4) | **Covered** |
| `steps/memoryContextRetrieval`: memory, `reasoning` | Memory Read (AD §1.4) | Covered |
| `steps/knowledgeRetrieval`: query, keywords, results | Retrieval Event (AD §1.4) | Covered |
| `protocols/MCP`: full JSON-RPC payload | **MCP Server Identity & Primitive** (AD §1.3); **Protocol Envelope Capture** (AD §1.5) | **Covered** |
| `protocols/A2A`: full JSON-RPC payload | **A2A Task Lifecycle Event**, **Protocol Envelope Capture** (AD §1.5) | **Covered** |
| A2A methods: `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`, `tasks/resubscribe`, `tasks/pushNotificationConfig/get`+`/set` | **A2A Task Lifecycle Event** (AD §1.5) | **Covered** |
| `ping`: timestamp, timeout, status, version | AD §1.2 (see [§4.1](#41-pillar-1-instrument)) | **Covered** |
| OTel span hierarchy: `agent.run`, `agent.plan`, turn spans, step spans | **Session / Turn / Step IDs** + **Trace Context** (AD §1.1) specify the *identifiers and propagation*; span naming is left to the OTel binding | **Partial**: deliberate; this document is field-level, and span naming belongs in AITF |
| OTel attribute naming: `agent.*`, `llm.model.name`, `llm.provider.name` | This document uses OTel GenAI semconv `gen_ai.*` throughout ([§3](#3-aitf)) | **Divergence**: see [§4.6](#46-divergences--open-coordination-items) |
| OCSF binding: API Activity 6003, `type_uid` 600301, `actor.type_id: 99` "AI Agent", `unmapped.aos` namespace | [§1](#1-ocsf) proposes ratified classes 9001/9002 and an `ai_operation` profile | **Divergence**: see [§4.6](#46-divergences--open-coordination-items) |
| Sensitive-attribute handling ("may necessitate hashing, truncation, or redaction") | [RFC §5](CoSAI-AI-Telemetry-RFC.md#5-conformance): a content hash on every content-bearing field, raw content left to deployment policy; access control, retention and redaction are out of scope ([RFC §2.2](CoSAI-AI-Telemetry-RFC.md#22-not-in-scope)) | Partial: hashing only |

### 4.3 Pillar 3: Inspect


*AOS's Inspect pillar requires an agent to answer inspection requests with a dynamically-maintained **AgBOM**. This was the largest structural gap: AD §1.6 existed, but as a flat set of mostly-MAY attributes attached to events rather than as an inventory artifact, and with no signal at all for composition **change**.*

> **Binding status, which is weaker than the pillar's framing suggests.** AOS names CycloneDX, SPDX and SWID as AgBOM carriers, but only one binding has been written: the CycloneDX page is marked *work in progress* and consists of a single worked example, while the **SPDX and SWID pages are unfilled placeholders** soliciting contributions (AOS issues [#20](https://github.com/OWASP/www-project-agent-observability-standard/issues/20) and [#21](https://github.com/OWASP/www-project-agent-observability-standard/issues/21)). Two consequences for the rows below. The CycloneDX attribute names are verbatim from that example, where they ride CycloneDX's **generic `properties` name/value bag** rather than a modelled schema, so the modelling is AOS's and the carriage is CycloneDX's. And the SPDX 3.0 and SWID rows record what **those formats** carry, taken from their own specifications, not what AOS binds: there is no AOS binding for either to compare against yet.

| AOS element | This document | Status |
| :------------------------------------------------ | :--------------------------------------------- | :------- |
| AgBOM as a queryable, on-demand artifact | **AgBOM / Inventory Snapshot** (AD §1.6) | **Covered** |
| Dynamic refresh on discovery / removal / modification of agents, MCP servers, knowledge bases, tools, memory, models | **Capability-Set Change Event** (AD §1.6), MUST | **Covered** |
| Entity: Standard Packages, name, description, version | Tool/Agent Version, Repository/Software Ref (AD §1.6) | Covered |
| Entity: Models, identity, version, description, endpoint, `modelContextWindow`, arguments | Model Name/Version, Provider/Endpoint Identity (AD §1.1); **Inference Parameters** (AD §1.1) | **Covered** |
| Entity: Capabilities, agent cards, discovered agents, MCP servers and their protocols | **Peer Agent Card / Descriptor** (AD §1.5); **MCP Server Identity & Primitive** (AD §1.3) | **Covered** |
| Entity: Knowledge, name, description, schema, search parameters | **Declared Knowledge-Source Configuration** (AD §1.4) | **Covered** |
| Entity: Memory, name, description, type, size constraints, retrieval spec | **Declared Memory Configuration** (AD §1.4) | **Covered** |
| Entity: Tools, name, description, scheme, local and MCP endpoints | **Tool Definition Digest** (AD §1.3); **MCP Server Identity** (AD §1.3) | **Covered** |
| CycloneDX `dependencies[].dependsOn` | **Component Dependency Graph** (AD §1.6) | **Covered** |
| CycloneDX `signatures[]`: `value`, `keyId` | **Inventory Attestation Signature** (AD §1.6) | **Covered** |
| CycloneDX properties: `sandbox`, `languageRuntime`, `environment.os`, `environment.architecture`, `timeoutMs` | **Execution Environment / Sandbox** (AD §1.3) | **Covered** |
| CycloneDX properties: `auth`, `scope`, `endpoint` | Tool ACL / Required Scope (AD §1.3); Output Egress Destination (AD §1.2) | Covered |
| CycloneDX properties: `memoryBackend`, `memoryLimitMB` | **Declared Memory Configuration** (AD §1.4) | **Covered** |
| CycloneDX property: `compliance` | Not a distinct field; AITF `compliance.*` carries it ([§3](#3-aitf)) | Partial |
| SPDX 3.0 `Relationship` with `relationshipType: dependsOn` / `contains` / `hasPrerequisite`; SWID `<Link rel="requires">` | **Component Dependency Graph** (AD §1.6) | **Covered** |
| SPDX 3.0 `Element.verifiedUsing` → `Hash`; SWID `<Payload>` / `<Evidence>` `<File>` with `SHA256:` and W3C XMLDSig `<Signature>` | **Inventory Attestation Signature** (AD §1.6); Version / Repository / Software Ref (AD §1.6) | **Covered** |
| SPDX 3.0 Build profile: `buildType`, `environment`, `parameter`, `configSourceDigest`; SWID `<Meta>` | **Execution Environment / Sandbox** (AD §1.3) | Partial: build-time environment, not the runtime isolation posture the field records |
| SPDX 3.0 AI profile `AIPackage`: `typeOfModel`, `autonomyType`, `domain`, `hyperparameter`, `limitation`, `safetyRiskAssessment`, `useSensitivePersonalInformation` | Model Name/Version (AD §1.1); **Autonomy Level** (AD §1.1, declared baseline) | Partial: model governance metadata, not runtime telemetry |
| SPDX and SWID: no analogue for MCP endpoints, memory backends, tool scopes, or agent cards | **MCP Server Identity** (AD §1.3), **Declared Memory Configuration** (AD §1.4), Tool ACL / Scope (AD §1.3), **Peer Agent Card** (AD §1.5) | **Gap in those formats.** AOS's CycloneDX example is the only place the agent runtime is described, and it rides the generic `properties` bag; SPDX and SWID carry identity, dependency and integrity, and have no AOS binding yet |
| CycloneDX property: `a2aCardUrl` | **Peer Agent Card / Descriptor** (AD §1.5) | **Covered** |

### 4.4 What this implies for OpenTelemetry, AITF and OCSF


Closing the AOS gaps surfaced attributes missing from this document's bindings. All were initially filed against AITF; [§2](#2-opentelemetry) then established that **several already have an upstream home in the OpenTelemetry GenAI conventions**, and that others are answered by OTel's *native structure* rather than by any new attribute. That changes where each ask should be filed.

**The coordination finding: where OTel already defines a name, AITF should adopt it rather than mint a parallel one.** Three of the twelve asks below were substantially resolved upstream while this document was being written, the GenAI conventions gained `gen_ai.tool.definitions`, `gen_ai.tool.call.id`, and an entire `mcp.*` namespace. Filing them again against AITF would create exactly the drift [§4.6](#46-divergences--open-coordination-items) warns about between AOS's `llm.*` binding and semconv's `gen_ai.*`.

| # | Ask | OpenTelemetry today | Where to file |
| :---- | :------------------------ | :---------------------------------------------- | :------------------------------ |
| 1 | **Turn and step identifiers**, plus guidance that the run maps to the trace ID rather than to a session attribute | `gen_ai.conversation.id`, `gen_ai.workflow.name`; **step ordering is already native**: the `invoke_agent` → `execute_tool` → `chat` span tree *is* the step hierarchy, and the span ID *is* the step ID. The **turn** level has no representation | **OTel** (`gen_ai.turn.id`); AITF adopts. Do **not** mint a step-ID attribute, use the span |
| 2 | **Enforcement outcome attributes**: reachability, latency, fail-open/fail-closed, a `modify` decision value, before/after digests | `gen_ai.evaluation.*` exists but is quality-oriented, no blocked/allowed outcome, guardrail type, or threat reference | **OTel** by extending `gen_ai.evaluation.*` ([`otel_security_guardrail`](#ask-otel-security-guardrail)); enforcement *availability* to OCSF |
| 3 | **Content-part attributes**: part type, MIME type, attachment name/size/hash | `gen_ai.input.messages` / `gen_ai.output.messages` carry typed parts; **no attachment identity or hash** | **OTel**: extend existing message parts |
| 4 | **Citation attributes** on output, with a resolution flag against retrieval | `gen_ai.retrieval.documents` covers the retrieval side; nothing on the output side | **OTel** |
| 5 | **Tool contract attributes**: definition digest; consistent request↔result correlator | **`gen_ai.tool.definitions` and `gen_ai.tool.call.id` both exist upstream** | **Resolved upstream.** AITF adopts the names; only `…definitions.hash` remains to file with OTel |
| 6 | **Execution-environment attributes**: sandbox mode, runtime, OS/architecture, timeout, egress policy | Runtime and platform are already covered by **core resource conventions** (`host.*`, `os.*`, `process.runtime.*`). **Sandbox mode and egress policy are not** | **Reuse** core resource semconv; file only `sandbox` and egress policy as new |
| 7 | **MCP primitive discriminator**, server version and transport | An `mcp.*` namespace exists upstream: `mcp.method.name`, `mcp.protocol.version`, `mcp.resource.uri`, `mcp.session.id`, plus client/server operation and session duration metrics | **Largely resolved upstream.** `mcp.method.name` partially serves as the discriminator; file only an explicit primitive value set |
| 8 | **A2A attributes**: task lifecycle, push-notification callback registration, peer agent card | **Nothing.** The GenAI repository covers MCP but has no A2A conventions | **OTel**: an `a2a.*` namespace, parallel to `mcp.*`, is the natural proposal |
| 9 | **Trigger attributes**: user-initiated vs autonomous, and source event | Nothing | **OTel** ([`otel_trigger`](#ask-otel-trigger)) |
| 10 | **Tenant / organization** | No tenant attribute, but **resource attributes are the established mechanism** for this class of value | **Reuse** resource semconv; propose a tenant attribute only if none fits |
| 11 | **Declared-configuration attributes** for memory and knowledge sources | **`gen_ai.memory.*` exists** (store/record identity, query, count, and a memory span), but carries no declared-configuration, provenance or footprint attributes; knowledge partially via `gen_ai.data_source.id` | **OTel**: extend `gen_ai.memory.*` ([`otel_memory_provenance_footprint`](#ask-otel-memory-provenance-footprint), pending re-scope) |
| 12 | **Instrumentation coverage** and **event sequence number** | **Instrumentation scope is native**: every signal carries an emitting scope name and version, which partially answers coverage. **No envelope sequence number**, and no gap-detection concept | Coverage: **reuse** instrumentation scope, extend for hook-level detail. Sequence number: **OCSF**, as an envelope concern rather than an instrumentation one |

**What the pattern shows.** Of twelve asks, two are substantially resolved upstream (5, 7), three are answered wholly or partly by OTel structure that already exists and should be reused rather than duplicated (1, 6, 10, and the first half of 12), and seven remain genuine gaps. Memory is not among them. OpenTelemetry now carries a `gen_ai.memory.*` namespace and a memory span ([§2.1](#21-what-it-is-and-the-version-mapped)), and AITF carries `memory.*` including `memory.provenance` ([§3](#3-aitf)). What remains absent upstream is narrower and specific: **memory provenance and footprint**, the two attributes `IR-02`, `IR-05` and `AOC-05` turn on.

**Governance.** Per the rule in [§3.4](#34-path-to-ocsf-and-opentelemetry), each item graduates from AITF-proposed to a standardization ask once ≥ 2 independent documented instances in [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) require it, a bar every MUST-tier item above already clears. File emission-side asks with OpenTelemetry, consumption-side asks with OCSF, and use AITF to carry both in the interim.

### 4.5 What this document contributes back to AOS


The cross reference runs both ways. AOS defines a strong exposure interface but does not answer the questions this document is organized around, and the following are offered as contributions upstream:

1. **Attack grounding.** AOS asserts that agents should be observable; it does not tie any element to a documented attack. [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) supplies a 34-item corpus with per-field evidence.
2. **Priority tiering.** AOS has no MUST/SHOULD/MAY distinction across its event and AgBOM fields, so an implementer has no guidance on what to instrument first. The [tiers](CoSAI-AI-Telemetry-RFC.md#47-tiers) and the [implementation order](CoSAI-AI-Telemetry-RFC.md#6-field-catalogue) supply one, with an explicit evidence rule behind it.
3. **MITRE ATLAS technique tagging.** AOS has no threat-classification vocabulary. The [ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping) makes AOS-derived detections correlate with the ATT&CK-aligned rest of a SOC.
4. **Input trust classification.** AOS captures message `role` (user / agent / system) but not the *trusted-instruction vs untrusted-data* distinction that the CoSAI risk map treats as the core agentic control (AD §1.2). This is arguably the single highest-value field AOS lacks.
5. **Output egress destination.** AOS traces messages and tool calls but has no field for *where output went*: recipients, outbound URLs, broadcast scope. AD §1.2 argues this is the field that catches `TA-01` and `TA-03` before data leaves.
6. **Delegation and attestation.** AOS's `A2AContext` records the immediate from/to hop but not the originating principal, the multi-hop delegation chain, granted authorizations, or runtime attestation. AD §1.6 and the ODIS cross reference in [§3](#3-aitf) supply these.
7. **Verified vs displayed identity.** `AOC-08`'s lesson (bind and log the immutable identifier, not the display name) applies directly to AOS's user objects and A2A agent cards, which are displayed identities by construction.
8. **Observability-plane integrity (AD §1.2).** AOS's own architecture creates the exposure: a synchronous guardian callout is a dependency that can fail or be starved, and a self-reporting agent can omit. AOS specifies the happy path; AD §1.2 specifies the telemetry for when it does not hold. This is the contribution most specific to AOS's design.
9. **Hash-first content.** AOS notes that sensitive attributes "may necessitate hashing, truncation, or redaction." [RFC §5](CoSAI-AI-Telemetry-RFC.md#5-conformance) requires a content hash on every content-bearing field and leaves raw content to deployment policy, so payloads stay correlatable without being retained. Access control, retention and redaction are left to a later CoSAI publication ([RFC §2.2](CoSAI-AI-Telemetry-RFC.md#22-not-in-scope)).

### 4.6 Divergences & open coordination items


Two genuine divergences and two coordination items. None is blocking; all should be reconciled before either document is treated as normative alongside the other.

1. **OCSF strategy.** AOS extends **API Activity (6003)** with an `unmapped.aos` namespace and types the agent as `actor.type_id: 99` ("Other") with `type: "AI Agent"`. [§1](#1-ocsf) instead asks OCSF to ratify **AI Agent Activity (9001)** and **AI Delegation Activity (9002)** plus an `ai_operation` profile. These are different bets on the same schema. The positions are reconcilable and arguably sequential. AOS's `unmapped.*` approach is the correct *interim* carrier under an unratified schema, and matches Phase 0 in [§3.4](#34-path-to-ocsf-and-opentelemetry); this document's asks are the ratification endpoint. Worth noting that AOS's need for an `actor.type_id: 99` workaround is independent evidence for standardization ask (6) in [§1.4](#14-asks). **Action:** align on a shared phase plan before either party submits to OCSF.
2. **OpenTelemetry attribute naming.** AOS's OTel binding uses `agent.*`, `llm.model.name`, and `llm.provider.name`. This document and AITF use the OTel **GenAI semantic conventions** (`gen_ai.*`), which is the upstream-maintained namespace; `llm.*` is not current semconv. The divergence is wider than a prefix: AOS's binding predates the GenAI conventions moving to their own repository and gaining `gen_ai.system_instructions`, `gen_ai.tool.definitions`, the retrieval attributes, and a dedicated `mcp.*` namespace; much of what AOS models by hand now has an upstream home (see [§2.1](#21-what-it-is-and-the-version-mapped)). **Action:** recommend AOS migrate its OTel binding to `gen_ai.*` / `mcp.*`. Low cost while both are drafts, high cost later.
3. **Scope boundary.** This document treats enforcement *outcomes* as telemetry (AD §1.2) and the enforcement *protocol* as out of scope. AOS specifies the protocol and is comparatively quiet on outcomes. The split is clean and probably correct, but it is a choice both groups should ratify rather than assume.

---

## 5. CPEX Cross Reference


[CPEX](https://contextforge-org.github.io/cpex/) is a deterministic reference monitor between an agent and its capabilities. It produces the policy, identity, taint, approval, and routing decisions recorded by AD §1.3; this appendix maps those outputs to the field set and identifies remaining gaps. AD §1.3 takes only these decision records, not CPEX's policy language, plugin model, or deployment architecture.

> **Sourcing.** Element names below are verified against the CPEX repository at commit `035012f` (18 August 2026). The citation is pinned to a commit rather than to a release because the released tags trail the documentation: the latest release, `v0.2.2` (15 July 2026), does not contain the threat-model document that [§5.1](#51-the-threat-model-the-most-important-contribution) and AD §1.3 rest on. The published documentation site also renders a legacy `0.1.x` tree alongside the current pages; nothing in this appendix is taken from it.

### 5.1 The threat model: the most important contribution


CPEX's [threat model](https://contextforge-org.github.io/cpex/docs/threat-model/) is a zero-trust, assume-breach model whose central move is to treat **the LLM itself as the adversary**, not merely as a component an adversary attacks. Three assumptions:

1. **Input vulnerability**: "Prompt injection can arrive through any content the model reads: user messages, tool results, fetched resources, other agents' replies."
2. **Output manipulation**: "An injected instruction becomes a tool call, an argument value, an email body. **The model is a confused deputy.**"
3. **No security properties**: the model cannot maintain confidentiality or enforce authorization; context contents can leak through permitted channels.

From this follows the trust boundary: everything on the agent side of the monitor is assumed hostile, and **"nothing the policy reads comes from there: verified tokens come from the IdP (identity provider), decisions from the PDP, taint labels from the session store, and the delegation and audit state is CPEX's own."** That last clause is why `enforcement-state` is one of the authorities in the **Attribute Source** enum (AD §1.2): the enforcement point's own record of a decision is a distinct provenance from anything an identity provider or policy engine supplied.

**Read strictly, the rest of this document operates on a weaker premise, and the gap is not cosmetic.** AD §1 treat the agent as a *victim* of attack, something to be instrumented so that attacks against it become visible. Under CPEX's model the agent is also a potential *liar*, and that distinction propagates straight into the telemetry: several fields this document marks MUST or SHOULD are values the agent itself supplies. **Autonomy Level** (AD §1.1), **Task / Intent Declaration** (AD §1.5), **System Prompt** (AD §1.1), **Observation / Thought** (AD §1.2), and every reasoning field are self-asserted. A compromised agent can report a benign autonomy level while acting outside it, and `AOC-01` is the corpus's demonstration that agents do misreport: it declared a secret destroyed while the data remained recoverable.

**Verified vs Displayed Identity** (AD §1.6) is already MUST because `AOC-08` turns on the difference between an immutable identifier and a spoofable display name. CPEX generalizes that lesson: identity is not special; *every* security-relevant attribute has a provenance, and telemetry that does not record it cannot survive the assume-breach model. That is the reasoning behind the new cross-cutting **Attribute Source / Trusted-Provenance Marking** ([AD §1.2](Telemetry-Attack-Detection-Addendum.md#12-content-trust-verdicts-and-their-availability)), and it is the largest change this appendix produced.

Denied and failed attempts are first-class telemetry under this model, not exhaust. CPEX's audit requirement explicitly includes denied attempts. This document was already aligned in spirit (`AOC-12`/`AOC-13`/`AOC-14` are catalogued because their telemetry documents *attempted* attacks that were resisted) but AD §1.3's Authorization Decision Record now makes it structural rather than incidental.

### 5.2 Threats & controls cross reference


CPEX's threat matrix, mapped to this document's fields. This is the tightest available test of coverage, because each row is a control CPEX considers necessary.

| CPEX threat | CPEX control | Covered by | Status |
| :------------- | :------------------- | :----------------------------------------- | :--------------------------- |
| Prompt-injection tool misuse | Policy gates and argument validation before dispatch | Input Trust Classification, Guardrail (Input) Verdict (AD §1.2); Tool Call I/O (AD §1.3); **Authorization Decision Record** (AD §1.3) | **Covered**: the decision record was missing |
| Confused deputy / privilege escalation | Per-caller identity from verified tokens | Identities Used, Verified vs Displayed Identity, Granted Authorizations (AD §1.6) | Covered |
| Cross-request data exfiltration | Session-level taint blocks the write-down | **Session Taint Labels & Information-Flow Decisions** (AD §1.3) | **Covered**: expressible as state, not only as a correlation pattern |
| Credential exposure | Fresh audience-scoped tokens minted per call | **Credential Minting & Scope-Narrowing Check** (AD §1.6) | **Covered** |
| PII disclosure | Field-level redaction on outputs | Guardrail (Output) Verdict (AD §1.2); Guardrail Modification Record (AD §1.2); Tool Privacy Classification (AD §1.3) | Partial: see [§5.5](#55-divergences--gaps-remaining) on field-level granularity |
| Unauthorized high-impact actions | Out-of-band human approval | **Human Approval / Elicitation Event** (AD §1.3) | **Covered** |
| Approval replay | Approvals bound to live arguments | **Human Approval / Elicitation Event**: scope-binding validation result (AD §1.3) | **Covered** |
| Unaccountable actions | Append-only audit per decision, denied attempts included | **Authorization Decision Record** (AD §1.3); Event Sequence Continuity (AD §1.6) | **Covered** |

Five of eight CPEX controls map only to fields in AD §1.3; they had **no counterpart** anywhere else in the field set. That is the strongest single finding in this appendix, and it reflects a real blind spot rather than a difference of emphasis: the document was thorough on *observation* and near-silent on *enforcement*.

### 5.3 APL, CMF & identity surface


| CPEX element | This document | Status |
| :----------------------------------------- | :----------------------------------------- | :------------------ |
| Effects: `deny` / `deny(reason)` / `deny(reason, code)`; per-step **suppressed deny** (a plugin in `transform` mode cannot block, so a deny it attempts is recorded and not enforced), `Aborted`, `Error`; fail-closed `plugin_panic` deny code ([cpex#166](https://github.com/contextforge-org/cpex/pull/166) audit seam) | **Authorization Decision Record**: decision, reason, machine-readable code, per-step actions including suppressed deny and abort (AD §1.3) | **Covered** |
| Effect: `taint(label[, scope])`; session vs message scope | **Session Taint Labels** (AD §1.3) | **Covered** |
| Effect: `delegate(...)`, subject `user` / `client` / `caller_workload` / `this_workload` | **Credential Minting & Scope-Narrowing Check** (AD §1.6) | **Covered** |
| Effect: `require_approval(...)`; `elicitation.id` / `.status` / `.outcome` / `.approver` / `.channel` | **Human Approval / Elicitation Event** (AD §1.3) | **Covered** |
| Effect: `restrict: {allow_models, deny_models, allow_regions, allow_sites, max_cost_tier, custom, on_empty}` | **Backend / Route Restriction Decision** (AD §1.3) | **Covered** |
| Effect: `plugin(name)` dispatch | Guardrail Verdict (AD §1.2); Guardrail Modification Record (AD §1.2) | Covered |
| Field pipelines: `mask(N)`, `redact`, `redact(!pred)`, `omit`, `hash`, `pii.redact`, `pii.detect`, `injection.scan` | Guardrail Modification Record (AD §1.2); Guardrail (Output) Verdict (AD §1.2) | Partial: whole-payload, not per-field |
| Route phases: `args` → `authorization.pre_invocation` → `result` → `authorization.post_invocation` | Action Type (AD §1.1); Tool Execution ID (AD §1.3) pairs pre/post | Partial: phase identity is not recorded |
| PDP integration: Cedar / CEL / OPA resolvers, `on_allow` / `on_deny` | **Authorization Decision Record**: deciding authority and rule id (AD §1.3) | **Covered** |
| `delegation.depth`, `delegation.origin_subject_id`, `delegation.granted.permissions` | Delegation Chain, Originating Principal, Granted Authorizations (AD §1.6); scope delta via **Credential Minting** (AD §1.6) | Covered |
| Identity slots: `subject` (human), `client` (OAuth app), `caller_workload` (SPIFFE SVID), simultaneously | Identities Used (AD §1.6), now explicitly a **set**, not a single value | Covered (clarified) |
| Attribute namespaces `agent.*`, `framework.*`, `subject.*`, `delegation.*`, `security.*`, `http.*`, `data.*` | Mapped to AITF namespaces in [§3](#3-aitf) | Covered |
| CMF (protocol-agnostic envelope; one policy across tools, A2A, inference, prompts, resources) | Action Type (AD §1.1); MCP Server Identity & Primitive (AD §1.3); Inter-Agent Message (AD §1.5) | Partial, see [§5.5](#55-divergences--gaps-remaining) |
| Extension mutability tiers: immutable / **monotonic** / mutable | Monotonicity is asserted for taint and delegation but not recorded | Out of scope: policy-engine internal |
| Capability-gating: plugins declare capabilities; extensions filtered per plugin | Least-privilege for enforcement components | Out of scope: enforcement architecture |
| Deployment placements: gateway / sidecar / in-process, each with named coverage gaps | **Mediation Coverage & Bypass Path** (AD §1.3) | **Covered** |
| Builtins: `identity/jwt`, `delegator/oauth`, `validator/pii-scan`, `audit/logger`, `cedar-direct`, `cel`, `valkey` | Named as implementations, not telemetry | Out of scope |

### 5.4 What this document contributes back to CPEX


1. **Priority and evidence.** CPEX produces decision records; it does not say which are worth keeping or in what order to adopt them. The [tiers](CoSAI-AI-Telemetry-RFC.md#47-tiers) and the [implementation order](CoSAI-AI-Telemetry-RFC.md#6-field-catalogue) supply that, with attack grounding behind each call. How long to keep them is out of scope ([RFC §2.2](CoSAI-AI-Telemetry-RFC.md#22-not-in-scope)).
2. **A SOC destination.** CPEX's audit log is a local artifact. [§1](#1-ocsf) now proposes `ai_authorization`, `ai_taint`, and `ai_approval` OCSF objects plus an `attribute_source` enum, so enforcement decisions correlate with the rest of the security estate rather than sitting in a separate store.
3. **MITRE ATLAS tagging.** CPEX has no threat-classification vocabulary; a denial carries a policy reason, not a technique. Stamping decisions with `AML.Txxxx` ([AD §3.6](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping)) makes them correlate with ATT&CK-aligned tooling.
4. **The observation surface CPEX explicitly cannot see.** CPEX mediates the agent↔capability boundary. It does not observe memory reads and writes (AD §1.4), retrieval and its provenance (AD §1.4), token consumption and loop behaviour (AD §1.1, AD §1.5), model supply chain (AD §1.1), or asset composition (AD §1.6). `IR-02` (MINJA) poisons memory using entirely benign queries; every individual operation is policy-clean, and a reference monitor sees nothing wrong. **Enforcement and observation are complementary, not substitutable**, and a deployment running CPEX still needs most of AD §1.1 to 1.10.
5. **Provider-side and governance signals.** `AOC-06`, silent provider truncation on sensitive topics, is invisible to a reference monitor, since the operation was permitted and completed.
6. **Attack grounding for the threat matrix.** CPEX's threat rows are stated as principles; [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) supplies documented incidents for each, which is useful for justifying the controls to a risk committee.

### 5.5 Divergences & gaps remaining


1. **Redaction granularity.** CPEX redacts *per field* under a predicate (`ssn: 'str | redact(!perm.view_ssn)'`); this document's **Guardrail Modification Record** is whole-payload. Per-field records are more useful and more privacy-sensitive at once. Left as-is deliberately (a per-field redaction map is a policy decision, not a default) but implementers running field-level pipelines should record at that granularity.
2. **Route-phase identity is not captured.** CPEX distinguishes four phases, and *which* phase denied an operation is diagnostically meaningful (argument validation vs authorization vs post-check). This document records the decision but not the phase. A candidate sub-attribute of the Authorization Decision Record; not proposed as a separate field.
3. **CMF normalization is an unadopted good idea.** CPEX's Common Message Format lets one policy cover tool calls, A2A, inference, prompts, and resources uniformly. This document organizes telemetry by *component* (AD §1), which means an equivalent operation is described differently depending on which pipeline carried it. The component organization is deliberate (it maps to the CoSAI Risk Map) but a normalized **operation view** across protocols would make cross-protocol detections expressible.
4. **Covert channels are out of scope for both.** CPEX states plainly that "determined models can encode data within permitted output channels." This document's **Output Egress Destination** and **Citations** narrow the channel but do not close it. Neither document should claim otherwise.
5. **Host compromise.** CPEX's guarantees "hold only with intact processes and state stores"; this document's AD §1.2 covers telemetry suppression but neither addresses a compromised enforcement host. Shared limitation, worth stating in both.
6. **Terminology collision.** CPEX uses *taint* for session-scoped information-flow labels; this document uses *trust classification* for per-segment input labelling. They are different mechanisms and both are needed, AD §1.2 classifies a payload, AD §1.3 tracks accumulated state. The terms should not be merged, and AD §1.3 says so explicitly.

---

## 6. ODIS

### 6.1 What it is, and the version mapped

<!-- BEGIN GENERATED: xm pin odis -->
<!-- END GENERATED: xm pin odis -->

Maps each conceptual field to the [AITF](https://github.com/cosai-oasis/ws2-defenders/tree/main/telemetry) attribute namespace and to the relevant [ODIS](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md) data-model field, verified against ODIS at commit `148dc41` (8 September 2026). Per the brief, ODIS coverage is **selective**: it targets the delegation/identity fields relevant to detection & response, not the full ODIS spec. The ODIS column resolves **names**, not shapes: ODIS defines abstract schemas that implementations bind to a wire format, and this document is a requirements layer rather than a binding ([RFC §2.1](CoSAI-AI-Telemetry-RFC.md#21-in-scope)). Where cardinality or structure is normative for an ask, it is stated in [§1](#1-ocsf).

### 6.2 Correspondence

<!-- BEGIN GENERATED: xm correspondence odis -->
**RFC §6.1 Identifiers, trace context and model identity**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Agent Name](Telemetry-Attack-Detection-Addendum.md#f-agent-name) | MUST | covered | `agent_id`, `owner_ref` | `agent_id` /`owner_ref` (6.1) |
| [Agent (Runtime) Instance ID](Telemetry-Attack-Detection-Addendum.md#f-agent-runtime-instance-id) | MUST | covered | `runtime_instance_id` | `runtime_instance_id` (6.2) |
| [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#f-workflow-run-id) | MUST | covered | `request_trace_id` | `request_trace_id` (6.4) |
| [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#f-session-turn-step-ids) | MUST | none |  |  |
| [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#f-trigger-type-source-event) | MUST | none |  |  |
| [Action Type](Telemetry-Attack-Detection-Addendum.md#f-action-type) | MUST | covered | `action` | `action.{tool,method}` (6.4) |
| [Execution Status](Telemetry-Attack-Detection-Addendum.md#f-execution-status) | MUST | none |  |  |
| [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) | MUST | none |  | n/a (policy input) |
| [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) | MUST | none |  | n/a (see note) |
| [Model Name + Version](Telemetry-Attack-Detection-Addendum.md#f-model-name-version) | MUST | covered | `approved_software_refs` | `approved_software_refs` (6.1) |
| [Inference Parameters](Telemetry-Attack-Detection-Addendum.md#f-inference-parameters) | MUST | none |  |  |
| [Input / Output Token Counts](Telemetry-Attack-Detection-Addendum.md#f-input-output-token-counts) | MUST | none |  |  |
| [LLM Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-llm-error-exception) | MUST | none |  |  |
| [Trace Context (propagated)](Telemetry-Attack-Detection-Addendum.md#f-trace-context-propagated) | MUST | covered | `request_trace_id` | `request_trace_id` (6.4) |
| [Stop Reason](Telemetry-Attack-Detection-Addendum.md#f-stop-reason) | MUST | none |  |  |
| [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) | SHOULD | none |  |  |
| [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) | SHOULD | covered | `software_hash`, `approved_software_refs` | `software_hash` (6.2), `approved_software_refs` (6.1) |
| [Organization / Tenant ID](Telemetry-Attack-Detection-Addendum.md#f-organization-tenant-id) | SHOULD | covered | `trust_domain` | `trust_domain` (6.1) |
| [Provider / Endpoint Identity](Telemetry-Attack-Detection-Addendum.md#f-provider-endpoint-identity) | MAY | none |  |  |
| [Pre-Forward-Pass State Digest/Vector](Telemetry-Attack-Detection-Addendum.md#f-pre-forward-pass-state-digest-vector) | MAY | none |  |  |
| [Token Malformation / Context-Corruption Indicator](Telemetry-Attack-Detection-Addendum.md#f-token-malformation-context-corruption-indicator) | MAY | none |  |  |

**RFC §6.2 Content, trust, verdicts and their availability**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Model Input](Telemetry-Attack-Detection-Addendum.md#f-model-input) | MUST | covered | `action` | `action.parameters` (6.4) |
| [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#f-input-source-channel) | MUST | covered | `delegation_chain` | `delegation_chain` origin (6.3) |
| [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification) | MUST | covered | `constraints` | `constraints` (6.3) |
| [Source host / IP + request metadata](Telemetry-Attack-Detection-Addendum.md#f-source-host-ip-request-metadata) | MUST | none |  | n/a (policy input) |
| [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-input-verdict) | MUST | none |  |  |
| [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#f-response-model-output) | MUST | none |  |  |
| [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination) | MUST | covered | `resource_indicators` | `resource_indicators` (6.3) |
| [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#f-citations-source-attribution) | MUST | none |  |  |
| [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-output-verdict) | MUST | covered | `constraints` | `constraints` (6.3) |
| [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) | MUST | none |  |  |
| [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) | MUST | none |  |  |
| [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) | MUST | partial | `attestation_evidence` | `attestation_evidence` (6.2, partial) |
| [Instrumentation Coverage / Hook Attestation](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) | MUST | none |  |  |
| [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode) | MUST | none |  |  |
| [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) | MUST | none |  |  |
| [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) | MUST | none |  |  |
| [Observation / Thought (reasoning trace)](Telemetry-Attack-Detection-Addendum.md#f-observation-thought-reasoning-trace) | SHOULD | none |  |  |
| [Threat Classification / ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#f-threat-classification-atlas-technique-tag) | MAY | none |  |  |

**RFC §6.3 Tool calls and policy decisions**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#f-execution-environment-sandbox) | MUST | partial | `binding_profile` | `binding_profile` (6.2, partial) |
| [Tool Call I/O](Telemetry-Attack-Detection-Addendum.md#f-tool-call-io) | MUST | covered | `action` | `action` (6.4) |
| [Tool Name](Telemetry-Attack-Detection-Addendum.md#f-tool-name) | MUST | none |  |  |
| [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#f-tool-type-trust-boundary) | MUST | none |  |  |
| [Tool Execution ID](Telemetry-Attack-Detection-Addendum.md#f-tool-execution-id) | MUST | none |  |  |
| [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#f-tool-definition-digest) | MUST | covered | `approved_software_refs` | `approved_software_refs` (6.1) |
| [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive) | MUST | none |  |  |
| [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-tool-error-exception) | MUST | none |  |  |
| [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) | MUST | none |  | n/a (see note) |
| [Tool Selection Rationale](Telemetry-Attack-Detection-Addendum.md#f-tool-selection-rationale) | SHOULD | none |  |  |
| [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#f-human-approval-elicitation-event) | SHOULD | partial | `originating_principal` | `originating_principal` (6.3, partial) |
| [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#f-tool-acl-required-scope) | SHOULD | covered | `granted_authorizations` | `granted_authorizations` (6.3) |
| [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#f-session-taint-labels-information-flow-decisions) | SHOULD | covered | `constraints` | `constraints` (6.3) |
| [Backend / Route Restriction Decision](Telemetry-Attack-Detection-Addendum.md#f-backend-route-restriction-decision) | SHOULD | covered | `resource_indicators`, `constraints` | `resource_indicators`, `constraints` (6.3) |
| [Mediation Coverage & Bypass Path](Telemetry-Attack-Detection-Addendum.md#f-mediation-coverage-bypass-path) | SHOULD | none |  |  |
| [Tool ID](Telemetry-Attack-Detection-Addendum.md#f-tool-id) | MAY | none |  |  |
| [Tool Privacy Classification](Telemetry-Attack-Detection-Addendum.md#f-tool-privacy-classification) | MAY | covered | `constraints` | `constraints` (6.3) |
| [Policy Reason Code](Telemetry-Attack-Detection-Addendum.md#f-policy-reason-code) | MAY | none |  |  |

**RFC §6.4 Memory and retrieval**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Memory Write Event](Telemetry-Attack-Detection-Addendum.md#f-memory-write-event) | MUST | none |  |  |
| [Memory Read / Injection Event](Telemetry-Attack-Detection-Addendum.md#f-memory-read-injection-event) | MUST | none |  |  |
| [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#f-memory-provenance-source) | MUST | none |  |  |
| [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#f-memory-footprint-growth) | MUST | none |  |  |
| [Retrieval Event](Telemetry-Attack-Detection-Addendum.md#f-retrieval-event) | MUST | none |  |  |
| [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-source-provenance) | MUST | covered | `delegation_chain`, `constraints` | `delegation_chain`/`constraints` (6.3) |
| [Memory Integrity / Poisoning Signal](Telemetry-Attack-Detection-Addendum.md#f-memory-integrity-poisoning-signal) | SHOULD | none |  |  |
| [Memory Write Rationale](Telemetry-Attack-Detection-Addendum.md#f-memory-write-rationale) | SHOULD | none |  |  |
| [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) | SHOULD | none |  |  |
| [Declared Memory Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-memory-configuration) | MAY | none |  |  |
| [Declared Knowledge-Source Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-knowledge-source-configuration) | MAY | none |  |  |

**RFC §6.5 Orchestration**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) | MUST | covered | `delegation_chain` | `delegation_chain` (6.3) |
| [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) | MUST | none |  |  |
| [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) | MUST | none |  |  |
| [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) | MUST | covered | `constraints` | `constraints` (rate) (6.3) |
| [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#f-task-intent-declaration) | SHOULD | covered | `task_id`, `task_description` | `task_id`, `task_description` (6.3) |
| [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) | SHOULD | covered | `delegation_id`, `parent_delegation_ref` | `delegation_id`, `parent_delegation_ref` (6.3) |
| [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#f-peer-agent-card-descriptor) | SHOULD | covered | `agent_id`, `approved_software_refs` | `agent_id`, `approved_software_refs` (6.1) |
| [Protocol Envelope Capture](Telemetry-Attack-Detection-Addendum.md#f-protocol-envelope-capture) | MAY | none |  |  |

**RFC §6.6 Identity, provenance and inventory**

| Field | Tier | Coverage | Carried by | Gap or note |
| :------------------ | :---- | :------- | :------------------ | :------------------ |
| [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) | MUST | covered | `approved_software_refs` | `approved_software_refs` (6.1) |
| [Identities Used (per hop)](Telemetry-Attack-Detection-Addendum.md#f-identities-used-per-hop) | MUST | covered | `actor` | `actor`, chain (6.3) |
| [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#f-verified-vs-displayed-identity) | MUST | covered | `originating_principal`, `actor` | `originating_principal`/`actor` (6.3) |
| [Originating Principal (on-behalf-of)](Telemetry-Attack-Detection-Addendum.md#f-originating-principal-on-behalf-of) | SHOULD | covered | `originating_principal` | `originating_principal` (6.3) |
| [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) | SHOULD | covered | `delegation_chain`, `delegation_id`, `parent_delegation_ref` | `delegation_chain`, `delegation_id`, `parent_delegation_ref` (6.3) |
| [Granted Authorizations / Scope](Telemetry-Attack-Detection-Addendum.md#f-granted-authorizations-scope) | SHOULD | covered | `granted_authorizations`, `attenuation_profile_ref` | `granted_authorizations`, `attenuation_profile_ref` (6.3) |
| [Resource Indicators + Constraints](Telemetry-Attack-Detection-Addendum.md#f-resource-indicators-constraints) | SHOULD | covered | `resource_indicators`, `constraints` | `resource_indicators`, `constraints` (6.3) |
| [Credential Minting & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#f-credential-minting-scope-narrowing-check) | SHOULD | covered | `granted_authorizations`, `binding_profile` | `granted_authorizations`, `binding_profile` (6.2/6.3) |
| [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#f-trust-domain-crossing-delegation-depth) | SHOULD | covered | `trust_domain`, `max_depth` | `trust_domain` (6.1, 6.2), `max_depth` (6.3) |
| [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#f-runtime-credential-attestation) | SHOULD | covered | `attestation_evidence`, `issuer`, `holder_key_ref`, `expires_at`, `binding_profile` | `attestation_evidence`, `issuer`, `holder_key_ref`, `expires_at`, `binding_profile` (6.2) |
| [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#f-lifecycle-state) | SHOULD | covered | `lifecycle_state` | `lifecycle_state` (6.1) |
| [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) | SHOULD | covered | `approved_software_refs` | `approved_software_refs` (6.1) |
| [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) | SHOULD | covered | `approved_software_refs` | `approved_software_refs` (6.1) |
| [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) | SHOULD | covered | `approved_software_refs` | `approved_software_refs` (6.1) |
| [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) | SHOULD | none |  |  |
| [Inventory Attestation Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) | SHOULD | covered | `software_hash`, `attestation_evidence` | `software_hash`, `attestation_evidence` (6.2) |
| [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#f-event-sequence-continuity) | SHOULD | none |  |  |
| [Description](Telemetry-Attack-Detection-Addendum.md#f-tool-description) | MAY | covered | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` (6.1) |
| [Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#f-tool-status) | MAY | covered | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` (6.1) |
| [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#f-creator-id-oncall-creation-update-dates) | MAY | covered | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` (6.1) |
| [Surfaces Supported](Telemetry-Attack-Detection-Addendum.md#f-surfaces-supported) | MAY | covered | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` (6.1) |
| [Fleet counts](Telemetry-Attack-Detection-Addendum.md#f-fleet-counts) | MAY | none |  |  |
<!-- END GENERATED: xm correspondence odis -->

### 6.3 Notes on the mapping

> **Policy-engine consumption and telemetry emission are orthogonal.** A field presented to a policy engine is not thereby excluded from telemetry, and the reverse also holds; AD §1.3's **Authorization Decision Record** exists to record a decision together with the attributes it turned on. Inclusion here is decided by detection and response value, not by how ODIS §6.4 classifies a field.
>
> **ODIS fields intentionally out of telemetry scope** (identity/authority mechanics rather than detection signals): `approved_runtime_issuers`, `policy_profile_ref`, `permitted_delegation_modes`, `provider_entitlements`, and the details of `binding_profile`: the token-binding method (DPoP, mTLS, or TLS session binding via `tls_exp`) together with key custody and which component is authorized to present the derived credential. These are consumed by the policy engine (ODIS §6.4 Identity Context) rather than emitted as security telemetry. `policy_profile_ref` names the policy profile in force; it is neither the content of an instruction configuration nor the record of a decision, so **System Prompt / Instruction Config** and **Authorization Decision Record** carry no ODIS mapping above.
>
> **`trust_domain` and `max_depth` are the exception and are in scope.** AD §1.6's **Trust-Domain Crossing & Delegation Depth** carries both as telemetry, because each becomes detection-grade once a delegation chain leaves the domain that issued it (see [RFC §4.6](CoSAI-AI-Telemetry-RFC.md#46-record-your-boundary-not-their-internals)). `trust_domain` appears in both the registration record (6.1) and the runtime credential descriptor (6.2).
>
> **Data classification travels as a constraint.** ODIS defines `constraints` (6.3) as time, purpose, rate, locality "or other narrowing constraints" and enumerates no keys, so the data-classification narrowing recorded by **Guardrail (Output) Verdict** (AD §1.2), **Tool Privacy Classification** (AD §1.3) and **Session Taint Labels** (AD §1.3) is an illustrative key of that object rather than an ODIS-defined field name.

---

## 7. Implications for NIST AI RMF and NIST CSF (incl. the Cyber AI Profile)


§§2 to 3 route this field set toward **schemas**; §§4 and 5 reference it against **adjacent technical standards**. This appendix and [§8](#8-implications-for-isoiec-42001) address a different consumer: **governance frameworks that use telemetry as control evidence**.

That places them at the **A** end of this document's [use-case priority](CoSAI-AI-Telemetry-RFC.md#41-detection-first): compliance audit, the lowest of the four. The ordering is deliberate: **this field set is designed for detection and response, and its audit value is a by-product.** A telemetry programme built to satisfy an auditor produces different fields than one built to catch `TA-01`, and where the two diverge this document follows detection. The useful consequence is that a deployment implementing the MUST tier for **D** and **R** reasons will find it has already produced most of the evidence these frameworks ask for, which is a far easier argument to fund than the reverse.

> **Framework status as of 11 September 2026.** NIST AI RMF 1.0 (January 2023) **is being revised as part of the White House AI Action Plan**; no revised draft has published, so the MEASURE mapping in [§7.3](#73-ai-rmf-mapping-by-function) is drawn against 1.0. The **Cyber AI Profile** remains at *initial preliminary draft* (**NIST IR 8596**, published 16 December 2025): the comment period closed 30 January 2026, NIST ran Cyber AI Profile working sessions in April and May 2026, and **no Initial Public Draft has published**. The three focus areas are confirmed as *Securing AI System Components* (**Secure**), *Conducting AI-Enabled Cyber Defense* (**Defend**) and *Thwarting AI-enabled Cyber Attacks* (**Thwart**). Every CSF 2.0 category identifier cited in [§7.2](#72-csf-20-mapping-by-function) and [§7.3](#73-ai-rmf-mapping-by-function) is verified against NIST's published CSF reference data.

### 7.1 Why these two frameworks, and how they differ


| Framework | What it governs | Relationship to this document |
| :-------------------- | :------------------------ | :-------------------------------------------------------- |
| **NIST AI RMF 1.0** (+ **AI 600-1** Generative AI Profile) | AI-specific risk management across **GOVERN / MAP / MEASURE / MANAGE** | Asks *whether AI risks are identified, measured and managed.* This field set is the **measurement substrate**: mostly MEASURE, with MANAGE for response |
| **NIST CSF 2.0** (+ the **Cyber AI Profile**, NIST IR 8596) | Cybersecurity outcomes across **GV / ID / PR / DE / RS / RC** | Asks *whether attacks are detected and responded to.* This is the closer fit by far, the document's D and R priorities map almost one-to-one onto **DE** and **RS** |

The **Cyber AI Profile** is the significant development for this work. It is a CSF 2.0 *community profile* that overlays three **AI Focus Areas** on existing CSF outcomes:

- **Secure**: securing AI systems and their infrastructure.
- **Defend**: using AI to strengthen cyber defence.
- **Thwart**: defending against adversarial *uses* of AI.

**This document sits squarely in *Secure*, and it is the telemetry layer that focus area presupposes.** The Profile asks organizations to achieve CSF detection and response outcomes *for AI systems*; it does not specify which fields make that possible. That is precisely the gap this document fills, and the alignment is close enough that the CoSAI field set is a credible candidate reference for Profile implementers.

### 7.2 CSF 2.0 mapping, by function


CSF Categories cited: **GV.OC** Organizational Context · **GV.SC** Cybersecurity Supply Chain Risk Management · **ID.AM** Asset Management · **ID.RA** Risk Assessment · **PR.AA** Identity Management, Authentication and Access Control · **PR.DS** Data Security · **DE.CM** Continuous Monitoring · **DE.AE** Adverse Event Analysis · **RS.MA** Incident Management · **RS.AN** Incident Analysis · **RC.RP** Incident Recovery Plan Execution.

| CSF function | Telemetry that evidences it | Coverage |
| :------ | :----------------------------------------------------------------- | :----------------------------- |
| **GOVERN** (GV.OC, GV.SC) | Asset inventory and AgBOM (AD §1.6); model provenance and signing (AD §1.1); dependency graph and version (AD §1.6); autonomy level and task declaration (AD §1.1) | **Partial**: supply-chain outcomes are well served; policy and role outcomes are organizational, not telemetric |
| **IDENTIFY** (ID.AM, ID.RA) | Agent name, instance ID, surface (AD §1.1); capability-set change (AD §1.6); AgBOM (AD §1.6); tool and MCP inventory (AD §1.3); fleet aggregates (AD §1.6) | **Strong**: Capability-Set Change is the field that makes ID.AM *continuous* rather than periodic |
| **PROTECT** (PR.AA, PR.DS) | Identities used, verified-vs-displayed identity, granted authorizations, credential minting (AD §1.6); authorization decision record (AD §1.3); guardrail verdicts (AD §1.2); sandbox posture (AD §1.3) | **Strong**: AD §§1.3 and 1.6 are PR.AA evidence almost verbatim |
| **DETECT** (DE.CM, DE.AE) | **The entire MUST tier.** Input trust classification and guardrail verdicts (AD §1.2); output egress and refusals (AD §1.2); tool call I/O (AD §1.3); memory and retrieval events (AD §1.4); loop and resource signals (AD §1.5); session taint (AD §1.3); every [correlation pattern](Telemetry-Attack-Detection-Addendum.md#2-correlation-patterns) | **Strongest alignment in the document.** DE.CM is continuous monitoring; DE.AE is the correlation-pattern layer |
| **RESPOND** (RS.MA, RS.AN) | The identifier hierarchy and trace context (AD §1.1); tool execution IDs (AD §1.3); memory and retrieval provenance (AD §1.4); delegation chain (AD §1.6); ATLAS technique tag (AD §1.2); event sequence continuity (AD §1.6) | **Strong**: this is the document's **R** priority, and the ATLAS tag makes RS.AN findings portable |
| **RECOVER** (RC.RP) | Lifecycle state and revocation (AD §1.6); instance ID for per-instance quarantine (AD §1.1); capability-set change for rollback verification (AD §1.6) | **Weak, and appropriately so**: recovery is largely an operational discipline; telemetry scopes it but does not perform it |

Coverage is strongest where this document concentrates (**DETECT**, **RESPOND**) and weakest where its priorities place least weight (**RECOVER**, the organizational half of **GOVERN**). That follows the [D > R > Q > A ordering](CoSAI-AI-Telemetry-RFC.md#41-detection-first), and it shows which CSF outcomes this field set will and will not evidence.

### 7.3 AI RMF mapping, by function


| AI RMF function | Telemetry that evidences it | Coverage |
| :---- | :-------------------------------------------------------- | :----------------------------------------- |
| **GOVERN** | Autonomy level (AD §1.1); task/intent declaration (AD §1.5); tool ACL and scope (AD §1.3); human approval events (AD §1.3) | Partial: **Human Approval / Elicitation** (AD §1.3) is the strongest single piece of GOVERN evidence, because it records oversight *actually exercised* rather than merely documented |
| **MAP** | Component taxonomy (the CoSAI Risk Map [[23]](#standards--frameworks) component that emits each field, AD §1); AgBOM (AD §1.6); trust boundaries (AD §1.3); [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) attack corpus | Strong: the risk-map component mapping and attack inventory are MAP artifacts in substance |
| **MEASURE** | **The whole field set.** Every MUST field; guardrail scores; refusal rates; loop and resource metrics; ATLAS-tagged detections | **The natural home.** AI RMF asks that AI risks be measured; this document specifies what to measure and why |
| **MANAGE** | Incident response fields (AD §§1.1, 1.3 and 1.6); enforcement decisions and taint (AD §1.3); kill-switch and lifecycle state (AD §1.6); [correlation patterns](Telemetry-Attack-Detection-Addendum.md#2-correlation-patterns) | Strong for security risk; silent on fairness, bias, and environmental risk, which are out of scope here |

**Scope note.** AI RMF's trustworthiness characteristics extend well beyond security: validity, fairness, bias management, interpretability, and environmental impact. **This document evidences the security slice only.** An organization using AI RMF should not read comprehensive MEASURE coverage into it. The `gen_ai.evaluation.*` conventions discussed in [§2.1](#21-what-it-is-and-the-version-mapped) are the natural carrier for the quality and fairness slice, which is one more reason to keep security guardrail signals distinguishable from quality evaluations rather than merging them.

### 7.4 What this implies


1. **Propose the field set as a reference implementation for the Cyber AI Profile's *Secure* focus area.** The Profile specifies outcomes for securing AI systems but not the telemetry that evidences them; this document supplies exactly that and is attack-grounded, which is the kind of justification a NIST community profile can cite. **This is the highest-value action in this appendix**, and the timing is favourable while the Profile is between preliminary and public draft.
2. **Publish a CSF subcategory-level mapping.** [§7.2](#72-csf-20-mapping-by-function) maps to Category granularity; auditors work at Subcategory granularity (106 subcategories). A per-subcategory mapping is mechanical work with real adoption value, and it is the single most requested artifact when a security framework meets a compliance programme.
3. **Do not reshape the field set to improve framework coverage.** The weak areas (RECOVER, organizational GOVERN) are weak because they are not telemetry problems. Adding fields to improve a coverage table would violate the [evidence rule](CoSAI-AI-Telemetry-RFC.md#47-tiers) and inflate the MUST tier for **A**-tier benefit.
4. **Track the AI RMF revision.** AI RMF 1.0 is under revision and the Generative AI Profile (AI 600-1) already extends it; if the revision adds agentic content, the [MEASURE](#73-ai-rmf-mapping-by-function) mapping should be re-checked against it.

---

## 8. Implications for ISO/IEC 42001


**ISO/IEC 42001:2023** specifies an **AI Management System (AIMS)**: a certifiable management-system standard in the ISO tradition, structured as management-system clauses 4 to 10 plus **Annex A**, a normative reference set of **38 controls under nine control objectives, A.2 to A.10**, selected through a **Statement of Applicability (SoA)**.

The relationship differs from every other appendix here, and the difference is the point:

- **NIST frameworks ask whether outcomes are achieved.** Telemetry is evidence.
- **ISO/IEC 42001 asks whether a *management system* exists, operates, and is improved.** Telemetry is evidence *and* the raw material for the monitoring, measurement, analysis and evaluation the standard requires of the system itself.

**42001 is also the only framework here that is certifiable.** That raises the bar on evidentiary quality: an auditor will ask not just whether telemetry exists but whether it is retained, access-controlled, and demonstrably used as an input to management review. That is a records-management property, not a field-selection property, and it is where this document is thinnest.

### 8.1 Annex A mapping


> **Granularity and sourcing.** This mapping is drawn at **control-objective** level. The objective structure it rests on (nine objectives numbered A.2 to A.10, 38 controls between them) is corroborated across independent public summaries of Annex A. The **individual control identifiers** named below and in [§8.3](#83-what-this-implies) (`A.4.2`, `A.4.5`, `A.5.4`, `A.5.5`, `A.6.2.8`, `A.7.4`, `A.8.4`, `A.9.3`) are **indicative**: ISO/IEC 42001 is a paid standard, those identifiers were taken from public summaries rather than from the purchased text, and numbering *within* an objective is where secondary sources are least reliable. Verify each against the standard before citing this mapping in a Statement of Applicability or treating it as normative. The objective-level mapping does not depend on them.

| Annex A objective | Telemetry that evidences it | Coverage |
| :----------- | :----------------------------------------------------- | :------------------------------------ |
| **A.2 Policies related to AI** | System prompt / instruction config (AD §1.1) as the enforced expression of policy; authorization decision record and rule identity (AD §1.3) | Partial: AD §1.3 evidences policy *in force*, which is stronger than a policy document |
| **A.3 Internal organization** | Creator, oncall, ownership metadata (AD §1.6) | Weak: organizational, not telemetric |
| **A.4 Resources for AI systems** | AgBOM and dependency graph (AD §1.6); model, tool, memory and knowledge inventory (AD §§1.1, 1.3 and 1.4); token, compute and storage aggregates (AD §1.5) | **Strong**: the AgBOM cluster is an A.4 artifact almost exactly; A.4.2 *Resource documentation* and A.4.5 *System and computing resources* are directly served |
| **A.5 Assessing impacts of AI systems** | [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) attack corpus; guardrail and refusal rates as realized-impact measures | Partial: supplies the security input to impact assessment, not the assessment |
| **A.6 AI system life cycle** | **Event logs (A.6.2.8) is the direct hit**: AD §1 in their entirety; capability-set change (AD §1.6) for change control; verification via evaluation and guardrail records | **Strongest alignment.** 42001 requires event logging without specifying content; this document specifies the content |
| **A.7 Data for AI systems** | Retrieval provenance (AD §1.4); memory provenance (AD §1.4); input source and trust classification (AD §1.2); data classification constraints (AD §1.6) | **Strong**: A.7's provenance and quality controls are served by the provenance fields, which exist here for detection reasons and satisfy A.7 as a by-product |
| **A.8 Information for interested parties** | Incident-response evidence (AD §§1.1, 1.3 and 1.6); ATLAS-tagged detections (AD §1.2) supporting incident communication | Partial: supplies substance for A.8.4 incident communication; the communication process itself is out of scope |
| **A.9 Use of AI systems** | Autonomy level (AD §1.1); task/intent declaration (AD §1.5); human approval events (AD §1.3); trigger type (AD §1.1); surface (AD §1.1) | **Strong**: A.9's *intended use* and *responsible use* controls are evidenced by exactly the fields that detect goal drift |
| **A.10 Third-party and customer relationships** | MCP server identity (AD §1.3); peer agent card (AD §1.5); provider identity (AD §1.1); model provenance (AD §1.1); delegation chain (AD §1.6) | **Strong**: third-party AI dependencies are visible through the tool, MCP, A2A and supply-chain fields |

### 8.2 Where this document is thin, and what would fix it


Three of the four weak areas are properly out of scope. The fourth is a genuine gap.

1. **Organizational controls (A.3, parts of A.2, A.8)** are roles, reporting lines and communication processes. Not telemetry. Out of scope, correctly.
2. **Impact assessment (A.5)** is a *process* control. This document supplies inputs; it should not attempt the assessment.
3. **Non-security trustworthiness**, fairness, bias, and societal impact under A.5.4 and A.5.5, is outside this document's remit, as it is for [AI RMF](#73-ai-rmf-mapping-by-function).
4. **Records management is a real gap.** 42001 clause 7.5 (documented information) and clause 9 (monitoring, measurement, analysis and evaluation; internal audit; management review) require telemetry to be *retained, controlled, and demonstrably used*. This document leaves retention, access control and chain of custody to a later CoSAI publication ([RFC §2.2](CoSAI-AI-Telemetry-RFC.md#22-not-in-scope)), so it specifies none of the **evidentiary properties** those clauses need: immutability, defined retention periods per field class, chain of custody, or reviewer access records. **Event Sequence Continuity** (AD §1.6) is the nearest thing and is SHOULD. **Recommendation:** if CoSAI wants this field set to be usable as certification evidence, that later publication should set per-tier retention minimums in a normative table.

### 8.3 What this implies


1. **Position the field set as the content specification for the Annex A event-logging control** (`A.6.2.8` as public summaries number it). 42001 requires event logging across the AI life cycle without saying what to log. This is the clearest single fit between the two documents, and (as with the Cyber AI Profile) it lets an organization satisfy a standard using telemetry it built for detection. The position turns on A.6 containing an event-logging requirement that specifies no content, which is corroborated independently of the control's number; if the purchased text numbers it differently, the argument moves with it unchanged.
2. **Map to Statement of Applicability granularity.** SoA is where 42001 implementation happens. A mapping at individual-control level (A.6.2.8, A.7.4, A.9.3 …) rather than objective level would let an organization cite specific fields per control. Same recommendation, and same mechanical-but-valuable character, as the CSF subcategory mapping in [§7.4](#74-what-this-implies). One prerequisite differs: at individual-control granularity the numbering is load-bearing, so that work needs the purchased text rather than the public summaries this appendix was built from.
3. **Close the records-management gap** if certification evidence is a goal, see [§8.2](#82-where-this-document-is-thin-and-what-would-fix-it) item 4. This is the one place where a compliance framework surfaces a genuine weakness rather than an out-of-scope boundary.
4. **Reuse, do not re-derive.** ISO/IEC 42001 and NIST AI RMF overlap substantially; organizations frequently run both. The mappings in [§7](#7-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile) and here should share a single underlying field→control table with two views, rather than diverging.

> **The through-line for both appendices.** These frameworks are **consumers** of this telemetry, not designers of it. The document's value to them is that a field set built to catch documented attacks turns out to evidence a large share of what they ask for, and that the evidence carries attack grounding, which is more defensible under audit than a control asserted to exist. The direction of derivation should not reverse: **do not add fields to improve a coverage table.**

---

## References

### Standards & frameworks

23. **CoSAI Risk Map**: Coalition for Secure AI, fine-grained AI system components taxonomy. <https://github.com/cosai-oasis/secure-ai-tooling/tree/main/risk-map>. Identifiers are resolved against `develop` at commit `37e7bed` (30 September 2026). Those not yet on `develop` are proposals: most come from PR [#507](https://github.com/cosai-oasis/secure-ai-tooling/pull/507), open and in draft; `riskAgentMemoryPoisoning`, `riskDeceptiveAgentReporting`, `riskCrossAgentReputationPoisoning`, `riskErroneousAgentAction` and `controlMemoryReferentRevalidation` come from issues [#524](https://github.com/cosai-oasis/secure-ai-tooling/issues/524) to [#527](https://github.com/cosai-oasis/secure-ai-tooling/issues/527), proposed on a branch stacked on #507 (commit `0e9601d`).
24. **CoSAI MCP Security**: Coalition for Secure AI, Workstream 4 (Secure Design Patterns for Agentic Systems): *Model Context Protocol (MCP) Security*, approved 8 January 2026. Twelve threat categories (MCP-T1…T12), ~40 threats. <https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf>
25. **AITF**: AI Telemetry Framework (OTel + OCSF binding), donated to CoSAI WS2. <https://github.com/cosai-oasis/ws2-defenders/tree/main/telemetry>
26. **ODIS**: Coalition for Secure AI, Workstream 4: *Open Delegation & Identity Standard*. Apache-2.0. Records defined in ODIS §6: Agent Registration Record (6.1), Agent Runtime Credential Descriptor (6.2), Delegation Record (6.3), Identity Context (Policy Engine Feed) (6.4). Cited at commit `148dc41` (8 September 2026); ODIS is a working draft, so this reference is pinned to a commit rather than to `main` to keep the section numbers and field names in [XM §6](Telemetry-Cross-Mapping-Addendum.md#6-odis) checkable. <https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md>

<!-- list break: reference numbers are not contiguous -->

29. **MITRE ATT&CK**: adversary tactics & techniques knowledge base (ATLAS-aligned). MITRE. <https://attack.mitre.org/>
30. **NIST AI Risk Management Framework (AI RMF 1.0)**: NIST, January 2023; **currently under revision**. GOVERN / MAP / MEASURE / MANAGE. <https://www.nist.gov/itl/ai-risk-management-framework> · companion **NIST AI 600-1, Generative AI Profile** (July 2024). Mapped in [XM §7](Telemetry-Cross-Mapping-Addendum.md#7-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile).
31. **NIST Cybersecurity Framework (CSF) 2.0**: GV / ID / PR / DE / RS / RC; 6 functions, 22 categories, 106 subcategories. <https://www.nist.gov/cyberframework>
32. **NIST Cyber AI Profile**: *Cybersecurity Framework Profile for Artificial Intelligence: NIST Community Profile*, **NIST IR 8596**, *initial preliminary draft* published 16 December 2025; CSF 2.0 community profile overlaying the **Secure / Defend / Thwart** AI focus areas. Comment period closed 30 January 2026; working sessions held April and May 2026; **no Initial Public Draft as of 11 September 2026**. <https://csrc.nist.gov/pubs/ir/8596/iprd> · project: <https://www.nccoe.nist.gov/projects/cyber-ai-profile>
33. **ISO/IEC 42001:2023**: *Information technology — Artificial intelligence — Management system.* Clauses 4 to 10 plus **Annex A** (38 controls under 9 objectives, A.2 to A.10) selected via a Statement of Applicability. Paid standard. <https://www.iso.org/standard/42001>. Mapped in [XM §8](Telemetry-Cross-Mapping-Addendum.md#8-implications-for-isoiec-42001).

<!-- list break: reference numbers are not contiguous -->

35. **OpenTelemetry, GenAI semantic conventions.** Now maintained in a dedicated repository: <https://github.com/open-telemetry/semantic-conventions-genai>. Spans, metrics, events, MCP, and provider-specific conventions, **all at Development status**. Attribute registry: <https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/>. Entries marked *Deprecated* there mostly reflect the relocation rather than withdrawal, but not always: some were **renamed** in the move (`gen_ai.usage.cache_creation.input_tokens` → `gen_ai.usage.cache_write.input_tokens`) and some were **withdrawn outright** (`gen_ai.prompt` and `gen_ai.completion`, both `reason: obsoleted`, "Removed, no replacement at this time"). Names therefore come from the new repository, not the deprecated registry. **Names in XM §§2 to 3 were verified against `semantic-conventions-genai` @ `0c87594` (10 September 2026) and `semantic-conventions` @ `22b6cbb` (9 September 2026); neither repository publishes release tags, so commit SHAs are the only stable anchor.** Cross referenced in [XM §2](Telemetry-Cross-Mapping-Addendum.md#2-opentelemetry).
36. **OpenTelemetry, core specification.** Signals, context propagation, sampling. <https://opentelemetry.io/docs/specs/otel/> · **W3C Trace Context**: <https://www.w3.org/TR/trace-context/> · MCP context propagation via `params._meta` (Specification Enhancement Proposal **SEP-414**): <https://modelcontextprotocol.io/community/seps/414-request-meta>
37. **OCSF. Open Cybersecurity Schema Framework.** <https://ocsf.io/> · schema browser: <https://schema.ocsf.io/>
38. **OWASP AOS, Agent Observability Standard.** OWASP. <https://aos.owasp.org/>. Three pillars (Instrument / Trace / Inspect); cross referenced in [XM §4](Telemetry-Cross-Mapping-Addendum.md#4-owasp-aos-cross-reference). *Working draft.* Verified against the specification sources at commit `e4a50f6` (30 December 2025), schema version **0.1.0** (`specification/AOS/aos_schema.json` in [OWASP/www-project-agent-observability-standard](https://github.com/OWASP/www-project-agent-observability-standard)); the specification has not changed since that date.
39. **Model Context Protocol (MCP).** <https://modelcontextprotocol.io/>. Tools, resources, prompts, sampling, elicitation, roots (AD §1.3).
40. **A2A, Agent-to-Agent Protocol.** <https://a2a-protocol.org/>. Agent cards, task lifecycle, push-notification configuration (AD §1.5).
41. **CycloneDX**: OWASP BOM standard, incl. ML-BOM. <https://cyclonedx.org/>
42. **SPDX**: Linux Foundation software bill-of-materials standard. <https://spdx.dev/>
43. **SWID**: ISO/IEC 19770-2 software identification tags. <https://csrc.nist.gov/projects/Software-Identification-SWID>
44. **CPEX**: policy-enforcement runtime and reference monitor for AI agents. <https://contextforge-org.github.io/cpex/> · threat model: <https://contextforge-org.github.io/cpex/docs/threat-model/>, cross referenced in [XM §5](Telemetry-Cross-Mapping-Addendum.md#5-cpex-cross-reference). Verified against [contextforge-org/cpex](https://github.com/contextforge-org/cpex) at commit `035012f` (18 August 2026). Pinned to a commit rather than to the current release (`v0.2.2`, 15 July 2026), which predates the threat-model document this appendix cites.

<!-- list break: reference numbers are not contiguous -->

47. **SPIFFE / SVID**: Secure Production Identity Framework for Everyone (workload identity). <https://spiffe.io/>

<!-- list break: reference numbers are not contiguous -->

49. **Cedar**: authorization policy language. <https://www.cedarpolicy.com/> · **Open Policy Agent (Rego)**. <https://www.openpolicyagent.org/>

<!-- list break: reference numbers are not contiguous -->

53. **RFC 9943**: *An Architecture for Trustworthy and Transparent Digital Supply Chains* (SCITT). Standards Track. <https://www.rfc-editor.org/rfc/rfc9943.html>
54. **RFC 9942**: *CBOR Object Signing and Encryption (COSE) Receipts.* Standards Track, June 2026. <https://www.rfc-editor.org/rfc/rfc9942.html>
