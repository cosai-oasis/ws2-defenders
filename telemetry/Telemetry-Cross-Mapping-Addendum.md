# Telemetry for AI Security: Cross-Mapping Addendum {**Working Draft v0.5**}

**Status:** Request for Comments, revision 0.5
**Origin:** Coalition for Secure AI (CoSAI), Workstream 2 (Defenders)
**Companion to:** [Telemetry for AI Security](CoSAI-AI-Telemetry-RFC.md) (cited as RFC); see also the [Attack Detection Addendum](Telemetry-Attack-Detection-Addendum.md) (cited as AD).

---

### For the open source security community

Each section below states what the field set already maps onto in one adjacent specification, what that specification cannot currently express, and the additions proposed.

| Community | Section | What is proposed |
| :------------- | :---- | :-------------------------------------------------------------------------------------- |
| **OpenTelemetry** [[35]](#standards--frameworks) | §2 | 9 attribute proposals: input trust classification, a security guardrail signal, memory provenance and footprint, retrieval provenance, turn and step identifiers |
| **OCSF** [[37]](#standards--frameworks) | §3 | 4 asks: two AI event classes (tracking ocsf-schema#1640), extensions to the existing `ai_operation` profile (ocsf-schema#1704 and #1729 in flight), new objects and enums; ATLAS technique tagging needs no schema change |
| **CoSAI Risk Map (WS3)** [[23]](#standards--frameworks) | §1 | 3 refinements: confirm `componentMemory` covers persistent long-term memory, add a component for background and scheduled execution, and require the ATLAS technique tag on `controlThreatDetection` |
| **OWASP AOS** [[38]](#standards--frameworks) | §5 | 9 contributions: trust classification, egress destination, ATLAS tagging, priority tiering, and migration of its OTel binding from `llm.*` to `gen_ai.*` |
| **CPEX** [[44]](#standards--frameworks) | §6 | 6 contributions: retention and priority guidance, and a SOC destination for enforcement decisions |

**AITF** [[25]](#standards--frameworks), the AI Telemetry Framework, donated to CoSAI Workstream 2, is the bridge between this document and both of those destinations, OpenTelemetry for emission, OCSF for consumption. It carries these fields as OpenTelemetry attributes today and emits them into OCSF ahead of formal ratification, so adopters are not blocked on either standards body. The field-level mapping is **§4**. **NIST** (AI RMF and CSF, including the Cyber AI Profile) and **ISO/IEC 42001** are consumers of this field set rather than destinations for proposals, so they are not in the table above; their mappings are [§7](#7-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile) and [§8](#8-implications-for-isoiec-42001).

- **The proposals are evidence-gated and therefore small.** A field becomes a standardization ask only once two or more independent documented attacks require it. Nothing is proposed speculatively.
- **Emission and consumption move together.** A field OpenTelemetry emits but OCSF cannot represent arrives at the SIEM as unstructured overflow; a field OCSF defines but no instrumentation produces stays theoretical. Paired asks are the intent.

CoSAI is engaging the **OpenTelemetry** and **OCSF** communities directly on this work, and welcomes input from the wider open source security community in turn. The timing favours it: every OpenTelemetry GenAI convention is at *Development* status and has just moved to a dedicated repository, so contributions land more cheaply now than after stabilization.

What is wanted in return: corrections to the mappings, and attacks the corpus is missing.

### Agents you do not operate

[RFC §4.6](CoSAI-AI-Telemetry-RFC.md#46-agents-you-do-not-operate) sets knowability tiers for counterparties the deployment does not run. Each adjacent standard supplies one of the rules behind them.

**From CPEX: the counterparty is on the hostile side of the monitor, by definition.** CPEX's boundary places the agent, the caller, and everything beyond it in the untrusted region, and admits nothing from there into policy. An external agent is simply the clearest case. The consequence for telemetry is that you instrument **your own boundary**, not their internals, and CPEX's inbound-gateway placement is the one that sees every caller. What you record is a mediated interaction, not an observed agent.

**From ODIS: authority becomes legible through presented claims, not through inspection.** You cannot audit an external agent's reasoning, but you can require it to present a verifiable delegation record: originating principal, chain, granted authorizations, constraints. This is why `trust_domain` and delegation depth are detection-grade rather than mere policy-engine inputs the moment a chain leaves your domain (see AD §1.9).

**From OWASP AOS: ask the counterparty to be inspectable, and record the answer.** AOS's *Observed Agent* is one that exposes hooks, events, and an AgBOM on request; an external agent is an **unobserved** agent until it agrees otherwise. AOS's A2A extension already distinguishes full from partial counterparty context, which is the same distinction as knowing versus not knowing who you are talking to. Whether an inspection request was answered is itself a signal.

---

## 1. Mapping to the CoSAI Risk Map (risks & controls)

*Does this telemetry work imply changes to the [CoSAI Risk Map](https://github.com/cosai-oasis/secure-ai-tooling/tree/main/risk-map)?* The risk map has expanded considerably, from 36 risks and 37 controls to **55 risks and 68 controls**, and the expansion, driven largely by review of CoSAI's [MCP Security paper](https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf) (WS4, approved 8 January 2026), lands directly on the agentic surface this document instruments. Every risk and control this field set requires is present in the risk map, so this appendix is a mapping rather than a set of asks. What remains open is a small number of component and control refinements, in [§1.3](#13-component--control-refinements).

> **Version basis.** This mapping is built against the risk map with PR [#507](https://github.com/cosai-oasis/secure-ai-tooling/pull/507) merged, plus `riskAgentMemoryPoisoning`, `riskDeceptiveAgentReporting`, `riskUnsafeInterAgentPropagation` and `controlAgentMemoryIntegrity`: **55 risks and 68 controls**. Risk IDs use the `risk` + camelCase convention. Verify IDs against `main`.

### 1.1 Controls this telemetry operationalizes

This document is, in effect, the implementation spec for the risk map's **detection and observability** controls; those that require logging without specifying fields:

- **`controlAgentObservability`**: "an agent's actions, tool use, and reasoning are transparent and auditable through logging." → AD §§1.1, 1.3, 1.5, 1.8, 1.9 fields.
- **`controlThreatDetection`**: detect and alert on attacks against AI assets. → all MUST fields + the [ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping).
- **`controlAuditTrailCompleteness`**: → **Instrumentation Coverage / Hook Attestation** (AD §1.11) is the field that evidences completeness rather than asserting it.
- **`controlAuditTrailIntegrityVerification`**: → **Event Sequence Continuity** (AD §1.11).
- **`controlAIInfrastructureObservability`**: → AD §§1.4, 1.8, 1.10 resource, loop, and inventory signals.
- **`controlAgentMemoryIntegrity`**: provenance, integrity and isolation of persistent memory. → AD §1.6 **Memory Write Event**, **Memory Read / Injection Event** and **Memory Provenance / Source**, the field that separates a legitimate write from an implant.
- **`controlIncidentResponseManagement`**: post-incident forensics. → content, tool I/O, identity, memory and retrieval provenance.
- **`controlVulnerabilityManagement`**, **`controlRiskGovernance`**, **`controlAIComponentPatchManagement`**: fleet monitoring and residual-risk measurement. → AD §1.10 aggregates, version and provenance.

**Recommendation:** have `controlAgentObservability`, `controlThreatDetection`, the audit-trail controls and `controlAgentMemoryIntegrity` reference this field set **by tier** as their normative telemetry schema, rather than each deployment reinventing it.

### 1.2 Telemetry cluster → risk → control

| Telemetry cluster (§) | Risks it detects or evidences | Controls it operationalizes |
| :---------------- | :------------------------------------ | :------------------------------------ |
| Execution context & agent identity (AD §1.1) | `riskRogueActions`, `riskShadowAndUnknownAgents`, `riskDeceptiveAgentReporting`, `riskConcentratedAccessCorrelation`, `riskCrossTenantCredentialPropagation` | `controlAgentInventoryManagement`, `controlAgentObservability` |
| Input handling & trust provenance (AD §1.2) | `riskPromptInjection`, `riskModelEvasion`, `riskRetrievalVectorStorePoisoning`, `riskImplicitCrossBoundaryTrust` | `controlInputValidationAndSanitization`, `controlUntrustedContextContainment`, `controlThreatDetection` |
| Output handling & egress (AD §1.3) | `riskSensitiveDataDisclosure`, `riskInsecureModelOutput`, `riskCovertChannelsInModelOutputs`, `riskExcessiveNetworkExposure` | `controlOutputValidationAndSanitization`, `controlNetworkEgressControl` |
| Model & serving (AD §1.4) | `riskModelSourceTampering`, `riskModelDeploymentTampering`, `riskModelExfiltration`, `riskDenialOfMLService`, `riskEconomicDenialOfWallet`, `riskAdapterPEFTInjection`, `riskMaliciousLoaderDeserialization` | `controlModelAndDataIntegrityManagement`, `controlModelRegistryIntegrity`, `controlMessageAndPayloadResourceLimits` |
| Tools & MCP (AD §1.5) | `riskRogueActions`, `riskInsecureIntegratedComponent`, `riskToolRegistryTampering`, `riskToolSourceProvenance`, `riskMCPTransportHijacking`, `riskZombieShadowMCPServers`, `riskUnsandboxedCodeExecution`, `riskUntrustedHostToolRuntimeExposure`, `riskOverScopedToolAuthority`, `riskAgenticToolSupplyChain` | `controlToolServerVetting`, `controlToolServerSupplyChainIntegrity`, `controlRuntimeHostIsolation`, `controlToolArgumentValidationAndSanitization`, `controlAgentPluginPermissions`, `controlInterComponentTransportSecurity` |
| Memory (AD §1.6) | `riskAgentMemoryPoisoning`, `riskPromptResponseCachePoisoning`, `riskLongLivedSessionStateWeakness`, `riskDataPoisoning` (loose) | `controlAgentMemoryIntegrity`, `controlUntrustedContextContainment`, `controlRetrievalAndVectorSystemIntegrity` (partial) |
| RAG / retrieval (AD §1.7) | `riskRetrievalVectorStorePoisoning` | `controlRetrievalAndVectorSystemIntegrity`, `controlInputValidationAndSanitization` |
| Orchestration & multi-agent (AD §1.8) | `riskRunawayAgentToolLoops`, `riskDenialOfMLService`, `riskEconomicDenialOfWallet`, `riskOrchestratorRouteHijacking`, `riskImplicitCrossBoundaryTrust`, `riskUnsafeInterAgentPropagation` | `controlAgentExecutionBounds`, `controlOrchestratorAndRouteIntegrity`, `controlAgentCapabilityNegotiation` |
| Identity, delegation & attestation (AD §1.9) | `riskAgentDelegationChainOpacity`, `riskAgentIdentitySpoofing`, `riskAgenticDelegationConfusedDeputy`, `riskStaleAgentIdentityBinding`, `riskCredentialAndTokenTheft`, `riskLongLivedSessionStateWeakness`, `riskConfidentialComputingAttestationBypass` | `controlComponentIdentityAuthentication`, `controlComponentIdentityRegistration`, `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlSenderConstrainedCredentials`, `controlSessionCredentialBindingAndLifecycle`, `controlAgentCredentialIsolation` |
| Asset inventory & fleet (AD §1.10) | `riskShadowAndUnknownAgents`, `riskZombieShadowMCPServers`, `riskToolRegistryTampering`, `riskAgenticToolSupplyChain` | `controlAgentInventoryManagement`, `controlToolRegistryAndDiscoveryIntegrity`, `controlThirdPartyCapabilityAdmission`, `controlAIComponentPatchManagement` |
| Observability-plane integrity (AD §1.11) | `riskAuditTrailTampering` | `controlAuditTrailCompleteness`, `controlAuditTrailIntegrityVerification`, `controlAuditRecordRepositoryIndependence` |
| Policy enforcement & mediation (AD §1.12) | `riskBrokenAuthorizationEnforcement`, `riskUnconsentedAgentAction`, `riskConsentFatigue`, `riskOverScopedToolAuthority`, `riskAgenticDelegationConfusedDeputy`, `riskImplicitCrossBoundaryTrust` | `controlTrustedPolicyEnforcementPoint`, `controlExternalizedAuthorizationDecisioning`, `controlInformedAgentConsentSurface`, `controlResourceAuthorizationEnforcement`, `controlAgenticZeroTrustPosture` |

### 1.3 Component & control refinements

- **No new pipeline components required.** `componentMemory` and `componentRAGContent` exist. Two clarifications stand: confirm `componentMemory` scope explicitly covers *persistent long-term* memory, which `riskAgentMemoryPoisoning` targets; and note that **background and scheduled execution** (heartbeats, cron, self-scheduled loops; AD §1.8) still has no dedicated component, despite being a distinct autonomy surface (`AOC-04`, `AOC-10`).
- **Identity and delegation is now well covered by controls.** The recommendation to document an identity/delegation control-plane view is largely satisfied by `controlComponentIdentityAuthentication`, `controlComponentIdentityRegistration`, `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, and `controlSenderConstrainedCredentials`. AD §1.9 telemetry now has an explicit home.
- **`controlAuditRecordRepositoryIndependence` intersects this document's stated scope boundary.** [RFC §2.2](CoSAI-AI-Telemetry-RFC.md#22-not-in-scope) excludes securing the telemetry pipeline and defers it to subsequent work. That control now names part of the problem (repository independence from the workload being recorded) which strengthens the case for taking the deferred work up, and gives it a control to map onto when it is.
- **The audit-trail controls are where defending the telemetry plane lands.** The CoSAI Risk Map reaches the same conclusion from the control side, carrying `controlAuditTrailCompleteness`, `controlAuditTrailIntegrityVerification` and `controlAuditRecordRepositoryIndependence`; RFC AD §1.11 is the telemetry those controls presuppose. The realization those controls describe is a signed head or checkpoint published to a witness outside the emitter's trust domain; **RFC 9943** [[53]](#standards--frameworks) and **RFC 9942** [[54]](#standards--frameworks) are the standards form of it. Naming the exit keeps RFC AD §1.11 a hand-off rather than a gap, without committing the field set to a format.
- **Augment `controlThreatDetection`** to require the **ATLAS technique tag** on emitted detections, tying this appendix to [§3](#3-implications-for-ocsf--aitf-the-standardization-bridge).

## 2. Implications for OpenTelemetry (the instrumentation bridge)

This appendix covers the OpenTelemetry emission side of the standards bridge; [§3](#3-implications-for-ocsf--aitf-the-standardization-bridge) covers OCSF consumption. AITF carries the interim binding between them, so the proposals should be sequenced together.

**Scope of the ask.** OpenTelemetry is not a security telemetry framework and should not become one. Its GenAI conventions are shaped by observability concerns, latency, cost, token accounting, evaluation quality, and that is the right centre of gravity. The argument here is narrower and, in this document's view, uncontroversial: **OTel's ubiquity means it is where AI instrumentation is being written**, so the subset of security-relevant fields that map cleanly onto its existing model should be added to the specification, so that deployments already running OTel get them by default rather than by bespoke effort. Fields that do not map cleanly, such as authorization decisions, delegation chains, and information-flow labels, are noted as such and left to OCSF and the [AOS](#5-owasp-aos-cross-reference) / [CPEX](#6-cpex-cross-reference) surfaces. **This appendix asks OTel to cover what OTel is already shaped to cover, and no more.**

> **Convention status.** The GenAI conventions **moved** out of the main `open-telemetry/semantic-conventions` repository into a dedicated **`open-telemetry/semantic-conventions-genai`** repository; the attributes still listed in the main registry are marked *Deprecated* to reflect that relocation, not abandonment. Every convention cited below carries **Status: Development**: none is stable, which is precisely why this is the moment to contribute.

### 2.1 What the GenAI conventions cover today

The conventions are richer than is commonly assumed, and several fields in fact have a natural OTel home already.

- **Spans.** `chat`, `text_completion`, `embeddings`, `generate_content`, `execute_tool`, `create_agent`, `invoke_agent` (client and internal variants), `invoke_workflow`, and a **`plan`** span, discriminated by `gen_ai.operation.name`.
- **Core attributes.** `gen_ai.provider.name`; `gen_ai.agent.id` / `.name` / `.description` / `.version`; `gen_ai.conversation.id`; `gen_ai.workflow.name`; `gen_ai.request.model` and the full decoding set (`temperature`, `top_p`, `top_k`, `max_tokens`, `stop_sequences`, `seed`, `frequency_penalty`, `presence_penalty`, `choice.count`, `stream`); `gen_ai.response.id` / `.model` / `.finish_reasons`; `gen_ai.usage.input_tokens` / `.output_tokens` / `.reasoning.output_tokens` / `.cache_read.input_tokens` / `.cache_write.input_tokens`.
- **Content and definitions.** `gen_ai.input.messages`, `gen_ai.output.messages`, **`gen_ai.system_instructions`**, **`gen_ai.tool.definitions`**, `gen_ai.tool.name` / `.description` / `.type` / `.call.id` / `.call.arguments` / `.call.result`, `gen_ai.output.type`, `gen_ai.prompt.name`.
- **Retrieval.** **`gen_ai.retrieval.query.text`**, **`gen_ai.retrieval.documents`**, `gen_ai.data_source.id`, `gen_ai.embeddings.dimension.count`.
- **Memory.** A **`gen_ai.memory.*`** namespace: `store.id`, `record.id`, `record.count`, `query.text`, `records`, with a `MemoryRecord` schema (`content`, `id`, `metadata`, `score`); seven memory operations on `gen_ai.operation.name` (`create_memory`, `create_memory_store`, `delete_memory`, `delete_memory_store`, `search_memory`, `update_memory`, `upsert_memory`); and a **`gen_ai.memory.client`** span, already implemented by `aws-bedrock-agentcore` and `google-adk`.
- **Evaluation.** A `gen_ai.evaluation.result` event with `gen_ai.evaluation.name`, `.score.value`, `.score.label`, `.explanation`.
- **Metrics.** `gen_ai.client.operation.duration`, `gen_ai.client.token.usage`, `gen_ai.client.operation.time_to_first_chunk` / `.time_per_output_chunk`, `gen_ai.execute_tool.duration`, **`gen_ai.invoke_agent.duration` / `.inference_calls` / `.tool_calls`**, `gen_ai.invoke_workflow.duration`, `gen_ai.server.request.duration` / `.time_to_first_token` / `.time_per_output_token`.
- **MCP.** A distinct **`mcp.*`** namespace: `mcp.method.name`, `mcp.protocol.version`, `mcp.resource.uri`, `mcp.session.id`, plus `mcp.client.operation.duration`, `mcp.server.operation.duration`, and client/server `session.duration` metrics.

Three existing GenAI attributes already close gaps this document had left open. `gen_ai.system_instructions` gives **System Prompt** (AD §1.1) a home. `gen_ai.tool.definitions` gives **Tool Definition Digest** (AD §1.5) one; the raw material for a digest is already in scope, and only the *hash-and-compare* is missing. And `gen_ai.invoke_agent.tool_calls` / `.inference_calls` are already the shape of **Loop / Step-Count Signal** (AD §1.8) and part of **Resource-Consumption Aggregate** (AD §1.8), as metrics rather than attributes.

### 2.2 Coverage & gaps, by field cluster

Where each cluster lands in OTel **today**, the gap, and the recommended change. Clusters are grouped by pipeline component; the tier tag records which tiers the identified gap spans, not the full tier mix of the underlying section.

| Field cluster (tier) | OTel today | Gap | Recommended OTel change |
| :---------- | :------------------ | :--------------------- | :---------------------------------------------------- |
| Execution context & agent identity (MUST / SHOULD) | `gen_ai.agent.*`, `gen_ai.conversation.id`, `gen_ai.workflow.name`; span hierarchy | No turn/step identifier; no trigger type; no tenant; no surface | Add `gen_ai.turn.id` / `gen_ai.step.id`; `gen_ai.trigger.type` (`user_initiated` / `autonomous`) + `gen_ai.trigger.event`; adopt existing tenant/resource attrs |
| Prompt / response / system prompt (MUST) | `gen_ai.input.messages`, `gen_ai.output.messages`, `gen_ai.system_instructions` | **Covered.** Gated behind content-capture opt-in | Keep; ensure a **hash-only** capture mode exists (see [§2.5](#25-context-propagation-sampling--privacy-three-operational-traps)) |
| Content modality & attachments (MUST) | Message parts carry types | No attachment name/size/**hash** | Add attachment identity attrs on message parts; hash especially, as it survives redaction |
| Input trust classification (MUST) | n/a | **No trust-provenance concept at all** | Add `gen_ai.input.trust_level` (trusted-instruction / trusted-data / untrusted-instruction / untrusted-data) per message part |
| Guardrail verdicts (MUST) | `gen_ai.evaluation.*`: quality-oriented | No security guardrail verdict, blocked flag, or threat classification | **Extend the evaluation event for security use**, or add `gen_ai.guardrail.*` (type, verdict, score, blocked, threat technique), see [§2.3](#23-what-cosai-asks-opentelemetry-to-include) item 2 |
| Citations (MUST) | `gen_ai.retrieval.documents` exists | Output-side citations not linked to retrieved items | Add citation attrs on output messages with a resolution flag against retrieval |
| Model & serving (SHOULD) | `gen_ai.request.*` decoding set, `gen_ai.provider.name`, `gen_ai.response.*` | **Inference Parameters fully covered.** No model provenance/signing | Add `gen_ai.model.hash` / `.signature` / `.source` (supply-chain) |
| Token counts & resource aggregates (MUST) | `gen_ai.client.token.usage`, `gen_ai.invoke_agent.*` metrics | **Largely covered** | Add per-run budget/threshold semantics; document security use of the loop metrics |
| Tools & MCP (MUST / SHOULD) | `gen_ai.tool.*` incl. `definitions`, `call.id`, `call.arguments` and `call.result`; an `mcp.*` namespace covering `method.name`, `protocol.version`, `resource.uri`, `session.id` and duration metrics | No tool-definition **digest**; no MCP **primitive** discriminator; no sandbox/isolation attrs | Add `gen_ai.tool.definitions.hash`; add an `mcp.primitive` value set (tool / resource / prompt / sampling / elicitation / roots), `mcp.method.name` partially serves; add execution-environment attrs (`sandbox`, runtime, egress policy) |
| Memory (MUST) | **`gen_ai.memory.*`**: `store.id`, `record.id`, `record.count`, `query.text`, `records`; seven memory operations on `gen_ai.operation.name`; a `gen_ai.memory.client` span | Operation and item identity are **covered**. No **provenance** and no **footprint** attribute exists anywhere in the `gen_ai` registry | Add **provenance** and **footprint** attributes to the existing `gen_ai.memory.*` namespace |
| Retrieval / RAG (MUST / SHOULD) | `gen_ai.retrieval.query.text`, `.documents`, `gen_ai.data_source.id` | No per-item **source/provenance**, freshness, or integrity signal | Add provenance and last-modified attrs to retrieval document entries |
| Output egress (MUST) | n/a | No link from model output to destination | Correlate via existing HTTP/network semconv on the child span; document the pattern |
| Orchestration & multi-agent (MUST) | `invoke_agent`, `invoke_workflow`, `plan` spans; agent metrics | No inter-agent message attrs; no background-task/termination-condition signal | Add inter-agent messaging attrs; treat scheduled/self-triggered runs via `gen_ai.trigger.type` |
| Identity & delegation (SHOULD) | n/a | No principal, delegation chain, scope, or attestation | **Out of natural scope for OTel**: carry via OCSF Authentication/Delegation; see [§2.3](#23-what-cosai-asks-opentelemetry-to-include) note |
| Asset inventory & AgBOM (MUST / SHOULD) | Resource attributes, partially | No capability-change event; no BOM reference | Add a capability-change event; reference an external BOM by URI/digest rather than embedding it |
| Policy enforcement & mediation (MUST / SHOULD) | n/a | No authorization decision, taint, approval, or attribute-provenance concept | **Out of natural scope for OTel**: carry via OCSF `ai_authorization` / `ai_taint` / `ai_approval` ([§3.2](#32-what-cosai-asks-ocsf-to-include-summary)) |
| Observability-plane integrity (SHOULD) | n/a | No enforcement-availability or instrumentation-coverage representation | Partially natural: OTel can record hook coverage as a resource attribute; enforcement outcomes belong to OCSF |

### 2.3 What CoSAI asks OpenTelemetry to include

Ordered by ratio of security value to specification cost. Every item is scoped to something OTel already models, and the two clusters that are *not* a natural fit are named as such rather than pushed.

1. **A trust-provenance attribute on message parts.** `gen_ai.input.trust_level` (trusted-instruction / trusted-data / untrusted-instruction / untrusted-data), crossing origin authority with whether the segment was consumed as instruction or as data. **`untrusted-instruction` is the attack state**: `TA-01` is untrusted email content promoted to instruction. The enum carries provenance only; detector verdicts belong on the **Guardrail (Input) Verdict** (AD §1.2). This is the single highest-value addition and the one with no current analogue anywhere in the conventions. It is cheap (an enum on an existing structure) and it is the field the CoSAI Risk Map treats as the core agentic control (AD §1.2).
2. **A security-guardrail signal, ideally by extending `gen_ai.evaluation.*`.** The evaluation event already carries name, score, label, and explanation, the right shape for a classifier verdict. What it lacks is the security semantics: a **blocked / allowed** outcome, a guardrail **type**, and a **threat technique** reference. Reusing evaluation avoids a parallel namespace; the alternative is a dedicated `gen_ai.guardrail.*`. Either way, this is the field that makes classifier *bypass* detectable (`TA-01`).
3. **Memory provenance and footprint, on the existing `gen_ai.memory.*` namespace.** `gen_ai.memory.*` carries store and record identity, query text, record count, seven memory operations and a `gen_ai.memory.client` span ([§2.1](#21-what-the-genai-conventions-cover-today)). Operation and item identity are therefore covered; **provenance** and **footprint** are not, and neither appears anywhere in the `gen_ai` registry. Memory remains a MUST cluster here (AD §1.6), with `IR-02` and `IR-05` as direct grounding and `AOC-05` for footprint.
4. **Retrieval provenance.** `gen_ai.retrieval.documents` exists; per-document **source, owner, trust level, and last-modified** do not, and `TA-09` turns specifically on recently-modified retrievable content.
5. **Turn and step identifiers.** `gen_ai.conversation.id` and `gen_ai.workflow.name` exist; the intermediate levels do not. `TA-08` and `IR-01` are across-turn patterns (AD §1.1).
6. **`gen_ai.trigger.type` and `gen_ai.trigger.event`.** Whether a run was user-initiated or autonomous, and what event started it. `TA-01` is zero-click; this is the first filter of any injection hunt.
7. **Tool-definition digest and MCP primitive discriminator.** `gen_ai.tool.definitions` and `mcp.method.name` already carry the raw material; a stable hash attribute and an explicit primitive value set make definition drift and non-tool MCP surfaces queryable (AD §1.5).
8. **Attachment identity on content parts**: name, size, and hash. `AOC-12` is an image/OCR injection; `AOC-05` is attachment flooding.
9. **Model provenance attributes**: hash, signature, source, completing the supply-chain story that `gen_ai.request.model` starts.

**Two clusters this document deliberately does *not* ask OTel to adopt.** **Identity and delegation** (AD §1.9) and **policy enforcement** (AD §1.12) are authorization-domain concerns with mature homes elsewhere, OCSF Authentication, and the proposed `ai_authorization` / `ai_taint` / `ai_approval` objects in [§3.2](#32-what-cosai-asks-ocsf-to-include-summary). Pushing them into OTel would duplicate schema and invite drift. The one exception worth raising is **correlation**: an OTel span should be able to reference an authorization decision by ID so the two layers join at query time, which is a single attribute rather than a namespace. Two identity facts do have OTel homes and should be emitted there rather than in a private namespace: the originating principal as `audit.actor.id` / `audit.actor.type` (the OpenTelemetry audit data model draft, where it is MUST-level) and the acting agent as `gen_ai.agent.id` / `gen_ai.agent.name`. The OCSF transform is `actor.user.uid` and `ai_agent.uid` respectively.

### 2.4 Signal selection: traces, events/logs, metrics

OTel has three signal types and OCSF has one event model, so this guidance has no counterpart in [§3](#3-implications-for-ocsf--aitf-the-standardization-bridge), but getting it wrong is the most common way security telemetry becomes unusable or unaffordable.

| Signal | Use for | Fields from this document |
| :-------- | :-------------------------- | :------------------------------------------------------------------ |
| **Span attributes** | Low-cardinality identifiers and the execution skeleton | Agent/instance/run/session/turn/step IDs, action type, execution status, model and provider, tool name and type, trigger type, trust level, decision references |
| **Events / logs** | Content and anything high-cardinality, large, or privacy-bearing | Prompts, responses, system instructions, tool arguments and results, memory operations, retrieved documents, citations, guardrail verdicts, capability-change events |
| **Metrics** | Aggregates, budgets, and rate-based detections | Token usage, loop and step counts, tool-call rates, resource aggregates, guardrail block rates, deny rates |

Signal choice matters. The following rules correct mistakes that show up often when GenAI instrumentation is reused for security:

- **Never put content in span attributes.** Prompts, responses, and tool results are unbounded in size and often contain PII. OTel already models them as event bodies; keep them there. A span attribute carrying a full prompt breaks cardinality limits and leaks into every trace backend that samples the span.
- **Emit detection-relevant aggregates as metrics, not as derived queries.** Loop counts and token budgets (AD §1.8) are cheap as metrics and expensive as trace aggregations, and metrics survive sampling, which traces may not. With one qualification: a metric does not survive *with* the action record, so where an aggregate is what a decision turned on, the consumed and remaining figures belong on the decision as well (AD §§1.8, 1.12). The metric serves detection; the record on the action is what can be audited afterwards.
- **Cross-reference rather than duplicate.** A guardrail verdict event should carry the span and trace IDs, not a copy of the prompt it evaluated.

### 2.5 Context propagation, sampling & privacy: three operational traps

**Propagation is solved for MCP, and the mechanism should be adopted deliberately.** The MCP conventions specify that instrumentations SHOULD inject context into the MCP request **`params._meta`** property bag, with `traceparent`, `tracestate`, and `baggage` written unprefixed per **SEP-414**, and that the receiver uses the extracted context as the remote parent. That is exactly the mechanism **Trace Context (propagated)** (AD §1.1) requires, and it means cross-hop correlation over MCP is a matter of configuration rather than invention. Two cautions. First, HTTP-level propagation covers the HTTP request but **not** individual messages within a streaming request/response, a gap that matters for long-lived agent sessions. Second, and more important for security: **`baggage` crosses the trust boundary.** It is attacker-influenceable in exactly the way AD §1.12's provenance rule describes, so baggage may carry correlation identifiers but **must never carry trust levels, authorization decisions, taint labels, or identity claims**. Those come from the enforcement point, not from the wire.

**Sampling is the trap most likely to silently defeat this entire field set.** OTel's default is head-based sampling at some fraction of traces. Applied to security telemetry, that means *most attacks are simply not recorded*. Worse, the sample is drawn without regard to whether an event is security-relevant, so a guardrail block has the same chance of being discarded as a routine completion. The three requirements that follow (100% retention of security-relevant events, security relevance as a tail-sampling predicate, and recording the sampling configuration itself) are **normative** and stated in [RFC §5](CoSAI-AI-Telemetry-RFC.md#5-implementation-guidance). The rationale is that discarding a block or a denial is the same failure mode as fail-open enforcement ([AD §1.11](Telemetry-Attack-Detection-Addendum.md#111-observability-plane-integrity)), and deserves the same treatment.

**Privacy: content capture is opt-in, and that default is correct.** GenAI instrumentations gate message content behind an explicit capture setting, which aligns with this document's [privacy-preserving logging](CoSAI-AI-Telemetry-RFC.md#5-implementation-guidance) position. The gap is that capture is close to binary (on or off) where security work needs a **middle setting**: hashes and classifications without raw content, so that correlation (same payload across many sessions, same attachment hash) survives even where raw capture is prohibited. That is [§2.3](#23-what-cosai-asks-opentelemetry-to-include) item 1's companion ask, and it is the OTel expression of this document's **hash-first** principle. The OTel Collector is also the correct place to run redaction, since it applies uniformly across every instrumented service rather than per-library.

**Canonicalization is a prerequisite for hash-first, and it must be declared.** A content hash or an event fingerprint correlates across producers only if every producer hashes the same logical bytes. The OpenTelemetry audit data model draft mandates RFC 8785 (JCS); OCSF's `attestation.fingerprint` instead *declares* its serialization (`serialization_id` plus a free-text `serialization`) so that non-JCS producers can declare it; CPEX's audit seam ([cpex#166](https://github.com/contextforge-org/cpex/pull/166)) hashes a sorted-key JSON that is documented as not RFC 8785. Two conformant implementations with different canonicalizations produce different digests for the same event, and the integrity claim degrades silently from "verify" to "trust the producer". Requirement: a producer that emits a hash of content or of an event MUST declare the canonicalization used (JCS by default), and consumers MUST NOT compare digests across producers whose declared canonicalizations differ. OCSF carries the declaration on `attestation.fingerprint`; the OTel-side ask is a single `audit.integrity.canonicalization` attribute.

---

## 3. Implications for OCSF & AITF (the standardization bridge)

This appendix covers the OCSF consumption side of the standards bridge and AITF's role as the interim binding. OpenTelemetry coverage and emission-side proposals are in [§2](#2-implications-for-opentelemetry-the-instrumentation-bridge).

### 3.1 OCSF coverage & gaps, by field cluster

For each cluster of fields defined above: where it lands in OCSF **today**, the **gap**, the **AITF interim carrier**, and the **recommended OCSF change**. Clusters are grouped by pipeline component; the tier tag records which tiers the identified gap spans, not the full tier mix of the underlying section.

| Field cluster (tier) | OCSF today | Gap | AITF interim carrier | Recommended OCSF change |
| :------ | :---------- | :---------------------- | :---------- | :---------------------------------------------------- |
| Execution context & agent identity (MUST / SHOULD) | API Activity (6003) with the `ai_operation` profile: `ai_agent` (stable `uid`, restart-sensitive `instance_uid`, framework `type_id`, `charter`, backing `ai_model`), `delegation`, `message_context` | No workflow / run / turn / step identifiers, action type, trigger type, or autonomy level | `gen_ai.agent.*`; proposed **Agent Activity (9001)** | Ratify an **AI agent activity** class for agent-originated control-plane events (tracking [ocsf-schema#1640](https://github.com/ocsf/ocsf-schema/issues/1640); the OCSF working group agreed 2026-09-04 that Application Lifecycle is not the home); extend the `ai_operation` profile with the run / turn / step identifiers, action type, trigger type |
| Stop reason (SHOULD) | `ai_stop_reason_id` on the `ai_operation` profile ([ocsf-schema#1704](https://github.com/ocsf/ocsf-schema/pull/1704), maintainer-approved 2026-09-04): Unknown / End of Turn / Token Limit / Tool Use / Session Stop / Content Filter / Other | None once merged | `gen_ai.response.finish_reasons` | Merge #1704; no further ask |
| Prompt / response / system prompt (MUST) | `message_context` on the `ai_operation` profile: `prompt_text`, `response_text`, token counts, `ai_role_id`, session `uid` | No content hash, redaction / PII flags, system prompt, or attachment identity | `gen_ai.prompt` / `gen_ai.completion` / system message | Extend **`message_context`** with `prompt_hash` / `response_hash`, `is_redacted`, `system_prompt` (+ hash), attachment identity; this is the OCSF expression of the hash-first principle. A separate `ai_content` object only if content must attach to classes other than 6003 |
| Input trust classification (MUST) | Detection Finding (2004), partial | No trust-provenance enum | `security.*` (trust/threat) | New **`trust_level`** enum (trusted-instruction / trusted-data / untrusted-data / adversarial-suspected), usable on content and message objects |
| Guardrail verdicts (MUST) | Detection Finding (2004), partial | No guardrail-verdict object | `security.guardrail.*`, `security.blocked`, `security.threat_type` | New **`ai_guardrail`** object (type, verdict, score, blocked flag, threat reference) |
| Threat classification / **ATLAS technique tag** (MUST) | Detection Finding (2004) `attacks[]`, documented as compatible with MITRE ATLAS tactics, techniques and sub-techniques; `attack.version` carries the ATLAS matrix version | None: producer guidance only | `security.threat_type` + `compliance.framework=mitre_atlas` / `compliance.control_id` | No schema change. Populate `attacks[].technique.uid` with `AML.Txxxx`, `attacks[].tactic` with the ATLAS tactic, `attacks[].version` with the ATLAS matrix version |
| Output egress (MUST) | Network / HTTP Activity (partial) | No link from model output → egress channel/recipient | `gen_ai.tool.call.arguments`, `security.pii.*` | Add **egress correlation** attribute on Agent Activity linking output → destination/recipient/URL |
| Model & serving (SHOULD) | API Activity (6003) model attrs; App Lifecycle (6002); Vulnerability Finding (2002) | Provenance/signing not standardized in profile | `gen_ai.request.model`, `gen_ai.provider.name`, `supply_chain.*` | Standardize model name/version/provider + **provenance/signing** attrs in `ai_operation` |
| Tools & MCP (MUST / SHOULD) | API Activity (6003) | No MCP object, tool trust-boundary, ACL/scope | `mcp.*`, `identity.auth.scope_granted` | Land **`ai_tool`** with its `mcp` sub-block, `primitive` axis and `transaction_uid` join key, drafted in [ocsf-schema#1729](https://github.com/ocsf/ocsf-schema/pull/1729); add **`tool_trust_boundary`** enum (mcp / internal / direct-storage) + scope attr to it |
| Memory (MUST / SHOULD) | Datastore Activity (6005), loosely | No memory-operation object, provenance, poisoning/isolation signals | `memory.*`, `memory.security.*` | New **`ai_memory`** object (op, provenance, footprint, poisoning score, isolation-verified) |
| Retrieval / RAG (MUST / SHOULD) | Datastore Activity (6005) | No retrieved-content source/provenance/integrity | `rag.*` | New **`ai_retrieval`** object (query, items, source/provenance, integrity signal) |
| Orchestration & multi-agent (MUST) | None native | No inter-agent message, background task, loop/step, resource aggregate | Proposed **Agent Activity (9001)**; inter-agent via 9002 | Ratify **AI Agent Activity (9001)** carrying inter-agent, background-task, loop, and resource-aggregate attrs |
| Identity & delegation (SHOULD) | `delegation` object on the `ai_operation` profile: durable authorization context with `uid` minted by a trusted issuer, `parent_uid` lineage, `issuer_uid`, `created_time`; Authentication (3002) for the credential events | No granted scope / constraints, runtime credential attestation, trust-domain crossing, lifecycle state. Depth is derivable **only if every hop carries `parent_uid`, which is optional today** ([ocsf-schema#1739](https://github.com/ocsf/ocsf-schema/issues/1739)): a fully conformant producer can emit a re-delegated action with no parent link, and one such record anywhere in the chain breaks the walk without anyone violating the schema. A walk is also not a join, so reconstructing a subtree means resolving every intermediate delegation out of band, which an aggregate check evaluated at the consuming action (**Resource-Consumption Aggregate**, AD §1.8, MUST) cannot afford at request latency | `identity.*`; proposed **Delegation Activity (9002)** | Extend **`delegation`** with scope, constraints, lifecycle state; **require `parent_uid` where a parent exists**, and add a **root / subtree identifier** so subtree membership is a single-field join rather than an out-of-band walk ([ocsf-schema#1739](https://github.com/ocsf/ocsf-schema/issues/1739)); ratify **AI Delegation Activity (9002)** for the control-plane lifecycle (tracking [ocsf-schema#1640](https://github.com/ocsf/ocsf-schema/issues/1640)); add a **`runtime_attestation`** object (not `ai_attestation`: `attestation` already exists in OCSF and means record integrity), carrying evidence as an **array of independently issued evidence objects** (software-provenance and runtime/workload, each with issuer, subject, validity and integrity metadata) and an explicit **not-available status with a reason**, so that absence is an assertion rather than an inference; align to the ODIS delegation record at concept level |
| Asset inventory & fleet (SHOULD / MAY) | Inventory Info (partial) | No AI-asset object; fleet aggregates derived | `asset.*` | New **`ai_asset`** object (version, software ref, ownership, status); the agent trust-base half of this is proposed as a Discovery class in [ocsf-schema#1724](https://github.com/ocsf/ocsf-schema/issues/1724) |
| Capability-set change & AgBOM (MUST / SHOULD) | Inventory Info; App Lifecycle (6002) | No agent-composition BOM, no dependency graph, no capability-change event | `supply_chain.ai_bom.*` | New **`ai_bom`** object (BOM ref, format, signature, dependency edges) + a **capability-change** activity on Agent Activity (9001). [ocsf-schema#1724](https://github.com/ocsf/ocsf-schema/issues/1724) already proposes the declared-versus-executed configuration record, emitted at first use of a new dependency and chained with `record_integrity`; cite it as the vehicle for capability-change timing |
| Observability-plane integrity (SHOULD) | `record_integrity` profile + `attestation` object on `base_event` (OCSF 1.9.0, [ocsf-schema#1661](https://github.com/ocsf/ocsf-schema/pull/1661)): per-event `fingerprint`, `signatures`, `chain_uid`, `prev_event` linkage | No enforcement-availability, fail-open, or hook-coverage representation. Event continuity (AD §1.11) maps to `attestation.prev_event` and `attestation.chain_uid` with no new schema | `security.guardrail.*` (partial) | Add **enforcement availability / failure-mode** attrs to `ai_guardrail`; add **instrumentation coverage** to `ai_asset` |
| Policy enforcement & mediation (MUST / SHOULD) | Authorization (3003) partially; Detection Finding (2004) for classifier verdicts | No authorization-decision object for AI operations; no information-flow/taint labels; no human-approval lifecycle; no attribute-provenance marking; no mediation-coverage representation. No carrier for the **accounting decision** either: the aggregate consumed and remaining against the *principal's* budget, recorded on the action that consumed it. A dictionary search (2026-08-25) found no attributes in that family, and a metric cannot testify because it does not survive with the action record | `security.*` (partial) | New **`ai_authorization`** object (decision, reason, code, deciding authority, rule id, obligations, plus **budget accounting on the decision**: quantity, consumed, remaining, budget reference, and the principal / subtree join key, so that a budget denial is auditable and a budget-exceeded state found after the fact is distinguishable as a control failure); new **`ai_taint`** object (labels, scope, origin, taint-caused denial); new **`ai_approval`** object (correlation id, status, IdP-verified approver, channel, scope-binding result); an **`attribute_source`** enum (idp / pdp / enforcement-state / platform / **self-asserted**) usable on identity, authorization, and agent-state attributes |

### 3.2 What CoSAI asks OCSF to include (summary)

1. **Promote the two proposed AI event classes to ratified:** **AI Agent Activity (9001)** and **AI Delegation Activity (9002)**. **The boundary against tool invocation, stated so that adjacent proposals arrive reconciled rather than adjudicated at OCSF:** a per-invocation tool record rides **API Activity (6003) with `ai_tool`** ([ocsf-schema#1729](https://github.com/ocsf/ocsf-schema/pull/1729)), while **9001** carries agent-originated **control-plane lifecycle** events. A dedicated per-invocation class, proposed separately from CoSAI WS4's containment work, is compatible with that split provided it joins on `ai_tool`'s `transaction_uid` rather than restating its fields; three artifacts adjacent to "what the agent did" otherwise read as overlapping asks.
2. **Extend the existing `ai_operation` profile** (which already carries `ai_agent`, `ai_model`, `delegation`, `message_context`, and, once ocsf-schema#1704 merges, `ai_stop_reason_id`) so that it represents the [classification summary](CoSAI-AI-Telemetry-RFC.md#44-classification-summary) using **class- and activity-specific applicability**: common correlation attributes are required at profile level, while the remaining MUST fields are required when their defining operation or event applies. SHOULD/MAY fields remain recommended/optional within the same applicable scope.
3. **Add or extend AI-specific objects:** extend `message_context` (content hashes, redaction flags, system prompt) and `delegation` (scope, constraints, lifecycle state); land `ai_tool`/`mcp` (ocsf-schema#1729); add `ai_guardrail`, `ai_memory`, `ai_retrieval`, `runtime_attestation`, `ai_asset`, `ai_bom`, `ai_authorization`, `ai_taint`, `ai_approval`. **Every hash-bearing attribute added by this appendix carries or references a canonicalization declaration, per [§2.5](#25-context-propagation-sampling--privacy-three-operational-traps)**: the content hashes on `message_context`, the tool-definition digest, attachment hashes, and the `ai_bom` signature, not only `attestation.fingerprint`. Without it the same silent degradation from "verify" to "trust the producer" reappears one field over.
4. **Add AI-specific enums:** `trust_level`, `autonomy_level` (L1 to L5), `tool_trust_boundary`, `memory_provenance`, `enforcement_decision` (allow / deny, the terminal verdict, with an `is_modified` flag for allow-after-modification and a machine-readable code on deny; a fail-closed enforcement failure is a deny coded as such, and **budget-exceeded / aggregate-threshold** is a deny code of its own, so that a denial on accumulated consumption is queryable as distinct from one on the operation's own payload), `enforcement_step_action` (allowed / denied / modified_payload / modified_extensions / deny_suppressed / aborted / error, one per plugin or rule that ran, so that a suppressed deny is queryable), `enforcement_failure_mode` (fail-open / fail-closed), `mcp_primitive` (tool / resource / prompt / sampling / elicitation / roots), `trigger_type` (user-initiated / autonomous), **`attribute_source`** (idp / pdp / enforcement-state / platform / self-asserted), **`taint_scope`** (session / message), **`approval_status`** (pending / resolved / expired / bypassed).
5. **ATLAS technique tagging needs no OCSF change.** Detection Finding's `attacks[]` is already documented as compatible with MITRE ATLAS tactics, techniques and sub-techniques, and `attack.version` carries the matrix version. The [ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping) is portable today; this document supplies the producer guidance (populate `attacks[].technique.uid` with `AML.Txxxx`) rather than an ask.
6. **Agent attribution rides `ai_agent`, not an actor type.** OWASP AOS's OCSF binding currently represents the agent through the `actor.user` type enum with an "Other" override and a free-text `"AI Agent"`: a documented workaround, and one that types the agent as a kind of user. The OCSF `actor` object has no type of its own. The correct representation exists: `ai_agent` on the `ai_operation` profile for which agent acted, and `delegation` for whose authority it acted under. The change is on the AOS side (see [§5.5](#55-what-this-document-contributes-back-to-aos)): migrate the binding to `ai_agent` + `delegation`.

### 3.3 Incremental extension path via AITF

AITF lets adopters emit this telemetry **before** OCSF ratifies it, and stages the upstream proposals so each is backward-compatible:

- **Phase 0, today.** AITF carries every MUST field as OTel attributes and emits OCSF via the `ai_operation` profile on existing classes (6003/6005/2004/3002); the ATLAS tag rides on `compliance.control_id` (framework `mitre_atlas`).
- **Phase 1, profile extension (backward-compatible).** Contribute the MUST attribute set plus the `ai_guardrail` and `ai_tool` objects to the OCSF `ai_operation` profile, and the `message_context` extensions (content hashes with their canonicalization declaration, redaction flags, system prompt, attachment identity); no new classes required, and `ai_content` only if content must attach to classes other than 6003 ([§3.1](#31-ocsf-coverage--gaps-by-field-cluster)).
- **Phase 2, agentic classes.** Ratify **AI Agent Activity (9001)** plus the `ai_memory` and `ai_retrieval` objects (memory & RAG are absent from OCSF today and are MUST here).
- **Phase 3, delegated authority.** Ratify **AI Delegation Activity (9002)** and the `runtime_attestation` object (ODIS-aligned), and land the lineage asks of [ocsf-schema#1739](https://github.com/ocsf/ocsf-schema/issues/1739) on `delegation`.
- **Phase 4, inventory & analytics.** SHOULD/MAY clusters (`ai_asset`, drift, quality, fleet aggregates) as they stabilize.

**Governance rule for promotion:** a field graduates from AITF-proposed to an OCSF standardization ask when **≥ 2 independent documented instances in [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory)** require it, the same evidence rule that sets the MUST tier ([RFC §4.2](CoSAI-AI-Telemetry-RFC.md#42-classification-legend)). This keeps the OCSF surface minimal and evidence-driven rather than speculative.

---

## 4. AITF & ODIS Cross Reference

Maps each conceptual field to the [AITF](https://github.com/cosai-oasis/ws2-defenders/tree/main/telemetry) attribute namespace and to the relevant [ODIS](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md) data-model field, verified against ODIS at commit `148dc41` (8 September 2026). Per the brief, ODIS coverage is **selective**: it targets the delegation/identity fields relevant to detection & response, not the full ODIS spec. The ODIS column resolves **names**, not shapes: ODIS defines abstract schemas that implementations bind to a wire format, and this document is a requirements layer rather than a binding ([RFC §2.1](CoSAI-AI-Telemetry-RFC.md#21-in-scope)). Where cardinality or structure is normative for an ask, it is stated in [§3](#3-implications-for-ocsf--aitf-the-standardization-bridge).

> **The `Cls` column is reproduced from the [classification summary](CoSAI-AI-Telemetry-RFC.md#44-classification-summary) for convenience and is not normative.** [RFC §4.4](CoSAI-AI-Telemetry-RFC.md#44-classification-summary) and the section tables in AD §§1.1 to 1.12 govern; any disagreement between them and this column is a defect in this table.

| Conceptual field | Cls | AITF attribute (namespace) | ODIS field (§) |
| :------------------------- | :---- | :--------------------------------------- | :--------------------------------- |
| Agent Name | MUST | `gen_ai.agent.name`, `asset.*` | `agent_id` /`owner_ref` (6.1) |
| Agent (Runtime) Instance ID | MUST | `gen_ai.agent.id` | `runtime_instance_id` (6.2) |
| Workflow / Run ID | MUST | trace id / run attr, *see note below* | `request_trace_id` (6.4) |
| Session / Turn / Step IDs | MUST | `gen_ai.conversation.id`; turn attr; OTel `span_id` + `gen_ai.agent.step.index` | n/a |
| Trace Context (propagated) | MUST | OTel `trace_id`/`span_id`, W3C `traceparent` | `request_trace_id` (6.4) |
| Organization / Tenant ID | SHOULD | `asset.*` / resource attrs | `trust_domain` (6.1) |
| Trigger Type & Source Event | MUST | `gen_ai.agent.*` trigger attrs | n/a |
| Action Type | MUST | `gen_ai.agent.step.type` | `action.{tool,method}` (6.4) |
| Execution Status | MUST | span status + `error.type` | n/a |
| Stop Reason | SHOULD | `gen_ai.response.finish_reasons` | n/a |
| Surface / App | MUST | `gen_ai.*` (surface attr) | n/a (policy input) |
| System Prompt / Instruction Config | MUST | `gen_ai.*` (system message / request) | n/a (see note) |
| Autonomy Level | SHOULD | `gen_ai.agent.state` | n/a |
| Model Input | MUST | `gen_ai.prompt` / input events | `action.parameters` (6.4) |
| Input Source / Channel | MUST | `gen_ai.*` / `rag.*` / `mcp.*` source | `delegation_chain` origin (6.3) |
| Input Trust Classification | MUST | `security.*` (trust/threat) | `constraints` (6.3) |
| Source host / IP + request metadata | MUST | `security.*` / resource attrs | n/a (policy input) |
| Guardrail (Input) Verdict | MUST | `security.guardrail.type`, `security.blocked`, `security.threat_type` | n/a |
| Content Modality & Attachment Identity | MUST ‡ | `gen_ai.*` content-part attrs | n/a |
| Guardrail Modification Record | SHOULD ‡ | `security.guardrail.*` + modified/redacted flags | n/a |
| Threat Classification / ATLAS Technique Tag | MUST † | `security.threat_type`, `compliance.framework=mitre_atlas`, `compliance.control_id` | n/a |
| Encoded / Obfuscated Payload Indicator | MAY | `security.*` obfuscation / decoded-form attrs | n/a |
| Response / Model Output | MUST | `gen_ai.completion` | n/a |
| Citations / Source Attribution | MUST | `rag.*` (source) + output citation attrs | n/a |
| Output Egress Destination | MUST | `gen_ai.tool.call.arguments`, `security.pii.*` | `resource_indicators` (6.3) |
| Observation / Thought (reasoning trace) | SHOULD | `gen_ai.agent.step.thought` | n/a |
| Guardrail (Output) Verdict | MUST | `security.guardrail.*`, `security.pii.*` | `constraints` (6.3) |
| LLM Refusal | MUST | `gen_ai.response.finish_reasons`, `security.*` | n/a |
| Model Name + Version | MUST | `gen_ai.request.model`, `gen_ai.provider.name` | `approved_software_refs` (6.1) |
| Provider / Endpoint Identity | MAY | `gen_ai.provider.name` | n/a |
| Inference Parameters | MUST | `gen_ai.request.temperature/top_p/max_tokens/stop_sequences/seed` | n/a |
| Input / Output Token Counts | MUST | `gen_ai.usage.input_tokens/output_tokens`, `cost.*` | n/a |
| LLM Error / Exception | MUST | `gen_ai.*` error + `security.*` | n/a |
| Model Provenance / Signing / Hash | SHOULD | `supply_chain.model.hash/signed/source`, `supply_chain.ai_bom.*` | `software_hash` (6.2), `approved_software_refs` (6.1) |
| Pre-Forward-Pass State Digest/Vector | MAY | `drift.*` | n/a |
| Token Malformation / Context-Corruption Indicator | MAY | `drift.*`, `quality.*` | n/a |
| Tool Call I/O | MUST | `gen_ai.tool.call.arguments` / `gen_ai.tool.call.result`, `mcp.tool.name` | `action` (6.4) |
| Tool Name | MUST | `mcp.tool.name` | n/a |
| Tool Type / Trust Boundary | MUST | `mcp.*` vs internal | n/a |
| Tool ID | MAY | `mcp.server.name` + tool id | n/a |
| Tool Execution ID | MUST | `gen_ai.tool.call.id` | n/a |
| Tool Definition Digest | MUST | `mcp.tool.*` schema/description hash | `approved_software_refs` (6.1) |
| Execution Environment / Sandbox | MUST | `supply_chain.*` + runtime/sandbox attrs | `binding_profile` (6.2, partial) |
| MCP Server Identity & Primitive | MUST | `mcp.server.name/version`, primitive attr | n/a |
| Tool Error / Exception | MUST | `mcp.*` error, `security.*` | n/a |
| Tool ACL / Required Scope | SHOULD | `identity.auth.scope_granted` | `granted_authorizations` (6.3) |
| Tool Privacy Classification | MAY | `security.pii.*`, `compliance.*` | `constraints` (6.3) |
| Tool Selection Rationale | SHOULD | `gen_ai.agent.step.thought` (per-step) | n/a |
| Memory Write Event, Memory Read / Injection Event | MUST | `memory.*` | n/a |
| Memory Provenance / Source | MUST | `memory.provenance` | n/a |
| Memory Integrity / Poisoning Signal | SHOULD | `memory.security.poisoning_score`, `memory.security.isolation_verified`, `memory.security.cross_session` | n/a |
| Memory Footprint / Growth | MUST | `memory.*`, `cost.*` | n/a |
| Declared Memory Configuration | MAY | `memory.*` config attrs | n/a |
| Memory Write Rationale | SHOULD | `gen_ai.agent.step.thought` (per-step) | n/a |
| Retrieval Event | MUST | `rag.*` | n/a |
| Retrieved-Content Source / Provenance | MUST | `rag.*` (source) | `delegation_chain`/`constraints` (6.3) |
| Retrieved-Content / Metadata Integrity Signal | SHOULD | `rag.*`, `security.*` | n/a |
| Declared Knowledge-Source Configuration | MAY | `rag.*` config/index attrs | n/a |
| Inter-Agent Message | MUST | `gen_ai.agent.*`, delegation activity (OCSF 9002) | `delegation_chain` (6.3) |
| A2A Task Lifecycle Event | SHOULD | delegation activity (OCSF 9002); a2a attrs | `delegation_id`, `parent_delegation_ref` (6.3) |
| Peer Agent Card / Descriptor | SHOULD | `gen_ai.agent.*` peer attrs | `agent_id`, `approved_software_refs` (6.1) |
| Background / Scheduled Task Event | MUST | `gen_ai.agent.next_action` / step events | n/a |
| Loop / Step-Count Signal | MUST | `gen_ai.agent.turn_count` | n/a |
| Resource-Consumption Aggregate | MUST | `cost.*`, `gen_ai.usage.*` | `constraints` (rate) (6.3) |
| Task / Intent Declaration | SHOULD | `gen_ai.agent.next_action` | `task_id`, `task_description` (6.3) |
| Protocol Envelope Capture | MAY | `mcp.*` / a2a raw payload | n/a |
| Identities Used (per hop) | MUST | `identity.*` (OCSF Authentication 3002) | `actor`, chain (6.3) |
| Verified vs Displayed Identity | MUST | `identity.auth.method`, `identity.auth.result` | `originating_principal`/`actor` (6.3) |
| Originating Principal (on-behalf-of) | SHOULD | `identity.*` | `originating_principal` (6.3) |
| Delegation Chain | SHOULD | delegation activity (OCSF 9002) | `delegation_chain`, `delegation_id`, `parent_delegation_ref` (6.3) |
| Granted Authorizations / Scope | SHOULD | `identity.auth.scope_granted` | `granted_authorizations`, `attenuation_profile_ref` (6.3) |
| Resource Indicators + Constraints | SHOULD | `identity.*`, `compliance.*` | `resource_indicators`, `constraints` (6.3) |
| Trust-Domain Crossing & Delegation Depth | SHOULD | `identity.*` domain/depth attrs | `trust_domain` (6.1, 6.2), `max_depth` (6.3) |
| Runtime Credential / Attestation | SHOULD | `identity.auth.method` (mTLS/SPIFFE/OAuth/DID-VC), `identity.trust.method` | `attestation_evidence`, `issuer`, `holder_key_ref`, `expires_at`, `binding_profile` (6.2) |
| Lifecycle State | SHOULD | `identity.lifecycle.operation` | `lifecycle_state` (6.1) |
| Tool/Agent Version, Repository / Code Path / Software Ref | SHOULD | `supply_chain.*`, `asset.*` | `approved_software_refs` (6.1) |
| Capability-Set Change Event | MUST | `asset.*` change events | `approved_software_refs` (6.1) |
| AgBOM / Inventory Snapshot | SHOULD | `supply_chain.ai_bom.*` | `approved_software_refs` (6.1) |
| Component Dependency Graph | SHOULD | `supply_chain.ai_bom.*` (dependency edges) | n/a |
| Inventory Attestation Signature | SHOULD | `supply_chain.*` signature attrs | `software_hash`, `attestation_evidence` (6.2) |
| Description, Status (active/disabled), Creator ID / Oncall / Creation & Update dates, Surfaces Supported | MAY | `asset.*` | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` (6.1) |
| Fleet counts | MAY | (derived) | n/a |
| Credential Minting & Scope-Narrowing Check | SHOULD | `identity.auth.scope_granted` + token-exchange attrs | `granted_authorizations`, `binding_profile` (6.2/6.3) |
| Authorization Decision Record | MUST | `security.*` decision + `compliance.control_id` | n/a (see note) |
| Attribute Source / Trusted-Provenance Marking | MUST ‡ | n/a | `attestation_evidence` (6.2, partial) |
| Session Taint Labels & Information-Flow Decisions | SHOULD | `security.*` labels | `constraints` (6.3) |
| Human Approval / Elicitation Event | SHOULD | `identity.*` approver + approval attrs | `originating_principal` (6.3, partial) |
| Backend / Route Restriction Decision | SHOULD | `gen_ai.provider.name` + routing constraint attrs | `resource_indicators`, `constraints` (6.3) |
| Mediation Coverage & Bypass Path | SHOULD | n/a | n/a |
| Enforcement-Point Availability & Failure Mode | SHOULD | `security.guardrail.*` availability/latency | n/a |
| Instrumentation Coverage / Hook Attestation | MUST | `asset.*` / instrumentation attrs | n/a |
| Event Sequence Continuity | SHOULD | n/a | n/a |
| Policy Reason Code | MAY | `security.*` + `compliance.control_id` | n/a |

> **Note on the identifier mapping.** AD §1.1 distinguishes five levels (instance → run → session → turn → step). AITF maps the runtime instance to `gen_ai.agent.id` and the session to `gen_ai.conversation.id`; the run maps to the trace ID. AITF has no dedicated turn attribute today. Step identity is the OTel `span_id`, with `gen_ai.agent.step.index` recording its order within the agent sequence; see [§5.4](#54-what-this-implies-for-opentelemetry-aitf-and-ocsf).

> **Note on upstream OTel coverage.** The **OpenTelemetry GenAI conventions** moved to a dedicated repository and cover more of this field set than is commonly assumed (notably `gen_ai.system_instructions` (System Prompt), `gen_ai.tool.definitions` (Tool Definition Digest), `gen_ai.retrieval.query.text` / `.documents` (Retrieval Event), the full `gen_ai.request.*` decoding set (Inference Parameters), the `mcp.*` namespace (MCP Server Identity), and `gen_ai.invoke_agent.tool_calls` / `.inference_calls` (Loop Signal, as metrics)). See **[§2.1](#21-what-the-genai-conventions-cover-today)** for the inventory and **[§2.2](#22-coverage--gaps-by-field-cluster)** for what remains genuinely absent: chiefly trust classification, security guardrail verdicts, retrieval provenance, and (within an otherwise-covered `gen_ai.memory.*` namespace) memory provenance and footprint.

> **Policy-engine consumption and telemetry emission are orthogonal.** A field presented to a policy engine is not thereby excluded from telemetry, and the reverse also holds; AD §1.12's **Authorization Decision Record** exists to record a decision together with the attributes it turned on. Inclusion here is decided by detection and response value, not by how ODIS §6.4 classifies a field.
>
> **ODIS fields intentionally out of telemetry scope** (identity/authority mechanics rather than detection signals): `approved_runtime_issuers`, `policy_profile_ref`, `permitted_delegation_modes`, `provider_entitlements`, and the details of `binding_profile`: the token-binding method (DPoP, mTLS, or TLS session binding via `tls_exp`) together with key custody and which component is authorized to present the derived credential. These are consumed by the policy engine (ODIS §6.4 Identity Context) rather than emitted as security telemetry. `policy_profile_ref` names the policy profile in force; it is neither the content of an instruction configuration nor the record of a decision, so **System Prompt / Instruction Config** and **Authorization Decision Record** carry no ODIS mapping above.
>
> **`trust_domain` and `max_depth` are the exception and are in scope.** AD §1.9's **Trust-Domain Crossing & Delegation Depth** carries both as telemetry, because each becomes detection-grade once a delegation chain leaves the domain that issued it (see [RFC §4.6](CoSAI-AI-Telemetry-RFC.md#46-agents-you-do-not-operate)). `trust_domain` appears in both the registration record (6.1) and the runtime credential descriptor (6.2).
>
> **Data classification travels as a constraint.** ODIS defines `constraints` (6.3) as time, purpose, rate, locality "or other narrowing constraints" and enumerates no keys, so the data-classification narrowing recorded by **Guardrail (Output) Verdict** (AD §1.3), **Tool Privacy Classification** (AD §1.5) and **Session Taint Labels** (AD §1.12) is an illustrative key of that object rather than an ODIS-defined field name.

---

## 5. OWASP AOS Cross Reference

The [OWASP Agent Observability Standard](https://aos.owasp.org/) (AOS) defines how agents expose runtime behaviour through hooks, events, and a queryable Agent Bill-of-Materials; this RFC defines which security fields are required and how they are tiered. The tables below map AOS's **Instrument**, **Trace**, and **Inspect** pillars to the field set. Status values:

| Status | Meaning |
| :----------------- | :----------------------------------------------------------------------------------- |
| **Covered** | In the field set. |
| **Partial** | Deliberately narrower coverage; the difference is explained. |
| **Out of scope** | Control-plane or wire-protocol material this document intentionally does not specify. |

### 5.1 Pillar 1: Instrument

*AOS's Instrument pillar defines lifecycle hooks that emit to, and can be intervened on by, a **Guardian Agent**: a policy decision point that returns `allow`, `deny`, or `modify` before the agent proceeds. This is the pillar that required the most additions, because a guardrail model that only records verdicts is observational (a verdict was recorded) rather than interventional (a decision was enforced, or failed to be).*

| AOS element | This document | Status |
| :-------------------------------------------------------- | :-------------------------------------- | :------ |
| Hook set (agent trigger, user message, agent response, tool call request, tool call result, memory store, memory retrieval, knowledge retrieval, MCP inbound/outbound) | Field coverage across AD §§1.1 to 1.8; **Instrumentation Coverage / Hook Attestation** (AD §1.11) records which hooks are live | **Covered** |
| Decision `allow` / `deny` | Guardrail (Input/Output) Verdict, pass / block (AD §§1.2 to 1.3) | Covered |
| Decision `modify` + `modifiedRequest` | **Guardrail Modification Record** (AD §1.2), cross-cutting | **Covered** |
| `reasoning` (human-readable decision rationale) | Guardrail Verdict detector + score (AD §§1.2 to 1.3) | Covered |
| `reasonCode[]` (machine-readable) | **Policy Reason Code** (AD §1.11) | **Covered** |
| Enforcement callout failure, timeout, unavailability | **Enforcement-Point Availability & Failure Mode** (AD §1.11) | **Covered** |
| `ping` / liveness | **Enforcement-Point Availability** + **Event Sequence Continuity** (AD §1.11) | **Covered** |
| `StepContext`: agent, session, turn, step, timestamp, user, organization | **Session / Turn / Step IDs**, **Organization / Tenant ID** (AD §1.1) | **Covered** |
| `Agent` object, name, id, description, version, `instructions`, provider, model, tools, mcpServers, resources | Agent Name, Instance ID, System Prompt (AD §1.1); Model fields (AD §1.4); inventory (AD §1.10) | Covered |
| `Message` object + `Part` union (TextPart / FilePart / DataPart) | **Content Modality & Attachment Identity** (AD §1.2), cross-cutting | **Covered** |
| `ToolDefinition` / `ToolArgumentDefinition` / `ToolOutputDefinition` | **Tool Definition Digest** (AD §1.5) | **Covered** |
| `ToolCallRequest`: `executionId`, `toolId`, inputs | **Tool Execution ID** (AD §1.5) + Tool Call I/O, Tool Name (AD §1.5) | **Covered** |
| `Source` union, FileSource, SiteSource | **Citations / Source Attribution** (AD §1.3) | **Covered** |
| `KnowledgeRetrievalStepParams`: query, keywords, results | Retrieval Event, Retrieved-Content Source (AD §1.7) | Covered |
| `A2AContext`: from / to, role (client / server) | **Peer Agent Card / Descriptor** (AD §1.8); Identities Used (AD §1.9) | **Covered** |
| Guardian Agent architecture; agent↔guardian authentication | Not specified, but its **outcomes** are, via AD §1.11 | Out of scope |
| JSON-RPC 2.0 over HTTP(S); error code ranges | Wire protocol not specified; error *content* covered by LLM Error (AD §1.4), Tool Error (AD §1.5) | Out of scope |

### 5.2 Pillar 2: Trace

*AOS's Trace pillar defines the event set and its bindings to OpenTelemetry and OCSF. This is the field set's strongest area; the gaps were per-step reasoning, citations, the identifier hierarchy, and protocol-level events.*

| AOS element | This document | Status |
| :------------------------------------- | :---------------------------------------- | :----------------------- |
| `steps/agentTrigger`: `trigger.type` (autonomous), `trigger.event`, content | **Trigger Type & Source Event** (AD §1.1) | **Covered** |
| `steps/message`: role, content | Model Input (AD §1.2); Response (AD §1.3); System Prompt (AD §1.1) | Covered |
| `steps/message`: `citations` | **Citations / Source Attribution** (AD §1.3) | **Covered** |
| `steps/message`: `reasoning` | Observation / Thought (AD §1.3) | Covered |
| `steps/toolCallRequest`: `reasoning` | **Tool Selection Rationale** (AD §1.5) | **Covered** |
| `steps/toolCallResult`: `executionId`, outputs, `isError` | Tool Call I/O, Tool Error (AD §1.5); **Tool Execution ID** (AD §1.5) | **Covered** |
| `steps/memoryStore`: memory, `reasoning` | Memory Write (AD §1.6); **Memory Write Rationale** (AD §1.6) | **Covered** |
| `steps/memoryContextRetrieval`: memory, `reasoning` | Memory Read (AD §1.6) | Covered |
| `steps/knowledgeRetrieval`: query, keywords, results | Retrieval Event (AD §1.7) | Covered |
| `protocols/MCP`: full JSON-RPC payload | **MCP Server Identity & Primitive** (AD §1.5); **Protocol Envelope Capture** (AD §1.8) | **Covered** |
| `protocols/A2A`: full JSON-RPC payload | **A2A Task Lifecycle Event**, **Protocol Envelope Capture** (AD §1.8) | **Covered** |
| A2A methods: `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`, `tasks/resubscribe`, `tasks/pushNotificationConfig/get`+`/set` | **A2A Task Lifecycle Event** (AD §1.8) | **Covered** |
| `ping`: timestamp, timeout, status, version | AD §1.11 (see [§5.1](#51-pillar-1-instrument)) | **Covered** |
| OTel span hierarchy: `agent.run`, `agent.plan`, turn spans, step spans | **Session / Turn / Step IDs** + **Trace Context** (AD §1.1) specify the *identifiers and propagation*; span naming is left to the OTel binding | **Partial**: deliberate; this document is field-level, and span naming belongs in AITF |
| OTel attribute naming: `agent.*`, `llm.model.name`, `llm.provider.name` | This document uses OTel GenAI semconv `gen_ai.*` throughout ([§4](#4-aitf--odis-cross-reference)) | **Divergence**: see [§5.6](#56-divergences--open-coordination-items) |
| OCSF binding: API Activity 6003, `type_uid` 600301, `actor.type_id: 99` "AI Agent", `unmapped.aos` namespace | [§3](#3-implications-for-ocsf--aitf-the-standardization-bridge) proposes ratified classes 9001/9002 and an `ai_operation` profile | **Divergence**: see [§5.6](#56-divergences--open-coordination-items) |
| Sensitive-attribute handling ("may necessitate hashing, truncation, or redaction") | [Privacy-preserving logging](CoSAI-AI-Telemetry-RFC.md#5-implementation-guidance), access control, tiered retention, redaction pipelines, hash-first correlation | Covered (stronger) |

### 5.3 Pillar 3: Inspect

*AOS's Inspect pillar requires an agent to answer inspection requests with a dynamically-maintained **AgBOM**. This was the largest structural gap: AD §1.10 existed, but as a flat set of mostly-MAY attributes attached to events rather than as an inventory artifact, and with no signal at all for composition **change**.*

> **Binding status, which is weaker than the pillar's framing suggests.** AOS names CycloneDX, SPDX and SWID as AgBOM carriers, but only one binding has been written: the CycloneDX page is marked *work in progress* and consists of a single worked example, while the **SPDX and SWID pages are unfilled placeholders** soliciting contributions (AOS issues [#20](https://github.com/OWASP/www-project-agent-observability-standard/issues/20) and [#21](https://github.com/OWASP/www-project-agent-observability-standard/issues/21)). Two consequences for the rows below. The CycloneDX attribute names are verbatim from that example, where they ride CycloneDX's **generic `properties` name/value bag** rather than a modelled schema, so the modelling is AOS's and the carriage is CycloneDX's. And the SPDX 3.0 and SWID rows record what **those formats** carry, taken from their own specifications, not what AOS binds: there is no AOS binding for either to compare against yet.

| AOS element | This document | Status |
| :------------------------------------------------ | :--------------------------------------------- | :------- |
| AgBOM as a queryable, on-demand artifact | **AgBOM / Inventory Snapshot** (AD §1.10) | **Covered** |
| Dynamic refresh on discovery / removal / modification of agents, MCP servers, knowledge bases, tools, memory, models | **Capability-Set Change Event** (AD §1.10), MUST | **Covered** |
| Entity: Standard Packages, name, description, version | Tool/Agent Version, Repository/Software Ref (AD §1.10) | Covered |
| Entity: Models, identity, version, description, endpoint, `modelContextWindow`, arguments | Model Name/Version, Provider/Endpoint Identity (AD §1.4); **Inference Parameters** (AD §1.4) | **Covered** |
| Entity: Capabilities, agent cards, discovered agents, MCP servers and their protocols | **Peer Agent Card / Descriptor** (AD §1.8); **MCP Server Identity & Primitive** (AD §1.5) | **Covered** |
| Entity: Knowledge, name, description, schema, search parameters | **Declared Knowledge-Source Configuration** (AD §1.7) | **Covered** |
| Entity: Memory, name, description, type, size constraints, retrieval spec | **Declared Memory Configuration** (AD §1.6) | **Covered** |
| Entity: Tools, name, description, scheme, local and MCP endpoints | **Tool Definition Digest** (AD §1.5); **MCP Server Identity** (AD §1.5) | **Covered** |
| CycloneDX `dependencies[].dependsOn` | **Component Dependency Graph** (AD §1.10) | **Covered** |
| CycloneDX `signatures[]`: `value`, `keyId` | **Inventory Attestation Signature** (AD §1.10) | **Covered** |
| CycloneDX properties: `sandbox`, `languageRuntime`, `environment.os`, `environment.architecture`, `timeoutMs` | **Execution Environment / Sandbox** (AD §1.5) | **Covered** |
| CycloneDX properties: `auth`, `scope`, `endpoint` | Tool ACL / Required Scope (AD §1.5); Output Egress Destination (AD §1.3) | Covered |
| CycloneDX properties: `memoryBackend`, `memoryLimitMB` | **Declared Memory Configuration** (AD §1.6) | **Covered** |
| CycloneDX property: `compliance` | Not a distinct field; AITF `compliance.*` carries it ([§4](#4-aitf--odis-cross-reference)) | Partial |
| SPDX 3.0 `Relationship` with `relationshipType: dependsOn` / `contains` / `hasPrerequisite`; SWID `<Link rel="requires">` | **Component Dependency Graph** (AD §1.10) | **Covered** |
| SPDX 3.0 `Element.verifiedUsing` → `Hash`; SWID `<Payload>` / `<Evidence>` `<File>` with `SHA256:` and W3C XMLDSig `<Signature>` | **Inventory Attestation Signature** (AD §1.10); Version / Repository / Software Ref (AD §1.10) | **Covered** |
| SPDX 3.0 Build profile: `buildType`, `environment`, `parameter`, `configSourceDigest`; SWID `<Meta>` | **Execution Environment / Sandbox** (AD §1.5) | Partial: build-time environment, not the runtime isolation posture the field records |
| SPDX 3.0 AI profile `AIPackage`: `typeOfModel`, `autonomyType`, `domain`, `hyperparameter`, `limitation`, `safetyRiskAssessment`, `useSensitivePersonalInformation` | Model Name/Version (AD §1.4); **Autonomy Level** (AD §1.1, declared baseline) | Partial: model governance metadata, not runtime telemetry |
| SPDX and SWID: no analogue for MCP endpoints, memory backends, tool scopes, or agent cards | **MCP Server Identity** (AD §1.5), **Declared Memory Configuration** (AD §1.6), Tool ACL / Scope (AD §1.5), **Peer Agent Card** (AD §1.8) | **Gap in those formats.** AOS's CycloneDX example is the only place the agent runtime is described, and it rides the generic `properties` bag; SPDX and SWID carry identity, dependency and integrity, and have no AOS binding yet |
| CycloneDX property: `a2aCardUrl` | **Peer Agent Card / Descriptor** (AD §1.8) | **Covered** |

### 5.4 What this implies for OpenTelemetry, AITF and OCSF

Closing the AOS gaps surfaced attributes missing from this document's bindings. All were initially filed against AITF; [§2](#2-implications-for-opentelemetry-the-instrumentation-bridge) then established that **several already have an upstream home in the OpenTelemetry GenAI conventions**, and that others are answered by OTel's *native structure* rather than by any new attribute. That changes where each ask should be filed.

**The coordination finding: where OTel already defines a name, AITF should adopt it rather than mint a parallel one.** Three of the twelve asks below were substantially resolved upstream while this document was being written, the GenAI conventions gained `gen_ai.tool.definitions`, `gen_ai.tool.call.id`, and an entire `mcp.*` namespace. Filing them again against AITF would create exactly the drift [§5.6](#56-divergences--open-coordination-items) warns about between AOS's `llm.*` binding and semconv's `gen_ai.*`.

| # | Ask | OpenTelemetry today | Where to file |
| :---- | :------------------------ | :---------------------------------------------- | :------------------------------ |
| 1 | **Turn and step identifiers**, plus guidance that the run maps to the trace ID rather than to a session attribute | `gen_ai.conversation.id`, `gen_ai.workflow.name`; **step ordering is already native**: the `invoke_agent` → `execute_tool` → `chat` span tree *is* the step hierarchy, and the span ID *is* the step ID. The **turn** level has no representation | **OTel** (`gen_ai.turn.id`); AITF adopts. Do **not** mint a step-ID attribute, use the span |
| 2 | **Enforcement outcome attributes**: reachability, latency, fail-open/fail-closed, a `modify` decision value, before/after digests | `gen_ai.evaluation.*` exists but is quality-oriented, no blocked/allowed outcome, guardrail type, or threat reference | **OTel** by extending `gen_ai.evaluation.*` ([§2.3](#23-what-cosai-asks-opentelemetry-to-include) item 2); enforcement *availability* to OCSF |
| 3 | **Content-part attributes**: part type, MIME type, attachment name/size/hash | `gen_ai.input.messages` / `gen_ai.output.messages` carry typed parts; **no attachment identity or hash** | **OTel**: extend existing message parts |
| 4 | **Citation attributes** on output, with a resolution flag against retrieval | `gen_ai.retrieval.documents` covers the retrieval side; nothing on the output side | **OTel** |
| 5 | **Tool contract attributes**: definition digest; consistent request↔result correlator | **`gen_ai.tool.definitions` and `gen_ai.tool.call.id` both exist upstream** | **Resolved upstream.** AITF adopts the names; only `…definitions.hash` remains to file with OTel |
| 6 | **Execution-environment attributes**: sandbox mode, runtime, OS/architecture, timeout, egress policy | Runtime and platform are already covered by **core resource conventions** (`host.*`, `os.*`, `process.runtime.*`). **Sandbox mode and egress policy are not** | **Reuse** core resource semconv; file only `sandbox` and egress policy as new |
| 7 | **MCP primitive discriminator**, server version and transport | An `mcp.*` namespace exists upstream: `mcp.method.name`, `mcp.protocol.version`, `mcp.resource.uri`, `mcp.session.id`, plus client/server operation and session duration metrics | **Largely resolved upstream.** `mcp.method.name` partially serves as the discriminator; file only an explicit primitive value set |
| 8 | **A2A attributes**: task lifecycle, push-notification callback registration, peer agent card | **Nothing.** The GenAI repository covers MCP but has no A2A conventions | **OTel**: an `a2a.*` namespace, parallel to `mcp.*`, is the natural proposal |
| 9 | **Trigger attributes**: user-initiated vs autonomous, and source event | Nothing | **OTel** ([§2.3](#23-what-cosai-asks-opentelemetry-to-include) item 6) |
| 10 | **Tenant / organization** | No tenant attribute, but **resource attributes are the established mechanism** for this class of value | **Reuse** resource semconv; propose a tenant attribute only if none fits |
| 11 | **Declared-configuration attributes** for memory and knowledge sources | **`gen_ai.memory.*` exists** (store/record identity, query, count, and a memory span), but carries no declared-configuration, provenance or footprint attributes; knowledge partially via `gen_ai.data_source.id` | **OTel**: extend `gen_ai.memory.*` ([§2.3](#23-what-cosai-asks-opentelemetry-to-include) item 3, pending re-scope) |
| 12 | **Instrumentation coverage** and **event sequence number** | **Instrumentation scope is native**: every signal carries an emitting scope name and version, which partially answers coverage. **No envelope sequence number**, and no gap-detection concept | Coverage: **reuse** instrumentation scope, extend for hook-level detail. Sequence number: **OCSF**, as an envelope concern rather than an instrumentation one |

**What the pattern shows.** Of twelve asks, two are substantially resolved upstream (5, 7), three are answered wholly or partly by OTel structure that already exists and should be reused rather than duplicated (1, 6, 10, and the first half of 12), and seven remain genuine gaps. Memory is not among them. OpenTelemetry now carries a `gen_ai.memory.*` namespace and a memory span ([§2.1](#21-what-the-genai-conventions-cover-today)), and AITF carries `memory.*` including `memory.provenance` ([§4](#4-aitf--odis-cross-reference)). What remains absent upstream is narrower and specific: **memory provenance and footprint**, the two attributes `IR-02`, `IR-05` and `AOC-05` turn on.

**Governance.** Per the rule in [§3.3](#33-incremental-extension-path-via-aitf), each item graduates from AITF-proposed to a standardization ask once ≥ 2 independent documented instances in [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) require it, a bar every MUST-tier item above already clears. File emission-side asks with OpenTelemetry, consumption-side asks with OCSF, and use AITF to carry both in the interim.

### 5.5 What this document contributes back to AOS

The cross reference runs both ways. AOS defines a strong exposure interface but does not answer the questions this document is organized around, and the following are offered as contributions upstream:

1. **Attack grounding.** AOS asserts that agents should be observable; it does not tie any element to a documented attack. [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) supplies a 34-item corpus with per-field evidence.
2. **Priority tiering.** AOS has no MUST/SHOULD/MAY distinction across its event and AgBOM fields, so an implementer has no guidance on what to instrument first. The [classification summary](CoSAI-AI-Telemetry-RFC.md#44-classification-summary) and [maturity model](CoSAI-AI-Telemetry-RFC.md#5-implementation-guidance) supply one, with an explicit evidence rule behind it.
3. **MITRE ATLAS technique tagging.** AOS has no threat-classification vocabulary. The [ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping) makes AOS-derived detections correlate with the ATT&CK-aligned rest of a SOC.
4. **Input trust classification.** AOS captures message `role` (user / agent / system) but not the *trusted-instruction vs untrusted-data* distinction that the CoSAI risk map treats as the core agentic control (AD §1.2). This is arguably the single highest-value field AOS lacks.
5. **Output egress destination.** AOS traces messages and tool calls but has no field for *where output went*: recipients, outbound URLs, broadcast scope. AD §1.3 argues this is the field that catches `TA-01` and `TA-03` before data leaves.
6. **Delegation and attestation.** AOS's `A2AContext` records the immediate from/to hop but not the originating principal, the multi-hop delegation chain, granted authorizations, or runtime attestation. AD §1.9 and the ODIS cross reference in [§4](#4-aitf--odis-cross-reference) supply these.
7. **Verified vs displayed identity.** `AOC-08`'s lesson (bind and log the immutable identifier, not the display name) applies directly to AOS's user objects and A2A agent cards, which are displayed identities by construction.
8. **Observability-plane integrity (AD §1.11).** AOS's own architecture creates the exposure: a synchronous guardian callout is a dependency that can fail or be starved, and a self-reporting agent can omit. AOS specifies the happy path; AD §1.11 specifies the telemetry for when it does not hold. This is the contribution most specific to AOS's design.
9. **Privacy and retention normativity.** AOS notes that sensitive attributes "may necessitate hashing, truncation, or redaction." [Privacy-preserving logging](CoSAI-AI-Telemetry-RFC.md#5-implementation-guidance) gives a concrete position: access control, tiered retention, hash-first correlation, and redaction as an audited, logged transformation.

### 5.6 Divergences & open coordination items

Two genuine divergences and two coordination items. None is blocking; all should be reconciled before either document is treated as normative alongside the other.

1. **OCSF strategy.** AOS extends **API Activity (6003)** with an `unmapped.aos` namespace and types the agent as `actor.type_id: 99` ("Other") with `type: "AI Agent"`. [§3](#3-implications-for-ocsf--aitf-the-standardization-bridge) instead asks OCSF to ratify **AI Agent Activity (9001)** and **AI Delegation Activity (9002)** plus an `ai_operation` profile. These are different bets on the same schema. The positions are reconcilable and arguably sequential. AOS's `unmapped.*` approach is the correct *interim* carrier under an unratified schema, and matches Phase 0 in [§3.3](#33-incremental-extension-path-via-aitf); this document's asks are the ratification endpoint. Worth noting that AOS's need for an `actor.type_id: 99` workaround is independent evidence for standardization ask (6) in [§3.2](#32-what-cosai-asks-ocsf-to-include-summary). **Action:** align on a shared phase plan before either party submits to OCSF.
2. **OpenTelemetry attribute naming.** AOS's OTel binding uses `agent.*`, `llm.model.name`, and `llm.provider.name`. This document and AITF use the OTel **GenAI semantic conventions** (`gen_ai.*`), which is the upstream-maintained namespace; `llm.*` is not current semconv. The divergence is wider than a prefix: AOS's binding predates the GenAI conventions moving to their own repository and gaining `gen_ai.system_instructions`, `gen_ai.tool.definitions`, the retrieval attributes, and a dedicated `mcp.*` namespace; much of what AOS models by hand now has an upstream home (see [§2.1](#21-what-the-genai-conventions-cover-today)). **Action:** recommend AOS migrate its OTel binding to `gen_ai.*` / `mcp.*`. Low cost while both are drafts, high cost later.
3. **Scope boundary.** This document treats enforcement *outcomes* as telemetry (AD §1.11) and the enforcement *protocol* as out of scope. AOS specifies the protocol and is comparatively quiet on outcomes. The split is clean and probably correct, but it is a choice both groups should ratify rather than assume.

---

## 6. CPEX Cross Reference

[CPEX](https://contextforge-org.github.io/cpex/) is a deterministic reference monitor between an agent and its capabilities. It produces the policy, identity, taint, approval, and routing decisions recorded by AD §1.12; this appendix maps those outputs to the field set and identifies remaining gaps. AD §1.12 takes only these decision records, not CPEX's policy language, plugin model, or deployment architecture.

> **Sourcing.** Element names below are verified against the CPEX repository at commit `035012f` (18 August 2026). The citation is pinned to a commit rather than to a release because the released tags trail the documentation: the latest release, `v0.2.2` (15 July 2026), does not contain the threat-model document that [§6.1](#61-the-threat-model-the-most-important-contribution) and AD §1.12 rest on. The published documentation site also renders a legacy `0.1.x` tree alongside the current pages; nothing in this appendix is taken from it.

### 6.1 The threat model: the most important contribution

CPEX's [threat model](https://contextforge-org.github.io/cpex/docs/threat-model/) is a zero-trust, assume-breach model whose central move is to treat **the LLM itself as the adversary**, not merely as a component an adversary attacks. Three assumptions:

1. **Input vulnerability**: "Prompt injection can arrive through any content the model reads: user messages, tool results, fetched resources, other agents' replies."
2. **Output manipulation**: "An injected instruction becomes a tool call, an argument value, an email body. **The model is a confused deputy.**"
3. **No security properties**: the model cannot maintain confidentiality or enforce authorization; context contents can leak through permitted channels.

From this follows the trust boundary: everything on the agent side of the monitor is assumed hostile, and **"nothing the policy reads comes from there: verified tokens come from the IdP (identity provider), decisions from the PDP, taint labels from the session store, and the delegation and audit state is CPEX's own."** That last clause is why `enforcement-state` is one of the authorities in the **Attribute Source** enum (AD §1.12): the enforcement point's own record of a decision is a distinct provenance from anything an identity provider or policy engine supplied.

**Read strictly, the rest of this document operates on a weaker premise, and the gap is not cosmetic.** AD §§1.1 to 1.11 treat the agent as a *victim* of attack, something to be instrumented so that attacks against it become visible. Under CPEX's model the agent is also a potential *liar*, and that distinction propagates straight into the telemetry: several fields this document marks MUST or SHOULD are values the agent itself supplies. **Autonomy Level** (AD §1.1), **Task / Intent Declaration** (AD §1.8), **System Prompt** (AD §1.1), **Observation / Thought** (AD §1.3), and every reasoning field are self-asserted. A compromised agent can report a benign autonomy level while acting outside it, and `AOC-01` is the corpus's demonstration that agents do misreport: it declared a secret destroyed while the data remained recoverable.

**Verified vs Displayed Identity** (AD §1.9) is already MUST because `AOC-08` turns on the difference between an immutable identifier and a spoofable display name. CPEX generalizes that lesson: identity is not special; *every* security-relevant attribute has a provenance, and telemetry that does not record it cannot survive the assume-breach model. That is the reasoning behind the new cross-cutting **Attribute Source / Trusted-Provenance Marking** ([AD §1.12](Telemetry-Attack-Detection-Addendum.md#112-policy-enforcement--mediation)), and it is the largest change this appendix produced.

Denied and failed attempts are first-class telemetry under this model, not exhaust. CPEX's audit requirement explicitly includes denied attempts. This document was already aligned in spirit (`AOC-12`/`AOC-13`/`AOC-14` are catalogued because their telemetry documents *attempted* attacks that were resisted) but AD §1.12's Authorization Decision Record now makes it structural rather than incidental.

### 6.2 Threats & controls cross reference

CPEX's threat matrix, mapped to this document's fields. This is the tightest available test of coverage, because each row is a control CPEX considers necessary.

| CPEX threat | CPEX control | Covered by | Status |
| :------------- | :------------------- | :----------------------------------------- | :--------------------------- |
| Prompt-injection tool misuse | Policy gates and argument validation before dispatch | Input Trust Classification, Guardrail (Input) Verdict (AD §1.2); Tool Call I/O (AD §1.5); **Authorization Decision Record** (AD §1.12) | **Covered**: the decision record was missing |
| Confused deputy / privilege escalation | Per-caller identity from verified tokens | Identities Used, Verified vs Displayed Identity, Granted Authorizations (AD §1.9) | Covered |
| Cross-request data exfiltration | Session-level taint blocks the write-down | **Session Taint Labels & Information-Flow Decisions** (AD §1.12) | **Covered**: expressible as state, not only as a correlation pattern |
| Credential exposure | Fresh audience-scoped tokens minted per call | **Credential Minting & Scope-Narrowing Check** (AD §1.9) | **Covered** |
| PII disclosure | Field-level redaction on outputs | Guardrail (Output) Verdict (AD §1.3); Guardrail Modification Record (AD §1.2); Tool Privacy Classification (AD §1.5) | Partial: see [§6.5](#65-divergences--gaps-remaining) on field-level granularity |
| Unauthorized high-impact actions | Out-of-band human approval | **Human Approval / Elicitation Event** (AD §1.12) | **Covered** |
| Approval replay | Approvals bound to live arguments | **Human Approval / Elicitation Event**: scope-binding validation result (AD §1.12) | **Covered** |
| Unaccountable actions | Append-only audit per decision, denied attempts included | **Authorization Decision Record** (AD §1.12); Event Sequence Continuity (AD §1.11) | **Covered** |

Five of eight CPEX controls map only to fields in AD §1.12; they had **no counterpart** anywhere else in the field set. That is the strongest single finding in this appendix, and it reflects a real blind spot rather than a difference of emphasis: the document was thorough on *observation* and near-silent on *enforcement*.

### 6.3 APL, CMF & identity surface

| CPEX element | This document | Status |
| :----------------------------------------- | :----------------------------------------- | :------------------ |
| Effects: `deny` / `deny(reason)` / `deny(reason, code)`; per-step **suppressed deny** (a plugin in `transform` mode cannot block, so a deny it attempts is recorded and not enforced), `Aborted`, `Error`; fail-closed `plugin_panic` deny code ([cpex#166](https://github.com/contextforge-org/cpex/pull/166) audit seam) | **Authorization Decision Record**: decision, reason, machine-readable code, per-step actions including suppressed deny and abort (AD §1.12) | **Covered** |
| Effect: `taint(label[, scope])`; session vs message scope | **Session Taint Labels** (AD §1.12) | **Covered** |
| Effect: `delegate(...)`, subject `user` / `client` / `caller_workload` / `this_workload` | **Credential Minting & Scope-Narrowing Check** (AD §1.9) | **Covered** |
| Effect: `require_approval(...)`; `elicitation.id` / `.status` / `.outcome` / `.approver` / `.channel` | **Human Approval / Elicitation Event** (AD §1.12) | **Covered** |
| Effect: `restrict: {allow_models, deny_models, allow_regions, allow_sites, max_cost_tier, custom, on_empty}` | **Backend / Route Restriction Decision** (AD §1.12) | **Covered** |
| Effect: `plugin(name)` dispatch | Guardrail Verdict (AD §§1.2 to 1.3); Guardrail Modification Record (AD §1.2) | Covered |
| Field pipelines: `mask(N)`, `redact`, `redact(!pred)`, `omit`, `hash`, `pii.redact`, `pii.detect`, `injection.scan` | Guardrail Modification Record (AD §1.2); Guardrail (Output) Verdict (AD §1.3) | Partial: whole-payload, not per-field |
| Route phases: `args` → `authorization.pre_invocation` → `result` → `authorization.post_invocation` | Action Type (AD §1.1); Tool Execution ID (AD §1.5) pairs pre/post | Partial: phase identity is not recorded |
| PDP integration: Cedar / CEL / OPA resolvers, `on_allow` / `on_deny` | **Authorization Decision Record**: deciding authority and rule id (AD §1.12) | **Covered** |
| `delegation.depth`, `delegation.origin_subject_id`, `delegation.granted.permissions` | Delegation Chain, Originating Principal, Granted Authorizations (AD §1.9); scope delta via **Credential Minting** (AD §1.9) | Covered |
| Identity slots: `subject` (human), `client` (OAuth app), `caller_workload` (SPIFFE SVID), simultaneously | Identities Used (AD §1.9), now explicitly a **set**, not a single value | Covered (clarified) |
| Attribute namespaces `agent.*`, `framework.*`, `subject.*`, `delegation.*`, `security.*`, `http.*`, `data.*` | Mapped to AITF namespaces in [§4](#4-aitf--odis-cross-reference) | Covered |
| CMF (protocol-agnostic envelope; one policy across tools, A2A, inference, prompts, resources) | Action Type (AD §1.1); MCP Server Identity & Primitive (AD §1.5); Inter-Agent Message (AD §1.8) | Partial, see [§6.5](#65-divergences--gaps-remaining) |
| Extension mutability tiers: immutable / **monotonic** / mutable | Monotonicity is asserted for taint and delegation but not recorded | Out of scope: policy-engine internal |
| Capability-gating: plugins declare capabilities; extensions filtered per plugin | Least-privilege for enforcement components | Out of scope: enforcement architecture |
| Deployment placements: gateway / sidecar / in-process, each with named coverage gaps | **Mediation Coverage & Bypass Path** (AD §1.12) | **Covered** |
| Builtins: `identity/jwt`, `delegator/oauth`, `validator/pii-scan`, `audit/logger`, `cedar-direct`, `cel`, `valkey` | Named as implementations, not telemetry | Out of scope |

### 6.4 What this document contributes back to CPEX

1. **Retention, priority, and evidence.** CPEX produces decision records; it does not say which are worth keeping, for how long, or in what order to adopt them. The [tiering rubric](CoSAI-AI-Telemetry-RFC.md#42-classification-legend) and [maturity model](CoSAI-AI-Telemetry-RFC.md#5-implementation-guidance) supply that, with attack grounding behind each call.
2. **A SOC destination.** CPEX's audit log is a local artifact. [§3](#3-implications-for-ocsf--aitf-the-standardization-bridge) now proposes `ai_authorization`, `ai_taint`, and `ai_approval` OCSF objects plus an `attribute_source` enum, so enforcement decisions correlate with the rest of the security estate rather than sitting in a separate store.
3. **MITRE ATLAS tagging.** CPEX has no threat-classification vocabulary; a denial carries a policy reason, not a technique. Stamping decisions with `AML.Txxxx` ([AD §3.6](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping)) makes them correlate with ATT&CK-aligned tooling.
4. **The observation surface CPEX explicitly cannot see.** CPEX mediates the agent↔capability boundary. It does not observe memory reads and writes (AD §1.6), retrieval and its provenance (AD §1.7), token consumption and loop behaviour (AD §1.4, AD §1.8), model supply chain (AD §1.4), or asset composition (AD §1.10). `IR-02` (MINJA) poisons memory using entirely benign queries; every individual operation is policy-clean, and a reference monitor sees nothing wrong. **Enforcement and observation are complementary, not substitutable**, and a deployment running CPEX still needs most of AD §§1.1 to 1.10.
5. **Provider-side and governance signals.** `AOC-06`, silent provider truncation on sensitive topics, is invisible to a reference monitor, since the operation was permitted and completed.
6. **Attack grounding for the threat matrix.** CPEX's threat rows are stated as principles; [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) supplies documented incidents for each, which is useful for justifying the controls to a risk committee.

### 6.5 Divergences & gaps remaining

1. **Redaction granularity.** CPEX redacts *per field* under a predicate (`ssn: 'str | redact(!perm.view_ssn)'`); this document's **Guardrail Modification Record** is whole-payload. Per-field records are more useful and more privacy-sensitive at once. Left as-is deliberately (a per-field redaction map is a policy decision, not a default) but implementers running field-level pipelines should record at that granularity.
2. **Route-phase identity is not captured.** CPEX distinguishes four phases, and *which* phase denied an operation is diagnostically meaningful (argument validation vs authorization vs post-check). This document records the decision but not the phase. A candidate sub-attribute of the Authorization Decision Record; not proposed as a separate field.
3. **CMF normalization is an unadopted good idea.** CPEX's Common Message Format lets one policy cover tool calls, A2A, inference, prompts, and resources uniformly. This document organizes telemetry by *component* (AD §§1.1 to 1.12), which means an equivalent operation is described differently depending on which pipeline carried it. The component organization is deliberate (it maps to the CoSAI Risk Map) but a normalized **operation view** across protocols would make cross-protocol detections expressible.
4. **Covert channels are out of scope for both.** CPEX states plainly that "determined models can encode data within permitted output channels." This document's **Output Egress Destination** and **Citations** narrow the channel but do not close it. Neither document should claim otherwise.
5. **Host compromise.** CPEX's guarantees "hold only with intact processes and state stores"; this document's AD §1.11 covers telemetry suppression but neither addresses a compromised enforcement host. Shared limitation, worth stating in both.
6. **Terminology collision.** CPEX uses *taint* for session-scoped information-flow labels; this document uses *trust classification* for per-segment input labelling. They are different mechanisms and both are needed, AD §1.2 classifies a payload, AD §1.12 tracks accumulated state. The terms should not be merged, and AD §1.12 says so explicitly.

---

## 7. Implications for NIST AI RMF and NIST CSF (incl. the Cyber AI Profile)

§§2 to 4 route this field set toward **schemas**; §§5 and 6 reference it against **adjacent technical standards**. This appendix and [§8](#8-implications-for-isoiec-42001) address a different consumer: **governance frameworks that use telemetry as control evidence**.

That places them at the **A** end of this document's [use-case priority](CoSAI-AI-Telemetry-RFC.md#41-use-case-priorities): compliance audit, the lowest of the four. The ordering is deliberate: **this field set is designed for detection and response, and its audit value is a by-product.** A telemetry programme built to satisfy an auditor produces different fields than one built to catch `TA-01`, and where the two diverge this document follows detection. The useful consequence is that a deployment implementing the MUST tier for **D** and **R** reasons will find it has already produced most of the evidence these frameworks ask for, which is a far easier argument to fund than the reverse.

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
| **GOVERN** (GV.OC, GV.SC) | Asset inventory and AgBOM (AD §1.10); model provenance and signing (AD §1.4); dependency graph and version (AD §1.10); autonomy level and task declaration (AD §§1.1, 1.4) | **Partial**: supply-chain outcomes are well served; policy and role outcomes are organizational, not telemetric |
| **IDENTIFY** (ID.AM, ID.RA) | Agent name, instance ID, surface (AD §1.1); capability-set change (AD §1.10); AgBOM (AD §1.10); tool and MCP inventory (AD §1.5); fleet aggregates (AD §1.10) | **Strong**: Capability-Set Change is the field that makes ID.AM *continuous* rather than periodic |
| **PROTECT** (PR.AA, PR.DS) | Identities used, verified-vs-displayed identity, granted authorizations, credential minting (AD §1.9); authorization decision record (AD §1.12); guardrail verdicts (AD §§1.2 to 1.3); sandbox posture (AD §1.5) | **Strong**: AD §§1.9 and 1.12 are PR.AA evidence almost verbatim |
| **DETECT** (DE.CM, DE.AE) | **The entire MUST tier.** Input trust classification and guardrail verdicts (AD §1.2); output egress and refusals (AD §1.3); tool call I/O (AD §1.5); memory and retrieval events (AD §§1.6 to 1.7); loop and resource signals (AD §1.8); session taint (AD §1.12); every [correlation pattern](Telemetry-Attack-Detection-Addendum.md#2-correlation-patterns) | **Strongest alignment in the document.** DE.CM is continuous monitoring; DE.AE is the correlation-pattern layer |
| **RESPOND** (RS.MA, RS.AN) | The identifier hierarchy and trace context (AD §1.1); tool execution IDs (AD §1.5); memory and retrieval provenance (AD §§1.6 to 1.7); delegation chain (AD §1.9); ATLAS technique tag (AD §1.2); event sequence continuity (AD §1.11) | **Strong**: this is the document's **R** priority, and the ATLAS tag makes RS.AN findings portable |
| **RECOVER** (RC.RP) | Lifecycle state and revocation (AD §1.9); instance ID for per-instance quarantine (AD §1.1); capability-set change for rollback verification (AD §1.10) | **Weak, and appropriately so**: recovery is largely an operational discipline; telemetry scopes it but does not perform it |

Coverage is strongest where this document concentrates (**DETECT**, **RESPOND**) and weakest where its priorities place least weight (**RECOVER**, the organizational half of **GOVERN**). That follows the [D > R > Q > A ordering](CoSAI-AI-Telemetry-RFC.md#41-use-case-priorities), and it shows which CSF outcomes this field set will and will not evidence.

### 7.3 AI RMF mapping, by function

| AI RMF function | Telemetry that evidences it | Coverage |
| :---- | :-------------------------------------------------------- | :----------------------------------------- |
| **GOVERN** | Autonomy level (AD §1.1); task/intent declaration (AD §1.8); tool ACL and scope (AD §1.5); human approval events (AD §1.12); privacy and retention posture ([Implementation Guidance](CoSAI-AI-Telemetry-RFC.md#5-implementation-guidance)) | Partial: **Human Approval / Elicitation** (AD §1.12) is the strongest single piece of GOVERN evidence, because it records oversight *actually exercised* rather than merely documented |
| **MAP** | Component taxonomy (AD §§1.1 to 1.12 organized by [CoSAI Risk Map](#1-mapping-to-the-cosai-risk-map-risks--controls)); AgBOM (AD §1.10); trust boundaries (AD §1.5); [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) attack corpus | Strong: the risk-map component mapping and attack inventory are MAP artifacts in substance |
| **MEASURE** | **The whole field set.** Every MUST field; guardrail scores; refusal rates; loop and resource metrics; ATLAS-tagged detections | **The natural home.** AI RMF asks that AI risks be measured; this document specifies what to measure and why |
| **MANAGE** | Incident response fields (AD §§1.1, 1.5, 1.9); enforcement decisions and taint (AD §1.12); kill-switch and lifecycle state (AD §1.9); [correlation patterns](Telemetry-Attack-Detection-Addendum.md#2-correlation-patterns) | Strong for security risk; silent on fairness, bias, and environmental risk, which are out of scope here |

**Scope note.** AI RMF's trustworthiness characteristics extend well beyond security: validity, fairness, bias management, interpretability, and environmental impact. **This document evidences the security slice only.** An organization using AI RMF should not read comprehensive MEASURE coverage into it. The `gen_ai.evaluation.*` conventions discussed in [§2.1](#21-what-the-genai-conventions-cover-today) are the natural carrier for the quality and fairness slice, which is one more reason to keep security guardrail signals distinguishable from quality evaluations rather than merging them.

### 7.4 What this implies

1. **Propose the field set as a reference implementation for the Cyber AI Profile's *Secure* focus area.** The Profile specifies outcomes for securing AI systems but not the telemetry that evidences them; this document supplies exactly that and is attack-grounded, which is the kind of justification a NIST community profile can cite. **This is the highest-value action in this appendix**, and the timing is favourable while the Profile is between preliminary and public draft.
2. **Publish a CSF subcategory-level mapping.** [§7.2](#72-csf-20-mapping-by-function) maps to Category granularity; auditors work at Subcategory granularity (106 subcategories). A per-subcategory mapping is mechanical work with real adoption value, and it is the single most requested artifact when a security framework meets a compliance programme.
3. **Do not reshape the field set to improve framework coverage.** The weak areas (RECOVER, organizational GOVERN) are weak because they are not telemetry problems. Adding fields to improve a coverage table would violate the [evidence rule](CoSAI-AI-Telemetry-RFC.md#42-classification-legend) and inflate the MUST tier for **A**-tier benefit.
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
| **A.2 Policies related to AI** | System prompt / instruction config (AD §1.1) as the enforced expression of policy; authorization decision record and rule identity (AD §1.12) | Partial: AD §1.12 evidences policy *in force*, which is stronger than a policy document |
| **A.3 Internal organization** | Creator, oncall, ownership metadata (AD §1.10) | Weak: organizational, not telemetric |
| **A.4 Resources for AI systems** | AgBOM and dependency graph (AD §1.10); model, tool, memory and knowledge inventory (AD §§1.4 to 1.7, 1.6); token, compute and storage aggregates (AD §1.8) | **Strong**: the AgBOM cluster is an A.4 artifact almost exactly; A.4.2 *Resource documentation* and A.4.5 *System and computing resources* are directly served |
| **A.5 Assessing impacts of AI systems** | [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) attack corpus; [§1](#1-mapping-to-the-cosai-risk-map-risks--controls) risk mapping; guardrail and refusal rates as realized-impact measures | Partial: supplies the security input to impact assessment, not the assessment |
| **A.6 AI system life cycle** | **Event logs (A.6.2.8) is the direct hit**: AD §§1.1 to 1.12 in their entirety; capability-set change (AD §1.10) for change control; verification via evaluation and guardrail records | **Strongest alignment.** 42001 requires event logging without specifying content; this document specifies the content |
| **A.7 Data for AI systems** | Retrieval provenance (AD §1.7); memory provenance (AD §1.6); input source and trust classification (AD §1.2); data classification constraints (AD §1.9) | **Strong**: A.7's provenance and quality controls are served by the provenance fields, which exist here for detection reasons and satisfy A.7 as a by-product |
| **A.8 Information for interested parties** | Incident-response evidence (AD §§1.1, 1.5, 1.9); ATLAS-tagged detections (AD §1.2) supporting incident communication | Partial: supplies substance for A.8.4 incident communication; the communication process itself is out of scope |
| **A.9 Use of AI systems** | Autonomy level (AD §1.1); task/intent declaration (AD §1.8); human approval events (AD §1.12); trigger type (AD §1.1); surface (AD §1.1) | **Strong**: A.9's *intended use* and *responsible use* controls are evidenced by exactly the fields that detect goal drift |
| **A.10 Third-party and customer relationships** | MCP server identity (AD §1.5); peer agent card (AD §1.8); provider identity (AD §1.4); model provenance (AD §1.4); delegation chain (AD §1.9) | **Strong**: third-party AI dependencies are visible through the tool, MCP, A2A and supply-chain fields |

### 8.2 Where this document is thin, and what would fix it

Three of the four weak areas are properly out of scope. The fourth is a genuine gap.

1. **Organizational controls (A.3, parts of A.2, A.8)** are roles, reporting lines and communication processes. Not telemetry. Out of scope, correctly.
2. **Impact assessment (A.5)** is a *process* control. This document supplies inputs; it should not attempt the assessment.
3. **Non-security trustworthiness**, fairness, bias, and societal impact under A.5.4 and A.5.5, is outside this document's remit, as it is for [AI RMF](#73-ai-rmf-mapping-by-function).
4. **Records management is a real gap.** 42001 clause 7.5 (documented information) and clause 9 (monitoring, measurement, analysis and evaluation; internal audit; management review) require telemetry to be *retained, controlled, and demonstrably used*. This document specifies retention tiers and access control in [Implementation Guidance](CoSAI-AI-Telemetry-RFC.md#5-implementation-guidance) but does not specify **evidentiary properties**: immutability, defined retention periods per field class, chain of custody, or reviewer access records. AD §1.11's **Event Sequence Continuity** is the nearest thing and is SHOULD. **Recommendation:** if CoSAI wants this field set to be usable as certification evidence, the retention guidance should be promoted from prose to a normative table with per-tier retention minimums.

### 8.3 What this implies

1. **Position the field set as the content specification for the Annex A event-logging control** (`A.6.2.8` as public summaries number it). 42001 requires event logging across the AI life cycle without saying what to log. This is the clearest single fit between the two documents, and (as with the Cyber AI Profile) it lets an organization satisfy a standard using telemetry it built for detection. The position turns on A.6 containing an event-logging requirement that specifies no content, which is corroborated independently of the control's number; if the purchased text numbers it differently, the argument moves with it unchanged.
2. **Map to Statement of Applicability granularity.** SoA is where 42001 implementation happens. A mapping at individual-control level (A.6.2.8, A.7.4, A.9.3 …) rather than objective level would let an organization cite specific fields per control. Same recommendation, and same mechanical-but-valuable character, as the CSF subcategory mapping in [§7.4](#74-what-this-implies). One prerequisite differs: at individual-control granularity the numbering is load-bearing, so that work needs the purchased text rather than the public summaries this appendix was built from.
3. **Close the records-management gap** if certification evidence is a goal, see [§8.2](#82-where-this-document-is-thin-and-what-would-fix-it) item 4. This is the one place where a compliance framework surfaces a genuine weakness rather than an out-of-scope boundary.
4. **Reuse, do not re-derive.** ISO/IEC 42001 and NIST AI RMF overlap substantially; organizations frequently run both. The mappings in [§7](#7-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile) and here should share a single underlying field→control table with two views, rather than diverging.

> **The through-line for both appendices.** These frameworks are **consumers** of this telemetry, not designers of it. The document's value to them is that a field set built to catch documented attacks turns out to evidence a large share of what they ask for, and that the evidence carries attack grounding, which is more defensible under audit than a control asserted to exist. The direction of derivation should not reverse: **do not add fields to improve a coverage table.**

---

## References

### Standards & frameworks

23. **CoSAI Risk Map**: Coalition for Secure AI, fine-grained AI system components taxonomy. <https://github.com/cosai-oasis/secure-ai-tooling/tree/main/risk-map>. 55 risks / 68 controls: PR [#507](https://github.com/cosai-oasis/secure-ai-tooling/pull/507) merged, plus `riskAgentMemoryPoisoning`, `riskDeceptiveAgentReporting`, `riskUnsafeInterAgentPropagation` and `controlAgentMemoryIntegrity`; risk IDs migrated to the `risk`+camelCase convention.

<!-- list break: reference numbers are not contiguous -->

25. **AITF**: AI Telemetry Framework (OTel + OCSF binding), donated to CoSAI WS2. <https://github.com/cosai-oasis/ws2-defenders/tree/main/telemetry>

<!-- list break: reference numbers are not contiguous -->

35. **OpenTelemetry, GenAI semantic conventions.** Now maintained in a dedicated repository: <https://github.com/open-telemetry/semantic-conventions-genai>. Spans, metrics, events, MCP, and provider-specific conventions, **all at Development status**. Attribute registry: <https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/>. Entries marked *Deprecated* there mostly reflect the relocation rather than withdrawal, but not always: some were **renamed** in the move (`gen_ai.usage.cache_creation.input_tokens` → `gen_ai.usage.cache_write.input_tokens`) and some were **withdrawn outright** (`gen_ai.prompt` and `gen_ai.completion`, both `reason: obsoleted`, "Removed, no replacement at this time"). Names must therefore be read from the new repository, not the deprecated registry. **Names in XM §§2 to 4 were verified against `semantic-conventions-genai` @ `0c87594` (10 September 2026) and `semantic-conventions` @ `22b6cbb` (9 September 2026); neither repository publishes release tags, so commit SHAs are the only stable anchor.** Cross referenced in [XM §2](Telemetry-Cross-Mapping-Addendum.md#2-implications-for-opentelemetry-the-instrumentation-bridge).

<!-- list break: reference numbers are not contiguous -->

37. **OCSF. Open Cybersecurity Schema Framework.** <https://ocsf.io/> · schema browser: <https://schema.ocsf.io/>
38. **OWASP AOS, Agent Observability Standard.** OWASP. <https://aos.owasp.org/>. Three pillars (Instrument / Trace / Inspect); cross referenced in [XM §5](Telemetry-Cross-Mapping-Addendum.md#5-owasp-aos-cross-reference). *Working draft.* Verified against the specification sources at commit `e4a50f6` (30 December 2025), schema version **0.1.0** (`specification/AOS/aos_schema.json` in [OWASP/www-project-agent-observability-standard](https://github.com/OWASP/www-project-agent-observability-standard)); the specification has not changed since that date.

<!-- list break: reference numbers are not contiguous -->

44. **CPEX**: policy-enforcement runtime and reference monitor for AI agents. <https://contextforge-org.github.io/cpex/> · threat model: <https://contextforge-org.github.io/cpex/docs/threat-model/>, cross referenced in [XM §6](Telemetry-Cross-Mapping-Addendum.md#6-cpex-cross-reference). Verified against [contextforge-org/cpex](https://github.com/contextforge-org/cpex) at commit `035012f` (18 August 2026). Pinned to a commit rather than to the current release (`v0.2.2`, 15 July 2026), which predates the threat-model document this appendix cites.

<!-- list break: reference numbers are not contiguous -->

53. **RFC 9943**: *An Architecture for Trustworthy and Transparent Digital Supply Chains* (SCITT). Standards Track. <https://www.rfc-editor.org/rfc/rfc9943.html>
54. **RFC 9942**: *CBOR Object Signing and Encryption (COSE) Receipts.* Standards Track, June 2026. <https://www.rfc-editor.org/rfc/rfc9942.html>
