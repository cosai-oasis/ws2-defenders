# Telemetry for AI Security {**Working Draft v0.5**}

**Status:** Request for Comments, revision 0.5
**Origin:** Coalition for Secure AI (CoSAI), Workstream 2 (Defenders)
**Disclosure:** Prepared for open publication under CoSAI. No commercial sponsorship; the standards positions taken favour open specifications (OpenTelemetry, OCSF, OWASP AOS, CPEX) over any vendor implementation. Drafting, cross-referencing, and consistency checking were performed with AI assistance.

---

## 1. Introduction

AI systems now read untrusted content, decide what to do about it, and act: calling tools, writing memory, retrieving documents, sending mail, invoking other agents. Attacks against them succeed in the gap between reading and acting. Detection has to happen in that gap, as far left in the kill chain as possible.

Catching an injection attack in flight means knowing what the model was given, how far that input was trusted, what it decided to do, and where its output went. Most deployments record none of this. Traditional application logging captures HTTP requests, database queries, and authentication events. The decisive moments in an AI system (an instruction arriving inside a retrieved document, a guardrail verdict, a memory write that will shape every future session) leave no trace there. Without those records there is nothing to detect against, and afterwards nothing solid to investigate, debug, or audit.

### 1.1 One umbrella, many efforts

Several communities are converging on AI telemetry, and their work is complementary. **OpenTelemetry** [[35]](#standards--frameworks) defines how instrumentation emits GenAI and agent data. **OCSF**, the Open Cybersecurity Schema Framework [[37]](#standards--frameworks), defines how security events are normalized for a SOC. **OWASP AOS**, the Agent Observability Standard [[38]](#standards--frameworks), defines how an agent exposes itself for observation. **CPEX** [[44]](#standards--frameworks) defines how a policy runtime mediates agent actions. **ODIS**, the Open Delegation and Identity Standard [[26]](#standards--frameworks), defines delegated identity and authority. **MITRE ATLAS** [[1]](#primary-sources-attack-corpus--taxonomy) defines the adversary techniques to classify against. Regulation adds its own obligations, notably EU AI Act Article 12 [[34]](#standards--frameworks) and the NIST AI Risk Management Framework [[30]](#standards--frameworks).

Those efforts answer different questions. The open question this RFC addresses is which fields must exist, why, and at what priority.

This RFC is a requirements layer for security telemetry, not a wire format. It specifies the fields an AI system must produce for security, the evidence that makes each field necessary, and a suggested build order.

### 1.2 For example: EchoLeak

In June 2025 Microsoft disclosed **EchoLeak** (CVE-2025-32711, CVSS 9.3), reported by Aim Labs [[4]](#real-world-attack-primary-sources). A single crafted email caused Microsoft 365 Copilot to retrieve the attacker's text as context, act on it as instruction, and exfiltrate internal SharePoint, OneDrive and Teams content to an attacker-controlled endpoint. No user ever clicked anything. The chain defeated the cross-prompt-injection classifier, link redaction, and content-security policy in turn, and routed the egress through a trusted proxy domain.

Each step in that chain is detectable, and each depends on a field most deployments do not collect:

- The email entered as **untrusted data** and was acted on as instruction, a distinction nothing recorded.
- The run was **autonomous**; no human initiated it, which is itself the strongest first filter for injection.
- The **injection classifier was bypassed**. A classifier whose verdicts are not logged cannot be shown to have failed.
- Content left for a **previously unseen outbound destination**: the last point at which the attack could have been stopped rather than reconstructed afterwards.

Four fields, none exotic. Their absence is the difference between a detection and a disclosure notice.

---

## 2. How To Use This Doc

### 2.1 For CISOs

Go to the **classification summary** ([§4.5](#45-classification-summary), the single table listing every field by component and tier) and treat the **applicable subset of the MUST column** as the baseline each AI deployment should meet. The three tiers are **MUST**, **SHOULD**, and **MAY**, used in the RFC 2119 sense and defined in [§4.2](#42-classification-legend). The catalogue contains 50 MUST fields; a deployment's baseline consists of those whose defining component, operation, or event exists in that deployment. This is the artifact to take into an engineering plan or a budget discussion.

- **The justification is evidentiary.** Every MUST field cites named real-world attacks and incidents. The ask is "these fields catch these attacks," not "best practice suggests." [Appendix J](Telemetry-Attack-Detection-Addendum.md#appendix-j-tiering-rationale) sets out that reasoning per component if it is challenged.
- **There is a build order.** The MUST tier is sequenced, so a team starts with the identifiers and content that everything else correlates through rather than instrumenting alphabetically.
- **Compliance follows detection, not the reverse.** MUST coverage already evidences most of NIST CSF [[31]](#standards--frameworks) **DETECT** and **RESPOND**, AI RMF **MEASURE**, and ISO/IEC 42001 [[33]](#standards--frameworks) event-logging control; the mappings are in [Appendix H](Telemetry-Cross-Mapping-Addendum.md#appendix-h-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile) and [Appendix I](Telemetry-Cross-Mapping-Addendum.md#appendix-i-implications-for-isoiec-42001), which show coverage strongest exactly where this document concentrates and weakest where it places least weight. Build for detection and the audit evidence is a by-product; building for audit does not produce detection.

One decision cannot be delegated to engineering: how much prompt, response, and memory content is retained, for how long, and who may read it. The MUST tier can be met with hashes and classifications where raw content is too sensitive to keep, but that is a policy call, and it should be made deliberately rather than defaulted into.

### 2.2 For the open source security community

Each adjacent open specification has its own appendix, stating what this field set already maps onto, what that standard cannot currently express, and the specific additions proposed. Start with yours.

| Community | Appendix | What is proposed |
| :------------- | :---- | :-------------------------------------------------------------------------------------- |
| **OpenTelemetry** [[35]](#standards--frameworks) | D | 9 attribute proposals: input trust classification, a security guardrail signal, memory provenance and footprint, retrieval provenance, turn and step identifiers |
| **OCSF** [[37]](#standards--frameworks) | E | 4 asks: two AI event classes (tracking ocsf-schema#1640), extensions to the existing `ai_operation` profile (ocsf-schema#1704 and #1729 in flight), new objects and enums; ATLAS technique tagging needs no schema change |
| **CoSAI Risk Map (WS3)** [[23]](#standards--frameworks) | B | 3 refinements: confirm `componentMemory` covers persistent long-term memory, add a component for background and scheduled execution, and require the ATLAS technique tag on `controlThreatDetection` |
| **OWASP AOS** [[38]](#standards--frameworks) | F | 9 contributions: trust classification, egress destination, ATLAS tagging, priority tiering, and migration of its OTel binding from `llm.*` to `gen_ai.*` |
| **CPEX** [[44]](#standards--frameworks) | G | 6 contributions: retention and priority guidance, and a SOC destination for enforcement decisions |

**AITF** [[25]](#standards--frameworks), the AI Telemetry Framework, donated to CoSAI Workstream 2, is the bridge between this document and both of those destinations, OpenTelemetry for emission, OCSF for consumption. It carries these fields as OpenTelemetry attributes today and emits them into OCSF ahead of formal ratification, so adopters are not blocked on either standards body. The field-level mapping is **Appendix C**. **NIST** (AI RMF and CSF, including the Cyber AI Profile) and **ISO/IEC 42001** are consumers of this field set rather than destinations for proposals, so they are not in the table above; their mappings are [Appendix H](Telemetry-Cross-Mapping-Addendum.md#appendix-h-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile) and [Appendix I](Telemetry-Cross-Mapping-Addendum.md#appendix-i-implications-for-isoiec-42001).

- **They are evidence-gated and therefore small.** A field becomes a standardization ask only once two or more independent documented attacks require it. Nothing is proposed speculatively.
- **Emission and consumption move together.** A field OpenTelemetry emits but OCSF cannot represent arrives at the SIEM as unstructured overflow; a field OCSF defines but no instrumentation produces stays theoretical. Paired asks are the intent.

CoSAI is engaging the **OpenTelemetry** and **OCSF** communities directly on this work, and welcomes input from the wider open source security community in turn. The timing favours it: every OpenTelemetry GenAI convention is at *Development* status and has just moved to a dedicated repository, so contributions land more cheaply now than after stabilization.

What is wanted in return: corrections to the mappings, and attacks the corpus is missing.

### 2.3 For builders of AI solutions

One telemetry set covers **detection** while a run is in flight, **response** afterwards, **debugging** of behaviour, and **compliance audit**. Instrumenting once for all four is cheaper than retrofitting each purpose later.

Work from the **per-component breakdown**. The field set is organized by the components of an AI system (reasoning core, input handling, output handling, model and serving, tools, memory, retrieval, orchestration, identity and delegation, asset inventory, observability plane, and policy enforcement) so you can take the components you actually build and read off what each must emit. Every field states what to capture and the attacks that make it necessary. The correlation patterns that follow the field tables show how fields combine into detections, and are usually the fastest way to see why a given field earns its place.

Practical notes:

- **Do not invent a schema.** Appendices C to E give the OpenTelemetry attribute names and the OCSF mapping. Emit over OpenTelemetry today; the bindings are already specified.
- **Content in events, identifiers in span attributes, aggregates in metrics.** Prompts, tool results, and retrieved documents are unbounded and often sensitive; as span attributes they break cardinality limits and follow the span into every backend.
- **Do not head-sample security events.** Default OpenTelemetry sampling [[36]](#standards--frameworks) discards attack evidence blind to whether an event is security-relevant. Guardrail verdicts, refusals, tool errors, and authorization denials are recorded at 100%.
- **Propagate trace context across every hop**, including MCP [[39]](#standards--frameworks) and agent-to-agent [[40]](#standards--frameworks) calls. Without it, multi-agent activity cannot be reassembled into a single incident.

---

## 3. Scope

### 3.1 In scope

The security-relevant telemetry an AI system should produce: which fields, justified by which documented attacks, at which priority. Fields are organized by the component that emits them (reasoning core, input and output handling, model and serving, tools, memory, retrieval, orchestration, identity and delegation, asset inventory, observability plane, and policy enforcement) and each is tiered **MUST**, **SHOULD**, or **MAY** against a stated test. The document adds correlation patterns showing how fields combine into detections, and mappings onto OpenTelemetry, OCSF, AITF, ODIS, OWASP AOS, CPEX, the CoSAI Risk Map, NIST CSF and AI RMF, and ISO/IEC 42001.

Telemetry for **agents the deployment does not operate** is in scope, with the limits that implies: what is observable at your own boundary, plus whatever the counterparty presents and can be verified. [§4.7](#47-agents-you-do-not-operate) sets out how the field set applies in that case.

The framing implies three limits. This is **not a wire format**: the bindings are in the appendices. It does **not specify detection logic**, only the fields detections consume. And it covers the **security** slice of AI trustworthiness; fairness, bias, safety alignment, and environmental impact are outside its remit.

### 3.2 Not in scope

Two areas are excluded deliberately, and both are intended for subsequent work.

**Privacy compliance.** The implementation guidance recommends handling practices (access control, tiered retention, redaction, hash-first correlation) because content-bearing fields carry evident risk. Those are handling practices, not a compliance programme. Lawful basis, data-subject rights, cross-border transfer, and impact-assessment obligations are not addressed, and meeting the MUST tier does not discharge them.

**Security of the telemetry itself.** The field set treats the telemetry plane as an asset only insofar as it must report its own failure: the observability-plane section covers detecting suppressed events, unreached enforcement points, and incomplete instrumentation. Defending the pipeline is a different problem and is not solved here: authenticating emitters, securing transport and storage, controlling access to collected content, and establishing the tamper-evidence and chain of custody that evidentiary use requires. This is a genuine tension with the immutable, tamper-evident logging that classic audit practice expects, and it is an exclusion of *this document's* scope rather than a claim that the problem does not matter: the CoSAI Risk Map now carries `controlAuditTrailIntegrityVerification` and `controlAuditRecordRepositoryIndependence` for it, and [§15](#15-observability-plane-integrity) records when the plane fails even though it does not defend it. **Conformance to this document's field catalogue alone does not satisfy those integrity controls**; adopters needing audit-grade evidence must implement them separately.

---

## 4. How to read the field set

Each section below is a fine-grained component (or a tightly related cluster). Field tables use these columns:

- **Field**: conceptual field name (implementation-neutral).
- **Cls**: MUST / SHOULD / MAY.
- **Capture (concept)**: what to record, stated generally enough to bind to any framework.
- **Evidence**: attack IDs that establish the need (see Appendix A).

The reasoning behind each tier is in **[Appendix J](Telemetry-Attack-Detection-Addendum.md#appendix-j-tiering-rationale)**; AITF and ODIS attribute names are in **[Appendix C](Telemetry-Cross-Mapping-Addendum.md#appendix-c-aitf--odis-cross-reference)**.

### 4.1 Use-case priorities

Every field is justified against four use cases, **in this priority order**:

| | Use case | What it means |
| :---- | :------------------------- | :---------------------------------------------------------------------- |
| **D** | **Threat detection** | Enables a detection to fire on an attack in progress. *Highest priority.* |
| **R** | **Incident response** | Enables scoping, attribution, containment, and forensic reconstruction after the fact. |
| **Q** | **Service debugging / quality** | Explains why the system behaved as it did; performance, cost, and correctness. |
| **A** | **Compliance audit** | Evidences a control to an auditor or regulator. *Lowest priority.* |

Where a field serves several, the **highest-priority** use case governs its tier. A field whose value is mainly Q or A does not reach MUST no matter how useful it is.

**Availability and provider-policy signals are in scope, and this order is what places them.** A signal that makes a *silent failure distinguishable from a clean result* is detection material, not governance reporting: `AOC-06` is a provider API truncating responses and returning "unknown error", which is the model-serving instance of the problem [§15](#15-observability-plane-integrity) is built around, where a verdict that never arrived and a verdict of `allow` read identically in the log. Where such a signal instead evidences a policy or an SLA, its value is Q or A and it lands at MAY, as **Provider / Endpoint Identity** (§8) does. The boundary is drawn by what the signal lets a defender distinguish, not by whether an adversary was involved.

### 4.2 Classification legend

The keywords **MUST**, **SHOULD**, and **MAY** are used as defined in **RFC 2119** [[51]](#standards--frameworks), as updated by **RFC 8174** [[52]](#standards--frameworks): they carry that meaning only in capitals, so lowercase "optional" or "should" elsewhere in this document is ordinary prose. Each field carries exactly one keyword, and the table below states both the RFC 2119 obligation and the evidentiary test this document applies to assign it.

| Tag | Meaning | Test |
| :---- | :-------------------- | :------------------------------------------------------------------------------ |
| **MUST** | Baseline. Required whenever the field is applicable under the rules below. | Grounded in **≥ 2 independent documented instances** in [Appendix A](Telemetry-Attack-Detection-Addendum.md#appendix-a-attack--incident-inventory); **or 1 where the field is especially useful for D or R**; *and* implementable on essentially any current system that has the relevant component, operation, or event. |
| **SHOULD** | Required once a deployment adopts a modality or faces a threat scenario at the **edge of current agentic practice**. | The field serves a deployment modality or threat scenario that is emerging rather than typical; **delegation chains and cascaded authority**, cryptographic identity and attestation, agent-to-agent protocol surfaces, inline enforcement that mutates payloads, dynamic third-party capability composition, or self-attesting instrumentation. Attack grounding may be **analogical**: the corpus motivates the scenario without yet containing a documented instance. |
| **MAY** | Valuable, but not required to catch the core attack classes. | The field's dominant value is **Q or A**; or its attack motivation is thin (single weak instance, or none); or it is a research-grade signal, a derived detector output, or redundant with a MUST field. |

- **Some fields are supplied by the agent, and the agent may be lying.** The threat model in [Appendix G.1](Telemetry-Cross-Mapping-Addendum.md#g1-the-threat-model-the-most-important-contribution) treats a compromised agent as a potential source of false statements, not only as a victim. These fields are **self-asserted** and carry no independent authority: **Autonomy Level** and **System Prompt / Instruction Config** (§5), **Observation / Thought** (§7), **Tool Selection Rationale** (§9), **Memory Write Rationale** (§10), and **Task / Intent Declaration** (§12). **Peer Agent Card / Descriptor** (§12) is the counterparty's assertion rather than the agent's own, and carries the same weakness. `AOC-01` is the corpus's demonstration that agents do misreport: it declared a secret destroyed while the data remained recoverable. A detection resting on any of these inherits whatever the agent chose to say, which is why **Attribute Source / Trusted-Provenance Marking** (§16) is a cross-cutting MUST. Corroboration is a decidable property, not a judgement: a claim about an outcome is **verified** when it resolves, by an identifier carried in the record, to the result it rests on, as **Execution Status** (§5) resolves to the **Tool Call I/O** outcome sharing its **Tool Execution ID** (§9). Where no identifier resolves, the claim is **attested**: the record says so and no reader can settle it. Attested claims should be recorded as attested rather than counted as outcomes, which lets a checker decide the question instead of leaving it to an adjective.
- **Taxonomies establish recognition, not occurrence.** Evidence means a **documented instance traceable to a primary source**. A MITRE ATLAS *technique*, a CoSAI Risk Map entry, an OWASP threat class, and the threat taxonomy of CoSAI's MCP Security paper are classifications: each records that a scenario is credible, none records that it happened. Where such a document cites a specific incident, that incident may enter the corpus **cited to its own primary source**, which is how `TA-11` to `TA-13` and four of `TA-14` to `TA-19` arrived. ATLAS **case studies** (`AML.CS####`) are instances and qualify; ATLAS **techniques** (`AML.Txxxx`) are classes and do not, which is why they are used to tag an attack and never to ground a field.
- **An instance need not be an executed attack.** The corpus holds three kinds of entry, and all three are admissible. Most are **executed attacks**. Four are **resisted attempts** (`AOC-12` to `AOC-15`, cited across 25 field slots): an attempt that was refused still evidences the field that recorded the refusal, and in those entries the refusal *is* the detection. Three are **non-adversarial failures of the same mechanism** (`TA-11`, a tenant boundary that failed unaided; `AOC-06`, provider-side silent truncation; `AOC-16`, an emergent cross-agent defence; 10 field slots between them): a field that makes a failure mode visible does so whatever caused it, and requiring an adversary would exclude the clearest instances of several failure modes for reasons of attribution rather than of detection. The document is nonetheless **attack-grounded** as described, because the large majority of the corpus is executed attacks; the rule describes the corpus as it stands.
- **The evidence gate admits those instances; the [priority gate](#41-use-case-priorities) is what keeps reliability-only signals out of MUST.** The two are independent, and it has always been the second one doing that work. `AOC-06` is the proof: non-adversarial, grounding six fields of which four are MUST, and yet **Provider / Endpoint Identity** (§8) still sits at MAY, because its dominant value is Q and A and the D > R > Q > A order governs. A reliability incident can therefore ground a field without lifting a reliability-dominant field to MUST.
- **Closing an evidence gap does not promote a modality-gated field.** The two gates are sequential and independent, so supplying a documented instance retires the evidence argument without moving the tier. That is still worth doing, because it removes the weaker of the two reasons a field sits below MUST, but a field held by its modality stays SHOULD however much evidence accumulates. Only a judgement that the modality has become typical moves it.
- **Attack count alone does not set the tier.** A field cited by five attacks is still SHOULD if every one of those attacks presupposes a delegation chain, and still MAY if its real job is compliance reporting. The modality gate applies after the evidence gate.
- **SHOULD is not "MUST later."** It is "MUST *if you run this modality*." This is the RFC 2119 reading applied narrowly: the "valid reasons in particular circumstances" for omitting a SHOULD field are **not running the modality it describes**, and nothing else. Cost, effort, and inconvenience are not among them. A deployment with cascaded delegation should treat §13 as mandatory on day one; a single-agent deployment may never need it.
- **Applicability precedes obligation.** A tier does not require a deployment to add a component or manufacture an event solely to emit its telemetry. A MUST field applies when its defining component, operation, or event exists: for example, §10 applies when the deployment uses persistent memory, and **Inter-Agent Message** applies when an agent-to-agent message is sent. A deployment that lacks the relevant capability marks the field **not applicable** in its conformance statement; it does not emit a synthetic value.
- **Schema support and event emission are distinct.** A conformant implementation supports every applicable MUST field and emits it whenever the corresponding event occurs. An individual event carries only the fields applicable to that event class and activity. Absence because the event did not occur is not a defect; omission from an event to which the field applies is.

> Tags are **deployment-agnostic**: a tag reflects *what evidence requires the field* and *how common the modality is*, not any one vendor's maturity. See the maturity model in [Implementation Guidance](#18-implementation-guidance).

### 4.3 Component taxonomy

Fields are organized under the CoSAI Risk Map fine-grained components. The table lists all 42 by risk-map category and subcategory, using the canonical IDs from [`risk-map/yaml/components.yaml`](https://github.com/cosai-oasis/secure-ai-tooling/blob/main/risk-map/yaml/components.yaml), with the sections whose fields each component emits:

| Category / subcategory | Components and sections |
| :-------------------- | :-------------------------------------------------------------------------------- |
| **Application / Core** | `componentApplication` §5, §14; `componentApplicationInputHandling` §6; `componentApplicationOutputHandling` §7; `componentApplicationConsentSurface` §16; `componentApplicationNetworkPolicyEnforcementPoint` §16 |
| **Application / Agent** | `componentReasoningCore` §5, §12, §13; `componentAgentUserQuery` §5; `componentAgentSystemInstruction` §5; `componentAgentInputHandling` §6; `componentAgentOutputHandling` §7; `componentAgentToolTransport` §9; `componentAgentConsentSurface` §16; `componentAgentNetworkPolicyEnforcementPoint` §16 |
| **Model / Orchestration** | `componentOrchestrationInputHandling` §6, §12; `componentOrchestrationOutputHandling` §7, §12; `componentMemory` §10; `componentRAGContent` §11 |
| **Model / Core** | `componentTheModel` §8; `componentModelServing` §8, §13 |
| **Model / Training** | `componentModelFrameworksAndCode` §14; `componentModelTrainingTuning`, `componentModelEvaluation`: none |
| **External Tools / Tool Invocation Path** | `componentTools` §9, §13, §14; `componentToolServer` §9; `componentToolInputHandling` §9; `componentToolOutputHandling` §9; `componentAuthorizationPolicyEnforcementPoint` §16 |
| **External Tools / Tool Network Controls** | `componentToolNetworkPolicyEnforcementPoint` §16 |
| **Infrastructure / Identity** | `componentIdentityProvider` §13; `componentFederationProxy` §13; `componentAuthorizationPolicyDecisionPoint` §16 |
| **Infrastructure / Registries** | `componentModelRegistry` §8, §14; `componentToolRegistry` §9, §14 |
| **Infrastructure / Deployment** | `componentModelStorage` §8; `componentIsolationRuntime` §9; `componentToolHosting` §9; `componentAuditRecordRepository` §15; `componentRuntimeHosting`: none |
| **Infrastructure / Data** | `componentDataSources`, `componentDataFilteringAndProcessing`, `componentTrainingData`, `componentDataStorage`: none |

**The field set covers the runtime path.** No corpus entry attacks the training pipeline (`IR-05` and `AOC-10` carry `AML.T0020` but poison memory and retrieval at runtime), so the evidence gate admits no field for the data and training components. `componentRuntimeHosting` has none: no field records the substrate that first-party workloads run on.

> **Component attribution is a mapping, not an emitted attribute.** Events do not carry a risk-map `component_id`. Attribution is established by this section, [Appendix B](Telemetry-Cross-Mapping-Addendum.md#appendix-b-mapping-to-the-cosai-risk-map-risks--controls) and [Appendix C](Telemetry-Cross-Mapping-Addendum.md#appendix-c-aitf--odis-cross-reference), which is sufficient for a static cross reference and costs nothing at runtime. A runtime identifier would need a resolvable namespace and a deprecation policy before it could be emitted safely, since events are immutable records and a component renamed upstream would invalidate every event already carrying it. That is tracked as part of the CoSAI Risk Map ontology work ([secure-ai-tooling#388](https://github.com/cosai-oasis/secure-ai-tooling/issues/388)); if that effort settles a stable namespace, the field belongs in [§14](#14-asset-inventory--fleet-aggregates-mostly-may) at MAY.

### 4.5 Classification summary

The complete field-by-component classification, before the detailed tables that follow: **98 fields, of which 50 are MUST, 33 SHOULD and 15 MAY.** It is an index rather than a definition: each field name is defined, with what to capture, when it applies, and the attacks that motivate it, in the section shown against it. The table is a catalogue, not a claim that every deployment or every event emits every field; the [applicability rules](#42-classification-legend) determine each deployment's required subset. The reasoning behind each tier (why the MUSTs are MUST, and where the boundaries are closest) is in **[Appendix J](Telemetry-Attack-Detection-Addendum.md#appendix-j-tiering-rationale)**, ordered to match this table.

| Component (risk-map) | MUST fields | SHOULD fields | MAY fields |
| :-------- | :---------------------------------- | :------------------------------------------ | :---------------- |
| Application / Reasoning Core (§5) | Agent Name, Instance ID, Workflow ID, Session/Turn/Step IDs, Trace Context, Trigger Type & Source Event, Action Type, Exec Status, Surface, System Prompt | Autonomy Level, Organization/Tenant ID, Stop Reason | n/a |
| Input Handling (§6) | Model Input, Input Source, Input Trust Class, Source IP, Guardrail(In), Content Modality & Attachment Identity ‡, ATLAS Technique Tag † | Guardrail Modification Record ‡ | Encoded-Payload Indicator |
| Output Handling (§7) | Response, Output Egress, Citations / Source Attribution, Guardrail(Out), LLM Refusal | Observation/Thought | n/a |
| Model & Serving (§8) | Model Name/Version, Inference Parameters, Token Counts, LLM Error | Model Provenance/Signing | Pre-Forward State, Token Malformation, Provider/Endpoint Identity |
| Tools (§9) | Tool Call I/O, Tool Name, Tool Type, Tool Execution ID, Execution Environment / Sandbox, Tool Error, Tool Definition Digest, MCP Server Identity & Primitive | Tool ACL/Scope, Tool Selection Rationale | Tool ID, Tool Privacy Class |
| Memory (§10) | Memory Write, Memory Read, Memory Provenance, Memory Footprint | Memory Integrity/Poisoning, Memory Write Rationale | Declared Memory Configuration |
| RAG (§11) | Retrieval Event, Retrieved-Content Source | Content/Metadata Integrity | Declared Knowledge-Source Configuration |
| Orchestration / Multi-Agent (§12) | Inter-Agent Message, Background Task, Loop Signal, Resource Aggregate | Task/Intent Declaration, *A2A Task Lifecycle Event*, Peer Agent Card / Descriptor | Protocol Envelope Capture |
| Identity & Delegation (§13) | Identities Used, Verified-vs-Displayed Identity | Originating Principal, Delegation Chain, Granted Authorizations, Resource Indicators+Constraints, **Credential Minting & Scope-Narrowing**, **Trust-Domain Crossing & Delegation Depth**, Runtime Credential/Attestation, Lifecycle State | n/a |
| Asset & Fleet (§14) | Capability-Set Change Event | Version, Repository/Software Ref, AgBOM / Inventory Snapshot, Component Dependency Graph, Inventory Attestation Signature | Description, Status, Creator/Oncall/dates, Surfaces, Fleet counts |
| Observability-Plane Integrity (§15) | Instrumentation Coverage / Hook Attestation | Event Sequence Continuity, Enforcement-Point Availability & Failure Mode | Policy Reason Code |
| Policy Enforcement & Mediation (§16) | **Authorization Decision Record**, **Attribute Source / Trusted-Provenance Marking** ‡ | **Session Taint Labels & Information-Flow Decisions**, **Human Approval / Elicitation Event**, **Backend / Route Restriction Decision**, **Mediation Coverage & Bypass Path** | n/a |

† **Threat Classification / ATLAS Technique Tag** is a cross-cutting enrichment listed under §6 for convenience; it applies to any flagged event across all components and is **MUST when a detection fires**. Value = one or more MITRE ATLAS `AML.Txxxx` IDs from [Appendix A.5](Telemetry-Attack-Detection-Addendum.md#a5-attack-inventory--mitre-atlas-technique-mapping).

‡ Also cross-cutting, also listed under §6 for convenience. **Content Modality & Attachment Identity** applies to every content-bearing field (model input, response, memory item, retrieved item, tool argument). **Guardrail Modification Record** is SHOULD in the catalogue; it is **MUST whenever an enforcement point rewrites rather than blocks**, on either the input or the output side. **Attribute Source / Trusted-Provenance Marking** (§16) applies to every security-relevant attribute a hostile agent could fabricate.

---

### 4.6 Where to start

The full MUST catalogue contains 50 fields, which is more than most full-stack deployments can instrument at once. Within a deployment's applicable subset, adoption has an order.

**Adoption order for a deployment starting from zero.** (1) the identifier hierarchy and trace context (§5), because everything else correlates through them and nothing else is interpretable without them; (2) content, trust classification, and guardrail verdicts (§§6 to 7), the highest D-density cluster in the document; (3) tool call I/O with execution IDs and sandbox posture (§9), the highest R value; (4) memory and retrieval (§§10 to 11); (5) orchestration (§12); (6) identity (§13) and capability-set change (§14).

**Early SHOULD fields that protect Tier 1 value**, even before the matching modality is fully adopted: **Enforcement-Point Availability** (§15), without which a starved guardrail is indistinguishable from a clean pass, and **Guardrail Modification Record** (§6), without which a redaction pipeline silently falsifies the log it feeds.

The order is driven by dependency: identifiers come first because later detections resolve through them. Each step is also useful on its own; stopping after step (2) still leaves a working injection-detection capability. See [§18](#18-implementation-guidance) for additional detail: the full maturity model across all three tiers, how to operationalize these fields for detection, and the privacy constraints on logging the content-bearing ones.

### 4.7 Agents you do not operate

Much of the corpus involves a counterparty someone else runs: another owner's agent (`AOC-04`, `AOC-09`, `AOC-11`, `AOC-16`), an MCP server you did not deploy (`TA-12`, `TA-13`), or a shared multi-tenant service (`TA-11`). You cannot instrument what you do not operate, so the field set applies differently. The adjacent standards each supply a useful rule:

**From CPEX: the counterparty is on the hostile side of the monitor, by definition.** CPEX's boundary places the agent, the caller, and everything beyond it in the untrusted region, and admits nothing from there into policy. An external agent is simply the clearest case. The consequence for telemetry is that you instrument **your own boundary**, not their internals, and CPEX's inbound-gateway placement is the one that sees every caller. What you record is a mediated interaction, not an observed agent.

**From ODIS: authority becomes legible through presented claims, not through inspection.** You cannot audit an external agent's reasoning, but you can require it to present a verifiable delegation record: originating principal, chain, granted authorizations, constraints. This is why `trust_domain` and delegation depth are detection-grade rather than mere policy-engine inputs the moment a chain leaves your domain (see §13).

**From OWASP AOS: ask the counterparty to be inspectable, and record the answer.** AOS's *Observed Agent* is one that exposes hooks, events, and an AgBOM on request; an external agent is an **unobserved** agent until it agrees otherwise. AOS's A2A extension already distinguishes full from partial counterparty context, which is the same distinction as knowing versus not knowing who you are talking to. Whether an inspection request was answered is itself a signal.

Read every field in §§5 to 16 against one of these **knowability** tiers:

| Tier | What you have | How the field set applies |
| :------- | :------------------------- | :------------------------------------------------ |
| **Mediated** | You own the boundary the interaction crosses | Full boundary telemetry: §§6, 7, 9, 16 apply as written. The counterparty's internals are absent, and their absence is expected rather than a gap |
| **Attested** | The counterparty presents verifiable claims (ODIS credential, signed AgBOM, agent card) | Record the claim **and its verification outcome**. **Attribute Source / Trusted-Provenance Marking** (§16) is the mechanism: an unverified claim is `self-asserted`, whatever it asserts |
| **Opaque** | Only the wire interaction | §§6, 7, 12 at the protocol surface, and nothing more. **Do not synthesize** fields you cannot observe. An opaque counterparty should be visibly opaque in the telemetry, not silently defaulted |

The third row collapsing into the second is the failure to avoid: recording an external agent's self-description as though it were established fact. `AOC-08` is that failure in miniature, and `AOC-11` is its consequence at scale.

---

## 5. Application & Agent Reasoning Core
**Components:** `componentApplication`, `componentReasoningCore`, `componentAgentUserQuery`, `componentAgentSystemInstruction`

*Establishes **what** is running and **where**: the asset inventory of the AI attack surface and the trace anchor for every incident.*

---

## 6. Input Handling & Trust Provenance
**Components:** `componentApplicationInputHandling`, `componentAgentInputHandling`, `componentOrchestrationInputHandling`

*The `componentAgentInputHandling` risk-map definition is literally "processing distinguishing trusted user commands from untrusted environmental data." That distinction is the single most important agentic-security signal.*

---

## 7. Output Handling, Egress & Refusals
**Components:** `componentApplicationOutputHandling`, `componentAgentOutputHandling`, `componentOrchestrationOutputHandling`

*Where damage materializes: PII leakage, exfiltration channels, harmful content, mass broadcast.*

---

## 8. The Model & Model Serving
**Components:** `componentTheModel`, `componentModelServing`, `componentModelStorage`, `componentModelRegistry` (provenance)

*Supply-chain integrity, resource/DoS signals, and pre-inference integrity.*

---

## 9. Tools & External Services
**Components:** `componentTools`, `componentToolServer`, `componentToolInputHandling`, `componentToolOutputHandling`, `componentAgentToolTransport`, `componentToolRegistry` (approved baseline), `componentIsolationRuntime` and `componentToolHosting` (execution environment)

*The security perimeter between AI reasoning and real-world consequences. When an agent calls a tool it crosses from "thinking" to "acting."*

> **Gateways, namespaces, and multiple hops.** A tool call is frequently not a single hop. Tools and prompts commonly sit behind a **gateway or broker** that re-namespaces them, and the call may traverse several intermediaries before reaching the system that acts. Three fields carry this, and they should be read together: **Tool Name** records the name *as the agent saw it*, which is the namespaced or gateway-local name and not necessarily the name at the far end; **MCP Server Identity & Primitive** records the immediate counterparty; and **Trace Context** (§5) is what stitches the hops into one trace, propagated over MCP via `params._meta`, per [Appendix D.5](Telemetry-Cross-Mapping-Addendum.md#d5-context-propagation-sampling--privacy-three-operational-traps).
>
> Two consequences. First, **the same underlying capability may appear under different names** depending on the path taken to it, so detections keyed on tool name alone will miss re-namespaced invocations; keying on the server identity and primitive as well is what makes them robust. Second, an intermediary is a **mediation boundary**, and whether it was traversed at all is the subject of **Mediation Coverage & Bypass Path** (§16); `AOC-14` is precisely an attempt to reach a capability by a path that bypasses the mediated one.

---

## 10. Memory
**Component:** `componentMemory`

*Persistent memory is a first-class attack surface. Multiple corpus attacks target it directly.*

> **What counts as memory, and at what granularity.** *Memory* here means **any store the agent writes to in one turn and reads back in a later one**, whatever its substrate: a vector store, a scratchpad file, a database row, a project instruction file, or a file the agent edits in a repository it also reads from. The substrate is irrelevant; the read-after-write-across-turns property is what creates the attack surface, because it is what lets `IR-02` and `AOC-10` outlive the session that planted them.
>
> The fields below are specified at **item granularity, not store granularity**: a Memory Write Event describes one item, and **Memory Provenance** attaches to that item. This requires a stable item identifier, and deployments whose memory is an opaque blob (a single file rewritten wholesale) cannot supply one. Such deployments should emit the write event with a **content digest** in place of an item ID, which preserves change detection and correlation while losing per-item provenance. That is a real reduction in detection capability and the reason item-level identity is worth engineering for.
>
> **Out of scope:** the durability, consistency, and retention semantics of the store itself, and any judgement about whether a given design *should* persist state. This section records what was written, read, and by what authority, not whether the memory architecture is sound.

---

## 11. Retrieval & Content (RAG)
**Component:** `componentRAGContent`

*RAG is a primary injection and manipulation channel.*

---

## 12. Orchestration, Multi-Agent & Background Execution
**Components:** `componentReasoningCore`, `componentOrchestrationInputHandling`, `componentOrchestrationOutputHandling`

*Multi-agent and autonomous-execution telemetry: the corpus shows these are where agentic risk compounds.*

---

## 13. Identity, Delegation & Attribution *(ODIS-aligned; mostly SHOULD)*
**Components:** `componentIdentityProvider`, `componentFederationProxy`; cross-cutting across `componentReasoningCore`, `componentTools` and `componentModelServing`, which it binds into an accountable chain.

*The "Quadruple Identity" problem: a **principal** authorizes an **agent** which (possibly via **other agents**) calls a **tool** that acts on **infrastructure**. Without identity at each hop, accountability collapses and confused-deputy attacks succeed. This is the ODIS problem space; delegation fields are **SHOULD** by the classification rule. Two of these identities already have homes in the adjacent standards and should be emitted there rather than in a private namespace: the originating principal as OpenTelemetry `audit.actor.*` (OCSF `actor.user.uid`) and the acting agent as `gen_ai.agent.*` (OCSF `ai_agent.uid`). The OTel audit model has a single actor slot that its guidance fills with the human, so the acting agent must travel in `gen_ai.agent.*` to keep "who authorized" and "which agent acted" separable.*

---

## 14. Asset Inventory & Fleet Aggregates *(mostly MAY)*
**Components:** `componentTools`, `componentApplication`, `componentModelFrameworksAndCode` (inventory), `componentModelRegistry` and `componentToolRegistry` (admission); fleet-level metrics are cross-component.

*These define the inventory and posture rather than per-request activity. Most are governance and CVE-response signals rather than detection signals, hence mostly MAY. The exceptions are the **change** signal, which is detection-grade and MUST, and the AgBOM cluster, which is the structural counterpart to OWASP AOS's **Inspect** pillar.*

---

## 15. Observability-Plane Integrity
**Cross-cutting:** applies to the instrumentation and enforcement layer itself, not to any one pipeline component; its records land in `componentAuditRecordRepository`.

> **Scope.** This section records **when the observability plane fails**; it does not defend it. Authenticating emitters, securing transport and storage, and establishing chain of custody are excluded by [§3.2](#32-not-in-scope) and left to subsequent work. The line is the one drawn in [§4.1](#41-use-case-priorities): a signal that makes a silent failure distinguishable from a clean result is detection material, and every field below is that. The CoSAI Risk Map reaches the same conclusion from the control side, carrying `controlAuditTrailCompleteness`, `controlAuditTrailIntegrityVerification` and `controlAuditRecordRepositoryIndependence`; this section is the telemetry those controls presuppose. The realization those controls describe is a signed head or checkpoint published to a witness outside the emitter's trust domain; **RFC 9943** [[53]](#standards--frameworks) and **RFC 9942** [[54]](#standards--frameworks) are the standards form of it. Naming the exit keeps this section a hand-off rather than a gap, without committing the field set to a format.

*Every field in §§5 to 14 and §16 assumes the telemetry and enforcement path is functioning and uncompromised. Nothing elsewhere in the field set tests that assumption. This section closes the loop: it is telemetry **about the observability plane**, motivated by the OWASP AOS **Instrument** pillar, where enforcement is a synchronous callout that can fail, be bypassed, or be starved.*

> **Scope note for the working group.** §15 sits on the boundary between telemetry and control-plane design, and the WG should confirm the line drawn here. The position taken is that the **outcomes** of enforcement (availability, failure mode, coverage, decision rationale) are security telemetry and belong in this document, while the **protocol** for performing enforcement (AOS's JSON-RPC hook transport, guardian-agent architecture, authentication between agent and guardian) does not.

---

## 16. Policy Enforcement & Mediation
**Components:** `componentAuthorizationPolicyDecisionPoint`, `componentAuthorizationPolicyEnforcementPoint`, the network enforcement points (`componentAgentNetworkPolicyEnforcementPoint`, `componentApplicationNetworkPolicyEnforcementPoint`, `componentToolNetworkPolicyEnforcementPoint`), and for approvals `componentAgentConsentSurface` and `componentApplicationConsentSurface`. **Cross-cutting:** the reference-monitor layer between the agent and every capability it invokes, tools, prompts, resources, inference providers, and inter-agent methods.

*§§5 to 14 record what the agent **did**; §15 records whether the observability plane **worked**. Neither records what policy **decided**, or on what basis. This section closes that gap, and it is grounded in the [CPEX](https://contextforge-org.github.io/cpex/) threat model, whose starting assumption is stronger than this document's has been: **the LLM is the adversary**. Prompt injection can arrive through any content the model reads; an injected instruction becomes a tool call; the model has no security properties and cannot be relied on to enforce anything. Everything on the agent side of the monitor is hostile, so nothing a policy reads (and, this section argues, nothing security telemetry treats as authoritative) may originate there.*

> **Scope note.** CPEX is a *runtime*; this section takes only the **decision records it produces**, not its policy language, plugin model, or deployment architecture. The boundary matches the one drawn for AOS in [§15](#15-observability-plane-integrity): enforcement outcomes are telemetry, enforcement mechanisms are not. See [Appendix G](Telemetry-Cross-Mapping-Addendum.md#appendix-g-cpex-cross-reference).

---

## 18. Implementation Guidance

### Maturity model (how the three tiers phase in)

Adoption sequencing within the MUST tier is in [§4.6](#46-where-to-start).

- **Tier 1, MUST (baseline detection and response): a catalogue of 50 fields across §§5 to 16.** For each deployment, the baseline is the subset applicable to the components and operations it actually implements, as defined in [§4.2](#42-classification-legend). Together the catalogue covers prompt injection, data disclosure, memory/RAG poisoning, exfiltration, resource/DoS abuse, identity spoofing, runaway multi-agent loops, and unauthorized action. Every MUST field is grounded in ≥2 corpus attacks (or in one attack where it is especially useful for **D** or **R**) and is **D- or R-dominant**.
- **Tier 2, SHOULD (edge-modality hardening).** Adopt the relevant cluster **as soon as you run the modality**, not on a maturity schedule. Delegated authority → all of §13 plus Tool ACL/Scope (§9). Multi-tenancy → Organization/Tenant ID (§5). A2A → task lifecycle and peer agent cards (§12). Inline enforcement that mutates payloads → Guardrail Modification Record (§6). Autonomous action → autonomy level (§5) and task/intent declaration (§12). Supply-chain attestation → model signing (§8), the AgBOM cluster (§14). Self-attesting instrumentation → §15. Information-flow control → session taint (§16). Out-of-band human approval → elicitation events (§16). Policy-driven backend selection → route restriction (§16). Token exchange → credential minting (§13). Plus the reasoning-trace and integrity-scoring fields (§§7, 9, 10, 11), which are gated by provider availability and privacy policy rather than by modality.
- **Tier 3, MAY (Q, A, and thin-evidence signals).** Fleet aggregates and static asset metadata; declared memory and knowledge configuration (§§10 to 11); provider/endpoint identity (§8); tool privacy classification (§9); protocol envelopes (§12); policy reason codes (§15); derived detector outputs already covered by a MUST (encoded-payload indicator, §6); and research-grade signals (pre-forward-pass state, token malformation, §8).

### Operationalizing telemetry for detection
Logged fields are a necessary evidentiary foundation, not detection by themselves. A four-year measurement study of a production security operations centre; 115 million alerts, 2018 to 2022; found volumes of **24 K to 134 K alerts per day of which 0.01% corresponded to true attacks or compromises**, with 27% attack attempts and 49% benign triggers [[50]](#standards--frameworks). Treat logged values as inputs to layered analytics: signature rules, self-learning anomaly detection, cross-layer correlation (the patterns above), and ML scoring of prompts/outputs/action-sequences. The corollary is a staffing one, and it is the reason this document orders fields by detection value rather than completeness: a trail no analyst can read is not an asset. Field names, tier, and the [correlation patterns](Telemetry-Attack-Detection-Addendum.md#17-correlation-patterns) are meant to be usable directly as detection-engineering and triage input, and the attack IDs on every field are there so an analyst can see what a field was collected *for*. Continuously re-evaluate detectors; benchmarks show injection detectors effective on explicit attacks often fail on subtler variants. **When a detector fires, stamp the event with its MITRE ATLAS `AML.Txxxx` technique** (the *Threat Classification / ATLAS Technique Tag* field) using the [Appendix A.5](Telemetry-Attack-Detection-Addendum.md#a5-attack-inventory--mitre-atlas-technique-mapping) mapping; this makes AI-specific alerts correlate with the ATT&CK-aligned rest of the SOC and roll up cleanly into ATLAS-based compliance reporting.

### Sampling when OpenTelemetry is the carrier

Default OpenTelemetry head-based sampling discards traces without regard to security relevance. For any deployment that relies on OTel as its security-telemetry carrier, the following are **normative** (rationale in [Appendix D.5](Telemetry-Cross-Mapping-Addendum.md#d5-context-propagation-sampling--privacy-three-operational-traps)):

1. **Security-relevant events MUST NOT be head-sampled.** Guardrail verdicts, refusals, tool errors, authorization denials, capability changes, session and turn stop events carrying a **Stop Reason** (§5), per-invocation tool activity events, and any event carrying a fired detection are recorded at **100%**. A sampled-away `content_filter` stop is a missed guardrail bypass.
2. **Where tail sampling is used, security relevance MUST be a retention predicate**: a trace containing a block, a denial, an error, or a flagged classification is always kept.
3. **The sampling configuration in force MUST itself be recorded as telemetry.** A detection that never fires because its input was sampled away is indistinguishable from a clean environment.

### Privacy-preserving logging
**Model Input, Response, System Prompt, Observation/Thought, Memory, and Retrieved Content** carry significant privacy weight (they can contain PII/secrets, see `AOC-03`). Apply: access controls restricting content-log access to IR with justification; short retention for full content (7 to 30 days) and longer retention for hashed/classified signals; redaction pipelines that strip PII while keeping content hashes for correlation; encryption at rest with audited key access. **Every content-bearing field MUST carry a content hash; whether the raw content accompanies it is a deployment policy decision.** The hash is the correlation primitive the corpus turns on: `TA-04` is verbatim reproduction, `AOC-03` is escalating extraction across turns, and `IR-02` is an implant that persists into later sessions. None of those is detectable without the ability to match one content item against another, and none of them requires the raw text to be retained. Mandating the hash and leaving the raw content to policy keeps a MUST field comparable between two deployments with different privacy postures, which a free choice between raw and hash does not. This is why several high-value fields (Observation/Thought, memory and RAG content) are specified *conceptually* here: the obligation is the hash, not the payload.

**Three fields carry identifiers rather than payloads, and resolve as follows.** **Content Modality & Attachment Identity** (§6) already requires a content hash; the **filename** is the sensitive part and is deployment policy. **Citations / Source Attribution** (§7) names its own signal as *whether each citation resolves to an item actually returned by a logged Retrieval Event*, so the **resolution outcome is the obligation** and the clear-text URL is policy; a deployment that withholds URLs keeps the detection intact. **Protocol Envelope Capture** (§12) is MAY because raw payload capture is the field, and its tier already carries that judgement.

One limit worth stating: hashing a **filename or a URL** is a correlation primitive, not a confidentiality control. Those input spaces are small enough to enumerate, so a hash makes two records joinable without making either private. Where the identifier itself is sensitive, omit it rather than hash it.

**A hash is evidence only if a second party can recompute it.** The canonicalization the digest is taken over MUST be declared, either by the deployment or by the carrier ([D.5](Telemetry-Cross-Mapping-Addendum.md#d5-context-propagation-sampling--privacy-three-operational-traps)). Two emitters that hash the same tool call under different serializations produce different digests, and the field degrades silently from evidence to a correlation key that only works within one producer.

---

## 19. References

### Primary sources (attack corpus & taxonomy)

1. **MITRE ATLAS**: Adversarial Threat Landscape for Artificial-Intelligence Systems (technique matrix; `AML.Txxxx` taxonomy). MITRE. <https://atlas.mitre.org/>. Citations verified against release **`v2026.08`** (1 September 2026), 197 techniques and 72 case studies; machine-readable at <https://github.com/mitre-atlas/atlas-data>.
2. **Agents of Chaos**: Shapira, N., Wendler, C., Yen, A., et al. *Agents of Chaos.* arXiv:2602.20021 (2026). <https://arxiv.org/abs/2602.20021> · interactive log: <https://agentsofchaos.baulab.info/>
3. **CoSAI AI Incident Response**: Coalition for Secure AI, Workstream 2 (Defenders): *AI Incident Response Framework* (case studies). <https://github.com/cosai-oasis/ws2-defenders/blob/main/incident-response/AI-Incident-Response.md>

### Real-world attack primary sources

One source per real-world attack vector, each mapping to a `TA-` ID in [Appendix A.1](Telemetry-Attack-Detection-Addendum.md#a1-real-world-attack-vectors). Ref 4 is the lead case study; refs 5 to 13 are the source citations for `TA-02…10`.

4. **[TA-01]** EchoLeak, zero-click data exfiltration from Microsoft 365 Copilot (CVE-2025-32711, CVSS 9.3). Discovered and disclosed by **Aim Labs (Aim Security)**; reported to MSRC Jan 2025, fixed server-side and publicly disclosed Jun 2025. Microsoft advisory: <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711> · CVE record: <https://nvd.nist.gov/vuln/detail/CVE-2025-32711> · **Technical analysis:** Reddy, P. & Gujral, A. *EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System.* arXiv:2509.10540 (2025). <https://arxiv.org/abs/2509.10540>
5. **[TA-02]** Slack AI private-channel data exfiltration. Dark Reading. <https://www.darkreading.com/cyberattacks-data-breaches/slack-ai-patches-bug-that-let-attackers-steal-data-from-private-channels>
6. **[TA-03]** Data exfiltration via markdown images. J. Rehberger, *Embrace The Red.* <https://embracethered.com/blog/posts/2023/google-bard-data-exfiltration/>
7. **[TA-04]** Scalable extraction of training data from (production) LLMs. Nasr et al., arXiv:2311.17035. <https://arxiv.org/abs/2311.17035>
8. **[TA-05]** Samsung proprietary-data leak via ChatGPT. AI Incident Database, cite 768. <https://incidentdatabase.ai/cite/768/>
9. **[TA-06]** LangChain prompt-injection → RCE (CVE-2023-36095, CVE-2023-29374, CVE-2023-34540). Liu et al., arXiv:2309.02926. <https://arxiv.org/abs/2309.02926>
10. **[TA-07]** System-prompt extraction / jailbreak via system prompts. Wu, Y., Li, X., Liu, Y., Zhou, P. & Sun, L. *Jailbreaking GPT-4V via Self-Adversarial Attacks with System Prompts.* arXiv:2311.09127 (2023). <https://arxiv.org/abs/2311.09127>
11. **[TA-08]** Agentic AI threats: tool-chaining privilege escalation. Lakera. <https://www.lakera.ai/blog/agentic-ai-threats-p2>
12. **[TA-09]** RAG knowledge-base poisoning, arXiv:2507.08862. <https://arxiv.org/abs/2507.08862>
13. **[TA-10]** LLM04: Model Denial of Service. OWASP Top 10 for LLM Applications. <https://genai.owasp.org/llmrisk2023-24/llm04-model-denial-of-service/>
14. **[TA-11]** Asana MCP server cross-tenant data exposure (Jun 2025); experimental MCP server launched 1 May 2025; tenant-isolation flaw found 4 Jun, exposure window 5 to 17 Jun, ~1,000 customers potentially affected; no evidence of exploitation. <https://www.theregister.com/2025/06/18/asana_mcp_server_bug/>
15. **[TA-12]** Supabase MCP private-table exposure via stored prompt injection. General Analysis. <https://generalanalysis.com/blog/supabase-mcp-blog> · analysis coining the **"lethal trifecta"** framing (private data + untrusted content + external communication): S. Willison, 6 Jul 2025, <https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/> · vendor response: <https://supabase.com/blog/defense-in-depth-mcp>
16. **[TA-13]** AI Engine (WordPress) MCP privilege escalation, **CVE-2025-5071** (CVSS 8.8, v2.8.0 to 2.8.3, patched 2.8.4 on 18 Jun 2025). <https://wpscan.com/vulnerability/b0d583a2-14e1-40bc-b875-3b48e992b803/> · a second, unauthenticated flaw on the same MCP surface followed: **CVE-2025-11749** (CVSS 9.8, patched 3.1.4 on 19 Oct 2025), <https://github.com/advisories/GHSA-q6x7-qqgq-h832>
17. **[TA-14]** MCPoison, Cursor MCP configuration trust bypass, **CVE-2025-54136** (CVSS 7.2; affects ≤ 1.2.4, fixed in 1.3 on 29 July 2025). Check Point Research; disclosed to the vendor 16 July 2025, published 5 August 2025. <https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/>
18. **[TA-15]** MCP tool poisoning via tool-description injection. Invariant Labs, April 2025. MITRE ATLAS case study **`AML.CS0054`**. <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>
19. **[TA-16]** `postmark-mcp` malicious npm package (first malicious MCP server found in the wild); malicious from v1.0.16, removed from npm 25 September 2025. Koi Security. MITRE ATLAS case study **`AML.CS0053`**. <https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft>
20. **[TA-17]** DifyTap, four vulnerabilities in Dify enabling cross-tenant data exposure; **CVE-2026-41947** (CVSS 9.1) trace-configuration authorization bypass, with CVE-2026-41948/-41949/-41950. Zafran Security (Ido Shani, Gal Zaban), 22 June 2026; fixed in 1.14.2. <https://thehackernews.com/2026/06/researchers-detail-difytap-flaws-in.html>
21. **[TA-18]** ChatGPT persistent memory poisoning via indirect prompt injection. J. Rehberger, *Embrace The Red*. MITRE ATLAS case study **`AML.CS0040`**. <https://embracethered.com/blog/posts/2024/chatgpt-hacking-memories/>
22. **[TA-19]** Google Gemini: planting instructions for delayed automatic tool invocation. J. Rehberger, *Embrace The Red*. MITRE ATLAS case study **`AML.CS0038`**. <https://embracethered.com/blog/posts/2024/llm-context-pollution-and-delayed-automated-tool-invocation/>

<!-- References 55 onward were appended after 54; this break keeps renderers from renumbering them. -->

55. **[TA-20]** LLMjacking: stolen cloud credentials used to access cloud-hosted models and resell that access via a reverse proxy. Sysdig Threat Research Team, 6 May 2024. MITRE ATLAS case study **`AML.CS0030`**. <https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/>
56. **[TA-21]** Rules File Backdoor: invisible-Unicode instructions in AI coding-assistant rules files, distributed through repositories. Pillar Security, 18 March 2025. MITRE ATLAS case study **`AML.CS0041`**. <https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents>
57. **[TA-22]** Storm-2139: credential scraping and custom tooling to bypass Azure OpenAI guardrails and modify service capabilities, resold as a service. Microsoft, January and February 2025. MITRE ATLAS case study **`AML.CS0057`**. <https://blogs.microsoft.com/on-the-issues/2025/02/27/disrupting-cybercrime-abusing-gen-ai/>
58. **[TA-23]** OpenClaw 1-click remote code execution, **CVE-2026-25253**: token theft, configuration change disabling user confirmation, container escape. DepthFirst, February 2026. MITRE ATLAS case study **`AML.CS0050`**. <https://nvd.nist.gov/vuln/detail/CVE-2026-25253>
59. **[TA-24]** GTG-1002: state-sponsored group configuring an agent as an autonomous attack framework against ~30 organizations. Anthropic, September 2025; MITRE ATT&CK campaign **C0062**. MITRE ATLAS case study **`AML.CS0069`**. <https://www.anthropic.com/news/disrupting-AI-espionage>
60. **[TA-25]** Multi-agent framework used against Taiwanese government systems: 12 attack waves, 1 to 4 July 2026, recovered 160 MB / 1,395-file operational workspace. Taiwan Ministry of Digital Affairs; Dream Research Labs; *Financial Times*. MITRE ATLAS case study **`AML.CS0071`**. <https://moda.gov.tw/ACS/press/news/press/20394>
61. **[TA-26]** Indirect prompt injection of Claude Computer Use: PDF-borne injection invoking the agent's shell tool to destroy user data. HiddenLayer, 24 October 2024. MITRE ATLAS case study **`AML.CS0046`**. <https://hiddenlayer.com/innovation-hub/indirect-prompt-injection-of-claude-computer-use/>
62. **[TA-27]** Morris II: zero-click adversarial self-replicating prompt propagating between GenAI systems via a RAG-based email assistant. S. Cohen, R. Bitton, B. Nassi, 5 March 2024. MITRE ATLAS case study **`AML.CS0024`**. <https://arxiv.org/abs/2403.02817>
63. **[TA-28]** SesameOp: backdoor abusing the OpenAI Assistants API as a covert command-and-control and exfiltration channel over several months. Microsoft Incident Response (DART), 3 November 2025. MITRE ATLAS case study **`AML.CS0042`**. <https://www.microsoft.com/en-us/security/blog/2025/11/03/sesameop-novel-backdoor-uses-openai-assistants-api-for-command-and-control/>

### Standards & frameworks

23. **CoSAI Risk Map**: Coalition for Secure AI, fine-grained AI system components taxonomy. <https://github.com/cosai-oasis/secure-ai-tooling/tree/main/risk-map>. 55 risks / 68 controls: PR [#507](https://github.com/cosai-oasis/secure-ai-tooling/pull/507) merged, plus `riskAgentMemoryPoisoning`, `riskDeceptiveAgentReporting`, `riskUnsafeInterAgentPropagation` and `controlAgentMemoryIntegrity`; risk IDs migrated to the `risk`+camelCase convention.
24. **CoSAI MCP Security**: Coalition for Secure AI, Workstream 4 (Secure Design Patterns for Agentic Systems): *Model Context Protocol (MCP) Security*, approved 8 January 2026. Twelve threat categories (MCP-T1…T12), ~40 threats. <https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf>
25. **AITF**: AI Telemetry Framework (OTel + OCSF binding), donated to CoSAI WS2. <https://github.com/cosai-oasis/ws2-defenders/tree/main/telemetry>
26. **ODIS**: Coalition for Secure AI, Workstream 4: *Open Delegation & Identity Standard*. Apache-2.0. Records defined in §6: Agent Registration Record (6.1), Agent Runtime Credential Descriptor (6.2), Delegation Record (6.3), Identity Context (Policy Engine Feed) (6.4). Cited at commit `148dc41` (8 September 2026); ODIS is a working draft, so this reference is pinned to a commit rather than to `main` to keep the section numbers and field names in [Appendix C](Telemetry-Cross-Mapping-Addendum.md#appendix-c-aitf--odis-cross-reference) checkable. <https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md>
27. **OWASP Top 10 for LLM Applications (2025)**: OWASP GenAI Security Project. <https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/>
28. **OWASP Top 10 for Agentic Applications (2026)**: OWASP GenAI Security Project. <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
29. **MITRE ATT&CK**: adversary tactics & techniques knowledge base (ATLAS-aligned). MITRE. <https://attack.mitre.org/>
30. **NIST AI Risk Management Framework (AI RMF 1.0)**: NIST, January 2023; **currently under revision**. GOVERN / MAP / MEASURE / MANAGE. <https://www.nist.gov/itl/ai-risk-management-framework> · companion **NIST AI 600-1, Generative AI Profile** (July 2024). Mapped in [Appendix H](Telemetry-Cross-Mapping-Addendum.md#appendix-h-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile).
31. **NIST Cybersecurity Framework (CSF) 2.0**: GV / ID / PR / DE / RS / RC; 6 functions, 22 categories, 106 subcategories. <https://www.nist.gov/cyberframework>
32. **NIST Cyber AI Profile**: *Cybersecurity Framework Profile for Artificial Intelligence: NIST Community Profile*, **NIST IR 8596**, *initial preliminary draft* published 16 December 2025; CSF 2.0 community profile overlaying the **Secure / Defend / Thwart** AI focus areas. Comment period closed 30 January 2026; working sessions held April and May 2026; **no Initial Public Draft as of 11 September 2026**. <https://csrc.nist.gov/pubs/ir/8596/iprd> · project: <https://www.nccoe.nist.gov/projects/cyber-ai-profile>
33. **ISO/IEC 42001:2023**: *Information technology — Artificial intelligence — Management system.* Clauses 4 to 10 plus **Annex A** (38 controls under 9 objectives, A.2 to A.10) selected via a Statement of Applicability. Paid standard. <https://www.iso.org/standard/42001>. Mapped in [Appendix I](Telemetry-Cross-Mapping-Addendum.md#appendix-i-implications-for-isoiec-42001).
34. **EU AI Act. Article 12 (Record-keeping / Logging).** <https://artificialintelligenceact.eu/article/12/>
35. **OpenTelemetry, GenAI semantic conventions.** Now maintained in a dedicated repository: <https://github.com/open-telemetry/semantic-conventions-genai>. Spans, metrics, events, MCP, and provider-specific conventions, **all at Development status**. Attribute registry: <https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/>. Entries marked *Deprecated* there mostly reflect the relocation rather than withdrawal, but not always: some were **renamed** in the move (`gen_ai.usage.cache_creation.input_tokens` → `gen_ai.usage.cache_write.input_tokens`) and some were **withdrawn outright** (`gen_ai.prompt` and `gen_ai.completion`, both `reason: obsoleted`, "Removed, no replacement at this time"). Names must therefore be read from the new repository, not the deprecated registry. **Names in Appendices C, D and E were verified against `semantic-conventions-genai` @ `0c87594` (10 September 2026) and `semantic-conventions` @ `22b6cbb` (9 September 2026); neither repository publishes release tags, so commit SHAs are the only stable anchor.** Cross referenced in [Appendix D](Telemetry-Cross-Mapping-Addendum.md#appendix-d-implications-for-opentelemetry-the-instrumentation-bridge).
36. **OpenTelemetry, core specification.** Signals, context propagation, sampling. <https://opentelemetry.io/docs/specs/otel/> · **W3C Trace Context**: <https://www.w3.org/TR/trace-context/> · MCP context propagation via `params._meta` (**SEP-414**): <https://modelcontextprotocol.io/community/seps/414-request-meta>
37. **OCSF. Open Cybersecurity Schema Framework.** <https://ocsf.io/> · schema browser: <https://schema.ocsf.io/>
38. **OWASP AOS, Agent Observability Standard.** OWASP. <https://aos.owasp.org/>. Three pillars (Instrument / Trace / Inspect); cross referenced in [Appendix F](Telemetry-Cross-Mapping-Addendum.md#appendix-f-owasp-aos-cross-reference). *Working draft.* Verified against the specification sources at commit `e4a50f6` (30 December 2025), schema version **0.1.0** (`specification/AOS/aos_schema.json` in [OWASP/www-project-agent-observability-standard](https://github.com/OWASP/www-project-agent-observability-standard)); the specification has not changed since that date.
39. **Model Context Protocol (MCP).** <https://modelcontextprotocol.io/>. Tools, resources, prompts, sampling, elicitation, roots (§9).
40. **A2A, Agent-to-Agent Protocol.** <https://a2a-protocol.org/>. Agent cards, task lifecycle, push-notification configuration (§12).
41. **CycloneDX**: OWASP BOM standard, incl. ML-BOM. <https://cyclonedx.org/>
42. **SPDX**: Linux Foundation software bill-of-materials standard. <https://spdx.dev/>
43. **SWID**: ISO/IEC 19770-2 software identification tags. <https://csrc.nist.gov/projects/Software-Identification-SWID>
44. **CPEX**: policy-enforcement runtime and reference monitor for AI agents. <https://contextforge-org.github.io/cpex/> · threat model: <https://contextforge-org.github.io/cpex/docs/threat-model/>, cross referenced in [Appendix G](Telemetry-Cross-Mapping-Addendum.md#appendix-g-cpex-cross-reference). Verified against [contextforge-org/cpex](https://github.com/contextforge-org/cpex) at commit `035012f` (18 August 2026). Pinned to a commit rather than to the current release (`v0.2.2`, 15 July 2026), which predates the threat-model document this appendix cites.
45. **RFC 8693**: OAuth 2.0 Token Exchange (on-behalf-of delegation). <https://www.rfc-editor.org/rfc/rfc8693>
46. **RFC 7523**: JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants. <https://www.rfc-editor.org/rfc/rfc7523>
47. **SPIFFE / SVID**: Secure Production Identity Framework for Everyone (workload identity). <https://spiffe.io/>
48. **NIST SP 800-207**: Zero Trust Architecture. <https://csrc.nist.gov/pubs/sp/800/207/final>
49. **Cedar**: authorization policy language. <https://www.cedarpolicy.com/> · **Open Policy Agent (Rego)**. <https://www.openpolicyagent.org/>

---

50. **SOC alert-volume measurement**: Yang, L., Chen, Z., Wang, C., Zhang, Z., Booma, S., Cao, P., Adam, C., Withers, A., Kalbarczyk, Z. T., Iyer, R. K. & Wang, G. *True Attacks, Attack Attempts, or Benign Triggers? An Empirical Measurement of Network Alerts in a Security Operations Center.* USENIX Security 2024. <https://www.usenix.org/conference/usenixsecurity24/presentation/yang-limin>

51. **RFC 2119**: Bradner, S. *Key words for use in RFCs to Indicate Requirement Levels.* BCP 14, RFC 2119 (1997). <https://www.rfc-editor.org/rfc/rfc2119>
52. **RFC 8174**: Leiba, B. *Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.* BCP 14, RFC 8174 (2017). <https://www.rfc-editor.org/rfc/rfc8174>
53. **RFC 9943**: *An Architecture for Trustworthy and Transparent Digital Supply Chains* (SCITT). Standards Track. <https://www.rfc-editor.org/rfc/rfc9943.html>
54. **RFC 9942**: *CBOR Object Signing and Encryption (COSE) Receipts.* Standards Track, June 2026. <https://www.rfc-editor.org/rfc/rfc9942.html>
