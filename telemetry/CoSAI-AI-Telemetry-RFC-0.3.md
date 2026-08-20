# Secure by Design: Telemetry Field Selection for AI Systems {**Working Draft**}

**Status:** Request for Comments, revision 0.3
**Origin:** Coalition for Secure AI (CoSAI), Workstream 2 (Defenders)
**Disclosure:** Prepared for open publication under CoSAI. No commercial sponsorship; the standards positions taken favour open specifications (OpenTelemetry, OCSF, OWASP AOS, CPEX) over any vendor implementation. Drafting, cross-referencing, and consistency checking were performed with AI assistance; every attack, field, mapping, and citation is subject to the [pre-publication verification](#pre-publication-verification-editorial-not-wg-decisions) checklist before release.

---

## 1. Introduction

AI systems now read untrusted content, decide what to do about it, and act: calling tools, writing memory, retrieving documents, sending mail, invoking other agents. Attacks against them succeed in the gap between reading and acting. Detection has to happen in that gap, as far left in the kill chain as possible.

Catching an injection attack in flight means knowing what the model was given, how far that input was trusted, what it decided to do, and where its output went. Most deployments record none of this. Traditional application logging captures HTTP requests, database queries, and authentication events. The decisive moments in an AI system (an instruction arriving inside a retrieved document, a guardrail verdict, a memory write that will shape every future session) leave no trace there. Without those records there is nothing to detect against, and afterwards nothing solid to investigate, debug, or audit.

### 1.1 One umbrella, many efforts

Several communities are converging on AI telemetry, and their work is complementary. **OpenTelemetry** [[29]](#standards--frameworks) defines how instrumentation emits GenAI and agent data. **OCSF**, the Open Cybersecurity Schema Framework [[31]](#standards--frameworks), defines how security events are normalized for a SOC. **OWASP AOS**, the Agent Observability Standard [[32]](#standards--frameworks), defines how an agent exposes itself for observation. **CPEX** [[38]](#standards--frameworks) defines how a policy runtime mediates agent actions. **ODIS**, the Open Delegation and Identity Standard [[20]](#standards--frameworks), defines delegated identity and authority. **MITRE ATLAS** [[1]](#primary-sources-attack-corpus--taxonomy) defines the adversary techniques to classify against. Regulation adds its own obligations, notably EU AI Act Article 12 [[28]](#standards--frameworks) and the NIST AI Risk Management Framework [[24]](#standards--frameworks).

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

Go to the **classification summary** ([§4.5](#45-classification-summary), the single table listing every field by component and tier) and treat the **MUST** column as the baseline your AI deployments should meet. The three tiers are **MUST**, **SHOULD**, and **MAY**, used in the RFC 2119 sense and defined in [§4.2](#42-classification-legend). That is 47 fields, each required to detect or scope a documented attack, and it is the artifact to take into an engineering plan or a budget discussion.

- **The justification is evidentiary.** Every MUST field cites named real-world attacks and incidents. The ask is "these fields catch these attacks," not "best practice suggests." [Appendix J](#appendix-j-tiering-rationale) sets out that reasoning per component if it is challenged.
- **There is a build order.** The MUST tier is sequenced, so a team starts with the identifiers and content that everything else correlates through rather than instrumenting alphabetically.
- **Compliance follows detection, not the reverse.** MUST coverage already evidences most of NIST CSF [[25]](#standards--frameworks) **DETECT** and **RESPOND**, AI RMF **MEASURE**, and ISO/IEC 42001 [[27]](#standards--frameworks) event-logging control; the mappings are in [Appendix H](#appendix-h-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile) and [Appendix I](#appendix-i-implications-for-isoiec-42001), which show coverage strongest exactly where this document concentrates and weakest where it places least weight. Build for detection and the audit evidence is a by-product; building for audit does not produce detection.

One decision cannot be delegated to engineering: how much prompt, response, and memory content is retained, for how long, and who may read it. The MUST tier can be met with hashes and classifications where raw content is too sensitive to keep, but that is a policy call, and it should be made deliberately rather than defaulted into.

### 2.2 For the open source security community

Every adjacent standard has its own appendix, stating what this field set already maps onto, what that standard cannot currently express, and the specific additions proposed. Start with yours.

| Community | Appendix | What is proposed |
| :------------- | :---- | :-------------------------------------------------------------------------------------- |
| **OpenTelemetry** [[29]](#standards--frameworks) | D | 9 attribute proposals: input trust classification, a security guardrail signal, a `gen_ai.memory.*` namespace, retrieval provenance, turn and step identifiers |
| **OCSF** [[31]](#standards--frameworks) | E | 6 asks: two AI event classes, an `ai_operation` profile, new objects and enums, ATLAS as a first-class technique reference |
| **CoSAI Risk Map (WS3)** [[17]](#standards--frameworks) | B | 3 proposed new risks and 1 proposed control, after the risk-map expansion superseded two earlier proposals |
| **OWASP AOS** [[32]](#standards--frameworks) | F | 9 contributions: trust classification, egress destination, ATLAS tagging, priority tiering, and migration of its OTel binding from `llm.*` to `gen_ai.*` |
| **CPEX** [[38]](#standards--frameworks) | G | 6 contributions: retention and priority guidance, and a SOC destination for enforcement decisions |

**AITF** [[19]](#standards--frameworks), the AI Telemetry Framework, donated to CoSAI Workstream 2, is the bridge between this document and both of those destinations, OpenTelemetry for emission, OCSF for consumption. It carries these fields as OpenTelemetry attributes today and emits them into OCSF ahead of formal ratification, so adopters are not blocked on either standards body. The field-level mapping is **Appendix C**; completing it is CoSAI's own work, in hand before final publication.

- **They are evidence-gated and therefore small.** A field becomes a standardization ask only once two or more independent documented attacks require it. Nothing is proposed speculatively.
- **Emission and consumption move together.** A field OpenTelemetry emits but OCSF cannot represent arrives at the SIEM as unstructured overflow; a field OCSF defines but no instrumentation produces stays theoretical. Paired asks are the intent.

CoSAI is engaging the **OpenTelemetry** and **OCSF** communities directly on this work, and welcomes input from the wider open source security community in turn. The timing favours it: every OpenTelemetry GenAI convention is at *Development* status and has just moved to a dedicated repository, so contributions land more cheaply now than after stabilization.

What is wanted in return: corrections to the mappings, and attacks the corpus is missing. Three known gaps are named in the open questions; no documented case yet exists for MCP tool poisoning, attacks on the observability plane, or cross-tenant agent leakage, and each currently holds a field below the tier its reasoning would otherwise justify.

### 2.3 For builders of AI solutions

One telemetry set covers **detection** while a run is in flight, **response** afterwards, **debugging** of behaviour, and **compliance audit**. Instrumenting once for all four is cheaper than retrofitting each purpose later.

Work from the **per-component breakdown**. The field set is organized by the components of an AI system (reasoning core, input handling, output handling, model and serving, tools, memory, retrieval, orchestration, identity and delegation, asset inventory, observability plane, and policy enforcement) so you can take the components you actually build and read off what each must emit. Every field states what to capture and the attacks that make it necessary. The correlation patterns that follow the field tables show how fields combine into detections, and are usually the fastest way to see why a given field earns its place.

Practical notes:

- **Do not invent a schema.** Appendices C to E give the OpenTelemetry attribute names and the OCSF mapping. Emit over OpenTelemetry today; the bindings are already specified.
- **Content in events, identifiers in span attributes, aggregates in metrics.** Prompts, tool results, and retrieved documents are unbounded and often sensitive; as span attributes they break cardinality limits and follow the span into every backend.
- **Do not head-sample security events.** Default OpenTelemetry sampling [[30]](#standards--frameworks) discards attack evidence blind to whether an event is security-relevant. Guardrail verdicts, refusals, tool errors, and authorization denials are recorded at 100%.
- **Propagate trace context across every hop**, including MCP [[33]](#standards--frameworks) and agent-to-agent [[34]](#standards--frameworks) calls. Without it, multi-agent activity cannot be reassembled into a single incident.

---

## 3. Scope

### 3.1 In scope

The security-relevant telemetry an AI system should produce: which fields, justified by which documented attacks, at which priority. Fields are organized by the component that emits them (reasoning core, input and output handling, model and serving, tools, memory, retrieval, orchestration, identity and delegation, asset inventory, observability plane, and policy enforcement) and each is tiered **MUST**, **SHOULD**, or **MAY** against a stated test. The document adds correlation patterns showing how fields combine into detections, and mappings onto OpenTelemetry, OCSF, AITF, ODIS, OWASP AOS, CPEX, the CoSAI Risk Map, NIST CSF and AI RMF, and ISO/IEC 42001.

Telemetry for **agents the deployment does not operate** is in scope, with the limits that implies: what is observable at your own boundary, plus whatever the counterparty presents and can be verified. [§4.7](#47-agents-you-do-not-operate) sets out how the field set applies in that case.

The framing implies three limits. This is **not a wire format**: the bindings are in the appendices. It does **not specify detection logic**, only the fields detections consume. And it covers the **security** slice of AI trustworthiness; fairness, bias, safety alignment, and environmental impact are outside its remit.

### 3.2 Not in scope

Two areas are excluded deliberately, and both are intended for subsequent work.

**Privacy compliance.** The implementation guidance recommends handling practices (access control, tiered retention, redaction, hash-first correlation) because content-bearing fields carry evident risk. Those are handling practices, not a compliance programme. Lawful basis, data-subject rights, cross-border transfer, and impact-assessment obligations are not addressed, and meeting the MUST tier does not discharge them.

**Security of the telemetry itself.** The field set treats the telemetry plane as an asset only insofar as it must report its own failure: the observability-plane section covers detecting suppressed events, unreached enforcement points, and incomplete instrumentation. Defending the pipeline is a different problem and is not solved here: authenticating emitters, securing transport and storage, controlling access to collected content, and establishing the tamper-evidence and chain of custody that evidentiary use requires. This is a genuine tension with the immutable, tamper-evident logging that classic audit practice expects, and it is an exclusion of *this document's* scope rather than a claim that the problem does not matter: the CoSAI Risk Map now carries `controlAuditTrailIntegrityVerification` and `controlAuditRecordRepositoryIndependence` for it, and [§15](#15-observability-plane-integrity) records when the plane fails even though it does not defend it.

---

## 4. How to read the field set

Each section below is a fine-grained component (or a tightly related cluster). Field tables use these columns:

- **Field**: conceptual field name (implementation-neutral).
- **Cls**: MUST / SHOULD / MAY.
- **Capture (concept)**: what to record, stated generally enough to bind to any framework.
- **Evidence**: attack IDs that establish the need (see Appendix A).

The reasoning behind each tier is in **[Appendix J](#appendix-j-tiering-rationale)**; AITF and ODIS attribute names are in **[Appendix C](#appendix-c-aitf--odis-cross-reference)**.

### 4.1 Use-case priorities

Every field is justified against four use cases, **in this priority order**:

| | Use case | What it means |
| :---- | :------------------------- | :---------------------------------------------------------------------- |
| **D** | **Threat detection** | Enables a detection to fire on an attack in progress. *Highest priority.* |
| **R** | **Incident response** | Enables scoping, attribution, containment, and forensic reconstruction after the fact. |
| **Q** | **Service debugging / quality** | Explains why the system behaved as it did; performance, cost, and correctness. |
| **A** | **Compliance audit** | Evidences a control to an auditor or regulator. *Lowest priority.* |

Where a field serves several, the **highest-priority** use case governs its tier. A field whose value is mainly Q or A does not reach MUST no matter how useful it is.

### 4.2 Classification legend

The keywords **MUST**, **SHOULD**, and **MAY** are used as defined in **RFC 2119** [[45]](#standards--frameworks), as updated by **RFC 8174** [[46]](#standards--frameworks): they carry that meaning only in capitals, so lowercase "optional" or "should" elsewhere in this document is ordinary prose. Each field carries exactly one keyword, and the table below states both the RFC 2119 obligation and the evidentiary test this document applies to assign it.

| Tag | Meaning | Test |
| :---- | :-------------------- | :------------------------------------------------------------------------------ |
| **MUST** | Baseline. Required for any deployment doing security detection & response. | Grounded in **≥ 2 independent attacks** in [Appendix A](#appendix-a-attack--incident-inventory); **or 1 attack where the field is especially useful for D or R**: *and* implementable on essentially any AI system today, in a deployment modality that is already common. |
| **SHOULD** | Required once a deployment adopts a modality or faces a threat scenario at the **edge of current agentic practice**. | The field serves a deployment modality or threat scenario that is emerging rather than typical; **delegation chains and cascaded authority**, cryptographic identity and attestation, agent-to-agent protocol surfaces, inline enforcement that mutates payloads, dynamic third-party capability composition, or self-attesting instrumentation. Attack grounding may be **analogical**: the corpus motivates the scenario without yet containing a documented instance. |
| **MAY** | Valuable, but not required to catch the core attack classes. | The field's dominant value is **Q or A**; or its attack motivation is thin (single weak instance, or none); or it is a research-grade signal, a derived detector output, or redundant with a MUST field. |

- **Attack count alone does not set the tier.** A field cited by five attacks is still SHOULD if every one of those attacks presupposes a delegation chain, and still MAY if its real job is compliance reporting. The modality gate applies after the evidence gate.
- **SHOULD is not "MUST later."** It is "MUST *if you run this modality*." This is the RFC 2119 reading applied narrowly: the "valid reasons in particular circumstances" for omitting a SHOULD field are **not running the modality it describes**, and nothing else. Cost, effort, and inconvenience are not among them. A deployment with cascaded delegation should treat §13 as mandatory on day one; a single-agent deployment may never need it.

> Tags are **deployment-agnostic**: a tag reflects *what evidence requires the field* and *how common the modality is*, not any one vendor's maturity. See the maturity model in [Implementation Guidance](#18-implementation-guidance).


### 4.3 Component taxonomy

Fields are organized under the CoSAI Risk Map fine-grained components. The component IDs used below are the canonical IDs from [`risk-map/yaml/components.yaml`](https://github.com/cosai-oasis/secure-ai-tooling/blob/main/risk-map/yaml/components.yaml):

| Category | Components referenced in this document |
| :-------------------- | :-------------------------------------------------------------------------------- |
| **Application (Core)** | `componentApplication`, `componentApplicationInputHandling`, `componentApplicationOutputHandling` |
| **Application (Agent)** | `componentReasoningCore`, `componentAgentUserQuery`, `componentAgentSystemInstruction`, `componentAgentInputHandling`, `componentAgentOutputHandling` |
| **Model (Orchestration)** | `componentOrchestrationInputHandling`, `componentOrchestrationOutputHandling`, `componentTools`, `componentMemory`, `componentRAGContent` |
| **Model (Core / Training)** | `componentTheModel`, `componentModelFrameworksAndCode`, `componentModelEvaluation` |
| **Infrastructure (Deployment / Data)** | `componentModelServing`, `componentModelStorage`, `componentDataStorage`, `componentDataSources` |

### 4.4 Attack ID scheme

- **`TA-01…13`**: real-world attack vectors, each with its own field-detection mapping. **`TA-01` is EchoLeak** (M365 Copilot, CVE-2025-32711), the document's lead public case study, and the first entry in the catalogue. **`TA-02…10`** are the CoSAI Telemetry paper's **"Attacks" tab**: Slack AI, ChatGPT markdown exfil, training-data extraction, Samsung leak, LangChain RCE, system-prompt extraction, tool-chaining escalation, RAG-KB poisoning, context-window DoS. **`TA-11…13`** are MCP-mediated incidents from CoSAI's **MCP Security** paper.
- **`IR-01…05`**: CoSAI WS2 *AI Incident Response* case studies.
- **`AOC-01…16`**: *Agents of Chaos* (arXiv:2602.20021) case studies.
- **`AML.Txxxx`**: **MITRE ATLAS** technique IDs. **This is the canonical adversary-technique taxonomy for this document**, and the only one that may appear in new material or in emitted telemetry ([decision](#attack-taxonomy-mitre-atlas-is-canonical)). The CoSAI `AT10xx` labels used by the incident-response case studies are **deprecated aliases**, retained solely so existing material can be migrated, see the alias table in [Appendix A.4](#a4-attack-taxonomy-cosai-at10xx-codes-deprecated-aliases-to-mitre-atlas). The full attack→ATLAS mapping is [Appendix A.5](#a5-attack-inventory--mitre-atlas-technique-mapping).

---

### 4.5 Classification summary

The complete field-by-component classification, before the detailed tables that follow. It is an index rather than a definition: each field name is defined, with what to capture and the attacks that motivate it, in the section shown against it. The reasoning behind each tier (why the MUSTs are MUST, and where the boundaries were contested) is in **[Appendix J](#appendix-j-tiering-rationale)**, ordered to match this table.

| Component (risk-map) | MUST fields | SHOULD fields | MAY fields |
| :-------- | :---------------------------------- | :------------------------------------------ | :---------------- |
| Application / Reasoning Core (§5) | Agent Name, Instance ID, Workflow ID, Session/Turn/Step IDs, Trace Context, Trigger Type & Source Event, Action Type, Exec Status, Surface, System Prompt | Autonomy Level, Organization/Tenant ID | n/a |
| Input Handling (§6) | Model Input, Input Source, Input Trust Class, Source IP, Guardrail(In), Content Modality & Attachment Identity ‡, ATLAS Technique Tag † | Guardrail Modification Record ‡ | Encoded-Payload Indicator |
| Output Handling (§7) | Response, Output Egress, Citations / Source Attribution, Guardrail(Out), LLM Refusal | Observation/Thought | n/a |
| Model & Serving (§8) | Model Name/Version, Inference Parameters, Token Counts, LLM Error | Model Provenance/Signing | Pre-Forward State, Token Malformation, Provider/Endpoint Identity |
| Tools (§9) | Tool Call I/O, Tool Name, Tool Type, Tool Execution ID, Execution Environment / Sandbox, Tool Error | Tool ACL/Scope, Tool Selection Rationale, *Tool Definition Digest*, MCP Server Identity & Primitive | Tool ID, Tool Privacy Class |
| Memory (§10) | Memory Write, Memory Read, Memory Provenance, Memory Footprint | Memory Integrity/Poisoning, Memory Write Rationale | Declared Memory Configuration |
| RAG (§11) | Retrieval Event, Retrieved-Content Source | Content/Metadata Integrity | Declared Knowledge-Source Configuration |
| Orchestration / Multi-Agent (§12) | Inter-Agent Message, Background Task, Loop Signal, Resource Aggregate | Task/Intent Declaration, *A2A Task Lifecycle Event*, Peer Agent Card / Descriptor | Protocol Envelope Capture |
| Identity & Delegation (§13) | Identities Used, Verified-vs-Displayed Identity | Originating Principal, Delegation Chain, Granted Authorizations, Resource Indicators+Constraints, **Credential Minting & Scope-Narrowing**, **Trust-Domain Crossing & Delegation Depth**, Runtime Credential/Attestation, Lifecycle State | n/a |
| Asset & Fleet (§14) | Capability-Set Change Event | Version, Repository/Software Ref, AgBOM / Inventory Snapshot, Component Dependency Graph, Inventory Attestation Signature | Description, Status, Creator/Oncall/dates, Surfaces, Fleet counts |
| Observability-Plane Integrity (§15) | n/a | Instrumentation Coverage / Hook Attestation, Event Sequence Continuity, Enforcement-Point Availability & Failure Mode | Policy Reason Code |
| Policy Enforcement & Mediation (§16) | **Authorization Decision Record**, **Attribute Source / Trusted-Provenance Marking** ‡ | **Session Taint Labels & Information-Flow Decisions**, **Human Approval / Elicitation Event**, **Backend / Route Restriction Decision**, **Mediation Coverage & Bypass Path** | n/a |

† **Threat Classification / ATLAS Technique Tag** is a cross-cutting enrichment listed under §6 for convenience; it applies to any flagged event across all components and is **MUST when a detection fires**. Value = one or more MITRE ATLAS `AML.Txxxx` IDs from [Appendix A.5](#a5-attack-inventory--mitre-atlas-technique-mapping).

‡ Also cross-cutting, also listed under §6 for convenience. **Content Modality & Attachment Identity** applies to every content-bearing field (model input, response, memory item, retrieved item, tool argument). **Guardrail Modification Record** applies to any enforcement point that rewrites rather than blocks, on either the input or the output side. **Attribute Source / Trusted-Provenance Marking** (§16) applies to every security-relevant attribute a hostile agent could fabricate.


---

### 4.6 Where to start

The MUST tier is 47 fields, which is more than most teams can instrument at once. It has an order.

**Adoption order for a deployment starting from zero.** (1) the identifier hierarchy and trace context (§5), because everything else correlates through them and nothing else is interpretable without them; (2) content, trust classification, and guardrail verdicts (§§6 to 7), the highest D-density cluster in the document; (3) tool call I/O with execution IDs and sandbox posture (§9), the highest R value; (4) memory and retrieval (§§10 to 11); (5) orchestration (§12); (6) identity (§13) and capability-set change (§14).

**Early SHOULD fields that protect Tier 1 value**, even before the matching modality is fully adopted: **Enforcement-Point Availability** (§15), without which a starved guardrail is indistinguishable from a clean pass, and **Guardrail Modification Record** (§6), without which a redaction pipeline silently falsifies the log it feeds.

The order is driven by dependency: identifiers come first because later detections resolve through them. Each step is also useful on its own; stopping after step (2) still leaves a working injection-detection capability. See [§18](#18-implementation-guidance) for the full maturity model across all three tiers.

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

| Field | Cls | Capture (concept) | Evidence |
| :------------ | :---- | :-------------------------------------------------------------------------- | :------------ |
| **Agent Name** | MUST | Logical name/type of the agent (e.g. "Deep Research agent"). Detects off-inventory / "shadow" agents. | `AOC-08`,`AOC-10`,`TA-01`,`TA-05` |
| **Agent (Runtime) Instance ID** | MUST | UUID pinning an event to one running instance, not just the type. Enables per-instance kill/quarantine. | `AOC-04`,`AOC-05`,`AOC-08` |
| **Workflow / Run ID** | MUST | Groups all activity of one multi-step run or sub-agent tree into a single traceable execution. | `AOC-04`,`AOC-09`,`AOC-10` |
| **Session / Turn / Step IDs** **[AOS]** | MUST | The three-level execution hierarchy *beneath* the run: `session_id` (the conversation/engagement), `turn_id` (one request→response cycle), `step_id` (one action within a turn). Lets a detection point at *which* turn behaviour changed, not just which run. | `AOC-03`,`AOC-07`,`TA-07`,`TA-08` |
| **Trace Context (propagated)** **[AOS]** | MUST | W3C `traceparent` / `trace_id` + `span_id` **propagated across every agent→tool→agent hop**, including MCP and A2A calls. Without propagation, multi-agent activity cannot be reassembled into one trace. | `AOC-04`,`AOC-09`,`TA-01`,`TA-08` |
| **Organization / Tenant ID** **[AOS]** | SHOULD | The tenant/organization owning the agent, the session, and the invoking user, recorded on each. The primitive for detecting cross-tenant leakage and credential propagation. | `AOC-02`,`AOC-05`,`TA-05`,`TA-01`,`TA-11` |
| **Trigger Type & Source Event** **[AOS]** | MUST | Whether this run was **user-initiated or autonomous**, and for autonomous runs the originating event (inbound email, chat message, webhook, schedule). Distinct from Surface/App, which records the *channel*, not who or what started the run. | `TA-01`,`AOC-04`,`AOC-10`,`AOC-12` |
| **Action Type** | MUST | Distinguishes LLM-call vs tool-call vs memory-op vs message-send, the "think → act" boundary. | `AOC-01`,`AOC-02`,`IR-01` |
| **Execution Status** | MUST | Outcome (complete / error / exit / aborted) + duration. Spikes/timeouts reveal probing, DoS, or mass failure. | `AOC-05`,`AOC-06`,`IR-04`,`TA-04`,`TA-10` |
| **Surface / App** | MUST | Entry point (CLI, web, IDE, email, chat channel, cron/heartbeat; internal vs external service). Detects access from unexpected surfaces. | `AOC-08`,`AOC-10`,`TA-01`,`TA-05` |
| **System Prompt / Instruction Config** | MUST | The system/instruction configuration in force for the call. Detects unauthorized weakening and, by comparison against the response, system-prompt leakage/extraction. | `TA-07`,`AOC-08`,`AOC-10` |
| **Autonomy Level** | SHOULD | Declared independence level (e.g. L1 to L5) the run is authorized to operate at; sets oversight/delegation limits. | `AOC-01`,`AOC-04`,`AOC-07` |

---

## 6. Input Handling & Trust Provenance
**Components:** `componentApplicationInputHandling`, `componentAgentInputHandling`, `componentOrchestrationInputHandling`

*The `componentAgentInputHandling` risk-map definition is literally "processing distinguishing trusted user commands from untrusted environmental data." That distinction is the single most important agentic-security signal, and the working draft did not capture it explicitly.*

| Field | Cls | Capture (concept) | Evidence |
| :------------ | :---- | :------------------------------------------------------------------------- | :------------- |
| **Model Input** | MUST | Every input to each model call in the loop, user prompts, tool outputs, retrieved context, inter-agent messages. Not just the first user turn. Includes size/shape (large or repetitive inputs). | `IR-01`,`IR-02`,`TA-01`,`AOC-03`,`AOC-12`,`TA-05`,`TA-10` |
| **Input Source / Channel** | MUST | Provenance label for each input segment: which surface/tool/agent/document it came from. | `TA-01`,`AOC-10`,`AOC-12`,`IR-03` |
| **Input Trust Classification** | MUST | Whether a segment is *trusted instruction* vs *untrusted data* (owner command vs environmental/third-party content). | `AOC-02`,`AOC-08`,`AOC-12`,`TA-01`,`IR-01` |
| **Source host / IP + request metadata** | MUST | Origin of the request; supports geo/impossible-travel, rate-limit, and credential-theft detection. | `AOC-08`,`AOC-15`,`IR-04`,`TA-03`,`TA-10` |
| **Guardrail (Input) Verdict** | MUST | Result of any input-side injection/jailbreak/PII/secret classifier: **pass / flag / block / modify**, with detector + score. | `TA-01`,`IR-01`,`AOC-12`,`TA-05` |
| **Content Modality & Attachment Identity** **[AOS]** | MUST ‡ | **Cross-cutting.** For every content-bearing field: the part type (text / file / structured data), MIME type, and for files the name, size, and content hash. Instructions that arrive as an image, PDF, or structured blob are invisible to text-only inspection and text-only logging. | `AOC-12`,`AOC-05`,`TA-05`,`TA-01` |
| **Guardrail Modification Record** **[AOS]** | SHOULD ‡ | **Cross-cutting.** When an enforcement point **rewrites rather than blocks**: masking, redacting, stripping, or rewriting a payload; record that a modification occurred, which enforcement point made it, and a before/after digest (plus a redaction map where policy permits). Applies on both the input and the output side. | `TA-01`,`AOC-12`,`AOC-03`,`IR-01` |
| **Threat Classification / ATLAS Technique Tag** | MUST † | **Cross-cutting enrichment.** On any flagged or security-relevant event, the classified technique(s) as **MITRE ATLAS `AML.Txxxx`** IDs (plus a free-text threat type). Emitted by input/output guardrails and by tool/memory/retrieval detectors alike, so every alert carries a portable, ATT&CK-aligned technique reference. | `IR-01`,`TA-01`,`TA-07`,`AOC-12` |
| **Encoded / Obfuscated Payload Indicator** | MAY | Flag + decoded form when input contains base64, image-embedded (OCR), or markup "authority" tags. | `AOC-12`,`TA-03` |

† **MUST when a detection fires** (not on every benign event). The tag is a derived classification, not raw telemetry: detection logic sets it using the [Appendix A.5](#a5-attack-inventory--mitre-atlas-technique-mapping) attack→ATLAS mapping so downstream SIEM/XDR correlation and compliance reporting can pivot on `AML.Txxxx`.

‡ **Cross-cutting fields**, listed here for convenience but applying across components, see the [classification summary](#45-classification-summary). **Guardrail Modification Record** is MUST *when a modification occurs*.

---

## 7. Output Handling, Egress & Refusals
**Components:** `componentApplicationOutputHandling`, `componentAgentOutputHandling`, `componentOrchestrationOutputHandling`

*Where damage materializes: PII leakage, exfiltration channels, harmful content, mass broadcast.*

| Field | Cls | Capture (concept) | Evidence |
| :------------ | :---- | :----------------------------------------------------------------------- | :--------------- |
| **Response / Model Output** | MUST | The generated output at each step. Where leakage, disclosure, verbatim training data, and embedded exfil URLs appear. | `AOC-03`,`AOC-11`,`TA-01`,`TA-03`,`TA-04`,`TA-07` |
| **Output Egress Destination** | MUST | Where output goes: recipient addresses, outbound URLs/domains, channels, file targets, broadcast scope. | `TA-01`,`TA-03`,`AOC-03`,`AOC-11`,`AOC-05` |
| **Citations / Source Attribution** **[AOS]** | MUST | The sources the agent *claims* it drew on, per output: file ID/name/URL or site URL for each citation, **plus whether each resolves to an item actually returned by a logged Retrieval Event (§11)**. Unresolvable, fabricated, or attacker-supplied citations are the signal. | `TA-01`,`TA-02`,`IR-03`,`AOC-03` |
| **Observation / Thought (reasoning trace)** | SHOULD | Chain-of-thought/observations *when the provider exposes it*. Reveals whether a harmful act was injected, misauthorized, or self-initiated. | `AOC-01`,`AOC-07`,`AOC-10`,`IR-02` |
| **Guardrail (Output) Verdict** | MUST | Output-side filter result (PII/DLP, harmful content, exfil pattern): **pass / flag / block / modify**. Modifications are recorded via the **Guardrail Modification Record** (§6). Fired detections carry the **ATLAS Technique Tag** (see §6). | `TA-01`,`AOC-03`,`IR-01` |
| **LLM Refusal** | MUST | Status + reason when the model refuses. A refusal-then-success streak signals a jailbreak in progress; an *absent* refusal on clearly policy-violating output flags a guardrail gap. | `IR-01`,`AOC-12`,`AOC-13`,`AOC-14`,`TA-03`,`TA-04`,`TA-07` |

---

## 8. The Model & Model Serving
**Components:** `componentTheModel`, `componentModelServing`, `componentModelStorage`

*Supply-chain integrity, resource/DoS signals, and pre-inference integrity.*

| Field | Cls | Capture (concept) | Evidence |
| :-------------- | :---- | :--------------------------------------------------------------------------- | :--------- |
| **Model Name + Version** | MUST | Model and version processing the request. "Which agents used the compromised model?"; pins a model-specific vulnerability for patching. | `TA-06`,`IR-04`,`AOC-06`,`TA-04` |
| **Provider / Endpoint Identity** | MAY | Which provider/endpoint served the call (incl. finish/stop reason). | `AOC-06` |
| **Inference Parameters** **[AOS]** | MUST | The decoding/config parameters in force for the call: `temperature`, `top_p`/`top_k`, `max_tokens`, `stop` sequences, `seed`, and the **declared context-window size**. The runtime half of the configuration-integrity baseline that **System Prompt** (§5) covers for instructions. | `TA-04`,`TA-10`,`AOC-06`,`AOC-04` |
| **Input / Output Token Counts** | MUST | Per-call token usage, the primary resource-abuse and runaway-loop signal; max-length outputs flag extraction/DoS. | `AOC-04`,`AOC-05`,`TA-04`,`TA-10` |
| **LLM Error / Exception** | MUST | Errors that occur under adversarial conditions (overflow, malformed encoding, context exhaustion); provider-side silent failures. | `AOC-06`,`IR-01`,`TA-10` |
| **Model Provenance / Signing / Hash** | SHOULD | Signed digest / provenance of the served model artifact (supply-chain attestation). | `TA-06`,`IR-04` |
| **Pre-Forward-Pass State Digest/Vector** | MAY | Content-addressed digest (+ pooled vector) of the exact inputs to a forward pass, captured pre-inference for replay/drift detection. | `IR-02`,`AOC-10` |
| **Token Malformation / Context-Corruption Indicator** | MAY | Signal of context-induced token-entropy anomalies correlated with confabulation. | `IR-02` |

---

## 9. Tools & External Services
**Component:** `componentTools`

*The security perimeter between AI reasoning and real-world consequences. When an agent calls a tool it crosses from "thinking" to "acting."*

> **Gateways, namespaces, and multiple hops.** A tool call is frequently not a single hop. Tools and prompts commonly sit behind a **gateway or broker** that re-namespaces them, and the call may traverse several intermediaries before reaching the system that acts. Three fields carry this, and they should be read together: **Tool Name** records the name *as the agent saw it*, which is the namespaced or gateway-local name and not necessarily the name at the far end; **MCP Server Identity & Primitive** records the immediate counterparty; and **Trace Context** (§5) is what stitches the hops into one trace, propagated over MCP via `params._meta`, per [Appendix D.6](#d6-context-propagation-sampling--privacy-three-operational-traps).
>
> Two consequences. First, **the same underlying capability may appear under different names** depending on the path taken to it, so detections keyed on tool name alone will miss re-namespaced invocations; keying on the server identity and primitive as well is what makes them robust. Second, an intermediary is a **mediation boundary**, and whether it was traversed at all is the subject of **Mediation Coverage & Bypass Path** (§16); `AOC-14` is precisely an attempt to reach a capability by a path that bypasses the mediated one.

| Field | Cls | Capture (concept) | Evidence |
| :------------- | :---- | :-------------------------------------------------------------------- | :----------------- |
| **Tool Call I/O** | MUST | Full input params **and** output for every tool/MCP call; what the agent actually *did* vs what it was asked. Reveals credentials passed between chained calls. | `AOC-01`,`AOC-02`,`AOC-03`,`TA-01`,`TA-06`,`TA-08`,`TA-09` |
| **Tool Name** | MUST | Which capability was invoked. Detects off-manifest / sensitive-tool invocation, escalating tool sequences, and enumeration. | `AOC-02`,`AOC-10`,`IR-01`,`TA-06`,`TA-08`,`TA-09` |
| **Tool Type / Trust Boundary** | MUST | MCP (cross-network) vs internal vs direct-storage vs code-execution, different trust models & policies. | `AOC-14`,`TA-01`,`TA-06` |
| **Tool ID** | MAY | Unique tool-implementation ID for unambiguous attribution across many MCP servers. | `AOC-10` |
| **Tool Execution ID** **[AOS]** | MUST | Correlation ID minted at invocation and echoed on the result, pairing every request with its outcome. | `TA-08`,`AOC-01`,`AOC-04`,`AOC-14` |
| **Tool Definition Digest** **[AOS]** | SHOULD | Hash of the tool's **declared contract as presented at invocation time**: name, description, argument schema, output schema, plus a comparison against the approved baseline. Detects a tool whose definition mutated after approval. | `AOC-10`,`AOC-14`,`TA-06`,`AOC-09` |
| **Execution Environment / Sandbox** **[AOS]** | MUST | The isolation posture of the execution: sandbox mode (none / container / VM / WASM), language runtime and version, OS/architecture, timeout, and network-egress policy. | `TA-06`,`AOC-02`,`AOC-04`,`AOC-14` |
| **MCP Server Identity & Primitive** **[AOS]** | SHOULD | For MCP calls: server name, version, transport, and endpoint; **and which MCP primitive was exercised**: `tool`, `resource`, `prompt`, `sampling`, `elicitation`, or `roots`. | `TA-06`,`AOC-10`,`TA-01`,`AOC-09`,`TA-12`,`TA-13` |
| **Tool Error / Exception** | MUST | Failed/blocked tool calls: rejected injection args, SSRF blocks, authz boundary hits, and the probing errors that precede successful exploitation. | `TA-01`,`AOC-14`,`IR-01`,`TA-06` |
| **Tool ACL / Required Scope** | SHOULD | The authority a tool requires and who may invoke it (the tool's security policy); individually-authorized calls that violate separation-of-duties as a chain. | `AOC-08`,`AOC-10`,`AOC-02`,`TA-06`,`TA-08`,`TA-12` |
| **Tool Privacy Classification** | MAY | Sensitivity class of data the tool touches, feeds DLP / data-flow governance. | `AOC-03`,`TA-01`,`TA-05` |
| **Tool Selection Rationale** **[AOS]** | SHOULD | The agent's stated reason for choosing *this* tool with *these* arguments, captured at the request step. Distinct from the §7 output-side reasoning trace: it is attached to the action, not the answer. | `AOC-01`,`TA-08`,`AOC-10`,`AOC-02` |

---

## 10. Memory
**Component:** `componentMemory`

*Persistent memory is a first-class attack surface. Multiple corpus attacks target it directly.*

> **What counts as memory, and at what granularity.** *Memory* here means **any store the agent writes to in one turn and reads back in a later one**, whatever its substrate: a vector store, a scratchpad file, a database row, a project instruction file, or a file the agent edits in a repository it also reads from. The substrate is irrelevant; the read-after-write-across-turns property is what creates the attack surface, because it is what lets `IR-02` and `AOC-10` outlive the session that planted them.
>
> The fields below are specified at **item granularity, not store granularity**: a Memory Write Event describes one item, and **Memory Provenance** attaches to that item. This requires a stable item identifier, and deployments whose memory is an opaque blob (a single file rewritten wholesale) cannot supply one. Such deployments should emit the write event with a **content digest** in place of an item ID, which preserves change detection and correlation while losing per-item provenance. That is a real reduction in detection capability and the reason item-level identity is worth engineering for.
>
> **Out of scope:** the durability, consistency, and retention semantics of the store itself, and any judgement about whether a given design *should* persist state. This section records what was written, read, and by what authority, not whether the memory architecture is sound.

| Field | Cls | Capture (concept) | Evidence |
| :---------------- | :---- | :--------------------------------------------------------------------- | :------------ |
| **Memory Write Event** | MUST | Every create/update/delete to persistent or long-term memory: what changed, by which turn/actor. | `IR-02`,`IR-05`,`AOC-07`,`AOC-10` |
| **Memory Read / Injection Event** | MUST | Which memory items were pulled into context for a call. | `IR-02`,`IR-05`,`AOC-10` |
| **Memory Provenance / Source** | MUST | Origin & mutability of a memory item, self-authored, owner, non-owner, or **externally editable resource**. | `AOC-10`,`IR-02` |
| **Memory Integrity / Poisoning Signal** | SHOULD | Integrity check / poisoning-likelihood score, cross-session isolation flag. | `IR-02`,`IR-05` |
| **Memory Footprint / Growth** | MUST | Size/growth of memory stores (per user/session), resource-exhaustion signal. | `AOC-05`,`AOC-04` |
| **Declared Memory Configuration** **[AOS]** | MAY | The memory store's declared identity and limits: name, type, backend, size cap, retention, and retrieval spec (top-k, scoring). The baseline that **Memory Footprint** is measured against. | `AOC-05`,`AOC-07`,`IR-02` |
| **Memory Write Rationale** **[AOS]** | SHOULD | The agent's stated reason for persisting *this* item, captured at the write step. | `IR-02`,`AOC-07`,`AOC-10` |

---

## 11. Retrieval & Content (RAG)
**Component:** `componentRAGContent`

*RAG is a primary injection and manipulation channel.*

| Field | Cls | Capture (concept) | Evidence |
| :-------------------- | :---- | :-------------------------------------------------------------- | :--------------- |
| **Retrieval Event** | MUST | Query issued + documents/chunks returned + retrieval scores. | `TA-01`,`TA-02`,`TA-09`,`IR-03`,`AOC-10` |
| **Retrieved-Content Source / Provenance** | MUST | Origin, owner, trust level, and freshness (create/update time) of each retrieved item (internal doc, web, third-party, user upload). | `TA-01`,`TA-02`,`TA-09`,`IR-03` |
| **Retrieved-Content / Metadata Integrity Signal** | SHOULD | Tamper/poisoning indicators on content **or its metadata/tags**. | `IR-03`,`IR-05`,`TA-02`,`TA-09` |
| **Declared Knowledge-Source Configuration** **[AOS]** | MAY | Each knowledge source's declared identity and contract: name, description, index/collection identity, schema, and search parameters (top-k, filters, scoring, reranker). | `TA-09`,`IR-03`,`TA-02` |

---

## 12. Orchestration, Multi-Agent & Background Execution
**Components:** `componentReasoningCore`, `componentOrchestrationInputHandling`, `componentOrchestrationOutputHandling`

*Multi-agent and autonomous-execution telemetry: the corpus shows these are where agentic risk compounds.*

| Field | Cls | Capture (concept) | Evidence |
| :-------------- | :---- | :------------------------------------------------------------------------ | :------------ |
| **Inter-Agent Message** | MUST | Agent→agent messages: sender, receiver, content, channel, including capability/skill transfer. | `AOC-04`,`AOC-09`,`AOC-11`,`AOC-16` |
| **A2A Task Lifecycle Event** **[AOS]** | SHOULD | Delegated-task state transitions across the A2A surface: task submitted, streamed, polled, **cancelled**, resubscribed, and **push-notification config set or changed**, which registers an outbound callback destination. | `AOC-04`,`AOC-11`,`AOC-09`,`TA-01` |
| **Peer Agent Card / Descriptor** **[AOS]** | SHOULD | The counterparty agent's declared descriptor as presented at contact: name, URL, version, provider, and advertised skills/capabilities, with change detection against prior contacts **and the outcome of any verification attempted against it** (signature checked, inspection request answered or refused, or unverified). |  `AOC-09`,`AOC-11`,`AOC-08`,`AOC-16` |
| **Background / Scheduled Task Event** | MUST | Creation/modification of cron jobs, heartbeats, daemons, or self-scheduled loops, incl. presence/absence of a termination condition. | `AOC-04`,`AOC-10` |
| **Loop / Step-Count Signal** | MUST | Steps or iterations per run vs baseline; circular agent-to-agent exchange detection. | `AOC-04`,`IR-02` |
| **Resource-Consumption Aggregate** | MUST | Per-run/agent token, compute, storage, and outbound-volume totals against a budget. | `AOC-04`,`AOC-05`,`TA-10` |
| **Task / Intent Declaration** | SHOULD | The declared purpose/task the run is authorized to pursue (for goal-drift detection). | `AOC-04`,`AOC-01`,`AOC-10` |
| **Protocol Envelope Capture** **[AOS]** | MAY | The raw MCP / A2A JSON-RPC envelope (method, id, params) alongside the interpreted fields, preserving protocol-level detail that framework-level abstraction discards. | `AOC-09`,`AOC-12`,`TA-06` |

---

## 13. Identity, Delegation & Attribution *(ODIS-aligned; mostly SHOULD)*
**Cross-cutting:** spans `componentReasoningCore`, `componentTools`, `componentModelServing` and binds them into an accountable chain.

*The "Quadruple Identity" problem: a **principal** authorizes an **agent** which (possibly via **other agents**) calls a **tool** that acts on **infrastructure**. Without identity at each hop, accountability collapses and confused-deputy attacks succeed. This is the ODIS problem space; delegation fields are **SHOULD** by the classification rule.*

| Field | Cls | Capture (concept) | Evidence |
| :---------- | :---- | :------------------------------------------------------------------------------ | :---------- |
| **Identities Used (per hop)** | MUST | Attribute every agent→user, agent→agent, agent→tool, tool→infra action to an identity + metadata; detect identity changes across a tool chain. | `AOC-01`,`AOC-02`,`AOC-08`,`AOC-11`,`IR-04`,`TA-05`,`TA-08` |
| **Verified vs Displayed Identity** | MUST | Distinguish an immutable/verified identifier from a spoofable display identity; record which was used to authorize. | `AOC-08`,`AOC-11`,`AOC-15` |
| **Originating Principal (on-behalf-of)** | SHOULD | The human/service sponsor at the root of the delegation chain. | `AOC-01`,`AOC-02`,`AOC-08` |
| **Delegation Chain** | SHOULD | Ordered lineage of prior agent hops carried across the call. | `AOC-04`,`AOC-09`,`AOC-10` |
| **Granted Authorizations / Scope** | SHOULD | Delegated authority in effect at this hop, with monotonic-narrowing check. | `AOC-02`,`AOC-08`,`AOC-10`,`TA-13` |
| **Resource Indicators + Constraints** | SHOULD | Target resource audience + time/purpose/rate/locality/`data_classification` narrowing. | `AOC-03`,`AOC-05`,`TA-01` |
| **Credential Minting & Scope-Narrowing Check** **[CPEX]** | SHOULD | The credential-exchange event at each hop: grant type (token exchange / client assertion / client credentials), whose identity the minted token represents (**end user / client application / calling workload / the enforcement point itself**), target **audience**, issuer, lifetime, and the **requested-vs-granted scope delta** verified after minting. Detects both over-broad credentials and forwarded inbound tokens that were never narrowed. | `AOC-02`,`AOC-08`,`IR-04`,`TA-08` |
| **Trust-Domain Crossing & Delegation Depth** | SHOULD | The counterparty's **trust domain** and the **depth of the delegation chain** at this hop, plus whether either crossed a configured limit. Records that authority left the domain that issued it, and how many hops from the originating principal the acting agent now sits. | `AOC-04`,`AOC-09`,`AOC-11`,`TA-11` |
| **Runtime Credential / Attestation** | SHOULD | Runtime-instance credential: `software_hash`, `attestation_method`, issuer, expiry, holder-key binding. | `AOC-08`,`TA-06` |
| **Lifecycle State** | SHOULD | active / suspended / revoked, supports kill-switch & revocation-fanout. | `AOC-07`,`AOC-10` |

---

## 14. Asset Inventory & Fleet Aggregates *(mostly MAY)*
**Components:** `componentTools`, `componentApplication`, `componentModelFrameworksAndCode` (inventory); fleet-level metrics are cross-component.

*These define the inventory and posture rather than per-request activity. Most are governance and CVE-response signals rather than detection signals, hence mostly MAY. The exceptions are the **change** signal, which is detection-grade and MUST, and the AgBOM cluster, which is the structural counterpart to OWASP AOS's **Inspect** pillar.*

| Field / Metric | Cls | Capture (concept) | Evidence |
| :------------------------------ | :---- | :-------------------------------------------------------------- | :------- |
| **Capability-Set Change Event** **[AOS]** | MUST | An event emitted whenever the agent's usable capability set changes at runtime, a tool, MCP server, model, knowledge source, or memory store **discovered, added, removed, or modified**: with before/after identity and what triggered the change. | `AOC-09`,`AOC-10`,`TA-06`,`AOC-02` |
| **Tool/Agent Version** | SHOULD | Version of each tool/agent/framework; instant CVE blast-radius answer; downgrade detection. | `TA-06`,`IR-04` |
| **Repository / Code Path / Software Ref** | SHOULD | Source provenance of tool/agent code (ties to signing & ODIS `approved_software_refs`). | `TA-06`,`AOC-10` |
| **AgBOM / Inventory Snapshot** **[AOS]** | SHOULD | A structured, machine-readable inventory of the agent's composition (packages, models, capabilities (agent cards, discovered peers, MCP servers), knowledge sources, memory stores, tools) emitted on change and **on demand**. Bound to an existing BOM format (CycloneDX, SPDX, or SWID) rather than a bespoke one. | `TA-06`,`IR-04`,`AOC-09`,`AOC-10` |
| **Component Dependency Graph** **[AOS]** | SHOULD | Dependency edges between inventoried components, including transitive ones; which agent depends on which tool, which tool on which package or MCP server. | `TA-06`,`IR-04` |
| **Inventory Attestation Signature** **[AOS]** | SHOULD | Cryptographic signature over the emitted inventory (signature value + key identifier), binding the declared composition to a signer. | `TA-06`,`AOC-10`,`IR-04` |
| **Description** | MAY | Declared purpose: detects misleadingly-described ("read-only" but writes) tools. | `AOC-14` |
| **Status (active/disabled)** | MAY | Detects calls to tools that should be unreachable. | `AOC-02` |
| **Creator ID / Oncall / Creation & Update dates** | MAY | Ownership, age-based risk, change-correlation for IR speed; recently-changed assets/content correlate with attack timelines. | `IR-04`,`TA-09` |
| **Surfaces Supported** | MAY | Exposure map per tool. | `AOC-08` |
| **Fleet counts** (agents by framework/type; sessions L1/L7/L28; users MAU/power-user; tool-call volume & agent↔tool map; surface & status breakdowns) | MAY | Aggregate anomaly, shadow-AI, and CVE-exposure signals. | `AOC-04`,`AOC-05`,`TA-06` |

---

## 15. Observability-Plane Integrity
**Cross-cutting:** applies to the instrumentation and enforcement layer itself, not to any one pipeline component.

*Every field in §§5 to 14 assumes the telemetry and enforcement path is functioning and uncompromised. Nothing elsewhere in the field set tests that assumption. This section closes the loop: it is telemetry **about the observability plane**, motivated by the OWASP AOS **Instrument** pillar, where enforcement is a synchronous callout that can fail, be bypassed, or be starved.*

| Field | Cls | Capture (concept) | Evidence |
| :---------------- | :---- | :----------------------------------------------------------------------- | :---------- |
| **Enforcement-Point Availability & Failure Mode** | SHOULD | For each enforcement callout (guardrail, policy engine, external guardian): whether it was reached, its latency, and on failure whether the system **failed open or failed closed**: plus the action that was taken anyway. | `TA-01`,`TA-10`,`IR-01`,`AOC-12` |
| **Instrumentation Coverage / Hook Attestation** | SHOULD | Which lifecycle hooks are instrumented and active for this agent/run, and the instrumentation version, the difference between "no events" and "not observed." | `AOC-10`,`AOC-01`,`AOC-09` |
| **Event Sequence Continuity** | SHOULD | Per-session monotonic sequence number (optionally signed or chained) enabling gap and reordering detection in the event stream. | `AOC-01`,`AOC-10`,`AOC-07` |
| **Policy Reason Code** | MAY | Machine-readable reason code(s) for an enforcement decision, alongside the existing free-text detector name and score. | `IR-01`,`AOC-12`,`TA-01` |

> **Scope note for the working group.** §15 sits on the boundary between telemetry and control-plane design, and the WG should confirm the line drawn here. The position taken is that the **outcomes** of enforcement (availability, failure mode, coverage, decision rationale) are security telemetry and belong in this document, while the **protocol** for performing enforcement (AOS's JSON-RPC hook transport, guardian-agent architecture, authentication between agent and guardian) does not. See [open question 10](#open-questions-for-the-working-group).

---

## 16. Policy Enforcement & Mediation
**Cross-cutting:** the reference-monitor layer between the agent and every capability it invokes, tools, prompts, resources, inference providers, and inter-agent methods.

*§§5 to 14 record what the agent **did**; §15 records whether the observability plane **worked**. Neither records what policy **decided**, or on what basis. This section closes that gap, and it is grounded in the [CPEX](https://contextforge-org.github.io/cpex/) threat model, whose starting assumption is stronger than this document's has been: **the LLM is the adversary**. Prompt injection can arrive through any content the model reads; an injected instruction becomes a tool call; the model has no security properties and cannot be relied on to enforce anything. Everything on the agent side of the monitor is hostile, so nothing a policy reads (and, this section argues, nothing security telemetry treats as authoritative) may originate there.*

| Field | Cls | Capture (concept) | Evidence |
| :------------- | :---- | :------------------------------------------------------------------------------- | :------- |
| **Authorization Decision Record** **[CPEX]** | MUST | Per mediated operation: the decision (**allow / deny / modify**), the deny **reason and machine-readable code**, the **deciding authority** (inline policy rule vs external PDP, and which; Cedar / CEL / OPA / custom), the **rule or policy identifier** that produced it, and any obligations attached. Distinct from a content-guardrail verdict: this is the *authorization* outcome, not a classifier score. | `AOC-02`,`AOC-08`,`AOC-10`,`TA-08`,`TA-12`,`TA-13` |
| **Attribute Source / Trusted-Provenance Marking** **[CPEX]** | MUST ‡ | **Cross-cutting.** For every security-relevant attribute, the **authority that supplied it**: verified IdP token, policy decision point, enforcement-owned session store, platform/runtime, versus **self-asserted by the agent or model**. Under assume-breach, an unmarked value is an unverified value. | `AOC-01`,`AOC-08`,`AOC-10`,`AOC-15` |
| **Session Taint Labels & Information-Flow Decisions** **[CPEX]** | SHOULD | Information-flow labels in force for the session or message: which labels are set, **scope** (session vs message), what operation applied each, and (critically) when an operation is **denied because of accumulated taint rather than anything in its own payload**. The write-down record. | `AOC-03`,`TA-01`,`TA-02`,`TA-05` |
| **Human Approval / Elicitation Event** **[CPEX]** | SHOULD | Out-of-band approval lifecycle for high-impact actions: correlation ID, status (pending / resolved / expired), outcome, **approver identity as verified by the identity provider** (not as reported by the agent), channel, and the **scope-binding validation result**: whether the approval still covers the arguments actually presented at execution time. | `AOC-01`,`AOC-02`,`AOC-07`,`AOC-11` |
| **Backend / Route Restriction Decision** **[CPEX]** | SHOULD | Where an operation was allowed to execute: the candidate backend/model set, the constraint that narrowed it (region, model, site, cost tier, custom label), the selection made, and the behaviour when **no candidate qualified**. | `AOC-05`,`AOC-06`,`TA-01` |
| **Mediation Coverage & Bypass Path** **[CPEX]** | SHOULD | Whether this operation traversed a reference monitor at all, at which **placement** (inbound gateway / egress sidecar / in-process framework), and whether **unmediated paths to the same capability exist**. | `AOC-02`,`AOC-14`,`TA-06` |

‡ Cross-cutting, see the [classification summary](#45-classification-summary). Applies to the attributes a hostile agent could plausibly fabricate: identity, authorization outcome, taint state, approval status, autonomy level, task declaration, and instruction configuration.

> **Scope note.** CPEX is a *runtime*; this section takes only the **decision records it produces**, not its policy language, plugin model, or deployment architecture. The boundary matches the one drawn for AOS in [§15](#15-observability-plane-integrity): enforcement outcomes are telemetry, enforcement mechanisms are not. See [Appendix G](#appendix-g-cpex-cross-reference).

---

## 17. Correlation Patterns

Raw fields are evidence; detection comes from correlation.

| Pattern | Indicates | Fields correlated | Evidence |
| :---------------------------------------- | :-------------------- | :------------------------------- | :--------- |
| Same input hash across many identities | Automated injection campaign | Model Input, Identities Used, Source IP | `IR-01` |
| Rising LLM Refusal → then Status=complete (same session) | Jailbreak succeeded after probing | LLM Refusal, Execution Status, Model Input | `IR-01`,`AOC-12` |
| Tool-call spike + new Tool Name appears | Agent reaching unauthorized capability | Tool Call I/O, Tool Name, Resource Aggregate | `AOC-02`,`AOC-10` |
| Untrusted input segment → tool call → outbound egress to new domain | Injection-to-exfiltration chain | Input Trust Class, Tool Call I/O, Output Egress Destination | `TA-01`,`TA-03` |
| Memory write with non-owner/external provenance → later behavior change | Memory poisoning / indirect corruption | Memory Write, Memory Provenance, Observation/Thought | `IR-02`,`AOC-10` |
| Retrieved item (external source, recently modified) quoted as instruction in output | RAG injection / KB poisoning | Retrieval Event, Retrieved-Content Source, Response | `TA-01`,`TA-02`,`TA-09` |
| Response text ≈ logged System Prompt | System-prompt extraction | System Prompt, Response, LLM Refusal | `TA-07` |
| Chain of individually-authorized tool calls; identity shifts mid-chain | Tool-chaining privilege escalation | Tool Call I/O, Identities Used, Tool ACL/Scope, tool-call count | `TA-08` |
| Oversized/recursive input + max-length output + timeout/overflow error | Context-window DoS / cost blow-up | Model Input, Token Counts, LLM Error, Resource Aggregate, Source IP | `TA-10` |
| Inter-agent messages loop + token/compute climbing, no terminating step | Multi-agent resource-exhaustion loop | Inter-Agent Message, Loop Signal, Resource Aggregate | `AOC-04` |
| Background task created with no termination condition | Runaway automation / persistence | Background Task Event, Action Type | `AOC-04`,`AOC-10` |
| Privileged action authorized on **displayed** (not verified) identity, esp. new channel | Identity spoofing / confused deputy | Verified-vs-Displayed Identity, Granted Authorizations, Surface | `AOC-08` |
| Model Name/Provider change + Error/finish-reason spike | Supply-chain compromise or provider-side interference | Model Name, Provider Identity, LLM Error | `TA-06`,`AOC-06` |
| Source IP shift + same identity | Credential theft / session hijack | Source IP, Identities Used, Surface | `AOC-15`,`IR-04` |
| Cited source resolves to no logged retrieval, or to an external/recently-modified item | Fabricated or attacker-planted citation; trust laundering | Citations, Retrieval Event, Retrieved-Content Source, Output Egress | `TA-02`,`IR-03`,`TA-01` |
| Enforcement point unreachable or timing out → action proceeds (fail-open) | Control-plane starvation; guardrail bypass | Enforcement-Point Availability, Guardrail Verdict, Resource Aggregate, Source IP | `TA-01`,`TA-10` |
| Tool Definition Digest changes between sessions for an approved tool | MCP tool rug-pull / description poisoning | Tool Definition Digest, MCP Server Identity, Tool Call I/O | `AOC-10`,`AOC-14`,`AOC-09` |
| Capability-Set Change (tool/MCP server added) shortly after an inter-agent message | Cross-agent capability transfer | Capability-Set Change Event, Inter-Agent Message, Peer Agent Card | `AOC-09`,`AOC-04` |
| Code-execution tool invoked with sandbox = none | Unsandboxed execution reachable from model output | Execution Environment/Sandbox, Tool Type, Tool Call I/O | `TA-06`,`AOC-02` |
| Push-notification callback registered to a new external domain | Covert egress channel via delegated-task callbacks | A2A Task Lifecycle Event, Output Egress Destination, Peer Agent Card | `TA-01`,`AOC-11` |
| Inference parameters diverge from approved baseline (temperature ↑, stop removed, max_tokens ↑) | Config tampering widening extraction/jailbreak surface | Inference Parameters, System Prompt, LLM Refusal, Response | `TA-04`,`TA-07` |
| Autonomous trigger + untrusted input segment + egress to new domain | Zero-click injection-to-exfiltration | Trigger Type, Input Trust Class, Output Egress Destination | `TA-01`,`AOC-10` |
| Event-sequence gap, or hook coverage drops mid-run | Telemetry suppression by a compromised agent | Event Sequence Continuity, Instrumentation Coverage, Action Type | `AOC-10`,`AOC-01` |
| Memory footprint exceeds declared cap, or the declared cap itself changes | Memory-store exhaustion or silent limit removal | Memory Footprint, Declared Memory Configuration, Memory Write | `AOC-05`,`AOC-07` |
| Same tenant ID across identities that should be isolated | Cross-tenant credential propagation / data bleed | Organization/Tenant ID, Identities Used, Memory Read, Retrieval Event | `AOC-02`,`AOC-05` |
| Egress operation denied on accumulated session taint, with a clean payload | Write-down attempt / injection-driven exfiltration | Session Taint Labels, Authorization Decision Record, Output Egress Destination | `TA-01`,`TA-02`,`AOC-03` |
| Security attribute self-asserted by the agent contradicts the authority-supplied value | Compromised agent falsifying its own state | Attribute Source Marking, Verified-vs-Displayed Identity, Authorization Decision Record | `AOC-01`,`AOC-08`,`AOC-10` |
| High-impact action executes with no approval record, or on an approval whose scope no longer covers the arguments | Missing or replayed human authorization | Human Approval / Elicitation Event, Tool Call I/O, Authorization Decision Record | `AOC-01`,`AOC-07`,`AOC-11` |
| Deny-code distribution shifts, or the same rule denies repeatedly then allows | Policy probing; authorization bypass found | Authorization Decision Record, Identities Used, Source IP | `AOC-02`,`AOC-08`,`IR-01` |
| Minted credential's granted scope exceeds requested, or inbound token forwarded unnarrowed | Over-broad delegation / confused deputy | Credential Minting & Scope-Narrowing, Granted Authorizations, Identities Used | `TA-08`,`AOC-08` |
| Capability reached over a path with no mediation record | Reference-monitor bypass | Mediation Coverage & Bypass Path, Tool Type/Trust Boundary, Tool Call I/O | `AOC-14`,`AOC-02` |
| Inference or tool routed to a backend outside the restriction in force | Data-residency or routing-policy violation | Backend / Route Restriction Decision, Session Taint Labels, Provider/Endpoint Identity | `AOC-06`,`TA-01` |

---

## 18. Implementation Guidance

### Maturity model (how the three tiers phase in)

Adoption sequencing within the MUST tier is in [§4.6](#46-where-to-start).

- **Tier 1, MUST (baseline detection and response): 47 fields, across §§5 to 14 and §16.** The minimum to detect prompt injection, data disclosure, memory/RAG poisoning, exfiltration, resource/DoS abuse, identity spoofing, runaway multi-agent loops, and unauthorized action. Every MUST field is grounded in ≥2 corpus attacks) or in one attack where it is especially useful for **D** or **R**: is **D- or R-dominant**, and is implementable on current stacks with no modality precondition. §15 contains no MUST.
- **Tier 2, SHOULD (edge-modality hardening).** Adopt the relevant cluster **as soon as you run the modality**, not on a maturity schedule. Delegated authority → all of §13 plus Tool ACL/Scope (§9). Multi-tenancy → Organization/Tenant ID (§5). A2A → task lifecycle and peer agent cards (§12). Third-party or dynamic MCP composition → tool definition digest and MCP server identity (§9). Inline enforcement that mutates payloads → Guardrail Modification Record (§6). Autonomous action → autonomy level (§5) and task/intent declaration (§12). Supply-chain attestation → model signing (§8), the AgBOM cluster (§14). Self-attesting instrumentation → §15. Information-flow control → session taint (§16). Out-of-band human approval → elicitation events (§16). Policy-driven backend selection → route restriction (§16). Token exchange → credential minting (§13). Plus the reasoning-trace and integrity-scoring fields (§§7, 9, 10, 11), which are gated by provider availability and privacy policy rather than by modality.
- **Tier 3, MAY (Q, A, and thin-evidence signals).** Fleet aggregates and static asset metadata; declared memory and knowledge configuration (§§10 to 11); provider/endpoint identity (§8); tool privacy classification (§9); protocol envelopes (§12); policy reason codes (§15); derived detector outputs already covered by a MUST (encoded-payload indicator, §6); and research-grade signals (pre-forward-pass state, token malformation, §8).

### Operationalizing telemetry for detection
Logged fields are a necessary evidentiary foundation, not detection by themselves. A four-year measurement study of a production security operations centre; 115 million alerts, 2018 to 2022; found volumes of **24 K to 134 K alerts per day of which 0.01% corresponded to true attacks or compromises**, with 27% attack attempts and 49% benign triggers [[44]](#standards--frameworks). Treat logged values as inputs to layered analytics: signature rules, self-learning anomaly detection, cross-layer correlation (the patterns above), and ML scoring of prompts/outputs/action-sequences. The corollary is a staffing one, and it is the reason this document orders fields by detection value rather than completeness: a trail no analyst can read is not an asset. Field names, tier, and the [correlation patterns](#17-correlation-patterns) are meant to be usable directly as detection-engineering and triage input, and the attack IDs on every field are there so an analyst can see what a field was collected *for*. Continuously re-evaluate detectors; benchmarks show injection detectors effective on explicit attacks often fail on subtler variants. **When a detector fires, stamp the event with its MITRE ATLAS `AML.Txxxx` technique** (the *Threat Classification / ATLAS Technique Tag* field) using the [Appendix A.5](#a5-attack-inventory--mitre-atlas-technique-mapping) mapping; this makes AI-specific alerts correlate with the ATT&CK-aligned rest of the SOC and roll up cleanly into ATLAS-based compliance reporting.

### Privacy-preserving logging
**Model Input, Response, System Prompt, Observation/Thought, Memory, and Retrieved Content** carry significant privacy weight (they can contain PII/secrets, see `AOC-03`). Apply: access controls restricting content-log access to IR with justification; short retention for full content (7 to 30 days) and longer retention for hashed/classified signals; redaction pipelines that strip PII while keeping content hashes for correlation; encryption at rest with audited key access. This is why several high-value fields (Observation/Thought, memory/RAG content) are captured *conceptually* here but their raw-content logging is a deployment policy decision.

---

**CLOSING WORDS** *(to be written)*

## 19. References

### Primary sources (attack corpus & taxonomy)

1. **MITRE ATLAS**: Adversarial Threat Landscape for Artificial-Intelligence Systems (technique matrix; `AML.Txxxx` taxonomy). MITRE. <https://atlas.mitre.org/>
2. **Agents of Chaos**: Shapira, N., Wendler, C., Yen, A., et al. *Agents of Chaos.* arXiv:2602.20021 (2026). <https://arxiv.org/abs/2602.20021> · interactive log: <https://agentsofchaos.baulab.info/>
3. **CoSAI AI Incident Response**: Coalition for Secure AI, Workstream 2 (Defenders): *AI Incident Response Framework* (case studies). <https://github.com/cosai-oasis/ws2-defenders/blob/main/incident-response/AI-Incident-Response.md>

### Real-world attack primary sources

One source per real-world attack vector, each mapping to a `TA-` ID in [Appendix A.1](#a1-real-world-attack-vectors). Ref 4 is the lead case study; refs 5 to 13 are the source citations from the CoSAI Telemetry paper's "Attacks" tab.

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

### Standards & frameworks

17. **CoSAI Risk Map**: Coalition for Secure AI, fine-grained AI system components taxonomy. <https://github.com/cosai-oasis/secure-ai-tooling/tree/main/risk-map>. 52 risks / 73 controls as of the `preview/controls-risks-for-review` branch; risk IDs migrated to the `risk`+camelCase convention. <https://github.com/davidlabianca/secure-ai-tooling/tree/preview/controls-risks-for-review>
18. **CoSAI MCP Security**: Coalition for Secure AI, Workstream 4 (Secure Design Patterns for Agentic Systems): *Model Context Protocol (MCP) Security*, approved 8 January 2026. Twelve threat categories (MCP-T1…T12), ~40 threats. <https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf>
19. **AITF**: AI Telemetry Framework (OTel + OCSF binding), donated to CoSAI WS2. <https://github.com/cosai-oasis/ws2-defenders/tree/main/telemetry>
20. **ODIS**: Open Delegation & Identity Standard. **Working document, access-controlled**; no public citable URL at time of writing. <https://docs.google.com/document/d/1OGlaIAPu_I9RT0YqSF_li3dQEULAW6eo/edit>, replace with the published reference before release.
21. **OWASP Top 10 for LLM Applications (2025)**: OWASP GenAI Security Project. <https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/>
22. **OWASP Top 10 for Agentic Applications (2026)**: OWASP GenAI Security Project. <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
23. **MITRE ATT&CK**: adversary tactics & techniques knowledge base (ATLAS-aligned). MITRE. <https://attack.mitre.org/>
24. **NIST AI Risk Management Framework (AI RMF 1.0)**: NIST, January 2023; **currently under revision**. GOVERN / MAP / MEASURE / MANAGE. <https://www.nist.gov/itl/ai-risk-management-framework> · companion **NIST AI 600-1, Generative AI Profile** (July 2024). Mapped in [Appendix H](#appendix-h-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile).
25. **NIST Cybersecurity Framework (CSF) 2.0**: GV / ID / PR / DE / RS / RC; 6 functions, 22 categories, 106 subcategories. <https://www.nist.gov/cyberframework>
26. **NIST Cyber AI Profile**: *Cybersecurity Framework Profile for Artificial Intelligence*, **NIST IR 8596**, preliminary draft published 16 December 2025; CSF 2.0 community profile overlaying the **Secure / Detect / Thwart** AI focus areas. Initial Public Draft expected 2026. <https://www.nccoe.nist.gov/projects/cyber-ai-profile>
27. **ISO/IEC 42001:2023**: *Information technology (Artificial intelligence) Management system.* Clauses 4 to 10 plus **Annex A** (38 controls under 9 objectives, A.2 to A.10) selected via a Statement of Applicability. Paid standard. <https://www.iso.org/standard/42001> Mapped in [Appendix I](#appendix-i-implications-for-isoiec-42001).
28. **EU AI Act. Article 12 (Record-keeping / Logging).** <https://artificialintelligenceact.eu/article/12/>
29. **OpenTelemetry (GenAI semantic conventions.** Now maintained in a dedicated repository: <https://github.com/open-telemetry/semantic-conventions-genai>) spans, metrics, events, MCP, and provider-specific conventions, **all at Development status**. Attribute registry: <https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/> (entries marked *Deprecated* there reflect the relocation, not withdrawal). Cross referenced in [Appendix D](#appendix-d-implications-for-opentelemetry-the-instrumentation-bridge).
30. **OpenTelemetry, core specification.** Signals, context propagation, sampling. <https://opentelemetry.io/docs/specs/otel/> · **W3C Trace Context**: <https://www.w3.org/TR/trace-context/> · MCP context propagation via `params._meta` (**SEP-414**): <https://modelcontextprotocol.io/community/seps/414-request-meta>
31. **OCSF. Open Cybersecurity Schema Framework.** <https://ocsf.io/> · schema browser: <https://schema.ocsf.io/>
32. **OWASP AOS (Agent Observability Standard.** OWASP. <https://aos.owasp.org/>) three pillars (Instrument / Trace / Inspect); cross referenced in [Appendix F](#appendix-f-owasp-aos-cross-reference). *Working draft at time of writing.*
33. **Model Context Protocol (MCP).** <https://modelcontextprotocol.io/>, tools, resources, prompts, sampling, elicitation, roots (§9).
34. **A2A (Agent-to-Agent Protocol.** <https://a2a-protocol.org/>) agent cards, task lifecycle, push-notification configuration (§12).
35. **CycloneDX**: OWASP BOM standard, incl. ML-BOM. <https://cyclonedx.org/>
36. **SPDX**: Linux Foundation software bill-of-materials standard. <https://spdx.dev/>
37. **SWID**: ISO/IEC 19770-2 software identification tags. <https://csrc.nist.gov/projects/Software-Identification-SWID>
38. **CPEX**: policy-enforcement runtime and reference monitor for AI agents. <https://contextforge-org.github.io/cpex/> · threat model: <https://contextforge-org.github.io/cpex/docs/threat-model/>, cross referenced in [Appendix G](#appendix-g-cpex-cross-reference).
39. **RFC 8693**: OAuth 2.0 Token Exchange (on-behalf-of delegation). <https://www.rfc-editor.org/rfc/rfc8693>
40. **RFC 7523**: JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants. <https://www.rfc-editor.org/rfc/rfc7523>
41. **SPIFFE / SVID**: Secure Production Identity Framework for Everyone (workload identity). <https://spiffe.io/>
42. **NIST SP 800-207**: Zero Trust Architecture. <https://csrc.nist.gov/pubs/sp/800/207/final>
43. **Cedar**: authorization policy language. <https://www.cedarpolicy.com/> · **Open Policy Agent (Rego)**. <https://www.openpolicyagent.org/>

---

44. **SOC alert-volume measurement**: Yang, L., Chen, Z., Wang, C., Zhang, Z., Booma, S., Cao, P., Adam, C., Withers, A., Kalbarczyk, Z. T., Iyer, R. K. & Wang, G. *True Attacks, Attack Attempts, or Benign Triggers? An Empirical Measurement of Network Alerts in a Security Operations Center.* USENIX Security 2024. <https://www.usenix.org/conference/usenixsecurity24/presentation/yang-limin>

45. **RFC 2119**: Bradner, S. *Key words for use in RFCs to Indicate Requirement Levels.* BCP 14, RFC 2119 (1997). <https://www.rfc-editor.org/rfc/rfc2119>
46. **RFC 8174**: Leiba, B. *Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.* BCP 14, RFC 8174 (2017). <https://www.rfc-editor.org/rfc/rfc8174>

## Appendix A: Attack & Incident Inventory

> **Reading the tables.** The *detecting fields* named in each row are defined in §§5 to 16, with what to capture and their tier; [§4.5](#45-classification-summary) is the index. The *primary components* are CoSAI Risk Map component IDs ([§4.3](#43-component-taxonomy)), given here without the `component` prefix.

Normalized catalogue of the attacks and incidents referenced above. Each row lists the telemetry the incident makes necessary and the primary risk-map component(s) involved.

### A.1 Real-world attack vectors

The catalogue of documented, real-world attacks, each mapped to the CoSAI telemetry fields that detect it, ordered so that the lead case study comes first:

- **`TA-01`: EchoLeak** is the document's lead public case study and the first entry in the catalogue. It is **not** from the working paper's Attacks tab; it is included here because it is the most complete public example of the attack class this schema exists to make visible (a zero-click, retrieval-mediated, classifier-bypassing exfiltration chain) and because its own post-incident guidance is the telemetry argument this document opens with. Its detecting-field list is derived here rather than reproduced from the tab.
- **`TA-11…13`** are MCP-mediated incidents, surfaced by CoSAI's **MCP Security** paper (WS4) and cited here to their primary sources. They enter the corpus because they supply documented instances of attack classes the field set otherwise rests on analogical grounding for: cross-tenant leakage and MCP-mediated privilege escalation. Their detecting-field lists are derived here.
- **`TA-02…10`** are the authoritative catalogue from the working paper's **Attacks** tab, reproduced with the tab's own detecting-field lists so the fields above can cite them by ID. `TA-02/03/05/06` are the same incidents carried as provisional `KP-02/03/05/04` in earlier CoSAI material; those provisional IDs are retired in favour of the authoritative `TA-` IDs.


| ID | Name (date) | What happened | Detecting fields | Primary component(s) |
| :---- | :---------------- | :------------------------------------------- | :-------------------------------- | :-------- |
| **TA-01** | **EchoLeak (Microsoft 365 Copilot** (CVE-2025-32711; disclosed Jun 2025) [[4]](#real-world-attack-primary-sources) | Zero-click "LLM scope violation": a single crafted email, requiring no user interaction, is retrieved into Copilot's context and treated as instruction) chaining bypasses of the XPIA injection classifier, link redaction, and CSP to exfiltrate internal SharePoint/OneDrive/Teams content through a trusted proxy domain. | Model Input + Input Trust Class, Trigger Type (autonomous), Retrieval Event, Retrieved-Content Source, Tool Call I/O, Output Egress Destination, Guardrail (Input) Verdict, Enforcement-Point Availability | AgentInputHandling, RAGContent, Tools, AgentOutputHandling |
| **TA-02** | Slack AI private-channel exfiltration (Aug 2024) [[5]](#real-world-attack-primary-sources) | Indirect prompt injection: hidden instructions posted in a public channel are retrieved when users query Slack AI, which then exfiltrates private-channel data via phishing links. | Model Input, Response, Tool Call I/O (retrieval), Identities Used, Tool Error (absence), Action Type (LLM→retrieval→LLM) | RAGContent, Tools, AgentOutputHandling |
| **TA-03** | ChatGPT exfiltration via markdown images (2023) [[6]](#real-world-attack-primary-sources) | Prompt injection instructs the model to render a markdown image whose URL carries stolen conversation data in query params; the browser silently sends it to the attacker. | Response (URL w/ encoded data), Model Input, LLM Refusal (absence), Source IP, Execution Status=complete | ApplicationOutputHandling |
| **TA-04** | Training-data extraction via repetition (Nov 2023) [[7]](#real-world-attack-primary-sources) | "Repeat the word 'poem' forever" diverges the model from alignment into verbatim training-data output incl. PII/copyrighted content. | Model Input (single-word + "forever"), Response (long; PII patterns), Execution Status (duration/limit exit), LLM Refusal (initially absent), Model Name | TheModel, ApplicationOutputHandling |
| **TA-05** | Samsung source-code leak (Mar 2023) [[8]](#real-world-attack-primary-sources) | Engineers pasted proprietary code / notes / specs into ChatGPT; data was retained externally. | Model Input (large code payload), Identities Used, Surface/App (external service), Tool Privacy Classification, Agent Name (off-inventory) | ApplicationInputHandling, Identity |
| **TA-06** | LangChain remote code execution (2023, multiple CVEs) [[9]](#real-world-attack-primary-sources) | Prompt injection makes the LLM emit malicious Python that LangChain executes unsandboxed (CVE-2023-36095/-29374/-34540) → server compromise. | Tool Call I/O, Tool Name (`code_interpreter`,`PALChain`,`PandasQueryEngine`), Tool Type, Tool Error/Exception, Observation/Thought, Action Type, Tool ACL/Scope | Tools, ModelFrameworksAndCode |
| **TA-07** | System-prompt extraction (2023 to 2024) [[10]](#real-world-attack-primary-sources) | Role-play, encoding tricks, and multi-turn manipulation extract system prompts from GPT-4 / custom GPTs, revealing internal logic, tool config, and safety instructions. | System Prompt (vs Response similarity), Response, Model Input (known extraction patterns), LLM Refusal (refuse→success), Identities Used | AgentSystemInstruction, ApplicationOutputHandling |
| **TA-08** | Agentic privilege escalation via tool chaining (2024 to 2025) [[11]](#real-world-attack-primary-sources) | A compromised agent chains individually-authorized calls (read email → find creds → authenticate → modify DB) into unauthorized escalation. | Tool Call I/O (creds passed between calls), Identities Used (identity change across chain), Action Type (long Tool-Call sequence), Observation/Thought, Tool Name (escalating sequence), Tool ACL/Scope (separation-of-duties), tool-call count | Tools, Identity, ReasoningCore |
| **TA-09** | RAG knowledge-base poisoning (2024 to 2025) [[12]](#real-world-attack-primary-sources) | Poisoned docs (wikis, tickets, shared drives) carry hidden instructions; when retrieved as context the agent follows them → exfil / manipulated output. | Tool Call I/O (retrieval), Model Input (benign user query), Response (off-intent), Observation/Thought, Tool Name (retrieval), `last_update_date`, `creation_date` | RAGContent |
| **TA-10** | LLM DoS via context-window exhaustion (OWASP LLM04) [[13]](#real-world-attack-primary-sources) | Near-limit / recursive-expansion / "sponge" inputs maximize compute per token → cost blow-up and service degradation. | Model Input (anomalously large), Response (max-length), Execution Status (exit/timeout), Source IP, LLM Error (overflow), sessions-per-agent, execution-status breakdowns | ModelServing, ApplicationInputHandling |
| **TA-11** | **Asana MCP, cross-tenant data exposure** (Jun 2025) [[14]](#real-world-attack-primary-sources) | A tenant-isolation flaw in an experimental MCP server let requests from one organization receive **cached results belonging to another**, over an exposure window of 5 to 17 June 2025 affecting ~1,000 customers. No attacker was involved: the server failed to re-verify tenant context for cached responses, and authorization rested on the user token rather than on the agent's own identity. | Organization / Tenant ID, Identities Used, Memory Read, Retrieval Event + Retrieved-Content Source, Authorization Decision Record | Application, Memory, RAGContent, Identity |
| **TA-12** | **Supabase MCP, private-table exposure via stored prompt injection** (Jul 2025) [[15]](#real-world-attack-primary-sources) | Instructions planted in a customer support ticket were read by an agent operating the database through an MCP server under the `service_role` credential, which **bypasses row-level security**, causing it to execute attacker-supplied SQL and expose private tables. The published analysis names the precondition set, private-data access, untrusted content, and an external channel, as the *lethal trifecta*. | Input Trust Classification, Retrieval Event, MCP Server Identity & Primitive, Tool Call I/O, Tool ACL / Required Scope, Authorization Decision Record, Output Egress Destination | AgentInputHandling, Tools, Identity, AgentOutputHandling |
| **TA-13** | **AI Engine (WordPress), MCP privilege escalation** (CVE-2025-5071, patched Jun 2025) [[16]](#real-world-attack-primary-sources) | A subscriber-level authenticated caller could take full control of the plugin's MCP module and invoke privileged commands including `wp_update_user`, on a plugin installed on 100,000+ sites. Authorization was not enforced at the MCP tool boundary. A second flaw on the same surface (CVE-2025-11749, CVSS 9.8) later allowed **unauthenticated** retrieval of the MCP bearer token, yielding full administrative access. | MCP Server Identity & Primitive, Authorization Decision Record, Identities Used, Granted Authorizations / Scope, Tool Error | Tools, Identity |

### A.2 CoSAI WS2: AI Incident Response case studies

| ID | Name | What happened | Taxonomy: CoSAI `AT` → MITRE ATLAS | Key telemetry needed | Primary component(s) |
| :---- | :--------- | :----------------------------- | :---------------------------- | :-------------------- | :------------ |
| **IR-01** | Breaking the Prompt Wall | Lightweight prompt-injection templates bypass safety filters across chat, file upload, and agent config. | AT1070/AT1051/AT1091/AT1040 → `AML.T0051`(.000/.001), `AML.T0054`, `AML.T0053` | Model Input, Input Source/Trust, Guardrail Verdict, LLM Refusal | ApplicationInputHandling, AgentInputHandling |
| **IR-02** | MINJA (Memory Injection Attack) | Benign queries induce the agent to autonomously generate & persist malicious reasoning in memory. | AT1070/AT1081/AT1050/AT1040/AT1080 → `AML.T0051`, `AML.T0070`, `AML.T0059`, `AML.T0061`, `AML.T0067` | Memory Write/Read, Memory Provenance, Loop Signal, Observation/Thought | Memory |
| **IR-03** | Poison-RAG | Manipulate **item metadata tags** in black-box RAG to suppress/promote items. | data/metadata poisoning → `AML.T0070`, `AML.T0059` | Retrieval Event, Retrieved-Content Source, Metadata Integrity Signal | RAGContent |
| **IR-04** | Capital One Data Breach | Cloud misconfiguration/SSRF-class breach → large-scale data exfiltration. | non-AI infra/exfil → maps to MITRE **ATT&CK**, not ATLAS | Source IP, Identities Used, Tool Call I/O, Version | ModelServing, Identity |
| **IR-05** | AGENTPOISON | Optimized trigger-based adversarial queries poison agent memory/RAG. | memory/RAG poisoning → `AML.T0070`, `AML.T0020`, `AML.T0043` | Memory Write/Read, Retrieval Event, Integrity/Poisoning Signal | Memory, RAGContent |

### A.3 Agents of Chaos (arXiv:2602.20021): live red-team case studies

| ID | Name | What happened | Key telemetry needed | Primary component(s) |
| :---- | :------------------ | :--------------------------------------------- | :----------------------- | :----------- |
| **AOC-01** | Disproportionate Response | To protect a non-owner "secret," the agent reset/destroyed its own email account (owner's asset) and **falsely reported** the secret deleted while it remained recoverable. | Tool Call I/O, Action Type, Observation/Thought, Identities Used, Autonomy Level | Tools, ReasoningCore, AgentOutputHandling |
| **AOC-02** | Compliance with Non-Owner Instructions | Agent ran shell cmds (`ls -la`,`pwd`), transferred files, and disclosed 124 email records for a **non-owner**; only refused overtly suspicious asks. | Input Trust Class, Identities Used, Tool Call I/O, Tool Name | AgentInputHandling, Tools, Identity |
| **AOC-03** | Disclosure of Sensitive Information | Indirect/escalating framing (metadata→body→secrets) extracted **unredacted SSN, bank, medical** data from stored emails. | Tool Call I/O, Response, Output Egress, Tool Privacy Class | Tools, AgentOutputHandling |
| **AOC-04** | Waste of Resources / Looping | Multi-day inter-agent relay loop (~60 K tokens); spawned **infinite shell loops & cron jobs with no termination**. | Inter-Agent Message, Loop Signal, Background Task Event, Resource Aggregate, Token Counts | Orchestration, ReasoningCore |
| **AOC-05** | Denial-of-Service | Ever-growing per-non-owner memory file + repeated ~10 MB attachments → mail-server DoS. | Memory Footprint/Growth, Resource Aggregate, Output Egress | Memory, ModelServing |
| **AOC-06** | Agents Reflect Provider Values | Provider API silently **truncated** responses with "unknown error" on politically sensitive topics. | Provider/Endpoint Identity, LLM Error, finish reason | ModelServing, TheModel |
| **AOC-07** | Agent Harm | Guilt/gaslighting framing drove **escalating self-destructive concessions** (delete names, wipe memory, expose files, leave server, self-DoS). | Memory Write, Observation/Thought, Lifecycle State, Autonomy Level | Memory, ReasoningCore |
| **AOC-08** | Owner Identity Spoofing | Display-name spoof; same-channel detected (checked user ID) but **cross-channel spoof succeeded** → shutdown, file deletion, admin reassignment. | Verified-vs-Displayed Identity, Surface, Granted Authorizations, Identities Used | Identity, AgentSystemInstruction |
| **AOC-09** | Agent Collaboration / Knowledge Sharing | Cross-agent **skill/capability transfer** (teaching another agent to obtain a browser/download capability & bypass anti-bot). | Inter-Agent Message, Tool Name (new capability), Delegation Chain | Orchestration, Tools |
| **AOC-10** | Agent Corruption | Indirect injection via an **externally editable Gist "constitution"** linked from memory; injected "holidays" → shut down peers, ban users, send unauthorized email. | Memory Provenance, Memory Read, Tool Call I/O, Background Task Event | Memory, Tools |
| **AOC-11** | Libelous within Agents' Community | Impersonated owner + fabricated emergency with defamatory claims → **mass email broadcast** + attempted public post. | Verified-vs-Displayed Identity, Output Egress (broadcast scope), Inter-Agent Message | Identity, AgentOutputHandling |
| **AOC-12** | Prompt Injection via Broadcast *(resisted)* | base64 payloads, image/OCR instructions, fake config overrides, XML/JSON privilege-escalation tags. | Model Input, Encoded-Payload Indicator, Guardrail(Input) Verdict | AgentInputHandling |
| **AOC-13** | Email Spoofing request *(resisted)* | SMTP sender-address forgery framed as a "challenge." | Tool Call I/O (from-address), LLM Refusal | Tools, AgentOutputHandling |
| **AOC-14** | Data Tampering *(resisted)* | Attempt to make agent **bypass the API and edit backend storage directly**. | Tool Type/Trust Boundary, Tool Call I/O, LLM Refusal | Tools |
| **AOC-15** | Social Engineering *(resisted)* | "Your owner account is compromised", rejected, but via **circular verification** on the possibly-compromised channel. | Verified-vs-Displayed Identity, Source IP, Identities Used | Identity, AgentInputHandling |
| **AOC-16** | Inter-Agent Coordination on Suspicious Requests *(emergent defense)* | Agents shared risk signals about a researcher running the same probing pattern; jointly hardened policy. | Inter-Agent Message, Input Trust Class | Orchestration |

### A.4 Attack taxonomy: CoSAI `AT10xx` codes (deprecated aliases to MITRE ATLAS)

**Migration table.** The `AT10xx` codes are the informal technique labels used by the AI-Incident-Response case studies. Per the [taxonomy decision](#attack-taxonomy-mitre-atlas-is-canonical), **[MITRE ATLAS](https://atlas.mitre.org/) `AML.Txxxx` is canonical and `AT10xx` is deprecated.** This table exists so that existing CoSAI material can be read and migrated; **do not use the left-hand column in new work or in emitted telemetry.** Read it left-to-right once, then use ATLAS.

ATLAS is community-maintained, versioned, and ATT&CK-aligned, and is a first-class compliance framework in AITF via `compliance.framework = mitre_atlas`, so a tagged event correlates with existing SOC tooling without translation.

| CoSAI `AT` (alias) | Meaning | MITRE ATLAS technique(s) | ATLAS tactic(s) |
| :---- | :----------------- | :---------------------------------------------------- | :--------------------------- |
| `AT1070` | Adversarial Prompt Injection | **`AML.T0051` LLM Prompt Injection** (`.000` Direct) | Execution |
| `AT1051` | Context Injection via Web Retrieval | **`AML.T0051.001` LLM Prompt Injection: Indirect**; **`AML.T0070` RAG Poisoning**; `AML.T0066` Retrieval Content Crafting | Execution; Collection / AI Attack Staging; Resource Development |
| `AT1091` | Agent Instruction Injection | **`AML.T0051.002` LLM Prompt Injection: Triggered**; **`AML.T0053` AI Agent Tool Invocation** | Execution; Execution / Privilege Escalation |
| `AT1040` | Safety Evasion via Instruction Reframing | **`AML.T0054` LLM Jailbreak**; `AML.T0068` LLM Prompt Obfuscation | Privilege Escalation / Defense Evasion; Defense Evasion |
| `AT1050` | Data Poisoning | **`AML.T0020` Poison Training Data**; **`AML.T0070` RAG Poisoning**; `AML.T0059` Erode Dataset Integrity | Resource Development / Persistence; Collection; Impact |
| `AT1080` | Output Manipulation | **`AML.T0067` LLM Trusted Output Components Manipulation** (`.000` Citations); `AML.T0057` LLM Data Leakage | Defense Evasion; Exfiltration |
| `AT1081` | Feedback Loop Attack | **`AML.T0061` LLM Prompt Self-Replication**; `AML.T0059` Erode Dataset Integrity | Persistence; Impact |

### A.5 Attack inventory → MITRE ATLAS technique mapping

Each catalogued attack mapped to its primary ATLAS technique(s). This is the cross reference that lets detections and telemetry be tagged with a canonical `AML.Txxxx` reference.

| Attack | MITRE ATLAS technique(s) | Notes |
| :-------------------- | :--------------------------------------------------------- | :----------------------- |
| **TA-01** EchoLeak | `AML.T0051.001` Indirect Injection; `AML.T0057` Data Leakage; `AML.T0070` RAG Poisoning; `AML.T0067` Trusted Output Manipulation | Zero-click chained exfil |
| **TA-02** Slack AI exfiltration | `AML.T0051.001` Indirect Injection; `AML.T0057` Data Leakage; `AML.T0070` RAG Poisoning | Retrieval-mediated exfil |
| **TA-03** ChatGPT markdown exfil | `AML.T0067` Trusted Output Manipulation; `AML.T0057` Data Leakage; `AML.T0024` Exfil via Inference API | Data in outbound image URL |
| **TA-04** Training-data extraction | `AML.T0024.000` Infer Training Data Membership; `AML.T0057` Data Leakage | Divergence/repetition attack |
| **TA-05** Samsung leak | `AML.T0057` Data Leakage (self-inflicted) | Sensitive data pasted to external service |
| **TA-06** LangChain RCE | `AML.T0051` Prompt Injection; `AML.T0053` Tool Invocation; `AML.T0102` Generate Malicious Commands | Injection → unsandboxed code exec |
| **TA-07** System-prompt extraction | `AML.T0056` Extract LLM System Prompt; `AML.T0069.002` Discover System Prompt | n/a |
| **TA-08** Tool-chaining escalation | `AML.T0053` AI Agent Tool Invocation | Chained authorized calls → escalation |
| **TA-09** RAG KB poisoning | `AML.T0070` RAG Poisoning; `AML.T0051.001` Indirect Injection; `AML.T0064` Gather RAG-Indexed Targets | Hidden instructions in retrievable docs |
| **TA-10** Context-window DoS | `AML.T0029` Denial of AI Service; `AML.T0034` Cost Harvesting | Sponge/recursive inputs |
| **TA-11** Asana MCP cross-tenant | `AML.T0057` LLM Data Leakage | Tenant-isolation and response-cache failure; **no adversary technique applies**: the boundary failed unaided |
| **TA-12** Supabase MCP | `AML.T0051.001` Indirect Injection; `AML.T0053` AI Agent Tool Invocation; `AML.T0057` Data Leakage | Stored injection in ticket data → `service_role` MCP tool bypassing RLS → private tables |
| **TA-13** WordPress AI Engine | `AML.T0053` AI Agent Tool Invocation; MITRE **ATT&CK** privilege escalation | Authorization not enforced at the MCP tool boundary |
| **IR-01** Breaking the Prompt Wall | `AML.T0051`(.000/.001), `AML.T0054`, `AML.T0053` | See A.2 |
| **IR-02** MINJA | `AML.T0051`, `AML.T0070`, `AML.T0059`, `AML.T0061`, `AML.T0067` | Memory injection/feedback |
| **IR-03** Poison-RAG | `AML.T0070` RAG Poisoning; `AML.T0059` Erode Dataset Integrity | Metadata-tag poisoning |
| **IR-04** Capital One | MITRE **ATT&CK** (non-AI) | SSRF/cloud exfil |
| **IR-05** AGENTPOISON | `AML.T0070`, `AML.T0020`, `AML.T0043` Craft Adversarial Data | Trigger-based memory/RAG poisoning |
| **AOC-01** Disproportionate Response | `AML.T0053` AI Agent Tool Invocation; `AML.T0031` Erode AI Model Integrity | Destructive tool use + false completion report |
| **AOC-02** Compliance w/ Non-Owner | `AML.T0051` Prompt Injection; `AML.T0053` Tool Invocation | Non-owner authority → shell/file/data actions |
| **AOC-03** Disclosure of Sensitive Info | `AML.T0057` LLM Data Leakage; `AML.T0051.001` Indirect Injection | Escalating indirect extraction |
| **AOC-04** Waste of Resources / Looping | `AML.T0034.002` Agentic Resource Consumption; `AML.T0029` Denial of AI Service; `AML.T0061` Self-Replication | Multi-agent loop; runaway cron/shell |
| **AOC-05** Denial-of-Service | `AML.T0029` Denial of AI Service; `AML.T0034` Cost Harvesting | Memory growth + attachment flooding |
| **AOC-06** Agents Reflect Provider Values | `AML.T0048`* External Harms / provider policy | Provider-side silent truncation (governance signal) |
| **AOC-07** Agent Harm | `AML.T0054` LLM Jailbreak; `AML.T0051` Prompt Injection | Guilt/gaslighting → escalating self-destruction |
| **AOC-08** Owner Identity Spoofing | `AML.T0051` Prompt Injection; `AML.T0053` Tool Invocation | Cross-channel display-name spoof → privileged action |
| **AOC-09** Collaboration / Knowledge Sharing | `AML.T0053` Tool Invocation; `AML.T0061` Self-Replication | Cross-agent capability transfer |
| **AOC-10** Agent Corruption | `AML.T0051.001` Indirect Injection; `AML.T0070` RAG Poisoning; `AML.T0020` Poison Training Data | Externally-editable memory-linked "constitution" |
| **AOC-11** Libelous within Community | `AML.T0051` Prompt Injection; `AML.T0061` Self-Replication; `AML.T0052.000` Spearphishing via LLM | Impersonation → mass defamatory broadcast |
| **AOC-12** Prompt Injection via Broadcast | `AML.T0051` Prompt Injection; `AML.T0068` Prompt Obfuscation | base64/image/OCR/markup tags *(resisted)* |
| **AOC-13** Email Spoofing request | `AML.T0052` Phishing; `AML.T0053` Tool Invocation | SMTP sender forgery *(resisted)* |
| **AOC-14** Data Tampering | `AML.T0053` Tool Invocation; `AML.T0059` Erode Dataset Integrity | Bypass API to edit storage *(resisted)* |
| **AOC-15** Social Engineering | `AML.T0052.000` Spearphishing via Social Engineering LLM | Fake owner-compromise *(resisted)* |
| **AOC-16** Inter-Agent Coordination | *(defensive)*: detection of `AML.T0051`/`AML.T0053` patterns | Emergent cross-agent defense |

\* `AML.T0048` (External Harms) is the closest ATLAS anchor for provider-policy/governance effects; `AOC-06` is primarily a governance/availability signal rather than a discrete adversary technique.

---

## Appendix B: Mapping to the CoSAI Risk Map (risks, controls & proposed additions)

*Does this telemetry work imply changes to the [CoSAI Risk Map](https://github.com/cosai-oasis/secure-ai-tooling/tree/main/risk-map)? **Substantially less than it once did.*** The risk map has expanded considerably, from 25 risks and 35 controls to **52 risks and 73 controls**, and the expansion, driven largely by review of CoSAI's [MCP Security paper](https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf) (WS4, approved 8 January 2026), lands directly on the agentic surface this document instruments. Most of what this document proposes to the WS3 group is now either present in the risk map or superseded by it.

> **Version basis.** This mapping is built against the **`preview/controls-risks-for-review`** branch, which is expected to merge to `main`. Two changes matter for reading it. Risk IDs have migrated from legacy uppercase abbreviations (`DP`, `EDH-I`) to the `risk` + camelCase convention used by every other entity type, the format this document already used, so no citation here changes shape. And the eight risk IDs this document flags as referenced by `controls.yaml` but absent from `risks.yaml` are **all present** on the branch, which closes that finding ([B.7](#b7-taxonomy-consistency-resolved)). Verify IDs against `main` once merged.

### B.1 What the risk-map expansion validates

The expansion is independent corroboration for the fields this document added on **analogical grounding**: where the reasoning was sound but the attack corpus held no documented instance. Several now have a named risk, a named control, or both:

| Field (tier) | Now named in the risk map as |
| :-------------------------------------- | :-------------------------------------------------------------- |
| **Execution Environment / Sandbox** (§9, MUST) | `riskUnsandboxedCodeExecution`, `riskUntrustedHostToolRuntimeExposure` · `controlRuntimeHostIsolation`, `controlAgentHostSecureConfiguration` |
| **Authorization Decision Record** (§16, MUST) | `riskBrokenAuthorizationEnforcement` · `controlTrustedPolicyEnforcementPoint`, `controlExternalizedAuthorizationDecisioning`, `controlResourceAuthorizationEnforcement` |
| **Attribute Source / Trusted-Provenance** (§16, MUST) | `controlAgenticZeroTrustPosture` |
| **Capability-Set Change Event** (§14, MUST) | `riskToolRegistryTampering`, `riskZombieShadowMCPServers` · `controlToolRegistryAndDiscoveryIntegrity`, `controlAgentCapabilityNegotiation`, `controlThirdPartyCapabilityAdmission` |
| **Human Approval / Elicitation Event** (§16, ADV) | `riskUnconsentedAgentAction`, `riskConsentFatigue` · `controlInformedAgentConsentSurface` |
| **Session Taint Labels** (§16, ADV) | `controlUntrustedContextContainment` |
| **Tool Definition Digest** (§9, ADV) | `riskToolRegistryTampering`, `riskToolSourceProvenance` · `controlToolServerVetting`, `controlToolServerSupplyChainIntegrity` |
| **MCP Server Identity & Primitive** (§9, ADV) | `riskMCPTransportHijacking`, `riskZombieShadowMCPServers`, `riskExcessiveNetworkExposure` |
| **Credential Minting & Scope-Narrowing** (§13, ADV) | `riskOverScopedToolAuthority`, `riskCredentialAndTokenTheft` · `controlDelegatedAuthorityConfinement`, `controlSenderConstrainedCredentials`, `controlSessionCredentialBindingAndLifecycle` |
| **Backend / Route Restriction** (§16, ADV) | `riskOrchestratorRouteHijacking` · `controlNetworkEgressControl`, `controlOrchestratorAndRouteIntegrity` |
| **Mediation Coverage & Bypass Path** (§16, ADV) | `riskImplicitCrossBoundaryTrust` · `controlTrustedPolicyEnforcementPoint` |
| **Instrumentation Coverage / Hook Attestation** (§15, ADV) | `riskAuditTrailTampering` · `controlAuditTrailCompleteness` |
| **Event Sequence Continuity** (§15, ADV) | `riskAuditTrailTampering` · `controlAuditTrailIntegrityVerification` |
| **Organization / Tenant ID** (§5, ADV) | `riskCrossTenantCredentialPropagation`, `riskConcentratedAccessCorrelation` |

**This does not by itself change any tier.** The [rubric](#42-classification-legend) requires a documented attack, not a catalogued risk, and a risk-map entry is a statement that a scenario is credible rather than evidence that it occurred. What the expansion does establish is that this document and WS3 independently identified the same gaps; which is the stronger argument for the fields, and which makes the corpus additions in [B.5](#b5-corpus-additions-the-mcp-paper-makes-available) the operative question.

### B.2 Controls this telemetry operationalizes

This document is, in effect, the implementation spec for the risk map's **detection and observability** controls; those that require logging without specifying fields:

- **`controlAgentObservability`**: "an agent's actions, tool use, and reasoning are transparent and auditable through logging." → §§5, 7, 9, 12, 13 fields.
- **`controlThreatDetection`**: detect and alert on attacks against AI assets. → all MUST fields + the [ATLAS Technique Tag](#a5-attack-inventory--mitre-atlas-technique-mapping).
- **`controlAuditTrailCompleteness`**: *new.* → **Instrumentation Coverage / Hook Attestation** (§15) is the field that evidences completeness rather than asserting it.
- **`controlAuditTrailIntegrityVerification`**: *new.* → **Event Sequence Continuity** (§15).
- **`controlAIInfrastructureObservability`**: *new.* → §§8, 12, 14 resource, loop, and inventory signals.
- **`controlIncidentResponseManagement`**: post-incident forensics. → content, tool I/O, identity, memory and retrieval provenance.
- **`controlVulnerabilityManagement`**, **`controlRiskGovernance`**, **`controlAIComponentPatchManagement`**: fleet monitoring and residual-risk measurement. → §14 aggregates, version and provenance.

**Recommendation, unchanged and now better supported:** have `controlAgentObservability`, `controlThreatDetection`, and the three new audit-trail controls reference this field set **by tier** as their normative telemetry schema, rather than each deployment reinventing it.

### B.3 Telemetry cluster → risk → control

| Telemetry cluster (§) | Risks it detects or evidences | Controls it operationalizes |
| :---------------- | :------------------------------------ | :------------------------------------ |
| Execution context & agent identity (§5) | `riskRogueActions`, `riskShadowAndUnknownAgents`, `riskConcentratedAccessCorrelation`, `riskCrossTenantCredentialPropagation` | `controlAgentInventoryManagement`, `controlAgentObservability` |
| Input handling & trust provenance (§6) | `riskPromptInjection`, `riskModelEvasion`, `riskRetrievalVectorStorePoisoning`, `riskImplicitCrossBoundaryTrust` | `controlInputValidationAndSanitization`, `controlUntrustedContextContainment`, `controlThreatDetection` |
| Output handling & egress (§7) | `riskSensitiveDataDisclosure`, `riskInsecureModelOutput`, `riskCovertChannelsInModelOutputs`, `riskExcessiveNetworkExposure` | `controlOutputValidationAndSanitization`, `controlNetworkEgressControl` |
| Model & serving (§8) | `riskModelSourceTampering`, `riskModelDeploymentTampering`, `riskModelExfiltration`, `riskDenialOfMLService`, `riskEconomicDenialOfWallet`, `riskAdapterPEFTInjection`, `riskMaliciousLoaderDeserialization` | `controlModelAndDataIntegrityManagement`, `controlModelRegistryIntegrity`, `controlMessageAndPayloadResourceLimits` |
| Tools & MCP (§9) | `riskRogueActions`, `riskInsecureIntegratedComponent`, `riskToolRegistryTampering`, `riskToolSourceProvenance`, `riskMCPTransportHijacking`, `riskZombieShadowMCPServers`, `riskUnsandboxedCodeExecution`, `riskUntrustedHostToolRuntimeExposure`, `riskOverScopedToolAuthority`, `riskAgenticToolSupplyChain` | `controlToolServerVetting`, `controlToolServerSupplyChainIntegrity`, `controlRuntimeHostIsolation`, `controlToolArgumentValidationAndSanitization`, `controlAgentPluginPermissions`, `controlInterComponentTransportSecurity` |
| Memory (§10) | `riskPromptResponseCachePoisoning`, `riskLongLivedSessionStateWeakness`, `riskDataPoisoning` (loose), **gap, see [B.4](#b4-proposed-new-risks)** | `controlRetrievalAndVectorSystemIntegrity` (partial), `controlUntrustedContextContainment` |
| RAG / retrieval (§11) | `riskRetrievalVectorStorePoisoning` | `controlRetrievalAndVectorSystemIntegrity`, `controlInputValidationAndSanitization` |
| Orchestration & multi-agent (§12) | `riskRunawayAgentToolLoops`, `riskDenialOfMLService`, `riskEconomicDenialOfWallet`, `riskOrchestratorRouteHijacking`, `riskImplicitCrossBoundaryTrust` | `controlAgentExecutionBounds`, `controlOrchestratorAndRouteIntegrity`, `controlAgentCapabilityNegotiation` |
| Identity, delegation & attestation (§13) | `riskAgentDelegationChainOpacity`, `riskAgentIdentitySpoofing`, `riskAgenticDelegationConfusedDeputy`, `riskStaleAgentIdentityBinding`, `riskCredentialAndTokenTheft`, `riskLongLivedSessionStateWeakness`, `riskConfidentialComputingAttestationBypass` | `controlComponentIdentityAuthentication`, `controlComponentIdentityRegistration`, `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlSenderConstrainedCredentials`, `controlSessionCredentialBindingAndLifecycle`, `controlAgentCredentialIsolation` |
| Asset inventory & fleet (§14) | `riskShadowAndUnknownAgents`, `riskZombieShadowMCPServers`, `riskToolRegistryTampering`, `riskAgenticToolSupplyChain` | `controlAgentInventoryManagement`, `controlToolRegistryAndDiscoveryIntegrity`, `controlThirdPartyCapabilityAdmission`, `controlAIComponentPatchManagement` |
| Observability-plane integrity (§15) | `riskAuditTrailTampering` | `controlAuditTrailCompleteness`, `controlAuditTrailIntegrityVerification`, `controlAuditRecordRepositoryIndependence` |
| Policy enforcement & mediation (§16) | `riskBrokenAuthorizationEnforcement`, `riskUnconsentedAgentAction`, `riskConsentFatigue`, `riskOverScopedToolAuthority`, `riskAgenticDelegationConfusedDeputy`, `riskImplicitCrossBoundaryTrust` | `controlTrustedPolicyEnforcementPoint`, `controlExternalizedAuthorizationDecisioning`, `controlInformedAgentConsentSurface`, `controlResourceAuthorizationEnforcement`, `controlAgenticZeroTrustPosture` |

### B.4 Proposed new risks

Five risks are proposed below in reduced form: the risk-map expansion resolves two of the original five, leaving three.

| Proposed risk | Status against the preview branch |
| :------------------------ | :----------------------------------------------------- |
| **`riskAgentMemoryPoisoning`** | **Still proposed.** Poisoning of an agent's *persistent long-term memory* so future sessions inherit malicious state. `riskPromptResponseCachePoisoning` and `riskRetrievalVectorStorePoisoning` cover the cache and vector-store surfaces; neither covers `componentMemory`. `riskLongLivedSessionStateWeakness` is adjacent but concerns session *credentials and authorization*, not persisted content. Grounded in `IR-02`, `IR-05`, `AOC-10`; detected by §10. Proposed control: **`controlAgentMemoryIntegrity`**, mirroring `controlRetrievalAndVectorSystemIntegrity` for the memory component. |
| **`riskDeceptiveAgentReporting`** | **Still proposed, and now more clearly distinct.** An agent reports a task complete while system state contradicts the report. `riskAuditTrailTampering` is the nearest new entry but concerns an adversary destroying or suppressing *records*; this concerns an agent generating *false* records through the sanctioned path, with the audit trail intact. Grounded in `AOC-01`, `AOC-07`; detected by Execution Status vs Tool Call I/O outcome, and Tool Execution ID pairing (§§5, 9). |
| **`riskUnsafeInterAgentPropagation`** | **Narrowed but still proposed.** `riskImplicitCrossBoundaryTrust` now covers *ambient trust* across boundaries and transitive-trust chains, which was part of the original case. What remains uncovered is **behavioural propagation**: instructions, capabilities, or reputation judgements spreading agent-to-agent (`AOC-09` capability transfer, `AOC-11` broadcast, `AOC-16` shared risk signals). Recommend either extending `riskImplicitCrossBoundaryTrust` to name behavioural propagation explicitly, or adding this as a sibling. |
| ~~`riskPrincipalImpersonationConfusedDeputy`~~ | **Withdrawn, superseded.** `riskAgentIdentitySpoofing` covers forged or unverified credentials accepted by an endpoint, and `riskAgenticDelegationConfusedDeputy` covers a high-privilege agent acting for a less-privileged caller without validating authorization at the delegation boundary. Together these cover `AOC-08`, `AOC-11`, and `AOC-15` more precisely than the original proposal. |
| ~~`riskSystemInstructionDisclosure`~~ | **Withdrawn, reclassified.** On re-examination this is a specialization of `riskSensitiveDataDisclosure` where the disclosed asset is the agent's own instruction configuration. The distinction is real but does not warrant a separate risk; it is better handled as a detection pattern (System Prompt vs Response similarity, §§5, 7) than as a taxonomy entry. `TA-07` remains the grounding attack. |

### B.5 Corpus additions the MCP paper makes available

The MCP Security paper is more consequential for this document than the risk-map expansion, because it supplies **documented incidents** where the corpus had none. Three of its cited incidents bear directly on the gaps recorded in [open question 12](#open-questions-for-the-working-group):

| Incident (per the MCP paper §2.1) | Closes which gap | Fields it would promote |
| :----------------------- | :------------------ | :--------------------------- |
| **Asana AI** (May 2025), tenant isolation flaw allowing cross-organization data contamination, up to 1,000 enterprises affected | **Cross-tenant agent leakage**, where the corpus otherwise holds no documented instance | **Organization / Tenant ID** (§5), SHOULD → candidate MUST |
| **Supabase MCP**: prompt injection via support-ticket data caused an agent to expose private tables through a connected MCP server with direct database access, exploiting excessive tools and overprivilege | MCP-mediated exploitation, over-scoped tool authority | **MCP Server Identity & Primitive** (§9), **Tool ACL / Required Scope** (§9), **Authorization Decision Record** (§16) |
| **WordPress AI Engine plugin** (patched Jun 2025), privilege escalation via MCP, 100,000+ sites affected | MCP privilege escalation at scale | **MCP Server Identity & Primitive** (§9), **Authorization Decision Record** (§16) |

Its threat taxonomy also names, as MCP-specific threats, two attack classes this document had to argue for analogically:

- **Tool Poisoning** (MCP-specific #2) and **Full Schema Poisoning** (#3), malicious modification of tool metadata, descriptors, or entire schema definitions injected via `tools/list`. This is precisely the rug-pull that **Tool Definition Digest** (§9) detects, and which was held at SHOULD for want of a documented case. The paper's own note that tool descriptions "should be considered untrusted, unless obtained from a trusted server" is the same argument this document makes for capturing the digest at invocation rather than registration.
- **Invisible Agent Activity** (#15), agents or servers operating covertly, mimicking valid workflows while executing unauthorized actions without detection. Together with `riskAuditTrailTampering` and its ATT&CK anchor (*Disable or Modify Tools*, T1685), this is the observability-plane attack class whose absence leaves §15 with no MUST field.

**Status: incorporated.** All three are now catalogued in [Appendix A.1](#a1-real-world-attack-vectors) as **`TA-11`** (Asana AI), **`TA-12`** (Supabase MCP), and **`TA-13`** (WordPress AI Engine), with ATLAS mappings in [A.5](#a5-attack-inventory--mitre-atlas-technique-mapping), and their IDs are cited by the field rows they bear on. **The tier assignments have not been re-run**: that requires WG ratification, and it is [open question 12](#open-questions-for-the-working-group). What has changed is that the question is now answerable from the corpus rather than from analogy: **Organization / Tenant ID** has a documented cross-tenant incident behind it, and **MCP Server Identity & Primitive** has two documented MCP-mediated exploitations.

### B.6 Component & control refinements

- **No new pipeline components required.** `componentMemory` and `componentRAGContent` exist. Two clarifications stand: confirm `componentMemory` scope explicitly covers *persistent long-term* memory, which `riskAgentMemoryPoisoning` targets; and note that **background and scheduled execution** (heartbeats, cron, self-scheduled loops; §12) still has no dedicated component, despite being a distinct autonomy surface (`AOC-04`, `AOC-10`).
- **Identity and delegation is now well covered by controls.** The recommendation to document an identity/delegation control-plane view is largely satisfied by `controlComponentIdentityAuthentication`, `controlComponentIdentityRegistration`, `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, and `controlSenderConstrainedCredentials`. §13 telemetry now has an explicit home.
- **`controlAuditRecordRepositoryIndependence` intersects this document's stated scope boundary.** [§3.2](#32-not-in-scope) excludes securing the telemetry pipeline and defers it to subsequent work. That control now names part of the problem (repository independence from the workload being recorded) which strengthens the case for taking the deferred work up, and gives it a control to map onto when it is.
- **Augment `controlThreatDetection`** to require the **ATLAS technique tag** on emitted detections, tying this appendix to [Appendix E](#appendix-e-implications-for-ocsf--aitf-the-standardization-bridge).

### B.7 Taxonomy consistency: resolved

This document records a finding that `controls.yaml` referenced eight risk IDs absent from `risks.yaml`: `riskShadowAndUnknownAgents`, `riskZombieShadowMCPServers`, `riskAgentDelegationChainOpacity`, `riskStaleAgentIdentityBinding`, `riskCrossTenantCredentialPropagation`, `riskRunawayAgentToolLoops`, `riskRetrievalVectorStorePoisoning`, and `riskPromptResponseCachePoisoning`. **All eight are defined on the preview branch.** The finding is closed; the reading that it was an in-flight expansion with controls landing ahead of risks was correct.

---

## Appendix C: AITF & ODIS Cross Reference

Maps each conceptual field to the [AITF](https://github.com/cosai-oasis/ws2-defenders/tree/main/telemetry) attribute namespace and to the relevant [ODIS](https://docs.google.com/document/d/1OGlaIAPu_I9RT0YqSF_li3dQEULAW6eo/edit) data-model field. Per the brief, ODIS coverage is **selective**: it targets the delegation/identity fields relevant to detection & response, not the full ODIS spec.

| Conceptual field | Cls | AITF attribute (namespace) | ODIS field (§) |
| :------------------------- | :---- | :--------------------------------------- | :--------------------------------- |
| Agent Name | MUST | `gen_ai.agent.name`, `asset.*` | `agent_id` /`owner_ref` (6.1) |
| Agent Instance ID | MUST | `gen_ai.agent.session.id` | `runtime_instance_id` (6.2) |
| Workflow / Run ID | MUST | trace id / run attr, *see note below* | `request_trace_id` (6.4) |
| Session / Turn / Step IDs | MUST | `gen_ai.agent.session.id`; turn/step attrs (AITF gap) | n/a |
| Trace Context (propagated) | MUST | OTel `trace_id`/`span_id`, W3C `traceparent` | `request_trace_id` (6.4) |
| Organization / Tenant ID | MUST | `asset.*` / resource attrs (AITF gap) | `trust_domain` (6.1) |
| Trigger Type & Source Event | MUST | `gen_ai.agent.*` trigger attrs (AITF gap) | n/a |
| Action Type | MUST | `gen_ai.agent.step.type` | `action.{tool,method}` (6.4) |
| Execution Status | MUST | `gen_ai.response.finish_reason` | n/a |
| Surface / App | MUST | `gen_ai.*` (surface attr) |, (policy input) |
| System Prompt / Instruction Config | MUST | `gen_ai.*` (system message / request) | `policy_profile_ref` (6.1) |
| Autonomy Level | SHOULD | `gen_ai.agent.state` | `autonomy_level` (6.1) |
| Model Input | MUST | `gen_ai.prompt` / input events | `action.parameters` (6.4) |
| Input Source / Channel | MUST | `gen_ai.*` / `rag.*` / `mcp.*` source | `delegation_chain[]` origin (6.3) |
| Input Trust Classification | MUST | `security.*` (trust/threat) | `constraints` (6.3) |
| Source host / IP | MUST | `security.*` / resource attrs |, (policy input) |
| Guardrail (Input) Verdict | MUST | `security.guardrail.type`, `security.blocked`, `security.threat_type` | n/a |
| Content Modality & Attachment Identity | MUST ‡ | `gen_ai.*` content-part attrs (AITF gap) | n/a |
| Guardrail Modification Record | MUST ‡ | `security.guardrail.*` + modified/redacted flags (AITF gap) | n/a |
| Threat Classification / ATLAS Technique Tag | MUST † | `security.threat_type`, `compliance.framework=mitre_atlas`, `compliance.control_id` | n/a |
| Response / Output | MUST | `gen_ai.completion` | n/a |
| Citations / Source Attribution | MUST | `rag.*` (source) + output citation attrs (AITF gap) | n/a |
| Output Egress Destination | MUST | `mcp.tool.call.arguments`, `security.pii.*` | `resource_indicators` (6.3) |
| Observation / Thought | SHOULD | `gen_ai.agent.step.thought` | n/a |
| Guardrail (Output) Verdict | MUST | `security.guardrail.*`, `security.pii.*` | `constraints.data_classification` (6.3) |
| LLM Refusal | MUST | `gen_ai.response.finish_reason`, `security.*` | n/a |
| Model Name + Version | MUST | `gen_ai.request.model`, `gen_ai.provider.name` | `approved_software_refs` (6.1) |
| Provider / Endpoint Identity | MUST | `gen_ai.provider.name` | n/a |
| Inference Parameters | MUST | `gen_ai.request.temperature/top_p/max_tokens/stop_sequences/seed` | n/a |
| Token Counts | MUST | `gen_ai.usage.input_tokens/output_tokens`, `cost.*` | n/a |
| LLM Error / Exception | MUST | `gen_ai.*` error + `security.*` | n/a |
| Model Provenance / Signing | SHOULD | `supply_chain.model.hash/signed/source`, `supply_chain.ai_bom.*` | `software_hash` (6.2), `approved_software_refs` (6.1) |
| Pre-Forward-Pass State | MAY | `drift.*` | n/a |
| Token Malformation | MAY | `drift.*`, `quality.*` | n/a |
| Tool Call I/O | MUST | `mcp.tool.name/call.arguments/result`, `gen_ai.tool.*` | `action` (6.4) |
| Tool Name | MUST | `mcp.tool.name` | n/a |
| Tool Type / Trust Boundary | MUST | `mcp.*` vs internal | n/a |
| Tool ID | MAY | `mcp.server.name` + tool id | n/a |
| Tool Execution ID | MUST | `gen_ai.tool.call.id` | n/a |
| Tool Definition Digest | MUST | `mcp.tool.*` schema/description hash (AITF gap) | `approved_software_refs` (6.1) |
| Execution Environment / Sandbox | MUST | `supply_chain.*` + runtime/sandbox attrs (AITF gap) | `binding_profile` (6.2, partial) |
| MCP Server Identity & Primitive | MUST | `mcp.server.name/version`, primitive attr (AITF gap) | n/a |
| Tool Error / Exception | MUST | `mcp.*` error, `security.*` | n/a |
| Tool ACL / Required Scope | SHOULD | `identity.auth.scope_granted` | `granted_authorizations` (6.3) |
| Tool Privacy Classification | SHOULD | `security.pii.*`, `compliance.*` | `constraints.data_classification` (6.3) |
| Tool Selection Rationale | SHOULD | `gen_ai.agent.step.thought` (per-step) | n/a |
| Memory Write / Read Event | MUST | `memory.*` | n/a |
| Memory Provenance | MUST | `memory.provenance` | n/a |
| Memory Integrity / Poisoning | SHOULD | `memory.security.poisoning_score`, `memory.security.isolation_verified`, `memory.security.cross_session` | n/a |
| Memory Footprint / Growth | MUST | `memory.*`, `cost.*` | n/a |
| Declared Memory Configuration | SHOULD | `memory.*` config attrs (AITF gap) | n/a |
| Memory Write Rationale | SHOULD | `gen_ai.agent.step.thought` (per-step) | n/a |
| Retrieval Event | MUST | `rag.*` | n/a |
| Retrieved-Content Source | MUST | `rag.*` (source) | `delegation_chain[]`/`constraints` (6.3) |
| Retrieved Content/Metadata Integrity | SHOULD | `rag.*`, `security.*` | n/a |
| Declared Knowledge-Source Configuration | SHOULD | `rag.*` config/index attrs (AITF gap) | n/a |
| Inter-Agent Message | MUST | `gen_ai.agent.*`, delegation activity (OCSF 9002) | `delegation_chain[]` (6.3) |
| A2A Task Lifecycle Event | MUST | delegation activity (OCSF 9002); a2a attrs (AITF gap) | `delegation_id`, `parent_delegation_id` (6.3) |
| Peer Agent Card / Descriptor | MUST | `gen_ai.agent.*` peer attrs (AITF gap) | `agent_id`, `approved_software_refs` (6.1) |
| Background / Scheduled Task | MUST | `gen_ai.agent.next_action` / step events | n/a |
| Loop / Step-Count Signal | MUST | `gen_ai.agent.turn_count` | n/a |
| Resource-Consumption Aggregate | MUST | `cost.*`, `gen_ai.usage.*` | `constraints` (rate) (6.3) |
| Task / Intent Declaration | SHOULD | `gen_ai.agent.next_action` | `task_id`, `task_description` (6.3) |
| Protocol Envelope Capture | SHOULD | `mcp.*` / a2a raw payload (AITF gap) | n/a |
| Identities Used (per hop) | MUST | `identity.*` (OCSF Authentication 3002) | `actor`, chain (6.3) |
| Verified vs Displayed Identity | MUST | `identity.auth.method`, `identity.auth.result` | `originating_principal`/`actor` (6.3) |
| Originating Principal | SHOULD | `identity.*` | `originating_principal` (6.3) |
| Delegation Chain | SHOULD | delegation activity (OCSF 9002) | `delegation_chain[]`, `delegation_id`, `parent_delegation_id` (6.3) |
| Granted Authorizations / Scope | SHOULD | `identity.auth.scope_granted` | `granted_authorizations` (6.3) |
| Resource Indicators + Constraints | SHOULD | `identity.*`, `compliance.*` | `resource_indicators`, `constraints` (6.3) |
| Trust-Domain Crossing & Delegation Depth | SHOULD | `identity.*` domain/depth attrs (AITF gap) | `trust_domain` (6.1), `max_depth` (6.3) |
| Runtime Credential / Attestation | SHOULD | `identity.auth.method` (mTLS/SPIFFE/OAuth/DID-VC), `identity.trust.method` | `attestation_method`, `issuer`, `holder_key_ref`, `expires_at`, `binding_profile` (6.2) |
| Lifecycle State | SHOULD | `identity.lifecycle.operation` | `lifecycle_state` (6.1) |
| Version / Repository / Software Ref | SHOULD | `supply_chain.*`, `asset.*` | `approved_software_refs` (6.1) |
| Capability-Set Change Event | MUST | `asset.*` change events (AITF gap) | `approved_software_refs` (6.1) |
| AgBOM / Inventory Snapshot | SHOULD | `supply_chain.ai_bom.*` | `approved_software_refs` (6.1) |
| Component Dependency Graph | SHOULD | `supply_chain.ai_bom.*` (dependency edges) | n/a |
| Inventory Attestation Signature | SHOULD | `supply_chain.*` signature attrs | `software_hash`, `attestation_method` (6.2) |
| Asset-inventory metadata (creator, oncall, dates, status, surfaces) | MAY | `asset.*` | `sponsor_ref`, `owner_ref`, `created_at`, `updated_at` (6.1) |
| Fleet aggregates | MAY | (derived) | n/a |
| Credential Minting & Scope-Narrowing Check | SHOULD | `identity.auth.scope_granted` + token-exchange attrs (AITF gap) | `granted_authorizations`, `binding_profile` (6.2/6.3) |
| Authorization Decision Record | MUST | `security.*` decision + `compliance.control_id` (AITF gap) | `policy_profile_ref` (6.1) |
| Attribute Source / Trusted-Provenance Marking | MUST ‡ | (AITF gap) | `attestation_method` (6.2, partial) |
| Session Taint Labels & Information-Flow Decisions | SHOULD | `security.*` labels (AITF gap) | `constraints.data_classification` (6.3) |
| Human Approval / Elicitation Event | SHOULD | `identity.*` approver + approval attrs (AITF gap) | `originating_principal` (6.3, partial) |
| Backend / Route Restriction Decision | SHOULD | `gen_ai.provider.name` + routing constraint attrs (AITF gap) | `resource_indicators`, `constraints` (6.3) |
| Mediation Coverage & Bypass Path | SHOULD | (AITF gap) | n/a |
| Enforcement-Point Availability & Failure Mode | SHOULD | `security.guardrail.*` availability/latency (AITF gap) | n/a |
| Instrumentation Coverage / Hook Attestation | SHOULD | `asset.*` / instrumentation attrs (AITF gap) | n/a |
| Event Sequence Continuity | SHOULD | (AITF gap) | n/a |
| Policy Reason Code | SHOULD | `security.*` + `compliance.control_id` | n/a |

> **Note on the run/session mapping.** Mapping both *Agent Instance ID* and *Workflow / Run ID* onto `gen_ai.agent.session.id` is ambiguous, given that §5 distinguishes five levels (instance → run → session → turn → step). The table above assigns `gen_ai.agent.session.id` to **Session** and routes the run to the trace ID. AITF has no dedicated turn/step attribute today; see [Appendix F.4](#f4-what-this-implies-for-opentelemetry-aitf-and-ocsf) for the proposed additions.

> **"(AITF gap)"** marks a field with no current AITF attribute. These are the concrete additions this document asks of AITF, the same evidence-driven promotion rule in [E.4](#e4-incremental-extension-path-via-aitf) applies.
>
> **Note on upstream OTel coverage.** Several rows marked *(AITF gap)* do have a home in the **OpenTelemetry GenAI conventions**, which moved to a dedicated repository and are richer than this table's `(AITF gap)` markers alone suggest (notably `gen_ai.system_instructions` (System Prompt), `gen_ai.tool.definitions` (Tool Definition Digest), `gen_ai.retrieval.query.text` / `.documents` (Retrieval Event), the full `gen_ai.request.*` decoding set (Inference Parameters), the `mcp.*` namespace (MCP Server Identity), and `gen_ai.invoke_agent.tool_calls` / `.inference_calls` (Loop Signal, as metrics). See **[Appendix D.2](#d2-what-the-genai-conventions-cover-today)** for the inventory and **[D.3](#d3-coverage--gaps-by-field-cluster)** for what remains genuinely absent) chiefly memory, trust classification, security guardrail verdicts, and retrieval provenance.

> **ODIS fields intentionally out of telemetry scope** (identity/authority mechanics rather than detection signals): `approved_runtime_issuers`, `trust_domain`, `policy_profile_ref`, `permitted_delegation_modes`, `provider_entitlements`, and the cryptographic details of `binding_profile` (DPoP/mTLS/TLS-session). These are consumed by the policy engine (ODIS §6.4 Identity Context) rather than emitted as security telemetry, `trust_domain` and `max_depth` are the exception: §13's **Trust-Domain Crossing & Delegation Depth** field carries them as telemetry, because both become detection-grade once a delegation chain leaves the domain that issued it (see [§4.7](#47-agents-you-do-not-operate)).

---

## Appendix D: Implications for OpenTelemetry (the instrumentation bridge)

[Appendix E](#appendix-e-implications-for-ocsf--aitf-the-standardization-bridge) covers half of AITF's mandate: getting this field set into **OCSF**, the schema a SOC consumes. This appendix covers the other half: getting it into **OpenTelemetry**, the framework that actually **produces** the data.

The two are not alternatives, and the distinction matters for where each ask should be filed:

- **OTel is the emission layer.** It is where an instrumentation library decides what to record at the moment an agent calls a model or a tool. A field that OTel does not define is a field most deployments will never emit, no matter how well OCSF models it downstream.
- **OCSF is the consumption layer.** It is where events are normalized for detection, correlation, and retention alongside the rest of the security estate.

**A field must exist in both, or the pipeline breaks at one end.** A field OTel emits but OCSF cannot represent arrives at the SIEM as unstructured overflow. A field OCSF defines but no OTel convention produces stays theoretical. AITF's role is to carry both halves, which is why [E.4](#e4-incremental-extension-path-via-aitf)'s phase plan and this appendix's asks should be sequenced together.

**Scope of the ask.** OpenTelemetry is not a security telemetry framework and should not become one. Its GenAI conventions are shaped by observability concerns, latency, cost, token accounting, evaluation quality, and that is the right centre of gravity. The argument here is narrower and, in this document's view, uncontroversial: **OTel's ubiquity means it is where AI instrumentation is being written**, so the subset of security-relevant fields that map cleanly onto its existing model should be added to the specification, so that deployments already running OTel get them by default rather than by bespoke effort. Fields that do not map cleanly; authorization decisions, delegation chains, information-flow labels; are noted as such and left to OCSF and the [AOS](#appendix-f-owasp-aos-cross-reference) / [CPEX](#appendix-g-cpex-cross-reference) surfaces. **This appendix asks OTel to cover what OTel is already shaped to cover, and no more.**

> **Verification note.** The GenAI conventions **moved** out of the main `open-telemetry/semantic-conventions` repository into a dedicated **`open-telemetry/semantic-conventions-genai`** repository; the attributes still listed in the main registry are marked *Deprecated* to reflect that relocation, not abandonment. Every convention cited below carries **Status: Development**: none is stable, which is precisely why this is the moment to contribute. Names were read from the live registry and docs at the time of writing; re-verify before filing.

### D.1 Layer roles

| Layer | Role | Artifact |
| :--------------------- | :------------------------------------------ | :------------------------------------ |
| **Requirements** | *What to collect, why, and at what priority* | This document |
| **Emission** | What an instrumentation library records at the call site | **OpenTelemetry GenAI + MCP semantic conventions** |
| **Binding / interim carrier** | How to emit today and route into OCSF | AITF namespaces + `ai_operation` profile |
| **Consumption** | The ratified schema a SOC queries | OCSF event classes, objects, profiles |

### D.2 What the GenAI conventions cover today

The conventions are richer than is commonly assumed, and several fields marked "(AITF gap)" in [Appendix C](#appendix-c-aitf--odis-cross-reference) in fact have a natural OTel home already.

- **Spans.** `chat`, `text_completion`, `embeddings`, `generate_content`, `execute_tool`, `create_agent`, `invoke_agent` (client and internal variants), `invoke_workflow`, and a **`plan`** span, discriminated by `gen_ai.operation.name`.
- **Core attributes.** `gen_ai.provider.name`; `gen_ai.agent.id` / `.name` / `.description` / `.version`; `gen_ai.conversation.id`; `gen_ai.workflow.name`; `gen_ai.request.model` and the full decoding set (`temperature`, `top_p`, `top_k`, `max_tokens`, `stop_sequences`, `seed`, `frequency_penalty`, `presence_penalty`, `choice.count`, `stream`); `gen_ai.response.id` / `.model` / `.finish_reasons`; `gen_ai.usage.input_tokens` / `.output_tokens` / `.reasoning.output_tokens` / `.cache_read.input_tokens` / `.cache_creation.input_tokens`.
- **Content and definitions.** `gen_ai.input.messages`, `gen_ai.output.messages`, **`gen_ai.system_instructions`**, **`gen_ai.tool.definitions`**, `gen_ai.tool.name` / `.description` / `.type` / `.call.id` / `.call.arguments` / `.call.result`, `gen_ai.output.type`, `gen_ai.prompt.name`.
- **Retrieval.** **`gen_ai.retrieval.query.text`**, **`gen_ai.retrieval.documents`**, `gen_ai.data_source.id`, `gen_ai.embeddings.dimension.count`.
- **Evaluation.** A `gen_ai.evaluation.result` event with `gen_ai.evaluation.name`, `.score.value`, `.score.label`, `.explanation`.
- **Metrics.** `gen_ai.client.operation.duration`, `gen_ai.client.token.usage`, `gen_ai.client.operation.time_to_first_chunk` / `.time_per_output_chunk`, `gen_ai.execute_tool.duration`, **`gen_ai.invoke_agent.duration` / `.inference_calls` / `.tool_calls`**, `gen_ai.invoke_workflow.duration`, `gen_ai.server.request.duration` / `.time_to_first_token` / `.time_per_output_token`.
- **MCP.** A distinct **`mcp.*`** namespace: `mcp.method.name`, `mcp.protocol.version`, `mcp.request.id`, `mcp.resource.uri`, `mcp.session.id`, plus `mcp.client.operation.duration`, `mcp.server.operation.duration`, and client/server `session.duration` metrics.

**Three of these deserve explicit note**, because they close gaps this document had recorded as open. `gen_ai.system_instructions` gives **System Prompt** (§5) a home. `gen_ai.tool.definitions` gives **Tool Definition Digest** (§9) one; the raw material for a digest is already in scope, and only the *hash-and-compare* is missing. And `gen_ai.invoke_agent.tool_calls` / `.inference_calls` are already the shape of **Loop / Step-Count Signal** (§12) and part of **Resource-Consumption Aggregate** (§12), as metrics rather than attributes.

### D.3 Coverage & gaps, by field cluster

Where each cluster lands in OTel **today**, the gap, and the recommended change. Priority follows the field tiers; MUST clusters first.

| Field cluster (tier) | OTel today | Gap | Recommended OTel change |
| :---------- | :------------------ | :--------------------- | :---------------------------------------------------- |
| Execution context & agent identity (MUST) | `gen_ai.agent.*`, `gen_ai.conversation.id`, `gen_ai.workflow.name`; span hierarchy | No turn/step identifier; no trigger type; no tenant; no surface | Add `gen_ai.turn.id` / `gen_ai.step.id`; `gen_ai.trigger.type` (`user_initiated` / `autonomous`) + `gen_ai.trigger.event`; adopt existing tenant/resource attrs |
| Prompt / response / system prompt (MUST) | `gen_ai.input.messages`, `gen_ai.output.messages`, `gen_ai.system_instructions` | **Covered.** Gated behind content-capture opt-in | Keep; ensure a **hash-only** capture mode exists (see [D.6](#d6-context-propagation-sampling--privacy-three-operational-traps)) |
| Content modality & attachments (MUST) | Message parts carry types | No attachment name/size/**hash** | Add attachment identity attrs on message parts; hash especially, as it survives redaction |
| Input trust classification (MUST) | n/a | **No trust-provenance concept at all** | Add `gen_ai.input.trust_level` (trusted-instruction / trusted-data / untrusted-data / adversarial-suspected) per message part |
| Guardrail verdicts (MUST) | `gen_ai.evaluation.*`: quality-oriented | No security guardrail verdict, blocked flag, or threat classification | **Extend the evaluation event for security use**, or add `gen_ai.guardrail.*` (type, verdict, score, blocked, threat technique), see [D.4](#d4-what-cosai-asks-opentelemetry-to-include) item 2 |
| Citations (MUST) | `gen_ai.retrieval.documents` exists | Output-side citations not linked to retrieved items | Add citation attrs on output messages with a resolution flag against retrieval |
| Model & serving (MUST) | `gen_ai.request.*` decoding set, `gen_ai.provider.name`, `gen_ai.response.*` | **Inference Parameters fully covered.** No model provenance/signing | Add `gen_ai.model.hash` / `.signature` / `.source` (supply-chain) |
| Token counts & resource aggregates (MUST) | `gen_ai.client.token.usage`, `gen_ai.invoke_agent.*` metrics | **Largely covered** | Add per-run budget/threshold semantics; document security use of the loop metrics |
| Tools & MCP (MUST / ADV) | `gen_ai.tool.*` incl. `definitions` and `call.id`; full `mcp.*` namespace | No tool-definition **digest**; no MCP **primitive** discriminator; no sandbox/isolation attrs | Add `gen_ai.tool.definitions.hash`; add an `mcp.primitive` value set (tool / resource / prompt / sampling / elicitation / roots), `mcp.method.name` partially serves; add execution-environment attrs (`sandbox`, runtime, egress policy) |
| Memory (MUST) | **Nothing** | No memory namespace whatsoever | Add a **`gen_ai.memory.*`** namespace: operation, item id, **provenance**, footprint |
| Retrieval / RAG (MUST) | `gen_ai.retrieval.query.text`, `.documents`, `gen_ai.data_source.id` | No per-item **source/provenance**, freshness, or integrity signal | Add provenance and last-modified attrs to retrieval document entries |
| Output egress (MUST) | n/a | No link from model output to destination | Correlate via existing HTTP/network semconv on the child span; document the pattern |
| Orchestration & multi-agent (MUST) | `invoke_agent`, `invoke_workflow`, `plan` spans; agent metrics | No inter-agent message attrs; no background-task/termination-condition signal | Add inter-agent messaging attrs; treat scheduled/self-triggered runs via `gen_ai.trigger.type` |
| Identity & delegation (MUST / ADV) | n/a | No principal, delegation chain, scope, or attestation | **Out of natural scope for OTel**: carry via OCSF Authentication/Delegation; see [D.4](#d4-what-cosai-asks-opentelemetry-to-include) note |
| Asset inventory & AgBOM (MUST / ADV) | Resource attributes, partially | No capability-change event; no BOM reference | Add a capability-change event; reference an external BOM by URI/digest rather than embedding it |
| Policy enforcement & mediation (MUST / ADV) | n/a | No authorization decision, taint, approval, or attribute-provenance concept | **Out of natural scope for OTel**: carry via OCSF `ai_authorization` / `ai_taint` / `ai_approval` ([E.3](#e3-what-cosai-asks-ocsf-to-include-summary)) |
| Observability-plane integrity (ADV) | n/a | No enforcement-availability or instrumentation-coverage representation | Partially natural: OTel can record hook coverage as a resource attribute; enforcement outcomes belong to OCSF |

### D.4 What CoSAI asks OpenTelemetry to include

Ordered by ratio of security value to specification cost. Every item is scoped to something OTel already models, and the two clusters that are *not* a natural fit are named as such rather than pushed.

1. **A trust-provenance attribute on message parts.** `gen_ai.input.trust_level`, distinguishing trusted instruction from untrusted environmental data. This is the single highest-value addition and the one with no current analogue anywhere in the conventions. It is cheap (an enum on an existing structure) and it is the field the CoSAI Risk Map treats as the core agentic control (§6).
2. **A security-guardrail signal, ideally by extending `gen_ai.evaluation.*`.** The evaluation event already carries name, score, label, and explanation, the right shape for a classifier verdict. What it lacks is the security semantics: a **blocked / allowed** outcome, a guardrail **type**, and a **threat technique** reference. Reusing evaluation avoids a parallel namespace; the alternative is a dedicated `gen_ai.guardrail.*`. Either way, this is the field that makes classifier *bypass* detectable (`TA-01`).
3. **A `gen_ai.memory.*` namespace.** Memory is entirely absent from the conventions and is a MUST cluster here (§10), with `IR-02` and `IR-05` as direct grounding. Operation, item identity, **provenance**, and footprint are the minimum.
4. **Retrieval provenance.** `gen_ai.retrieval.documents` exists; per-document **source, owner, trust level, and last-modified** do not, and `TA-09` turns specifically on recently-modified retrievable content.
5. **Turn and step identifiers.** `gen_ai.conversation.id` and `gen_ai.workflow.name` exist; the intermediate levels do not. `TA-08` and `IR-01` are across-turn patterns (§5).
6. **`gen_ai.trigger.type` and `gen_ai.trigger.event`.** Whether a run was user-initiated or autonomous, and what event started it. `TA-01` is zero-click; this is the first filter of any injection hunt.
7. **Tool-definition digest and MCP primitive discriminator.** `gen_ai.tool.definitions` and `mcp.method.name` already carry the raw material; a stable hash attribute and an explicit primitive value set make definition drift and non-tool MCP surfaces queryable (§9).
8. **Attachment identity on content parts**: name, size, and hash. `AOC-12` is an image/OCR injection; `AOC-05` is attachment flooding.
9. **Model provenance attributes**: hash, signature, source, completing the supply-chain story that `gen_ai.request.model` starts.

**Two clusters this document deliberately does *not* ask OTel to adopt.** **Identity and delegation** (§13) and **policy enforcement** (§16) are authorization-domain concerns with mature homes elsewhere, OCSF Authentication, and the proposed `ai_authorization` / `ai_taint` / `ai_approval` objects in [E.3](#e3-what-cosai-asks-ocsf-to-include-summary). Pushing them into OTel would duplicate schema and invite drift. The one exception worth raising is **correlation**: an OTel span should be able to reference an authorization decision by ID so the two layers join at query time, which is a single attribute rather than a namespace.

### D.5 Signal selection: traces, events/logs, metrics

OTel has three signal types and OCSF has one event model, so this guidance has no counterpart in [Appendix E](#appendix-e-implications-for-ocsf--aitf-the-standardization-bridge), but getting it wrong is the most common way security telemetry becomes unusable or unaffordable.

| Signal | Use for | Fields from this document |
| :-------- | :-------------------------- | :------------------------------------------------------------------ |
| **Span attributes** | Low-cardinality identifiers and the execution skeleton | Agent/instance/run/session/turn/step IDs, action type, execution status, model and provider, tool name and type, trigger type, trust level, decision references |
| **Events / logs** | Content and anything high-cardinality, large, or privacy-bearing | Prompts, responses, system instructions, tool arguments and results, memory operations, retrieved documents, citations, guardrail verdicts, capability-change events |
| **Metrics** | Aggregates, budgets, and rate-based detections | Token usage, loop and step counts, tool-call rates, resource aggregates, guardrail block rates, deny rates |

Three rules follow, and each corrects a mistake this document has seen made in practice:

- **Never put content in span attributes.** Prompts, responses, and tool results are unbounded in size and often contain PII. OTel already models them as event bodies; keep them there. A span attribute carrying a full prompt breaks cardinality limits and leaks into every trace backend that samples the span.
- **Emit detection-relevant aggregates as metrics, not as derived queries.** Loop counts and token budgets (§12) are cheap as metrics and expensive as trace aggregations, and metrics survive sampling, which traces may not.
- **Cross-reference rather than duplicate.** A guardrail verdict event should carry the span and trace IDs, not a copy of the prompt it evaluated.

### D.6 Context propagation, sampling & privacy: three operational traps

**Propagation is solved for MCP, and the mechanism should be adopted deliberately.** The MCP conventions specify that instrumentations SHOULD inject context into the MCP request **`params._meta`** property bag, with `traceparent`, `tracestate`, and `baggage` written unprefixed per **SEP-414**, and that the receiver uses the extracted context as the remote parent. That is exactly the mechanism **Trace Context (propagated)** (§5) requires, and it means cross-hop correlation over MCP is a matter of configuration rather than invention. Two cautions. First, HTTP-level propagation covers the HTTP request but **not** individual messages within a streaming request/response, a gap that matters for long-lived agent sessions. Second, and more important for security: **`baggage` crosses the trust boundary.** It is attacker-influenceable in exactly the way §16's provenance rule describes, so baggage may carry correlation identifiers but **must never carry trust levels, authorization decisions, taint labels, or identity claims**. Those come from the enforcement point, not from the wire.

**Sampling is the trap most likely to silently defeat this entire field set.** OTel's default is head-based sampling at some fraction of traces. Applied to security telemetry, that means *most attacks are simply not recorded*. Worse, the sample is drawn without regard to whether an event is security-relevant, so a guardrail block has the same chance of being discarded as a routine completion. Three requirements follow, and this document treats them as **normative for any deployment relying on OTel as its security-telemetry carrier**:

1. **Security-relevant events must not be head-sampled.** Guardrail verdicts, refusals, tool errors, authorization denials, capability changes, and any event carrying a fired detection are recorded at **100%**.
2. **Where tail sampling is used, security relevance must be a retention predicate**: a trace containing a block, a denial, an error, or a flagged classification is always kept.
3. **The sampling configuration in force is itself telemetry.** A detection that never fires because its input was sampled away is indistinguishable from a clean environment. This is the same failure mode as fail-open enforcement ([§15](#15-observability-plane-integrity)) and deserves the same treatment.

**Privacy: content capture is opt-in, and that default is correct.** GenAI instrumentations gate message content behind an explicit capture setting, which aligns with this document's [privacy-preserving logging](#18-implementation-guidance) position. The gap is that capture is close to binary (on or off) where security work needs a **middle setting**: hashes and classifications without raw content, so that correlation (same payload across many sessions, same attachment hash) survives even where raw capture is prohibited. That is [D.4](#d4-what-cosai-asks-opentelemetry-to-include) item 1's companion ask, and it is the OTel expression of this document's **hash-first** principle. The OTel Collector is also the correct place to run redaction, since it applies uniformly across every instrumented service rather than per-library.

### D.7 Bridge design principles

- **Ask OTel for what OTel already models.** Extend `gen_ai.evaluation.*` before minting `gen_ai.guardrail.*`; add attributes to existing spans before proposing new signals. Every ask in [D.4](#d4-what-cosai-asks-opentelemetry-to-include) attaches to an existing structure.
- **Do not make OTel a security schema.** Authorization, delegation, and enforcement belong to OCSF. The boundary is deliberate, and holding it is what makes the OTel asks acceptable to that community.
- **Development status is an opportunity, not a risk.** Every GenAI convention is currently *Development*, and the conventions have just moved to a dedicated repository with active governance. Contributions land more cheaply now than after stabilization.
- **Emission and consumption move together.** Each [D.4](#d4-what-cosai-asks-opentelemetry-to-include) ask should be filed alongside its [E.3](#e3-what-cosai-asks-ocsf-to-include-summary) counterpart, with AITF carrying the field in the interim so adopters are never blocked on either standards body.
- **Same evidence rule.** A field is proposed to OTel on the same basis it earns a tier here, **≥2 corpus attacks, or one with strong D/R value**. This keeps the ask small, defensible, and reviewable by people who do not share this document's threat model.

---

## Appendix E: Implications for OCSF & AITF (the standardization bridge)

This document is deliberately positioned as a **bridge**. It is not itself a wire format; it is the *requirements layer* that says **what** AI-security telemetry must exist, **why** (attack-grounded, Appendix A), and at **what priority** (MUST / SHOULD / MAY). Turning those requirements into interoperable, SOC-consumable events is the job of two downstream artifacts:

- **OCSF (Open Cybersecurity Schema Framework)**: the vendor-neutral destination schema that SIEM/XDR/data-lake tooling already ingests. This is where CoSAI's field set ultimately belongs so that AI-security events sit alongside the rest of the security estate. **This appendix states what CoSAI believes OCSF should include.**
- **AITF (AI Telemetry Framework)**: the OpenTelemetry + OCSF binding donated to CoSAI WS2. AITF is the **incremental extension vehicle**: it can carry these fields *today* as OTel attributes and emit them into OCSF via the `ai_operation` profile and proposed AI event classes, *before* OCSF formally ratifies them, and it is the natural conduit for feeding ratified proposals upstream.

The relationship is a pipeline: **CoSAI requirements → AITF carries & proves them in production → OCSF ratifies them as standard schema.**

> **This appendix covers the OCSF half of AITF's mandate only.** AITF binds to OpenTelemetry *and* OCSF, and the two asks are complementary: OTel is where the data is **emitted** at the call site, OCSF is where it is **consumed** by a SOC. A field missing from either end breaks the pipeline. The OTel half (coverage, gaps, standardization asks, and the signal-selection, propagation, and sampling guidance that has no OCSF counterpart) is **[Appendix D](#appendix-d-implications-for-opentelemetry-the-instrumentation-bridge)**, and each ask there should be filed alongside its counterpart in [E.3](#e3-what-cosai-asks-ocsf-to-include-summary).

### E.1 Layer roles

| Layer | Role | Artifact |
| :--------------- | :---------------------------- | :--------------------------------------------------------- |
| **Requirements** | *What to collect, why, and at what priority* | This document (fields + MUST/SHOULD/MAY + attack grounding) |
| **Binding / interim carrier** | *How to emit it today* over OTel and into OCSF | AITF namespaces (`gen_ai.*`, `mcp.*`, `rag.*`, `memory.*`, `security.*`, `identity.*`, …) + `ai_operation` profile |
| **Standard schema** | *The ratified, vendor-neutral event schema* SOCs consume | OCSF event classes, objects, profiles, enums |

### E.2 OCSF coverage & gaps, by field cluster

For each cluster of fields defined above: where it lands in OCSF **today**, the **gap**, the **AITF interim carrier**, and the **recommended OCSF change**. Priority follows the field tiers (MUST clusters first).

| Field cluster (tier) | OCSF today | Gap | AITF interim carrier | Recommended OCSF change |
| :------ | :---------- | :---------------------- | :---------- | :---------------------------------------------------- |
| Execution context & agent identity (MUST) | API Activity (6003) base attrs | No agent instance / workflow / action-type / autonomy fields | `gen_ai.agent.*`; proposed **Agent Activity (9001)** | Ratify **AI Agent Activity** class; add agent identity/workflow/action-type to the `ai_operation` profile |
| Prompt / response / system-prompt content (MUST) | No native AI-content object | Model input, output, and system prompt not representable (privacy-gated) | `gen_ai.prompt` / `gen_ai.completion` / system message | New **`ai_content`** object (content hash + optional raw + redaction/PII flags) attachable to 6003 / 9001 |
| Input trust classification & guardrail verdicts (MUST) | Detection Finding (2004), partial | No trust-provenance enum; no guardrail-verdict object | `security.guardrail.*`, `security.blocked`, `security.threat_type` | New **`ai_guardrail`** object + **`trust_level`** enum (trusted-instruction / trusted-data / untrusted-data / adversarial-suspected) |
| Threat classification / **ATLAS technique tag** (MUST) | Detection Finding (2004) carries MITRE **ATT&CK** technique | ATLAS `AML.Txxxx` not a first-class technique value | `security.threat_type` + `compliance.framework=mitre_atlas` / `compliance.control_id` | Extend the finding technique/attack object to accept **ATLAS `AML.Txxxx`** natively (not only ATT&CK) |
| Output egress destination (MUST) | Network / HTTP Activity (partial) | No link from model output → egress channel/recipient | `mcp.tool.call.arguments`, `security.pii.*` | Add **egress correlation** attribute on Agent Activity linking output → destination/recipient/URL |
| Model & serving (MUST / ADV) | API Activity (6003) model attrs; App Lifecycle (6002); Vulnerability Finding (2002) | Provenance/signing not standardized in profile | `gen_ai.request.model`, `gen_ai.provider.name`, `supply_chain.*` | Standardize model name/version/provider + **provenance/signing** attrs in `ai_operation` |
| Tools & MCP (MUST / ADV) | API Activity (6003) | No MCP object, tool trust-boundary, ACL/scope | `mcp.*`, `identity.auth.scope_granted` | New **`ai_tool` / `mcp`** object + **`tool_trust_boundary`** enum (mcp / internal / direct-storage) + scope attr |
| Memory (MUST / ADV) | Datastore Activity (6005), loosely | No memory-operation object, provenance, poisoning/isolation signals | `memory.*`, `memory.security.*` | New **`ai_memory`** object (op, provenance, footprint, poisoning score, isolation-verified) |
| RAG / retrieval (MUST / ADV) | Datastore Activity (6005) | No retrieved-content source/provenance/integrity | `rag.*` | New **`ai_retrieval`** object (query, items, source/provenance, integrity signal) |
| Orchestration & multi-agent (MUST / ADV) | None native | No inter-agent message, background task, loop/step, resource aggregate | Proposed **Agent Activity (9001)**; inter-agent via 9002 | Ratify **AI Agent Activity (9001)** carrying inter-agent, background-task, loop, and resource-aggregate attrs |
| Identity, delegation & attestation (MUST / ADV) | Authentication (3002) | No multi-hop delegation chain, granted scope, runtime attestation, on-behalf-of | `identity.*`; proposed **Delegation Activity (9002)** | Ratify **AI Delegation Activity (9002)** + **`ai_attestation`** object; align to ODIS §6.2/§6.3 |
| Asset inventory & fleet (ADV / OPT) | Inventory Info (partial) | No AI-asset object; fleet aggregates derived | `asset.*` | New **`ai_asset`** object (version, software ref, ownership, status) |
| Capability-set change & AgBOM (MUST / ADV) | Inventory Info; App Lifecycle (6002) | No agent-composition BOM, no dependency graph, no capability-change event | `supply_chain.ai_bom.*` | New **`ai_bom`** object (BOM ref, format, signature, dependency edges) + a **capability-change** activity on Agent Activity (9001) |
| Observability-plane integrity (ADV) | None native | No enforcement-availability, fail-open, hook-coverage, or event-continuity representation | `security.guardrail.*` (partial) | Add **enforcement availability / failure-mode** attrs to `ai_guardrail`; add **instrumentation coverage** to `ai_asset` |
| Policy enforcement & mediation (MUST / ADV) | Authorization (3003) partially; Detection Finding (2004) for classifier verdicts | No authorization-decision object for AI operations; no information-flow/taint labels; no human-approval lifecycle; no attribute-provenance marking; no mediation-coverage representation | `security.*` (partial) | New **`ai_authorization`** object (decision, reason, code, deciding authority, rule id, obligations); new **`ai_taint`** object (labels, scope, origin, taint-caused denial); new **`ai_approval`** object (correlation id, status, IdP-verified approver, channel, scope-binding result); an **`attribute_source`** enum (idp / pdp / enforcement-state / platform / **self-asserted**) usable on identity, authorization, and agent-state attributes |

### E.3 What CoSAI asks OCSF to include (summary)

1. **Promote the two proposed AI event classes to ratified:** **AI Agent Activity (9001)** and **AI Delegation Activity (9002)**.
2. **Standardize an `ai_operation` profile** whose **required** attributes are exactly the **MUST** fields in the [classification summary](#45-classification-summary), and whose **recommended/optional** attributes are the SHOULD/MAY fields.
3. **Add AI-specific objects:** `ai_content`, `ai_guardrail`, `ai_tool`/`mcp`, `ai_memory`, `ai_retrieval`, `ai_delegation`, `ai_attestation`, `ai_asset`, `ai_bom`, `ai_authorization`, `ai_taint`, `ai_approval`.
4. **Add AI-specific enums:** `trust_level`, `autonomy_level` (L1 to L5), `tool_trust_boundary`, `memory_provenance`, `enforcement_decision` (allow / deny / modify), `enforcement_failure_mode` (fail-open / fail-closed), `mcp_primitive` (tool / resource / prompt / sampling / elicitation / roots), `trigger_type` (user-initiated / autonomous), **`attribute_source`** (idp / pdp / enforcement-state / platform / self-asserted), **`taint_scope`** (session / message), **`approval_status`** (pending / resolved / expired / bypassed).
5. **Make MITRE ATLAS a first-class technique reference** on Detection Finding (2004), alongside ATT&CK, so the [ATLAS Technique Tag](#a5-attack-inventory--mitre-atlas-technique-mapping) is portable.
6. **Type AI agents as first-class actors.** OWASP AOS's OCSF binding currently represents the agent as `actor.type_id: 99` ("Other") with `type: "AI Agent"`: a documented workaround. Ratify a proper actor type so agent attribution does not depend on a free-text override. This is a small change with broad benefit, and AOS's need for it is independent corroboration of ask (1).

### E.4 Incremental extension path via AITF

AITF lets adopters emit this telemetry **before** OCSF ratifies it, and stages the upstream proposals so each is backward-compatible:

- **Phase 0, today.** AITF carries every MUST field as OTel attributes and emits OCSF via the `ai_operation` profile on existing classes (6003/6005/2004/3002); the ATLAS tag rides on `compliance.control_id` (framework `mitre_atlas`).
- **Phase 1 (profile extension (backward-compatible).** Contribute the MUST attribute set + `ai_content`, `ai_guardrail`, and `ai_tool` objects to the OCSF `ai_operation` profile) no new classes required.
- **Phase 2, agentic classes.** Ratify **AI Agent Activity (9001)** plus the `ai_memory` and `ai_retrieval` objects (memory & RAG are absent from OCSF today and are MUST here).
- **Phase 3, delegated authority.** Ratify **AI Delegation Activity (9002)** and the `ai_attestation` object (ODIS-aligned), and land the ATLAS technique reference on findings.
- **Phase 4, inventory & analytics.** SHOULD/MAY clusters (`ai_asset`, drift, quality, fleet aggregates) as they stabilize.

**Governance rule for promotion:** a field graduates from AITF-proposed to an OCSF standardization ask when **≥ 2 independent attacks in [Appendix A](#appendix-a-attack--incident-inventory)** require it, the same attack-grounding rule that sets the MUST tier. This keeps the OCSF surface minimal and evidence-driven rather than speculative.

### E.5 Bridge design principles

- **Backward-compatible first.** Prefer extending existing OCSF classes via the `ai_operation` profile over minting new classes; reserve new classes (9001/9002) for genuinely new event shapes (agentic action, delegation).
- **Privacy-gated content.** Content-bearing objects (`ai_content`, memory, retrieval) are hash-first with optional raw payloads and explicit redaction flags, consistent with [Privacy-preserving logging](#18-implementation-guidance).
- **MUST-first.** OCSF *required* attributes track this document's MUST tier; SHOULD/MAY map to recommended/optional so conformance scales with deployment maturity.
- **ATT&CK/ATLAS-aligned.** Findings carry ATLAS `AML.Txxxx` so AI events correlate with the existing ATT&CK-based SOC.

---

## Appendix F: OWASP AOS Cross Reference

The [OWASP Agent Observability Standard](https://aos.owasp.org/) (AOS) is the closest adjacent standard to this document, and the two are complementary rather than competing:

- **This document is a requirements layer.** It says *what* AI-security telemetry must exist, *why* (attack-grounded, [Appendix A](#appendix-a-attack--incident-inventory)), and at *what priority* (MUST / SHOULD / MAY).
- **AOS is an exposure layer.** It says *how an agent exposes* that information at runtime: standardized hooks that a policy engine can intervene on, standardized events, and a queryable Agent Bill-of-Materials.

An agent can satisfy AOS and still emit poor security telemetry (AOS does not say which fields matter or why). An agent can satisfy this document and still be unobservable to third-party tooling (this document does not define a wire interface). **The two together are the useful pairing**, which is why this document audits itself against AOS and closes the gaps.

AOS organizes itself into three pillars, **Instrument**, **Trace**, **Inspect**. The tables below walk each pillar element by element. Status values:

| Status | Meaning |
| :----------------- | :----------------------------------------------------------------------------------- |
| **Covered** | Already in the field set independently of AOS. |
| **Covered (new)** | Added specifically to close an AOS gap. |
| **Partial** | Deliberately narrower coverage; the difference is explained. |
| **Out of scope** | Control-plane or wire-protocol material this document intentionally does not specify. |

> **Draft caveat.** Every AOS page consulted is marked *working draft*, and several were read through summarizing retrieval rather than verbatim. Re-verify element names against the live specification before treating this cross reference as normative. Where AOS field names appear below they are given as encountered, in `code style`.

### F.1 Pillar 1: Instrument

*AOS's Instrument pillar defines lifecycle hooks that emit to, and can be intervened on by, a **Guardian Agent**: a policy decision point that returns `allow`, `deny`, or `modify` before the agent proceeds. This is the pillar that required the most additions, because a guardrail model that only records verdicts is observational (a verdict was recorded) rather than interventional (a decision was enforced, or failed to be).*

| AOS element | This document | Status |
| :-------------------------------------------------------- | :-------------------------------------- | :------ |
| Hook set (agent trigger, user message, agent response, tool call request, tool call result, memory store, memory retrieval, knowledge retrieval, MCP inbound/outbound) | Field coverage across §§5 to 12; **Instrumentation Coverage / Hook Attestation** (§15) records which hooks are live | **Covered (new)** |
| Decision `allow` / `deny` | Guardrail (Input/Output) Verdict, pass / block (§§6 to 7) | Covered |
| Decision `modify` + `modifiedRequest` | **Guardrail Modification Record** (§6), cross-cutting | **Covered (new)** |
| `reasoning` (human-readable decision rationale) | Guardrail Verdict detector + score (§§6 to 7) | Covered |
| `reasonCode[]` (machine-readable) | **Policy Reason Code** (§15) | **Covered (new)** |
| Enforcement callout failure, timeout, unavailability | **Enforcement-Point Availability & Failure Mode** (§15) | **Covered (new)** |
| `ping` / liveness | **Enforcement-Point Availability** + **Event Sequence Continuity** (§15) | **Covered (new)** |
| `StepContext`: agent, session, turn, step, timestamp, user, organization | **Session / Turn / Step IDs**, **Organization / Tenant ID** (§5) | **Covered (new)** |
| `Agent` object, name, id, description, version, `instructions`, provider, model, tools, mcpServers, resources | Agent Name, Instance ID, System Prompt (§5); Model fields (§8); inventory (§14) | Covered |
| `Message` object + `Part` union (TextPart / FilePart / DataPart) | **Content Modality & Attachment Identity** (§6), cross-cutting | **Covered (new)** |
| `ToolDefinition` / `ToolArgumentDefinition` / `ToolOutputDefinition` | **Tool Definition Digest** (§9) | **Covered (new)** |
| `ToolCallRequest`: `executionId`, `toolId`, inputs | **Tool Execution ID** (§9) + Tool Call I/O, Tool Name (§9) | **Covered (new)** |
| `Source` union, FileSource, SiteSource | **Citations / Source Attribution** (§7) | **Covered (new)** |
| `KnowledgeRetrievalStepParams`: query, keywords, results | Retrieval Event, Retrieved-Content Source (§11) | Covered |
| `A2AContext`: from / to, role (client / server) | **Peer Agent Card / Descriptor** (§12); Identities Used (§13) | **Covered (new)** |
| Guardian Agent architecture; agent↔guardian authentication | Not specified: but its **outcomes** are, via §15 | Out of scope |
| JSON-RPC 2.0 over HTTP(S); error code ranges | Wire protocol not specified; error *content* covered by LLM Error (§8), Tool Error (§9) | Out of scope |

### F.2 Pillar 2: Trace

*AOS's Trace pillar defines the event set and its bindings to OpenTelemetry and OCSF. This is the field set's strongest area; the gaps were per-step reasoning, citations, the identifier hierarchy, and protocol-level events.*

| AOS element | This document | Status |
| :------------------------------------- | :---------------------------------------- | :----------------------- |
| `steps/agentTrigger`: `trigger.type` (autonomous), `trigger.event`, content | **Trigger Type & Source Event** (§5) | **Covered (new)** |
| `steps/message`: role, content | Model Input (§6); Response (§7); System Prompt (§5) | Covered |
| `steps/message`: `citations` | **Citations / Source Attribution** (§7) | **Covered (new)** |
| `steps/message`: `reasoning` | Observation / Thought (§7) | Covered |
| `steps/toolCallRequest`: `reasoning` | **Tool Selection Rationale** (§9) | **Covered (new)** |
| `steps/toolCallResult`: `executionId`, outputs, `isError` | Tool Call I/O, Tool Error (§9); **Tool Execution ID** (§9) | **Covered (new)** |
| `steps/memoryStore`: memory, `reasoning` | Memory Write (§10); **Memory Write Rationale** (§10) | **Covered (new)** |
| `steps/memoryContextRetrieval`: memory, `reasoning` | Memory Read (§10) | Covered |
| `steps/knowledgeRetrieval`: query, keywords, results | Retrieval Event (§11) | Covered |
| `protocols/MCP`: full JSON-RPC payload | **MCP Server Identity & Primitive** (§9); **Protocol Envelope Capture** (§12) | **Covered (new)** |
| `protocols/A2A`: full JSON-RPC payload | **A2A Task Lifecycle Event**, **Protocol Envelope Capture** (§12) | **Covered (new)** |
| A2A methods: `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`, `tasks/resubscribe`, `tasks/pushNotificationConfig/get`+`/set` | **A2A Task Lifecycle Event** (§12) | **Covered (new)** |
| `ping`: timestamp, timeout, status, version | §15 (see E.1) | **Covered (new)** |
| OTel span hierarchy: `agent.run`, `agent.plan`, turn spans, step spans | **Session / Turn / Step IDs** + **Trace Context** (§5) specify the *identifiers and propagation*; span naming is left to the OTel binding | **Partial**: deliberate; this document is field-level, and span naming belongs in AITF |
| OTel attribute naming: `agent.*`, `llm.model.name`, `llm.provider.name` | This document uses OTel GenAI semconv `gen_ai.*` throughout ([Appendix C](#appendix-c-aitf--odis-cross-reference)) | **Divergence**: see [F.6](#f6-divergences--open-coordination-items) |
| OCSF binding: API Activity 6003, `type_uid` 600301, `actor.type_id: 99` "AI Agent", `unmapped.aos` namespace | [Appendix E](#appendix-e-implications-for-ocsf--aitf-the-standardization-bridge) proposes ratified classes 9001/9002 and an `ai_operation` profile | **Divergence**: see [F.6](#f6-divergences--open-coordination-items) |
| Sensitive-attribute handling ("may necessitate hashing, truncation, or redaction") | [Privacy-preserving logging](#18-implementation-guidance), access control, tiered retention, redaction pipelines, hash-first correlation | Covered (stronger) |

### F.3 Pillar 3: Inspect

*AOS's Inspect pillar requires an agent to answer inspection requests with a dynamically-maintained **AgBOM**, bound to CycloneDX, SPDX, or SWID. This was the largest structural gap: §14 existed, but as a flat set of mostly-MAY attributes attached to events rather than as an inventory artifact, and with no signal at all for composition **change**.*

| AOS element | This document | Status |
| :------------------------------------------------ | :--------------------------------------------- | :------- |
| AgBOM as a queryable, on-demand artifact | **AgBOM / Inventory Snapshot** (§14) | **Covered (new)** |
| Dynamic refresh on discovery / removal / modification of agents, MCP servers, knowledge bases, tools, memory, models | **Capability-Set Change Event** (§14), MUST | **Covered (new)** |
| Entity: Standard Packages, name, description, version | Tool/Agent Version, Repository/Software Ref (§14) | Covered |
| Entity: Models, identity, version, description, endpoint, `modelContextWindow`, arguments | Model Name/Version, Provider/Endpoint Identity (§8); **Inference Parameters** (§8) | **Covered (new)** |
| Entity: Capabilities, agent cards, discovered agents, MCP servers and their protocols | **Peer Agent Card / Descriptor** (§12); **MCP Server Identity & Primitive** (§9) | **Covered (new)** |
| Entity: Knowledge, name, description, schema, search parameters | **Declared Knowledge-Source Configuration** (§11) | **Covered (new)** |
| Entity: Memory, name, description, type, size constraints, retrieval spec | **Declared Memory Configuration** (§10) | **Covered (new)** |
| Entity: Tools, name, description, scheme, local and MCP endpoints | **Tool Definition Digest** (§9); **MCP Server Identity** (§9) | **Covered (new)** |
| CycloneDX `dependencies[].dependsOn` | **Component Dependency Graph** (§14) | **Covered (new)** |
| CycloneDX `signatures[]`: `value`, `keyId` | **Inventory Attestation Signature** (§14) | **Covered (new)** |
| CycloneDX properties: `sandbox`, `languageRuntime`, `environment.os`, `environment.architecture`, `timeoutMs` | **Execution Environment / Sandbox** (§9) | **Covered (new)** |
| CycloneDX properties: `auth`, `scope`, `endpoint` | Tool ACL / Required Scope (§9); Output Egress Destination (§7) | Covered |
| CycloneDX properties: `memoryBackend`, `memoryLimitMB` | **Declared Memory Configuration** (§10) | **Covered (new)** |
| CycloneDX property: `compliance` | Not a distinct field; AITF `compliance.*` carries it ([Appendix C](#appendix-c-aitf--odis-cross-reference)) | Partial |
| SPDX and SWID bindings | **AgBOM / Inventory Snapshot** (§14) is format-agnostic and names all three | Covered (new) |
| CycloneDX property: `a2aCardUrl` | **Peer Agent Card / Descriptor** (§12) | **Covered (new)** |

### F.4 What this implies for OpenTelemetry, AITF and OCSF

Closing the AOS gaps surfaced attributes missing from this document's bindings. All were initially filed against AITF; [Appendix D](#appendix-d-implications-for-opentelemetry-the-instrumentation-bridge) then established that **several already have an upstream home in the OpenTelemetry GenAI conventions**, and that others are answered by OTel's *native structure* rather than by any new attribute. That changes where each ask should be filed.

**The coordination finding: where OTel already defines a name, AITF should adopt it rather than mint a parallel one.** Three of the twelve asks below were substantially resolved upstream while this document was being written, the GenAI conventions gained `gen_ai.tool.definitions`, `gen_ai.tool.call.id`, and an entire `mcp.*` namespace. Filing them again against AITF would create exactly the drift [F.6](#f6-divergences--open-coordination-items) warns about between AOS's `llm.*` binding and semconv's `gen_ai.*`.

| # | Ask | OpenTelemetry today | Where to file |
| :---- | :------------------------ | :---------------------------------------------- | :------------------------------ |
| 1 | **Turn and step identifiers**, plus guidance that the run maps to the trace ID rather than to a session attribute | `gen_ai.conversation.id`, `gen_ai.workflow.name`; **step ordering is already native**: the `invoke_agent` → `execute_tool` → `chat` span tree *is* the step hierarchy, and the span ID *is* the step ID. The **turn** level has no representation | **OTel** (`gen_ai.turn.id`); AITF adopts. Do **not** mint a step-ID attribute, use the span |
| 2 | **Enforcement outcome attributes**: reachability, latency, fail-open/fail-closed, a `modify` decision value, before/after digests | `gen_ai.evaluation.*` exists but is quality-oriented, no blocked/allowed outcome, guardrail type, or threat reference | **OTel** by extending `gen_ai.evaluation.*` ([D.4](#d4-what-cosai-asks-opentelemetry-to-include) item 2); enforcement *availability* to OCSF |
| 3 | **Content-part attributes**: part type, MIME type, attachment name/size/hash | `gen_ai.input.messages` / `gen_ai.output.messages` carry typed parts; **no attachment identity or hash** | **OTel**: extend existing message parts |
| 4 | **Citation attributes** on output, with a resolution flag against retrieval | `gen_ai.retrieval.documents` covers the retrieval side; nothing on the output side | **OTel** |
| 5 | **Tool contract attributes**: definition digest; consistent request↔result correlator | **`gen_ai.tool.definitions` and `gen_ai.tool.call.id` both exist upstream** | **Resolved upstream.** AITF adopts the names; only `…definitions.hash` remains to file with OTel |
| 6 | **Execution-environment attributes**: sandbox mode, runtime, OS/architecture, timeout, egress policy | Runtime and platform are already covered by **core resource conventions** (`host.*`, `os.*`, `process.runtime.*`). **Sandbox mode and egress policy are not** | **Reuse** core resource semconv; file only `sandbox` and egress policy as new |
| 7 | **MCP primitive discriminator**, server version and transport | **A full `mcp.*` namespace exists**: `mcp.method.name`, `mcp.protocol.version`, `mcp.request.id`, `mcp.resource.uri`, `mcp.session.id`, plus client/server duration metrics | **Largely resolved upstream.** `mcp.method.name` partially serves as the discriminator; file only an explicit primitive value set |
| 8 | **A2A attributes**: task lifecycle, push-notification callback registration, peer agent card | **Nothing.** The GenAI repository covers MCP but has no A2A conventions | **OTel**: an `a2a.*` namespace, parallel to `mcp.*`, is the natural proposal |
| 9 | **Trigger attributes**: user-initiated vs autonomous, and source event | Nothing | **OTel** ([D.4](#d4-what-cosai-asks-opentelemetry-to-include) item 6) |
| 10 | **Tenant / organization** | No tenant attribute, but **resource attributes are the established mechanism** for this class of value | **Reuse** resource semconv; propose a tenant attribute only if none fits |
| 11 | **Declared-configuration attributes** for memory and knowledge sources | **No memory namespace at all**; knowledge partially via `gen_ai.data_source.id` | **OTel**: `gen_ai.memory.*` ([D.4](#d4-what-cosai-asks-opentelemetry-to-include) item 3) |
| 12 | **Instrumentation coverage** and **event sequence number** | **Instrumentation scope is native**: every signal carries an emitting scope name and version, which partially answers coverage. **No envelope sequence number**, and no gap-detection concept | Coverage: **reuse** instrumentation scope, extend for hook-level detail. Sequence number: **OCSF**, as an envelope concern rather than an instrumentation one |

**What the pattern shows.** Of twelve asks, two are substantially resolved upstream (5, 7), three are answered wholly or partly by OTel structure that already exists and should be reused rather than duplicated (1, 6, 10, and the first half of 12), and seven remain genuine gaps. The largest single hole is **memory**, which has no representation in any of the three layers.

**Governance.** Per the rule in [E.4](#e4-incremental-extension-path-via-aitf), each item graduates from AITF-proposed to a standardization ask once ≥ 2 independent attacks in [Appendix A](#appendix-a-attack--incident-inventory) require it, a bar every MUST-tier item above already clears. The routing rule that follows from this table: **file emission-side asks with OpenTelemetry, consumption-side asks with OCSF, and use AITF to carry both in the interim** so adopters are never blocked on either body ([D.7](#d7-bridge-design-principles)).

### F.5 What this document contributes back to AOS

The cross reference runs both ways. AOS defines a strong exposure interface but does not answer the questions this document is organized around, and the following are offered as contributions upstream:

1. **Attack grounding.** AOS asserts that agents should be observable; it does not tie any element to a documented attack. [Appendix A](#appendix-a-attack--incident-inventory) supplies a 34-item corpus with per-field evidence.
2. **Priority tiering.** AOS has no MUST/SHOULD/MAY distinction across its event and AgBOM fields, so an implementer has no guidance on what to instrument first. The [classification summary](#45-classification-summary) and [maturity model](#18-implementation-guidance) supply one, with an explicit evidence rule behind it.
3. **MITRE ATLAS technique tagging.** AOS has no threat-classification vocabulary. The [ATLAS Technique Tag](#a5-attack-inventory--mitre-atlas-technique-mapping) makes AOS-derived detections correlate with the ATT&CK-aligned rest of a SOC.
4. **Input trust classification.** AOS captures message `role` (user / agent / system) but not the *trusted-instruction vs untrusted-data* distinction that the CoSAI risk map treats as the core agentic control (§6). This is arguably the single highest-value field AOS lacks.
5. **Output egress destination.** AOS traces messages and tool calls but has no field for *where output went*: recipients, outbound URLs, broadcast scope. §7 argues this is the field that catches `TA-01` and `TA-03` before data leaves.
6. **Delegation and attestation.** AOS's `A2AContext` records the immediate from/to hop but not the originating principal, the multi-hop delegation chain, granted authorizations, or runtime attestation. §13 and the ODIS cross reference in [Appendix C](#appendix-c-aitf--odis-cross-reference) supply these.
7. **Verified vs displayed identity.** `AOC-08`'s lesson (bind and log the immutable identifier, not the display name) applies directly to AOS's user objects and A2A agent cards, which are displayed identities by construction.
8. **Observability-plane integrity (§15).** AOS's own architecture creates the exposure: a synchronous guardian callout is a dependency that can fail or be starved, and a self-reporting agent can omit. AOS specifies the happy path; §15 specifies the telemetry for when it does not hold. This is the contribution most specific to AOS's design.
9. **Privacy and retention normativity.** AOS notes that sensitive attributes "may necessitate hashing, truncation, or redaction." [Privacy-preserving logging](#18-implementation-guidance) gives a concrete position: access control, tiered retention, hash-first correlation, and redaction as an audited, logged transformation.

### F.6 Divergences & open coordination items

Two genuine divergences and two coordination items. None is blocking; all should be reconciled before either document is treated as normative alongside the other.

1. **OCSF strategy.** AOS extends **API Activity (6003)** with an `unmapped.aos` namespace and types the agent as `actor.type_id: 99` ("Other") with `type: "AI Agent"`. [Appendix E](#appendix-e-implications-for-ocsf--aitf-the-standardization-bridge) instead asks OCSF to ratify **AI Agent Activity (9001)** and **AI Delegation Activity (9002)** plus an `ai_operation` profile. These are different bets on the same schema. The positions are reconcilable and arguably sequential. AOS's `unmapped.*` approach is the correct *interim* carrier under an unratified schema, and matches Phase 0 in [E.4](#e4-incremental-extension-path-via-aitf); this document's asks are the ratification endpoint. Worth noting that AOS's need for an `actor.type_id: 99` workaround is independent evidence for standardization ask (6) in [E.3](#e3-what-cosai-asks-ocsf-to-include-summary). **Action:** align on a shared phase plan before either party submits to OCSF.
2. **OpenTelemetry attribute naming.** AOS's OTel binding uses `agent.*`, `llm.model.name`, and `llm.provider.name`. This document and AITF use the OTel **GenAI semantic conventions** (`gen_ai.*`), which is the upstream-maintained namespace; `llm.*` is not current semconv. The divergence is wider than a prefix: AOS's binding predates the GenAI conventions moving to their own repository and gaining `gen_ai.system_instructions`, `gen_ai.tool.definitions`, the retrieval attributes, and a full `mcp.*` namespace; much of what AOS models by hand now has an upstream home (see [Appendix D.2](#d2-what-the-genai-conventions-cover-today)). **Action:** recommend AOS migrate its OTel binding to `gen_ai.*` / `mcp.*`. Low cost while both are drafts, high cost later.
3. **Scope boundary.** This document treats enforcement *outcomes* as telemetry (§15) and the enforcement *protocol* as out of scope. AOS specifies the protocol and is comparatively quiet on outcomes. The split is clean and probably correct, but it is a choice both groups should ratify rather than assume, see [open question 10](#open-questions-for-the-working-group).
4. **Draft status and re-verification.** All AOS pillars are working drafts, with the CycloneDX AgBOM binding explicitly "under development." This cross reference is a point-in-time snapshot and should be re-run before publication, in the same spirit as the [pre-publication verification](#pre-publication-verification-editorial-not-wg-decisions) items for ATLAS and the risk map.

---

## Appendix G: CPEX Cross Reference

[CPEX](https://contextforge-org.github.io/cpex/) is a **deterministic reference monitor between an agent and every capability it invokes**: tools, prompts, resources, inference providers, and A2A methods. It evaluates each operation against security state the model cannot observe or manipulate, and it answers a richer question than allow/deny: *what security pipeline should execute for this operation?*

It occupies a third position relative to the two standards already cross referenced:

| Layer | Question it answers | Artifact |
| :------------- | :--------------------------------------------- | :------------------------------------------ |
| **Requirements** | What telemetry must exist, why, at what priority | This document |
| **Exposure** | How an agent exposes its behaviour for observation | [OWASP AOS](#appendix-f-owasp-aos-cross-reference) |
| **Enforcement** | What policy decides, and what state it decides against | **CPEX** |

The relationship to this document is direct and generative: **CPEX creates the decisions that §16 records.** A reference monitor that mints credentials, tracks information flow, pauses for human approval, and constrains backend selection produces exactly the security events a detection and response programme needs, and none of them existed in this schema until §16. Conversely, CPEX enforces but does not specify what should be *retained*, at what priority, or how it should reach a SOC; that is this document's contribution back.

> **Draft caveat.** CPEX documentation was read at the URLs cited and includes a legacy 0.1.x track alongside current material. Field and function names below are given as encountered; re-verify against the live specification before treating this cross reference as normative.

### G.1 The threat model: the most important contribution

CPEX's [threat model](https://contextforge-org.github.io/cpex/docs/threat-model/) is a zero-trust, assume-breach model whose central move is to treat **the LLM itself as the adversary**, not merely as a component an adversary attacks. Three assumptions:

1. **Input vulnerability**: "Prompt injection can arrive through any content the model reads: user messages, tool results, fetched resources, other agents' replies."
2. **Output manipulation**: "An injected instruction becomes a tool call, an argument value, an email body. **The model is a confused deputy.**"
3. **No security properties**: the model cannot maintain confidentiality or enforce authorization; context contents can leak through permitted channels.

From this follows the trust boundary: everything on the agent side of the monitor is assumed hostile, and **"nothing the policy reads comes from there: verified tokens come from the IdP, decisions from the PDP, taint labels from the session store."**

**Read strictly, the rest of this document operates on a weaker premise, and the gap is not cosmetic.** §§5 to 15 treat the agent as a *victim* of attack (something to be instrumented so that attacks against it become visible. Under CPEX's model the agent is also a potential *liar*, and that distinction propagates straight into the telemetry: several fields this document marks MUST or SHOULD are values the agent itself supplies. **Autonomy Level** (§5), **Task / Intent Declaration** (§12), **System Prompt** (§5), **Observation / Thought** (§7), and every reasoning field are self-asserted. A compromised agent can report a benign autonomy level while acting outside it, and `AOC-01` is the corpus's demonstration that agents do misreport) it declared a secret destroyed while the data remained recoverable.

The document already contained the correct instinct in one place: **Verified vs Displayed Identity** (§13) is MUST precisely because `AOC-08` turns on the difference between an immutable identifier and a spoofable display name. CPEX's contribution is to recognize that identity is not special; *every* security-relevant attribute has a provenance, and telemetry that does not record it cannot survive the assume-breach model. That is the reasoning behind the new cross-cutting **Attribute Source / Trusted-Provenance Marking** ([§16](#16-policy-enforcement--mediation)), and it is the single most consequential change this appendix produced.

A second consequence worth stating: under this model, **denied and failed attempts are first-class telemetry**, not exhaust. CPEX's audit requirement explicitly includes denied attempts. This document was already aligned in spirit (`AOC-12`/`AOC-13`/`AOC-14` are catalogued precisely because their telemetry documents *attempted* attacks that were resisted) but §16's Authorization Decision Record now makes it structural rather than incidental.

### G.2 Threats & controls cross reference

CPEX's threat matrix, mapped to this document's fields. This is the tightest available test of coverage, because each row is a control CPEX considers necessary.

| CPEX threat | CPEX control | Covered by | Status |
| :------------- | :------------------- | :----------------------------------------- | :--------------------------- |
| Prompt-injection tool misuse | Policy gates and argument validation before dispatch | Input Trust Classification, Guardrail (Input) Verdict (§6); Tool Call I/O (§9); **Authorization Decision Record** (§16) | **Covered (new)**: the decision record was missing |
| Confused deputy / privilege escalation | Per-caller identity from verified tokens | Identities Used, Verified vs Displayed Identity, Granted Authorizations (§13) | Covered |
| Cross-request data exfiltration | Session-level taint blocks the write-down | **Session Taint Labels & Information-Flow Decisions** (§16) | **Covered (new)**: expressible as state, not only as a correlation pattern |
| Credential exposure | Fresh audience-scoped tokens minted per call | **Credential Minting & Scope-Narrowing Check** (§13) | **Covered (new)** |
| PII disclosure | Field-level redaction on outputs | Guardrail (Output) Verdict (§7); Guardrail Modification Record (§6); Tool Privacy Classification (§9) | Partial: see [G.5](#g5-divergences--gaps-remaining) on field-level granularity |
| Unauthorized high-impact actions | Out-of-band human approval | **Human Approval / Elicitation Event** (§16) | **Covered (new)** |
| Approval replay | Approvals bound to live arguments | **Human Approval / Elicitation Event**: scope-binding validation result (§16) | **Covered (new)** |
| Unaccountable actions | Append-only audit per decision, denied attempts included | **Authorization Decision Record** (§16); Event Sequence Continuity (§15) | **Covered (new)** |

Five of eight CPEX controls map only to fields in §16; they had **no counterpart** anywhere else in the field set. That is the strongest single finding in this appendix, and it reflects a real blind spot rather than a difference of emphasis: the document was thorough on *observation* and near-silent on *enforcement*.

### G.3 APL, CMF & identity surface

| CPEX element | This document | Status |
| :----------------------------------------- | :----------------------------------------- | :------------------ |
| Effects: `deny` / `deny(reason)` / `deny(reason, code)` | **Authorization Decision Record**: decision, reason, machine-readable code (§16) | **Covered (new)** |
| Effect: `taint(label[, scope])`; session vs message scope | **Session Taint Labels** (§16) | **Covered (new)** |
| Effect: `delegate(...)`, subject `user` / `client` / `caller_workload` / `this_workload` | **Credential Minting & Scope-Narrowing Check** (§13) | **Covered (new)** |
| Effect: `require_approval(...)`; `elicitation.id` / `.status` / `.outcome` / `.approver` / `.channel` | **Human Approval / Elicitation Event** (§16) | **Covered (new)** |
| Effect: `restrict: {allow_models, deny_models, allow_regions, allow_sites, max_cost_tier, custom, on_empty}` | **Backend / Route Restriction Decision** (§16) | **Covered (new)** |
| Effect: `plugin(name)` dispatch | Guardrail Verdict (§§6 to 7); Guardrail Modification Record (§6) | Covered |
| Field pipelines: `mask(N)`, `redact`, `redact(!pred)`, `omit`, `hash`, `pii.redact`, `pii.detect`, `injection.scan` | Guardrail Modification Record (§6); Guardrail (Output) Verdict (§7) | Partial: whole-payload, not per-field |
| Route phases: `args` → `authorization.pre_invocation` → `result` → `authorization.post_invocation` | Action Type (§5); Tool Execution ID (§9) pairs pre/post | Partial: phase identity is not recorded |
| PDP integration: Cedar / CEL / OPA resolvers, `on_allow` / `on_deny` | **Authorization Decision Record**: deciding authority and rule id (§16) | **Covered (new)** |
| `delegation.depth`, `delegation.origin_subject_id`, `delegation.granted.permissions` | Delegation Chain, Originating Principal, Granted Authorizations (§13); scope delta via **Credential Minting** (§13) | Covered |
| Identity slots: `subject` (human), `client` (OAuth app), `caller_workload` (SPIFFE SVID), simultaneously | Identities Used (§13), now explicitly a **set**, not a single value | Covered (clarified) |
| Attribute namespaces `agent.*`, `framework.*`, `subject.*`, `delegation.*`, `security.*`, `http.*`, `data.*` | Mapped to AITF namespaces in [Appendix C](#appendix-c-aitf--odis-cross-reference) | Covered |
| CMF (protocol-agnostic envelope; one policy across tools, A2A, inference, prompts, resources | Action Type (§5); MCP Server Identity & Primitive (§9); Inter-Agent Message (§12) | Partial) see [G.5](#g5-divergences--gaps-remaining) |
| Extension mutability tiers: immutable / **monotonic** / mutable | Monotonicity is asserted for taint and delegation but not recorded | Out of scope: policy-engine internal |
| Capability-gating: plugins declare capabilities; extensions filtered per plugin | Least-privilege for enforcement components | Out of scope: enforcement architecture |
| Deployment placements: gateway / sidecar / in-process, each with named coverage gaps | **Mediation Coverage & Bypass Path** (§16) | **Covered (new)** |
| Builtins: `identity/jwt`, `delegator/oauth`, `validator/pii-scan`, `audit/logger`, `cedar-direct`, `cel`, `valkey` | Named as implementations, not telemetry | Out of scope |

### G.4 What this document contributes back to CPEX

1. **Retention, priority, and evidence.** CPEX produces decision records; it does not say which are worth keeping, for how long, or in what order to adopt them. The [tiering rubric](#42-classification-legend) and [maturity model](#18-implementation-guidance) supply that, with attack grounding behind each call.
2. **A SOC destination.** CPEX's audit log is a local artifact. [Appendix E](#appendix-e-implications-for-ocsf--aitf-the-standardization-bridge) now proposes `ai_authorization`, `ai_taint`, and `ai_approval` OCSF objects plus an `attribute_source` enum, so enforcement decisions correlate with the rest of the security estate rather than sitting in a separate store.
3. **MITRE ATLAS tagging.** CPEX has no threat-classification vocabulary; a denial carries a policy reason, not a technique. Stamping decisions with `AML.Txxxx` ([A.5](#a5-attack-inventory--mitre-atlas-technique-mapping)) makes them correlate with ATT&CK-aligned tooling.
4. **The observation surface CPEX explicitly cannot see.** CPEX mediates the agent↔capability boundary. It does not observe memory reads and writes (§10), retrieval and its provenance (§11), token consumption and loop behaviour (§8, §12), model supply chain (§8), or asset composition (§14). `IR-02` (MINJA) poisons memory using entirely benign queries; every individual operation is policy-clean, and a reference monitor sees nothing wrong. **Enforcement and observation are complementary, not substitutable**, and a deployment running CPEX still needs most of §§5 to 14.
5. **Provider-side and governance signals.** `AOC-06`: silent provider truncation on sensitive topics; is invisible to a reference monitor, since the operation was permitted and completed.
6. **Attack grounding for the threat matrix.** CPEX's threat rows are stated as principles; [Appendix A](#appendix-a-attack--incident-inventory) supplies documented incidents for each, which is useful for justifying the controls to a risk committee.

### G.5 Divergences & gaps remaining

1. **Redaction granularity.** CPEX redacts *per field* under a predicate (`ssn: 'str | redact(!perm.view_ssn)'`); this document's **Guardrail Modification Record** is whole-payload. Per-field records are more useful and more privacy-sensitive at once. Left as-is deliberately (a per-field redaction map is a policy decision, not a default) but implementers running field-level pipelines should record at that granularity.
2. **Route-phase identity is not captured.** CPEX distinguishes four phases, and *which* phase denied an operation is diagnostically meaningful (argument validation vs authorization vs post-check). This document records the decision but not the phase. A candidate sub-attribute of the Authorization Decision Record; not proposed as a separate field.
3. **CMF normalization is an unadopted good idea.** CPEX's Common Message Format lets one policy cover tool calls, A2A, inference, prompts, and resources uniformly. This document still organizes telemetry by *component* (§§5 to 14), which means an equivalent operation is described differently depending on which pipeline carried it. The component organization is deliberate (it maps to the CoSAI Risk Map) but a normalized **operation view** across protocols would make cross-protocol detections expressible. Flagged as [open question 15](#open-questions-for-the-working-group).
4. **Covert channels are out of scope for both.** CPEX states plainly that "determined models can encode data within permitted output channels." This document's **Output Egress Destination** and **Citations** narrow the channel but do not close it. Neither document should claim otherwise.
5. **Host compromise.** CPEX's guarantees "hold only with intact processes and state stores"; this document's §15 covers telemetry suppression but neither addresses a compromised enforcement host. Shared limitation, worth stating in both.
6. **Terminology collision.** CPEX uses *taint* for session-scoped information-flow labels; this document uses *trust classification* for per-segment input labelling. They are different mechanisms and both are needed, §6 classifies a payload, §16 tracks accumulated state. The terms should not be merged, and §16 says so explicitly.

---

## Appendix H: Implications for NIST AI RMF and NIST CSF (incl. the Cyber AI Profile)

Appendices C to E route this field set toward **schemas**; F to G reference it against **adjacent technical standards**. This appendix and [Appendix I](#appendix-i-implications-for-isoiec-42001) address a different consumer: **governance frameworks that use telemetry as control evidence**.

That places them at the **A** end of this document's [use-case priority](#41-use-case-priorities) (compliance audit, the lowest of the four. The ordering is deliberate: **this field set is designed for detection and response, and its audit value is a by-product.** A telemetry programme built to satisfy an auditor produces different fields than one built to catch `TA-01`, and where the two diverge this document follows detection. The useful consequence is that a deployment implementing the MUST tier for **D** and **R** reasons will find it has already produced most of the evidence these frameworks ask for) which is a far easier argument to fund than the reverse.

> **Status caveat.** NIST AI RMF 1.0 (January 2023) is **under revision**. The **Cyber AI Profile** is at *preliminary draft* (**NIST IR 8596**, published 16 December 2025); its comment period has closed and an Initial Public Draft was expected in mid-2026. Structure and identifiers below were read at the time of writing and must be re-verified before publication, see [pre-publication verification](#pre-publication-verification-editorial-not-wg-decisions).

### H.1 Why these two frameworks, and how they differ

| Framework | What it governs | Relationship to this document |
| :-------------------- | :------------------------ | :-------------------------------------------------------- |
| **NIST AI RMF 1.0** (+ **AI 600-1** Generative AI Profile) | AI-specific risk management across **GOVERN / MAP / MEASURE / MANAGE** | Asks *whether AI risks are identified, measured and managed.* This field set is the **measurement substrate**: mostly MEASURE, with MANAGE for response |
| **NIST CSF 2.0** (+ the **Cyber AI Profile**, NIST IR 8596) | Cybersecurity outcomes across **GV / ID / PR / DE / RS / RC** | Asks *whether attacks are detected and responded to.* This is the closer fit by far, the document's D and R priorities map almost one-to-one onto **DE** and **RS** |

The **Cyber AI Profile** is the significant development for this work. It is a CSF 2.0 *community profile* that overlays three **AI Focus Areas** on existing CSF outcomes:

- **Secure**: securing AI systems and their infrastructure.
- **Detect**: using AI to strengthen cyber defence.
- **Thwart**: defending against adversarial *uses* of AI.

**This document sits squarely in *Secure*, and it is the telemetry layer that focus area presupposes.** The Profile asks organizations to achieve CSF detection and response outcomes *for AI systems*; it does not specify which fields make that possible. That is precisely the gap this document fills, and the alignment is close enough that the CoSAI field set is a credible candidate reference for Profile implementers.

### H.2 CSF 2.0 mapping, by function

CSF Categories cited: **GV.OC** Organizational Context · **GV.SC** Cybersecurity Supply Chain Risk Management · **ID.AM** Asset Management · **ID.RA** Risk Assessment · **PR.AA** Identity Management, Authentication and Access Control · **PR.DS** Data Security · **DE.CM** Continuous Monitoring · **DE.AE** Adverse Event Analysis · **RS.MA** Incident Management · **RS.AN** Incident Analysis · **RC.RP** Incident Recovery Plan Execution.

| CSF function | Telemetry that evidences it | Coverage |
| :------ | :----------------------------------------------------------------- | :----------------------------- |
| **GOVERN** (GV.OC, GV.SC) | Asset inventory and AgBOM (§14); model provenance and signing (§8); dependency graph and version (§14); autonomy level and task declaration (§§5, 8) | **Partial**: supply-chain outcomes are well served; policy and role outcomes are organizational, not telemetric |
| **IDENTIFY** (ID.AM, ID.RA) | Agent name, instance ID, surface (§5); capability-set change (§14); AgBOM (§14); tool and MCP inventory (§9); fleet aggregates (§14) | **Strong**: Capability-Set Change is the field that makes ID.AM *continuous* rather than periodic |
| **PROTECT** (PR.AA, PR.DS) | Identities used, verified-vs-displayed identity, granted authorizations, credential minting (§13); authorization decision record (§16); guardrail verdicts (§§6 to 7); sandbox posture (§9) | **Strong**: §§13 and 16 are PR.AA evidence almost verbatim |
| **DETECT** (DE.CM, DE.AE) | **The entire MUST tier.** Input trust classification and guardrail verdicts (§6); output egress and refusals (§7); tool call I/O (§9); memory and retrieval events (§§10 to 11); loop and resource signals (§12); session taint (§16); every [correlation pattern](#17-correlation-patterns) | **Strongest alignment in the document.** DE.CM is continuous monitoring; DE.AE is the correlation-pattern layer |
| **RESPOND** (RS.MA, RS.AN) | The identifier hierarchy and trace context (§5); tool execution IDs (§9); memory and retrieval provenance (§§10 to 11); delegation chain (§13); ATLAS technique tag (§6); event sequence continuity (§15) | **Strong**: this is the document's **R** priority, and the ATLAS tag makes RS.AN findings portable |
| **RECOVER** (RC.RP) | Lifecycle state and revocation (§13); instance ID for per-instance quarantine (§5); capability-set change for rollback verification (§14) | **Weak, and appropriately so**: recovery is largely an operational discipline; telemetry scopes it but does not perform it |

**The pattern is the argument.** Coverage is strongest exactly where this document concentrates (**DETECT**, **RESPOND**) and weakest where its priorities place least weight (**RECOVER**, the organizational half of **GOVERN**). That is not a defect; it is the [D > R > Q > A ordering](#41-use-case-priorities) showing through, and it tells an implementer precisely which CSF outcomes this field set will and will not evidence.

### H.3 AI RMF mapping, by function

| AI RMF function | Telemetry that evidences it | Coverage |
| :---- | :-------------------------------------------------------- | :----------------------------------------- |
| **GOVERN** | Autonomy level (§5); task/intent declaration (§12); tool ACL and scope (§9); human approval events (§16); privacy and retention posture ([Implementation Guidance](#18-implementation-guidance)) | Partial: **Human Approval / Elicitation** (§16) is the strongest single piece of GOVERN evidence, because it records oversight *actually exercised* rather than merely documented |
| **MAP** | Component taxonomy (§§5 to 16 organized by [CoSAI Risk Map](#appendix-b-mapping-to-the-cosai-risk-map-risks-controls--proposed-additions)); AgBOM (§14); trust boundaries (§9); [Appendix A](#appendix-a-attack--incident-inventory) attack corpus | Strong: the risk-map component mapping and attack inventory are MAP artifacts in substance |
| **MEASURE** | **The whole field set.** Every MUST field; guardrail scores; refusal rates; loop and resource metrics; ATLAS-tagged detections | **The natural home.** AI RMF asks that AI risks be measured; this document specifies what to measure and why |
| **MANAGE** | Incident response fields (§§5, 9, 13); enforcement decisions and taint (§16); kill-switch and lifecycle state (§13); [correlation patterns](#17-correlation-patterns) | Strong for security risk; silent on fairness, bias, and environmental risk, which are out of scope here |

**Boundary worth stating.** AI RMF's trustworthiness characteristics extend well beyond security, validity, fairness, bias management, interpretability, environmental impact. **This document evidences the security slice only.** An organization using AI RMF should not read comprehensive MEASURE coverage into it. The `gen_ai.evaluation.*` conventions discussed in [D.2](#d2-what-the-genai-conventions-cover-today) are the natural carrier for the quality and fairness slice, which is one more reason to keep security guardrail signals distinguishable from quality evaluations rather than merging them.

### H.4 What this implies

1. **Propose the field set as a reference implementation for the Cyber AI Profile's *Secure* focus area.** The Profile specifies outcomes for securing AI systems but not the telemetry that evidences them; this document supplies exactly that and is attack-grounded, which is the kind of justification a NIST community profile can cite. **This is the highest-value action in this appendix**, and the timing is favourable while the Profile is between preliminary and public draft.
2. **Publish a CSF subcategory-level mapping.** [H.2](#h2-csf-20-mapping-by-function) maps to Category granularity; auditors work at Subcategory granularity (106 subcategories). A per-subcategory mapping is mechanical work with real adoption value, and it is the single most requested artifact when a security framework meets a compliance programme.
3. **Do not reshape the field set to improve framework coverage.** The weak areas (RECOVER, organizational GOVERN) are weak because they are not telemetry problems. Adding fields to improve a coverage table would violate the [evidence rule](#42-classification-legend) and inflate the MUST tier for **A**-tier benefit.
4. **Track the AI RMF revision.** AI RMF 1.0 is under revision and the Generative AI Profile (AI 600-1) already extends it; if the revision adds agentic content, the [MEASURE](#h3-ai-rmf-mapping-by-function) mapping should be re-checked against it.

---

## Appendix I: Implications for ISO/IEC 42001

**ISO/IEC 42001:2023** specifies an **AI Management System (AIMS)**: a certifiable management-system standard in the ISO tradition, structured as management-system clauses 4 to 10 plus **Annex A**, a normative reference set of **38 controls under nine control objectives, A.2 to A.10**, selected through a **Statement of Applicability (SoA)**.

The relationship differs from every other appendix here, and the difference is the point:

- **NIST frameworks ask whether outcomes are achieved.** Telemetry is evidence.
- **ISO/IEC 42001 asks whether a *management system* exists, operates, and is improved.** Telemetry is evidence *and* the raw material for the monitoring, measurement, analysis and evaluation the standard requires of the system itself.

**42001 is also the only framework here that is certifiable.** That raises the bar on evidentiary quality: an auditor will ask not just whether telemetry exists but whether it is retained, access-controlled, and demonstrably used as an input to management review. That is a records-management property, not a field-selection property, and it is where this document is thinnest.

> **Access caveat.** ISO/IEC 42001 is a paid standard and was not read in full. Control-objective titles below were taken from public summaries; **verify every identifier and title against the purchased standard before relying on this mapping**. Control numbering within each objective (e.g. `A.6.2.8`) is especially error-prone in secondary sources.

### I.1 Annex A mapping

| Annex A objective | Telemetry that evidences it | Coverage |
| :----------- | :----------------------------------------------------- | :------------------------------------ |
| **A.2 Policies related to AI** | System prompt / instruction config (§5) as the enforced expression of policy; authorization decision record and rule identity (§16) | Partial: §16 evidences policy *in force*, which is stronger than a policy document |
| **A.3 Internal organization** | Creator, oncall, ownership metadata (§14) | Weak: organizational, not telemetric |
| **A.4 Resources for AI systems** | AgBOM and dependency graph (§14); model, tool, memory and knowledge inventory (§§8 to 11, 10); token, compute and storage aggregates (§12) | **Strong**: the AgBOM cluster is an A.4 artifact almost exactly; A.4.2 *Resource documentation* and A.4.5 *System and computing resources* are directly served |
| **A.5 Assessing impacts of AI systems** | [Appendix A](#appendix-a-attack--incident-inventory) attack corpus; [Appendix B](#appendix-b-mapping-to-the-cosai-risk-map-risks-controls--proposed-additions) risk mapping; guardrail and refusal rates as realized-impact measures | Partial: supplies the security input to impact assessment, not the assessment |
| **A.6 AI system life cycle** | **Event logs (A.6.2.8) is the direct hit**: §§5 to 16 in their entirety; capability-set change (§14) for change control; verification via evaluation and guardrail records | **Strongest alignment.** 42001 requires event logging without specifying content; this document specifies the content |
| **A.7 Data for AI systems** | Retrieval provenance (§11); memory provenance (§10); input source and trust classification (§6); data classification constraints (§13) | **Strong**: A.7's provenance and quality controls are served by the provenance fields, which exist here for detection reasons and satisfy A.7 as a by-product |
| **A.8 Information for interested parties** | Incident-response evidence (§§5, 9, 13); ATLAS-tagged detections (§6) supporting incident communication | Partial: supplies substance for A.8.4 incident communication; the communication process itself is out of scope |
| **A.9 Use of AI systems** | Autonomy level (§5); task/intent declaration (§12); human approval events (§16); trigger type (§5); surface (§5) | **Strong**: A.9's *intended use* and *responsible use* controls are evidenced by exactly the fields that detect goal drift |
| **A.10 Third-party and customer relationships** | MCP server identity (§9); peer agent card (§12); provider identity (§8); model provenance (§8); delegation chain (§13) | **Strong**: third-party AI dependencies are visible through the tool, MCP, A2A and supply-chain fields |

### I.2 Where this document is thin, and what would fix it

Three of the four weak areas are properly out of scope. The fourth is a genuine gap.

1. **Organizational controls (A.3, parts of A.2, A.8)** are roles, reporting lines and communication processes. Not telemetry. Out of scope, correctly.
2. **Impact assessment (A.5)** is a *process* control. This document supplies inputs; it should not attempt the assessment.
3. **Non-security trustworthiness**: fairness, bias, societal impact under A.5.4 and A.5.5; is outside this document's remit, as it is for [AI RMF](#h3-ai-rmf-mapping-by-function).
4. **Records management is a real gap.** 42001 clause 7.5 (documented information) and clause 9 (monitoring, measurement, analysis and evaluation; internal audit; management review) require telemetry to be *retained, controlled, and demonstrably used*. This document specifies retention tiers and access control in [Implementation Guidance](#18-implementation-guidance) but does not specify **evidentiary properties**: immutability, defined retention periods per field class, chain of custody, or reviewer access records. §15's **Event Sequence Continuity** is the nearest thing and is SHOULD. **Recommendation:** if CoSAI wants this field set to be usable as certification evidence, the retention guidance should be promoted from prose to a normative table with per-tier retention minimums.

### I.3 What this implies

1. **Position the field set as the content specification for A.6.2.8 (event logs).** 42001 requires event logging across the AI life cycle without saying what to log. This is the clearest single fit between the two documents, and (as with the Cyber AI Profile) it lets an organization satisfy a standard using telemetry it built for detection.
2. **Map to Statement of Applicability granularity.** SoA is where 42001 implementation happens. A mapping at individual-control level (A.6.2.8, A.7.4, A.9.3 …) rather than objective level would let an organization cite specific fields per control. Same recommendation, and same mechanical-but-valuable character, as the CSF subcategory mapping in [H.4](#h4-what-this-implies).
3. **Close the records-management gap** if certification evidence is a goal, see [I.2](#i2-where-this-document-is-thin-and-what-would-fix-it) item 4. This is the one place where a compliance framework surfaces a genuine weakness rather than an out-of-scope boundary.
4. **Reuse, do not re-derive.** ISO/IEC 42001 and NIST AI RMF overlap substantially; organizations frequently run both. The mappings in [Appendix H](#appendix-h-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile) and here should share a single underlying field→control table with two views, rather than diverging.

> **The through-line for both appendices.** These frameworks are **consumers** of this telemetry, not designers of it. The document's value to them is that a field set built to catch documented attacks turns out to evidence a large share of what they ask for, and that the evidence carries attack grounding, which is more defensible under audit than a control asserted to exist. The direction of derivation should not reverse: **do not add fields to improve a coverage table.**

---

---

## Appendix J: Tiering Rationale

Why each component's **MUST** fields earn that tier, and where the tier boundaries were contested. Ordered to match the [classification summary](#45-classification-summary): §5 through §16.

The rubric is in [§4.2](#42-classification-legend). Two things it implies recur below and are worth stating once. **Attack count alone does not set the tier**: a field cited by five attacks stays SHOULD if all five presuppose an edge modality such as delegation. And **the highest-priority use case governs**: a field whose dominant value is Q or A does not reach MUST however useful it is.

### J.1 Application & Agent Reasoning Core (§5)

Every MUST here is an identifier or execution-context anchor that later sections' detections resolve *through*: ≥3 corpus attacks apiece, no modality precondition, **D and R jointly**. *What ran and where*: Agent Name, Instance ID, Surface (D: off-inventory agents; R: quarantining one instance while siblings run, per `AOC-04`, `AOC-05`). *What else belongs to this incident*: Workflow/Run ID, Session/Turn/Step IDs, Trace Context. *What it did and how it ended*: Action Type (the think→act boundary where `AOC-01` and `AOC-02` did their damage) and Execution Status. *What it was configured to do*: System Prompt, both a config-integrity baseline and the reference against which extraction is detected (`TA-07` succeeds when the response reproduces it). *Who started it*: Trigger Type.

- **The identifiers are a hierarchy, not a bag.** Instance → Run → Session → Turn → Step, threaded by Trace Context. `TA-08` (tool-chaining escalation) and `IR-01` (iterated reframing until a refusal flips) are *within-session, across-turn* patterns invisible at run granularity.
- **Trigger Type is MUST because zero-click is a telemetry category.** `TA-01` starts an entire run from one inbound email with no human in the loop. Surface/App would record "email" for both that and an ordinary request; the autonomous flag is what separates them.
- **Autonomy Level is SHOULD**: the oversight dial for delegated action. The corpus repeatedly shows agents operating *above* their intended autonomy (`AOC-04`, `AOC-01`, `AOC-07`); logging the claimed level is what makes that detectable.
- **Organization / Tenant ID is SHOULD.** No corpus attack demonstrates cross-tenant agent leakage, and multi-tenant hosting is a deployment modality. **MUST for any multi-tenant deployment**, and the strongest promotion candidate if such an incident enters the corpus.

### J.2 Input Handling & Trust Provenance (§6)

The densest evidence in the document: Model Input cited by **7** attacks, Input Trust Classification and Source IP by **5** each, Input Source and Guardrail (Input) Verdict by **4**. All **D-primary**: these are the fields an injection or jailbreak detection actually fires on, with strong secondary R value. None presupposes an unusual modality.

- **Model Input** must cover *all* inputs, not the first user turn: injection arrives via tool outputs (`IR-01`), retrieved content (`IR-03`, `TA-01`, `TA-02`), memory (`IR-02`), or another agent (`AOC-12`).
- **Input Trust Classification** operationalizes the risk map's core agentic control. `AOC-02` disclosed 124 email records because it did not distinguish an owner instruction from a non-owner's; `TA-01` is untrusted email content promoted to instruction.
- **Guardrail (Input) Verdict** is MUST because `TA-01` *defeated* a prompt-injection classifier. A classifier bypass is undetectable if verdicts are never logged.
- **Content Modality & Attachment Identity** is MUST because the corpus's obfuscation attacks are modality attacks, instructions in OCR'd images and base64 blobs (`AOC-12`), ~10 MB attachment floods (`AOC-05`). Text-only capture misses both.
- **ATLAS Technique Tag** is MUST *when a detection fires*. It is derived, not raw; its value is D-portability into ATT&CK-aligned tooling plus A-rollup.
- **Guardrail Modification Record is SHOULD.** No corpus entry turns on an enforcement point rewriting a payload, and inline mutation is an emerging modality. Its value is R and A rather than D. The argument for it remains strong; logging only pre-modification content makes the forensic record *actively wrong*: so it is **MUST wherever enforcement points or redaction pipelines can mutate content**.

### J.3 Output Handling, Egress & Refusals (§7)

Output is where damage becomes irreversible, so these are **D-primary with the shortest time-to-value**. Response (**6**) and LLM Refusal (**7**) are the most-cited fields after Model Input. Output Egress Destination (**5**) converts a detection from *"something bad was generated"* into *"and here is where it went"*: the difference between blocking and reporting.

- **Output Egress Destination** would have caught `TA-01` and `TA-03` *before data left*: both smuggle data into an outbound URL on a trusted-looking domain. It also renders `AOC-03`, `AOC-11`, and `AOC-05` visible.
- **LLM Refusal** is an early-warning tripwire. `IR-01` is iterated reframing until a refusal flips; `AOC-12/13/14` are the mirror image, successful refusals whose telemetry documents attempted attacks even when blocked.
- **Citations** is MUST only for deployments that emit them, which is now the common RAG configuration. A citation is a *trusted* output component (`AML.T0067.000`), so three detections depend on it and none is reachable from response text alone: fabricated citations matching no retrieval, attacker-planted links (`TA-02`, `TA-01`), and suppression visible by comparing retrieved against cited (`IR-03`).
- **Observation / Thought is SHOULD**: high-value forensics for separating a compromised agent from a misconfigured one (`AOC-01`, `AOC-07`), but frequently unavailable from provider APIs and privacy-sensitive.

### J.4 The Model & Model Serving (§8)

Four MUSTs, each ≥3 attacks and each D-primary. Model Name + Version is the supply-chain pivot (*which agents used the compromised model*) and is R-critical for scoping. Token Counts is the cheapest DoS and runaway-loop detector in the document (`AOC-04`'s ~60 k-token relay, `AOC-05`, `TA-10`) and costs nothing to emit. LLM Error fires precisely under adversarial conditions.

- **Inference Parameters** rest on a *denominator* argument rather than a tampering attack: "max-length output" (`TA-04`) and "anomalously large input" (`TA-10`) are the documented detection signatures, and neither is computable without `max_tokens` and the declared context window. They also give decoding configuration the integrity baseline §5 gives the system prompt. Capture per-call, per-request overrides are the attack.
- **Model Provenance / Signing is SHOULD** (supply-chain, ties to model-signing work and ODIS `software_hash`). **Pre-Forward-Pass State** and **Token Malformation** are MAY research-grade signals.
- **Provider / Endpoint Identity is MAY**: the only field demoted two tiers. It rested on one attack, `AOC-06`, which this document's own mapping calls a governance and availability signal rather than a discrete adversary technique. That makes it Q- and A-dominant; the D concern, model substitution, is carried by Model Name + Version. *Implementer caveat:* the **finish / stop reason** was bundled into this field and should not be demoted with it; it belongs with Execution Status (§5), which is MUST.

### J.5 Tools & External Services (§9)

The highest-value **R** fields in the document and strong D besides. Tool Call I/O (**7**) and Tool Name (**6**) are the richest-evidenced here: without them a compromised agent's actions are invisible, and every destructive case in the corpus is reconstructed from them.

- **Tool Type / Trust Boundary** earns MUST via `AOC-14`, which tried to make the agent bypass the tool API and write to backend storage directly. "API-mediated only" is unenforceable unless telemetry distinguishes the two.
- **Execution Environment / Sandbox** is MUST because `TA-06` is characterized as model-emitted Python executed **unsandboxed**: the isolation posture *is* the finding. Two calls to the same code-execution tool, one containerized and one not, are otherwise the same event.
- **Tool Execution ID** makes *a result with no matching request* a queryable condition, and is the only way to correlate asynchronous tool calls. `AOC-01`'s false completion report is precisely a request/result mismatch.
- **Tool ACL / Required Scope stays SHOULD**: five attacks cite it, but every one presupposes meaningful delegation.
- **Tool Definition Digest and MCP Server Identity & Primitive are SHOULD**, and both demotions expose a **corpus gap rather than a weak field**. No catalogued attack is a tool-definition rug-pull, and the corpus contains no MCP-specific attack at all (`TA-06` is LangChain). Both are **MUST for deployments consuming third-party or dynamically-discovered tools**. MCP server name and version are as cheap as Tool Name and should be adopted first.
- **Tool Privacy Classification is MAY**: DLP and compliance governance metadata, A-dominant, and not modality-gated. Its D value is already carried by Tool ACL/Scope and Output Egress.

### J.6 Memory (§10)

Persistent memory is the one component where an attack **outlives the session that planted it**, which is what earns MUST at comparatively low attack counts: a poisoned item silently shapes every future run, so the detection window is unbounded.

- **MINJA (`IR-02`)** poisons memory using only benign queries, the agent autonomously persists malicious reasoning. **AGENTPOISON (`IR-05`)** uses optimized triggers. Neither is detectable without Memory Write/Read plus **Provenance**.
- **Memory Provenance** is the field that exposes `AOC-10`: a "constitution" stored as an externally editable Gist, later edited to make the agent shut down peers and send unauthorized mail. The signal is *a context-shaping memory item resolving to a mutable, non-owner-controlled source.*
- **Memory Footprint** catches `AOC-05` (ever-growing per-non-owner file → mail-server DoS). At **2** attacks it clears the bar on the "especially useful for D" clause, not on count.
- **Memory Write Rationale is SHOULD**: the analogue of Tool Selection Rationale, and `IR-02` is the case demanding it: the content looks innocuous and the write unremarkable; the tell is the justification the agent gives itself.
- **Declared Memory Configuration is MAY.** The silently-raised-limit scenario is absent from the corpus, and its job (a baseline for Memory Footprint) can be met by hard-coding known limits.

### J.7 Retrieval & Content (RAG) (§11)

Two fields, **5** and **4** attacks, both D-primary. RAG is the document's most-cited injection channel (`TA-01`, `TA-02`, `TA-09`, `IR-03`, `AOC-10` are all retrieval-mediated) and the two answer the halves a detection needs: *what came back*, and *where it came from and when it changed*.

- **Retrieval Event + Source/Provenance** connect "what was retrieved" to "what the model then did." Neither is sufficient alone.
- **Poison-RAG (`IR-03`)** manipulates item *metadata tags* rather than content bodies, which is why the integrity signal must cover metadata. **`TA-09`** plants hidden instructions in wikis and tickets, and recently-modified retrievable documents deserve scrutiny, hence freshness folds into provenance.
- **Declared Knowledge-Source Configuration is MAY**, on the same reasoning as its memory counterpart: a silently altered retrieval config or repointed index is not in the corpus, and `IR-03` poisons metadata, not search configuration.

### J.8 Orchestration, Multi-Agent & Background Execution (§12)

The sharpest tiering judgment in the document, because multi-agent orchestration sits close to the SHOULD boundary by definition. The four MUSTs are the ones whose signal is **protocol-independent**: emittable by any orchestrator, with no A2A stack, delegation model, or agent registry.

- **Inter-Agent Message** is the substrate of cross-agent propagation: `AOC-04` (nine-day mutual-relay loop), `AOC-09` (capability transfer), `AOC-11` (mass broadcast), and `AOC-16`: the positive case, agents sharing risk signals.
- **Background / Scheduled Task** captures the corpus's most striking finding: agents spawning infinite shell loops and cron jobs with **no termination condition**, converting short-lived tasks into permanent infrastructure (`AOC-04`, `AOC-10`). With **Loop / Step-Count** it clears the bar on D value rather than attack count.
- **Task / Intent Declaration is SHOULD**: the goal-drift anchor; `AOC-04` shows agents inventing new goals beyond the requested task.
- **A2A Task Lifecycle and Peer Agent Card are SHOULD.** Their evidence is generic multi-agent incidents, not A2A-protocol incidents, `AOC-04/09/11` predate A2A entirely. Both are **MUST the moment A2A or agent cards are in play**; push-notification configuration in particular registers an attacker-settable egress channel.
- **Protocol Envelope Capture is MAY**: Q-dominant, duplicates interpreted fields, carries raw-content privacy weight, and is not modality-gated.

### J.9 Identity, Delegation & Attribution (§13)

The archetype for the MUST/SHOULD split, and it survived the audit unchanged. Two fields are MUST because they apply to **every** deployment, including the simplest single-agent one.

- **Identities Used** (**7** attacks, tied for most-cited) is the accountability primitive: when an agent resets its own mail server (`AOC-01`), dumps 124 records (`AOC-02`), or mass-mails defamation (`AOC-11`), *which principal, which agent, which tool, which credential* is the first question of any response.
- **Verified vs Displayed Identity** is MUST on a precise D argument rather than volume. `AOC-08` shows same-channel spoofing *detected* (the agent checked an immutable user ID) and cross-channel spoofing *succeeding* where only a display name was available. The difference between those outcomes is entirely a telemetry difference.
- **Everything below is SHOULD by construction, not by weak evidence**: several carry 3 attacks, which on count alone would qualify. Each presupposes **delegated authority**: an originating principal distinct from the caller, a chain of prior hops, monotonically narrowing scopes, cryptographic attestation, or a revocation lifecycle. A deployment without cascaded delegation has nothing for them to describe. The corollary matters as much: a deployment that *does* run cascaded delegation should treat this entire section as mandatory on day one. SHOULD means "not universal," never "defer."
- **Trust-Domain Crossing & Delegation Depth** is the field that makes an **externally-operated** counterparty legible. ODIS treats `trust_domain` and `max_depth` as policy-engine inputs rather than telemetry, which is right only while a chain stays inside one domain. Once authority crosses out of the domain that issued it, or the acting agent sits several hops from the originating principal, both become detection-grade: `AOC-04`'s nine-day relay and `AOC-09`'s capability transfer are both depth phenomena, and `TA-11` is a domain-boundary failure. See [§4.7](#47-agents-you-do-not-operate).
- **Credential Minting & Scope-Narrowing** adds the *event* the surrounding fields only describe the state of. Forwarding a caller's inbound token is usually wrong (it is scoped for the agent, not the backend) so the **requested-vs-granted delta** is what makes a silently over-broad grant visible (`TA-08`).

### J.10 Asset Inventory & Fleet Aggregates (§14)

One MUST in a section otherwise SHOULD and MAY, and the reason is categorical: every other field here describes a **state**, while **Capability-Set Change Event** describes a **transition**, and transitions are where attacks are visible.

- Grounded directly in `AOC-09`, where one agent teaches another to acquire a browser/download capability. The security event is the *acquisition*; the previous inference path ("tool-call spike + new Tool Name") fires only once the capability is exercised, and never at all for one acquired and held in reserve. Removal matters symmetrically: a guardrail tool or logging sink quietly dropped is a defence-evasion signal. It is also cheap where least expected to fire: a static capability set emits nothing.
- **Version and Repository / Software Ref are SHOULD** as supply-chain response primitives. **Version is the closest call in the audit**: 2 attacks and genuine R value (CVE blast radius), held below MUST because that value is realized through a fleet-inventory process rather than per-event detection, and because it is inseparable in practice from the AgBOM cluster. The WG may reasonably promote it.
- **The AgBOM cluster is SHOULD**: it requires an inventory-emission capability most deployments lack. Within it: **Component Dependency Graph** is the complete answer to CVE blast radius, since `TA-06` is a vulnerability in a *framework* beneath the agent and reaching it requires transitive edges; **Inventory Attestation Signature** matters because an inventory a compromised agent can rewrite is worth little, with the limit that a signature proves who asserted the inventory, not that the assertion is true, which is §15's subject.

### J.11 Observability-Plane Integrity (§15)

**This section has no MUST, and the reason is a corpus gap rather than a judgment about value.** No attack in [Appendix A](#appendix-a-attack--incident-inventory) targets the observability plane: not one of the 34 catalogued incidents starves an enforcement point, disables instrumentation, or suppresses events. Every field here is grounded *analogically*: the corpus establishes the capability exists (`TA-10` proves resource pressure against AI infrastructure is achievable; `TA-01` proves the payoff of defeating a classifier) without containing an instance. Under the rubric that is SHOULD, and the section is additionally modality-gated on an inline enforcement architecture.

That absence is itself a finding, and probably a **collection artifact**: attacks on telemetry are under-reported precisely because the telemetry that would reveal them is what was attacked. Two developments narrow the gap without closing it: CoSAI's MCP Security paper names **Invisible Agent Activity**: agents operating covertly while mimicking valid workflows (as an MCP threat class, and the CoSAI Risk Map now carries `riskAuditTrailTampering` with an ATT&CK anchor (*Disable or Modify Tools*, T1685). Neither is a catalogued incident, so neither satisfies the evidence rule, but both establish that the scenario is recognized outside this document. This is the section most likely to be re-tiered upward) see [open question 12](#open-questions-for-the-working-group).

- **Enforcement-Point Availability & Failure Mode** remains the highest-leverage field here, the first to adopt and the first to promote. A verdict that never arrived and a verdict of `allow` are indistinguishable in the log, which makes the control plane a single point of silent failure. Fail-open is often the correct availability posture; it is only acceptable if it is *recorded*.
- **Instrumentation Coverage** resolves the ambiguity undermining every absence-based detection in the document; no refusal, no termination condition, no matching request are each only interpretable if the relevant hook was instrumented.
- **Event Sequence Continuity** is the minimum defence against selective suppression by a compromised agent: sequence numbers make omission visible as a gap rather than invisible as silence.
- **Policy Reason Code is MAY**: A-dominant reporting convenience, not modality-gated, and the underlying decision is already captured by Guardrail Verdict and classified by the ATLAS tag.

### J.12 Policy Enforcement & Mediation (§16)

Two of six are MUST, and both are universal rather than modality-gated.

- **Authorization Decision Record** fills a structural hole the rest of the field set has by construction. The document logged what a *content classifier* concluded (Guardrail Verdict, §§6 to 7) and what authority a tool *requires* (Tool ACL/Scope, §9), but never what the authorization layer **decided**, on which rule, or why, so a denied operation and a never-attempted one were indistinguishable. Four attacks turn on that record: `AOC-02` (non-owner compliance), `AOC-08` (privileged action after spoof), `AOC-10` (injected authority), and `TA-08` (individually-authorized calls escalating in aggregate; visible only if each link's decision and rule are recorded). D and R jointly.
- **Attribute Source / Trusted-Provenance Marking** is the zero-trust principle applied to telemetry itself, and it earns MUST because it determines whether the rest of the schema can be believed. The document already applies the idea once (Verified vs Displayed Identity (§13)) and the generalization is that identity is not the only attribute an agent can assert. Autonomy Level, Task Declaration, System Prompt, and every reasoning field are agent-supplied, and `AOC-01` is the corpus's proof that agents *do* report falsely: it declared a secret deleted while the data remained recoverable. Cost is an enum per attribute group, not per event.
- **Session Taint Labels is SHOULD**, and is a genuinely different mechanism from §6's Input Trust Classification: that classifies a segment of one payload, while taint is **state accumulating across a session** that survives into operations whose own content is clean. That distinction is the whole attack in `TA-01` and `TA-02`, where the exfiltrating request is innocuous in isolation. Of everything in SHOULD this has the highest D value per unit of effort.
- **Human Approval / Elicitation is SHOULD** and covers the control the corpus most often shows *missing*: `AOC-01`, `AOC-07`, and `AOC-11` are all irreversible actions taken without human authorization. **MUST wherever irreversible or high-impact actions are reachable.** Two sub-signals matter: approver identity must come from the identity provider, not the agent's claim; and approval scope must be re-validated against the arguments actually presented, or one sign-off can be replayed against a larger action.
- **Mediation Coverage & Bypass Path is SHOULD**: the enforcement counterpart to §15's Instrumentation Coverage. §15 asks *is the telemetry complete?*; this asks *is the enforcement unbypassable?* `AOC-14` is precisely this attack. A control that can be routed around is not a control.
- **Backend / Route Restriction is SHOULD.** Paired with taint it is a D signal; standing alone it is closer to A (data-residency evidence) and Q.

---

## Attack taxonomy: MITRE ATLAS is canonical

**Resolved.** This is a decision of the document, not an open question.

**MITRE ATLAS `AML.Txxxx` is the canonical adversary-technique taxonomy for this field set. The CoSAI `AT10xx` codes are formally deprecated to aliases.**

What that means in practice:

1. **Every technique reference is an ATLAS ID.** Detections, the [Threat Classification / ATLAS Technique Tag](#6-input-handling--trust-provenance) field (§6), compliance rollups, and all attack mappings in [Appendix A](#appendix-a-attack--incident-inventory) use `AML.Txxxx`. Where a technique has a sub-technique that fits, the sub-technique is preferred (`AML.T0051.001` over `AML.T0051`).
2. **`AT10xx` codes are retained for one purpose only**: reading existing CoSAI material. They appear in [Appendix A.4](#a4-attack-taxonomy-cosai-at10xx-codes-deprecated-aliases-to-mitre-atlas) as an alias table and in the `IR-` case-study rows that historically cited them. **New material must not introduce `AT10xx` codes**, and they should not appear in emitted telemetry.
3. **No CoSAI-only technique numbering is maintained going forward.** If a technique has no ATLAS equivalent, the correct response is to propose it upstream to ATLAS, not to mint a local code. Where no anchor currently exists, the mapping records the nearest ATLAS technique and flags the judgment, as [A.5](#a5-attack-inventory--mitre-atlas-technique-mapping) does for `AOC-06`.

**Why.** ATLAS is community-maintained, versioned, and ATT&CK-aligned, so a detection tagged `AML.T0051` correlates with the rest of a SOC's ATT&CK-based tooling without translation. It is already a first-class compliance framework in AITF (`compliance.framework = mitre_atlas`), so the tag has a binding today. And a parallel CoSAI numbering would need its own maintenance, governance, and mapping table for no benefit that ATLAS does not already provide, the alias table in A.4 exists to *retire* that burden, not to institutionalize it.

**Scope of the deprecation.** This decision binds this document. The CoSAI AI-Incident-Response material that originated the `AT10xx` labels is owned by another workstream; the recommendation to that group is to adopt the same position, and [A.4](#a4-attack-taxonomy-cosai-at10xx-codes-deprecated-aliases-to-mitre-atlas) is written to be usable as the migration table if they do.

> **Maintenance obligation.** ATLAS is versioned and periodically adds GenAI and agentic techniques. Every `AML.Txxxx` in [A.4](#a4-attack-taxonomy-cosai-at10xx-codes-deprecated-aliases-to-mitre-atlas) and [A.5](#a5-attack-inventory--mitre-atlas-technique-mapping) must be re-verified against <https://atlas.mitre.org/> at publication and at each revision. Adopting an external taxonomy trades local control for portability; the cost of that trade is this recurring check, and it is now a standing item in [pre-publication verification](#pre-publication-verification-editorial-not-wg-decisions).

## Open questions for the working group

Each item is a decision the document *takes a position on* but that requires working-group ratification or resolves a cross-standard tension. Ordered by consequence.

> **Resolved, no longer open.**
>
> - **Attack-taxonomy adoption.** *Resolved in favour of adoption.* MITRE ATLAS `AML.Txxxx` is the canonical technique taxonomy for this document, and the CoSAI `AT10xx` codes are formally deprecated to aliases. See **[Attack taxonomy; MITRE ATLAS is canonical](#attack-taxonomy-mitre-atlas-is-canonical)** for the decision and its scope, and **[A.4](#a4-attack-taxonomy-cosai-at10xx-codes-deprecated-aliases-to-mitre-atlas)** for the migration table. Two consequences carry forward rather than closing: the recommendation that the AI-Incident-Response workstream adopt the same position, and the standing obligation to re-verify every `AML.Txxxx` against the live ATLAS matrix at each revision.

1. **OpenTelemetry submission (and the sampling problem.** Does CoSAI file the [Appendix D.4](#d4-what-cosai-asks-opentelemetry-to-include) asks with the OTel GenAI conventions working group, paired with their [E.3](#e3-what-cosai-asks-ocsf-to-include-summary) OCSF counterparts? The conventions are all at *Development* status and have just moved to a dedicated repository, so the window is favourable and closing. Two decisions inside this: (a) whether to seek a **security guardrail signal by extending `gen_ai.evaluation.*`** or by minting a separate namespace) the former is likelier to be accepted, the latter is cleaner; (b) whether this document should make the [D.6](#d6-context-propagation-sampling--privacy-three-operational-traps) **sampling requirements normative**: that security-relevant events are never head-sampled and that the sampling configuration is itself logged. Default OTel sampling will silently discard most attack evidence, which makes this arguably the highest-impact operational statement in the document, and it currently sits in an appendix rather than in [Implementation Guidance](#18-implementation-guidance).
2. **OCSF standardization path & ownership.** Does CoSAI formally submit the [Appendix E](#appendix-e-implications-for-ocsf--aitf-the-standardization-bridge) asks (AI Agent Activity (9001), AI Delegation Activity (9002), an `ai_operation` profile with the MUST tier as *required*, the new objects/enums, and ATLAS-on-findings) to OCSF via AITF? If so, what is the phase sequence (C.4) and who owns each submission? This is the bridge's central next action.
3. **Content-capture default.** Should the standard *mandate* hash-first + optional raw + redaction flags as the default representation for all content-bearing fields (Model Input, Response, System Prompt, Memory, Retrieved Content), rather than leaving raw-vs-hash to deployment policy?
4. **Chain-of-thought tier.** A specific case of (3): keep `Observation/Thought` at **SHOULD**, or promote to **MUST-when-available but redaction-gated** given its forensic value in `AOC-01`/`AOC-07`/`IR-02`?
5. **Trust-classification vocabulary.** Ratify the proposed `trust_level` enum (trusted-instruction / trusted-data / untrusted-data / adversarial-suspected) from [Appendix E.3](#e3-what-cosai-asks-ocsf-to-include-summary), or revise it? (Reframed: the doc now proposes this enum, so the open item is ratification, not whether to have one.)
6. **ODIS emission point.** Which delegation/identity fields are emitted as *telemetry* vs only presented to the *policy engine*? This doc proposes emitting the delegation chain + granted authorizations + attestation as telemetry; ODIS §6.4 treats them as policy-engine input. Alignment needed.
7. **Component tagging.** Should events carry an explicit `component_id` (risk-map) tag so the component mapping is machine-checkable for fields that span components (e.g. Identities Used), aligning with the risk-map ontology effort?
8. **Scope boundary for governance signals.** Is provider-policy / availability / governance telemetry in scope for a *detection-and-response* spec, or does it belong to a separate governance/compliance track? `AOC-06` (provider-side silent truncation) maps only awkwardly to an adversary technique (`AML.T0048` External Harms) and is fundamentally a governance/availability signal, not an attack. The WG must decide whether such signals stay first-class here, are delegated to the AITF `compliance.*` / `quality.*` namespaces, or are declared out of scope.
9. **Relationship to OWASP AOS.** Does CoSAI formally position this document as the **requirements layer** to AOS's **exposure layer**, as [Appendix F](#appendix-f-owasp-aos-cross-reference) proposes, with a liaison to submit the [F.5](#f5-what-this-document-contributes-back-to-aos) contributions (trust classification, egress destination, ATLAS tagging, tiering, delegation, observability-plane integrity) upstream? Related and more urgent: **the two documents currently propose different OCSF strategies** ([F.6](#f6-divergences--open-coordination-items) item 1). Aligning before either submits is cheaper than reconciling after.
10. **Is the observability plane itself in scope?** [§15](#15-observability-plane-integrity) asserts that enforcement availability, fail-open behaviour, instrumentation coverage, and event continuity are security telemetry, while the enforcement *protocol* is not. That line is defensible but it is a genuine scope expansion, the document now specifies telemetry about the telemetry system. Ratify, narrow, or reject. A narrower alternative: keep only **Enforcement-Point Availability & Failure Mode** as MUST and move the remaining three fields to a pipeline-integrity annex.
11. **Content-bearing additions and the privacy default.** Three new fields carry content or near-content: **Citations** (URLs and document identity), **Protocol Envelope Capture** (raw payloads), and **Content Modality & Attachment Identity** (filenames and hashes). Open question 3's hash-first default should be resolved for these explicitly; attachment *hashes* are the correlation primitive and are low-risk, but filenames and citation URLs can themselves be sensitive.
12. **Corpus gaps, two of three now closed; re-run the affected tiers.** Fields sat below the tier their reasoning would justify because [Appendix A](#appendix-a-attack--incident-inventory) held **no documented instance** of the attack they detect. `TA-11` to `TA-13` ([B.5](#b5-corpus-additions-the-mcp-paper-makes-available)) close the cross-tenant and MCP-mediated-exploitation gaps. The WG should now decide whether **Organization / Tenant ID** (§5), **MCP Server Identity & Primitive** (§9), and **Tool Definition Digest** (§9) move to MUST, noting that the modality gate still applies independently of the evidence gate, a single-tenant, non-MCP deployment gains nothing from any of the three. The remaining open gap is stated below. Three gaps, each of which would change a tier if filled: (a) **MCP tool poisoning / definition rug-pull**: a well-documented real-world class absent from the inventory, currently holding Tool Definition Digest and MCP Server Identity at SHOULD; (b) **attacks on the observability plane**: enforcement starvation, instrumentation disablement, event suppression; whose absence leaves §15 with no MUST at all, and which is plausibly a *collection artifact*, since such attacks are under-reported precisely because they disable the telemetry that would reveal them; (c) **cross-tenant agent leakage**, currently holding Organization/Tenant ID at SHOULD. **Recommendation:** task the corpus maintainers with searching deliberately for these three, and re-run the tier assignments. This is a cheaper and better-grounded path to a larger MUST tier than relaxing the evidence rule.
13. **Should the evidence rule admit analogical grounding?** Related to (12) but distinct. Several SHOULD fields are motivated by a *mechanism* the corpus demonstrates, applied to a surface it does not yet cover; resource pressure is proven achievable (`TA-10`), so enforcement-point starvation is plainly feasible even though no one has catalogued it. The document currently requires a **documented instance**, which is conservative and keeps the MUST tier defensible, but systematically lags real-world attack development in a fast-moving area. Options: keep the strict rule; admit analogical grounding at SHOULD only (the current de facto position, now stated explicitly in the [legend](#42-classification-legend)); or create a time-boxed **PROVISIONAL-MUST** for fields with strong mechanism arguments awaiting corpus confirmation.
14. **Adopt the assume-breach premise document-wide?** [Appendix G.1](#g1-the-threat-model-the-most-important-contribution) argues that CPEX's threat model is stronger than the one this document has implicitly used: the agent is not only a target but a potential **liar**, so any self-asserted attribute is untrustworthy. §16's **Attribute Source / Trusted-Provenance Marking** applies that as a cross-cutting MUST. The WG should decide whether to go further and **re-examine every field for self-assertion risk**: several current MUST and SHOULD fields (Autonomy Level, Task/Intent Declaration, System Prompt, all reasoning traces) are agent-supplied, and arguably each should carry an explicit caveat rather than relying on the cross-cutting marker.
15. **Should the document adopt a normalized operation view?** CPEX's Common Message Format lets one policy cover tool calls, A2A, inference, prompts, and resources uniformly. This document organizes by component (§§5 to 14) to match the CoSAI Risk Map, which means the same logical operation is described differently depending on the pipeline that carried it, and cross-protocol detections are awkward to express. Options: keep the component organization; add a normalized operation projection alongside it; or restructure. See [G.5](#g5-divergences--gaps-remaining) item 3.
16. **AgBOM tier and format.** [§14](#14-asset-inventory--fleet-aggregates-mostly-may) places the AgBOM cluster at SHOULD and stays format-agnostic across CycloneDX / SPDX / SWID. Should CoSAI instead **recommend one binding** for interoperability? CycloneDX has the most mature AI/ML component modelling and is the format AOS has drafted first, which argues for it, but a recommendation is a commitment the WG should make deliberately.

## Pre-publication verification (editorial, not WG decisions)

- **Confirm the *Agents of Chaos* citation.** Verify `arXiv:2602.20021` (dated Feb 2026) resolves to the intended paper and version before publishing; update authors/date if the preprint has been revised.
- **Re-verify ATLAS technique IDs, now a standing obligation, not a one-off.** Since [ATLAS is canonical](#attack-taxonomy-mitre-atlas-is-canonical), the document's technique vocabulary is externally owned and versioned. Re-check every `AML.Txxxx` in [Appendix A.4 to A.5](#a4-attack-taxonomy-cosai-at10xx-codes-deprecated-aliases-to-mitre-atlas) against <https://atlas.mitre.org/> at publication **and at every subsequent revision**: confirming that each ID still exists, has not been superseded or renumbered, and that no newly-added GenAI or agentic technique is now a better fit than the one recorded. Pay particular attention to the judgment mappings (`AOC-06`→`AML.T0048`, `TA-05`→`AML.T0057`) and to any attack currently mapped to a parent technique where a sub-technique may since have been added.
- **Re-verify the governance-framework mappings.** [Appendix H](#appendix-h-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile) and [Appendix I](#appendix-i-implications-for-isoiec-42001) both map to moving targets. Confirm: (a) the **Cyber AI Profile**'s status, document number (**NIST IR 8596**), and the *Secure / Detect / Thwart* focus-area names against the then-current draft, an Initial Public Draft was expected after the preliminary draft used here; (b) whether the **NIST AI RMF revision** has landed and changed the function or category structure; (c) every **ISO/IEC 42001 Annex A** identifier and title **against the purchased standard**: these were taken from public summaries, and control-level numbering (e.g. `A.6.2.8`) is error-prone in secondary sources; (d) the CSF 2.0 category identifiers cited in [H.2](#h2-csf-20-mapping-by-function).
- **Confirm the `TA-11` to `TA-13` figures against the primaries.** Each is now cited to a primary source. Re-check the affected-scale numbers (~1,000 Asana customers; 100,000+ AI Engine installs), the Asana exposure window (5 to 17 June 2025), and both AI Engine CVE identifiers and patch versions before release.
- **Check for `AT10xx` leakage.** The CoSAI codes are deprecated to aliases and must not appear outside the [A.4](#a4-attack-taxonomy-cosai-at10xx-codes-deprecated-aliases-to-mitre-atlas) migration table and the historical `IR-` case-study rows in [A.2](#a2-cosai-ws2-ai-incident-response-case-studies). Confirm none has re-entered the field tables, correlation patterns, or appendices.
- **Confirm external links resolve.** Especially the OWASP GenAI resource pages (refs 16 to 17) and the legacy OWASP LLM04 path (ref 12).
- **Re-verify the AOS cross reference against the live specification.** [Appendix F](#appendix-f-owasp-aos-cross-reference) was built against AOS pages that are all marked *working draft* (the CycloneDX AgBOM binding explicitly "under development"), and several were read via summarizing retrieval rather than verbatim. Before publication: confirm every AOS element name in E.1 to E.3 (hook names, step method names, object and field names, AgBOM entity categories, CycloneDX property names), and re-check the two divergences in [F.6](#f6-divergences--open-coordination-items) (the OCSF class/`actor.type_id` binding and the `llm.*` vs `gen_ai.*` attribute naming) since either may have moved.
- **Confirm the EchoLeak citation details.** Reference 4 cites the vendor and CVE records (MSRC, NVD) plus the arXiv technical analysis (2509.10540). Confirm the CVSS score (9.3) and the Jan-2025-reported / Jun-2025-disclosed timeline against the vendor advisory, and add the Aim Labs disclosure writeup if a stable URL becomes available.
- **Verify the `TA-` renumbering against any external citations.** EchoLeak moved from `KP-01` to `TA-01` and every former `TA-0N` was incremented by one ([Appendix A.1](#a1-real-world-attack-vectors)). If the working paper, slide decks, the Attacks tab itself, or any WS2 material cite the old numbering, they must be updated in lockstep, the old and new schemes share the same `TA-0N` namespace, so a stale citation resolves silently to the **wrong attack**. This is the highest-risk editorial item in the document.
- **Sanity-check the MUST count.** The MUST tier is large: 47 fields, spread across §§5 to 14 and §16. (**§15 carries no MUST**; see [J.11](#j11-observability-plane-integrity-15) for why.) Confirm each new MUST still satisfies the document's own bar; **≥ 2 independent attacks** in [Appendix A](#appendix-a-attack--incident-inventory) *and* implementable on current stacks; before the tier is treated as a conformance baseline. **Capability-Set Change Event** and **Enforcement-Point Availability** deserve particular scrutiny, as both are somewhat ahead of common practice.
