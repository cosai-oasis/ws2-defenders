# Telemetry for AI Security {**Working Draft v0.5**}

**Status:** Request for Comments, revision 0.5
**Origin:** Coalition for Secure AI (CoSAI), Workstream 2 (Defenders)
**Companion documents:** [Attack Detection Addendum](Telemetry-Attack-Detection-Addendum.md) (cited as AD) and [Cross-Mapping Addendum](Telemetry-Cross-Mapping-Addendum.md) (cited as XM).
**Disclosure:** Prepared for open publication under CoSAI. No commercial sponsorship; the standards positions taken favour open specifications (OpenTelemetry, OCSF, OWASP AOS, CPEX) over any vendor implementation. Drafting, cross-referencing, and consistency checking were performed with AI assistance.

---

## 1. Introduction

AI systems now read untrusted content, decide what to do about it, and act: calling tools, writing memory, retrieving documents, sending mail, invoking other agents. Attacks against them succeed in the gap between reading and acting. Detection has to happen in that gap, as far left in the kill chain as possible.

Catching an injection attack in flight means knowing what the model was given, how far that input was trusted, what it decided to do, and where its output went. Most deployments record none of this. Traditional application logging captures HTTP requests, database queries, and authentication events. The decisive moments in an AI system (an instruction arriving inside a retrieved document, a guardrail verdict, a memory write that will shape every future session) leave no trace there. Without those records there is nothing to detect against, and afterwards nothing solid to investigate, debug, or audit.

### 1.1 One umbrella, many efforts

Several communities are converging on AI telemetry, and their work is complementary. **OpenTelemetry** [[35]](#standards--frameworks) defines how instrumentation emits GenAI and agent data. **OCSF**, the Open Cybersecurity Schema Framework [[37]](#standards--frameworks), defines how security events are normalized for a SOC. **OWASP AOS**, the Agent Observability Standard [[38]](#standards--frameworks), defines how an agent exposes itself for observation. **CPEX** [[44]](#standards--frameworks) defines how a policy runtime mediates agent actions. **ODIS**, the Open Delegation and Identity Standard [[26]](#standards--frameworks), defines delegated identity and authority. **MITRE ATLAS** [[1]](#primary-sources-attack-corpus--taxonomy) defines the adversary techniques to classify against. Regulation adds its own obligations, notably EU AI Act Article 12 [[34]](#standards--frameworks) and the NIST AI Risk Management Framework [[30]](#standards--frameworks).

Those efforts answer different questions. The open question this RFC addresses is which fields to collect, why, and at what priority.

This RFC is a requirements layer for security telemetry, not a wire format. It specifies the fields an AI system needs to produce for security, the evidence that makes each field necessary, and a suggested build order.

### 1.2 For example: EchoLeak

In June 2025 Microsoft disclosed **EchoLeak** (CVE-2025-32711, CVSS 9.3), reported by Aim Labs [[4]](#real-world-attack-primary-sources). A single crafted email caused Microsoft 365 Copilot to retrieve the attacker's text as context, act on it as instruction, and exfiltrate internal SharePoint, OneDrive and Teams content to an attacker-controlled endpoint. No user ever clicked anything. The chain defeated the cross-prompt-injection classifier, link redaction, and content-security policy in turn, and routed the egress through a trusted proxy domain.

Each step in that chain is detectable, and each depends on a field most deployments do not collect:

- The email entered as **untrusted data** and was acted on as instruction, a distinction nothing recorded.
- The run was **autonomous**; no human initiated it, which is itself the strongest first filter for injection.
- The **injection classifier was bypassed**. A classifier whose verdicts are not logged cannot be shown to have failed.
- Content left for a **previously unseen outbound destination**: the last point at which the attack could have been stopped rather than reconstructed afterwards.

Four fields, none exotic. Their absence is the difference between a detection and a disclosure notice.

---

## 2. Scope

### 2.1 In scope

The security-relevant telemetry an AI system needs to produce: which fields, justified by which documented attacks, at which priority. Fields are organized by the component that emits them (reasoning core, input and output handling, model and serving, tools, memory, retrieval, orchestration, identity and delegation, asset inventory, observability plane, and policy enforcement) and each is tiered **MUST**, **SHOULD**, or **MAY** against a stated test. The [Attack Detection Addendum](Telemetry-Attack-Detection-Addendum.md) adds correlation patterns showing how fields combine into detections, and the [Cross-Mapping Addendum](Telemetry-Cross-Mapping-Addendum.md) maps the field set onto OpenTelemetry, OCSF, AITF [[25]](#standards--frameworks), ODIS, OWASP AOS, CPEX, the CoSAI Risk Map, NIST CSF [[31]](#standards--frameworks) and AI RMF, and ISO/IEC 42001 [[33]](#standards--frameworks).

Telemetry for **agents the deployment does not operate** is in scope, with the limits that implies: what is observable at your own boundary, plus whatever the counterparty presents and can be verified. [§4.6](#46-record-your-boundary-not-their-internals) sets out how the field set applies in that case.

The framing implies three limits. This is **not a wire format**: the bindings are in the Cross-Mapping Addendum. It does **not specify detection logic**, only the fields detections consume; how they feed detection is discussed in the [Attack Detection Addendum](Telemetry-Attack-Detection-Addendum.md). And it covers the **security** slice of AI trustworthiness; fairness, bias, safety alignment, and environmental impact are outside its remit.

### 2.2 Not in scope

**Security and privacy of the telemetry itself** are left to a later CoSAI publication: authenticating emitters, securing transport and storage, controlling access to collected content, retention, redaction, encryption, tamper-evidence and chain of custody, and privacy compliance (lawful basis, data-subject rights, cross-border transfer, impact assessment). The field set treats the telemetry plane as an asset only insofar as it reports its own failure (§4.5). Meeting the MUST tier discharges none of those obligations, and it does not satisfy the CoSAI Risk Map's `controlAuditTrailIntegrityVerification` and `controlAuditRecordRepositoryIndependence`; adopters needing audit-grade evidence need to implement them separately.

---

## 3. How To Use This Doc

### 3.1 For CISOs

Go to the **classification summary** ([§5.4](#54-field-catalogue), every field by emitting component and tier) and treat the **applicable subset of the MUST column** as the baseline for each AI deployment. The three tiers are **MUST**, **SHOULD**, and **MAY**, used in the RFC 2119 sense and defined in [§5.1](#51-tiers). The catalogue contains 50 MUST fields; a deployment's baseline consists of those whose defining component, operation, or event exists in that deployment. This is the artifact to take into an engineering plan or a budget discussion.

- **The justification is evidentiary.** Every MUST field cites named real-world attacks and incidents. The ask is "these fields catch these attacks," not "best practice suggests." [AD §4](Telemetry-Attack-Detection-Addendum.md#4-tiering-rationale) sets out that reasoning per component if it is challenged.
- **There is a build order.** The MUST tier is sequenced, so a team starts with the identifiers and content that everything else correlates through rather than instrumenting alphabetically.
- **Compliance follows detection, not the reverse.** Build for detection and the audit evidence is a by-product; building for audit does not produce detection. The NIST and ISO/IEC 42001 mappings are [XM §§7 and 8](Telemetry-Cross-Mapping-Addendum.md#7-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile).

One decision cannot be delegated to engineering: how much prompt, response, and memory content is retained, for how long, and who can read it. The MUST tier can be met with hashes and classifications where raw content is too sensitive to keep, but that is a policy call, to be made deliberately rather than by default.

### 3.2 For defenders of AI systems

To operationalize telemetry collection for a live AI system:

1. **Scope.** Map what you run onto the risk-map components ([§5.3](#53-components)). Fields for components you do not run are not applicable ([§5.2](#52-conformance)).
2. **Select.** From the field catalogue ([§5.4](#54-field-catalogue)), take every MUST field your components emit, plus the SHOULD fields for each modality you run ([§5.1](#51-tiers)). That list is your baseline.
3. **Define.** Read each field's capture definition and evidence in [AD §1](Telemetry-Attack-Detection-Addendum.md#1-field-tables).
4. **Bind.** Use the OpenTelemetry attribute names and signal placement in [XM §2](Telemetry-Cross-Mapping-Addendum.md#2-implications-for-opentelemetry-the-instrumentation-bridge), the OCSF mapping in [XM §3](Telemetry-Cross-Mapping-Addendum.md#3-implications-for-ocsf--aitf-the-standardization-bridge), and the AITF names in [XM §4](Telemetry-Cross-Mapping-Addendum.md#4-aitf--odis-cross-reference). Do not invent a schema.
5. **Conform.** Hash every content-bearing field under a declared canonicalization, never head-sample security events, and record the sampling configuration ([§5.2](#52-conformance)). Propagate trace context across every hop, including MCP [[39]](#standards--frameworks) and agent-to-agent [[40]](#standards--frameworks) calls.
6. **Sequence.** Within your baseline, build in dependency order: identifiers and trace context ([AD §1.1](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core)), because every later detection resolves through them; content, trust classification and guardrail verdicts ([AD §1.2](Telemetry-Attack-Detection-Addendum.md#12-input-handling--trust-provenance) to 1.3), which alone give a working injection detection; tool call I/O with execution IDs and sandbox posture ([AD §1.5](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services)); memory and retrieval (AD §§1.6 to 1.7); orchestration (AD §1.8); identity (AD §1.9) and capability-set change (AD §1.10). Add **Enforcement-Point Availability** and **Guardrail Modification Record** early, before their modalities are fully adopted: without them a starved guardrail reads as a clean pass, and a redaction pipeline falsifies its own log.
7. **Detect.** Implement the correlation patterns in [AD §2](Telemetry-Attack-Detection-Addendum.md#2-correlation-patterns) as your first detections, and use the attacks each field cites ([AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory)) as test cases. Stamp each fired detection with its ATLAS technique ([AD §3.6](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping)).

---

## 4. Principles

### 4.1 Detection first

Every field is justified against four use cases, **in this priority order**:

| | Use case | What it means |
| :---- | :------------------------- | :---------------------------------------------------------------------- |
| **D** | **Threat detection** | Enables a detection to fire on an attack in progress. *Highest priority.* |
| **R** | **Incident response** | Enables scoping, attribution, containment, and forensic reconstruction after the fact. |
| **Q** | **Service debugging / quality** | Explains why the system behaved as it did; performance, cost, and correctness. |
| **A** | **Compliance audit** | Evidences a control to an auditor or regulator. *Lowest priority.* |

Where a field serves several, the **highest-priority** use case governs its tier. A field whose value is mainly Q or A does not reach MUST no matter how useful it is.

Availability and provider-policy signals are in scope where they make a silent failure distinguishable from a clean result ([AD §4](Telemetry-Attack-Detection-Addendum.md#4-tiering-rationale)).

### 4.2 Evidence sets the tier

A field earns its tier from documented instances, not from a judgement that it would be useful. MUST requires at least two independent instances in the attack corpus, or one where the field is especially useful for detection or response, and implementability wherever its component exists. Two gates then cap the tier, independently of each other: the priority order in §4.1 keeps fields whose value is mainly debugging or audit below MUST, and a field serving a modality at the edge of current practice stays SHOULD however much evidence accumulates. The test is stated in §5.1; what counts as a documented instance, and the corpus itself, are in [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory).

### 4.3 Untrusted instruction is the attack state

Prompt injection succeeds when content from an untrusted origin is consumed as instruction. **Input Trust Classification** ([AD §1.2](Telemetry-Attack-Detection-Addendum.md#12-input-handling--trust-provenance)) records exactly that, as the cross of origin (trusted or untrusted) with use (instruction or data); `untrusted-instruction` is the attack state. **Model Input** and **Input Source / Channel** make the classification checkable, and the guardrail verdicts record whether a classifier caught it. In EchoLeak (§1.2) the email occupied that cell, and nothing recorded it.

### 4.4 The agent might be lying

The threat model in [XM §6.1](Telemetry-Cross-Mapping-Addendum.md#61-the-threat-model-the-most-important-contribution) treats a compromised agent as a potential source of false statements, not only as a victim. These fields are **self-asserted** and carry no independent authority: **Autonomy Level** and **System Prompt / Instruction Config** (AD §1.1), **Observation / Thought** (AD §1.3), **Tool Selection Rationale** (AD §1.5), **Memory Write Rationale** (AD §1.6), and **Task / Intent Declaration** (AD §1.8). **Peer Agent Card / Descriptor** (AD §1.8) is the counterparty's assertion rather than the agent's own, and carries the same weakness. `AOC-01` is the corpus's demonstration that agents do misreport: it declared a secret destroyed while the data remained recoverable. A detection resting on any of these inherits whatever the agent chose to say, which is why **Attribute Source / Trusted-Provenance Marking** (AD §1.12) is a cross-cutting MUST. Corroboration is a decidable property, not a judgement: a claim about an outcome is **verified** when it resolves, by an identifier carried in the record, to the result it rests on, as **Execution Status** (AD §1.1) resolves to the **Tool Call I/O** outcome sharing its **Tool Execution ID** (AD §1.5). Where no identifier resolves, the claim is **attested**: the record says so and no reader can settle it. Recording attested claims as attested, rather than counting them as outcomes, lets a checker decide the question instead of leaving it to an adjective.

### 4.5 A missing verdict is not an allow

Every detection assumes the telemetry and enforcement path worked. When a guardrail is starved or a hook disabled, a verdict that never arrived reads the same as a verdict of `allow`. The field set therefore records the plane's own failures: **Instrumentation Coverage / Hook Attestation**, **Enforcement-Point Availability & Failure Mode** and **Event Sequence Continuity** ([AD §1.11](Telemetry-Attack-Detection-Addendum.md#111-observability-plane-integrity)). It records what policy decided, on which rule, and whether any path bypassed it: **Authorization Decision Record** and **Mediation Coverage & Bypass Path** ([AD §1.12](Telemetry-Attack-Detection-Addendum.md#112-policy-enforcement--mediation)). The same reasoning makes the sampling rules normative (§5.2): an event sampled away is indistinguishable from one that never occurred. Defending the plane itself is out of scope (§2.2).

### 4.6 Record your boundary, not their internals

Much of the corpus involves a counterparty someone else runs: another owner's agent (`AOC-04`, `AOC-09`, `AOC-11`, `AOC-16`), an MCP server you did not deploy (`TA-12`, `TA-13`), or a shared multi-tenant service (`TA-11`). You cannot instrument what you do not operate, so the field set applies differently. Each adjacent standard supplies a rule ([Cross-Mapping Addendum](Telemetry-Cross-Mapping-Addendum.md#agents-you-do-not-operate)): instrument your own boundary, not the counterparty's internals (CPEX); make authority legible through presented, verifiable claims (ODIS); and ask the counterparty to be inspectable, recording the answer (OWASP AOS).

Read every field in AD §§1.1 to 1.12 against one of these **knowability** tiers:

| Tier | What you have | How the field set applies |
| :------- | :------------------------- | :------------------------------------------------ |
| **Mediated** | You own the boundary the interaction crosses | Full boundary telemetry: AD §§1.2, 1.3, 1.5, 1.12 apply as written. The counterparty's internals are absent, and their absence is expected rather than a gap |
| **Attested** | The counterparty presents verifiable claims (ODIS credential, signed AgBOM, agent card) | Record the claim **and its verification outcome**. **Attribute Source / Trusted-Provenance Marking** (AD §1.12) is the mechanism: an unverified claim is `self-asserted`, whatever it asserts |
| **Opaque** | Only the wire interaction | AD §§1.2, 1.3, 1.8 at the protocol surface, and nothing more. **Do not synthesize** fields you cannot observe. An opaque counterparty needs to be visibly opaque in the telemetry, not silently defaulted |

The third row collapsing into the second is the failure to avoid: recording an external agent's self-description as though it were established fact. `AOC-08` is that failure in miniature, and `AOC-11` is its consequence at scale.

---

## 5. The field set

### 5.1 Tiers

The keywords **MUST**, **SHOULD**, and **MAY** are used as defined in **RFC 2119** [[51]](#standards--frameworks), as updated by **RFC 8174** [[52]](#standards--frameworks): they carry that meaning only in capitals, so lowercase `optional` or `should` elsewhere in this document is ordinary prose. Each field carries exactly one keyword, and the table below states both the RFC 2119 obligation and the evidentiary test this document applies to assign it.

| Tag | Meaning | Test |
| :---- | :-------------------- | :------------------------------------------------------------------------------ |
| **MUST** | Baseline. Required whenever the field is applicable under the rules below. | Grounded in **≥ 2 independent documented instances** in [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory); **or 1 where the field is especially useful for D or R**; *and* implementable on essentially any current system that has the relevant component, operation, or event. |
| **SHOULD** | Required once a deployment adopts a modality or faces a threat scenario at the **edge of current agentic practice**. | The field serves a deployment modality or threat scenario that is emerging rather than typical; **delegation chains and cascaded authority**, cryptographic identity and attestation, agent-to-agent protocol surfaces, inline enforcement that mutates payloads, dynamic third-party capability composition, or self-attesting instrumentation. Attack grounding can be **analogical**: the corpus motivates the scenario without yet containing a documented instance. |
| **MAY** | Valuable, but not needed to catch the core attack classes. | The field's dominant value is **Q or A**; or its attack motivation is thin (single weak instance, or none); or it is a research-grade signal, a derived detector output, or redundant with a MUST field. |

What counts as a documented instance, and how the evidence and priority tests interact, is set out in [AD §§3 and 4](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory).

- **SHOULD is not "MUST later."** It is "MUST *if you run this modality*." This is the RFC 2119 reading applied narrowly: the "valid reasons in particular circumstances" for omitting a SHOULD field are **not running the modality it describes**, and nothing else. Cost, effort, and inconvenience are not among them. For a deployment with cascaded delegation, AD §1.9 applies from day one; a single-agent deployment might never need it.

  Each modality brings its cluster, adopted as soon as the modality is run:

  - Delegated authority → all of AD §1.9 plus Tool ACL/Scope (AD §1.5).
  - Multi-tenancy → Organization/Tenant ID (AD §1.1).
  - A2A → task lifecycle and peer agent cards (AD §1.8).
  - Inline enforcement that mutates payloads → Guardrail Modification Record (AD §1.2).
  - Autonomous action → autonomy level (AD §1.1) and task/intent declaration (AD §1.8).
  - Supply-chain attestation → model signing (AD §1.4), the AgBOM cluster (AD §1.10).
  - Self-attesting instrumentation → AD §1.11.
  - Information-flow control → session taint (AD §1.12).
  - Out-of-band human approval → elicitation events (AD §1.12).
  - Policy-driven backend selection → route restriction (AD §1.12).
  - Token exchange → credential minting (AD §1.9).

  The reasoning-trace and integrity-scoring fields (AD §§1.3, 1.5, 1.6, 1.7), which are gated by provider availability and privacy policy rather than by modality.

> Tags are **deployment-agnostic**: a tag reflects *what evidence requires the field* and *how common the modality is*, not any one vendor's maturity. Build sequencing is in [§3.2](#32-for-defenders-of-ai-systems).

### 5.2 Conformance

- **Applicability precedes obligation.** A tier does not require a deployment to add a component or manufacture an event solely to emit its telemetry. A MUST field applies when its defining component, operation, or event exists: for example, AD §1.6 applies when the deployment uses persistent memory, and **Inter-Agent Message** applies when an agent-to-agent message is sent. A deployment that lacks the relevant capability marks the field **not applicable** in its conformance statement; it does not emit a synthetic value.
- **Schema support and event emission are distinct.** A conformant implementation supports every applicable MUST field and emits it whenever the corresponding event occurs. An individual event carries only the fields applicable to that event class and activity. Absence because the event did not occur is not a defect; omission from an event to which the field applies is.

**Sampling.** Default OpenTelemetry [[36]](#standards--frameworks) head-based sampling discards traces without regard to security relevance. For any deployment that relies on OTel as its security-telemetry carrier, the following are **normative** (rationale in [XM §2.5](Telemetry-Cross-Mapping-Addendum.md#25-context-propagation-sampling--privacy-three-operational-traps)):

1. **Security-relevant events MUST NOT be head-sampled.** Guardrail verdicts, refusals, tool errors, authorization denials, capability changes, session and turn stop events carrying a **Stop Reason** (AD §1.1), per-invocation tool activity events, and any event carrying a fired detection are recorded at **100%**. A sampled-away `content_filter` stop is a missed guardrail bypass.
2. **Where tail sampling is used, security relevance MUST be a retention predicate**: a trace containing a block, a denial, an error, or a flagged classification is always kept.
3. **The sampling configuration in force MUST itself be recorded as telemetry.** A detection that never fires because its input was sampled away is indistinguishable from a clean environment.

**Every content-bearing field MUST carry a content hash; whether the raw content accompanies it is a deployment policy decision.** The hash is the correlation primitive the corpus turns on: `TA-04` is verbatim reproduction, `AOC-03` is escalating extraction across turns, and `IR-02` is an implant that persists into later sessions. None of those is detectable without the ability to match one content item against another, and none of them requires the raw text to be retained. Mandating the hash and leaving the raw content to policy keeps a MUST field comparable between two deployments with different privacy postures, which a free choice between raw and hash does not. This is why several high-value fields (Observation/Thought, memory and RAG content) are specified *conceptually* here: the obligation is the hash, not the payload.

**Three fields carry identifiers rather than payloads, and resolve as follows.** **Content Modality & Attachment Identity** (AD §1.2) already requires a content hash; the **filename** is the sensitive part and is deployment policy. **Citations / Source Attribution** (AD §1.3) names its own signal as *whether each citation resolves to an item actually returned by a logged Retrieval Event*, so the **resolution outcome is the obligation** and the clear-text URL is policy; a deployment that withholds URLs keeps the detection intact. **Protocol Envelope Capture** (AD §1.8) is MAY because raw payload capture is the field, and its tier already carries that judgement.

**A hash is evidence only if a second party can recompute it.** The canonicalization the digest is taken over MUST be declared, either by the deployment or by the carrier ([XM §2.5](Telemetry-Cross-Mapping-Addendum.md#25-context-propagation-sampling--privacy-three-operational-traps)). Two emitters that hash the same tool call under different serializations produce different digests, and the field degrades silently from evidence to a correlation key that only works within one producer.

### 5.3 Components

Fields are organized under the CoSAI Risk Map [[23]](#standards--frameworks) fine-grained components. The table lists all 42 by risk-map category and subcategory, using the canonical IDs from [`risk-map/yaml/components.yaml`](https://github.com/cosai-oasis/secure-ai-tooling/blob/main/risk-map/yaml/components.yaml), with the sections whose fields each component emits:

| Category / subcategory | Components and sections |
| :-------------------- | :-------------------------------------------------------------------------------- |
| **Application / Core** | `componentApplication` AD §1.1, AD §1.10; `componentApplicationInputHandling` AD §1.2; `componentApplicationOutputHandling` AD §1.3; `componentApplicationConsentSurface` AD §1.12; `componentApplicationNetworkPolicyEnforcementPoint` AD §1.12 |
| **Application / Agent** | `componentReasoningCore` AD §1.1, AD §1.8, AD §1.9; `componentAgentUserQuery` AD §1.1; `componentAgentSystemInstruction` AD §1.1; `componentAgentInputHandling` AD §1.2; `componentAgentOutputHandling` AD §1.3; `componentAgentToolTransport` AD §1.5; `componentAgentConsentSurface` AD §1.12; `componentAgentNetworkPolicyEnforcementPoint` AD §1.12 |
| **Model / Orchestration** | `componentOrchestrationInputHandling` AD §1.2, AD §1.8; `componentOrchestrationOutputHandling` AD §1.3, AD §1.8; `componentMemory` AD §1.6; `componentRAGContent` AD §1.7 |
| **Model / Core** | `componentTheModel` AD §1.4; `componentModelServing` AD §1.4, AD §1.9 |
| **Model / Training** | `componentModelFrameworksAndCode` AD §1.10; `componentModelTrainingTuning`, `componentModelEvaluation`: none |
| **External Tools / Tool Invocation Path** | `componentTools` AD §1.5, AD §1.9, AD §1.10; `componentToolServer` AD §1.5; `componentToolInputHandling` AD §1.5; `componentToolOutputHandling` AD §1.5; `componentAuthorizationPolicyEnforcementPoint` AD §1.12 |
| **External Tools / Tool Network Controls** | `componentToolNetworkPolicyEnforcementPoint` AD §1.12 |
| **Infrastructure / Identity** | `componentIdentityProvider` AD §1.9; `componentFederationProxy` AD §1.9; `componentAuthorizationPolicyDecisionPoint` AD §1.12 |
| **Infrastructure / Registries** | `componentModelRegistry` AD §1.4, AD §1.10; `componentToolRegistry` AD §1.5, AD §1.10 |
| **Infrastructure / Deployment** | `componentModelStorage` AD §1.4; `componentIsolationRuntime` AD §1.5; `componentToolHosting` AD §1.5; `componentAuditRecordRepository` AD §1.11; `componentRuntimeHosting`: none |
| **Infrastructure / Data** | `componentDataSources`, `componentDataFilteringAndProcessing`, `componentTrainingData`, `componentDataStorage`: none |

**The field set covers the runtime path.** No corpus entry attacks the training pipeline (`IR-05` and `AOC-10` carry `AML.T0020` but poison memory and retrieval at runtime), so the evidence gate admits no field for the data and training components. `componentRuntimeHosting` has none: no field records the substrate that first-party workloads run on.

> **Component attribution is a mapping, not an emitted attribute.** Events do not carry a risk-map `component_id`. Attribution is established by this section, [XM §1](Telemetry-Cross-Mapping-Addendum.md#1-mapping-to-the-cosai-risk-map-risks--controls) and [XM §4](Telemetry-Cross-Mapping-Addendum.md#4-aitf--odis-cross-reference), which is sufficient for a static cross reference and costs nothing at runtime. A runtime identifier would need a resolvable namespace and a deprecation policy before it could be emitted safely, since events are immutable records and a component renamed upstream would invalidate every event already carrying it. That is tracked as part of the CoSAI Risk Map ontology work ([secure-ai-tooling#388](https://github.com/cosai-oasis/secure-ai-tooling/issues/388)); if that effort settles a stable namespace, the field belongs in [AD §1.10](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) at MAY.

### 5.4 Field catalogue

Every field in the set, **98 in all: 50 MUST, 33 SHOULD and 15 MAY**, grouped by the risk-map category of the component that emits it, then by tier. Together the MUST fields cover prompt injection, data disclosure, memory and retrieval poisoning, exfiltration, resource abuse and denial of service, identity spoofing, runaway multi-agent loops, and unauthorized action. Each name links to its full definition (what to capture, and the attacks that require it) in the [Attack Detection Addendum](Telemetry-Attack-Detection-Addendum.md#1-field-tables). The [applicability rules](#51-tiers) determine a given deployment's obligations; the reasoning behind each tier is in [AD §4](Telemetry-Attack-Detection-Addendum.md#4-tiering-rationale).

**1. Application.** Application Core and Agent subcategories.

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Agent Name](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | MUST | Logical name or type of the agent; exposes off-inventory agents. | `componentReasoningCore` |
| [Agent (Runtime) Instance ID](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | MUST | The running instance an event belongs to, for per-instance quarantine. | `componentReasoningCore` |
| [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | MUST | Groups one multi-step run or sub-agent tree into one execution. | `componentReasoningCore` |
| [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | MUST | The session, turn and step beneath a run, locating where behaviour changed. | `componentApplication`, `componentReasoningCore` |
| [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | MUST | User-initiated or autonomous, and for autonomous runs the originating event. | `componentReasoningCore` |
| [Action Type](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | MUST | LLM call, tool call, memory operation or message send. | `componentReasoningCore` |
| [Execution Status](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | MUST | Outcome and duration of an operation or turn. | `componentReasoningCore` |
| [Surface / App](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | MUST | Entry point: CLI, web, IDE, email, chat, scheduler; internal or external. | `componentApplication` |
| [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | MUST | Instruction configuration in force for the call. Self-asserted. | `componentAgentSystemInstruction` |
| [Model Input](Telemetry-Attack-Detection-Addendum.md#12-input-handling--trust-provenance) | MUST | Every input to each model call, including tool output, retrieved context and messages. | `componentApplicationInputHandling`, `componentAgentInputHandling` |
| [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#12-input-handling--trust-provenance) | MUST | Which surface, tool, agent or document each input segment came from. | `componentApplicationInputHandling`, `componentAgentInputHandling` |
| [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#12-input-handling--trust-provenance) | MUST | Trusted or untrusted origin, consumed as instruction or data; untrusted-instruction is the attack state. | `componentAgentInputHandling` |
| [Source host / IP + request metadata](Telemetry-Attack-Detection-Addendum.md#12-input-handling--trust-provenance) | MUST | Origin of the request, for geo, rate and credential-theft detection. | `componentApplicationInputHandling` |
| [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#12-input-handling--trust-provenance) | MUST | Input classifier result (pass, flag, block, modify) with detector and score. | `componentApplicationInputHandling`, `componentAgentInputHandling` |
| [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#13-output-handling-egress--refusals) | MUST | Generated output at each step. | `componentApplicationOutputHandling`, `componentAgentOutputHandling` |
| [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#13-output-handling-egress--refusals) | MUST | Where output goes: recipients, URLs, channels, files, broadcast scope. | `componentApplicationOutputHandling`, `componentAgentOutputHandling` |
| [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#13-output-handling-egress--refusals) | MUST | Sources the agent claims, and whether each resolves to a logged retrieval. | `componentApplicationOutputHandling`, `componentAgentOutputHandling` |
| [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#13-output-handling-egress--refusals) | MUST | Output filter result (pass, flag, block, modify). | `componentApplicationOutputHandling`, `componentAgentOutputHandling` |
| [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#13-output-handling-egress--refusals) | MUST | Refusal status and reason. | `componentAgentOutputHandling` |
| [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#18-orchestration-multi-agent--background-execution) | MUST | Agent-to-agent messages: sender, receiver, content, channel. | `componentReasoningCore` |
| [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#18-orchestration-multi-agent--background-execution) | MUST | Creation or change of cron jobs, heartbeats and self-scheduled loops. | `componentReasoningCore` |
| [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#18-orchestration-multi-agent--background-execution) | MUST | Steps per run against baseline; circular exchanges between agents. | `componentReasoningCore` |
| [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#18-orchestration-multi-agent--background-execution) | MUST | Token, compute, storage and outbound totals per run against a budget. | `componentReasoningCore` |
| [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) | MUST | A tool, server, model, knowledge source or memory store added, removed or modified at runtime. | `componentReasoningCore` |
| [Stop Reason](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | SHOULD | Why a completion ended: end of turn, token limit, tool use, cancellation, content filter. | `componentReasoningCore` |
| [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | SHOULD | Declared independence level the run is authorized for. Self-asserted. | `componentReasoningCore` |
| [Observation / Thought (reasoning trace)](Telemetry-Attack-Detection-Addendum.md#13-output-handling-egress--refusals) | SHOULD | Reasoning trace, where the provider exposes it. Self-asserted. | `componentReasoningCore` |
| [Tool Selection Rationale](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | SHOULD | The agent's stated reason for a tool call. Self-asserted. | `componentReasoningCore` |
| [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#18-orchestration-multi-agent--background-execution) | SHOULD | Declared purpose the run is authorized to pursue. Self-asserted. | `componentReasoningCore` |
| [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#18-orchestration-multi-agent--background-execution) | SHOULD | Delegated-task state changes across A2A, including callback registration. | `componentReasoningCore`, `componentAgentToolTransport` |
| [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#18-orchestration-multi-agent--background-execution) | SHOULD | A counterparty agent's descriptor at contact, with change and verification outcome. | `componentReasoningCore` |
| [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#112-policy-enforcement--mediation) | SHOULD | Approval lifecycle: status, IdP-verified approver, and whether it covers the executed arguments. | `componentAgentConsentSurface`, `componentApplicationConsentSurface` |
| [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#12-input-handling--trust-provenance) | MAY | Flag and decoded form of base64, image-embedded or markup-authority input. | `componentAgentInputHandling` |
| [Protocol Envelope Capture](Telemetry-Attack-Detection-Addendum.md#18-orchestration-multi-agent--background-execution) | MAY | Raw MCP or A2A JSON-RPC envelope alongside the interpreted fields. | `componentAgentToolTransport` |

**2. Model.** Model Core, Orchestration and Training subcategories.

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Model Name + Version](Telemetry-Attack-Detection-Addendum.md#14-the-model--model-serving) | MUST | Model and version that processed the request. | `componentModelServing` |
| [Inference Parameters](Telemetry-Attack-Detection-Addendum.md#14-the-model--model-serving) | MUST | Decoding parameters and declared context window in force for the call. | `componentModelServing` |
| [Input / Output Token Counts](Telemetry-Attack-Detection-Addendum.md#14-the-model--model-serving) | MUST | Per-call token usage. | `componentModelServing` |
| [LLM Error / Exception](Telemetry-Attack-Detection-Addendum.md#14-the-model--model-serving) | MUST | Errors under adversarial conditions and provider-side silent failures. | `componentModelServing` |
| [Memory Write Event](Telemetry-Attack-Detection-Addendum.md#16-memory) | MUST | Each create, update or delete of a persistent memory item, and by whom. | `componentMemory` |
| [Memory Read / Injection Event](Telemetry-Attack-Detection-Addendum.md#16-memory) | MUST | Which memory items were pulled into context for a call. | `componentMemory` |
| [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#16-memory) | MUST | Origin and mutability of a memory item, including externally editable sources. | `componentMemory` |
| [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#16-memory) | MUST | Size and growth of memory stores per user or session. | `componentMemory` |
| [Retrieval Event](Telemetry-Attack-Detection-Addendum.md#17-retrieval--content-rag) | MUST | Query issued, items returned and their scores. | `componentRAGContent` |
| [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#17-retrieval--content-rag) | MUST | Origin, owner, trust level and freshness of each retrieved item. | `componentRAGContent` |
| [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#14-the-model--model-serving) | SHOULD | Signed digest or provenance of the served model artifact. | `componentModelServing`, `componentModelRegistry` |
| [Memory Integrity / Poisoning Signal](Telemetry-Attack-Detection-Addendum.md#16-memory) | SHOULD | Integrity check or poisoning score; cross-session isolation flag. | `componentMemory` |
| [Memory Write Rationale](Telemetry-Attack-Detection-Addendum.md#16-memory) | SHOULD | The agent's stated reason for persisting an item. Self-asserted. | `componentMemory` |
| [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#17-retrieval--content-rag) | SHOULD | Tamper or poisoning indicators on content or its metadata. | `componentRAGContent` |
| [Provider / Endpoint Identity](Telemetry-Attack-Detection-Addendum.md#14-the-model--model-serving) | MAY | Which provider or endpoint served the call. | `componentModelServing` |
| [Pre-Forward-Pass State Digest/Vector](Telemetry-Attack-Detection-Addendum.md#14-the-model--model-serving) | MAY | Digest of the exact inputs to a forward pass, for replay and drift detection. | `componentTheModel` |
| [Token Malformation / Context-Corruption Indicator](Telemetry-Attack-Detection-Addendum.md#14-the-model--model-serving) | MAY | Token-entropy anomalies correlated with confabulation. | `componentTheModel` |
| [Declared Memory Configuration](Telemetry-Attack-Detection-Addendum.md#16-memory) | MAY | A memory store's declared identity, limits and retrieval settings. | `componentMemory` |
| [Declared Knowledge-Source Configuration](Telemetry-Attack-Detection-Addendum.md#17-retrieval--content-rag) | MAY | A knowledge source's declared identity, schema and search parameters. | `componentRAGContent` |

**3. Infrastructure.** Identity, Registries and Deployment subcategories. The Data subcategory has no fields (§5.3).

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Identities Used (per hop)](Telemetry-Attack-Detection-Addendum.md#19-identity-delegation--attribution) | MUST | The identity behind each agent, tool and infrastructure action, per hop. | `componentIdentityProvider` |
| [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#19-identity-delegation--attribution) | MUST | Verified identifier against spoofable display name, and which one authorized. | `componentIdentityProvider` |
| [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | MUST | Isolation posture: sandbox mode, runtime, OS, timeout, egress policy. | `componentIsolationRuntime`, `componentToolHosting` |
| [Originating Principal (on-behalf-of)](Telemetry-Attack-Detection-Addendum.md#19-identity-delegation--attribution) | SHOULD | The human or service at the root of the delegation chain. | `componentIdentityProvider`, `componentFederationProxy` |
| [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#19-identity-delegation--attribution) | SHOULD | Ordered agent hops, each integrity-bound to its parent. | `componentFederationProxy` |
| [Granted Authorizations / Scope](Telemetry-Attack-Detection-Addendum.md#19-identity-delegation--attribution) | SHOULD | Authority in effect at this hop, with the narrowing check and its rules. | `componentFederationProxy` |
| [Resource Indicators + Constraints](Telemetry-Attack-Detection-Addendum.md#19-identity-delegation--attribution) | SHOULD | Target audience and time, purpose, rate, locality and classification limits. | `componentFederationProxy` |
| [Credential Minting & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#19-identity-delegation--attribution) | SHOULD | Each credential exchange: grant type, whose identity, and whether scope narrowed. | `componentFederationProxy`, `componentIdentityProvider` |
| [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#19-identity-delegation--attribution) | SHOULD | Counterparty trust domain and delegation depth, and whether a limit was crossed. | `componentFederationProxy` |
| [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#19-identity-delegation--attribution) | SHOULD | Runtime-instance credential and attestation evidence, each source verified separately. | `componentIdentityProvider` |
| [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#19-identity-delegation--attribution) | SHOULD | Active, suspended or revoked, for kill-switch and revocation fan-out. | `componentIdentityProvider` |
| [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) | SHOULD | Version of each tool, agent and framework. | `componentToolRegistry`, `componentModelRegistry` |
| [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) | SHOULD | Source provenance of tool and agent code. | `componentToolRegistry` |
| [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) | SHOULD | Machine-readable inventory of the agent's composition, on change and on demand. | `componentApplication`, `componentToolRegistry` |
| [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) | SHOULD | Dependency edges between inventoried components, including transitive ones. | `componentApplication`, `componentToolRegistry` |
| [Inventory Attestation Signature](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) | SHOULD | Signature over the emitted inventory, binding it to a signer. | `componentApplication`, `componentToolRegistry` |
| [Description](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) | MAY | Declared purpose of a tool, against which behaviour is compared. | `componentToolRegistry` |
| [Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) | MAY | Whether a tool is meant to be reachable. | `componentToolRegistry` |
| [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) | MAY | Ownership and change dates. | `componentToolRegistry`, `componentModelRegistry` |
| [Surfaces Supported](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) | MAY | Exposure map per tool. | `componentToolRegistry` |

**4. External Tools.** Tool Invocation Path and Tool Network Controls subcategories.

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Tool Call I/O](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | MUST | Full arguments and output of every tool or MCP call. | `componentToolServer`, `componentTools` |
| [Tool Name](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | MUST | The capability invoked, as the agent saw it. | `componentToolServer` |
| [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | MUST | MCP, internal, direct-storage or code-execution. | `componentTools` |
| [Tool Execution ID](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | MUST | Correlation ID pairing each tool request with its outcome. | `componentToolServer` |
| [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | MUST | Hash of the tool contract as presented at invocation, compared with the approved baseline. | `componentToolServer`, `componentToolRegistry` |
| [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | MUST | MCP server name, version, transport and endpoint, and the primitive exercised. | `componentToolServer` |
| [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | MUST | Failed or blocked tool calls, including the probing that precedes exploitation. | `componentToolServer`, `componentToolInputHandling` |
| [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | SHOULD | Authority a tool requires and who can invoke it. | `componentAuthorizationPolicyEnforcementPoint` |
| [Tool ID](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | MAY | Unique tool-implementation ID across MCP servers. | `componentTools` |
| [Tool Privacy Classification](Telemetry-Attack-Detection-Addendum.md#15-tools--external-services) | MAY | Sensitivity class of the data a tool touches. | `componentTools` |

**5. Cross-cutting.** Fields that apply across components or belong to the enforcement and observability layers.

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Trace Context (propagated)](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | MUST | W3C trace context carried across every agent, tool and agent hop. | every hop |
| [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#12-input-handling--trust-provenance) | MUST | Part type, MIME type, and for files name, size and hash, on every content-bearing field. | every content-bearing field |
| [Threat Classification / ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#12-input-handling--trust-provenance) | MUST | MITRE ATLAS technique IDs on any event where a detection fires. | any detector |
| [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#112-policy-enforcement--mediation) | MUST | Per mediated operation: decision, reason code, deciding authority and rule. | `componentAuthorizationPolicyDecisionPoint`, `componentAuthorizationPolicyEnforcementPoint` |
| [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#112-policy-enforcement--mediation) | MUST | The authority that supplied each security-relevant attribute, or that it is self-asserted. | every security-relevant attribute |
| [Instrumentation Coverage / Hook Attestation](Telemetry-Attack-Detection-Addendum.md#111-observability-plane-integrity) | MUST | Which hooks are active, their version, and where each reports. | instrumentation layer |
| [Organization / Tenant ID](Telemetry-Attack-Detection-Addendum.md#11-application--agent-reasoning-core) | SHOULD | Owning tenant of the agent, the session and the invoking user. | agent, session and user records |
| [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#12-input-handling--trust-provenance) | SHOULD | That an enforcement point rewrote a payload, which one, with before and after digests. | any rewriting enforcement point |
| [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#112-policy-enforcement--mediation) | SHOULD | Information-flow labels in force, and denials caused by accumulated taint. | enforcement points |
| [Backend / Route Restriction Decision](Telemetry-Attack-Detection-Addendum.md#112-policy-enforcement--mediation) | SHOULD | Candidate backends, the constraint applied, the choice made. | enforcement points |
| [Mediation Coverage & Bypass Path](Telemetry-Attack-Detection-Addendum.md#112-policy-enforcement--mediation) | SHOULD | Whether an operation passed a reference monitor, where, and whether a bypass exists. | enforcement points |
| [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#111-observability-plane-integrity) | SHOULD | Whether each enforcement callout was reached, its latency, and fail-open or fail-closed. | enforcement points |
| [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#111-observability-plane-integrity) | SHOULD | Per-session sequence number, hash-chained, for gap and reordering detection. | `componentAuditRecordRepository` |
| [Policy Reason Code](Telemetry-Attack-Detection-Addendum.md#111-observability-plane-integrity) | MAY | Machine-readable reason code for an enforcement decision. | enforcement points |
| [Fleet counts](Telemetry-Attack-Detection-Addendum.md#110-asset-inventory--fleet-aggregates) | MAY | Fleet aggregates: agents, sessions, users, tool-call volume. | fleet level |

**Conditional tiers.** **Threat Classification / ATLAS Technique Tag** is MUST when a detection fires, not on every event; its values come from the mapping in [AD §3.6](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping). **Guardrail Modification Record** is SHOULD in the catalogue and MUST whenever an enforcement point rewrites rather than blocks.

---

## 6. Conclusion

**Using the document set.** The RFC states what to collect and why: the principles ([§4](#4-principles)), the tiers and conformance rules ([§§5.1 to 5.2](#51-tiers)), and the catalogue of 98 fields by emitting component ([§5.4](#54-field-catalogue)). The [Attack Detection Addendum](Telemetry-Attack-Detection-Addendum.md) defines each field and the attacks that require it; the [Cross-Mapping Addendum](Telemetry-Cross-Mapping-Addendum.md) binds the field set to OpenTelemetry, OCSF and AITF and relates it to adjacent standards and governance frameworks. A CISO takes the applicable MUST fields as the baseline ([§3.1](#31-for-cisos)); a defender follows the recipe in [§3.2](#32-for-defenders-of-ai-systems) from component inventory to first detections. Field names, tiers and attack IDs are written to be used directly as detection-engineering and triage input.

**Built from evidence.** The field set was assembled from documented instances, not from a list of what might be useful: 49 entries, comprising 28 real-world attacks and incidents, 5 CoSAI incident-response case studies [[3]](#primary-sources-attack-corpus--taxonomy), and 16 live red-team case studies from *Agents of Chaos* [[2]](#primary-sources-attack-corpus--taxonomy). A field enters only where an instance requires it, and its tier follows a stated test ([§4.2](#42-evidence-sets-the-tier)), so every MUST can be checked against the attacks it cites, and a tier moves when the evidence or the modality changes. The same rule accounts for the gaps: no corpus entry attacks the training pipeline, so the data and training components carry no fields ([§5.3](#53-components)).

**What defenders gain.** Each principle turns a failure seen in the corpus into something a defender can detect. Input trust classification makes an injection visible at the moment untrusted content is consumed as instruction ([§4.3](#43-untrusted-instruction-is-the-attack-state)). The distinction between verified and attested claims keeps detections from resting on what a compromised agent chose to report ([§4.4](#44-the-agent-might-be-lying)). Observability-plane fields and policy decision records make missing evidence distinguishable from clean evidence ([§4.5](#45-a-missing-verdict-is-not-an-allow)). Knowability tiers set what can be recorded about agents a deployment does not operate ([§4.6](#46-record-your-boundary-not-their-internals)). The content-hash and sampling rules keep the record comparable across deployments and complete where it matters ([§5.2](#52-conformance)).

**Scope, and what follows.** This RFC covers the security telemetry of the runtime path: which fields, at which priority, on what evidence. It does not specify detection logic, and it does not define a wire format. Security and privacy of the telemetry itself (access control, retention, redaction, encryption, integrity and chain of custody, and privacy compliance) are left to a later CoSAI publication ([§2.2](#22-not-in-scope)).

---

## 7. References

### Primary sources (attack corpus & taxonomy)

1. **MITRE ATLAS**: Adversarial Threat Landscape for Artificial-Intelligence Systems (technique matrix; `AML.Txxxx` taxonomy). MITRE. <https://atlas.mitre.org/>. Citations verified against release **`v2026.08`** (1 September 2026), 197 techniques and 72 case studies; machine-readable at <https://github.com/mitre-atlas/atlas-data>.
2. **Agents of Chaos**: Shapira, N., Wendler, C., Yen, A., et al. *Agents of Chaos.* arXiv:2602.20021 (2026). <https://arxiv.org/abs/2602.20021> · interactive log: <https://agentsofchaos.baulab.info/>
3. **CoSAI AI Incident Response**: Coalition for Secure AI, Workstream 2 (Defenders): *AI Incident Response Framework* (case studies). <https://github.com/cosai-oasis/ws2-defenders/blob/main/incident-response/AI-Incident-Response.md>

### Real-world attack primary sources

Reference 4 is cited in this document. The primary source for every attack in the corpus is listed in the [AD references](Telemetry-Attack-Detection-Addendum.md#references).

4. **[TA-01]** EchoLeak, zero-click data exfiltration from Microsoft 365 Copilot (CVE-2025-32711, CVSS 9.3). Discovered and disclosed by **Aim Labs (Aim Security)**; reported to MSRC Jan 2025, fixed server-side and publicly disclosed Jun 2025. Microsoft advisory: <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711> · CVE record: <https://nvd.nist.gov/vuln/detail/CVE-2025-32711> · **Technical analysis:** Reddy, P. & Gujral, A. *EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System.* arXiv:2509.10540 (2025). <https://arxiv.org/abs/2509.10540>

### Standards & frameworks

23. **CoSAI Risk Map**: Coalition for Secure AI, fine-grained AI system components taxonomy. <https://github.com/cosai-oasis/secure-ai-tooling/tree/main/risk-map>. 55 risks / 68 controls: PR [#507](https://github.com/cosai-oasis/secure-ai-tooling/pull/507) merged, plus `riskAgentMemoryPoisoning`, `riskDeceptiveAgentReporting`, `riskUnsafeInterAgentPropagation` and `controlAgentMemoryIntegrity`; risk IDs migrated to the `risk`+camelCase convention.

<!-- list break: reference numbers are not contiguous -->

25. **AITF**: AI Telemetry Framework (OTel + OCSF binding), donated to CoSAI WS2. <https://github.com/cosai-oasis/ws2-defenders/tree/main/telemetry>
26. **ODIS**: Coalition for Secure AI, Workstream 4: *Open Delegation & Identity Standard*. Apache-2.0. Records defined in AD §1.2: Agent Registration Record (6.1), Agent Runtime Credential Descriptor (6.2), Delegation Record (6.3), Identity Context (Policy Engine Feed) (6.4). Cited at commit `148dc41` (8 September 2026); ODIS is a working draft, so this reference is pinned to a commit rather than to `main` to keep the section numbers and field names in [XM §4](Telemetry-Cross-Mapping-Addendum.md#4-aitf--odis-cross-reference) checkable. <https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md>

<!-- list break: reference numbers are not contiguous -->

30. **NIST AI Risk Management Framework (AI RMF 1.0)**: NIST, January 2023; **currently under revision**. GOVERN / MAP / MEASURE / MANAGE. <https://www.nist.gov/itl/ai-risk-management-framework> · companion **NIST AI 600-1, Generative AI Profile** (July 2024). Mapped in [XM §7](Telemetry-Cross-Mapping-Addendum.md#7-implications-for-nist-ai-rmf-and-nist-csf-incl-the-cyber-ai-profile).
31. **NIST Cybersecurity Framework (CSF) 2.0**: GV / ID / PR / DE / RS / RC; 6 functions, 22 categories, 106 subcategories. <https://www.nist.gov/cyberframework>

<!-- list break: reference numbers are not contiguous -->

33. **ISO/IEC 42001:2023**: *Information technology — Artificial intelligence — Management system.* Clauses 4 to 10 plus **Annex A** (38 controls under 9 objectives, A.2 to A.10) selected via a Statement of Applicability. Paid standard. <https://www.iso.org/standard/42001>. Mapped in [XM §8](Telemetry-Cross-Mapping-Addendum.md#8-implications-for-isoiec-42001).
34. **EU AI Act. Article 12 (Record-keeping / Logging).** <https://artificialintelligenceact.eu/article/12/>
35. **OpenTelemetry, GenAI semantic conventions.** Now maintained in a dedicated repository: <https://github.com/open-telemetry/semantic-conventions-genai>. Spans, metrics, events, MCP, and provider-specific conventions, **all at Development status**. Attribute registry: <https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/>. Entries marked *Deprecated* there mostly reflect the relocation rather than withdrawal, but not always: some were **renamed** in the move (`gen_ai.usage.cache_creation.input_tokens` → `gen_ai.usage.cache_write.input_tokens`) and some were **withdrawn outright** (`gen_ai.prompt` and `gen_ai.completion`, both `reason: obsoleted`, "Removed, no replacement at this time"). Names therefore come from the new repository, not the deprecated registry. **Names in XM §§2 to 4 were verified against `semantic-conventions-genai` @ `0c87594` (10 September 2026) and `semantic-conventions` @ `22b6cbb` (9 September 2026); neither repository publishes release tags, so commit SHAs are the only stable anchor.** Cross referenced in [XM §2](Telemetry-Cross-Mapping-Addendum.md#2-implications-for-opentelemetry-the-instrumentation-bridge).
36. **OpenTelemetry, core specification.** Signals, context propagation, sampling. <https://opentelemetry.io/docs/specs/otel/> · **W3C Trace Context**: <https://www.w3.org/TR/trace-context/> · MCP context propagation via `params._meta` (**SEP-414**): <https://modelcontextprotocol.io/community/seps/414-request-meta>
37. **OCSF. Open Cybersecurity Schema Framework.** <https://ocsf.io/> · schema browser: <https://schema.ocsf.io/>
38. **OWASP AOS, Agent Observability Standard.** OWASP. <https://aos.owasp.org/>. Three pillars (Instrument / Trace / Inspect); cross referenced in [XM §5](Telemetry-Cross-Mapping-Addendum.md#5-owasp-aos-cross-reference). *Working draft.* Verified against the specification sources at commit `e4a50f6` (30 December 2025), schema version **0.1.0** (`specification/AOS/aos_schema.json` in [OWASP/www-project-agent-observability-standard](https://github.com/OWASP/www-project-agent-observability-standard)); the specification has not changed since that date.
39. **Model Context Protocol (MCP).** <https://modelcontextprotocol.io/>. Tools, resources, prompts, sampling, elicitation, roots (AD §1.5).
40. **A2A, Agent-to-Agent Protocol.** <https://a2a-protocol.org/>. Agent cards, task lifecycle, push-notification configuration (AD §1.8).

<!-- list break: reference numbers are not contiguous -->

44. **CPEX**: policy-enforcement runtime and reference monitor for AI agents. <https://contextforge-org.github.io/cpex/> · threat model: <https://contextforge-org.github.io/cpex/docs/threat-model/>, cross referenced in [XM §6](Telemetry-Cross-Mapping-Addendum.md#6-cpex-cross-reference). Verified against [contextforge-org/cpex](https://github.com/contextforge-org/cpex) at commit `035012f` (18 August 2026). Pinned to a commit rather than to the current release (`v0.2.2`, 15 July 2026), which predates the threat-model document this appendix cites.

<!-- list break: reference numbers are not contiguous -->

51. **RFC 2119**: Bradner, S. *Key words for use in RFCs to Indicate Requirement Levels.* BCP 14, RFC 2119 (1997). <https://www.rfc-editor.org/rfc/rfc2119>
52. **RFC 8174**: Leiba, B. *Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.* BCP 14, RFC 8174 (2017). <https://www.rfc-editor.org/rfc/rfc8174>
