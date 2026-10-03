# Telemetry for AI Security {**Working Draft v0.6**}

**Status:** Request for Comments, revision 0.6

**Origin:** Coalition for Secure AI (CoSAI), Workstream 2 (Defenders)

**Companion documents:** [Attack Detection Addendum](Telemetry-Attack-Detection-Addendum.md) (cited as AD) and [Cross-Mapping Addendum](Telemetry-Cross-Mapping-Addendum.md) (cited as XM).

**Disclosure:** This document was prepared for open publication under CoSAI, with no commercial sponsorship; the standards positions taken favor open specifications and open-source projects (OpenTelemetry, OCSF, OWASP AOS, CPEX) over proprietary implementations. Drafting, cross-referencing, and consistency checking were performed with AI assistance.

---

## 1. Introduction

AI systems now read untrusted content, decide what to do about it, and act: calling tools, writing memory, retrieving documents, sending mail, invoking other agents. Attacks against them succeed in the gap between reading and acting. Detection has to happen in that gap, as far left in the kill chain as possible.

Catching an injection attack in flight means knowing what the model was given, how far that input was trusted, what it decided to do, and where its output went. Default application logging records none of this. It captures HTTP requests, database queries, and authentication events. The decisive moments in an AI system (an instruction arriving inside a retrieved document, a guardrail verdict, a memory write that will shape every future session) leave no trace there. Without those records there is nothing to detect against, and afterwards nothing solid to investigate, debug, or audit.

Nor is the adversary always external. In July 2026, frontier models under evaluation at OpenAI and Anthropic reached production systems at other organizations from their test environments, and Hugging Face published a forensic timeline of one intrusion [[64]](#other-sources).

### 1.1 One umbrella, many efforts

Several communities are converging on AI telemetry, and their work is complementary. OpenTelemetry [[35]](#standards--frameworks) defines how instrumentation emits GenAI and agent data. OCSF, the Open Cybersecurity Schema Framework [[37]](#standards--frameworks), defines how security events are normalized for a security operations center (SOC). OWASP AOS, the Agent Observability Standard [[38]](#standards--frameworks), defines how an agent exposes itself for observation. CPEX [[44]](#standards--frameworks) defines how a policy runtime mediates agent actions. ODIS, the Open Delegation and Identity Standard [[26]](#standards--frameworks), defines delegated identity and authority. MITRE ATLAS [[1]](#primary-sources-attack-corpus--taxonomy) defines the adversary techniques to classify against. EU AI Act Article 12 [[34]](#standards--frameworks) imposes record-keeping on high-risk AI systems, and the NIST AI Risk Management Framework [[30]](#standards--frameworks) offers voluntary guidance.

Those efforts answer different questions. This RFC is the requirements layer: it specifies the fields an AI system needs to produce for security, the evidence that makes each field necessary, and the order in which to build them.

### 1.2 For example: EchoLeak

In June 2025 Microsoft disclosed EchoLeak (CVE-2025-32711, CVSS 9.3 as scored by Microsoft), reported by Aim Labs [[4]](#real-world-attack-primary-sources): an external adversary against a production deployment, documented end to end. A single crafted email caused Microsoft 365 Copilot to retrieve the attacker's text as context, act on it as instruction, and exfiltrate internal SharePoint, OneDrive and Teams content to an attacker-controlled endpoint. No user ever clicked anything. The chain defeated the cross-prompt-injection classifier, link redaction, and content-security policy in turn, and routed the egress through a trusted proxy domain.

Each step in that chain would have left evidence in a field that default logging does not collect:

- The email entered as untrusted data and was acted on as instruction, a distinction nothing recorded.
- The victim asked Copilot an ordinary question, and retrieval placed an external sender's email beside internal files in the answer's context. The provenance of retrieved content records how an external email was promoted into the prompt.
- The injection classifier was bypassed. A classifier whose verdicts are not logged cannot be shown to have failed.
- Content left for a previously unseen outbound destination: the last point at which the attack could have been stopped rather than reconstructed afterwards.

These are four fields, none exotic: Input Trust Classification, Retrieved-Content Source / Provenance, Guardrail (Input) Verdict and Output Egress Destination. Without them a detection has nothing to read, and the first record of the attack is the disclosure notice.

---

## 2. Scope

### 2.1 In scope

In scope is the security telemetry an AI system needs to produce. For each field the RFC gives its tier (**MUST**, **SHOULD**, or **MAY**, against the test in [§4.7](#47-tiers)) and the component that emits it, in implementation order ([§6](#6-field-catalog)). The [Attack Detection Addendum](Telemetry-Attack-Detection-Addendum.md) gives the documented attacks behind each field, and the correlation patterns that combine fields into detections. The [Cross-Mapping Addendum](Telemetry-Cross-Mapping-Addendum.md) maps the field catalog onto OpenTelemetry, OCSF, the AI Telemetry Framework (AITF) [[25]](#standards--frameworks), ODIS, OWASP AOS, the NIST Cybersecurity Framework (CSF) [[31]](#standards--frameworks) and AI RMF, and ISO/IEC 42001 [[33]](#standards--frameworks).

Telemetry for agents the deployment does not operate is in scope, within the limits set in [§4.6](#46-record-your-boundary-not-their-internals).

The catalog covers the runtime path and, as an independent track, training data and training infrastructure ([§6.7](#67-training-data-and-training-infrastructure)). It covers the security slice of AI trustworthiness; fairness, bias, safety alignment, and environmental impact are outside its remit.

### 2.2 Not in scope

This RFC is not a wire format.

It does not specify detection logic, only the fields detections consume.

Security and privacy of the telemetry itself are left to a later CoSAI publication. That covers authenticating emitters, securing transport and storage, controlling access to collected content, the sensitivity of content hashes, retention, redaction, encryption, tamper-evidence, and chain of custody. It also covers privacy compliance: lawful basis, data-subject rights, cross-border transfer, and impact assessment. The field catalog treats the telemetry plane as an asset only insofar as it reports its own failure ([§4.5](#45-a-missing-verdict-is-not-an-allow)). Meeting the MUST tier discharges none of those obligations, and it does not satisfy the CoSAI Risk Map's [[23]](#standards--frameworks) proposed `controlAuditTrailIntegrityVerification` and `controlAuditRecordRepositoryIndependence`; adopters needing audit-grade evidence need to implement them separately.

No field closes a covert channel inside permitted output; **Output Egress Destination** and **Citations / Source Attribution** narrow it. The catalog also assumes that the hosts running enforcement points are intact.

### 2.3 Terms

A **documented instance** is an attack, incident, resisted attempt, or failure traceable to a primary source; a taxonomy entry shows only that a scenario is recognized. The **evidence gate** admits a field only where the corpus motivates it, and to MUST only where documented instances require it ([§4.2](#42-evidence-sets-the-tier)). A **deployment modality** is a capability a deployment may or may not run, such as delegated authority, multi-tenancy, or agent-to-agent messaging; SHOULD fields apply once it runs ([§4.7](#47-tiers)). A **provider-gated** field depends on a signal the model or platform provider may not expose.

A **self-asserted** value is one an agent or counterparty supplies about itself, with no independent authority ([§4.4](#44-the-agent-might-be-lying)). A claim about an outcome is **verified** when an identifier in the record resolves it to the result it rests on, recorded by a component the deployment operates other than the one making the claim, and **unresolved** when none does ([§4.4](#44-the-agent-might-be-lying)). A **knowability tier** (mediated, attested, or opaque) states how much a deployment can observe of a counterparty it does not operate ([§4.6](#46-record-your-boundary-not-their-internals)).

A **content-bearing field** is one whose value includes text or a payload that a model reads or produces. The **telemetry plane** is the instrumentation, enforcement callouts, and pipeline that produce and carry these records.

---

## 3. How To Use This Doc

### 3.1 For CISOs

Go to the field catalog ([§6](#6-field-catalog)), which lists every field by implementation step and tier with its emitting component. Treat the applicable subset of the MUST column as the baseline for each AI deployment; [§5.1](#51-applicability-and-emission) defines applicability. The three tiers are **MUST**, **SHOULD**, and **MAY**, used in the RFC 2119 sense and defined in [§4.7](#47-tiers). The catalog contains 52 MUST fields. This is the artifact to take into an engineering plan or a budget discussion.

- **The justification is evidentiary.** Every MUST field rests on at least two documented instances from the corpus, or is needed to read another MUST field. The ask is "these fields catch these attacks," not "best practice suggests." Each field's entry in [AD §1](Telemetry-Attack-Detection-Addendum.md#1-field-tables) sets out that reasoning if it is challenged.
- **There is a build order.** The catalog is ordered by implementation step ([§6](#6-field-catalog)).
- **Adoption runs through existing standards.** The fields bind to OpenTelemetry for emission and to OCSF for SOC consumption ([XM §§1 and 2](Telemetry-Cross-Mapping-Addendum.md#1-ocsf)), and AITF carries all but five MUST fields on both today ([XM §3.4](Telemetry-Cross-Mapping-Addendum.md#34-path-to-ocsf-and-opentelemetry)). That lowers the cost of building to the catalog without removing it; where neither standard carries a field yet, the asks are in [XM §1.4](Telemetry-Cross-Mapping-Addendum.md#14-asks) and [XM §2.4](Telemetry-Cross-Mapping-Addendum.md#24-asks).
- **Compliance follows detection.** Fields built for detection also give an auditor the event content. Audit-grade evidence further needs the integrity and retention controls that [§2.2](#22-not-in-scope) excludes. Fields built only for audit produce no detection. The NIST and ISO/IEC 42001 mappings are in [XM §6](Telemetry-Cross-Mapping-Addendum.md#6-nist-csf-ai-rmf-and-isoiec-42001).

One decision cannot be delegated to engineering: how much prompt, response, and memory content is retained, for how long, and who can read it. For content-bearing fields the MUST tier requires a content hash, not the raw content ([§5.3](#53-content-hashing)); keeping raw content is a policy call, to be made deliberately rather than by default. The decision is recorded in the deployment's conformance statement ([§5](#5-conformance)).

### 3.2 For defenders of AI systems

To operationalize telemetry collection for a live AI system:

1. **Scope.** Map what you run onto the Risk Map components ([§6](#6-field-catalog)). Fields for components you do not run are not applicable ([§5.1](#51-applicability-and-emission)).
2. **Select.** From the field catalog ([§6](#6-field-catalog)), take every MUST field your components emit, plus the SHOULD fields for each modality you run ([§4.7](#47-tiers)). That list is your baseline.
3. **Define.** Read each field's capture definition and evidence in [AD §1](Telemetry-Attack-Detection-Addendum.md#1-field-tables).
4. **Bind.** Use the OpenTelemetry attribute names and signal placement in [XM §2](Telemetry-Cross-Mapping-Addendum.md#2-opentelemetry), the OCSF mapping in [XM §1](Telemetry-Cross-Mapping-Addendum.md#1-ocsf), and the AITF names in [XM §3](Telemetry-Cross-Mapping-Addendum.md#3-aitf). Do not invent a schema.
5. **Conform.** Meet the hashing and sampling rules in [§5](#5-conformance). Propagate trace context across every hop you operate, including Model Context Protocol (MCP) [[39]](#standards--frameworks) and agent-to-agent (A2A) [[40]](#standards--frameworks) calls.
6. **Sequence.** Build in the order of [§6](#6-field-catalog): each subsection is one step. [§6.1](#61-identifiers-trace-context-and-model-identity) comes first because every later step resolves through its identifiers.
7. **Detect.** Implement the correlation patterns in [AD §2](Telemetry-Attack-Detection-Addendum.md#2-correlation-patterns) as your first detections, and use the attacks each field cites ([AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory)) as test cases. Stamping each fired detection with its ATLAS technique ([AD §3.6](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping)) lets AI alerts join ATT&CK-aligned tooling; the tag itself is MAY ([§6.2](#62-content-trust-verdicts-and-their-availability)).

---

## 4. Principles

### 4.1 Detection first

Every field is justified against four use cases, in this priority order:

| Code | Use case | What it means |
| :---- | :------------------------- | :---------------------------------------------------------------------- |
| **D** | **Threat detection** | Enables a detection to fire on an attack in progress. *Highest priority.* |
| **R** | **Incident response** | Enables scoping, attribution, containment, and forensic reconstruction after the fact. |
| **Q** | **Service debugging / quality** | Explains why the system behaved as it did; performance, cost, and correctness. |
| **A** | **Compliance audit** | Evidences a control to an auditor or regulator. *Lowest priority.* |

Where a field serves several, the highest-priority use case governs its tier. A field whose value is mainly Q or A does not reach MUST no matter how useful it is.

### 4.2 Evidence sets the tier

A field earns its tier through three gates. The **evidence gate** admits it to MUST only where documented instances require it, directly or through a MUST field it is needed to read, and never on a judgment that it would be useful. The **priority gate** ([§4.1](#41-detection-first)) keeps a field whose value is mainly Q or A out of MUST. The **modality gate** holds a field serving a modality not yet typical of deployments at SHOULD, however much evidence accumulates. The gates are independent. The test is in [§4.7](#47-tiers); the corpus is in [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory).

### 4.3 Untrusted instruction is the attack state

Prompt injection succeeds when content from an untrusted origin is consumed as instruction. The input handler cannot see how the model uses a segment, so it records what it can. **Input Trust Classification** ([§6.2](#62-content-trust-verdicts-and-their-availability)) crosses the segment's origin (trusted or untrusted) with the role the deployment assigned it on entry (instruction or data). Untrusted content in an instruction role is a configuration defect and alerts at once. Untrusted content in a data role reaches the attack state when the same turn then acts on it. A detection finds candidate turns by joining the classification to **Tool Call I/O** and **Output Egress Destination** on the turn ID. The link is stronger when the action's arguments, such as a recipient or URL, appear in the untrusted segment. **Model Input** and **Input Source / Channel** make the classification checkable, and the guardrail verdicts record whether a classifier caught it. In EchoLeak ([§1.2](#12-for-example-echoleak)) the email entered as untrusted data and drove the egress, and nothing recorded either.

### 4.4 The agent might be lying

The CPEX threat model [[44]](#standards--frameworks) treats a compromised agent as a potential source of false statements, not only as a victim. The corpus shows that agents do misreport [[2]](#primary-sources-attack-corpus--taxonomy). In `AOC-07` the agent declared "I'm done responding" more than a dozen times and kept replying; in `AOC-01` it claimed a secret had been deleted while the data remained recoverable.

These fields are self-asserted and carry no independent authority: **Autonomy Level** and **System Prompt / Instruction Config** ([§6.1](#61-identifiers-trace-context-and-model-identity)), **Observation / Thought** ([§6.2](#62-content-trust-verdicts-and-their-availability)), **Tool Selection Rationale** ([§6.3](#63-tool-calls-and-policy-decisions)), **Memory Write Rationale** ([§6.4](#64-memory-and-retrieval)), and **Task / Intent Declaration** ([§6.5](#65-orchestration)). **Peer Agent Card / Descriptor** ([§6.5](#65-orchestration)) is the counterparty's assertion rather than the agent's own, and carries the same weakness. A detection resting on any of these inherits whatever the agent chose to say, which is why **Attribute Source / Trusted-Provenance Marking** ([§6.2](#62-content-trust-verdicts-and-their-availability)) is a cross-cutting MUST.

A claim about an outcome is verified or unresolved ([§2.3](#23-terms)). For example, **Execution Status** ([§6.1](#61-identifiers-trace-context-and-model-identity)) is verified when its **Tool Execution ID** matches a **Tool Call I/O** outcome ([§6.3](#63-tool-calls-and-policy-decisions)). A claim with no such identifier is **unresolved**: the record says so, and no reader can settle it. Recording unresolved claims as unresolved, rather than counting them as outcomes, makes corroboration a property a checker can decide.

### 4.5 A missing verdict is not an allow

Every detection assumes the telemetry plane worked. When a guardrail is starved or a hook disabled, a verdict that never arrived reads the same as a verdict of `allow`. Provider and availability signals belong here for the same reason: a provider that silently truncates a response is a failure the record has to distinguish from a clean result ([AD §4](Telemetry-Attack-Detection-Addendum.md#4-tiering-rationale)). The field catalog therefore records the plane's own failures: **Instrumentation Coverage / Hook Attestation** and **Enforcement-Point Availability & Failure Mode** ([§6.2](#62-content-trust-verdicts-and-their-availability)), and **Event Sequence Continuity** ([§6.6](#66-identity-provenance-and-inventory)). It records what policy decided, on which rule, and whether any path bypassed it: **Authorization Decision Record** and **Mediation Coverage & Bypass Path** ([§6.3](#63-tool-calls-and-policy-decisions)). A missing verdict is found by comparison: the model calls recorded in **Action Type** for a turn, against the verdicts and callouts recorded for it. The same reasoning makes the sampling rules normative ([§5.2](#52-sampling)): an event sampled away is indistinguishable from one that never occurred. Defending the plane itself is out of scope ([§2.2](#22-not-in-scope)).

### 4.6 Record your boundary, not their internals

Much of the corpus involves a counterparty someone else runs: another owner's agent (`AOC-11` [[2]](#primary-sources-attack-corpus--taxonomy)), an MCP server you did not deploy (`TA-12` [[15]](#real-world-attack-primary-sources), `TA-13` [[16]](#real-world-attack-primary-sources)), or a shared multi-tenant service (`TA-11` [[14]](#real-world-attack-primary-sources)). You cannot instrument what you do not operate, so the field catalog applies differently. Each adjacent standard supplies a rule. CPEX [[44]](#standards--frameworks) instruments your own boundary, not the counterparty's internals. ODIS [[26]](#standards--frameworks) makes authority legible through presented, verifiable claims. OWASP AOS [[38]](#standards--frameworks) asks the counterparty to be inspectable, and you record the answer.

Read every field in [§6](#6-field-catalog) against one of these **knowability** tiers, which **Attribute Source / Trusted-Provenance Marking** ([§6.2](#62-content-trust-verdicts-and-their-availability)) records for each counterparty:

| Tier | What you have | How the field catalog applies |
| :------- | :------------------------- | :------------------------------------------------ |
| **Mediated** | You own the boundary the interaction crosses | Full boundary telemetry: the input, output, tool, and policy-enforcement fields apply as written. The counterparty's internals are absent, and their absence is expected rather than a gap |
| **Attested** | The counterparty presents verifiable claims (ODIS credential, signed agent bill of materials (AgBOM), agent card) | Record the claim and its verification outcome. an unverified claim is `self-asserted`, whatever it asserts |
| **Opaque** | Only the wire interaction | The input, output, and orchestration fields at the protocol surface, and nothing more. Do not synthesize fields you cannot observe. An opaque counterparty needs to be visibly opaque in the telemetry, not silently defaulted |

The third row collapsing into the second is the failure to avoid: recording an external agent's self-description as though it were established fact. In `AOC-08` [[2]](#primary-sources-attack-corpus--taxonomy) an agent accepted a spoofed display name as its owner, which is that failure in miniature. In `AOC-11` an impersonated owner drove a mass broadcast of defamatory email, which is its consequence at scale.

### 4.7 Tiers

The keywords **MUST**, **SHOULD**, and **MAY** are used as defined in RFC 2119 [[51]](#standards--frameworks), as updated by RFC 8174 [[52]](#standards--frameworks). They carry that meaning only in capitals; lowercase `optional` or `should` is ordinary prose. Each field carries one keyword; the table gives its obligation and the test that assigns it.

| Tag | Meaning | Test |
| :---- | :-------------------- | :------------------------------------------------------------------------------ |
| **MUST** | The baseline, wherever the field applies ([§5.1](#51-applicability-and-emission)). | At least two independent documented instances in [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) require it, or an applicable MUST field cannot be read without it: that field's value would be ambiguous between states a detection has to distinguish, or inaccurate. Analogical grounding does not count toward the two, and neither does an entry the inventory marks as outside AI systems. In either case the field is implementable wherever its component, operation, or event exists. |
| **SHOULD** | Applies once a deployment runs the modality it serves. | Serves a deployment modality, named in its [§6](#6-field-catalog) row, that is not yet typical of deployments; or is provider-gated. Attack grounding can be analogical: the corpus motivates the scenario without yet containing a documented instance. |
| **MAY** | Valuable, but not needed to catch the core attack classes. | The field's dominant value is Q or A; or it has fewer than two independent documented instances, no MUST field depends on it, and it serves no modality; or it is a research-grade signal, or redundant with a MUST field. |

Two instances are independent when they are separate incidents, not two accounts of the same event. A field whose defining event is itself conditional (a rewrite, an emitted citation, a fired detection) is tiered like any other and applies where that event occurs ([§5.1](#51-applicability-and-emission)): conditionality is applicability, not a tier. Whether a field is observed or derived does not affect its tier. What counts as a documented instance, and how the evidence and priority tests interact, is set out in [AD §§3 and 4](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory). Tiers reflect evidence and how common a modality is, not any vendor's maturity; build sequencing is in [§6](#6-field-catalog).

**SHOULD is not "MUST later."** It is "MUST *if you run this modality*". RFC 2119 lets a SHOULD field be omitted for "valid reasons in particular circumstances". Here a valid reason is not running the modality the field serves, or, for a provider-gated field, a provider that does not expose the signal. Cost, effort, and inconvenience are not valid reasons.
---

## 5. Conformance

A deployment states conformance in a **conformance statement**. It lists each applicable MUST field as emitted, and each inapplicable field as not applicable, naming the component, operation, or event that is absent. It also records the sampling configuration, the digest algorithm and canonicalization, and the decision on retaining raw content. It is reissued when the deployment's components, sampling configuration, or digest algorithm change.

### 5.1 Applicability and emission

1. **A field applies only where its defining component, operation, or event exists.** The memory fields ([§6.4](#64-memory-and-retrieval)) apply when the deployment uses persistent memory, and **Inter-Agent Message** when an agent-to-agent message is sent. An inapplicable field is marked not applicable in the conformance statement; a deployment does not add a component, manufacture an event, or emit a synthetic value to fill it.
2. **Every applicable MUST field is supported, and emitted whenever its event occurs.** Each event carries only the fields that apply to its class: a field absent because its event did not occur is not a defect, and a field omitted from an event it applies to is.

### 5.2 Sampling

Default OpenTelemetry [[36]](#standards--frameworks) head sampling ignores security relevance, so where OpenTelemetry carries security telemetry ([XM §2.8](Telemetry-Cross-Mapping-Addendum.md#28-context-propagation-sampling-privacy-and-canonicalization) gives the rationale):

1. **Security-relevant events MUST NOT be head-sampled.** Guardrail verdicts, refusals, tool errors, authorization denials, capability changes, session and turn stop events carrying a **Stop Reason** ([§6.1](#61-identifiers-trace-context-and-model-identity)), per-invocation tool activity, and any event carrying a fired detection are recorded at 100%.
2. **Where tail sampling is used, security relevance MUST be a retention predicate**: a trace containing a block, a denial, an error, or a flagged classification is always kept.
3. **The sampling configuration in force MUST itself be recorded as telemetry**, in **Instrumentation Coverage / Hook Attestation** ([§6.2](#62-content-trust-verdicts-and-their-availability)), for the reason in [§4.5](#45-a-missing-verdict-is-not-an-allow).

### 5.3 Content hashing

1. **Every content-bearing field MUST carry a content hash.** Whether raw content accompanies it is deployment policy.
2. **The canonicalization the digest is taken over MUST be declared**, by the deployment or by the carrier ([XM §2.8](Telemetry-Cross-Mapping-Addendum.md#28-context-propagation-sampling-privacy-and-canonicalization)). Otherwise two emitters that hash the same tool call under different serializations produce different digests, and the hash correlates only within one producer. Consumers MUST NOT compare digests across producers whose declared canonicalizations differ.
3. **Where a field carries an identifier, the obligation is the signal, not the identifier.** For **Content Modality & Attachment Identity** ([§6.2](#62-content-trust-verdicts-and-their-availability)) it is the content hash, and the filename is policy. For **Citations / Source Attribution** ([§6.2](#62-content-trust-verdicts-and-their-availability)) it is the resolution outcome, whether each citation resolves to an item returned by a logged Retrieval Event, and the clear-text URL is policy.

The hash is the correlation primitive the corpus turns on: `AOC-03` [[2]](#primary-sources-attack-corpus--taxonomy) (extraction escalating across turns) and `IR-02` [[3]](#primary-sources-attack-corpus--taxonomy) (an implant persisting into later sessions) are both detected by matching one content item against another. A digest matches only content that is identical after canonicalization. It finds a repeated payload without the raw text, but a fragment or a paraphrase needs retained text or a finer-grained digest. Requiring the hash, and leaving raw content to policy, lets deployments with different privacy postures compare content without exchanging it.

## 6. Field catalog

Every field in the set, 101 in all: 52 MUST, 33 SHOULD and 16 MAY, grouped by implementation step, then by tier. Within a step the MUST fields form the baseline, SHOULD fields wait for their modality ([§4.7](#47-tiers)), and MAY fields can be added at any point. Together the MUST fields supply the records for detecting prompt injection, data disclosure through model output and egress, memory and retrieval poisoning, exfiltration, resource abuse and denial of service, identity spoofing, runaway multi-agent loops, and unauthorized action. Each name links to its full definition (what to capture, and the attacks that require it) in the [Attack Detection Addendum](Telemetry-Attack-Detection-Addendum.md#1-field-tables). For content-bearing fields, "What it records" describes the content the hash covers; whether raw content is kept is deployment policy ([§5.3](#53-content-hashing)). The basis and reasoning for each tier are in the field's AD entry, and what applies across fields in [AD §4](Telemetry-Attack-Detection-Addendum.md#4-tiering-rationale).

The "Emitted by" column names the CoSAI Risk Map [[23]](#standards--frameworks) component that produces each field, using the canonical IDs in [`risk-map/yaml/components.yaml`](https://github.com/cosai-oasis/secure-ai-tooling/blob/37e7beddd6611bdeb61ad707492aed069bcc51af/risk-map/yaml/components.yaml). Events do not carry a component identifier: attribution is a mapping, which costs nothing at runtime, whereas an emitted identifier would need a resolvable namespace and a deprecation policy, since events are immutable and a component renamed upstream would invalidate every event already carrying it. Fields for the data and training components and for `componentRuntimeHosting` form an independent track ([§6.7](#67-training-data-and-training-infrastructure)), grounded by `TA-33` to `TA-36` ([AD §3.2](Telemetry-Attack-Detection-Addendum.md#32-real-world-attack-vectors)). Two earlier entries, `IR-05` [[3]](#primary-sources-attack-corpus--taxonomy) and `AOC-10` [[2]](#primary-sources-attack-corpus--taxonomy), carry the ATLAS training-poisoning technique `AML.T0020`, but both poison memory and retrieval at runtime.

### 6.1 Identifiers, trace context and model identity

Every later detection resolves through these identifiers; the model and serving fields travel on the same span as each model call.

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Agent Name](Telemetry-Attack-Detection-Addendum.md#f-agent-name) | MUST | Logical name or type of the agent; exposes off-inventory agents. | `componentReasoningCore` |
| [Agent (Runtime) Instance ID](Telemetry-Attack-Detection-Addendum.md#f-agent-runtime-instance-id) | MUST | The running instance an event belongs to, for per-instance quarantine. | `componentReasoningCore` |
| [Workflow / Run ID](Telemetry-Attack-Detection-Addendum.md#f-workflow-run-id) | MUST | Groups one multi-step run or sub-agent tree into one execution. | `componentReasoningCore` |
| [Session / Turn / Step IDs](Telemetry-Attack-Detection-Addendum.md#f-session-turn-step-ids) | MUST | The session, turn and step beneath a run, locating where behavior changed. | `componentApplication`, `componentReasoningCore` |
| [Trigger Type & Source Event](Telemetry-Attack-Detection-Addendum.md#f-trigger-type-source-event) | MUST | User-initiated or autonomous, and for autonomous runs the originating event. | `componentReasoningCore` |
| [Action Type](Telemetry-Attack-Detection-Addendum.md#f-action-type) | MUST | LLM call, tool call, memory operation or message send. | `componentReasoningCore` |
| [Execution Status](Telemetry-Attack-Detection-Addendum.md#f-execution-status) | MUST | Outcome and duration of an operation or turn. | `componentReasoningCore` |
| [Surface / App](Telemetry-Attack-Detection-Addendum.md#f-surface-app) | MUST | Entry point: CLI, web, IDE, email, chat, scheduler; internal or external. | `componentApplication` |
| [System Prompt / Instruction Config](Telemetry-Attack-Detection-Addendum.md#f-system-prompt-instruction-config) | MUST | Instruction configuration in force for the call. Self-asserted. | `componentAgentSystemInstruction` |
| [Model Name + Version](Telemetry-Attack-Detection-Addendum.md#f-model-name-version) | MUST | Model and version that processed the request. | `componentModelServing` |
| [Inference Parameters](Telemetry-Attack-Detection-Addendum.md#f-inference-parameters) | MUST | Decoding parameters and declared context window in force for the call; the denominator for max-length-output and oversized-input detections. | `componentModelServing` |
| [Input / Output Token Counts](Telemetry-Attack-Detection-Addendum.md#f-input-output-token-counts) | MUST | Per-call token usage, which feeds the Resource-Consumption Aggregate budget check. | `componentModelServing` |
| [LLM Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-llm-error-exception) | MUST | Errors under adversarial conditions and provider-side silent failures. | `componentModelServing` |
| [Trace Context (propagated)](Telemetry-Attack-Detection-Addendum.md#f-trace-context-propagated) | MUST | W3C trace context carried across every agent and tool hop. | every hop |
| [Stop Reason](Telemetry-Attack-Detection-Addendum.md#f-stop-reason) | MUST | Why a completion ended: end of turn, token limit, tool use, cancellation, content filter. | `componentReasoningCore` |
| [Autonomy Level](Telemetry-Attack-Detection-Addendum.md#f-autonomy-level) | SHOULD | Declared independence level the run is authorized for. Self-asserted. Modality: autonomous action. | `componentReasoningCore` |
| [Model Provenance / Signing / Hash](Telemetry-Attack-Detection-Addendum.md#f-model-provenance-signing-hash) | SHOULD | Signed digest or provenance of the served model artifact. Modality: supply-chain attestation. | `componentModelServing`, `componentModelRegistry` |
| [Organization / Tenant ID](Telemetry-Attack-Detection-Addendum.md#f-organization-tenant-id) | SHOULD | Owning tenant of the agent, the session and the invoking user. Modality: multi-tenancy. | agent, session and user records |
| [Provider / Endpoint Identity](Telemetry-Attack-Detection-Addendum.md#f-provider-endpoint-identity) | MAY | Which provider or endpoint served the call. | `componentModelServing` |
| [Pre-Forward-Pass State Digest/Vector](Telemetry-Attack-Detection-Addendum.md#f-pre-forward-pass-state-digest-vector) | MAY | Digest of the exact inputs to a forward pass, for replay and drift detection. | `componentTheModel` |
| [Token Malformation / Context-Corruption Indicator](Telemetry-Attack-Detection-Addendum.md#f-token-malformation-context-corruption-indicator) | MAY | Token-entropy anomalies correlated with confabulation. | `componentTheModel` |

### 6.2 Content, trust, verdicts and their availability

This is the densest detection step. With [§6.1](#61-identifiers-trace-context-and-model-identity), it supplies the records an injection detection reads. Coverage, enforcement-point availability and attribute provenance come with it, for the reasons in [§§4.4 to 4.5](#44-the-agent-might-be-lying).

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Model Input](Telemetry-Attack-Detection-Addendum.md#f-model-input) | MUST | Every input to each model call, including tool output, retrieved context and messages. | `componentApplicationInputHandling`, `componentAgentInputHandling` |
| [Input Source / Channel](Telemetry-Attack-Detection-Addendum.md#f-input-source-channel) | MUST | Which surface, tool, agent or document each input segment came from. | `componentApplicationInputHandling`, `componentAgentInputHandling` |
| [Input Trust Classification](Telemetry-Attack-Detection-Addendum.md#f-input-trust-classification) | MUST | Trusted or untrusted origin, crossed with the role assigned on entry: instruction or data. | `componentAgentInputHandling` |
| [Source host / IP + request metadata](Telemetry-Attack-Detection-Addendum.md#f-source-host-ip-request-metadata) | MUST | Origin of the request, for geo, rate and credential-theft detection. | `componentApplicationInputHandling` |
| [Guardrail (Input) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-input-verdict) | MUST | Input classifier result (pass, flag, block, modify) with detector and score. | `componentApplicationInputHandling`, `componentAgentInputHandling` |
| [Response / Model Output](Telemetry-Attack-Detection-Addendum.md#f-response-model-output) | MUST | Generated output at each step. | `componentApplicationOutputHandling`, `componentAgentOutputHandling` |
| [Output Egress Destination](Telemetry-Attack-Detection-Addendum.md#f-output-egress-destination) | MUST | Where output goes: recipients, URLs, channels, files, broadcast scope. | `componentApplicationOutputHandling`, `componentAgentOutputHandling` |
| [Citations / Source Attribution](Telemetry-Attack-Detection-Addendum.md#f-citations-source-attribution) | MUST | Sources the agent claims, and whether each resolves to a logged retrieval. | `componentApplicationOutputHandling`, `componentAgentOutputHandling` |
| [Guardrail (Output) Verdict](Telemetry-Attack-Detection-Addendum.md#f-guardrail-output-verdict) | MUST | Output filter result (pass, flag, block, modify). | `componentApplicationOutputHandling`, `componentAgentOutputHandling` |
| [LLM Refusal](Telemetry-Attack-Detection-Addendum.md#f-llm-refusal) | MUST | Refusal status and reason. | `componentAgentOutputHandling` |
| [Content Modality & Attachment Identity](Telemetry-Attack-Detection-Addendum.md#f-content-modality-attachment-identity) | MUST | Part type, MIME type, and for files name, size and hash, on every content-bearing field. | every content-bearing field |
| [Attribute Source / Trusted-Provenance Marking](Telemetry-Attack-Detection-Addendum.md#f-attribute-source-trusted-provenance-marking) | MUST | The authority that supplied each security-relevant attribute, or that it is self-asserted, and each counterparty's knowability tier. | every security-relevant attribute |
| [Instrumentation Coverage / Hook Attestation](Telemetry-Attack-Detection-Addendum.md#f-instrumentation-coverage-hook-attestation) | MUST | Which hooks are active, their version, where each reports, and the sampling configuration in force. | instrumentation layer |
| [Enforcement-Point Availability & Failure Mode](Telemetry-Attack-Detection-Addendum.md#f-enforcement-point-availability-failure-mode) | MUST | Whether each enforcement callout was reached, its latency, and fail-open or fail-closed. | enforcement points |
| [Guardrail Modification Record](Telemetry-Attack-Detection-Addendum.md#f-guardrail-modification-record) | MUST | That an enforcement point rewrote a payload, which one, with before and after digests. | any rewriting enforcement point |
| [Encoded / Obfuscated Payload Indicator](Telemetry-Attack-Detection-Addendum.md#f-encoded-obfuscated-payload-indicator) | MUST | Flag and decoded form of base64, image-embedded, invisible-Unicode or markup-authority input. | `componentAgentInputHandling` |
| [Observation / Thought (reasoning trace)](Telemetry-Attack-Detection-Addendum.md#f-observation-thought-reasoning-trace) | SHOULD | Reasoning trace, where the provider exposes it. Self-asserted. Provider-gated. | `componentReasoningCore` |
| [Threat Classification / ATLAS Technique Tag](Telemetry-Attack-Detection-Addendum.md#f-threat-classification-atlas-technique-tag) | MAY | MITRE ATLAS technique IDs on any event where a detection fires. | any detector |

**Conditional fields.** **Guardrail Modification Record** applies whenever an enforcement point rewrites rather than blocks ([§5.1](#51-applicability-and-emission)). **Threat Classification / ATLAS Technique Tag** applies on events where a detection fires; its values come from the mapping in [AD §3.6](Telemetry-Attack-Detection-Addendum.md#36-attack-inventory--mitre-atlas-technique-mapping). It is MAY: no documented instance requires it and no MUST field depends on it.

### 6.3 Tool calls and policy decisions

These fields carry the highest response value: what the agent did, where it ran, and what policy decided about it.

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Execution Environment / Sandbox](Telemetry-Attack-Detection-Addendum.md#f-execution-environment-sandbox) | MUST | Isolation posture: sandbox mode, runtime, OS, timeout, egress policy. | `componentIsolationRuntime`, `componentToolHosting` |
| [Tool Call I/O](Telemetry-Attack-Detection-Addendum.md#f-tool-call-io) | MUST | Full arguments and output of every tool or MCP call. | `componentToolServer`, `componentTools` |
| [Tool Name](Telemetry-Attack-Detection-Addendum.md#f-tool-name) | MUST | The capability invoked, as the agent saw it. | `componentToolServer` |
| [Tool Type / Trust Boundary](Telemetry-Attack-Detection-Addendum.md#f-tool-type-trust-boundary) | MUST | MCP, internal, direct-storage or code-execution. | `componentTools` |
| [Tool Execution ID](Telemetry-Attack-Detection-Addendum.md#f-tool-execution-id) | MUST | Correlation ID pairing each tool request with its outcome. | `componentToolServer` |
| [Tool Definition Digest](Telemetry-Attack-Detection-Addendum.md#f-tool-definition-digest) | MUST | Hash of the tool contract as presented at invocation, compared with the approved baseline. | `componentToolServer`, `componentToolRegistry` |
| [MCP Server Identity & Primitive](Telemetry-Attack-Detection-Addendum.md#f-mcp-server-identity-primitive) | MUST | MCP server name, version, transport and endpoint, and the primitive exercised. | `componentToolServer` |
| [Authorization Decision Record](Telemetry-Attack-Detection-Addendum.md#f-authorization-decision-record) | MUST | Per mediated operation: decision, reason code, deciding authority and rule. | `componentAuthorizationPolicyDecisionPoint`, `componentAuthorizationPolicyEnforcementPoint` |
| [Tool Selection Rationale](Telemetry-Attack-Detection-Addendum.md#f-tool-selection-rationale) | SHOULD | The agent's stated reason for a tool call. Self-asserted. Provider-gated. | `componentReasoningCore` |
| [Human Approval / Elicitation Event](Telemetry-Attack-Detection-Addendum.md#f-human-approval-elicitation-event) | SHOULD | Approval lifecycle: status, identity-provider-verified approver, and whether it covers the executed arguments. Modality: out-of-band human approval. | `componentAgentConsentSurface`, `componentApplicationConsentSurface` |
| [Tool ACL / Required Scope](Telemetry-Attack-Detection-Addendum.md#f-tool-acl-required-scope) | SHOULD | Authority a tool requires and who can invoke it. Modality: delegated authority. | `componentAuthorizationPolicyEnforcementPoint` |
| [Session Taint Labels & Information-Flow Decisions](Telemetry-Attack-Detection-Addendum.md#f-session-taint-labels-information-flow-decisions) | SHOULD | Information-flow labels in force, and denials caused by accumulated taint. Modality: information-flow control. | enforcement points |
| [Backend / Route Restriction Decision](Telemetry-Attack-Detection-Addendum.md#f-backend-route-restriction-decision) | SHOULD | Candidate backends, the constraint applied, the choice made. Modality: policy-driven backend selection. | enforcement points |
| [Mediation Coverage & Bypass Path](Telemetry-Attack-Detection-Addendum.md#f-mediation-coverage-bypass-path) | SHOULD | Whether an operation passed a reference monitor, where, and whether a bypass exists. Modality: reference monitor in the request path. | enforcement points |
| [Tool Error / Exception](Telemetry-Attack-Detection-Addendum.md#f-tool-error-exception) | MAY | Failed or blocked tool calls, including the probing that precedes exploitation. | `componentToolServer`, `componentToolInputHandling` |
| [Tool ID](Telemetry-Attack-Detection-Addendum.md#f-tool-id) | MAY | Unique tool-implementation ID across MCP servers. | `componentTools` |
| [Tool Privacy Classification](Telemetry-Attack-Detection-Addendum.md#f-tool-privacy-classification) | MAY | Sensitivity class of the data a tool touches. | `componentTools` |
| [Policy Reason Code](Telemetry-Attack-Detection-Addendum.md#f-policy-reason-code) | MAY | Machine-readable reason code for an enforcement decision. | enforcement points |

### 6.4 Memory and retrieval

These apply where the deployment persists state across turns or retrieves content ([§5.1](#51-applicability-and-emission)).

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Memory Write Event](Telemetry-Attack-Detection-Addendum.md#f-memory-write-event) | MUST | Each create, update or delete of a persistent memory item, and by whom. | `componentMemory` |
| [Memory Read / Injection Event](Telemetry-Attack-Detection-Addendum.md#f-memory-read-injection-event) | MUST | Which memory items were pulled into context for a call. | `componentMemory` |
| [Memory Provenance / Source](Telemetry-Attack-Detection-Addendum.md#f-memory-provenance-source) | MUST | Origin and mutability of a memory item, including externally editable sources. | `componentMemory` |
| [Memory Footprint / Growth](Telemetry-Attack-Detection-Addendum.md#f-memory-footprint-growth) | MUST | Size and growth of memory stores per user or session. | `componentMemory` |
| [Retrieval Event](Telemetry-Attack-Detection-Addendum.md#f-retrieval-event) | MUST | Query issued, items returned and their scores. | `componentRAGContent` |
| [Retrieved-Content Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-source-provenance) | MUST | Origin, owner, trust level and freshness of each retrieved item. | `componentRAGContent` |
| [Memory Integrity / Poisoning Signal](Telemetry-Attack-Detection-Addendum.md#f-memory-integrity-poisoning-signal) | SHOULD | Integrity check or poisoning score; cross-session isolation flag. Provider-gated. | `componentMemory` |
| [Memory Write Rationale](Telemetry-Attack-Detection-Addendum.md#f-memory-write-rationale) | SHOULD | The agent's stated reason for persisting an item. Self-asserted. Provider-gated. | `componentMemory` |
| [Retrieved-Content / Metadata Integrity Signal](Telemetry-Attack-Detection-Addendum.md#f-retrieved-content-metadata-integrity-signal) | SHOULD | Tamper or poisoning indicators on content or its metadata. Provider-gated. | `componentRAGContent` |
| [Declared Memory Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-memory-configuration) | MAY | A memory store's declared identity, limits and retrieval settings. | `componentMemory` |
| [Declared Knowledge-Source Configuration](Telemetry-Attack-Detection-Addendum.md#f-declared-knowledge-source-configuration) | MAY | A knowledge source's declared identity, schema and search parameters. | `componentRAGContent` |

### 6.5 Orchestration

These fields cover multi-agent and autonomous execution, where agentic risk compounds.

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Inter-Agent Message](Telemetry-Attack-Detection-Addendum.md#f-inter-agent-message) | MUST | Agent-to-agent messages: sender, receiver, content, channel. | `componentReasoningCore` |
| [Background / Scheduled Task Event](Telemetry-Attack-Detection-Addendum.md#f-background-scheduled-task-event) | MUST | Creation or change of cron jobs, heartbeats and self-scheduled loops. | `componentReasoningCore` |
| [Loop / Step-Count Signal](Telemetry-Attack-Detection-Addendum.md#f-loop-step-count-signal) | MUST | Steps per run against baseline; circular exchanges between agents. | `componentReasoningCore` |
| [Resource-Consumption Aggregate](Telemetry-Attack-Detection-Addendum.md#f-resource-consumption-aggregate) | MUST | Token, compute, storage and outbound totals per run against a budget. | `componentReasoningCore` |
| [Task / Intent Declaration](Telemetry-Attack-Detection-Addendum.md#f-task-intent-declaration) | SHOULD | Declared purpose the run is authorized to pursue. Self-asserted. Modality: autonomous action. | `componentReasoningCore` |
| [A2A Task Lifecycle Event](Telemetry-Attack-Detection-Addendum.md#f-a2a-task-lifecycle-event) | SHOULD | Delegated-task state changes across A2A, including callback registration. Modality: A2A. | `componentReasoningCore`, `componentAgentToolTransport` |
| [Peer Agent Card / Descriptor](Telemetry-Attack-Detection-Addendum.md#f-peer-agent-card-descriptor) | SHOULD | A counterparty agent's descriptor at contact, with change and verification outcome. Modality: A2A. | `componentReasoningCore` |
| [Protocol Envelope Capture](Telemetry-Attack-Detection-Addendum.md#f-protocol-envelope-capture) | MAY | Raw MCP or A2A JSON-RPC envelope alongside the interpreted fields. | `componentAgentToolTransport` |

### 6.6 Identity, provenance and inventory

These fields cover delegated identity, inventory, and the integrity of the event stream, all of which build on everything before.

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Capability-Set Change Event](Telemetry-Attack-Detection-Addendum.md#f-capability-set-change-event) | MUST | A tool, server, model, knowledge source or memory store added, removed or modified at runtime. | `componentReasoningCore` |
| [Identities Used (per hop)](Telemetry-Attack-Detection-Addendum.md#f-identities-used-per-hop) | MUST | The identity behind each agent, tool and infrastructure action, per hop. | `componentIdentityProvider` |
| [Verified vs Displayed Identity](Telemetry-Attack-Detection-Addendum.md#f-verified-vs-displayed-identity) | MUST | Verified identifier against spoofable display name, and which one authorized. | `componentIdentityProvider` |
| [Originating Principal (on-behalf-of)](Telemetry-Attack-Detection-Addendum.md#f-originating-principal-on-behalf-of) | SHOULD | The human or service at the root of the delegation chain. Modality: delegated authority. | `componentIdentityProvider`, `componentFederationProxy` |
| [Delegation Chain](Telemetry-Attack-Detection-Addendum.md#f-delegation-chain) | SHOULD | Ordered agent hops, each integrity-bound to its parent. Modality: delegated authority. | `componentFederationProxy` |
| [Granted Authorizations / Scope](Telemetry-Attack-Detection-Addendum.md#f-granted-authorizations-scope) | SHOULD | Authority in effect at this hop, with the narrowing check and its rules. Modality: delegated authority. | `componentFederationProxy` |
| [Resource Indicators + Constraints](Telemetry-Attack-Detection-Addendum.md#f-resource-indicators-constraints) | SHOULD | Target audience and time, purpose, rate, locality and classification limits. Modality: delegated authority. | `componentFederationProxy` |
| [Credential Minting & Scope-Narrowing Check](Telemetry-Attack-Detection-Addendum.md#f-credential-minting-scope-narrowing-check) | SHOULD | Each credential exchange: grant type, whose identity, and whether scope narrowed. Modality: token exchange. | `componentFederationProxy`, `componentIdentityProvider` |
| [Trust-Domain Crossing & Delegation Depth](Telemetry-Attack-Detection-Addendum.md#f-trust-domain-crossing-delegation-depth) | SHOULD | Counterparty trust domain and delegation depth, and whether a limit was crossed. Modality: delegated authority. | `componentFederationProxy` |
| [Runtime Credential / Attestation](Telemetry-Attack-Detection-Addendum.md#f-runtime-credential-attestation) | SHOULD | Runtime-instance credential and attestation evidence, each source verified separately. Modality: cryptographic agent identity. | `componentIdentityProvider` |
| [Lifecycle State](Telemetry-Attack-Detection-Addendum.md#f-lifecycle-state) | SHOULD | Active, suspended or revoked, for kill-switch and revocation fan-out. Modality: cryptographic agent identity. | `componentIdentityProvider` |
| [Tool/Agent Version](Telemetry-Attack-Detection-Addendum.md#f-tool-agent-version) | SHOULD | Version of each tool, agent and framework. Modality: dynamic third-party capability composition. | `componentToolRegistry`, `componentModelRegistry` |
| [Repository / Code Path / Software Ref](Telemetry-Attack-Detection-Addendum.md#f-repository-code-path-software-ref) | SHOULD | Source provenance of tool and agent code. Modality: dynamic third-party capability composition. | `componentToolRegistry` |
| [AgBOM / Inventory Snapshot](Telemetry-Attack-Detection-Addendum.md#f-agbom-inventory-snapshot) | SHOULD | Machine-readable inventory of the agent's composition, on change and on demand. Modality: supply-chain attestation. | `componentApplication`, `componentToolRegistry` |
| [Component Dependency Graph](Telemetry-Attack-Detection-Addendum.md#f-component-dependency-graph) | SHOULD | Dependency edges between inventoried components, including transitive ones. Modality: supply-chain attestation. | `componentApplication`, `componentToolRegistry` |
| [Inventory Attestation Signature](Telemetry-Attack-Detection-Addendum.md#f-inventory-attestation-signature) | SHOULD | Signature over the emitted inventory, binding it to a signer. Modality: supply-chain attestation. | `componentApplication`, `componentToolRegistry` |
| [Event Sequence Continuity](Telemetry-Attack-Detection-Addendum.md#f-event-sequence-continuity) | SHOULD | Per-session sequence number, hash-chained, for gap and reordering detection. Modality: self-attesting instrumentation. | `componentAuditRecordRepository` |
| [Tool Description](Telemetry-Attack-Detection-Addendum.md#f-tool-description) | MAY | Declared purpose of a tool, against which behavior is compared. | `componentToolRegistry` |
| [Tool Status (active/disabled)](Telemetry-Attack-Detection-Addendum.md#f-tool-status) | MAY | Whether a tool is meant to be reachable. | `componentToolRegistry` |
| [Creator ID / Oncall / Creation & Update dates](Telemetry-Attack-Detection-Addendum.md#f-creator-id-oncall-creation-update-dates) | MAY | Ownership and change dates. | `componentToolRegistry`, `componentModelRegistry` |
| [Surfaces Supported](Telemetry-Attack-Detection-Addendum.md#f-surfaces-supported) | MAY | Exposure map per tool. | `componentToolRegistry` |
| [Fleet counts](Telemetry-Attack-Detection-Addendum.md#f-fleet-counts) | MAY | Fleet aggregates: agents, sessions, users, tool-call volume. | fleet level |


### 6.7 Training data and training infrastructure

These fields are an independent track: they depend on none of the steps before, and whoever runs training can build them in parallel. They apply where a deployment trains or fine-tunes on externally sourced data, or runs its own training or serving compute. **Model Provenance / Signing / Hash** ([§6.1](#61-identifiers-trace-context-and-model-identity)) joins the two tracks: it ties a served model to the training run and dataset version that produced it.

| Field | Tier | What it records | Emitted by |
| :------------------ | :---- | :--------------------------------------------- | :-------------------- |
| [Training-Data Item Digest](Telemetry-Attack-Detection-Addendum.md#f-training-data-item-digest) | SHOULD | Digest of each training item at curation, checked against the content fetched. Modality: training or fine-tuning on externally sourced data. | `componentDataFilteringAndProcessing`, `componentTrainingData` |
| [Training-Data Source / Provenance](Telemetry-Attack-Detection-Addendum.md#f-training-data-source-provenance) | SHOULD | Source, contributor and acquisition of each training document. Modality: training or fine-tuning on externally sourced data. | `componentDataSources`, `componentTrainingData` |
| [Compute Job Submission](Telemetry-Attack-Detection-Addendum.md#f-compute-job-submission-event) | SHOULD | Each job submitted to a training or serving compute framework, with its submitter. Modality: self-operated training or serving compute. | `componentModelFrameworksAndCode`, `componentRuntimeHosting` |

---

## 7. Conclusion

The field catalog was assembled from documented instances, not from a list of what might be useful: 61 entries, comprising 40 real-world attacks and incidents, 5 CoSAI incident-response case studies [[3]](#primary-sources-attack-corpus--taxonomy), and 16 live red-team case studies from *Agents of Chaos* [[2]](#primary-sources-attack-corpus--taxonomy) ([AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory)). Every MUST can therefore be checked against the attacks it cites, and a tier moves when the evidence or the deployment modality changes. Training data and training infrastructure form an independent track ([§6.7](#67-training-data-and-training-infrastructure)). Detection logic, wire formats, and the security and privacy of the telemetry itself are out of scope ([§2.2](#22-not-in-scope)).

---

## 8. References

### Primary sources (attack corpus & taxonomy)

1. **MITRE ATLAS**: Adversarial Threat Landscape for Artificial-Intelligence Systems (technique matrix; `AML.Txxxx` taxonomy). MITRE. <https://atlas.mitre.org/>. Citations verified against release **`v2026.08`** (1 September 2026), 197 techniques and 72 case studies; machine-readable at <https://github.com/mitre-atlas/atlas-data>.
2. **Agents of Chaos**: Shapira, N., Wendler, C., Yen, A., et al. *Agents of Chaos.* arXiv:2602.20021 (2026). <https://arxiv.org/abs/2602.20021> · interactive log: <https://agentsofchaos.baulab.info/>. Corpus IDs `AOC-01` to `AOC-16` are the paper's Case Studies #1 to #16.
3. **CoSAI AI Incident Response**: Coalition for Secure AI, Workstream 2 (Defenders): *AI Incident Response Framework* (case studies). <https://github.com/cosai-oasis/ws2-defenders/blob/main/incident-response/AI-Incident-Response.md>. Its case studies are the corpus's `IR-01` to `IR-05`.

### Real-world attack primary sources

References 4 and 14 to 16 are cited in this document. The primary source for every attack in the corpus is listed in the [AD references](Telemetry-Attack-Detection-Addendum.md#references).

4. **[TA-01]** EchoLeak, zero-click data exfiltration from Microsoft 365 Copilot (CVE-2025-32711, CVSS 9.3). Discovered and disclosed by **Aim Labs (Aim Security)**; reported to MSRC Jan 2025, fixed server-side and publicly disclosed Jun 2025. Microsoft advisory: <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711> · CVE record: <https://nvd.nist.gov/vuln/detail/CVE-2025-32711> · **Technical analysis:** Reddy, P. & Gujral, A. *EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System.* arXiv:2509.10540 (2025). <https://arxiv.org/abs/2509.10540>

<!-- list break: reference numbers are not contiguous -->

14. **[TA-11]** Asana MCP server cross-tenant data exposure (Jun 2025); experimental MCP server launched 1 May 2025; tenant-isolation flaw found 4 Jun, exposure window 5 to 17 Jun; no evidence of exploitation. <https://www.theregister.com/2025/06/18/asana_mcp_server_bug/>
15. **[TA-12]** Supabase MCP private-table exposure via stored prompt injection. General Analysis. <https://generalanalysis.com/blog/supabase-mcp-blog> · analysis applying the **"lethal trifecta"** framing (private data + untrusted content + external communication): S. Willison, 6 Jul 2025, <https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/> · vendor response: <https://supabase.com/blog/defense-in-depth-mcp>
16. **[TA-13]** AI Engine (WordPress) MCP privilege escalation, **CVE-2025-5071** (CVSS 8.8, v2.8.0 to 2.8.3, disclosed 18 Jun 2025). <https://www.cve.org/CVERecord?id=CVE-2025-5071> · a second, unauthenticated flaw on the same MCP surface followed: **CVE-2025-11749** (CVSS 9.8, fixed in 3.1.4), <https://wpscan.com/vulnerability/b0d583a2-14e1-40bc-b875-3b48e992b803/> · <https://github.com/advisories/GHSA-q6x7-qqgq-h832>

### Standards & frameworks

23. **CoSAI Risk Map**: Coalition for Secure AI, fine-grained AI system components taxonomy. <https://github.com/cosai-oasis/secure-ai-tooling/tree/main/risk-map>. Identifiers are resolved against `develop` at commit `37e7bed` (30 September 2026). Those not yet on `develop` are proposals: most come from PR [#507](https://github.com/cosai-oasis/secure-ai-tooling/pull/507), open and in draft; `riskAgentMemoryPoisoning`, `riskDeceptiveAgentReporting`, `riskCrossAgentReputationPoisoning`, `riskErroneousAgentAction` and `controlMemoryReferentRevalidation` come from issues [#524](https://github.com/cosai-oasis/secure-ai-tooling/issues/524) to [#527](https://github.com/cosai-oasis/secure-ai-tooling/issues/527), proposed on a branch stacked on #507 (commit `0e9601d`).

<!-- list break: reference numbers are not contiguous -->

25. **AITF**: AI Telemetry Framework (OTel + OCSF binding), donated to CoSAI WS2. <https://github.com/cosai-oasis/ws2-defenders/tree/main/telemetry/aitf>. Cited at version 0.4, commit `e17c514` (7 September 2026).
26. **ODIS**: Coalition for Secure AI, Workstream 4: *Open Delegation & Identity Standard*. Apache-2.0. Records defined in ODIS §6: Agent Registration Record (6.1), Agent Runtime Credential Descriptor (6.2), Delegation Record (6.3), Identity Context (Policy Engine Feed) (6.4). Cited at commit `148dc41` (8 September 2026); ODIS is a working draft, so this reference is pinned to a commit rather than to `main` to keep the section numbers and field names cited against it checkable. <https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md>

<!-- list break: reference numbers are not contiguous -->

30. **NIST AI Risk Management Framework (AI RMF 1.0)**: NIST, January 2023; **currently under revision**. GOVERN / MAP / MEASURE / MANAGE. <https://www.nist.gov/itl/ai-risk-management-framework> · companion **NIST AI 600-1, Generative AI Profile** (July 2024).
31. **NIST Cybersecurity Framework (CSF) 2.0**: GV / ID / PR / DE / RS / RC; 6 functions, 22 categories, 106 subcategories. <https://www.nist.gov/cyberframework>

<!-- list break: reference numbers are not contiguous -->

33. **ISO/IEC 42001:2023**: *Information technology — Artificial intelligence — Management system.* Clauses 4 to 10 plus **Annex A** (38 controls under 9 objectives, A.2 to A.10) selected via a Statement of Applicability. Paid standard. <https://www.iso.org/standard/42001>.
34. **EU AI Act. Article 12 (Record-keeping / Logging).** <https://artificialintelligenceact.eu/article/12/>
35. **OpenTelemetry, GenAI semantic conventions.** Now maintained in a dedicated repository: <https://github.com/open-telemetry/semantic-conventions-genai>. Spans, metrics, events, MCP, and provider-specific conventions, **all at Development status**. Attribute registry: <https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/>. Entries marked *Deprecated* there mostly reflect the relocation rather than withdrawal, but not always: some were **renamed** in the move (`gen_ai.usage.cache_creation.input_tokens` → `gen_ai.usage.cache_write.input_tokens`) and some were **withdrawn outright** (`gen_ai.prompt` and `gen_ai.completion`, both `reason: obsoleted`, "Removed, no replacement at this time"). Names therefore come from the new repository, not the deprecated registry. **Names cited from it resolve at `semantic-conventions-genai` commit `e07f4eb` (2 October 2026), which publishes no releases, and at `semantic-conventions` release v1.44.0 (4 August 2026).**
36. **OpenTelemetry, core specification.** Signals, context propagation, sampling. <https://opentelemetry.io/docs/specs/otel/> · **W3C Trace Context**: <https://www.w3.org/TR/trace-context/> · MCP context propagation via `params._meta` (Specification Enhancement Proposal **SEP-414**): <https://modelcontextprotocol.io/community/seps/414-request-meta>
37. **OCSF. Open Cybersecurity Schema Framework.** <https://ocsf.io/> · schema browser: <https://schema.ocsf.io/>. Cited at release 1.9.0 (3 August 2026).
38. **OWASP AOS, Agent Observability Standard.** OWASP. <https://aos.owasp.org/>. Three pillars (Instrument / Trace / Inspect). *Working draft.* Verified against the specification sources at commit `e4a50f6` (30 December 2025), schema version **0.1.0** (`specification/AOS/aos_schema.json` in [OWASP/www-project-agent-observability-standard](https://github.com/OWASP/www-project-agent-observability-standard)); the specification last changed on 10 November 2025.
39. **Model Context Protocol (MCP).** <https://modelcontextprotocol.io/>. Tools, resources, prompts, sampling, elicitation, roots. Cited at specification version 2026-07-28.
40. **A2A, Agent-to-Agent Protocol.** <https://a2a-protocol.org/>. Agent cards, task lifecycle, push-notification configuration. Cited at release v1.0.1 (28 May 2026).

<!-- list break: reference numbers are not contiguous -->

44. **CPEX**: policy-enforcement runtime and reference monitor for AI agents. <https://contextforge-org.github.io/cpex/> · threat model: <https://contextforge-org.github.io/cpex/docs/threat-model/>. Cited at release `v0.2.3` (2 October 2026), the first release to contain the threat-model document. <https://github.com/contextforge-org/cpex>

<!-- list break: reference numbers are not contiguous -->

51. **RFC 2119**: Bradner, S. *Key words for use in RFCs to Indicate Requirement Levels.* BCP 14, RFC 2119 (1997). <https://www.rfc-editor.org/rfc/rfc2119>
52. **RFC 8174**: Leiba, B. *Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.* BCP 14, RFC 8174 (2017). <https://www.rfc-editor.org/rfc/rfc8174>

### Other sources

64. **Frontier-model containment failures under evaluation (July 2026).** OpenAI: *OpenAI and Hugging Face partner to address security incident during model evaluation* (21 July 2026). <https://openai.com/index/hugging-face-model-evaluation-security-incident/> · technical report: <https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf> · Hugging Face: *Anatomy of a Frontier Lab Agent Intrusion: A Technical Timeline of the July 2026 Incident* (27 July 2026), documenting how an agent under OpenAI evaluation reached Hugging Face's production Kubernetes pods and database. <https://huggingface.co/blog/agent-intrusion-technical-timeline> · Anthropic: *Investigating three incidents in our cybersecurity evaluations* (30 July 2026), in each of which the model compromised a real organization's systems, including a production database. <https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals>
