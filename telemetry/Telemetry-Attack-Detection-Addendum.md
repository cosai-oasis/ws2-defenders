# Telemetry for AI Security: Attack Detection Addendum {**Working Draft v0.5**}

**Status:** Request for Comments, revision 0.5
**Origin:** Coalition for Secure AI (CoSAI), Workstream 2 (Defenders)
**Companion to:** [Telemetry for AI Security](CoSAI-AI-Telemetry-RFC.md) (cited as RFC); see also the [Cross-Mapping Addendum](Telemetry-Cross-Mapping-Addendum.md) (cited as XM).

---

Logged fields are a necessary evidentiary foundation, not detection by themselves; measured alert volumes are in [§2](#2-correlation-patterns). Treat logged values as inputs to layered analytics: signature rules, self-learning anomaly detection, cross-layer correlation, and ML scoring of prompts/outputs/action-sequences. Field names, tier, and the [correlation patterns](#2-correlation-patterns) are meant to be usable directly as detection-engineering and triage input, and the attack IDs on every field are there so an analyst can see what a field was collected *for*. Continuously re-evaluate detectors; benchmarks show injection detectors effective on explicit attacks often fail on subtler variants. **When a detector fires, stamp the event with its MITRE ATLAS `AML.Txxxx` technique** (the *Threat Classification / ATLAS Technique Tag* field) using the [§3.6](#36-attack-inventory--mitre-atlas-technique-mapping) mapping; this makes AI-specific alerts correlate with the ATT&CK-aligned rest of the SOC and roll up cleanly into ATLAS-based compliance reporting.

## 1. Field Tables

Each table holds the fields of one component cluster, with these columns:

- **Field**: conceptual field name (implementation-neutral).
- **Cls**: MUST / SHOULD / MAY.
- **Capture (concept)**: what to record, stated generally enough to bind to any framework.
- **Evidence**: attack IDs that establish the need (see [§3](#3-attack--incident-inventory)).

### 1.1 Application & Agent Reasoning Core

**Components:** `componentApplication`, `componentReasoningCore`, `componentAgentUserQuery`, `componentAgentSystemInstruction`

*Establishes **what** is running and **where**: the asset inventory of the AI attack surface and the trace anchor for every incident.*

| Field | Cls | Capture (concept) | Evidence |
| :------------ | :---- | :-------------------------------------------------------------------------- | :------------ |
| **Agent Name** | MUST | Logical name/type of the agent (e.g. "Deep Research agent"). Detects off-inventory / "shadow" agents. | `AOC-08`,`AOC-10`,`TA-01`,`TA-05` |
| **Agent (Runtime) Instance ID** | MUST | UUID pinning an event to one running instance, not just the type. Enables per-instance kill/quarantine. | `AOC-04`,`AOC-05`,`AOC-08` |
| **Workflow / Run ID** | MUST | Groups all activity of one multi-step run or sub-agent tree into a single traceable execution. | `AOC-04`,`AOC-09`,`AOC-10` |
| **Session / Turn / Step IDs** **[AOS]** | MUST | The three-level execution hierarchy *beneath* the run: `session_id` (the conversation/engagement), `turn_id` (one request→response cycle), `step_id` (one action within a turn). Lets a detection point at *which* turn behaviour changed, not just which run. | `AOC-03`,`AOC-07`,`TA-07`,`TA-08`,`TA-19` |
| **Trace Context (propagated)** **[AOS]** | MUST | W3C `traceparent` / `trace_id` + `span_id` **propagated across every agent→tool→agent hop**, including MCP and A2A calls. Without propagation, multi-agent activity cannot be reassembled into one trace. | `AOC-04`,`AOC-09`,`TA-01`,`TA-08` |
| **Organization / Tenant ID** **[AOS]** | SHOULD | The tenant/organization owning the agent, the session, and the invoking user, recorded on each. The primitive for detecting cross-tenant leakage and credential propagation. | `AOC-02`,`AOC-05`,`TA-05`,`TA-01`,`TA-11` |
| **Trigger Type & Source Event** **[AOS]** | MUST | Whether this run was **user-initiated or autonomous**, and for autonomous runs the originating event (inbound email, chat message, webhook, schedule). Distinct from Surface/App, which records the *channel*, not who or what started the run. | `TA-01`,`AOC-04`,`AOC-10`,`AOC-12`,`TA-27` |
| **Action Type** | MUST | Distinguishes LLM-call vs tool-call vs memory-op vs message-send, the "think → act" boundary. | `AOC-01`,`AOC-02`,`IR-01` |
| **Execution Status** | MUST | Outcome of the operation or turn (complete / error / exit / aborted) + duration. Spikes/timeouts reveal probing, DoS, or mass failure. Distinct from **Stop Reason** below, which records why a *completion* ended. | `AOC-05`,`AOC-06`,`IR-04`,`TA-04`,`TA-10` |
| **Stop Reason** | MUST | Normalized reason a model completion ended: end of turn, token limit, tool use pending, session stop (caller cancelled or disconnected), content filter. Separates a truncation from a clean stop and a guardrail kill from a crash; a `content_filter` stop is the completion-side view of a guardrail block (§1.3). | `TA-04`,`TA-10`,`IR-01` |
| **Surface / App** | MUST | Entry point (CLI, web, IDE, email, chat channel, cron/heartbeat; internal vs external service). Detects access from unexpected surfaces. | `AOC-08`,`AOC-10`,`TA-01`,`TA-05` |
| **System Prompt / Instruction Config** | MUST | The system/instruction configuration in force for the call. Detects unauthorized weakening and, by comparison against the response, system-prompt leakage/extraction. | `TA-07`,`AOC-08`,`AOC-10`,`TA-21` |
| **Autonomy Level** | SHOULD | Declared independence level (e.g. L1 to L5) the run is authorized to operate at; sets oversight/delegation limits. | `AOC-01`,`AOC-04`,`AOC-07` |

### 1.2 Input Handling & Trust Provenance

**Components:** `componentApplicationInputHandling`, `componentAgentInputHandling`, `componentOrchestrationInputHandling`

*The `componentAgentInputHandling` risk-map definition is literally "processing distinguishing trusted user commands from untrusted environmental data." That distinction is the single most important agentic-security signal.*

| Field | Cls | Capture (concept) | Evidence |
| :------------ | :---- | :------------------------------------------------------------------------- | :------------- |
| **Model Input** | MUST | Every input to each model call in the loop, user prompts, tool outputs, retrieved context, inter-agent messages. Not just the first user turn. Includes size/shape (large or repetitive inputs). | `IR-01`,`IR-02`,`TA-01`,`AOC-03`,`AOC-12`,`TA-05`,`TA-10`,`TA-19` |
| **Input Source / Channel** | MUST | Provenance label for each input segment: which surface/tool/agent/document it came from. | `TA-01`,`AOC-10`,`AOC-12`,`IR-03` |
| **Input Trust Classification** | MUST | The origin authority of a segment crossed with how it was consumed: **trusted-instruction**, **trusted-data**, **untrusted-instruction**, **untrusted-data**. Owner command against environmental or third-party content, and instruction against data. **`untrusted-instruction` is the attack state**, the cell `TA-01` occupies. | `AOC-02`,`AOC-08`,`AOC-12`,`TA-01`,`IR-01`,`TA-18`,`TA-19` |
| **Source host / IP + request metadata** | MUST | Origin of the request; supports geo/impossible-travel, rate-limit, and credential-theft detection. | `AOC-08`,`AOC-15`,`IR-04`,`TA-03`,`TA-10` |
| **Guardrail (Input) Verdict** | MUST | Result of any input-side injection/jailbreak/PII/secret classifier: **pass / flag / block / modify**, with detector + score. | `TA-01`,`IR-01`,`AOC-12`,`TA-05`,`TA-22`,`TA-26` |
| **Content Modality & Attachment Identity** **[AOS]** | MUST ‡ | **Cross-cutting.** For every content-bearing field: the part type (text / file / structured data), MIME type, and for files the name, size, and content hash. Instructions that arrive as an image, PDF, or structured blob are invisible to text-only inspection and text-only logging. | `AOC-12`,`AOC-05`,`TA-05`,`TA-01`,`TA-26` |
| **Guardrail Modification Record** **[AOS]** | MUST ‡ | **Cross-cutting.** When an enforcement point **rewrites rather than blocks**: masking, redacting, stripping, or rewriting a payload; record that a modification occurred, which enforcement point made it, and a before/after digest (plus a redaction map where policy permits). Applies on both the input and the output side. | `TA-01`,`AOC-12`,`AOC-03`,`IR-01` |
| **Threat Classification / ATLAS Technique Tag** | MUST † | **Cross-cutting enrichment.** On any flagged or security-relevant event, the classified technique(s) as **MITRE ATLAS `AML.Txxxx`** IDs (plus a free-text threat type). Emitted by input/output guardrails and by tool/memory/retrieval detectors alike, so every alert carries a portable, ATT&CK-aligned technique reference. | `IR-01`,`TA-01`,`TA-07`,`AOC-12` |
| **Encoded / Obfuscated Payload Indicator** | MAY | Flag + decoded form when input contains base64, image-embedded (OCR), or markup "authority" tags. | `AOC-12`,`TA-03`,`TA-21` |

† **MUST when a detection fires** (not on every benign event). The tag is a derived classification, not raw telemetry: detection logic sets it using the [§3.6](#36-attack-inventory--mitre-atlas-technique-mapping) attack→ATLAS mapping so downstream SIEM/XDR correlation and compliance reporting can pivot on `AML.Txxxx`.

‡ **Cross-cutting fields**, listed here for convenience but applying across components, see the [classification summary](CoSAI-AI-Telemetry-RFC.md#6-field-catalogue). **Guardrail Modification Record** applies **whenever an enforcement point rewrites rather than blocks**.

### 1.3 Output Handling, Egress & Refusals

**Components:** `componentApplicationOutputHandling`, `componentAgentOutputHandling`, `componentOrchestrationOutputHandling`

*Where damage materializes: PII leakage, exfiltration channels, harmful content, mass broadcast.*

| Field | Cls | Capture (concept) | Evidence |
| :------------ | :---- | :----------------------------------------------------------------------- | :--------------- |
| **Response / Model Output** | MUST | The generated output at each step. Where leakage, disclosure, verbatim training data, and embedded exfil URLs appear. | `AOC-03`,`AOC-11`,`TA-01`,`TA-03`,`TA-04`,`TA-07` |
| **Output Egress Destination** | MUST | Where output goes: recipient addresses, outbound URLs/domains, channels, file targets, broadcast scope. | `TA-01`,`TA-03`,`AOC-03`,`AOC-11`,`AOC-05`,`TA-28` |
| **Citations / Source Attribution** **[AOS]** | MUST | The sources the agent *claims* it drew on, per output: file ID/name/URL or site URL for each citation, **plus whether each resolves to an item actually returned by a logged Retrieval Event (§1.7)**. Unresolvable, fabricated, or attacker-supplied citations are the signal. | `TA-01`,`TA-02`,`IR-03`,`AOC-03` |
| **Observation / Thought (reasoning trace)** | SHOULD | Chain-of-thought/observations *when the provider exposes it*. Reveals whether a harmful act was injected, misauthorized, or self-initiated. | `AOC-01`,`AOC-07`,`AOC-10`,`IR-02` |
| **Guardrail (Output) Verdict** | MUST | Output-side filter result (PII/DLP, harmful content, exfil pattern): **pass / flag / block / modify**. Modifications are recorded via the **Guardrail Modification Record** (§1.2). Fired detections carry the **ATLAS Technique Tag** (see §1.2). | `TA-01`,`AOC-03`,`IR-01`,`TA-22` |
| **LLM Refusal** | MUST | Status + reason when the model refuses. A refusal-then-success streak signals a jailbreak in progress; an *absent* refusal on clearly policy-violating output flags a guardrail gap. | `IR-01`,`AOC-12`,`AOC-13`,`AOC-14`,`TA-03`,`TA-04`,`TA-07` |

### 1.4 The Model & Model Serving

**Components:** `componentTheModel`, `componentModelServing`, `componentModelStorage`, `componentModelRegistry` (provenance)

*Supply-chain integrity, resource/DoS signals, and pre-inference integrity.*

| Field | Cls | Capture (concept) | Evidence |
| :-------------- | :---- | :--------------------------------------------------------------------------- | :--------- |
| **Model Name + Version** | MUST | Model and version processing the request. "Which agents used the compromised model?"; pins a model-specific vulnerability for patching. | `TA-06`,`IR-04`,`AOC-06`,`TA-04` |
| **Provider / Endpoint Identity** | MAY | Which provider/endpoint served the call. The reason the completion ended is **Stop Reason** (§1.1). | `AOC-06`,`TA-28` |
| **Inference Parameters** **[AOS]** | MUST | The decoding/config parameters in force for the call: `temperature`, `top_p`/`top_k`, `max_tokens`, `stop` sequences, `seed`, and the **declared context-window size**. The runtime half of the configuration-integrity baseline that **System Prompt** (§1.1) covers for instructions. | `TA-04`,`TA-10`,`AOC-06`,`AOC-04` |
| **Input / Output Token Counts** | MUST | Per-call token usage, the primary resource-abuse and runaway-loop signal; max-length outputs flag extraction/DoS. | `AOC-04`,`AOC-05`,`TA-04`,`TA-10` |
| **LLM Error / Exception** | MUST | Errors that occur under adversarial conditions (overflow, malformed encoding, context exhaustion); provider-side silent failures. | `AOC-06`,`IR-01`,`TA-10` |
| **Model Provenance / Signing / Hash** | SHOULD | Signed digest / provenance of the served model artifact (supply-chain attestation). | `TA-06`,`IR-04` |
| **Pre-Forward-Pass State Digest/Vector** | MAY | Content-addressed digest (+ pooled vector) of the exact inputs to a forward pass, captured pre-inference for replay/drift detection. | `IR-02`,`AOC-10` |
| **Token Malformation / Context-Corruption Indicator** | MAY | Signal of context-induced token-entropy anomalies correlated with confabulation. | `IR-02` |

### 1.5 Tools & External Services

**Components:** `componentTools`, `componentToolServer`, `componentToolInputHandling`, `componentToolOutputHandling`, `componentAgentToolTransport`, `componentToolRegistry` (approved baseline), `componentIsolationRuntime` and `componentToolHosting` (execution environment)

*The security perimeter between AI reasoning and real-world consequences. When an agent calls a tool it crosses from "thinking" to "acting."*

> **Gateways, namespaces, and multiple hops.** A tool call is frequently not a single hop. Tools and prompts commonly sit behind a **gateway or broker** that re-namespaces them, and the call may traverse several intermediaries before reaching the system that acts. Three fields carry this, and they should be read together: **Tool Name** records the name *as the agent saw it*, which is the namespaced or gateway-local name and not necessarily the name at the far end; **MCP Server Identity & Primitive** records the immediate counterparty; and **Trace Context** (§1.1) is what stitches the hops into one trace, propagated over MCP via `params._meta`, per [XM §2.5](Telemetry-Cross-Mapping-Addendum.md#25-context-propagation-sampling--privacy-three-operational-traps).
>
> Two consequences. First, **the same underlying capability may appear under different names** depending on the path taken to it, so detections keyed on tool name alone will miss re-namespaced invocations; keying on the server identity and primitive as well is what makes them robust. Second, an intermediary is a **mediation boundary**, and whether it was traversed at all is the subject of **Mediation Coverage & Bypass Path** (§1.12); `AOC-14` is precisely an attempt to reach a capability by a path that bypasses the mediated one.

| Field | Cls | Capture (concept) | Evidence |
| :------------- | :---- | :-------------------------------------------------------------------- | :----------------- |
| **Tool Call I/O** | MUST | Full input params **and** output for every tool/MCP call; what the agent actually *did* vs what it was asked. Reveals credentials passed between chained calls. | `AOC-01`,`AOC-02`,`AOC-03`,`TA-01`,`TA-06`,`TA-08`,`TA-09`,`TA-15`,`TA-19` |
| **Tool Name** | MUST | Which capability was invoked. Detects off-manifest / sensitive-tool invocation, escalating tool sequences, and enumeration. | `AOC-02`,`AOC-10`,`IR-01`,`TA-06`,`TA-08`,`TA-09` |
| **Tool Type / Trust Boundary** | MUST | MCP (cross-network) vs internal vs direct-storage vs code-execution, different trust models & policies. | `AOC-14`,`TA-01`,`TA-06` |
| **Tool ID** | MAY | Unique tool-implementation ID for unambiguous attribution across many MCP servers. | `AOC-10` |
| **Tool Execution ID** **[AOS]** | MUST | Correlation ID minted at invocation and echoed on the result, pairing every request with its outcome. | `TA-08`,`AOC-01`,`AOC-04`,`AOC-14` |
| **Tool Definition Digest** **[AOS]** | MUST | Hash of the tool's **declared contract as presented at invocation time**: name, description, argument schema, output schema, plus a comparison against the approved baseline. Detects a tool whose definition mutated after approval. | `AOC-10`,`AOC-14`,`TA-06`,`AOC-09`,`TA-15` |
| **Execution Environment / Sandbox** **[AOS]** | MUST | The isolation posture of the execution: sandbox mode (none / container / VM / WASM), language runtime and version, OS/architecture, timeout, and network-egress policy. | `TA-06`,`AOC-02`,`AOC-04`,`AOC-14`,`TA-23`,`TA-14` |
| **MCP Server Identity & Primitive** **[AOS]** | MUST | For MCP calls: server name, version, transport, and endpoint; **and which MCP primitive was exercised**: `tool`, `resource`, `prompt`, `sampling`, `elicitation`, or `roots`. | `TA-06`,`AOC-10`,`TA-01`,`AOC-09`,`TA-12`,`TA-13`,`TA-15` |
| **Tool Error / Exception** | MUST | Failed/blocked tool calls: rejected injection args, SSRF blocks, authz boundary hits, and the probing errors that precede successful exploitation. | `TA-01`,`AOC-14`,`IR-01`,`TA-06` |
| **Tool ACL / Required Scope** | SHOULD | The authority a tool requires and who may invoke it (the tool's security policy); individually-authorized calls that violate separation-of-duties as a chain. | `AOC-08`,`AOC-10`,`AOC-02`,`TA-06`,`TA-08`,`TA-12` |
| **Tool Privacy Classification** | MAY | Sensitivity class of data the tool touches, feeds DLP / data-flow governance. | `AOC-03`,`TA-01`,`TA-05` |
| **Tool Selection Rationale** **[AOS]** | SHOULD | The agent's stated reason for choosing *this* tool with *these* arguments, captured at the request step. Distinct from the §1.3 output-side reasoning trace: it is attached to the action, not the answer. | `AOC-01`,`TA-08`,`AOC-10`,`AOC-02` |

### 1.6 Memory

**Component:** `componentMemory`

*Persistent memory is a first-class attack surface. Multiple corpus attacks target it directly.*

> **What counts as memory, and at what granularity.** *Memory* here means **any store the agent writes to in one turn and reads back in a later one**, whatever its substrate: a vector store, a scratchpad file, a database row, a project instruction file, or a file the agent edits in a repository it also reads from. The substrate is irrelevant; the read-after-write-across-turns property is what creates the attack surface, because it is what lets `IR-02` and `AOC-10` outlive the session that planted them.
>
> The fields below are specified at **item granularity, not store granularity**: a Memory Write Event describes one item, and **Memory Provenance** attaches to that item. This requires a stable item identifier, and deployments whose memory is an opaque blob (a single file rewritten wholesale) cannot supply one. Such deployments should emit the write event with a **content digest** in place of an item ID, which preserves change detection and correlation while losing per-item provenance. That is a real reduction in detection capability and the reason item-level identity is worth engineering for.
>
> **Out of scope:** the durability, consistency, and retention semantics of the store itself, and any judgement about whether a given design *should* persist state. This section records what was written, read, and by what authority, not whether the memory architecture is sound.

| Field | Cls | Capture (concept) | Evidence |
| :---------------- | :---- | :--------------------------------------------------------------------- | :------------ |
| **Memory Write Event** | MUST | Every create/update/delete to persistent or long-term memory: what changed, by which turn/actor. | `IR-02`,`IR-05`,`AOC-07`,`AOC-10`,`TA-18` |
| **Memory Read / Injection Event** | MUST | Which memory items were pulled into context for a call. | `IR-02`,`IR-05`,`AOC-10`,`TA-18` |
| **Memory Provenance / Source** | MUST | Origin & mutability of a memory item, self-authored, owner, non-owner, or **externally editable resource**. | `AOC-10`,`IR-02`,`TA-18` |
| **Memory Integrity / Poisoning Signal** | SHOULD | Integrity check / poisoning-likelihood score, cross-session isolation flag. | `IR-02`,`IR-05`,`TA-18` |
| **Memory Footprint / Growth** | MUST | Size/growth of memory stores (per user/session), resource-exhaustion signal. | `AOC-05`,`AOC-04` |
| **Declared Memory Configuration** **[AOS]** | MAY | The memory store's declared identity and limits: name, type, backend, size cap, retention, and retrieval spec (top-k, scoring). The baseline that **Memory Footprint** is measured against. | `AOC-05`,`AOC-07`,`IR-02` |
| **Memory Write Rationale** **[AOS]** | SHOULD | The agent's stated reason for persisting *this* item, captured at the write step. | `IR-02`,`AOC-07`,`AOC-10` |

### 1.7 Retrieval & Content (RAG)

**Component:** `componentRAGContent`

*RAG is a primary injection and manipulation channel.*

| Field | Cls | Capture (concept) | Evidence |
| :-------------------- | :---- | :-------------------------------------------------------------- | :--------------- |
| **Retrieval Event** | MUST | Query issued + documents/chunks returned + retrieval scores. | `TA-01`,`TA-02`,`TA-09`,`IR-03`,`AOC-10` |
| **Retrieved-Content Source / Provenance** | MUST | Origin, owner, trust level, and freshness (create/update time) of each retrieved item (internal doc, web, third-party, user upload). | `TA-01`,`TA-02`,`TA-09`,`IR-03`,`TA-27` |
| **Retrieved-Content / Metadata Integrity Signal** | SHOULD | Tamper/poisoning indicators on content **or its metadata/tags**. | `IR-03`,`IR-05`,`TA-02`,`TA-09` |
| **Declared Knowledge-Source Configuration** **[AOS]** | MAY | Each knowledge source's declared identity and contract: name, description, index/collection identity, schema, and search parameters (top-k, filters, scoring, reranker). | `TA-09`,`IR-03`,`TA-02` |

### 1.8 Orchestration, Multi-Agent & Background Execution

**Components:** `componentReasoningCore`, `componentOrchestrationInputHandling`, `componentOrchestrationOutputHandling`

*Multi-agent and autonomous-execution telemetry: the corpus shows these are where agentic risk compounds.*

| Field | Cls | Capture (concept) | Evidence |
| :-------------- | :---- | :------------------------------------------------------------------------ | :------------ |
| **Inter-Agent Message** | MUST | Agent→agent messages: sender, receiver, content, channel, including capability/skill transfer. | `AOC-04`,`AOC-09`,`AOC-11`,`AOC-16`,`TA-25`,`TA-27` |
| **A2A Task Lifecycle Event** **[AOS]** | SHOULD | Delegated-task state transitions across the A2A surface: task submitted, streamed, polled, **cancelled**, resubscribed, and **push-notification config set or changed**, which registers an outbound callback destination. | `AOC-04`,`AOC-11`,`AOC-09`,`TA-01` |
| **Peer Agent Card / Descriptor** **[AOS]** | SHOULD | The counterparty agent's declared descriptor as presented at contact: name, URL, version, provider, and advertised skills/capabilities, with change detection against prior contacts **and the outcome of any verification attempted against it** (signature checked, inspection request answered or refused, or unverified). |  `AOC-09`,`AOC-11`,`AOC-08`,`AOC-16` |
| **Background / Scheduled Task Event** | MUST | Creation/modification of cron jobs, heartbeats, daemons, or self-scheduled loops, incl. presence/absence of a termination condition. | `AOC-04`,`AOC-10`,`TA-25` |
| **Loop / Step-Count Signal** | MUST | Steps or iterations per run vs baseline; circular agent-to-agent exchange detection. | `AOC-04`,`IR-02`,`TA-24`,`TA-25` |
| **Resource-Consumption Aggregate** | MUST | Per-run/agent token, compute, storage, and outbound-volume totals against a budget, and, where authority is delegated, **accounted across the delegation subtree rather than per run**: individually modest runs can exhaust a principal's budget in aggregate. Where a budget is enforced, the **consumed and remaining figures ride the record of the action that consumed them** and not only the metric series, because a total cannot be recomputed after the fact from records that never carried it. That is what separates a budget denial from a budget overrun discovered later. | `AOC-04`,`AOC-05`,`TA-10`,`TA-20` |
| **Task / Intent Declaration** | SHOULD | The declared purpose/task the run is authorized to pursue (for goal-drift detection). | `AOC-04`,`AOC-01`,`AOC-10`,`TA-24` |
| **Protocol Envelope Capture** **[AOS]** | MAY | The raw MCP / A2A JSON-RPC envelope (method, id, params) alongside the interpreted fields, preserving protocol-level detail that framework-level abstraction discards. | `AOC-09`,`AOC-12`,`TA-06` |

### 1.9 Identity, Delegation & Attribution

**Components:** `componentIdentityProvider`, `componentFederationProxy`; cross-cutting across `componentReasoningCore`, `componentTools` and `componentModelServing`, which it binds into an accountable chain.

*The "Quadruple Identity" problem: a **principal** authorizes an **agent** which (possibly via **other agents**) calls a **tool** that acts on **infrastructure**. Without identity at each hop, accountability collapses and confused-deputy attacks succeed. This is the ODIS problem space; delegation fields are **SHOULD** by the classification rule. Where two of these identities are emitted in OpenTelemetry and OCSF is in [XM §2](Telemetry-Cross-Mapping-Addendum.md#2-implications-for-opentelemetry-the-instrumentation-bridge).*

| Field | Cls | Capture (concept) | Evidence |
| :---------- | :---- | :------------------------------------------------------------------------------ | :---------- |
| **Identities Used (per hop)** | MUST | Attribute every agent→user, agent→agent, agent→tool, tool→infra action to an identity + metadata; detect identity changes across a tool chain. | `AOC-01`,`AOC-02`,`AOC-08`,`AOC-11`,`IR-04`,`TA-05`,`TA-08` |
| **Verified vs Displayed Identity** | MUST | Distinguish an immutable/verified identifier from a spoofable display identity; record which was used to authorize. | `AOC-08`,`AOC-11`,`AOC-15` |
| **Originating Principal (on-behalf-of)** | SHOULD | The human/service sponsor at the root of the delegation chain. | `AOC-01`,`AOC-02`,`AOC-08` |
| **Delegation Chain** | SHOULD | Ordered lineage of prior agent hops carried across the call. Each hop carries an **integrity-protected reference to its parent** (issuer, delegation identifier, and a digest of the parent record), so lineage is verifiable from the records rather than asserted; a digest that does not match the resolved parent fails chain validation closed. | `AOC-04`,`AOC-09`,`AOC-10`,`TA-25` |
| **Granted Authorizations / Scope** | SHOULD | Delegated authority in effect at this hop, with monotonic-narrowing check. Record the **rules the check ran against** (ODIS `attenuation_profile_ref`: a versioned identifier and content digest for the normalization and comparison rules), since "narrower" is a semantic comparison and two profiles can disagree on the same pair of scopes. | `AOC-02`,`AOC-08`,`AOC-10`,`TA-13` |
| **Resource Indicators + Constraints** | SHOULD | Target resource audience + time/purpose/rate/locality/`data_classification` narrowing. | `AOC-03`,`AOC-05`,`TA-01` |
| **Credential Minting & Scope-Narrowing Check** **[CPEX]** | SHOULD | The credential-exchange event at each hop: grant type (token exchange / client assertion / client credentials), whose identity the minted token represents (**end user / client application / calling workload / the enforcement point itself**), target **audience**, issuer, lifetime, and the **requested-vs-granted scope delta** verified after minting. Detects both over-broad credentials and forwarded inbound tokens that were never narrowed. | `AOC-02`,`AOC-08`,`IR-04`,`TA-08` |
| **Trust-Domain Crossing & Delegation Depth** | SHOULD | The counterparty's **trust domain** and the **depth of the delegation chain** at this hop, plus whether either crossed a configured limit. Records that authority left the domain that issued it, and how many hops from the originating principal the acting agent now sits. Depth is **derived** from the chain (the OCSF `delegation.parent_uid` lineage or the RFC 8693 `act` chain), not transmitted as a counter; a transmitted copy can disagree with the chain it was derived from. The derivation holds only while every hop carries its parent link: a hop that does not is a **break in the chain**, to be recorded as such rather than read as a shorter chain ([XM §3.1](Telemetry-Cross-Mapping-Addendum.md#31-ocsf-coverage--gaps-by-field-cluster)). | `AOC-04`,`AOC-09`,`AOC-11`,`TA-11` |
| **Runtime Credential / Attestation** | SHOULD | Runtime-instance credential: `software_hash`, `attestation_evidence`, issuer, expiry, holder-key binding. Evidence is recorded **per source, each with its own issuer, validity and verification outcome**: software-provenance and runtime/workload evidence come from independent issuers, and a single collapsed value loses the independence that makes the attestation worth verifying (see **Attribute Source / Trusted-Provenance Marking**, [§1.12](#112-policy-enforcement--mediation)). | `AOC-08`,`TA-06` |
| **Lifecycle State** | SHOULD | active / suspended / revoked, supports kill-switch & revocation-fanout. | `AOC-07`,`AOC-10` |

### 1.10 Asset Inventory & Fleet Aggregates

**Components:** `componentTools`, `componentApplication`, `componentModelFrameworksAndCode` (inventory), `componentModelRegistry` and `componentToolRegistry` (admission); fleet-level metrics are cross-component.

*These define the inventory and posture rather than per-request activity. Most are governance and CVE-response signals rather than detection signals, hence mostly MAY. The exceptions are the **change** signal, which is detection-grade and MUST, and the AgBOM cluster, which is the structural counterpart to OWASP AOS's **Inspect** pillar.*

| Field / Metric | Cls | Capture (concept) | Evidence |
| :------------------------------ | :---- | :-------------------------------------------------------------- | :------- |
| **Capability-Set Change Event** **[AOS]** | MUST | An event emitted whenever the agent's usable capability set changes at runtime, a tool, MCP server, model, knowledge source, or memory store **discovered, added, removed, or modified**: with before/after identity and what triggered the change. | `AOC-09`,`AOC-10`,`TA-06`,`AOC-02`,`TA-23`,`TA-14` |
| **Tool/Agent Version** | SHOULD | Version of each tool/agent/framework; instant CVE blast-radius answer; downgrade detection. | `TA-06`,`IR-04` |
| **Repository / Code Path / Software Ref** | SHOULD | Source provenance of tool/agent code (ties to signing & ODIS `approved_software_refs`). | `TA-06`,`AOC-10` |
| **AgBOM / Inventory Snapshot** **[AOS]** | SHOULD | A structured, machine-readable inventory of the agent's composition (packages, models, capabilities (agent cards, discovered peers, MCP servers), knowledge sources, memory stores, tools) emitted on change and **on demand**. Bound to an existing BOM format rather than a bespoke one. The three carry different amounts of it: **CycloneDX** is the only one for which an agent-runtime binding has been written (sandbox, tool scopes and endpoints, memory backend, agent-card URL, carried in its generic property bag); **SPDX 3.0** carries dependency, integrity and, through its AI profile, model governance; **SWID** carries identity, version, dependency and signing. Emit in whichever format the deployment already uses, and record which one ([XM §5.3](Telemetry-Cross-Mapping-Addendum.md#53-pillar-3-inspect)). | `TA-06`,`TA-16`,`IR-04`,`AOC-09`,`AOC-10` |
| **Component Dependency Graph** **[AOS]** | SHOULD | Dependency edges between inventoried components, including transitive ones; which agent depends on which tool, which tool on which package or MCP server. | `TA-06`,`IR-04` |
| **Inventory Attestation Signature** **[AOS]** | SHOULD | Cryptographic signature over the emitted inventory (signature value + key identifier), binding the declared composition to a signer. | `TA-06`,`AOC-10`,`IR-04` |
| **Description** | MAY | Declared purpose: detects misleadingly-described ("read-only" but writes) tools. | `AOC-14` |
| **Status (active/disabled)** | MAY | Detects calls to tools that should be unreachable. | `AOC-02` |
| **Creator ID / Oncall / Creation & Update dates** | MAY | Ownership, age-based risk, change-correlation for IR speed; recently-changed assets/content correlate with attack timelines. | `IR-04`,`TA-09` |
| **Surfaces Supported** | MAY | Exposure map per tool. | `AOC-08` |
| **Fleet counts** (agents by framework/type; sessions L1/L7/L28; users MAU/power-user; tool-call volume & agent↔tool map; surface & status breakdowns) | MAY | Aggregate anomaly, shadow-AI, and CVE-exposure signals. | `AOC-04`,`AOC-05`,`TA-06` |

### 1.11 Observability-Plane Integrity

**Cross-cutting:** applies to the instrumentation and enforcement layer itself, not to any one pipeline component; its records land in `componentAuditRecordRepository`.

> **Scope.** This section records **when the observability plane fails**; it does not defend it. Authenticating emitters, securing transport and storage, and establishing chain of custody are excluded by [RFC §2.2](CoSAI-AI-Telemetry-RFC.md#22-not-in-scope); the controls and standards that address them are in [XM §1.3](Telemetry-Cross-Mapping-Addendum.md#13-component--control-refinements). The line is the one drawn in [RFC §4.1](CoSAI-AI-Telemetry-RFC.md#41-detection-first): a signal that makes a silent failure distinguishable from a clean result is detection material, and every §1.11 field is that.

*Every field in §§1.1 to 1.10 and §1.12 assumes the telemetry and enforcement path is functioning and uncompromised. Nothing elsewhere in the field set tests that assumption. This section closes the loop: it is telemetry **about the observability plane**, motivated by the OWASP AOS **Instrument** pillar, where enforcement is a synchronous callout that can fail, be bypassed, or be starved.*

| Field | Cls | Capture (concept) | Evidence |
| :---------------- | :---- | :----------------------------------------------------------------------- | :---------- |
| **Enforcement-Point Availability & Failure Mode** | MUST | For each enforcement callout (guardrail, policy engine, external guardian): whether it was reached, its latency, and on failure whether the system **failed open or failed closed**, plus the action that was taken anyway. | `TA-01`,`TA-10`,`IR-01`,`AOC-12` |
| **Instrumentation Coverage / Hook Attestation** | MUST | Which lifecycle hooks are instrumented and active for this agent/run, the instrumentation version, and **where each hook reports**, the difference between "no events", "not observed", and "observed by someone else." | `TA-17`,`AOC-10`,`AOC-01`,`AOC-09` |
| **Event Sequence Continuity** | SHOULD | Per-session monotonic sequence number enabling gap and reordering detection. The stream **SHOULD be hash-chained**, and where chained the **chain head SHOULD be periodically signed and published outside the emitter's trust domain**. That is the minimum that lets a verifier distinguish a gap from a suppression, and the only form that detects `TA-17`, where the emitter itself is redirected. | `TA-17`,`AOC-01`,`AOC-10`,`AOC-07` |
| **Policy Reason Code** | MAY | Machine-readable reason code(s) for an enforcement decision, alongside the existing free-text detector name and score. | `IR-01`,`AOC-12`,`TA-01` |

### 1.12 Policy Enforcement & Mediation

**Components:** `componentAuthorizationPolicyDecisionPoint`, `componentAuthorizationPolicyEnforcementPoint`, the network enforcement points (`componentAgentNetworkPolicyEnforcementPoint`, `componentApplicationNetworkPolicyEnforcementPoint`, `componentToolNetworkPolicyEnforcementPoint`), and for approvals `componentAgentConsentSurface` and `componentApplicationConsentSurface`. **Cross-cutting:** the reference-monitor layer between the agent and every capability it invokes, tools, prompts, resources, inference providers, and inter-agent methods.

*§§1.1 to 1.10 record what the agent **did**; §1.11 records whether the observability plane **worked**. This section records what policy **decided**, and on what basis, under the CPEX threat model in which the LLM itself is the adversary ([XM §6.1](Telemetry-Cross-Mapping-Addendum.md#61-the-threat-model-the-most-important-contribution)).*

| Field | Cls | Capture (concept) | Evidence |
| :------------- | :---- | :------------------------------------------------------------------------------- | :------- |
| **Authorization Decision Record** **[CPEX]** | MUST | Per mediated operation: the terminal decision (**allow / deny**, with **allow-after-modification** flagged), the deny **reason and machine-readable code** (a fail-closed enforcement failure arrives as a deny with its own code), the per-step actions that produced it including any **suppressed deny** (a plugin denied and was overridden by pipeline role) and any **abort**, the **deciding authority** (inline policy rule vs external PDP, and which; Cedar / CEL / OPA / custom), the **rule or policy identifier** that produced it, and any obligations attached. Distinct from a content-guardrail verdict: this is the *authorization* outcome, not a classifier score. | `AOC-02`,`AOC-08`,`AOC-10`,`TA-08`,`TA-12`,`TA-13` |
| **Attribute Source / Trusted-Provenance Marking** **[CPEX]** | MUST ‡ | **Cross-cutting.** For every security-relevant attribute, the **authority that supplied it**: verified IdP token, policy decision point, enforcement-owned session store, platform/runtime, versus **self-asserted by the agent or model**. Under assume-breach, an unmarked value is an unverified value. | `AOC-01`,`AOC-08`,`AOC-10`,`AOC-15` |
| **Session Taint Labels & Information-Flow Decisions** **[CPEX]** | SHOULD | Information-flow labels in force for the session or message: which labels are set, **scope** (session vs message), what operation applied each, and (critically) when an operation is **denied because of accumulated taint rather than anything in its own payload**. The write-down record. | `AOC-03`,`TA-01`,`TA-02`,`TA-05` |
| **Human Approval / Elicitation Event** **[CPEX]** | SHOULD | Out-of-band approval lifecycle for high-impact actions: correlation ID, status (pending / resolved / expired), outcome, **approver identity as verified by the identity provider** (not as reported by the agent), channel, and the **scope-binding validation result**: whether the approval still covers the arguments actually presented at execution time. | `AOC-01`,`AOC-02`,`AOC-07`,`AOC-11`,`TA-23`,`TA-15` |
| **Backend / Route Restriction Decision** **[CPEX]** | SHOULD | Where an operation was allowed to execute: the candidate backend/model set, the constraint that narrowed it (region, model, site, cost tier, custom label), the selection made, and the behaviour when **no candidate qualified**. | `AOC-05`,`AOC-06`,`TA-01` |
| **Mediation Coverage & Bypass Path** **[CPEX]** | SHOULD | Whether this operation traversed a reference monitor at all, at which **placement** (inbound gateway / egress sidecar / in-process framework), and whether **unmediated paths to the same capability exist**. | `AOC-02`,`AOC-14`,`TA-06` |

‡ Cross-cutting, see the [classification summary](CoSAI-AI-Telemetry-RFC.md#6-field-catalogue). Applies to the attributes a hostile agent could plausibly fabricate: identity, authorization outcome, taint state, approval status, autonomy level, task declaration, and instruction configuration.

## 2. Correlation Patterns

Raw fields are evidence; detection comes from correlation.

A four-year measurement study of a production security operations centre; 115 million alerts, 2018 to 2022; found volumes of **24 K to 134 K alerts per day of which 0.01% corresponded to true attacks or compromises**, with 27% attack attempts and 49% benign triggers [[50]](#standards--frameworks). The corollary is a staffing one, and it is the reason this document orders fields by detection value rather than completeness: a trail no analyst can read is not an asset.

> **This section is the document's cross-component view.** Fields are organized by component ([RFC §6](CoSAI-AI-Telemetry-RFC.md#6-field-catalogue)) to match the CoSAI Risk Map, and that organization is deliberate. Two mechanisms carry detection across it: **Action Type** (§1.1) normalizes what an operation *is*, distinguishing LLM-call from tool-call from memory-op from message-send regardless of which component performed it, and the patterns below correlate fields across components rather than within one. What neither supplies is a normalized identity for the *same* operation carried by different protocols, so a tool call over MCP and one over A2A are described separately; **Protocol Envelope Capture** (§1.8) preserves that difference rather than erasing it. See [XM §6.5](Telemetry-Cross-Mapping-Addendum.md#65-divergences--gaps-remaining) item 3.

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

## 3. Attack & Incident Inventory

> **Reading the tables.** The *detecting fields* named in each row are defined in §§1.1 to 1.12, with what to capture and their tier; [RFC §6](CoSAI-AI-Telemetry-RFC.md#6-field-catalogue) is the index. The *primary components* are CoSAI Risk Map component IDs ([RFC §6](CoSAI-AI-Telemetry-RFC.md#6-field-catalogue)), given here without the `component` prefix.

Normalized catalogue of the attacks and incidents referenced above. Each row lists the telemetry the incident makes necessary and the primary risk-map component(s) involved.

**What counts as evidence.**

- **Taxonomies establish recognition, not occurrence.** Evidence means a **documented instance traceable to a primary source**. A MITRE ATLAS *technique*, a CoSAI Risk Map entry, an OWASP threat class, and the threat taxonomy of CoSAI's MCP Security paper are classifications: each records that a scenario is credible, none records that it happened. Where such a document cites a specific incident, that incident may enter the corpus **cited to its own primary source**, which is how `TA-11` to `TA-13` and four of `TA-14` to `TA-19` arrived. ATLAS **case studies** (`AML.CS####`) are instances and qualify; ATLAS **techniques** (`AML.Txxxx`) are classes and do not, which is why they are used to tag an attack and never to ground a field.
- **An instance need not be an executed attack.** The corpus holds three kinds of entry, and all three are admissible. Most are **executed attacks**. Four are **resisted attempts** (`AOC-12` to `AOC-15`, cited across 25 field slots): an attempt that was refused still evidences the field that recorded the refusal, and in those entries the refusal *is* the detection. Three are **non-adversarial failures of the same mechanism** (`TA-11`, a tenant boundary that failed unaided; `AOC-06`, provider-side silent truncation; `AOC-16`, an emergent cross-agent defence; 10 field slots between them): a field that makes a failure mode visible does so whatever caused it, and requiring an adversary would exclude the clearest instances of several failure modes for reasons of attribution rather than of detection. The document is nonetheless **attack-grounded** as described, because the large majority of the corpus is executed attacks; the rule describes the corpus as it stands.

### 3.1 Attack ID scheme

- **`TA-01…28`**: real-world attack vectors, each with its own field-detection mapping. **`TA-01` is EchoLeak** (M365 Copilot, CVE-2025-32711), the document's lead public case study, and the first entry in the catalogue. **`TA-02…10`** are the authoritative catalogue: Slack AI, Bard markdown exfil, training-data extraction, Samsung leak, LangChain RCE, system-prompt extraction, tool-chaining escalation, RAG-KB poisoning, context-window DoS. **`TA-11…13`** are MCP-mediated incidents from CoSAI's **MCP Security** paper. **`TA-14…19`** are later additions: MCP tool poisoning and rug pulls, a cross-tenant trace-configuration hijack, persistent memory poisoning, and cross-turn deferred tool invocation. **`TA-20…28`** are drawn from the [MITRE ATLAS case-study corpus](#36-attack-inventory--mitre-atlas-technique-mapping), each cited to its own primary source: credential-funded model access, instruction-configuration poisoning, guardrail bypass at scale, an approval gate disabled as configuration, two autonomous multi-agent campaigns, a computer-use agent destroying data, a self-replicating GenAI worm, and a provider API used as command and control.
- **`IR-01…05`**: CoSAI WS2 *AI Incident Response* case studies.
- **`AOC-01…16`**: *Agents of Chaos* (arXiv:2602.20021) case studies.
- Entries are **annotated where they are not executed attacks**: *(resisted)* for an attempt that was refused, *(emergent defense)* for `AOC-16`, and, in [§3.6](#36-attack-inventory--mitre-atlas-technique-mapping), an explicit note where no adversary technique applies because the mechanism failed unaided. All are admissible evidence under [RFC §5.1](CoSAI-AI-Telemetry-RFC.md#51-tiers); the annotation records what kind of instance an entry is, not how much it counts for.
- **`AML.Txxxx`**: **MITRE ATLAS** technique IDs. **This is the canonical adversary-technique taxonomy for this document**, and the only one that may appear in new material or in emitted telemetry ([§3.7](#37-attack-taxonomy-mitre-atlas-is-canonical)). The CoSAI `AT10xx` labels used by the incident-response case studies are **deprecated aliases**, retained solely so existing material can be migrated, see the alias table in [§3.5](#35-attack-taxonomy-cosai-at10xx-codes-deprecated-aliases-to-mitre-atlas). The full attack→ATLAS mapping is [§3.6](#36-attack-inventory--mitre-atlas-technique-mapping).

---

### 3.2 Real-world attack vectors

The catalogue of documented, real-world attacks, each mapped to the CoSAI telemetry fields that detect it, ordered so that the lead case study comes first:

- **`TA-01`: EchoLeak** is the document's lead public case study and the first entry in the catalogue. It is included here because it is the most complete public example of the attack class this field set exists to make visible (a zero-click, retrieval-mediated, classifier-bypassing exfiltration chain) and because its own post-incident guidance is the telemetry argument this document opens with. Its detecting-field list is derived here.
- **`TA-14…19`** close two corpus gaps and strengthen three fields. `TA-14` and `TA-15` supply the tool-definition rug pull and the tool-description poisoning that **Tool Definition Digest** (§1.5) detects; `TA-17` is the first cross-tenant exposure with an adversary present, and the first documented attack **on the observability plane**; `TA-18` grounds the §1.6 memory cluster against a production system. Four are MITRE ATLAS case studies (`AML.CS0038`, `AML.CS0040`, `AML.CS0053`, `AML.CS0054`) and are cited to the primary sources ATLAS itself lists.
- **`TA-11…13`** are MCP-mediated incidents, surfaced by CoSAI's **MCP Security** paper (WS4) and cited here to their primary sources. They enter the corpus because they supply documented instances of attack classes the field set otherwise rests on analogical grounding for: cross-tenant leakage and MCP-mediated privilege escalation. Their detecting-field lists are derived here.
- **`TA-02…10`** are the authoritative catalogue, reproduced with their original detecting-field lists so the fields above can cite them by ID.

| ID | Name (date) | What happened | Detecting fields | Primary component(s) |
| :---- | :---------------- | :------------------------------------------- | :-------------------------------- | :-------- |
| **TA-01** | **EchoLeak** (Microsoft 365 Copilot; CVE-2025-32711; disclosed Jun 2025) [[4]](#real-world-attack-primary-sources) | Zero-click "LLM scope violation": a single crafted email, requiring no user interaction, is retrieved into Copilot's context and treated as instruction, chaining bypasses of the XPIA injection classifier, link redaction, and CSP to exfiltrate internal SharePoint/OneDrive/Teams content through a trusted proxy domain. | Model Input + Input Trust Class, Trigger Type (autonomous), Retrieval Event, Retrieved-Content Source, Tool Call I/O, Output Egress Destination, Guardrail (Input) Verdict, Enforcement-Point Availability | AgentInputHandling, RAGContent, Tools, AgentOutputHandling |
| **TA-02** | Slack AI private-channel exfiltration (Aug 2024) [[5]](#real-world-attack-primary-sources) | Indirect prompt injection: hidden instructions posted in a public channel are retrieved when users query Slack AI, which then exfiltrates private-channel data via phishing links. | Model Input, Response, Tool Call I/O (retrieval), Identities Used, Tool Error (absence), Action Type (LLM→retrieval→LLM) | RAGContent, Tools, AgentOutputHandling |
| **TA-03** | Google Bard exfiltration via markdown images (2023) [[6]](#real-world-attack-primary-sources) | Prompt injection instructs the model to render a markdown image whose URL carries stolen conversation data in query params; the browser silently sends it to the attacker. | Response (URL w/ encoded data), Model Input, LLM Refusal (absence), Source IP, Execution Status=complete | ApplicationOutputHandling |
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
| **TA-14** | **MCPoison, Cursor MCP configuration trust bypass** (CVE-2025-54136, CVSS 7.2; fixed in 1.3, 29 Jul 2025) [[17]](#real-world-attack-primary-sources) | Trust is bound only to an MCP entry's **name**: once a configuration is approved, later changes to its command or arguments run without re-validation or prompt. An attacker with repository write access swaps the payload after approval, and the malicious command re-executes every time the project is opened. **The declared tool contract is unchanged; what mutates is the launch command in the configuration entry**, so the detecting field is the capability-set change rather than a digest over the contract. | Capability-Set Change Event, Execution Environment / Sandbox | Tools, ToolRegistry |
| **TA-15** | **MCP tool-description poisoning** (Invariant Labs, Apr 2025) [[18]](#real-world-attack-primary-sources) | The tool's **docstring description** carries the injection. Ingested into agent context at discovery, it instructs the agent to read credential files and place their contents into a tool argument, exfiltrating them to the poisoned server when the tool runs. The declared contract is itself the payload. | Tool Definition Digest, Tool Call I/O (arguments), MCP Server Identity & Primitive, Human Approval / Elicitation Event | Tools, ToolServer |
| **TA-16** | **`postmark-mcp` npm rug pull** (malicious from v1.0.16; removed 25 Sep 2025) [[19]](#real-world-attack-primary-sources) | The actor registered the package name, published working versions until it passed 1,000 weekly downloads, then performed a **rug pull**: the malicious release BCC'd every email sent through the server, with attachments and headers, to an attacker address. The declared tool contract did not change; the shipped version did. | MCP Server Identity & Primitive (name **and version**), Output Egress Destination, Tool Call I/O, Version / Repository / Software Ref, AgBOM / Inventory Snapshot | Tools, ToolServer, AgentOutputHandling |
| **TA-17** | **DifyTap, cross-tenant trace-configuration hijack** (Dify; CVE-2026-41947, CVSS 9.1; Jun 2026) [[20]](#real-world-attack-primary-sources) | An authenticated editor could set and enable **trace configurations for any application regardless of tenant ownership**, redirecting every message and response of a victim tenant's application to an attacker-controlled trace provider: a persistent exfiltration channel built out of the observability plane itself. Three of the four disclosed flaws carried cross-tenant impact. | Organization / Tenant ID, Instrumentation Coverage / Hook Attestation, Authorization Decision Record, Output Egress Destination, Identities Used | Application, Identity |
| **TA-18** | **ChatGPT persistent memory poisoning** (Embrace The Red) [[21]](#real-world-attack-primary-sources) | A prompt injection in a document read through a connected app (Google Drive, OneDrive), an uploaded image, or a browsed page writes attacker-chosen instructions into long-term memory. **The injected memories persist and are recalled in later conversations**; the only visible trace is a "Memory updated" notice. | Memory Write Event, Memory Provenance / Source, Memory Read / Injection Event, Memory Integrity / Poisoning Signal, Input Trust Classification | Memory, AgentInputHandling |
| **TA-19** | **Delayed automatic tool invocation** (Google Gemini; Embrace The Red) [[22]](#real-world-attack-primary-sources) | Untrusted content entering context in one turn plants instructions that fire on a **later** turn, defeating a control that forbids sensitive tool invocation in the same turn the untrusted data arrived. Invisible to any detection scoped to a single turn. | Session / Turn / Step IDs, Input Trust Classification, Model Input, Tool Call I/O | ReasoningCore, AgentInputHandling, Tools |
| **TA-20** | **LLMjacking, stolen cloud credentials reselling model access** (Sysdig, May 2024) [[55]](#real-world-attack-primary-sources) | Stolen cloud credentials were used to reach cloud-hosted models, enumerate which models a victim account had enabled, and stand up a **reverse proxy reselling that access** to third parties. Cost lands on the victim; the activity is legitimate inference traffic under a valid identity. | Resource-Consumption Aggregate, Input / Output Token Counts, Identities Used, Provider / Endpoint Identity, Model Name + Version (enumeration) | ModelServing, Identity |
| **TA-21** | **Rules File Backdoor, AI coding-assistant instruction poisoning** (Pillar Security, Mar 2025) [[56]](#real-world-attack-primary-sources) | Malicious instructions hidden with **invisible Unicode characters** in the rules files that configure coding assistants, distributed through open-source repositories, causing the assistant to emit backdoored code. The instruction configuration is the payload, and it is not the system prompt the vendor shipped. | System Prompt / Instruction Config, Encoded / Obfuscated Payload Indicator, Repository / Code Path / Software Ref, Attribute Source / Trusted-Provenance Marking | AgentSystemInstruction, ModelFrameworksAndCode |
| **TA-22** | **Storm-2139, Azure OpenAI guardrail bypass at scale** (Microsoft, Dec 2024 onward) [[57]](#real-world-attack-primary-sources) | A criminal group scraped exposed customer credentials, accessed generative-AI accounts, and operated **custom tooling that bypassed safety guardrails and modified service capabilities**, reselling the bypass as a service. The second documented guardrail defeat in this corpus after `TA-01`, and the first operated as a business. | Guardrail (Input) Verdict, Guardrail (Output) Verdict, LLM Refusal, Identities Used, Organization / Tenant ID | ApplicationInputHandling, ModelServing, Identity |
| **TA-23** | **OpenClaw 1-click RCE with confirmation bypass** (CVE-2026-25253; DepthFirst, Feb 2026) [[58]](#real-world-attack-primary-sources) | A malicious link executed script in the agent's context, stole its token, then **modified the agent's configuration to disable the user-confirmation step** and escaped the container to run shell commands on the host. The approval gate was not defeated by argument; it was switched off as configuration. | Human Approval / Elicitation Event, Capability-Set Change Event, Execution Environment / Sandbox, Authorization Decision Record, Identities Used | Application, Tools, Identity |
| **TA-24** | **GTG-1002, AI-orchestrated espionage campaign** (Anthropic, Sep 2025; ATT&CK campaign C0062) [[59]](#real-world-attack-primary-sources) | A state-sponsored group circumvented an agent's safeguards and configured it as an **autonomous attack framework** against approximately 30 organizations, with the model performing the operational work and humans supervising. Reconnaissance, exploitation and collection ran as agent tool calls under one delegated authority. | Loop / Step-Count Signal, Task / Intent Declaration, Trigger Type, Tool Call I/O, LLM Refusal, Identities Used | ReasoningCore, Orchestration, Tools |
| **TA-25** | **Multi-agent framework against government systems** (Taiwan MODA / Dream Research Labs / FT, Jul 2026) [[60]](#real-world-attack-primary-sources) | An operator ran a **multi-agent framework** built on two agent runtimes through 12 attack waves over four days; a recovered 160 MB workspace of 1,395 files documented the orchestration. The defending ministry detected abnormal agent-driven activity rather than a human operator's pattern. | Inter-Agent Message, Delegation Chain, Background / Scheduled Task Event, Loop / Step-Count Signal, Trigger Type | Orchestration, Identity |
| **TA-26** | **Data destruction via computer-use agent** (HiddenLayer, Oct 2024) [[61]](#real-world-attack-primary-sources) | A prompt injection embedded in a **PDF** reached a computer-use agent when a user asked it to work with the file, used jailbreak and obfuscation to clear the guardrails, and invoked the agent's `bash` tool to destroy user data. The corpus's first computer-use instance: the capability is a shell, and the carrier is an attachment. | Content Modality & Attachment Identity, Input Trust Classification, Guardrail (Input) Verdict, Tool Call I/O, Action Type | AgentInputHandling, Tools |
| **TA-27** | **Morris II, self-replicating GenAI worm** (Cohen, Bitton & Nassi, Mar 2024) [[62]](#real-world-attack-primary-sources) | A **zero-click adversarial self-replicating prompt** that reproduces itself in the assistant's output and propagates between connected GenAI systems, demonstrated against a RAG-based email assistant that ingests mail automatically and retrieves prior correspondence. Propagation is the payload. | Inter-Agent Message, Retrieved-Content Source / Provenance, Model Input, Trigger Type, Memory Write Event | RAGContent, Orchestration |
| **TA-28** | **SesameOp, provider API as command and control** (Microsoft DART, Jul 2025) [[63]](#real-world-attack-primary-sources) | A backdoor used a **model provider's Assistants API as its C2 channel**, fetching commands and exfiltrating encrypted results through it for several months. The exfiltration destination is the same endpoint the application legitimately calls, so destination alone does not separate the two. | Output Egress Destination, Provider / Endpoint Identity, Tool Call I/O, Identities Used | ModelServing, ApplicationOutputHandling |

### 3.3 CoSAI WS2: AI Incident Response case studies

| ID | Name | What happened | Taxonomy: CoSAI `AT` → MITRE ATLAS | Key telemetry needed | Primary component(s) |
| :---- | :--------- | :----------------------------- | :---------------------------- | :-------------------- | :------------ |
| **IR-01** | Breaking the Prompt Wall | Lightweight prompt-injection templates bypass safety filters across chat, file upload, and agent config. | AT1070/AT1051/AT1091/AT1040 → `AML.T0051`(.000/.001), `AML.T0054`, `AML.T0053` | Model Input, Input Source/Trust, Guardrail Verdict, LLM Refusal | ApplicationInputHandling, AgentInputHandling |
| **IR-02** | MINJA (Memory Injection Attack) | Benign queries induce the agent to autonomously generate & persist malicious reasoning in memory. | AT1070/AT1081/AT1050/AT1040/AT1080 → `AML.T0051`, `AML.T0070`, `AML.T0059`, `AML.T0061`, `AML.T0067` | Memory Write/Read, Memory Provenance, Loop Signal, Observation/Thought | Memory |
| **IR-03** | Poison-RAG | Manipulate **item metadata tags** in black-box RAG to suppress/promote items. | data/metadata poisoning → `AML.T0070`, `AML.T0059` | Retrieval Event, Retrieved-Content Source, Metadata Integrity Signal | RAGContent |
| **IR-04** | Capital One Data Breach *(non-AI incident)* | Cloud misconfiguration/SSRF-class breach → large-scale data exfiltration. Carried for field overlap with AI incident response; **does not alone ground a MUST field**. | non-AI infra/exfil → maps to MITRE **ATT&CK**, not ATLAS | Source IP, Identities Used, Tool Call I/O, Version | ModelServing, Identity |
| **IR-05** | AGENTPOISON | Optimized trigger-based adversarial queries poison agent memory/RAG. | memory/RAG poisoning → `AML.T0070`, `AML.T0020`, `AML.T0043` | Memory Write/Read, Retrieval Event, Integrity/Poisoning Signal | Memory, RAGContent |

### 3.4 Agents of Chaos (arXiv:2602.20021): live red-team case studies

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

### 3.5 Attack taxonomy: CoSAI `AT10xx` codes (deprecated aliases to MITRE ATLAS)

**Migration table.** The `AT10xx` codes are the informal technique labels used by the AI-Incident-Response case studies. **[MITRE ATLAS](https://atlas.mitre.org/) `AML.Txxxx` is canonical and `AT10xx` is deprecated.** This table exists so that existing CoSAI material can be read and migrated; **do not use the left-hand column in new work or in emitted telemetry.** Read it left-to-right once, then use ATLAS.

ATLAS is community-maintained, versioned, and ATT&CK-aligned, and is a first-class compliance framework in AITF via `compliance.framework = mitre_atlas`, so a tagged event correlates with existing SOC tooling without translation.

| CoSAI `AT` (alias) | Meaning | MITRE ATLAS technique(s) | ATLAS tactic(s) |
| :---- | :----------------- | :---------------------------------------------------- | :--------------------------- |
| `AT1070` | Adversarial Prompt Injection | **`AML.T0051` LLM Prompt Injection** (`.000` Direct) | Execution |
| `AT1051` | Context Injection via Web Retrieval | **`AML.T0051.001` LLM Prompt Injection: Indirect**; **`AML.T0070` RAG Poisoning**; `AML.T0066` Retrieval Content Crafting | Execution; Collection / AI Attack Staging; Resource Development |
| `AT1091` | Agent Instruction Injection | **`AML.T0051.002` LLM Prompt Injection: Triggered**; **`AML.T0053` AI Agent Tool Invocation** | Execution; Execution / Privilege Escalation |
| `AT1040` | Safety Evasion via Instruction Reframing | **`AML.T0054` LLM Jailbreak**; `AML.T0068` LLM Prompt Obfuscation | Privilege Escalation / Defense Evasion; Defense Evasion |
| `AT1050` | Data Poisoning | **`AML.T0020` Training Data Poisoning**; **`AML.T0070` RAG Poisoning**; `AML.T0059` Erode Dataset Integrity | Resource Development / Persistence; Collection; Impact |
| `AT1080` | Output Manipulation | **`AML.T0067` LLM Trusted Output Components Manipulation** (`.000` Citations); `AML.T0057` LLM Data Leakage | Defense Evasion; Exfiltration |
| `AT1081` | Feedback Loop Attack | **`AML.T0061` LLM Prompt Self-Replication**; `AML.T0059` Erode Dataset Integrity | Persistence; Impact |

### 3.6 Attack inventory → MITRE ATLAS technique mapping

Each catalogued attack mapped to its primary ATLAS technique(s). This is the cross reference that lets detections and telemetry be tagged with a canonical `AML.Txxxx` reference.

> **Verified against ATLAS `v2026.08`** (released 1 September 2026; `dist/v6/ATLAS-2026.08.yaml` in [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data)). All 71 ATLAS identifiers cited anywhere in this document resolve at that version, and each is named as ATLAS names it. Re-run this check at publication and at each revision: ATLAS is versioned monthly and grew from 147 techniques and 45 case studies in `v2025.12` to **197 techniques and 72 case studies** in `v2026.08`, and it renames and retires identifiers as well as adding them: `AML.T0020` is named *Training Data Poisoning*, and `AML.T0104` has been absorbed into `AML.T0110` and its sub-techniques.
>
> **Coverage.** Rows are mapped to the most precise sub-technique ATLAS defines: prompt-injection rows name the vector (`.000` Direct, `.001` Indirect, `.002` Triggered), cost-harvesting rows the mechanism (`.000` Excessive Queries, `.001` Resource-Intensive Queries), and context-poisoning rows the scope (`.000` Memory, `.001` Thread). **42 of the techniques ATLAS has added since `v2025.12` are uncited here, because the corpus holds no instance of them**: under [RFC §5.1](CoSAI-AI-Telemetry-RFC.md#51-tiers) a technique establishes recognition rather than occurrence, so it cannot be cited against a row that does not instantiate it. Of the 72 case studies, nine are in the corpus as `TA-20` to `TA-28` and 15 are cross-referenced from the rows below.

| Attack | MITRE ATLAS technique(s) | Notes |
| :-------------------- | :--------------------------------------------------------- | :----------------------- |
| **TA-01** EchoLeak | `AML.T0051.001` Indirect Injection; `AML.T0057` Data Leakage; `AML.T0070` RAG Poisoning; `AML.T0067` LLM Trusted Output Components Manipulation | Zero-click chained exfil. ATLAS case study `AML.CS0059` |
| **TA-02** Slack AI exfiltration | `AML.T0051.001` Indirect Injection; `AML.T0057` Data Leakage; `AML.T0070` RAG Poisoning | Retrieval-mediated exfil |
| **TA-03** Bard markdown exfil | `AML.T0067.000` LLM Trusted Output Components Manipulation: Citations; `AML.T0057` Data Leakage | Data in outbound image URL. `AML.T0024` does not apply: its sub-techniques are training-data and model extraction, not exfiltration of user data |
| **TA-04** Training-data extraction | `AML.T0024.000` Infer Training Data Membership; `AML.T0057` Data Leakage | Divergence/repetition attack |
| **TA-05** Samsung leak | `AML.T0057` Data Leakage (self-inflicted) | Sensitive data pasted to external service |
| **TA-06** LangChain RCE | `AML.T0051.000` LLM Prompt Injection: Direct; `AML.T0053` Tool Invocation; `AML.T0102` Generate Malicious Commands | Injection → unsandboxed code exec |
| **TA-07** System-prompt extraction | `AML.T0056` Extract LLM System Prompt; `AML.T0069.002` Discover System Prompt | n/a |
| **TA-08** Tool-chaining escalation | `AML.T0053` AI Agent Tool Invocation | Chained authorized calls → escalation |
| **TA-09** RAG KB poisoning | `AML.T0070` RAG Poisoning; `AML.T0051.001` Indirect Injection; `AML.T0064` Gather RAG-Indexed Targets | Hidden instructions in retrievable docs |
| **TA-10** Context-window DoS | `AML.T0029` Denial of AI Service; `AML.T0034.001` Cost Harvesting: Resource-Intensive Queries | Sponge/recursive inputs |
| **TA-11** Asana MCP cross-tenant | `AML.T0057` LLM Data Leakage | Tenant-isolation and response-cache failure; **no adversary technique applies**: the boundary failed unaided |
| **TA-12** Supabase MCP | `AML.T0051.001` Indirect Injection; `AML.T0053` AI Agent Tool Invocation; `AML.T0057` Data Leakage | Stored injection in ticket data → `service_role` MCP tool bypassing RLS → private tables |
| **TA-13** WordPress AI Engine | `AML.T0053` AI Agent Tool Invocation; MITRE **ATT&CK** privilege escalation | Authorization not enforced at the MCP tool boundary |
| **TA-14** MCPoison | `AML.T0109` AI Supply Chain Rug Pull; `AML.T0011.002` Poisoned AI Agent Tool; `AML.T0053` Tool Invocation | Approved MCP configuration entry's launch command mutated after approval |
| **TA-15** MCP tool-description poisoning | `AML.T0110.000` AI Agent Tool Poisoning: Definition and Instructions; `AML.T0098` AI Agent Tool Credential Harvesting; `AML.T0086` Exfiltration via AI Agent Tool Invocation | ATLAS case study `AML.CS0054` |
| **TA-16** `postmark-mcp` rug pull | `AML.T0109` AI Supply Chain Rug Pull; `AML.T0110.001` AI Agent Tool Poisoning: Implementation; `AML.T0073` Impersonation; `AML.T0086` | ATLAS case study `AML.CS0053` |
| **TA-17** DifyTap | `AML.T0057` LLM Data Leakage; `AML.T0048` External Harms | Observability plane repurposed as the exfiltration channel |
| **TA-18** ChatGPT memory poisoning | `AML.T0051.001` Indirect Prompt Injection; `AML.T0080.000` AI Agent Context Poisoning: Memory; `AML.T0093` Prompt Infiltration via Public-Facing Application | ATLAS case study `AML.CS0040` |
| **TA-19** Delayed tool invocation | `AML.T0094` Delay Execution of LLM Instructions; `AML.T0080.001` AI Agent Context Poisoning: Thread; `AML.T0051.001`; `AML.T0053`; `AML.T0085.001` | ATLAS case study `AML.CS0038` |
| **TA-20** LLMjacking | `AML.T0034.000` Cost Harvesting: Excessive Queries; `AML.T0012` Valid Accounts; `AML.T0040` AI Model Inference API Access | Stolen credentials resold as model access |
| **TA-21** Rules File Backdoor | `AML.T0018.003` Modify Prompt Construction Logic; `AML.T0068` LLM Prompt Obfuscation; `AML.T0010.001` AI Supply Chain Compromise: AI Software | Instruction configuration as supply-chain payload |
| **TA-22** Storm-2139 | `AML.T0054` LLM Jailbreak; `AML.T0012` Valid Accounts; `AML.T0048.003` External Harms: User Harm | Guardrail bypass operated as a service |
| **TA-23** OpenClaw 1-click RCE | `AML.T0011.003` User Execution: Malicious Link; `AML.T0105` Escape to Host; `AML.T0053` AI Agent Tool Invocation | Approval gate disabled as configuration. ATLAS case study `AML.CS0050` |
| **TA-24** GTG-1002 | `AML.T0124` Autonomous Attack Orchestration; `AML.T0054` LLM Jailbreak; `AML.T0116` Autonomous Reconnaissance; `AML.T0117` Autonomous Attack-Path Adaptation | First reported AI-orchestrated campaign. ATLAS case study `AML.CS0069` |
| **TA-25** Multi-agent framework vs government systems | `AML.T0124` Autonomous Attack Orchestration; `AML.T0118` Autonomous AI Agent Communication | Multi-agent orchestration in the wild. ATLAS case study `AML.CS0071` |
| **TA-26** Computer-use data destruction | `AML.T0051.001` LLM Prompt Injection: Indirect; `AML.T0054` LLM Jailbreak; `AML.T0068` LLM Prompt Obfuscation; `AML.T0053` AI Agent Tool Invocation | Attachment-borne injection → shell. ATLAS case study `AML.CS0046` |
| **TA-27** Morris II | `AML.T0061` LLM Prompt Self-Replication; `AML.T0070` RAG Poisoning; `AML.T0051.001` Indirect | Zero-click propagation between GenAI systems. ATLAS case study `AML.CS0024` |
| **TA-28** SesameOp | `AML.T0086` Exfiltration via AI Agent Tool Invocation; `AML.T0040` AI Model Inference API Access | Provider API as C2. ATLAS case study `AML.CS0042` |
| **IR-01** Breaking the Prompt Wall | `AML.T0051`(.000/.001), `AML.T0054`, `AML.T0053` | See §3.3 |
| **IR-02** MINJA | `AML.T0051.000` Direct and `AML.T0051.002` Triggered; `AML.T0080.000` AI Agent Context Poisoning: Memory; `AML.T0070`, `AML.T0059`, `AML.T0061`, `AML.T0067` | Memory injection/feedback: injected as a user, activated by a victim's query |
| **IR-03** Poison-RAG | `AML.T0070` RAG Poisoning; `AML.T0059` Erode Dataset Integrity | Metadata-tag poisoning |
| **IR-04** Capital One | MITRE **ATT&CK** (non-AI) | SSRF/cloud exfil |
| **IR-05** AGENTPOISON | `AML.T0070`, `AML.T0020`, `AML.T0043.004` Craft Adversarial Data: Insert Backdoor Trigger | Trigger-based memory/RAG poisoning |
| **AOC-01** Disproportionate Response | `AML.T0053` AI Agent Tool Invocation; `AML.T0031` Erode AI Model Integrity | Destructive tool use + false completion report |
| **AOC-02** Compliance w/ Non-Owner | `AML.T0051.000` LLM Prompt Injection: Direct; `AML.T0053` Tool Invocation | Non-owner authority → shell/file/data actions |
| **AOC-03** Disclosure of Sensitive Info | `AML.T0057` LLM Data Leakage; `AML.T0051.001` Indirect Injection | Escalating indirect extraction |
| **AOC-04** Waste of Resources / Looping | `AML.T0034.002` Agentic Resource Consumption; `AML.T0118` Autonomous AI Agent Communication; `AML.T0029` Denial of AI Service; `AML.T0061` Self-Replication | Multi-agent loop; runaway cron/shell |
| **AOC-05** Denial-of-Service | `AML.T0029` Denial of AI Service; `AML.T0034.000` Cost Harvesting: Excessive Queries; `AML.T0034.001` Resource-Intensive Queries | Memory growth + attachment flooding |
| **AOC-06** Agents Reflect Provider Values | `AML.T0048`* External Harms / provider policy | Provider-side silent truncation (governance signal) |
| **AOC-07** Agent Harm | `AML.T0054` LLM Jailbreak; `AML.T0051.000` LLM Prompt Injection: Direct | Guilt/gaslighting → escalating self-destruction |
| **AOC-08** Owner Identity Spoofing | `AML.T0051.000` LLM Prompt Injection: Direct; `AML.T0053` Tool Invocation | Cross-channel display-name spoof → privileged action |
| **AOC-09** Collaboration / Knowledge Sharing | `AML.T0118.001` Autonomous AI Agent Communication: Direct Agent Communication; `AML.T0053` Tool Invocation; `AML.T0061` Self-Replication | Cross-agent capability transfer |
| **AOC-10** Agent Corruption | `AML.T0051.001` Indirect Injection; `AML.T0070` RAG Poisoning; `AML.T0020` Training Data Poisoning | Externally-editable memory-linked "constitution" |
| **AOC-11** Libelous within Community | `AML.T0051.000` LLM Prompt Injection: Direct; `AML.T0061` Self-Replication; `AML.T0052.000` Spearphishing via LLM | Impersonation → mass defamatory broadcast |
| **AOC-12** Prompt Injection via Broadcast | `AML.T0051.000` LLM Prompt Injection: Direct; `AML.T0068` LLM Prompt Obfuscation | base64/image/OCR/markup tags *(resisted)* |
| **AOC-13** Email Spoofing request | `AML.T0052` Phishing; `AML.T0053` Tool Invocation | SMTP sender forgery *(resisted)* |
| **AOC-14** Data Tampering | `AML.T0053` Tool Invocation; `AML.T0059` Erode Dataset Integrity | Bypass API to edit storage *(resisted)* |
| **AOC-15** Social Engineering | `AML.T0052.000` Spearphishing via Social Engineering LLM | Fake owner-compromise *(resisted)* |
| **AOC-16** Inter-Agent Coordination | *(defensive)*: `AML.T0118.001` Direct Agent Communication carrying detection of `AML.T0051`/`AML.T0053` patterns | Emergent cross-agent defense |

\* `AML.T0048` (External Harms) is the closest ATLAS anchor for provider-policy/governance effects; `AOC-06` is primarily a governance/availability signal rather than a discrete adversary technique. Two rows stay at parent granularity deliberately. `T0048`'s five sub-techniques are harm *categories* (financial, reputational, societal, user, AI intellectual-property theft) and none describes provider-side truncation. `AOC-13` stays at `AML.T0052` (Phishing) because `.000` is spearphishing *generated by* an LLM and `.001` is deepfake-assisted, whereas `AOC-13` is a forged sender phishing the agent itself.

---

### 3.7 Attack Taxonomy (MITRE ATLAS is canonical)

**MITRE ATLAS `AML.Txxxx` is the canonical adversary-technique taxonomy for this field set. The CoSAI `AT10xx` codes are formally deprecated to aliases.**

What that means in practice:

1. **Every technique reference is an ATLAS ID.** Detections, the [Threat Classification / ATLAS Technique Tag](#12-input-handling--trust-provenance) field (§1.2), compliance rollups, and all attack mappings in [§3](#3-attack--incident-inventory) use `AML.Txxxx`. Where a technique has a sub-technique that fits, the sub-technique is preferred (`AML.T0051.001` over `AML.T0051`).
2. **`AT10xx` codes are retained for one purpose only**: reading existing CoSAI material. They appear in [§3.5](#35-attack-taxonomy-cosai-at10xx-codes-deprecated-aliases-to-mitre-atlas) as an alias table and in the `IR-` case-study rows that historically cited them. **New material must not introduce `AT10xx` codes**, and they should not appear in emitted telemetry.
3. **No CoSAI-only technique numbering is maintained going forward.** If a technique has no ATLAS equivalent, the correct response is to propose it upstream to ATLAS, not to mint a local code. Where no anchor currently exists, the mapping records the nearest ATLAS technique and flags the judgment, as [§3.6](#36-attack-inventory--mitre-atlas-technique-mapping) does for `AOC-06`.

**Why.** ATLAS is community-maintained, versioned, and ATT&CK-aligned, so a detection tagged `AML.T0051` correlates with the rest of a SOC's ATT&CK-based tooling without translation. It is already a first-class compliance framework in AITF (`compliance.framework = mitre_atlas`), so the tag has a binding today. And a parallel CoSAI numbering would need its own maintenance, governance, and mapping table for no benefit that ATLAS does not already provide, the alias table in §3.5 exists to *retire* that burden, not to institutionalize it.

**Scope of the deprecation.** This decision binds this document. The CoSAI AI-Incident-Response material that originated the `AT10xx` labels is owned by another workstream; the recommendation to that group is to adopt the same position, and [§3.5](#35-attack-taxonomy-cosai-at10xx-codes-deprecated-aliases-to-mitre-atlas) is written to be usable as the migration table if they do.

## 4. Tiering Rationale

Why each component's **MUST** fields earn that tier, and where the tier boundaries are closest. Ordered to match the field tables, §1.1 through §1.12.

The rubric is in [RFC §5.1](CoSAI-AI-Telemetry-RFC.md#51-tiers). Two rules recur below. **Attack count alone does not set the tier**: a field cited by five attacks stays SHOULD if all five presuppose an edge modality such as delegation. And **the highest-priority use case governs**: a field whose dominant value is Q or A does not reach MUST however useful it is.

**Availability and provider-policy signals are in scope, and this order is what places them.** A signal that makes a *silent failure distinguishable from a clean result* is detection material, not governance reporting: `AOC-06` is a provider API truncating responses and returning "unknown error", which is the model-serving instance of the problem [§1.11](#111-observability-plane-integrity) is built around, where a verdict that never arrived and a verdict of `allow` read identically in the log. Where such a signal instead evidences a policy or an SLA, its value is Q or A and it lands at MAY, as **Provider / Endpoint Identity** (§1.4) does. The boundary is drawn by what the signal lets a defender distinguish, not by whether an adversary was involved.

- **The evidence gate admits resisted attempts and non-adversarial failures ([§3](#3-attack--incident-inventory)); the [priority gate](CoSAI-AI-Telemetry-RFC.md#41-detection-first) is what keeps reliability-only signals out of MUST.** The two are independent, and it has always been the second one doing that work. `AOC-06` is the proof: non-adversarial, grounding six fields of which four are MUST, and yet **Provider / Endpoint Identity** (§1.4) still sits at MAY, because its dominant value is Q and A and the D > R > Q > A order governs. A reliability incident can therefore ground a field without lifting a reliability-dominant field to MUST.
- **Closing an evidence gap does not promote a modality-gated field.** The two gates are sequential and independent, so supplying a documented instance retires the evidence argument without moving the tier. That is still worth doing, because it removes the weaker of the two reasons a field sits below MUST, but a field held by its modality stays SHOULD however much evidence accumulates. Only a judgement that the modality has become typical moves it.

### 4.1 Application & Agent Reasoning Core (§1.1)

Every MUST here is an identifier or execution-context anchor that later sections' detections resolve *through*: ≥3 corpus attacks apiece, no modality precondition, **D and R jointly**. *What ran and where*: Agent Name, Instance ID, Surface (D: off-inventory agents; R: quarantining one instance while siblings run, per `AOC-04`, `AOC-05`). *What else belongs to this incident*: Workflow/Run ID, Session/Turn/Step IDs, Trace Context. *What it did and how it ended*: Action Type (the think→act boundary where `AOC-01` and `AOC-02` did their damage) and Execution Status. *What it was configured to do*: System Prompt, both a config-integrity baseline and the reference against which extraction is detected (`TA-07` succeeds when the response reproduces it). *Who started it*: Trigger Type.

- **The identifiers are a hierarchy, not a bag.** Instance → Run → Session → Turn → Step, threaded by Trace Context. `TA-08` (tool-chaining escalation) and `IR-01` (iterated reframing until a refusal flips) are *within-session, across-turn* patterns invisible at run granularity.
- **Trigger Type is MUST because zero-click is a telemetry category.** `TA-01` starts an entire run from one inbound email with no human in the loop. Surface/App would record "email" for both that and an ordinary request; the autonomous flag is what separates them.
- **Stop Reason is MUST** on the [rubric](CoSAI-AI-Telemetry-RFC.md#51-tiers)'s interpretation clause, and on evidence (`TA-04`, `TA-10`, `IR-01`). Without it a **Response / Model Output** cut short by a provider content filter or a token limit reads the same as one that finished; a deployment's own guardrail verdict does not record the provider's filter, and token counts cannot infer it. Every major provider API returns a completion's stop reason, so it is implementable wherever a model is called.
- **Autonomy Level is SHOULD**: the oversight dial for delegated action. The corpus repeatedly shows agents operating *above* their intended autonomy (`AOC-04`, `AOC-01`, `AOC-07`); logging the claimed level is what makes that detectable.
- **Organization / Tenant ID is SHOULD on the modality gate, not the evidence gate.** Six attacks cite it (`AOC-02`, `AOC-05`, `TA-05`, `TA-01`, `TA-11`, `TA-17`), which clears the evidence bar comfortably; what holds it below MUST is that multi-tenant hosting is a deployment modality, and a single-tenant deployment has nothing for the field to describe. **MUST for any multi-tenant deployment.** The two cross-tenant entries differ in a way worth recording: `TA-11` involved **no attacker**, the boundary failed unaided, which under [RFC §5.1](CoSAI-AI-Telemetry-RFC.md#51-tiers) is a documented instance of the failure mode and not a lesser kind of evidence, since the field detects the boundary failure whatever caused it. `TA-17` supplies the adversarial instance, an authenticated caller reaching another tenant's application deliberately. Evidence is therefore settled twice over, and only the modality gate remains.

### 4.2 Input Handling & Trust Provenance (§1.2)

Model Input is cited by **8** attacks, second only to Tool Call I/O (§1.5) in the document; Input Trust Classification by **7**, Guardrail (Input) Verdict by **6**, Source IP and Content Modality by **5** each. All **D-primary**: these are the fields an injection or jailbreak detection actually fires on, with strong secondary R value. None presupposes an unusual modality.

- **Model Input** must cover *all* inputs, not the first user turn: injection arrives via tool outputs (`IR-01`), retrieved content (`IR-03`, `TA-01`, `TA-02`), memory (`IR-02`), or another agent (`AOC-12`).
- **Input Trust Classification** operationalizes the risk map's core agentic control. `AOC-02` disclosed 124 email records because it did not distinguish an owner instruction from a non-owner's; `TA-01` is untrusted email content promoted to instruction.
- **Guardrail (Input) Verdict** is MUST because `TA-01` *defeated* a prompt-injection classifier. A classifier bypass is undetectable if verdicts are never logged.
- **Content Modality & Attachment Identity** is MUST because the corpus's obfuscation attacks are modality attacks, instructions in OCR'd images and base64 blobs (`AOC-12`), ~10 MB attachment floods (`AOC-05`). Text-only capture misses both.
- **ATLAS Technique Tag** is MUST *when a detection fires*. It is derived, not raw; its value is D-portability into ATT&CK-aligned tooling plus A-rollup.
- **Guardrail Modification Record is MUST, applying whenever an enforcement point or redaction pipeline rewrites rather than blocks.** It meets the [rubric](CoSAI-AI-Telemetry-RFC.md#51-tiers)'s interpretation clause: without it, **Model Input**, **Response** and a guardrail verdict of `modify` record content that was not what the model or the recipient saw, so the record is *actively wrong*. Its value is R first and D second. No corpus entry turns on the rewrite itself; the tier rests on the dependency, not on an instance.

### 4.3 Output Handling, Egress & Refusals (§1.3)

Output is where damage becomes irreversible, so these are **D-primary with the shortest time-to-value**. Response (**6**) and LLM Refusal (**7**) are the most-cited fields after Model Input. Output Egress Destination (**5**) converts a detection from *"something bad was generated"* into *"and here is where it went"*: the difference between blocking and reporting.

- **Output Egress Destination** would have caught `TA-01` and `TA-03` *before data left*: both smuggle data into an outbound URL on a trusted-looking domain. It also renders `AOC-03`, `AOC-11`, and `AOC-05` visible.
- **LLM Refusal** is an early-warning tripwire. `IR-01` is iterated reframing until a refusal flips; `AOC-12/13/14` are the mirror image, successful refusals whose telemetry documents attempted attacks even when blocked.
- **Citations** is MUST only for deployments that emit them, which is now the common RAG configuration. A citation is a *trusted* output component (`AML.T0067.000`), so three detections depend on it and none is reachable from response text alone: fabricated citations matching no retrieval, attacker-planted links (`TA-02`, `TA-01`), and suppression visible by comparing retrieved against cited (`IR-03`).
- **Observation / Thought is SHOULD**: high-value forensics for separating a compromised agent from a misconfigured one (`AOC-01`, `AOC-07`), but frequently unavailable from provider APIs and privacy-sensitive.

### 4.4 The Model & Model Serving (§1.4)

Four MUSTs, each ≥3 attacks and each D-primary. Model Name + Version is the supply-chain pivot (*which agents used the compromised model*) and is R-critical for scoping. Token Counts is the cheapest DoS and runaway-loop detector in the document (`AOC-04`'s ~60 k-token relay, `AOC-05`, `TA-10`) and costs nothing to emit. LLM Error fires precisely under adversarial conditions.

- **Inference Parameters** rest on a *denominator* argument rather than a tampering attack: "max-length output" (`TA-04`) and "anomalously large input" (`TA-10`) are the documented detection signatures, and neither is computable without `max_tokens` and the declared context window. They also give decoding configuration the integrity baseline §1.1 gives the system prompt. Capture per-call, per-request overrides are the attack.
- **Model Provenance / Signing is SHOULD** (supply-chain, ties to model-signing work and ODIS `software_hash`). **Pre-Forward-Pass State** and **Token Malformation** are MAY research-grade signals.
- **Provider / Endpoint Identity is MAY, and `TA-28` is the case that tests it.** `AOC-06` is a governance and availability signal rather than a discrete adversary technique, which makes the field Q- and A-dominant, and the D concern it is usually asked to carry, model substitution, belongs to Model Name + Version. `TA-28` is different: a backdoor using a provider's own API as its command-and-control channel, where the exfiltration destination is an endpoint the application legitimately calls. That is a detection argument rather than a governance one, and it is carried by **Output Egress Destination** (§1.3, MUST) recording the destination together with what left, not by provider identity alone, because a legitimate call and a C2 beacon share the provider. The field stays MAY because knowing *which* provider was called does not separate them; knowing what was sent does.

### 4.5 Tools & External Services (§1.5)

The highest-value **R** fields in the document and strong D besides. Tool Call I/O (**7**) and Tool Name (**6**) are the richest-evidenced here: without them a compromised agent's actions are invisible, and every destructive case in the corpus is reconstructed from them.

- **Tool Type / Trust Boundary** earns MUST via `AOC-14`, which tried to make the agent bypass the tool API and write to backend storage directly. "API-mediated only" is unenforceable unless telemetry distinguishes the two.
- **Execution Environment / Sandbox** is MUST because `TA-06` is characterized as model-emitted Python executed **unsandboxed**: the isolation posture *is* the finding. Two calls to the same code-execution tool, one containerized and one not, are otherwise the same event.
- **Tool Execution ID** makes *a result with no matching request* a queryable condition, and is the only way to correlate asynchronous tool calls. `AOC-01`'s false completion report is precisely a request/result mismatch.
- **Tool ACL / Required Scope stays SHOULD**: five attacks cite it, but every one presupposes meaningful delegation.
- **Tool Definition Digest is MUST.** `TA-15` is the grounding instance: a definition that is malicious as published, the injection carried in the tool's own description. That is why the digest is taken **at invocation** rather than at registration, and why it must cover the description and not only the argument and output schemas. The comparison against an approved baseline addresses the adjacent rug-pull pattern, `TA-14` mutating an approved configuration's launch command and `TA-16` shipping a malicious implementation under an adopted name; in both of those the *declared contract* is itself unchanged, so the detecting fields there are Capability-Set Change Event and MCP Server Identity & Primitive respectively. The modality gate then fell with MCP itself: the gate is third-party or dynamically-discovered tools, and an MCP `tools/list` exchange is dynamic discovery by construction.
- **MCP Server Identity & Primitive is MUST, on prevalence rather than on evidence.** The corpus carries six MCP incidents (`TA-11` to `TA-16`), four of which this field cites directly, so the evidence gate was cleared several times over; `TA-16` is the sharpest, because the server's declared contract never changed and only its published **version** did, so name alone would not have distinguished the safe release from the malicious one. What held the field at SHOULD was the modality gate, and that gate turns on MCP being at the **edge of current agentic practice** ([RFC §5.1](CoSAI-AI-Telemetry-RFC.md#51-tiers)). It is not. Six of the twenty-eight real-world corpus entries are MCP-mediated and all are from 2025 onward, and the ratio understates the point, because the remaining agentic entries are incidents of other kinds rather than counter-examples to MCP's prevalence; CoSAI's Workstream 4 devoted a paper to MCP security; OWASP publishes an MCP Top 10; and MITRE ATLAS has added `AML.T0109` AI Supply Chain Rug Pull and `AML.T0110` AI Agent Tool Poisoning, the latter with three sub-techniques (`.000` Definition and Instructions, `.001` Implementation, `.002` Runtime Response). A protocol acquires a dedicated top-ten list and a dedicated technique family once it is typical. **Server name and version are as cheap as Tool Name and should be adopted first.**
- **Tool Privacy Classification is MAY**: DLP and compliance governance metadata, A-dominant, and not modality-gated. Its D value is already carried by Tool ACL/Scope and Output Egress.

### 4.6 Memory (§1.6)

Persistent memory is the one component where an attack **outlives the session that planted it**, which is what earns MUST at comparatively low attack counts: a poisoned item silently shapes every future run, so the detection window is unbounded.

- **MINJA (`IR-02`)** poisons memory using only benign queries, the agent autonomously persists malicious reasoning. **AGENTPOISON (`IR-05`)** uses optimized triggers. `TA-18` is the production instance: injected ChatGPT memories persisted and were recalled in later conversations. None is detectable without Memory Write/Read plus **Provenance**.
- **Memory Provenance** is the field that exposes `AOC-10`: a "constitution" stored as an externally editable Gist, later edited to make the agent shut down peers and send unauthorized mail. The signal is *a context-shaping memory item resolving to a mutable, non-owner-controlled source.*
- **Memory Footprint** catches `AOC-05` (ever-growing per-non-owner file → mail-server DoS). At **2** attacks it clears the bar on the "especially useful for D" clause, not on count.
- **Memory Write Rationale is SHOULD**: the analogue of Tool Selection Rationale, and `IR-02` is the case demanding it: the content looks innocuous and the write unremarkable; the tell is the justification the agent gives itself.
- **Declared Memory Configuration is MAY.** The silently-raised-limit scenario is absent from the corpus, and its job (a baseline for Memory Footprint) can be met by hard-coding known limits.

### 4.7 Retrieval & Content (RAG) (§1.7)

Two fields, **5** and **4** attacks, both D-primary. RAG is the document's most-cited injection channel (`TA-01`, `TA-02`, `TA-09`, `IR-03`, `AOC-10` are all retrieval-mediated) and the two answer the halves a detection needs: *what came back*, and *where it came from and when it changed*.

- **Retrieval Event + Source/Provenance** connect "what was retrieved" to "what the model then did." Neither is sufficient alone.
- **Poison-RAG (`IR-03`)** manipulates item *metadata tags* rather than content bodies, which is why the integrity signal must cover metadata. **`TA-09`** plants hidden instructions in wikis and tickets, and recently-modified retrievable documents deserve scrutiny, hence freshness folds into provenance.
- **Declared Knowledge-Source Configuration is MAY**, on the same reasoning as its memory counterpart: a silently altered retrieval config or repointed index is not in the corpus, and `IR-03` poisons metadata, not search configuration.

### 4.8 Orchestration, Multi-Agent & Background Execution (§1.8)

The sharpest tiering judgment in the document, because multi-agent orchestration sits close to the SHOULD boundary by definition. The four MUSTs are the ones whose signal is **protocol-independent**: emittable by any orchestrator, with no A2A stack, delegation model, or agent registry.

- **Inter-Agent Message** is the substrate of cross-agent propagation: `AOC-04` (nine-day mutual-relay loop), `AOC-09` (capability transfer), `AOC-11` (mass broadcast), and `AOC-16`: the positive case, agents sharing risk signals.
- **Background / Scheduled Task** captures the corpus's most striking finding: agents spawning infinite shell loops and cron jobs with **no termination condition**, converting short-lived tasks into permanent infrastructure (`AOC-04`, `AOC-10`). With **Loop / Step-Count** it clears the bar on D value rather than attack count.
- **Task / Intent Declaration is SHOULD**: the goal-drift anchor; `AOC-04` shows agents inventing new goals beyond the requested task.
- **A2A Task Lifecycle and Peer Agent Card are SHOULD.** Their evidence is generic multi-agent incidents, not A2A-protocol incidents, `AOC-04/09/11` predate A2A entirely. Both are **MUST the moment A2A or agent cards are in play**; push-notification configuration in particular registers an attacker-settable egress channel.
- **Protocol Envelope Capture is MAY**: Q-dominant, duplicates interpreted fields, carries raw-content privacy weight, and is not modality-gated.

### 4.9 Identity, Delegation & Attribution (§1.9)

The archetype for the MUST/SHOULD split, and it survived the audit unchanged. Two fields are MUST because they apply to **every** deployment, including the simplest single-agent one.

- **Identities Used** (**7** attacks, tied for most-cited) is the accountability primitive: when an agent resets its own mail server (`AOC-01`), dumps 124 records (`AOC-02`), or mass-mails defamation (`AOC-11`), *which principal, which agent, which tool, which credential* is the first question of any response.
- **Verified vs Displayed Identity** is MUST on a precise D argument rather than volume. `AOC-08` shows same-channel spoofing *detected* (the agent checked an immutable user ID) and cross-channel spoofing *succeeding* where only a display name was available. The difference between those outcomes is entirely a telemetry difference.
- **Everything below is SHOULD by construction, not by weak evidence**: several carry 3 attacks, which on count alone would qualify. Each presupposes **delegated authority**: an originating principal distinct from the caller, a chain of prior hops, monotonically narrowing scopes, cryptographic attestation, or a revocation lifecycle. A deployment without cascaded delegation has nothing for them to describe. The corollary matters as much: a deployment that *does* run cascaded delegation should treat this entire section as mandatory on day one. SHOULD means "not universal," never "defer."
- **Trust-Domain Crossing & Delegation Depth** is the field that makes an **externally-operated** counterparty legible. ODIS treats `trust_domain` and `max_depth` as policy-engine inputs rather than telemetry, which is right only while a chain stays inside one domain. Once authority crosses out of the domain that issued it, or the acting agent sits several hops from the originating principal, both become detection-grade: `AOC-04`'s nine-day relay and `AOC-09`'s capability transfer are both depth phenomena, and `TA-11` is a domain-boundary failure. See [RFC §4.6](CoSAI-AI-Telemetry-RFC.md#46-record-your-boundary-not-their-internals).
- **Credential Minting & Scope-Narrowing** adds the *event* the surrounding fields only describe the state of. Forwarding a caller's inbound token is usually wrong (it is scoped for the agent, not the backend) so the **requested-vs-granted delta** is what makes a silently over-broad grant visible (`TA-08`).

### 4.10 Asset Inventory & Fleet Aggregates (§1.10)

One MUST in a section otherwise SHOULD and MAY, and the reason is categorical: every other field here describes a **state**, while **Capability-Set Change Event** describes a **transition**, and transitions are where attacks are visible.

- Grounded directly in `AOC-09`, where one agent teaches another to acquire a browser/download capability. The security event is the *acquisition*; the previous inference path ("tool-call spike + new Tool Name") fires only once the capability is exercised, and never at all for one acquired and held in reserve. Removal matters symmetrically: a guardrail tool or logging sink quietly dropped is a defence-evasion signal. It is also cheap where least expected to fire: a static capability set emits nothing.
- **Version and Repository / Software Ref are SHOULD** as supply-chain response primitives. **Version is the closest call here**: 2 attacks and genuine R value (CVE blast radius), held below MUST because that value is realized through a fleet-inventory process rather than per-event detection, and because it is inseparable in practice from the AgBOM cluster. The WG may reasonably promote it.
- **The AgBOM cluster is SHOULD**: it requires an inventory-emission capability most deployments lack. Within it: **Component Dependency Graph** is the complete answer to CVE blast radius, since `TA-06` is a vulnerability in a *framework* beneath the agent and reaching it requires transitive edges; **Inventory Attestation Signature** matters because an inventory a compromised agent can rewrite is worth little, with the limit that a signature proves who asserted the inventory, not that the assertion is true, which is §1.11's subject.

### 4.11 Observability-Plane Integrity (§1.11)

**Two MUSTs, one on one attack and one on a dependency; the rest analogical.** `TA-17` is the corpus's only instance of an attack on the observability plane, and it is a mode this section did not anticipate: not starvation, disablement, or suppression, but **redirection**. An authenticated caller enabled trace configuration on another tenant's application and pointed it at infrastructure they controlled, turning the telemetry path itself into the exfiltration channel. **Instrumentation Coverage / Hook Attestation** is MUST on that instance under the single-attack clause of the [rubric](CoSAI-AI-Telemetry-RFC.md#51-tiers): it is D-dominant, it is not modality-gated (every deployment has an instrumentation configuration), and recording *where each hook reports* is what separates a hijacked plane from a healthy one. **Enforcement-Point Availability & Failure Mode** is MUST under the rubric's interpretation clause (below). The remaining fields stay SHOULD, grounded *analogically*: the corpus establishes the capability exists (`TA-10` proves resource pressure against AI infrastructure is achievable; `TA-01` proves the payoff of defeating a classifier) without containing an instance.

That absence is itself a finding, and probably a **collection artifact**: attacks on telemetry are under-reported precisely because the telemetry that would reveal them is what was attacked. `TA-17` narrows that absence without dissolving it: starvation, disablement and suppression remain uncatalogued, and a survey of all **72** MITRE ATLAS case studies at `v2026.08` returns no instance of any of the three. Two entries come closest and neither closes the gap. `AML.CS0050` is an adversary modifying an agent's configuration to **disable the user-confirmation step** before escaping its container, which is disablement of an *enforcement* control rather than of telemetry, and bears on §1.12's **Human Approval / Elicitation Event** more than on this section. `AML.CS0067` records CI **logs** as an exfiltration channel, a second instance of the redirection mode `TA-17` supplies rather than a new one. Two further developments establish recognition without supplying evidence: CoSAI's MCP Security paper names **Invisible Agent Activity** (agents operating covertly while mimicking valid workflows) as an MCP threat class, and the CoSAI Risk Map carries `riskAuditTrailTampering` with an ATT&CK anchor (*Disable or Modify Tools*, T1685). Neither is a catalogued incident, so neither satisfies the evidence rule. This is the section most likely to be re-tiered upward, and [RFC §5.1](CoSAI-AI-Telemetry-RFC.md#51-tiers) is what determines how: the instance that closes this gap need not be adversarial. A collector documented to have silently dropped events, or an enforcement point documented to have failed open unnoticed, is a documented instance of the same failure mode, and it is a far likelier thing to find in the literature than an adversary whose first act destroyed the record of it.

- **Enforcement-Point Availability & Failure Mode is MUST** on the interpretation clause, not on an instance: a verdict that never arrived and a verdict of `allow` are indistinguishable in the log, so without it the guardrail verdicts and the **Authorization Decision Record** cannot be read, and the control plane is a single point of silent failure. Deployments choose fail-open or fail-closed for availability reasons; **this document requires that the choice and the outcome be recorded**, and does not recommend either posture.
- **Instrumentation Coverage** resolves the ambiguity undermining every absence-based detection in the document; no refusal, no termination condition, no matching request are each only interpretable if the relevant hook was instrumented.
- **Event Sequence Continuity** is the minimum defence against selective suppression by a compromised agent: sequence numbers make omission visible as a gap rather than invisible as silence.
- **Policy Reason Code is MAY**: A-dominant reporting convenience, not modality-gated, and the underlying decision is already captured by Guardrail Verdict and classified by the ATLAS tag.

### 4.12 Policy Enforcement & Mediation (§1.12)

Two of six are MUST, and both are universal rather than modality-gated.

- **Authorization Decision Record** fills a structural hole the rest of the field set has by construction. The document logged what a *content classifier* concluded (Guardrail Verdict, §§1.2 to 1.3) and what authority a tool *requires* (Tool ACL/Scope, §1.5), but never what the authorization layer **decided**, on which rule, or why, so a denied operation and a never-attempted one were indistinguishable. Four attacks turn on that record: `AOC-02` (non-owner compliance), `AOC-08` (privileged action after spoof), `AOC-10` (injected authority), and `TA-08` (individually-authorized calls escalating in aggregate; visible only if each link's decision and rule are recorded). D and R jointly.
- **Attribute Source / Trusted-Provenance Marking** is the zero-trust principle applied to telemetry itself, and it earns MUST because it determines whether the rest of the field set can be believed. The document already applies the idea once (Verified vs Displayed Identity (§1.9)) and the generalization is that identity is not the only attribute an agent can assert. Autonomy Level, Task Declaration, System Prompt, and every reasoning field are agent-supplied, and `AOC-01` is the corpus's proof that agents *do* report falsely: it declared a secret deleted while the data remained recoverable. Cost is an enum per attribute group, not per event.
- **Session Taint Labels is SHOULD**, and is a genuinely different mechanism from §1.2's Input Trust Classification: that classifies a segment of one payload, while taint is **state accumulating across a session** that survives into operations whose own content is clean. That distinction is the whole attack in `TA-01` and `TA-02`, where the exfiltrating request is innocuous in isolation. Of everything in SHOULD this has the highest D value per unit of effort.
- **Human Approval / Elicitation is SHOULD** and covers the control the corpus most often shows *missing*: `AOC-01`, `AOC-07`, and `AOC-11` are all irreversible actions taken without human authorization. `TA-23` is the sharper case, because the gate was present and was **switched off as configuration** rather than argued past: the record that matters is not only the approval but the change to whether approval was required at all, which is why **Capability-Set Change Event** (§1.10, MUST) and this field are read together. **MUST wherever irreversible or high-impact actions are reachable.** Two sub-signals matter: approver identity must come from the identity provider, not the agent's claim; and approval scope must be re-validated against the arguments actually presented, or one sign-off can be replayed against a larger action.
- **Mediation Coverage & Bypass Path is SHOULD**: the enforcement counterpart to §1.11's Instrumentation Coverage. §1.11 asks *is the telemetry complete?*; this asks *is the enforcement unbypassable?* `AOC-14` is precisely this attack. A control that can be routed around is not a control.
- **Backend / Route Restriction is SHOULD.** Paired with taint it is a D signal; standing alone it is closer to A (data-residency evidence) and Q.

---

---

## References

### Real-world attack primary sources

One source per real-world attack vector, each mapping to a `TA-` ID in [§3.2](#32-real-world-attack-vectors). Ref 4 is the lead case study; refs 5 to 13 are the source citations for `TA-02…10`.

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
14. **[TA-11]** Asana MCP server cross-tenant data exposure (Jun 2025); experimental MCP server launched 1 May 2025; tenant-isolation flaw found 4 Jun, exposure window 5 to 17 Jun; no evidence of exploitation. <https://www.theregister.com/2025/06/18/asana_mcp_server_bug/>
15. **[TA-12]** Supabase MCP private-table exposure via stored prompt injection. General Analysis. <https://generalanalysis.com/blog/supabase-mcp-blog> · analysis applying the **"lethal trifecta"** framing (private data + untrusted content + external communication): S. Willison, 6 Jul 2025, <https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/> · vendor response: <https://supabase.com/blog/defense-in-depth-mcp>
16. **[TA-13]** AI Engine (WordPress) MCP privilege escalation, **CVE-2025-5071** (CVSS 8.8, v2.8.0 to 2.8.3, disclosed 18 Jun 2025). <https://www.cve.org/CVERecord?id=CVE-2025-5071> · a second, unauthenticated flaw on the same MCP surface followed: **CVE-2025-11749** (CVSS 9.8, fixed in 3.1.4), <https://wpscan.com/vulnerability/b0d583a2-14e1-40bc-b875-3b48e992b803/> · <https://github.com/advisories/GHSA-q6x7-qqgq-h832>
17. **[TA-14]** MCPoison, Cursor MCP configuration trust bypass, **CVE-2025-54136** (CVSS 7.2; affects ≤ 1.2.4, fixed in 1.3 on 29 July 2025). Check Point Research; disclosed to the vendor 16 July 2025, published 5 August 2025. <https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/>
18. **[TA-15]** MCP tool poisoning via tool-description injection. Invariant Labs, April 2025. MITRE ATLAS case study **`AML.CS0054`**. <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>
19. **[TA-16]** `postmark-mcp` malicious npm package (first malicious MCP server found in the wild); malicious from v1.0.16, removed from npm 25 September 2025. Koi Security. MITRE ATLAS case study **`AML.CS0053`**. <https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft>
20. **[TA-17]** DifyTap, four vulnerabilities in Dify enabling cross-tenant data exposure; **CVE-2026-41947** (CVSS 9.1) trace-configuration authorization bypass, with CVE-2026-41948/-41949/-41950. Zafran Security (Ido Shani, Gal Zaban), 22 June 2026; fixed in 1.14.2. <https://thehackernews.com/2026/06/researchers-detail-difytap-flaws-in.html>
21. **[TA-18]** ChatGPT persistent memory poisoning via indirect prompt injection. J. Rehberger, *Embrace The Red*. MITRE ATLAS case study **`AML.CS0040`**. <https://embracethered.com/blog/posts/2024/chatgpt-hacking-memories/>
22. **[TA-19]** Google Gemini: planting instructions for delayed automatic tool invocation. J. Rehberger, *Embrace The Red*. MITRE ATLAS case study **`AML.CS0038`**. <https://embracethered.com/blog/posts/2024/llm-context-pollution-and-delayed-automated-tool-invocation/>

<!-- list break: reference numbers are not contiguous -->

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

24. **CoSAI MCP Security**: Coalition for Secure AI, Workstream 4 (Secure Design Patterns for Agentic Systems): *Model Context Protocol (MCP) Security*, approved 8 January 2026. Twelve threat categories (MCP-T1…T12), ~40 threats. <https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf>

<!-- list break: reference numbers are not contiguous -->

29. **MITRE ATT&CK**: adversary tactics & techniques knowledge base (ATLAS-aligned). MITRE. <https://attack.mitre.org/>

<!-- list break: reference numbers are not contiguous -->

45. **RFC 8693**: OAuth 2.0 Token Exchange (on-behalf-of delegation). <https://www.rfc-editor.org/rfc/rfc8693>

<!-- list break: reference numbers are not contiguous -->

49. **Cedar**: authorization policy language. <https://www.cedarpolicy.com/> · **Open Policy Agent (Rego)**. <https://www.openpolicyagent.org/>
50. **SOC alert-volume measurement**: Yang, L., Chen, Z., Wang, C., Zhang, Z., Booma, S., Cao, P., Adam, C., Withers, A., Kalbarczyk, Z. T., Iyer, R. K. & Wang, G. *True Attacks, Attack Attempts, or Benign Triggers? An Empirical Measurement of Network Alerts in a Security Operations Center.* USENIX Security 2024. <https://www.usenix.org/conference/usenixsecurity24/presentation/yang-limin>
