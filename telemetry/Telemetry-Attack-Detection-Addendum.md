# Telemetry for AI Security: Attack Detection Addendum {**Working Draft v0.6**}

**Status:** Request for Comments, revision 0.6
**Origin:** Coalition for Secure AI (CoSAI), Workstream 2 (Defenders)
**Companion to:** [Telemetry for AI Security](CoSAI-AI-Telemetry-RFC.md) (cited as RFC); see also the [Cross-Mapping Addendum](Telemetry-Cross-Mapping-Addendum.md) (cited as XM).
**Normative status:** The capture definition that opens each field entry in [§1](#1-field-tables) is normative, by reference from [RFC §6](CoSAI-AI-Telemetry-RFC.md#6-field-catalog). The rest of this addendum is informative.

---

This addendum holds the evidence behind the RFC's field catalog and the detections the fields make possible. It is generated from the data in `build-telemetry/data/`, and the tables of [RFC §6](CoSAI-AI-Telemetry-RFC.md#6-field-catalog) are a projection of it.

Five kinds of record appear here, and each links to the others. **Attacks** are documented instances: executed attacks, resisted attempts and failures, each traceable to a primary source ([§3](#3-attack--incident-inventory)). An attack's row cites that source and names the CoSAI Risk Map [[23]](#standards--frameworks) **risks** it realizes and the **components** it involved. It also lists the fields whose records the instance contains.

**Fields** are the telemetry ([§1](#1-field-tables)). Each is emitted by a Risk Map component, and its entry names the Risk Map **controls** it helps implement. A field's tier follows from the attacks that ground it: two independent documented instances, or a MUST field that cannot be read without it ([RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers)). An attack that motivates a field without containing its value grounds it *analogically*, which does not count toward a tier.

**Correlation patterns** are the detections ([§2](#2-correlation-patterns)). Each reads a set of fields and catches an attack when that attack's instance contains every field it reads. Every attack is caught by a pattern or records why none applies.

The Risk Map supplies the frame: components say where telemetry is emitted, risks say what an attack was, and controls say what a field supports. The corpus supplies the evidence, and the patterns show that the fields, combined, detect what the corpus contains. [§4](#4-tiering-rationale) holds the tiering rules that apply across fields.

Fields alone are not detection. Feed them to layered analytics, and re-evaluate detectors as attacks vary. When a pattern fires, stamp the event with its MITRE ATLAS [[1]](#primary-sources-attack-corpus--taxonomy) technique ([§3.6](#36-attack-inventory--mitre-atlas-technique-mapping)), so that AI alerts correlate with the rest of the SOC's ATT&CK-aligned tooling [[29]](#standards--frameworks).

## 1. Field Tables

One table per implementation step of [RFC §6](CoSAI-AI-Telemetry-RFC.md#6-field-catalog), in the same order and with the same rows. The columns:

- **Field**: conceptual field name (implementation-neutral).
- **Tier**: MUST, SHOULD or MAY ([RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers)).
- **Role**: what the value is: an identifier, content, an outcome, a label, a descriptor, a measure, or provenance. Content fields carry the content-hash obligation ([RFC §5.3](CoSAI-AI-Telemetry-RFC.md#53-content-hashing)).
- **Origin**: where the value comes from. *Observed*: witnessed by a component the deployment operates, such as a gateway, runtime, tool host or identity provider. *Declared*: set by the deployment's configuration or by an authority it relies on, such as a registry or identity provider. *Asserted*: supplied by an agent, model or counterparty about itself, and self-asserted in the sense of [RFC §4.4](CoSAI-AI-Telemetry-RFC.md#44-the-agent-might-be-lying). *Derived*: computed by a detector or analytics from other records. Origin is fixed per field; whether a particular value was verified is recorded per value by [Attribute Source / Trusted-Provenance Marking](#f-attribute-source-trusted-provenance-marking).
- **What it records**: the one-line definition the RFC catalog carries.
- **Emitted by**: the CoSAI Risk Map component that produces the field.
- **Grounding attacks**: attack IDs that establish the need (see [§3](#3-attack--incident-inventory)). An ID in italics grounds the field analogically: the attack motivates it, but the documented instance does not contain what the field records ([RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers)).

After each table, an entry per field defines what to capture, generally enough to bind to any framework, then gives the basis of its tier: the number of documented instances, the MUST fields it is needed to read, or the modality it serves. Where the tier is not self-evident the entry gives the reasoning. Last, it lists the [correlation patterns](#2-correlation-patterns) whose conditions read the field, and the CoSAI Risk Map [[23]](#standards--frameworks) controls the field helps implement. The field links in RFC §6 point at these entries.

### 1.1 Identifiers, trace context and model identity

These fields establish what is running and where: the asset inventory of the AI attack surface, and the trace anchor for every incident. The model and serving fields add supply-chain integrity, resource and denial-of-service signals, and pre-inference integrity.

<!-- BEGIN GENERATED: fields 6.1 -->
| Field | Tier | Role | Origin | What it records | Emitted by | Grounding attacks |
| :------------ | :---- | :---------- | :-------- | :------------------------------------- | :-------------------- | :------------ |
| **Agent Name** | MUST | identifier | declared | Logical name or type of the agent; exposes off-inventory agents. | `componentReasoningCore` | *[`TA-01`](#a-ta-01)*, [`TA-05`](#a-ta-05), [`TA-31`](#a-ta-31), *[`AOC-08`](#a-aoc-08)*, *[`AOC-10`](#a-aoc-10)* |
| **Agent (Runtime) Instance ID** | MUST | identifier | observed | The running instance an event belongs to, for per-instance quarantine. | `componentReasoningCore` | [`AOC-04`](#a-aoc-04), *[`AOC-05`](#a-aoc-05)*, *[`AOC-08`](#a-aoc-08)* |
| **Workflow / Run ID** | MUST | identifier | observed | Groups one multi-step run or sub-agent tree into one execution. | `componentReasoningCore` | [`AOC-04`](#a-aoc-04), *[`AOC-09`](#a-aoc-09)*, *[`AOC-10`](#a-aoc-10)* |
| **Session / Turn / Step IDs** **[AOS]** | MUST | identifier | observed | The session, turn and step beneath a run, locating where behavior changed. | `componentApplication`, `componentReasoningCore` | [`TA-07`](#a-ta-07), [`TA-08`](#a-ta-08), [`TA-19`](#a-ta-19), [`AOC-03`](#a-aoc-03), [`AOC-07`](#a-aoc-07) |
| **Trigger Type & Source Event** **[AOS]** | MUST | label | observed | User-initiated or autonomous, and for autonomous runs the originating event. | `componentReasoningCore` | [`TA-01`](#a-ta-01), [`TA-24`](#a-ta-24), [`TA-25`](#a-ta-25), [`TA-27`](#a-ta-27), [`AOC-04`](#a-aoc-04), *[`AOC-10`](#a-aoc-10)*, *[`AOC-12`](#a-aoc-12)* |
| **Action Type** | MUST | label | observed | LLM call, tool call, memory operation or message send. | `componentReasoningCore` | [`TA-02`](#a-ta-02), [`TA-06`](#a-ta-06), [`TA-08`](#a-ta-08), [`TA-26`](#a-ta-26), *[`IR-01`](#a-ir-01)*, [`AOC-01`](#a-aoc-01), [`AOC-02`](#a-aoc-02) |
| **Execution Status** | MUST | outcome | observed | Outcome and duration of an operation or turn. | `componentReasoningCore` | [`TA-03`](#a-ta-03), [`TA-04`](#a-ta-04), [`TA-10`](#a-ta-10), *[`IR-04`](#a-ir-04)*, *[`AOC-05`](#a-aoc-05)*, [`AOC-06`](#a-aoc-06) |
| **Surface / App** | MUST | label | observed | Entry point: CLI, web, IDE, email, chat, scheduler; internal or external. | `componentApplication` | [`TA-01`](#a-ta-01), [`TA-05`](#a-ta-05), [`AOC-08`](#a-aoc-08), *[`AOC-10`](#a-aoc-10)* |
| **System Prompt / Instruction Config** | MUST | content | asserted | Instruction configuration in force for the call. Self-asserted. | `componentAgentSystemInstruction` | [`TA-07`](#a-ta-07), [`TA-21`](#a-ta-21), [`TA-40`](#a-ta-40), *[`AOC-08`](#a-aoc-08)*, [`AOC-10`](#a-aoc-10) |
| **Model Name + Version** | MUST | identifier | observed | Model and version that processed the request. | `componentModelServing` | [`TA-04`](#a-ta-04), *[`TA-06`](#a-ta-06)*, [`TA-20`](#a-ta-20), *[`TA-34`](#a-ta-34)*, *[`IR-04`](#a-ir-04)*, [`AOC-06`](#a-aoc-06) |
| **Inference Parameters** **[AOS]** | MUST | descriptor | declared | Decoding parameters and declared context window in force for the call; the denominator for max-length-output and oversized-input detections. | `componentModelServing` | [`TA-04`](#a-ta-04), [`TA-10`](#a-ta-10), *[`AOC-04`](#a-aoc-04)*, *[`AOC-06`](#a-aoc-06)* |
| **Input / Output Token Counts** | MUST | measure | observed | Per-call token usage, which feeds the Resource-Consumption Aggregate budget check. | `componentModelServing` | [`TA-04`](#a-ta-04), [`TA-10`](#a-ta-10), [`TA-20`](#a-ta-20), [`AOC-04`](#a-aoc-04), *[`AOC-05`](#a-aoc-05)* |
| **LLM Error / Exception** | MUST | outcome | observed | Errors under adversarial conditions and provider-side silent failures. | `componentModelServing` | [`TA-10`](#a-ta-10), *[`TA-38`](#a-ta-38)*, *[`IR-01`](#a-ir-01)*, [`AOC-06`](#a-aoc-06) |
| **Trace Context (propagated)** **[AOS]** | MUST | identifier | observed | W3C trace context carried across every agent and tool hop. | every hop | *[`TA-01`](#a-ta-01)*, [`TA-08`](#a-ta-08), [`TA-37`](#a-ta-37), [`AOC-04`](#a-aoc-04), [`AOC-09`](#a-aoc-09) |
| **Stop Reason** | MUST | outcome | observed | Why a completion ended: end of turn, token limit, tool use, cancellation, content filter. | `componentReasoningCore` | [`TA-04`](#a-ta-04), [`TA-10`](#a-ta-10), *[`TA-38`](#a-ta-38)*, *[`IR-01`](#a-ir-01)*, [`AOC-06`](#a-aoc-06) |
| **Autonomy Level** | SHOULD | label | asserted | Declared independence level the run is authorized for. Self-asserted. Modality: autonomous action. | `componentReasoningCore` | [`AOC-01`](#a-aoc-01), *[`AOC-04`](#a-aoc-04)*, [`AOC-07`](#a-aoc-07) |
| **Model Provenance / Signing / Hash** | SHOULD | provenance | declared | Signed digest or provenance of the served model artifact. Modality: supply-chain provenance. | `componentModelServing`, `componentModelRegistry` | *[`TA-34`](#a-ta-34)*, *[`IR-04`](#a-ir-04)* |
| **Organization / Tenant ID** **[AOS]** | SHOULD | identifier | declared | Owning tenant of the agent, the session and the invoking user. Modality: multi-tenancy. | agent, session and user records | *[`TA-05`](#a-ta-05)*, [`TA-11`](#a-ta-11), [`TA-17`](#a-ta-17), [`TA-22`](#a-ta-22) |
| **Provider / Endpoint Identity** | MAY | identifier | observed | Which provider or endpoint served the call. | `componentModelServing` | [`TA-20`](#a-ta-20), [`TA-28`](#a-ta-28), [`AOC-06`](#a-aoc-06) |
| **Pre-Forward-Pass State Digest/Vector** | MAY | content | derived | Digest of the exact inputs to a forward pass, for replay and drift detection. | `componentTheModel` | *[`IR-02`](#a-ir-02)*, *[`AOC-10`](#a-aoc-10)* |
| **Token Malformation / Context-Corruption Indicator** | MAY | label | derived | Token-entropy anomalies correlated with confabulation. | `componentTheModel` | *[`IR-02`](#a-ir-02)* |

**Field entries.**

<a id="f-agent-name"></a>**Agent Name.** Logical name/type of the agent (e.g. "Deep Research agent"). Detects off-inventory / "shadow" agents.

*Tier:* MUST, on 2 documented instances. Rests on [`TA-05`](#a-ta-05) (an agent nobody inventoried) and [`TA-31`](#a-ta-31) (one name bound to two peers, so requests reach the wrong one); both are found by comparing a name against what it should resolve to. *Read by:* [One agent name bound to two peers](#p-agent-name-collision) and [Sensitive input to an off-inventory AI service](#p-sensitive-input-to-off-inventory-ai). *Risk Map controls:* `controlAgentInventoryManagement`, `controlAgentObservability`.

<a id="f-agent-runtime-instance-id"></a>**Agent (Runtime) Instance ID.** UUID pinning an event to one running instance, not just the type. Enables per-instance kill/quarantine.

*Tier:* MUST, needed to read [Identities Used (per hop)](#f-identities-used-per-hop), [Source host / IP + request metadata](#f-source-host-ip-request-metadata), [Capability-Set Change Event](#f-capability-set-change-event) and [Instrumentation Coverage / Hook Status](#f-instrumentation-coverage-hook-attestation). One identity across a fleet is otherwise ambiguous between sibling instances and a stolen credential, and capability sets and hook state are per process. *Read by:* [Obfuscated content in the instruction configuration](#p-obfuscated-instruction-config), [New tool name with a rise in tool calls](#p-new-tool-with-call-spike), [Background task with no end condition](#p-background-task-without-end), [Capability added soon after an inter-agent message](#p-capability-after-inter-agent-message), [Capability or configuration change with no approval](#p-unapproved-capability-change) and [Hook coverage or destination changes mid-run](#p-hook-coverage-changed). *Risk Map controls:* `controlAgentInventoryManagement`, `controlAgentObservability`.

<a id="f-workflow-run-id"></a>**Workflow / Run ID.** Groups all activity of one multi-step run or sub-agent tree into a single traceable execution.

*Tier:* MUST, needed to read [Loop / Step-Count Signal](#f-loop-step-count-signal) and [Resource-Consumption Aggregate](#f-resource-consumption-aggregate). Both are defined per run. *Read by:* [Individually authorized calls chained across identities](#p-authorized-calls-chained-across-identities), [Inter-agent relay with no terminating step](#p-inter-agent-relay-loop), [Long autonomous run against many external targets](#p-autonomous-run-against-external-targets), [Untrusted attachment, then a destructive tool call](#p-untrusted-attachment-to-destructive-tool), [Autonomous trigger, untrusted content, new egress](#p-zero-click-to-new-egress) and [Task callback registered to an undeclared destination](#p-callback-to-undeclared-destination). *Risk Map controls:* `controlAgentInventoryManagement`, `controlAgentObservability`.

<a id="f-session-turn-step-ids"></a>**Session / Turn / Step IDs.** The three-level execution hierarchy *beneath* the run: `session_id` (the conversation/engagement), `turn_id` (one request→response cycle), `step_id` (one action within a turn). Lets a detection point at *which* turn behavior changed, not just which run.

*Tier:* MUST, on 5 documented instances. *Read by:* [Pre-filled prompt telling the assistant to remember a source](#p-prefilled-prompt-to-remember), [Instructions followed from an external retrieved item](#p-retrieved-instructions-followed), [Instructions followed from an untrusted-data segment](#p-untrusted-data-instructions-followed), [Operation duration off baseline for its token count](#p-duration-per-token-off-baseline), [Privileged action authorized on a displayed identity](#p-privileged-action-on-displayed-identity), [Refusals, then a completion, in one session](#p-refusals-then-completion), [Repeated refusals](#p-repeated-refusals), [Untrusted content acted on in a later turn](#p-untrusted-content-acted-on-later), [Citation with no matching retrieval](#p-citation-without-retrieval), [Output link carrying session data](#p-output-link-carrying-data), [Response reproduces the system prompt](#p-system-prompt-reproduced), [Untrusted input, then a tool call, then egress to a new destination](#p-untrusted-input-to-new-egress), [Egress under accumulated session taint](#p-egress-under-session-taint), [Enforcement point unreached, operation proceeds](#p-enforcement-point-fail-open), [Self-asserted attribute contradicts the authority](#p-self-asserted-attribute-contradicted) and [Gap in the event sequence](#p-event-sequence-gap). *Risk Map controls:* `controlAgentInventoryManagement`, `controlAgentObservability`.

<a id="f-trigger-type-source-event"></a>**Trigger Type & Source Event.** Whether this run was **user-initiated or autonomous**, and for autonomous runs the originating event (inbound email, chat message, webhook, schedule). Distinct from Surface / App, which records the *channel*, not who or what started the run.

*Tier:* MUST, on 5 documented instances. Zero-click is a telemetry category. [`TA-01`](#a-ta-01) starts an entire run from one inbound email with no human in the loop. Surface / App would record "email" for both that and an ordinary request; the autonomous flag is what separates them. *Read by:* [Autonomous trigger, untrusted content, new egress](#p-zero-click-to-new-egress). *Risk Map controls:* `controlAgentInventoryManagement`, `controlAgentObservability`.

<a id="f-action-type"></a>**Action Type.** Distinguishes LLM-call vs tool-call vs memory-op vs message-send, the "think → act" boundary.

*Tier:* MUST, on 6 documented instances. Marks the think→act boundary where [`AOC-01`](#a-aoc-01) and [`AOC-02`](#a-aoc-02) did their damage. No pattern lists it as a condition, because each names the operation's own field, such as **Tool Call I/O**. Action Type is what lets a detection select the same kind of operation across components ([§2](#2-correlation-patterns)). *Risk Map controls:* `controlAgentInventoryManagement`, `controlAgentObservability`.

<a id="f-execution-status"></a>**Execution Status.** Outcome of the operation or turn (complete / error / exit / aborted) + duration. Spikes/timeouts reveal probing, DoS, or mass failure. Distinct from **Stop Reason** below, which records why a *completion* ended.

*Tier:* MUST, on 4 documented instances. *Read by:* [Operation duration off baseline for its token count](#p-duration-per-token-off-baseline). *Risk Map controls:* `controlAgentInventoryManagement`, `controlAgentObservability`.

<a id="f-surface-app"></a>**Surface / App.** Entry point (CLI, web, IDE, email, chat channel, cron/heartbeat; internal vs external service). Detects access from unexpected surfaces.

*Tier:* MUST, on 3 documented instances. *Read by:* [Sensitive input to an off-inventory AI service](#p-sensitive-input-to-off-inventory-ai).

<a id="f-system-prompt-instruction-config"></a>**System Prompt / Instruction Config.** The system/instruction configuration in force for the call. Detects unauthorized weakening and, by comparison against the response, system-prompt leakage/extraction.

*Tier:* MUST, on 4 documented instances. Both a config-integrity baseline and the reference against which extraction is detected: [`TA-07`](#a-ta-07) succeeds when the response reproduces it. *Read by:* [Obfuscated content in the instruction configuration](#p-obfuscated-instruction-config) and [Response reproduces the system prompt](#p-system-prompt-reproduced).

<a id="f-model-name-version"></a>**Model Name + Version.** Model and version processing the request. "Which agents used the compromised model?"; pins a model-specific vulnerability for patching.

*Tier:* MUST, on 3 documented instances. The supply-chain pivot, and R-critical for scoping. *Read by:* [Model change, or error and stop-reason spike, for one provider](#p-model-or-provider-anomaly) and [Consumption spike and model enumeration under one identity](#p-consumption-spike-with-model-enumeration). *Risk Map controls:* `controlModelAndDataIntegrityManagement`, `controlMessageAndPayloadResourceLimits`.

<a id="f-inference-parameters"></a>**Inference Parameters.** The decoding/config parameters in force for the call: `temperature`, `top_p`/`top_k`, `max_tokens`, `stop` sequences, `seed`, and the **declared context-window size**. The runtime half of the configuration-integrity baseline that **System Prompt / Instruction Config** covers for instructions.

*Tier:* MUST, on 2 documented instances. Rests on a *denominator* argument rather than a tampering attack: "max-length output" ([`TA-04`](#a-ta-04)) and "anomalously large input" ([`TA-10`](#a-ta-10)) are the documented detection signatures, and neither is computable without `max_tokens` and the declared context window. It also gives decoding configuration the integrity baseline the system prompt has. Capture it per call: per-request overrides are the attack. *Read by:* [Inference parameters off the approved baseline](#p-inference-parameters-off-baseline) and [Input near the context limit ending on a limit or error](#p-context-limit-abuse). *Risk Map controls:* `controlModelAndDataIntegrityManagement`, `controlMessageAndPayloadResourceLimits`.

<a id="f-input-output-token-counts"></a>**Input / Output Token Counts.** Per-call token usage, the primary resource-abuse and runaway-loop signal; max-length outputs flag extraction/DoS.

*Tier:* MUST, on 4 documented instances. The cheapest DoS and runaway-loop detector in the document ([`AOC-04`](#a-aoc-04)'s ~60 k-token relay, [`AOC-05`](#a-aoc-05), [`TA-10`](#a-ta-10)), and it costs nothing to emit. *Read by:* [Input near the context limit ending on a limit or error](#p-context-limit-abuse) and [Operation duration off baseline for its token count](#p-duration-per-token-off-baseline). *Risk Map controls:* `controlModelAndDataIntegrityManagement`, `controlMessageAndPayloadResourceLimits`.

<a id="f-llm-error-exception"></a>**LLM Error / Exception.** Errors that occur under adversarial conditions (overflow, malformed encoding, context exhaustion); provider-side silent failures.

*Tier:* MUST, on 2 documented instances. *Read by:* [Model change, or error and stop-reason spike, for one provider](#p-model-or-provider-anomaly). *Risk Map controls:* `controlModelAndDataIntegrityManagement`, `controlMessageAndPayloadResourceLimits`.

<a id="f-trace-context-propagated"></a>**Trace Context (propagated).** W3C `traceparent` / `trace_id` + `span_id` **propagated across every agent→tool→agent hop**, including MCP [[39]](#standards--frameworks) and A2A [[40]](#standards--frameworks) calls. Without propagation, multi-agent activity cannot be reassembled into one trace. Records the baggage members received with the context, by key. A member that names a telemetry destination or credential is attacker-controllable input, not configuration.

*Tier:* MUST, on 4 documented instances. *Read by:* [Individually authorized calls chained across identities](#p-authorized-calls-chained-across-identities), [Inter-agent relay with no terminating step](#p-inter-agent-relay-loop), [Input content re-emitted to another agent or store](#p-input-reemitted) and [Untrusted input, then a tool call, then egress to a new destination](#p-untrusted-input-to-new-egress).

<a id="f-stop-reason"></a>**Stop Reason.** Normalized reason a model completion ended: end of turn, token limit, tool use pending, session stop (caller canceled or disconnected), content filter. Separates a truncation from a clean stop and a guardrail kill from a crash; a `content_filter` stop is the completion-side view of a guardrail block (§1.2).

*Tier:* MUST, on 3 documented instances. Without it a **Response / Model Output** cut short by a provider content filter or a token limit reads the same as one that finished, so it also passes the dependency test of [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers). A deployment's own guardrail verdict does not record the provider's filter, and token counts cannot infer it. Every major provider API returns a completion's stop reason, so it is implementable wherever a model is called. *Read by:* [Input near the context limit ending on a limit or error](#p-context-limit-abuse) and [Model change, or error and stop-reason spike, for one provider](#p-model-or-provider-anomaly). *Risk Map controls:* `controlAgentInventoryManagement`, `controlAgentObservability`.

<a id="f-autonomy-level"></a>**Autonomy Level.** Declared independence level (e.g. L1 to L5) the run is authorized to operate at; sets oversight/delegation limits.

*Tier:* SHOULD, modality: autonomous action. The oversight dial for delegated action. The corpus repeatedly shows agents operating *above* their intended autonomy ([`AOC-04`](#a-aoc-04), [`AOC-01`](#a-aoc-01), [`AOC-07`](#a-aoc-07)); logging the claimed level is what makes that detectable. *Risk Map controls:* `controlAgentInventoryManagement`, `controlAgentObservability`.

<a id="f-model-provenance-signing-hash"></a>**Model Provenance / Signing / Hash.** Signed digest / provenance of the served model artifact (supply-chain provenance). Where the deployment trains or fine-tunes the model, the provenance includes the training run and the digest of the dataset version it used.

*Tier:* SHOULD, modality: supply-chain provenance. A supply-chain primitive; ties to model-signing work and ODIS [[26]](#standards--frameworks) `software_hash`. *Risk Map controls:* `controlModelAndDataIntegrityManagement`, `controlModelRegistryIntegrity`, `controlMessageAndPayloadResourceLimits`.

<a id="f-organization-tenant-id"></a>**Organization / Tenant ID.** The tenant/organization owning the agent, the session, and the invoking user, recorded on each. The primitive for detecting cross-tenant leakage and credential propagation.

*Tier:* SHOULD, modality: multi-tenancy. Held by the modality gate, not the evidence gate. Its instances ([`TA-11`](#a-ta-11), [`TA-17`](#a-ta-17), [`TA-22`](#a-ta-22)) clear the evidence bar; what holds it below MUST is that multi-tenant hosting is a deployment modality, and a single-tenant deployment has nothing for the field to describe. **MUST for any multi-tenant deployment.** The two cross-tenant entries differ in a way worth recording: [`TA-11`](#a-ta-11) involved **no attacker**, the boundary failed unaided, which under [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers) is a documented instance of the failure mode and not a lesser kind of evidence, since the field detects the boundary failure whatever caused it. [`TA-17`](#a-ta-17) supplies the adversarial instance, an authenticated caller reaching another tenant's application deliberately. Evidence is therefore settled twice over, and only the modality gate remains. *Read by:* [Data or access across a tenant boundary](#p-cross-tenant-access).

<a id="f-provider-endpoint-identity"></a>**Provider / Endpoint Identity.** Which provider/endpoint served the call. The reason the completion ended is **Stop Reason**.

*Tier:* MAY, dominant value Q or A and redundant with MUST fields. [`TA-28`](#a-ta-28) is the case that tests the tier. [`AOC-06`](#a-aoc-06) is a governance and availability signal rather than a discrete adversary technique, which makes the field Q- and A-dominant, and the D concern it is usually asked to carry, model substitution, belongs to Model Name + Version. [`TA-28`](#a-ta-28) is different: a backdoor using a provider's own API as its command-and-control channel, where the exfiltration destination is an endpoint the application legitimately calls. That is a detection argument rather than a governance one, and it is carried by **Output Egress Destination** (§1.2, MUST) recording the destination together with what left, not by provider identity alone, because a legitimate call and a C2 beacon share the provider. The field stays MAY because knowing *which* provider was called does not separate them; knowing what was sent does. *Read by:* [Call routed outside the restriction in force](#p-route-outside-restriction). *Risk Map controls:* `controlModelAndDataIntegrityManagement`, `controlMessageAndPayloadResourceLimits`.

<a id="f-pre-forward-pass-state-digest-vector"></a>**Pre-Forward-Pass State Digest/Vector.** Content-addressed digest (+ pooled vector) of the exact inputs to a forward pass, captured pre-inference for replay/drift detection.

*Tier:* MAY, research-grade signal and fewer than two documented instances.

<a id="f-token-malformation-context-corruption-indicator"></a>**Token Malformation / Context-Corruption Indicator.** Signal of context-induced token-entropy anomalies correlated with confabulation.

*Tier:* MAY, research-grade signal and fewer than two documented instances.
<!-- END GENERATED: fields 6.1 -->

### 1.2 Content, trust, verdicts and their availability

Input handling is where an agent separates trusted commands from untrusted content. The CoSAI Risk Map defines `componentAgentInputHandling` as "processing distinguishing trusted user commands from untrusted environmental data", and that distinction is the most important agentic-security signal. Output handling is where damage materializes: disclosure, exfiltration channels, harmful content, mass broadcast.

This step also records whether the telemetry plane worked. Every other field assumes the telemetry and enforcement path is functioning. **Instrumentation Coverage / Hook Status** and **Enforcement-Point Availability & Failure Mode**, with **Event Sequence Continuity** (§1.6), test that assumption. They are telemetry about the plane, motivated by the OWASP AOS [[38]](#standards--frameworks) **Instrument** pillar, where enforcement is a synchronous callout that can fail, be bypassed, or be starved. They record when the plane fails; they do not defend it. Authenticating emitters, securing transport and storage, and establishing chain of custody are excluded by [RFC §2.2](CoSAI-AI-Telemetry-RFC.md#22-not-in-scope); the CoSAI Risk Map addresses them in its audit-trail controls (`controlAuditTrailCompleteness`, `controlAuditTrailIntegrityVerification`, `controlAuditRecordRepositoryIndependence`). The line is the one drawn in [RFC §4.5](CoSAI-AI-Telemetry-RFC.md#45-a-missing-verdict-is-not-an-allow): a signal that makes a silent failure distinguishable from a clean result is detection material.

<!-- BEGIN GENERATED: fields 6.2 -->
| Field | Tier | Role | Origin | What it records | Emitted by | Grounding attacks |
| :------------ | :---- | :---------- | :-------- | :------------------------------------- | :-------------------- | :------------ |
| **Model Input** | MUST | content | observed | Every input to each model call, including tool output, retrieved context and messages. | `componentApplicationInputHandling`, `componentAgentInputHandling` | [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), [`TA-03`](#a-ta-03), [`TA-04`](#a-ta-04), [`TA-05`](#a-ta-05), [`TA-07`](#a-ta-07), [`TA-09`](#a-ta-09), [`TA-10`](#a-ta-10), [`TA-19`](#a-ta-19), [`TA-27`](#a-ta-27), [`TA-32`](#a-ta-32), [`TA-34`](#a-ta-34), *[`TA-35`](#a-ta-35)*, *[`TA-38`](#a-ta-38)*, [`TA-39`](#a-ta-39), [`TA-40`](#a-ta-40), [`IR-01`](#a-ir-01), [`IR-02`](#a-ir-02), [`AOC-03`](#a-aoc-03), [`AOC-12`](#a-aoc-12) |
| **Input Source / Channel** | MUST | provenance | observed | Which surface, tool, agent or document each input segment came from. | `componentApplicationInputHandling`, `componentAgentInputHandling` | [`TA-01`](#a-ta-01), [`TA-32`](#a-ta-32), [`TA-39`](#a-ta-39), [`IR-01`](#a-ir-01), [`IR-03`](#a-ir-03), [`AOC-10`](#a-aoc-10), [`AOC-12`](#a-aoc-12) |
| **Input Trust Classification** | MUST | label | observed | Trusted or untrusted origin, crossed with the role assigned on entry: instruction or data. | `componentAgentInputHandling` | [`TA-01`](#a-ta-01), [`TA-12`](#a-ta-12), [`TA-18`](#a-ta-18), [`TA-19`](#a-ta-19), [`TA-26`](#a-ta-26), *[`TA-32`](#a-ta-32)*, [`TA-39`](#a-ta-39), [`TA-40`](#a-ta-40), [`IR-01`](#a-ir-01), [`AOC-02`](#a-aoc-02), [`AOC-08`](#a-aoc-08), [`AOC-12`](#a-aoc-12), [`AOC-16`](#a-aoc-16) |
| **Source host / IP + request metadata** | MUST | provenance | observed | Origin of the request, for geo, rate and credential-theft detection. | `componentApplicationInputHandling` | [`TA-03`](#a-ta-03), [`TA-10`](#a-ta-10), *[`TA-36`](#a-ta-36)*, *[`TA-37`](#a-ta-37)*, *[`IR-04`](#a-ir-04)*, *[`AOC-08`](#a-aoc-08)*, [`AOC-15`](#a-aoc-15) |
| **Guardrail (Input) Verdict** | MUST | outcome | observed | Input classifier result (pass, flag, block, modify) with detector and score. | `componentApplicationInputHandling`, `componentAgentInputHandling` | [`TA-01`](#a-ta-01), [`TA-05`](#a-ta-05), [`TA-22`](#a-ta-22), [`TA-26`](#a-ta-26), [`TA-39`](#a-ta-39), [`TA-40`](#a-ta-40), [`IR-01`](#a-ir-01), [`AOC-12`](#a-aoc-12) |
| **Response / Model Output** | MUST | content | observed | Generated output at each step. | `componentApplicationOutputHandling`, `componentAgentOutputHandling` | [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), [`TA-03`](#a-ta-03), [`TA-04`](#a-ta-04), [`TA-07`](#a-ta-07), [`TA-09`](#a-ta-09), [`TA-10`](#a-ta-10), *[`TA-32`](#a-ta-32)*, [`TA-34`](#a-ta-34), *[`TA-35`](#a-ta-35)*, [`TA-39`](#a-ta-39), [`TA-40`](#a-ta-40), [`AOC-03`](#a-aoc-03), [`AOC-11`](#a-aoc-11) |
| **Output Egress Destination** | MUST | identifier | observed | Where output goes: recipients, URLs, channels, files, broadcast scope. | `componentApplicationOutputHandling`, `componentAgentOutputHandling` | [`TA-01`](#a-ta-01), [`TA-03`](#a-ta-03), [`TA-12`](#a-ta-12), [`TA-16`](#a-ta-16), [`TA-17`](#a-ta-17), [`TA-28`](#a-ta-28), [`TA-29`](#a-ta-29), [`TA-37`](#a-ta-37), [`AOC-03`](#a-aoc-03), [`AOC-05`](#a-aoc-05), [`AOC-11`](#a-aoc-11) |
| **Citations / Source Attribution** **[AOS]** | MUST | outcome | derived | Sources the agent claims, and whether each resolves to a logged retrieval. | `componentApplicationOutputHandling`, `componentAgentOutputHandling` | [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), [`IR-03`](#a-ir-03) |
| **Guardrail (Output) Verdict** | MUST | outcome | observed | Output filter result (pass, flag, block, modify). | `componentApplicationOutputHandling`, `componentAgentOutputHandling` | [`TA-01`](#a-ta-01), [`TA-22`](#a-ta-22), [`TA-40`](#a-ta-40), [`IR-01`](#a-ir-01), [`AOC-03`](#a-aoc-03) |
| **LLM Refusal** | MUST | outcome | observed | Refusal status and reason. | `componentAgentOutputHandling` | [`TA-03`](#a-ta-03), [`TA-04`](#a-ta-04), [`TA-07`](#a-ta-07), [`TA-22`](#a-ta-22), [`TA-24`](#a-ta-24), *[`TA-35`](#a-ta-35)*, *[`TA-38`](#a-ta-38)*, [`IR-01`](#a-ir-01), [`AOC-12`](#a-aoc-12), [`AOC-13`](#a-aoc-13), [`AOC-14`](#a-aoc-14) |
| **Content Modality & Attachment Identity** **[AOS]** | MUST | label | observed | Part type, MIME type, and for files name, size and hash, on every content-bearing field. | every content-bearing field | *[`TA-01`](#a-ta-01)*, *[`TA-05`](#a-ta-05)*, [`TA-26`](#a-ta-26), [`AOC-05`](#a-aoc-05), [`AOC-12`](#a-aoc-12) |
| **Attribute Source / Trusted-Provenance Marking** **[CPEX]** | MUST | provenance | observed | The authority that supplied each security-relevant attribute, or that it is self-asserted, and each counterparty's knowability tier. | every security-relevant attribute | [`TA-21`](#a-ta-21), [`AOC-01`](#a-aoc-01), [`AOC-07`](#a-aoc-07), [`AOC-08`](#a-aoc-08), [`AOC-10`](#a-aoc-10), [`AOC-15`](#a-aoc-15) |
| **Instrumentation Coverage / Hook Status** | MUST | descriptor | observed | Which hooks are active, their version, where each reports, and the sampling configuration in force. | instrumentation layer | [`TA-17`](#a-ta-17), [`TA-37`](#a-ta-37), *[`AOC-01`](#a-aoc-01)*, *[`AOC-09`](#a-aoc-09)*, *[`AOC-10`](#a-aoc-10)* |
| **Enforcement-Point Availability & Failure Mode** | MUST | outcome | observed | Whether each enforcement callout was reached, its latency, and fail-open or fail-closed. | enforcement points | [`TA-01`](#a-ta-01), *[`TA-10`](#a-ta-10)*, *[`IR-01`](#a-ir-01)*, *[`AOC-12`](#a-aoc-12)* |
| **Guardrail Modification Record** **[AOS]** | MUST | outcome | observed | That an enforcement point rewrote a payload, which one, with before and after digests. | any rewriting enforcement point | [`TA-01`](#a-ta-01), *[`IR-01`](#a-ir-01)*, *[`AOC-03`](#a-aoc-03)*, *[`AOC-12`](#a-aoc-12)* |
| **Encoded / Obfuscated Payload Indicator** | MUST | label | derived | Flag and decoded form of base64, image-embedded, invisible-Unicode or markup-authority input. | `componentAgentInputHandling` | *[`TA-03`](#a-ta-03)*, [`TA-21`](#a-ta-21), *[`TA-38`](#a-ta-38)*, *[`TA-39`](#a-ta-39)*, [`TA-40`](#a-ta-40), [`AOC-12`](#a-aoc-12) |
| **Observation / Thought (reasoning trace)** | SHOULD | content | asserted | Reasoning trace, where the provider exposes it. Self-asserted. Provider-gated. | `componentReasoningCore` | [`TA-06`](#a-ta-06), [`TA-08`](#a-ta-08), [`TA-09`](#a-ta-09), [`IR-02`](#a-ir-02), [`AOC-01`](#a-aoc-01), [`AOC-07`](#a-aoc-07), *[`AOC-10`](#a-aoc-10)* |
| **Threat Classification / ATLAS Technique Tag** | MAY | label | derived | MITRE ATLAS technique IDs on any event where a detection fires. | any detector | *[`TA-01`](#a-ta-01)*, *[`TA-07`](#a-ta-07)*, *[`IR-01`](#a-ir-01)*, *[`AOC-12`](#a-aoc-12)* |

**Field entries.**

<a id="f-model-input"></a>**Model Input.** Every input to each model call in the loop, user prompts, tool outputs, retrieved context, inter-agent messages. Not just the first user turn. Includes size/shape (large or repetitive inputs).

*Tier:* MUST, on 18 documented instances. Must cover *all* inputs, not the first user turn: injection arrives via tool outputs ([`IR-01`](#a-ir-01)), retrieved content ([`IR-03`](#a-ir-03), [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02)), memory ([`IR-02`](#a-ir-02)), or another agent ([`AOC-12`](#a-aoc-12)). *Read by:* [Pre-filled prompt telling the assistant to remember a source](#p-prefilled-prompt-to-remember), [Same input across many identities](#p-same-input-many-identities), [Refusals, then a completion, in one session](#p-refusals-then-completion), [Input content re-emitted to another agent or store](#p-input-reemitted) and [Sensitive input to an off-inventory AI service](#p-sensitive-input-to-off-inventory-ai). *Risk Map controls:* `controlInputValidationAndSanitization`.

<a id="f-input-source-channel"></a>**Input Source / Channel.** Provenance label for each input segment: which surface/tool/agent/document it came from. Telemetry placed in a model's context for analysis (log records, alerts, malware samples) is a channel of its own: its fields carry text an attacker wrote.

*Tier:* MUST, on 7 documented instances. *Read by:* [Pre-filled prompt telling the assistant to remember a source](#p-prefilled-prompt-to-remember). *Risk Map controls:* `controlInputValidationAndSanitization`.

<a id="f-input-trust-classification"></a>**Input Trust Classification.** The origin authority of a segment crossed with the role the deployment assigned it on entry: **trusted-instruction**, **trusted-data**, **untrusted-instruction**, **untrusted-data**. Owner command against environmental or third-party content, and instruction against data. **`untrusted-instruction` is the attack state**, the cell [`TA-01`](#a-ta-01) occupies.

*Tier:* MUST, on 12 documented instances. Operationalizes the risk map's core agentic control. [`AOC-02`](#a-aoc-02) disclosed 124 email records because it did not distinguish an owner instruction from a non-owner's; [`TA-01`](#a-ta-01) is untrusted email content promoted to instruction. *Read by:* [Instructions followed from an untrusted-data segment](#p-untrusted-data-instructions-followed), [Untrusted attachment, then a destructive tool call](#p-untrusted-attachment-to-destructive-tool), [Untrusted content acted on in a later turn](#p-untrusted-content-acted-on-later), [Autonomous trigger, untrusted content, new egress](#p-zero-click-to-new-egress) and [Untrusted input, then a tool call, then egress to a new destination](#p-untrusted-input-to-new-egress). *Risk Map controls:* `controlInputValidationAndSanitization`.

<a id="f-source-host-ip-request-metadata"></a>**Source host / IP + request metadata.** Origin of the request; supports geo/impossible-travel, rate-limit, and credential-theft detection.

*Tier:* MUST, on 3 documented instances. *Read by:* [Same identity from a new source](#p-identity-from-new-source). *Risk Map controls:* `controlInputValidationAndSanitization`.

<a id="f-guardrail-input-verdict"></a>**Guardrail (Input) Verdict.** Result of any input-side injection/jailbreak/PII/secret classifier: **pass / flag / block / modify**, with detector + score.

*Tier:* MUST, on 8 documented instances. [`TA-01`](#a-ta-01) *defeated* a prompt-injection classifier. A classifier bypass is undetectable if verdicts are never logged. *Read by:* [Guardrail blocks stop while volume continues](#p-guardrail-blocks-stop). *Risk Map controls:* `controlInputValidationAndSanitization`.

<a id="f-response-model-output"></a>**Response / Model Output.** The generated output at each step. Where leakage, disclosure, verbatim training data, and embedded exfil URLs appear.

*Tier:* MUST, on 12 documented instances. *Read by:* [Instructions followed from an external retrieved item](#p-retrieved-instructions-followed), [Instructions followed from an untrusted-data segment](#p-untrusted-data-instructions-followed), [Output link carrying session data](#p-output-link-carrying-data) and [Response reproduces the system prompt](#p-system-prompt-reproduced). *Risk Map controls:* `controlOutputValidationAndSanitization`.

<a id="f-output-egress-destination"></a>**Output Egress Destination.** Where output goes: recipient addresses, outbound URLs/domains, channels, file targets, broadcast scope.

*Tier:* MUST, on 11 documented instances. Converts a detection from *"something bad was generated"* into *"and here is where it went"*: the difference between blocking and reporting. It would have caught [`TA-01`](#a-ta-01) and [`TA-03`](#a-ta-03) *before data left*: both smuggle data into an outbound URL on a trusted-looking domain. It also renders [`AOC-03`](#a-aoc-03), [`AOC-11`](#a-aoc-11), and [`AOC-05`](#a-aoc-05) visible. *Read by:* [Autonomous trigger, untrusted content, new egress](#p-zero-click-to-new-egress), [Output link carrying session data](#p-output-link-carrying-data), [Untrusted input, then a tool call, then egress to a new destination](#p-untrusted-input-to-new-egress), [Egress under accumulated session taint](#p-egress-under-session-taint) and [Task callback registered to an undeclared destination](#p-callback-to-undeclared-destination). *Risk Map controls:* `controlOutputValidationAndSanitization`.

<a id="f-citations-source-attribution"></a>**Citations / Source Attribution.** The sources the agent *claims* it drew on, per output: file ID/name/URL or site URL for each citation, **plus whether each resolves to an item actually returned by a logged Retrieval Event (§1.4)**. Unresolvable, fabricated, or attacker-supplied citations are the signal.

*Tier:* MUST, on 3 documented instances. Applies to deployments that emit citations, which is now the common RAG configuration. A citation is a *trusted* output component (`AML.T0067.000`), so three detections depend on it and none is reachable from response text alone: fabricated citations matching no retrieval, attacker-planted links ([`TA-02`](#a-ta-02), [`TA-01`](#a-ta-01)), and suppression visible by comparing retrieved against cited ([`IR-03`](#a-ir-03)). *Read by:* [Citation with no matching retrieval](#p-citation-without-retrieval). *Risk Map controls:* `controlOutputValidationAndSanitization`.

<a id="f-guardrail-output-verdict"></a>**Guardrail (Output) Verdict.** Output-side filter result (PII/DLP, harmful content, exfil pattern): **pass / flag / block / modify**. Modifications are recorded via the **Guardrail Modification Record**. Fired detections can carry the **ATLAS Technique Tag**.

*Tier:* MUST, on 5 documented instances. *Read by:* [Guardrail blocks stop while volume continues](#p-guardrail-blocks-stop). *Risk Map controls:* `controlOutputValidationAndSanitization`.

<a id="f-llm-refusal"></a>**LLM Refusal.** Status + reason when the model refuses. A refusal-then-success streak signals a jailbreak in progress; an *absent* refusal on clearly policy-violating output flags a guardrail gap.

*Tier:* MUST, on 9 documented instances. An early-warning tripwire. [`IR-01`](#a-ir-01) is iterated reframing until a refusal flips; [`AOC-12`](#a-aoc-12), [`AOC-13`](#a-aoc-13) and [`AOC-14`](#a-aoc-14) are the mirror image, successful refusals whose telemetry documents attempted attacks even when blocked. *Read by:* [Refusals, then a completion, in one session](#p-refusals-then-completion) and [Repeated refusals](#p-repeated-refusals). *Risk Map controls:* `controlOutputValidationAndSanitization`.

<a id="f-content-modality-attachment-identity"></a>**Content Modality & Attachment Identity.** **Cross-cutting.** For every content-bearing field: the part type (text / file / structured data), MIME type, and for files the name, size, and content hash. Instructions that arrive as an image, PDF, or structured blob are invisible to text-only inspection and text-only logging.

*Tier:* MUST, on 3 documented instances. The corpus's obfuscation attacks are modality attacks: instructions in OCR'd images and base64 blobs ([`AOC-12`](#a-aoc-12)), ~10 MB attachment floods ([`AOC-05`](#a-aoc-05)). Text-only capture misses both. *Read by:* [Untrusted attachment, then a destructive tool call](#p-untrusted-attachment-to-destructive-tool).

<a id="f-attribute-source-trusted-provenance-marking"></a>**Attribute Source / Trusted-Provenance Marking.** **Cross-cutting.** For every security-relevant attribute, the **authority that supplied it**: verified IdP token, policy decision point, enforcement-owned session store, platform/runtime, versus **self-asserted by the agent or model**. Security-relevant attributes are those a hostile agent could plausibly fabricate: identity, authorization outcome, taint state, approval status, autonomy level, task declaration, and instruction configuration. Under assume-breach, an unmarked value is an unverified value.

*Tier:* MUST, on 6 documented instances. The zero-trust principle applied to telemetry itself: it determines whether the rest of the field set can be believed. The document already applies the idea once (Verified vs Displayed Identity, §1.6) and the generalization is that identity is not the only attribute an agent can assert. Autonomy Level, Task / Intent Declaration, System Prompt / Instruction Config, and every reasoning field are agent-supplied, and the corpus shows that agents *do* report falsely ([RFC §4.4](CoSAI-AI-Telemetry-RFC.md#44-the-agent-might-be-lying)). Cost is an enum per attribute group, not per event. *Read by:* [Self-asserted attribute contradicts the authority](#p-self-asserted-attribute-contradicted).

<a id="f-instrumentation-coverage-hook-attestation"></a>**Instrumentation Coverage / Hook Status.** Which lifecycle hooks are instrumented and active for this agent/run, the instrumentation version, and **where each hook reports**, the difference between "no events", "not observed", and "observed by someone else."

*Tier:* MUST, needed to read [LLM Refusal](#f-llm-refusal), [Tool Execution ID](#f-tool-execution-id) and [Guardrail (Input) Verdict](#f-guardrail-input-verdict). Grounded by [`TA-17`](#a-ta-17), where the telemetry plane was redirected ([§4.2](#42-the-telemetry-plane)). Under sampling, an absent refusal, tool result or verdict cannot be read without the coverage and sampling record ([RFC §5.2](CoSAI-AI-Telemetry-RFC.md#52-sampling)). More generally it resolves the ambiguity undermining every absence-based detection in the document: no refusal, no termination condition, no matching request are each only interpretable if the relevant hook was instrumented. It is D-dominant, it is not modality-gated (every deployment has an instrumentation configuration), and recording *where each hook reports* is what separates a hijacked plane from a healthy one. *Read by:* [Hook coverage or destination changes mid-run](#p-hook-coverage-changed). *Risk Map controls:* `controlAuditTrailCompleteness`.

<a id="f-enforcement-point-availability-failure-mode"></a>**Enforcement-Point Availability & Failure Mode.** For each enforcement callout (guardrail, policy engine, external guardian): whether it was reached, its latency, and on failure whether the system **failed open or failed closed**, plus the action that was taken anyway.

*Tier:* MUST, needed to read [Guardrail (Input) Verdict](#f-guardrail-input-verdict), [Guardrail (Output) Verdict](#f-guardrail-output-verdict) and [Authorization Decision Record](#f-authorization-decision-record). A verdict that never arrived and a verdict of `allow` are indistinguishable in the log, so without it the guardrail verdicts and the **Authorization Decision Record** cannot be read, and the control plane is a single point of silent failure. Deployments choose fail-open or fail-closed for availability reasons; **the field records the choice and the outcome**, and neither posture is recommended. *Read by:* [Enforcement point unreached, operation proceeds](#p-enforcement-point-fail-open).

<a id="f-guardrail-modification-record"></a>**Guardrail Modification Record.** **Cross-cutting.** When an enforcement point **rewrites rather than blocks**: masking, redacting, stripping, or rewriting a payload; record that a modification occurred, which enforcement point made it, and a before/after digest (plus a redaction map where policy permits). Applies on both the input and the output side.

*Tier:* MUST, needed to read [Model Input](#f-model-input), [Response / Model Output](#f-response-model-output), [Guardrail (Input) Verdict](#f-guardrail-input-verdict) and [Guardrail (Output) Verdict](#f-guardrail-output-verdict). Applies whenever an enforcement point or redaction pipeline rewrites rather than blocks. Without it, **Model Input**, **Response** and a guardrail verdict of `modify` record content that was not what the model or the recipient saw, so the record is *actively wrong*. Its value is R first and D second. [`TA-01`](#a-ta-01), whose chain bypassed link redaction, is an instance, but the tier rests on the dependency.

<a id="f-encoded-obfuscated-payload-indicator"></a>**Encoded / Obfuscated Payload Indicator.** Flag + decoded form when input contains base64, image-embedded (OCR), or markup "authority" tags. Includes invisible or control Unicode characters (tag characters, zero-width joiners, bidirectional overrides) that hide instructions from a human reader.

*Tier:* MUST, on 3 documented instances. The corpus's obfuscation attacks hide instructions where a reader of the recorded input would not see them: base64 and OCR'd images ([`AOC-12`](#a-aoc-12)), invisible Unicode in a rules file ([`TA-21`](#a-ta-21)). Model Input is only required to carry a content hash ([RFC §5.3](CoSAI-AI-Telemetry-RFC.md#53-content-hashing)), so where raw content is not retained the flag and decoded form are the only record that the payload was there. *Read by:* [Obfuscated content in the instruction configuration](#p-obfuscated-instruction-config). *Risk Map controls:* `controlInputValidationAndSanitization`.

<a id="f-observation-thought-reasoning-trace"></a>**Observation / Thought (reasoning trace).** Chain-of-thought/observations *when the provider exposes it*. Reveals whether a harmful act was injected, misauthorized, or self-initiated.

*Tier:* SHOULD, provider-gated. High-value forensics for separating a compromised agent from a misconfigured one ([`AOC-01`](#a-aoc-01), [`AOC-07`](#a-aoc-07)), but frequently unavailable from provider APIs and privacy-sensitive. *Risk Map controls:* `controlNetworkEgressControl`.

<a id="f-threat-classification-atlas-technique-tag"></a>**Threat Classification / ATLAS Technique Tag.** **Cross-cutting enrichment.** On any flagged or security-relevant event, the classified technique(s) as **MITRE ATLAS `AML.Txxxx`** IDs (plus a free-text threat type). Emitted by input/output guardrails and by tool/memory/retrieval detectors alike, so every alert carries a portable, ATT&CK-aligned technique reference.

*Tier:* MAY, fewer than two documented instances. Its value is D-portability into ATT&CK-aligned tooling plus A-rollup, but no documented instance turns on its absence and no MUST field depends on it, so it fails both MUST tests. This document still recommends stamping every fired detection with it.
<!-- END GENERATED: fields 6.2 -->

### 1.3 Tool calls and policy decisions

A tool call is where an agent crosses from reasoning to acting: the perimeter between AI reasoning and real-world consequences. The policy fields record what policy **decided**, and on what basis, under the CPEX threat model [[44]](#standards--frameworks), in which the LLM itself is the adversary.

> **Gateways, namespaces, and multiple hops.** A tool call is frequently not a single hop. Tools and prompts commonly sit behind a **gateway or broker** that re-namespaces them, and the call may traverse several intermediaries before reaching the system that acts. Three fields carry this, and they should be read together: **Tool Name** records the name *as the agent saw it*, which is the namespaced or gateway-local name and not necessarily the name at the far end; **MCP Server Identity & Primitive** records the immediate counterparty; and **Trace Context** (§1.1) is what stitches the hops into one trace, propagated over MCP via `params._meta`, per [XM §2.8](Telemetry-Cross-Mapping-Addendum.md#28-context-propagation-sampling-privacy-and-canonicalization).
>
> Two consequences. First, **the same underlying capability may appear under different names** depending on the path taken to it, so detections keyed on tool name alone will miss re-namespaced invocations; keying on the server identity and primitive as well is what makes them robust. Second, an intermediary is a **mediation boundary**, and whether it was traversed at all is the subject of **Mediation Coverage & Bypass Path**; [`AOC-14`](#a-aoc-14) is precisely an attempt to reach a capability by a path that bypasses the mediated one.

<!-- BEGIN GENERATED: fields 6.3 -->
| Field | Tier | Role | Origin | What it records | Emitted by | Grounding attacks |
| :------------ | :---- | :---------- | :-------- | :------------------------------------- | :-------------------- | :------------ |
| **Execution Environment / Sandbox** **[AOS]** | MUST | descriptor | observed | Isolation posture: sandbox mode, runtime, OS, timeout, egress policy. | `componentIsolationRuntime`, `componentToolHosting` | [`TA-06`](#a-ta-06), [`TA-14`](#a-ta-14), [`TA-23`](#a-ta-23), *[`AOC-02`](#a-aoc-02)*, *[`AOC-04`](#a-aoc-04)*, *[`AOC-14`](#a-aoc-14)* |
| **Tool Call I/O** | MUST | content | observed | Full arguments and output of every tool or MCP call. | `componentToolServer`, `componentTools` | [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), [`TA-06`](#a-ta-06), [`TA-08`](#a-ta-08), [`TA-09`](#a-ta-09), [`TA-12`](#a-ta-12), [`TA-15`](#a-ta-15), [`TA-16`](#a-ta-16), [`TA-19`](#a-ta-19), [`TA-24`](#a-ta-24), [`TA-26`](#a-ta-26), [`TA-28`](#a-ta-28), [`TA-29`](#a-ta-29), *[`IR-04`](#a-ir-04)*, [`AOC-01`](#a-aoc-01), [`AOC-02`](#a-aoc-02), [`AOC-03`](#a-aoc-03), [`AOC-10`](#a-aoc-10), [`AOC-13`](#a-aoc-13), [`AOC-14`](#a-aoc-14) |
| **Tool Name** | MUST | identifier | observed | The capability invoked, as the agent saw it. | `componentToolServer` | [`TA-06`](#a-ta-06), [`TA-08`](#a-ta-08), [`TA-09`](#a-ta-09), *[`IR-01`](#a-ir-01)*, [`AOC-02`](#a-aoc-02), [`AOC-09`](#a-aoc-09), [`AOC-10`](#a-aoc-10) |
| **Tool Type / Trust Boundary** | MUST | label | declared | MCP, internal, direct-storage or code-execution. | `componentTools` | *[`TA-01`](#a-ta-01)*, [`TA-06`](#a-ta-06), [`AOC-14`](#a-aoc-14) |
| **Tool Execution ID** **[AOS]** | MUST | identifier | observed | Correlation ID pairing each tool request with its outcome. | `componentToolServer` | [`TA-08`](#a-ta-08), [`AOC-01`](#a-aoc-01), *[`AOC-04`](#a-aoc-04)*, *[`AOC-14`](#a-aoc-14)* |
| **Tool Definition Digest** **[AOS]** | MUST | provenance | derived | Hash of the tool contract as presented at invocation, compared with the approved baseline. | `componentToolServer`, `componentToolRegistry` | [`TA-15`](#a-ta-15), [`TA-29`](#a-ta-29) |
| **MCP Server Identity & Primitive** **[AOS]** | MUST | identifier | asserted | MCP server name, version, transport and endpoint, and the primitive exercised. | `componentToolServer` | [`TA-12`](#a-ta-12), [`TA-13`](#a-ta-13), [`TA-15`](#a-ta-15), [`TA-16`](#a-ta-16), [`TA-29`](#a-ta-29), *[`AOC-09`](#a-aoc-09)* |
| **Authorization Decision Record** **[CPEX]** | MUST | outcome | observed | Per mediated operation: decision, reason code, deciding authority and rule. | `componentAuthorizationPolicyDecisionPoint`, `componentAuthorizationPolicyEnforcementPoint` | [`TA-08`](#a-ta-08), [`TA-11`](#a-ta-11), [`TA-12`](#a-ta-12), [`TA-13`](#a-ta-13), [`TA-17`](#a-ta-17), [`TA-23`](#a-ta-23), *[`TA-36`](#a-ta-36)*, [`AOC-02`](#a-aoc-02), [`AOC-08`](#a-aoc-08), [`AOC-10`](#a-aoc-10) |
| **Tool Selection Rationale** **[AOS]** | SHOULD | content | asserted | The agent's stated reason for a tool call. Self-asserted. Provider-gated. | `componentReasoningCore` | *[`TA-08`](#a-ta-08)*, [`AOC-01`](#a-aoc-01), *[`AOC-02`](#a-aoc-02)*, *[`AOC-10`](#a-aoc-10)* |
| **Human Approval / Elicitation Event** **[CPEX]** | SHOULD | outcome | observed | Approval lifecycle: status, identity-provider-verified approver, and whether it covers the executed arguments. Modality: out-of-band human approval. | `componentAgentConsentSurface`, `componentApplicationConsentSurface` | [`TA-15`](#a-ta-15), [`TA-23`](#a-ta-23), [`TA-29`](#a-ta-29), [`AOC-01`](#a-aoc-01), [`AOC-02`](#a-aoc-02), [`AOC-07`](#a-aoc-07), [`AOC-11`](#a-aoc-11) |
| **Tool ACL / Required Scope** | SHOULD | descriptor | declared | Authority a tool requires and who can invoke it. Modality: delegated authority. | `componentAuthorizationPolicyEnforcementPoint` | [`TA-06`](#a-ta-06), [`TA-08`](#a-ta-08), [`TA-12`](#a-ta-12), [`AOC-02`](#a-aoc-02), [`AOC-08`](#a-aoc-08), [`AOC-10`](#a-aoc-10) |
| **Session Taint Labels & Information-Flow Decisions** **[CPEX]** | SHOULD | label | observed | Information-flow labels in force, and denials caused by accumulated taint. Modality: information-flow control. | enforcement points | [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), *[`TA-05`](#a-ta-05)*, [`AOC-03`](#a-aoc-03) |
| **Backend / Route Restriction Decision** **[CPEX]** | SHOULD | outcome | observed | Candidate backends, the constraint applied, the choice made. Modality: policy-driven backend selection. | enforcement points | *[`AOC-06`](#a-aoc-06)* |
| **Mediation Coverage & Bypass Path** **[CPEX]** | SHOULD | label | observed | Whether an operation passed a reference monitor, where, and whether a bypass exists. Modality: reference monitor in the request path. | enforcement points | *[`TA-06`](#a-ta-06)*, *[`AOC-02`](#a-aoc-02)*, [`AOC-14`](#a-aoc-14) |
| **Tool Error / Exception** | MAY | outcome | observed | Failed or blocked tool calls, including the probing that precedes exploitation. | `componentToolServer`, `componentToolInputHandling` | *[`TA-01`](#a-ta-01)*, *[`TA-02`](#a-ta-02)*, *[`TA-06`](#a-ta-06)*, *[`TA-13`](#a-ta-13)*, *[`IR-01`](#a-ir-01)*, *[`AOC-14`](#a-aoc-14)* |
| **Tool ID** | MAY | identifier | declared | Unique tool-implementation ID across MCP servers. | `componentTools` | *[`AOC-10`](#a-aoc-10)* |
| **Tool Privacy Classification** | MAY | label | declared | Sensitivity class of the data a tool touches. | `componentTools` | *[`TA-01`](#a-ta-01)*, [`TA-05`](#a-ta-05), [`AOC-03`](#a-aoc-03) |
| **Policy Reason Code** | MAY | label | observed | Machine-readable reason code for an enforcement decision. | enforcement points | *[`TA-01`](#a-ta-01)*, *[`IR-01`](#a-ir-01)*, *[`AOC-12`](#a-aoc-12)* |

**Field entries.**

<a id="f-execution-environment-sandbox"></a>**Execution Environment / Sandbox.** The isolation posture of the execution: sandbox mode (none / container / VM / WASM), language runtime and version, OS/architecture, timeout, and network-egress policy.

*Tier:* MUST, on 3 documented instances. [`TA-06`](#a-ta-06) is characterized as model-emitted Python executed **unsandboxed**: the isolation posture *is* the finding. Two calls to the same code-execution tool, one containerized and one not, are otherwise the same event. *Read by:* [Code execution with no sandbox](#p-unsandboxed-code-execution). *Risk Map controls:* `controlRuntimeHostIsolation`.

<a id="f-tool-call-io"></a>**Tool Call I/O.** Full input params **and** output for every tool/MCP call; what the agent actually *did* vs what it was asked. Reveals credentials passed between chained calls.

*Tier:* MUST, on 19 documented instances. Without it and **Tool Name** a compromised agent's actions are invisible, and every destructive case in the corpus is reconstructed from them. *Read by:* [Code execution with no sandbox](#p-unsandboxed-code-execution), [Individually authorized calls chained across identities](#p-authorized-calls-chained-across-identities), [Long autonomous run against many external targets](#p-autonomous-run-against-external-targets), [New tool name with a rise in tool calls](#p-new-tool-with-call-spike), [Untrusted attachment, then a destructive tool call](#p-untrusted-attachment-to-destructive-tool), [Untrusted content acted on in a later turn](#p-untrusted-content-acted-on-later), [Capability reached with no mediation record](#p-unmediated-capability), [Tool arguments carry data the request did not supply](#p-unrequested-data-in-tool-arguments) and [Untrusted input, then a tool call, then egress to a new destination](#p-untrusted-input-to-new-egress). *Risk Map controls:* `controlToolServerVetting`, `controlToolServerSupplyChainIntegrity`, `controlRuntimeHostIsolation`, `controlToolArgumentValidationAndSanitization`, `controlAgentPluginPermissions`, `controlInterComponentTransportSecurity`.

<a id="f-tool-name"></a>**Tool Name.** Which capability was invoked. Detects off-manifest / sensitive-tool invocation, escalating tool sequences, and enumeration.

*Tier:* MUST, on 6 documented instances. See [Tool Call I/O](#f-tool-call-io). *Read by:* [New tool name with a rise in tool calls](#p-new-tool-with-call-spike). *Risk Map controls:* `controlToolServerVetting`, `controlToolServerSupplyChainIntegrity`, `controlAgentPluginPermissions`.

<a id="f-tool-type-trust-boundary"></a>**Tool Type / Trust Boundary.** MCP (cross-network) vs internal vs direct-storage vs code-execution, different trust models & policies.

*Tier:* MUST, on 2 documented instances. Earned via [`AOC-14`](#a-aoc-14), which tried to make the agent bypass the tool API and write to backend storage directly. "API-mediated only" is unenforceable unless telemetry distinguishes the two. *Read by:* [Capability reached with no mediation record](#p-unmediated-capability). *Risk Map controls:* `controlToolServerSupplyChainIntegrity`, `controlRuntimeHostIsolation`, `controlToolArgumentValidationAndSanitization`, `controlAgentPluginPermissions`, `controlInterComponentTransportSecurity`.

<a id="f-tool-execution-id"></a>**Tool Execution ID.** Correlation ID minted at invocation and echoed on the result, pairing every request with its outcome.

*Tier:* MUST, on 2 documented instances. Makes *a result with no matching request* a queryable condition, and is the only way to correlate asynchronous tool calls. [`AOC-01`](#a-aoc-01)'s false completion report is precisely a request/result mismatch. *Read by:* [Code execution with no sandbox](#p-unsandboxed-code-execution), [Capability reached with no mediation record](#p-unmediated-capability), [High-impact action without a covering approval](#p-action-without-covering-approval) and [Tool arguments carry data the request did not supply](#p-unrequested-data-in-tool-arguments). *Risk Map controls:* `controlToolServerVetting`, `controlToolServerSupplyChainIntegrity`, `controlAgentPluginPermissions`.

<a id="f-tool-definition-digest"></a>**Tool Definition Digest.** Hash of the tool's **declared contract as presented at invocation time**: name, description, argument schema, output schema, plus a comparison against the approved baseline. Detects a tool whose definition mutated after approval.

*Tier:* MUST, on 2 documented instances. [`TA-15`](#a-ta-15) and [`TA-29`](#a-ta-29) are the grounding instances. In [`TA-15`](#a-ta-15) the definition is malicious as published, the injection carried in the tool's own description, which is why the digest is taken **at invocation** rather than at registration and must cover the description, not only the argument and output schemas. In [`TA-29`](#a-ta-29) the description changed after approval under an unchanged name, which the comparison against the approved baseline detects. The adjacent rug pulls fall outside the digest: [`TA-14`](#a-ta-14) mutates an approved configuration's launch command and [`TA-16`](#a-ta-16) ships a malicious implementation under an adopted name; in both of those the *declared contract* is itself unchanged, so the detecting fields there are Capability-Set Change Event and MCP Server Identity & Primitive respectively. The modality gate does not hold it: the gate is third-party or dynamically-discovered tools, and an MCP `tools/list` exchange is dynamic discovery by construction. *Read by:* [Tool definition changed after approval](#p-tool-definition-changed). *Risk Map controls:* `controlToolServerVetting`, `controlToolServerSupplyChainIntegrity`, `controlAgentPluginPermissions`.

<a id="f-mcp-server-identity-primitive"></a>**MCP Server Identity & Primitive.** For MCP calls: server name, version, transport, and endpoint; **and which MCP primitive was exercised**: `tool`, `resource`, `prompt`, `sampling`, `elicitation`, or `roots`.

*Tier:* MUST, on 5 documented instances. The corpus's MCP incidents ([`TA-11`](#a-ta-11) to [`TA-16`](#a-ta-16), [`TA-29`](#a-ta-29)) clear the evidence gate several times over; [`TA-16`](#a-ta-16) is the sharpest, because the server's declared contract never changed and only its published **version** did, so name alone would not have distinguished the safe release from the malicious one. What held the field at SHOULD was the modality gate, and that gate turns on MCP being at the **edge of current agentic practice** ([RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers)). It is not. The corpus's MCP-mediated entries all date from 2025 onward, and their share understates the point, because the remaining agentic entries are incidents of other kinds rather than counter-examples to MCP's prevalence; CoSAI's Workstream 4 devoted a paper to MCP security [[24]](#standards--frameworks); OWASP publishes an MCP Top 10 [[76]](#standards--frameworks); and MITRE ATLAS has added `AML.T0109` AI Supply Chain Rug Pull and `AML.T0110` AI Agent Tool Poisoning, the latter with three sub-techniques (`.000` Definition and Instructions, `.001` Implementation, `.002` Runtime Response). A protocol acquires a dedicated top-ten list and a dedicated technique family once it is typical. **Server name and version are as cheap as Tool Name and should be adopted first.** *Read by:* [MCP server version not the approved one](#p-mcp-server-version-unapproved), [Tool definition changed after approval](#p-tool-definition-changed), [Privileged MCP tool invoked by a low-privilege identity](#p-privileged-mcp-tool-low-privilege-identity) and [Tool arguments carry data the request did not supply](#p-unrequested-data-in-tool-arguments). *Risk Map controls:* `controlToolServerVetting`, `controlToolServerSupplyChainIntegrity`, `controlAgentPluginPermissions`.

<a id="f-authorization-decision-record"></a>**Authorization Decision Record.** Per mediated operation: the terminal decision (**allow / deny**, with **allow-after-modification** flagged), the deny **reason and machine-readable code** (a fail-closed enforcement failure arrives as a deny with its own code), the per-step actions that produced it including any **suppressed deny** (a plugin denied and was overridden by pipeline role) and any **abort**, the **deciding authority** (inline policy rule vs external PDP, and which; Cedar / CEL / OPA [[49]](#standards--frameworks) / custom), the **rule or policy identifier** that produced it, and any obligations attached. Distinct from a content-guardrail verdict: this is the *authorization* outcome, not a classifier score.

*Tier:* MUST, on 9 documented instances. It records what the authorization layer **decided**, on which rule, and why. The guardrail verdicts record what a *content classifier* concluded and Tool ACL / Required Scope what authority a tool *requires*; without this field a denied operation and a never-attempted one are indistinguishable. Among the attacks that turn on that record are [`AOC-02`](#a-aoc-02) (non-owner compliance), [`AOC-08`](#a-aoc-08) (privileged action after spoof), [`AOC-10`](#a-aoc-10) (injected authority), and [`TA-08`](#a-ta-08) (individually-authorized calls escalating in aggregate; visible only if each link's decision and rule are recorded). Universal rather than modality-gated; D and R jointly. *Read by:* [Denials, then an allow, for the same operation](#p-denials-then-allow), [Privileged action authorized on a displayed identity](#p-privileged-action-on-displayed-identity), [Privileged MCP tool invoked by a low-privilege identity](#p-privileged-mcp-tool-low-privilege-identity), [Data or access across a tenant boundary](#p-cross-tenant-access) and [Individually authorized calls chained across identities](#p-authorized-calls-chained-across-identities). *Risk Map controls:* `controlTrustedPolicyEnforcementPoint`, `controlExternalizedAuthorizationDecisioning`, `controlResourceAuthorizationEnforcement`.

<a id="f-tool-selection-rationale"></a>**Tool Selection Rationale.** The agent's stated reason for choosing *this* tool with *these* arguments, captured at the request step. Distinct from the §1.2 output-side reasoning trace: it is attached to the action, not the answer.

*Tier:* SHOULD, provider-gated. *Risk Map controls:* `controlAgentPluginPermissions`.

<a id="f-human-approval-elicitation-event"></a>**Human Approval / Elicitation Event.** Out-of-band approval lifecycle for high-impact actions: correlation ID, status (pending / resolved / expired), outcome, **approver identity as verified by the identity provider** (not as reported by the agent), channel, and the **scope-binding validation result**: whether the approval still covers the arguments actually presented at execution time.

*Tier:* SHOULD, modality: out-of-band human approval. Covers the control the corpus most often shows *missing*: [`AOC-01`](#a-aoc-01), [`AOC-07`](#a-aoc-07), and [`AOC-11`](#a-aoc-11) are all irreversible actions taken without human authorization. [`TA-23`](#a-ta-23) is the sharper case, because the gate was present and was **switched off as configuration** rather than argued past: the record that matters is not only the approval but the change to whether approval was required at all, which is why **Capability-Set Change Event** (§1.6, MUST) and this field are read together. **MUST wherever the deployment gates actions on human approval.** Two sub-signals matter: approver identity must come from the identity provider, not the agent's claim; and approval scope must be re-validated against the arguments actually presented, or one sign-off can be replayed against a larger action. *Read by:* [High-impact action without a covering approval](#p-action-without-covering-approval). *Risk Map controls:* `controlInformedAgentConsentSurface`.

<a id="f-tool-acl-required-scope"></a>**Tool ACL / Required Scope.** The authority a tool requires and who may invoke it (the tool's security policy); individually-authorized calls that violate separation-of-duties as a chain.

*Tier:* SHOULD, modality: delegated authority. Every attack that cites it presupposes meaningful delegation.

<a id="f-session-taint-labels-information-flow-decisions"></a>**Session Taint Labels & Information-Flow Decisions.** Information-flow labels in force for the session or message: which labels are set, **scope** (session vs message), what operation applied each, and (critically) when an operation is **denied because of accumulated taint rather than anything in its own payload**. The write-down record.

*Tier:* SHOULD, modality: information-flow control. A genuinely different mechanism from Input Trust Classification (§1.2): that classifies a segment of one payload, while taint is **state accumulating across a session** that survives into operations whose own content is clean. That distinction is the whole attack in [`TA-01`](#a-ta-01) and [`TA-02`](#a-ta-02), where the exfiltrating request is innocuous in isolation. Of everything in SHOULD this has the highest D value per unit of effort. *Read by:* [Egress under accumulated session taint](#p-egress-under-session-taint).

<a id="f-backend-route-restriction-decision"></a>**Backend / Route Restriction Decision.** Where an operation was allowed to execute: the candidate backend/model set, the constraint that narrowed it (region, model, site, cost tier, custom label), the selection made, and the behavior when **no candidate qualified**.

*Tier:* SHOULD, modality: policy-driven backend selection. Paired with taint it is a D signal; standing alone it is closer to A (data-residency evidence) and Q. *Read by:* [Call routed outside the restriction in force](#p-route-outside-restriction).

<a id="f-mediation-coverage-bypass-path"></a>**Mediation Coverage & Bypass Path.** Whether this operation traversed a reference monitor at all, at which **placement** (inbound gateway / egress sidecar / in-process framework), and whether **unmediated paths to the same capability exist**.

*Tier:* SHOULD, modality: reference monitor in the request path. The enforcement counterpart to Instrumentation Coverage (§1.2). That field asks *is the telemetry complete?*; this one asks *is the enforcement unbypassable?* [`AOC-14`](#a-aoc-14) is precisely this attack. A control that can be routed around is not a control. *Read by:* [Capability reached with no mediation record](#p-unmediated-capability).

<a id="f-tool-error-exception"></a>**Tool Error / Exception.** Failed/blocked tool calls: rejected injection args, SSRF blocks, authz boundary hits, and the probing errors that precede successful exploitation.

*Tier:* MAY, fewer than two documented instances. No documented instance records a failed or blocked tool call: [`TA-06`](#a-ta-06) reports exceptions only where exploitation failed, and the privileged calls in [`TA-13`](#a-ta-13) succeeded. The probing that precedes exploitation is the case the field serves, and the corpus has none. No MUST field depends on it, because **Execution Status** records each operation's outcome. *Risk Map controls:* `controlToolServerVetting`, `controlToolServerSupplyChainIntegrity`, `controlToolArgumentValidationAndSanitization`, `controlAgentPluginPermissions`.

<a id="f-tool-id"></a>**Tool ID.** Unique tool-implementation ID for unambiguous attribution across many MCP servers.

*Tier:* MAY, redundant with MUST fields and fewer than two documented instances. Tool Name together with **MCP Server Identity & Primitive** (both MUST) already identifies the implementation across servers; a unique ID makes the join cheaper, not possible. *Risk Map controls:* `controlToolServerSupplyChainIntegrity`, `controlRuntimeHostIsolation`, `controlToolArgumentValidationAndSanitization`, `controlAgentPluginPermissions`, `controlInterComponentTransportSecurity`.

<a id="f-tool-privacy-classification"></a>**Tool Privacy Classification.** Sensitivity class of data the tool touches, feeds DLP / data-flow governance.

*Tier:* MAY, dominant value Q or A and redundant with MUST fields. DLP and compliance governance metadata, A-dominant, and not modality-gated. Its D value is already carried by Tool ACL / Required Scope and Output Egress Destination. *Risk Map controls:* `controlToolServerSupplyChainIntegrity`, `controlRuntimeHostIsolation`, `controlToolArgumentValidationAndSanitization`, `controlAgentPluginPermissions`, `controlInterComponentTransportSecurity`.

<a id="f-policy-reason-code"></a>**Policy Reason Code.** Machine-readable reason code(s) for an enforcement decision, alongside the existing free-text detector name and score.

*Tier:* MAY, dominant value Q or A and redundant with MUST fields. A-dominant reporting convenience, not modality-gated, and the underlying decision is already captured by the guardrail verdicts and the **Authorization Decision Record**.
<!-- END GENERATED: fields 6.3 -->

### 1.4 Memory and retrieval

Persistent memory is the one surface where an attack outlives the session that planted it, and retrieval is a primary injection and manipulation channel.

> **What counts as memory, and at what granularity.** *Memory* here means **the agent's own persistent record of its interactions and state** (`componentMemory`): a store it writes to in one turn and reads back, trusted, in a later one, whatever its substrate, such as a vector store, a scratchpad file or a database row. The read-after-write-across-turns property is what creates the attack surface, because it is what lets [`IR-02`](#a-ir-02) and [`AOC-10`](#a-aoc-10) outlive the session that planted them. An instruction file is configuration, not memory, and is recorded by **System Prompt / Instruction Config** (§1.1); a curated corpus the agent retrieves from is recorded by the retrieval fields below. This is the scope of the CoSAI Risk Map's `riskAgentMemoryPoisoning`.
>
> The fields below are specified at **item granularity, not store granularity**: a Memory Write Event describes one item, and **Memory Provenance / Source** attaches to that item. This requires a stable item identifier, and deployments whose memory is an opaque blob (a single file rewritten wholesale) cannot supply one. Such deployments should emit the write event with a **content digest** in place of an item ID, which preserves change detection and correlation while losing per-item provenance. That is a real reduction in detection capability and the reason item-level identity is worth engineering for.
>
> **Out of scope:** the durability, consistency, and retention semantics of the store itself, and any judgment about whether a given design *should* persist state. This section records what was written, read, and by what authority, not whether the memory architecture is sound.

<!-- BEGIN GENERATED: fields 6.4 -->
| Field | Tier | Role | Origin | What it records | Emitted by | Grounding attacks |
| :------------ | :---- | :---------- | :-------- | :------------------------------------- | :-------------------- | :------------ |
| **Memory Write Event** | MUST | content | observed | Each create, update or delete of a persistent memory item, and by whom. | `componentMemory` | [`TA-18`](#a-ta-18), [`TA-27`](#a-ta-27), [`TA-32`](#a-ta-32), [`IR-02`](#a-ir-02), [`IR-05`](#a-ir-05), [`AOC-07`](#a-aoc-07), [`AOC-10`](#a-aoc-10) |
| **Memory Read / Injection Event** | MUST | content | observed | Which memory items were pulled into context for a call. | `componentMemory` | [`TA-11`](#a-ta-11), [`TA-18`](#a-ta-18), [`TA-32`](#a-ta-32), [`IR-02`](#a-ir-02), [`IR-05`](#a-ir-05), [`AOC-10`](#a-aoc-10) |
| **Memory Provenance / Source** | MUST | provenance | observed | Origin and mutability of a memory item, including externally editable sources. | `componentMemory` | [`TA-18`](#a-ta-18), [`TA-32`](#a-ta-32), [`IR-02`](#a-ir-02), [`AOC-10`](#a-aoc-10) |
| **Memory Footprint / Growth** | MUST | measure | observed | Size and growth of memory stores per user or session. | `componentMemory` | [`TA-30`](#a-ta-30), *[`AOC-04`](#a-aoc-04)*, [`AOC-05`](#a-aoc-05) |
| **Retrieval Event** | MUST | content | observed | Query issued, items returned and their scores. | `componentRAGContent` | [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), [`TA-09`](#a-ta-09), [`TA-11`](#a-ta-11), [`TA-12`](#a-ta-12), [`TA-40`](#a-ta-40), [`IR-03`](#a-ir-03), [`IR-05`](#a-ir-05), [`AOC-10`](#a-aoc-10) |
| **Retrieved-Content Source / Provenance** | MUST | provenance | observed | Origin, owner, trust level and freshness of each retrieved item. | `componentRAGContent` | [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), [`TA-09`](#a-ta-09), [`TA-11`](#a-ta-11), [`TA-27`](#a-ta-27), *[`TA-33`](#a-ta-33)*, [`TA-40`](#a-ta-40), [`IR-03`](#a-ir-03) |
| **Memory Integrity / Poisoning Signal** | SHOULD | measure | derived | Integrity check or poisoning score; cross-session isolation flag. Provider-gated. | `componentMemory` | [`TA-18`](#a-ta-18), *[`TA-32`](#a-ta-32)*, [`IR-02`](#a-ir-02), [`IR-05`](#a-ir-05) |
| **Memory Write Rationale** **[AOS]** | SHOULD | content | asserted | The agent's stated reason for persisting an item. Self-asserted. Provider-gated. | `componentMemory` | [`IR-02`](#a-ir-02), *[`AOC-07`](#a-aoc-07)*, *[`AOC-10`](#a-aoc-10)* |
| **Retrieved-Content / Metadata Integrity Signal** | SHOULD | measure | derived | Tamper or poisoning indicators on content or its metadata. Provider-gated. | `componentRAGContent` | *[`TA-02`](#a-ta-02)*, *[`TA-09`](#a-ta-09)*, *[`TA-33`](#a-ta-33)*, [`IR-03`](#a-ir-03), [`IR-05`](#a-ir-05) |
| **Declared Memory Configuration** **[AOS]** | MAY | descriptor | declared | A memory store's declared identity, limits and retrieval settings. | `componentMemory` | [`TA-30`](#a-ta-30), *[`IR-02`](#a-ir-02)*, *[`AOC-05`](#a-aoc-05)*, *[`AOC-07`](#a-aoc-07)* |
| **Declared Knowledge-Source Configuration** **[AOS]** | MAY | descriptor | declared | A knowledge source's declared identity, schema and search parameters. | `componentRAGContent` | *[`TA-02`](#a-ta-02)*, *[`TA-09`](#a-ta-09)*, *[`IR-03`](#a-ir-03)* |

**Field entries.**

<a id="f-memory-write-event"></a>**Memory Write Event.** Every create/update/delete to persistent or long-term memory: what changed, by which turn/actor. Deletions include evictions made by the store itself under a size or token budget, recorded with the policy that evicted the item, so an item lost to eviction is distinguishable from one that was retrieved poorly.

*Tier:* MUST, on 7 documented instances. MINJA ([`IR-02`](#a-ir-02)) poisons memory using only benign queries: the agent autonomously persists malicious reasoning. AGENTPOISON ([`IR-05`](#a-ir-05)) uses optimized triggers. [`TA-18`](#a-ta-18) is the production instance: injected ChatGPT memories persisted and were recalled in later conversations. None is detectable without Memory Write Event, Memory Read / Injection Event and **Memory Provenance / Source**. *Read by:* [Externally sourced memory read back later](#p-external-memory-read-back). *Risk Map controls:* `controlMemoryReferentRevalidation`, `controlUntrustedContextContainment`, `controlRetrievalAndVectorSystemIntegrity`.

<a id="f-memory-read-injection-event"></a>**Memory Read / Injection Event.** Which memory items were pulled into context for a call.

*Tier:* MUST, on 6 documented instances. See [Memory Write Event](#f-memory-write-event). *Read by:* [Externally sourced memory read back later](#p-external-memory-read-back) and [Item flagged as poisoned, then read into context](#p-poisoned-item-read). *Risk Map controls:* `controlMemoryReferentRevalidation`, `controlUntrustedContextContainment`, `controlRetrievalAndVectorSystemIntegrity`.

<a id="f-memory-provenance-source"></a>**Memory Provenance / Source.** Origin & mutability of a memory item, self-authored, owner, non-owner, or **externally editable resource**.

*Tier:* MUST, on 4 documented instances. Exposes [`AOC-10`](#a-aoc-10): a "constitution" stored as an externally editable Gist, later edited to make the agent shut down peers and send unauthorized mail. The signal is *a context-shaping memory item resolving to a mutable, non-owner-controlled source.* *Read by:* [Externally sourced memory read back later](#p-external-memory-read-back). *Risk Map controls:* `controlMemoryReferentRevalidation`, `controlUntrustedContextContainment`, `controlRetrievalAndVectorSystemIntegrity`.

<a id="f-memory-footprint-growth"></a>**Memory Footprint / Growth.** Size/growth of memory stores (per user/session), resource-exhaustion signal.

*Tier:* MUST, on 2 documented instances. Catches [`AOC-05`](#a-aoc-05) (ever-growing per-non-owner file → mail-server DoS) and [`TA-30`](#a-ta-30), a production memory index that grew without bound because the disk budget measured other tables. [`TA-30`](#a-ta-30) involved no adversary, which [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers) admits: the field detects the growth whatever caused it. *Read by:* [Memory store beyond its limit](#p-memory-beyond-limit). *Risk Map controls:* `controlMemoryReferentRevalidation`, `controlUntrustedContextContainment`, `controlRetrievalAndVectorSystemIntegrity`.

<a id="f-retrieval-event"></a>**Retrieval Event.** Query issued + documents/chunks returned + retrieval scores.

*Tier:* MUST, on 9 documented instances. RAG is the document's most-cited injection channel ([`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), [`TA-09`](#a-ta-09), [`IR-03`](#a-ir-03), [`AOC-10`](#a-aoc-10) are all retrieval-mediated). This field and **Retrieved-Content Source / Provenance** answer the halves a detection needs: *what came back*, and *where it came from and when it changed*. *Read by:* [Instructions followed from an external retrieved item](#p-retrieved-instructions-followed) and [Citation with no matching retrieval](#p-citation-without-retrieval). *Risk Map controls:* `controlRetrievalAndVectorSystemIntegrity`.

<a id="f-retrieved-content-source-provenance"></a>**Retrieved-Content Source / Provenance.** Origin, owner, trust level, and freshness (create/update time) of each retrieved item (internal doc, web, third-party, user upload).

*Tier:* MUST, on 7 documented instances. See [Retrieval Event](#f-retrieval-event). *Read by:* [Instructions followed from an external retrieved item](#p-retrieved-instructions-followed). *Risk Map controls:* `controlRetrievalAndVectorSystemIntegrity`.

<a id="f-memory-integrity-poisoning-signal"></a>**Memory Integrity / Poisoning Signal.** Integrity check / poisoning-likelihood score, cross-session isolation flag.

*Tier:* SHOULD, provider-gated. *Read by:* [Item flagged as poisoned, then read into context](#p-poisoned-item-read). *Risk Map controls:* `controlMemoryReferentRevalidation`, `controlUntrustedContextContainment`, `controlRetrievalAndVectorSystemIntegrity`.

<a id="f-memory-write-rationale"></a>**Memory Write Rationale.** The agent's stated reason for persisting *this* item, captured at the write step.

*Tier:* SHOULD, provider-gated. The analogue of Tool Selection Rationale, and [`IR-02`](#a-ir-02) is the case demanding it: the content looks innocuous and the write unremarkable; the tell is the justification the agent gives itself. *Risk Map controls:* `controlMemoryReferentRevalidation`, `controlUntrustedContextContainment`, `controlRetrievalAndVectorSystemIntegrity`.

<a id="f-retrieved-content-metadata-integrity-signal"></a>**Retrieved-Content / Metadata Integrity Signal.** Tamper/poisoning indicators on content **or its metadata/tags**.

*Tier:* SHOULD, provider-gated. Poison-RAG ([`IR-03`](#a-ir-03)) manipulates item *metadata tags* rather than content bodies, which is why the integrity signal must cover metadata. [`TA-09`](#a-ta-09) plants hidden instructions in wikis and tickets, and recently-modified retrievable documents deserve scrutiny, hence freshness folds into provenance. *Risk Map controls:* `controlRetrievalAndVectorSystemIntegrity`.

<a id="f-declared-memory-configuration"></a>**Declared Memory Configuration.** The memory store's declared identity and limits: name, type, backend, size cap, retention, and retrieval spec (top-k, scoring). The baseline that **Memory Footprint** is measured against.

*Tier:* MAY, fewer than two documented instances. [`TA-30`](#a-ta-30) is an instance (a store with no retention policy), but the silently-raised-limit scenario is absent from the corpus, and the field's job (a baseline for Memory Footprint / Growth) can be met by hard-coding known limits. *Risk Map controls:* `controlMemoryReferentRevalidation`, `controlUntrustedContextContainment`, `controlRetrievalAndVectorSystemIntegrity`.

<a id="f-declared-knowledge-source-configuration"></a>**Declared Knowledge-Source Configuration.** Each knowledge source's declared identity and contract: name, description, index/collection identity, schema, and search parameters (top-k, filters, scoring, reranker).

*Tier:* MAY, fewer than two documented instances. On the same reasoning as Declared Memory Configuration: a silently altered retrieval config or repointed index is not in the corpus, and [`IR-03`](#a-ir-03) poisons metadata, not search configuration. *Risk Map controls:* `controlRetrievalAndVectorSystemIntegrity`.
<!-- END GENERATED: fields 6.4 -->

### 1.5 Orchestration

Multi-agent and autonomous execution, where the corpus shows agentic risk compounds.

<!-- BEGIN GENERATED: fields 6.5 -->
| Field | Tier | Role | Origin | What it records | Emitted by | Grounding attacks |
| :------------ | :---- | :---------- | :-------- | :------------------------------------- | :-------------------- | :------------ |
| **Inter-Agent Message** | MUST | content | observed | Agent-to-agent messages: sender, receiver, content, channel. | `componentReasoningCore` | [`TA-25`](#a-ta-25), [`TA-27`](#a-ta-27), [`TA-31`](#a-ta-31), [`AOC-04`](#a-aoc-04), [`AOC-09`](#a-aoc-09), [`AOC-11`](#a-aoc-11), [`AOC-16`](#a-aoc-16) |
| **Background / Scheduled Task Event** | MUST | descriptor | observed | Creation or change of cron jobs, heartbeats and self-scheduled loops. | `componentReasoningCore` | [`TA-25`](#a-ta-25), [`AOC-04`](#a-aoc-04), [`AOC-10`](#a-aoc-10) |
| **Loop / Step-Count Signal** | MUST | measure | derived | Steps per run against baseline; circular exchanges between agents. | `componentReasoningCore` | [`TA-08`](#a-ta-08), [`TA-24`](#a-ta-24), [`TA-25`](#a-ta-25), [`IR-02`](#a-ir-02), [`AOC-04`](#a-aoc-04) |
| **Resource-Consumption Aggregate** | MUST | measure | derived | Token, compute, storage and outbound totals per run against a budget. | `componentReasoningCore` | [`TA-10`](#a-ta-10), [`TA-20`](#a-ta-20), *[`TA-30`](#a-ta-30)*, *[`TA-36`](#a-ta-36)*, [`AOC-04`](#a-aoc-04), [`AOC-05`](#a-aoc-05) |
| **Task / Intent Declaration** | SHOULD | descriptor | asserted | Declared purpose the run is authorized to pursue. Self-asserted. Modality: autonomous action. | `componentReasoningCore` | [`TA-24`](#a-ta-24), [`AOC-01`](#a-aoc-01), [`AOC-04`](#a-aoc-04), [`AOC-10`](#a-aoc-10) |
| **A2A Task Lifecycle Event** **[AOS]** | SHOULD | outcome | observed | Delegated-task state changes across A2A, including callback registration. Modality: A2A. | `componentReasoningCore`, `componentAgentToolTransport` | *[`AOC-04`](#a-aoc-04)*, *[`AOC-09`](#a-aoc-09)*, *[`AOC-11`](#a-aoc-11)* |
| **Peer Agent Card / Descriptor** **[AOS]** | SHOULD | descriptor | asserted | A counterparty agent's descriptor at contact, with change and verification outcome. Modality: A2A. | `componentReasoningCore` | [`TA-31`](#a-ta-31), *[`AOC-09`](#a-aoc-09)*, *[`AOC-11`](#a-aoc-11)*, *[`AOC-16`](#a-aoc-16)* |
| **Protocol Envelope Capture** **[AOS]** | MAY | content | observed | Raw MCP or A2A JSON-RPC envelope alongside the interpreted fields. | `componentAgentToolTransport` | *[`AOC-09`](#a-aoc-09)*, *[`AOC-12`](#a-aoc-12)* |

**Field entries.**

<a id="f-inter-agent-message"></a>**Inter-Agent Message.** Agent→agent messages: sender, receiver, content, channel, including capability/skill transfer.

*Tier:* MUST, on 7 documented instances. The substrate of cross-agent propagation: [`AOC-04`](#a-aoc-04) (nine-day mutual-relay loop), [`AOC-09`](#a-aoc-09) (capability transfer), [`AOC-11`](#a-aoc-11) (mass broadcast), and [`AOC-16`](#a-aoc-16): the positive case, agents sharing risk signals. *Read by:* [Inter-agent relay with no terminating step](#p-inter-agent-relay-loop), [Capability added soon after an inter-agent message](#p-capability-after-inter-agent-message) and [Input content re-emitted to another agent or store](#p-input-reemitted). *Risk Map controls:* `controlAgentExecutionBounds`, `controlAgentCapabilityNegotiation`.

<a id="f-background-scheduled-task-event"></a>**Background / Scheduled Task Event.** Creation/modification of cron jobs, heartbeats, daemons, or self-scheduled loops, incl. presence/absence of a termination condition.

*Tier:* MUST, on 3 documented instances. Captures the corpus's most striking finding: agents spawning infinite shell loops and cron jobs with **no termination condition**, converting short-lived tasks into permanent infrastructure ([`AOC-04`](#a-aoc-04), [`AOC-10`](#a-aoc-10)). *Read by:* [Background task with no end condition](#p-background-task-without-end). *Risk Map controls:* `controlAgentExecutionBounds`, `controlAgentCapabilityNegotiation`.

<a id="f-loop-step-count-signal"></a>**Loop / Step-Count Signal.** Steps or iterations per run vs baseline; circular agent-to-agent exchange detection.

*Tier:* MUST, on 5 documented instances. See [Background / Scheduled Task Event](#f-background-scheduled-task-event). *Read by:* [Inter-agent relay with no terminating step](#p-inter-agent-relay-loop) and [Long autonomous run against many external targets](#p-autonomous-run-against-external-targets). *Risk Map controls:* `controlAgentExecutionBounds`, `controlAgentCapabilityNegotiation`.

<a id="f-resource-consumption-aggregate"></a>**Resource-Consumption Aggregate.** Per-run/agent token, compute, storage, and outbound-volume totals against a budget, and, where authority is delegated, **accounted across the delegation subtree rather than per run**: individually modest runs can exhaust a principal's budget in aggregate. Where a budget is enforced, the **consumed and remaining figures ride the record of the action that consumed them** and not only the metric series, because a total cannot be recomputed after the fact from records that never carried it. That is what separates a budget denial from a budget overrun discovered later.

*Tier:* MUST, on 4 documented instances. *Read by:* [Consumption spike and model enumeration under one identity](#p-consumption-spike-with-model-enumeration) and [Inter-agent relay with no terminating step](#p-inter-agent-relay-loop). *Risk Map controls:* `controlAgentExecutionBounds`, `controlAgentCapabilityNegotiation`.

<a id="f-task-intent-declaration"></a>**Task / Intent Declaration.** The declared purpose/task the run is authorized to pursue (for goal-drift detection).

*Tier:* SHOULD, modality: autonomous action. The goal-drift anchor; [`AOC-04`](#a-aoc-04) shows agents inventing new goals beyond the requested task. *Risk Map controls:* `controlAgentExecutionBounds`, `controlAgentCapabilityNegotiation`.

<a id="f-a2a-task-lifecycle-event"></a>**A2A Task Lifecycle Event.** Delegated-task state transitions across the A2A surface: task submitted, streamed, polled, **canceled**, resubscribed, and **push-notification config set or changed**, which registers an outbound callback destination.

*Tier:* SHOULD, modality: A2A. Held by the modality gate. Its evidence is generic multi-agent incidents, not A2A-protocol incidents: [`AOC-04`](#a-aoc-04), [`AOC-09`](#a-aoc-09) and [`AOC-11`](#a-aoc-11) did not use A2A. **MUST the moment A2A is in play**; push-notification configuration in particular registers an attacker-settable egress channel. *Read by:* [Task callback registered to an undeclared destination](#p-callback-to-undeclared-destination). *Risk Map controls:* `controlAgentExecutionBounds`, `controlAgentCapabilityNegotiation`.

<a id="f-peer-agent-card-descriptor"></a>**Peer Agent Card / Descriptor.** The counterparty agent's declared descriptor as presented at contact: name, URL, version, provider, and advertised skills/capabilities, with change detection against prior contacts **and the outcome of any verification attempted against it** (signature checked, inspection request answered or refused, or unverified).

*Tier:* SHOULD, modality: A2A. Held by the modality gate. Its one A2A instance is [`TA-31`](#a-ta-31), where hosts keyed routing on a card's `name`; the rest of its grounding is generic multi-agent incidents. **MUST the moment agent cards are in play.** *Read by:* [One agent name bound to two peers](#p-agent-name-collision). *Risk Map controls:* `controlAgentExecutionBounds`, `controlAgentCapabilityNegotiation`.

<a id="f-protocol-envelope-capture"></a>**Protocol Envelope Capture.** The raw MCP / A2A JSON-RPC envelope (method, id, params) alongside the interpreted fields, preserving protocol-level detail that framework-level abstraction discards.

*Tier:* MAY, dominant value Q or A and redundant with MUST fields. Q-dominant, duplicates interpreted fields, carries raw-content privacy weight, and is not modality-gated.
<!-- END GENERATED: fields 6.5 -->

### 1.6 Identity, provenance and inventory

The identity fields address the "Quadruple Identity" problem: a **principal** authorizes an **agent** which (possibly via **other agents**) calls a **tool** that acts on **infrastructure**. Without identity at each hop, accountability collapses and confused-deputy attacks succeed. This is the ODIS problem space, and the delegation fields are SHOULD on the modality gate. Where OpenTelemetry and OCSF carry two of these identities is in [XM §2](Telemetry-Cross-Mapping-Addendum.md#2-opentelemetry).

The inventory fields describe posture rather than per-request activity. Most are governance and CVE-response signals rather than detection signals: the supply-chain fields are SHOULD on their modality, and the registry fields are MAY. The exception is the **change** signal, Capability-Set Change Event, which is detection-grade and MUST. The AgBOM fields are the structural counterpart to OWASP AOS's **Inspect** pillar.

<!-- BEGIN GENERATED: fields 6.6 -->
| Field | Tier | Role | Origin | What it records | Emitted by | Grounding attacks |
| :------------ | :---- | :---------- | :-------- | :------------------------------------- | :-------------------- | :------------ |
| **Capability-Set Change Event** **[AOS]** | MUST | descriptor | observed | A tool, server, model, knowledge source or memory store added, removed or modified at runtime. | `componentReasoningCore` | *[`TA-06`](#a-ta-06)*, [`TA-14`](#a-ta-14), [`TA-23`](#a-ta-23), [`TA-29`](#a-ta-29), [`AOC-09`](#a-aoc-09), *[`AOC-10`](#a-aoc-10)* |
| **Identities Used (per hop)** | MUST | identifier | declared | The identity behind each agent, tool and infrastructure action, per hop. | `componentIdentityProvider` | [`TA-02`](#a-ta-02), [`TA-05`](#a-ta-05), [`TA-07`](#a-ta-07), [`TA-08`](#a-ta-08), [`TA-11`](#a-ta-11), [`TA-13`](#a-ta-13), [`TA-17`](#a-ta-17), [`TA-20`](#a-ta-20), [`TA-22`](#a-ta-22), [`TA-23`](#a-ta-23), [`TA-24`](#a-ta-24), [`TA-28`](#a-ta-28), [`TA-31`](#a-ta-31), *[`IR-04`](#a-ir-04)*, [`AOC-01`](#a-aoc-01), [`AOC-02`](#a-aoc-02), [`AOC-08`](#a-aoc-08), [`AOC-11`](#a-aoc-11), [`AOC-15`](#a-aoc-15) |
| **Verified vs Displayed Identity** | MUST | identifier | observed | Verified identifier against spoofable display name, and which one authorized. | `componentIdentityProvider` | [`TA-31`](#a-ta-31), [`AOC-08`](#a-aoc-08), [`AOC-11`](#a-aoc-11), [`AOC-15`](#a-aoc-15) |
| **Originating Principal (on-behalf-of)** | SHOULD | identifier | declared | The human or service at the root of the delegation chain. Modality: delegated authority. | `componentIdentityProvider`, `componentFederationProxy` | [`AOC-01`](#a-aoc-01), [`AOC-02`](#a-aoc-02), [`AOC-08`](#a-aoc-08) |
| **Delegation Chain** | SHOULD | provenance | declared | Ordered agent hops, each integrity-bound to its parent. Modality: delegated authority. | `componentFederationProxy` | [`TA-25`](#a-ta-25), *[`AOC-04`](#a-aoc-04)*, [`AOC-09`](#a-aoc-09), *[`AOC-10`](#a-aoc-10)* |
| **Granted Authorizations / Scope** | SHOULD | descriptor | declared | Authority in effect at this hop, with the narrowing check and its rules. Modality: delegated authority. | `componentFederationProxy` | [`TA-13`](#a-ta-13), [`AOC-02`](#a-aoc-02), [`AOC-08`](#a-aoc-08), *[`AOC-10`](#a-aoc-10)* |
| **Resource Indicators + Constraints** | SHOULD | descriptor | declared | Target audience and time, purpose, rate, locality and classification limits. Modality: delegated authority. | `componentFederationProxy` | *[`TA-01`](#a-ta-01)*, *[`AOC-03`](#a-aoc-03)*, *[`AOC-05`](#a-aoc-05)* |
| **Token Exchange & Scope-Narrowing Check** **[CPEX]** | SHOULD | outcome | observed | Each token exchange: grant type, whose identity, and whether scope narrowed. Modality: token exchange. | `componentFederationProxy`, `componentIdentityProvider` | [`TA-08`](#a-ta-08), *[`IR-04`](#a-ir-04)*, *[`AOC-02`](#a-aoc-02)*, *[`AOC-08`](#a-aoc-08)* |
| **Trust-Domain Crossing & Delegation Depth** | SHOULD | measure | derived | Counterparty trust domain and delegation depth, and whether a limit was crossed. Modality: delegated authority. | `componentFederationProxy` | [`TA-11`](#a-ta-11), *[`AOC-04`](#a-aoc-04)*, *[`AOC-09`](#a-aoc-09)*, *[`AOC-11`](#a-aoc-11)* |
| **Runtime Credential / Attestation** | SHOULD | provenance | declared | Runtime-instance credential and attestation evidence, each source verified separately. Modality: cryptographic agent identity. | `componentIdentityProvider` | *[`TA-06`](#a-ta-06)*, *[`AOC-08`](#a-aoc-08)* |
| **Lifecycle State** | SHOULD | label | declared | Active, suspended or revoked, for kill-switch and revocation fan-out. Modality: cryptographic agent identity. | `componentIdentityProvider` | [`AOC-07`](#a-aoc-07), [`AOC-10`](#a-aoc-10) |
| **Tool/Agent Version** | SHOULD | identifier | declared | Version of each tool, agent and framework. Modality: dynamic third-party capability composition. | `componentToolRegistry`, `componentModelRegistry` | [`TA-06`](#a-ta-06), [`TA-16`](#a-ta-16), *[`IR-04`](#a-ir-04)* |
| **Repository / Code Path / Software Ref** | SHOULD | provenance | declared | Source provenance of tool and agent code. Modality: dynamic third-party capability composition. | `componentToolRegistry` | *[`TA-06`](#a-ta-06)*, [`TA-16`](#a-ta-16), [`TA-21`](#a-ta-21), *[`AOC-10`](#a-aoc-10)* |
| **AgBOM / Inventory Snapshot** **[AOS]** | SHOULD | descriptor | declared | Machine-readable inventory of the agent's composition, on change and on demand. Modality: supply-chain provenance. | `componentApplication`, `componentToolRegistry` | [`TA-06`](#a-ta-06), [`TA-16`](#a-ta-16), *[`IR-04`](#a-ir-04)*, *[`AOC-09`](#a-aoc-09)*, *[`AOC-10`](#a-aoc-10)* |
| **Component Dependency Graph** **[AOS]** | SHOULD | descriptor | declared | Dependency edges between inventoried components, including transitive ones. Modality: supply-chain provenance. | `componentApplication`, `componentToolRegistry` | [`TA-06`](#a-ta-06), *[`IR-04`](#a-ir-04)* |
| **Inventory Integrity Signature** **[AOS]** | SHOULD | provenance | declared | Signature over the emitted inventory, binding it to a signer. Modality: supply-chain provenance. | `componentApplication`, `componentToolRegistry` | *[`TA-06`](#a-ta-06)*, *[`IR-04`](#a-ir-04)*, *[`AOC-10`](#a-aoc-10)* |
| **Event Sequence Continuity** | SHOULD | identifier | observed | Per-session sequence number, hash-chained, for gap and reordering detection. Modality: hash-chained event streams. | `componentAuditRecordRepository` | *[`TA-17`](#a-ta-17)*, *[`AOC-01`](#a-aoc-01)*, *[`AOC-10`](#a-aoc-10)* |
| **Tool Description** | MAY | content | declared | Declared purpose of a tool, against which behavior is compared. | `componentToolRegistry` | *[`AOC-14`](#a-aoc-14)* |
| **Tool Status (active/disabled)** | MAY | label | declared | Whether a tool is meant to be reachable. | `componentToolRegistry` | *[`AOC-02`](#a-aoc-02)* |
| **Creator ID / Oncall / Creation & Update dates** | MAY | descriptor | declared | Ownership and change dates. | `componentToolRegistry`, `componentModelRegistry` | *[`TA-09`](#a-ta-09)*, *[`IR-04`](#a-ir-04)* |
| **Surfaces Supported** | MAY | descriptor | declared | Exposure map per tool. | `componentToolRegistry` | *[`AOC-08`](#a-aoc-08)* |
| **Fleet counts** | MAY | measure | derived | Fleet aggregates: agents, sessions, users, tool-call volume. | fleet level | *[`TA-06`](#a-ta-06)*, *[`TA-10`](#a-ta-10)*, *[`AOC-04`](#a-aoc-04)*, *[`AOC-05`](#a-aoc-05)* |

**Field entries.**

<a id="f-capability-set-change-event"></a>**Capability-Set Change Event.** An event emitted whenever the agent's usable capability set changes at runtime, a tool, MCP server, model, knowledge source, or memory store **discovered, added, removed, or modified**: with before/after identity and what triggered the change.

*Tier:* MUST, on 4 documented instances. Every other inventory field describes a **state**; this one describes a **transition**, and transitions are where attacks are visible. Grounded directly in [`AOC-09`](#a-aoc-09), where one agent teaches another to acquire a browser/download capability. The security event is the *acquisition*; the previous inference path ("tool-call spike + new Tool Name") fires only once the capability is exercised, and never at all for one acquired and held in reserve. Removal matters symmetrically: a guardrail tool or logging sink quietly dropped is a defense-evasion signal. It is also cheap where least expected to fire: a static capability set emits nothing. *Read by:* [Capability added soon after an inter-agent message](#p-capability-after-inter-agent-message) and [Capability or configuration change with no approval](#p-unapproved-capability-change). *Risk Map controls:* `controlAgentInventoryManagement`, `controlThirdPartyCapabilityAdmission`.

<a id="f-identities-used-per-hop"></a>**Identities Used (per hop).** Attribute every agent→user, agent→agent, agent→tool, tool→infra action to an identity + metadata; detect identity changes across a tool chain.

*Tier:* MUST, on 18 documented instances. The accountability primitive: when an agent resets its own mail server ([`AOC-01`](#a-aoc-01)), dumps 124 records ([`AOC-02`](#a-aoc-02)), or mass-mails defamation ([`AOC-11`](#a-aoc-11)), *which principal, which agent, which tool, which credential* is the first question of any response. It applies to every deployment, including the simplest single-agent one. *Read by:* [Same identity from a new source](#p-identity-from-new-source), [Same input across many identities](#p-same-input-many-identities), [Denials, then an allow, for the same operation](#p-denials-then-allow), [Guardrail blocks stop while volume continues](#p-guardrail-blocks-stop), [Input near the context limit ending on a limit or error](#p-context-limit-abuse), [Privileged MCP tool invoked by a low-privilege identity](#p-privileged-mcp-tool-low-privilege-identity), [Repeated refusals](#p-repeated-refusals), [Credential minted wider than requested](#p-credential-wider-than-requested), [Consumption spike and model enumeration under one identity](#p-consumption-spike-with-model-enumeration), [Individually authorized calls chained across identities](#p-authorized-calls-chained-across-identities) and [Sensitive input to an off-inventory AI service](#p-sensitive-input-to-off-inventory-ai). *Risk Map controls:* `controlComponentIdentityAuthentication`, `controlComponentIdentityRegistration`, `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlSenderConstrainedCredentials`, `controlSessionCredentialBindingAndLifecycle`.

<a id="f-verified-vs-displayed-identity"></a>**Verified vs Displayed Identity.** Distinguish an immutable/verified identifier from a spoofable display identity; record which was used to authorize.

*Tier:* MUST, on 4 documented instances. [`AOC-08`](#a-aoc-08) shows same-channel spoofing *detected* (the agent checked an immutable user ID) and cross-channel spoofing *succeeding* where only a display name was available. The difference between those outcomes is entirely a telemetry difference. *Read by:* [Privileged action authorized on a displayed identity](#p-privileged-action-on-displayed-identity) and [One agent name bound to two peers](#p-agent-name-collision). *Risk Map controls:* `controlComponentIdentityAuthentication`, `controlComponentIdentityRegistration`, `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlSenderConstrainedCredentials`, `controlSessionCredentialBindingAndLifecycle`.

<a id="f-originating-principal-on-behalf-of"></a>**Originating Principal (on-behalf-of).** The human/service sponsor at the root of the delegation chain.

*Tier:* SHOULD, modality: delegated authority. *Risk Map controls:* `controlComponentIdentityAuthentication`, `controlComponentIdentityRegistration`, `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlSenderConstrainedCredentials`, `controlSessionCredentialBindingAndLifecycle`, `controlAgentCredentialIsolation`.

<a id="f-delegation-chain"></a>**Delegation Chain.** Ordered lineage of prior agent hops carried across the call. Each hop carries an **integrity-protected reference to its parent** (issuer, delegation identifier, and a digest of the parent record), so lineage is verifiable from the records rather than asserted; a digest that does not match the resolved parent fails chain validation closed.

*Tier:* SHOULD, modality: delegated authority. *Risk Map controls:* `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlAgentCredentialIsolation`.

<a id="f-granted-authorizations-scope"></a>**Granted Authorizations / Scope.** Delegated authority in effect at this hop, with monotonic-narrowing check. Record the **rules the check ran against** (ODIS `attenuation_profile_ref`: a versioned identifier and content digest for the normalization and comparison rules), since "narrower" is a semantic comparison and two profiles can disagree on the same pair of scopes.

*Tier:* SHOULD, modality: delegated authority. *Risk Map controls:* `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlAgentCredentialIsolation`.

<a id="f-resource-indicators-constraints"></a>**Resource Indicators + Constraints.** Target resource audience + time/purpose/rate/locality/`data_classification` narrowing.

*Tier:* SHOULD, modality: delegated authority. *Risk Map controls:* `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlAgentCredentialIsolation`.

<a id="f-credential-minting-scope-narrowing-check"></a>**Token Exchange & Scope-Narrowing Check.** The token-exchange event at each hop: grant type (token exchange / client assertion / client credentials), whose identity the issued token represents (**end user / client application / calling workload / the enforcement point itself**), target **audience**, issuer, lifetime, and the **requested-vs-granted scope delta** verified after issuance. Detects both over-broad tokens and forwarded inbound tokens that were never narrowed.

*Tier:* SHOULD, modality: token exchange. Adds the *event* the surrounding fields only describe the state of. Forwarding a caller's inbound token is usually wrong (it is scoped for the agent, not the backend) so the **requested-vs-granted delta** is what makes a silently over-broad grant visible ([`TA-08`](#a-ta-08)). *Read by:* [Credential minted wider than requested](#p-credential-wider-than-requested). *Risk Map controls:* `controlComponentIdentityAuthentication`, `controlComponentIdentityRegistration`, `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlSenderConstrainedCredentials`, `controlSessionCredentialBindingAndLifecycle`, `controlAgentCredentialIsolation`.

<a id="f-trust-domain-crossing-delegation-depth"></a>**Trust-Domain Crossing & Delegation Depth.** The counterparty's **trust domain** and the **depth of the delegation chain** at this hop, plus whether either crossed a configured limit. Records that authority left the domain that issued it, and how many hops from the originating principal the acting agent now sits. Depth is **derived** from the chain (the OCSF [[37]](#standards--frameworks) `delegation.parent_uid` lineage or the RFC 8693 [[45]](#standards--frameworks) `act` chain), not transmitted as a counter; a transmitted copy can disagree with the chain it was derived from. The derivation holds only while every hop carries its parent link: a hop that does not is a **break in the chain**, to be recorded as such rather than read as a shorter chain ([XM §1.2](Telemetry-Cross-Mapping-Addendum.md#12-correspondence)).

*Tier:* SHOULD, modality: delegated authority. Makes an **externally-operated** counterparty legible. ODIS treats `trust_domain` and `max_depth` as policy-engine inputs rather than telemetry, which is right only while a chain stays inside one domain. Once authority crosses out of the domain that issued it, or the acting agent sits several hops from the originating principal, both become detection-grade: [`AOC-04`](#a-aoc-04)'s nine-day relay and [`AOC-09`](#a-aoc-09)'s capability transfer are both depth phenomena, and [`TA-11`](#a-ta-11) is a domain-boundary failure. See [RFC §4.6](CoSAI-AI-Telemetry-RFC.md#46-record-your-boundary-not-their-internals). *Risk Map controls:* `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlAgentCredentialIsolation`.

<a id="f-runtime-credential-attestation"></a>**Runtime Credential / Attestation.** Runtime-instance credential: `software_hash`, `attestation_evidence`, issuer, expiry, holder-key binding. Evidence is recorded **per source, each with its own issuer, validity and verification outcome**: software-provenance and runtime/workload evidence come from independent issuers, and a single collapsed value loses the independence that makes the evidence worth verifying (see **Attribute Source / Trusted-Provenance Marking**, [§1.2](#12-content-trust-verdicts-and-their-availability)).

*Tier:* SHOULD, modality: cryptographic agent identity. *Risk Map controls:* `controlComponentIdentityAuthentication`, `controlComponentIdentityRegistration`, `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlSenderConstrainedCredentials`, `controlSessionCredentialBindingAndLifecycle`.

<a id="f-lifecycle-state"></a>**Lifecycle State.** active / suspended / revoked, supports kill-switch & revocation-fanout.

*Tier:* SHOULD, modality: cryptographic agent identity. *Risk Map controls:* `controlComponentIdentityAuthentication`, `controlComponentIdentityRegistration`, `controlDelegatedAuthorizationIntegrity`, `controlDelegatedAuthorityConfinement`, `controlSenderConstrainedCredentials`, `controlSessionCredentialBindingAndLifecycle`.

<a id="f-tool-agent-version"></a>**Tool/Agent Version.** Version of each tool/agent/framework; instant CVE blast-radius answer; downgrade detection.

*Tier:* SHOULD, modality: dynamic third-party capability composition. A supply-chain response primitive, with Repository / Code Path / Software Ref. The closest call among the inventory fields: documented instances and genuine R value (CVE blast radius), held below MUST because that value is realized through a fleet-inventory process rather than per-event detection, and because it is inseparable in practice from the AgBOM fields. The WG may reasonably promote it. *Risk Map controls:* `controlToolRegistryAndDiscoveryIntegrity`.

<a id="f-repository-code-path-software-ref"></a>**Repository / Code Path / Software Ref.** Source provenance of tool/agent code (ties to signing & ODIS `approved_software_refs`).

*Tier:* SHOULD, modality: dynamic third-party capability composition. See [Tool/Agent Version](#f-tool-agent-version). *Risk Map controls:* `controlToolRegistryAndDiscoveryIntegrity`.

<a id="f-agbom-inventory-snapshot"></a>**AgBOM / Inventory Snapshot.** A structured, machine-readable inventory of the agent's composition (packages, models, capabilities (agent cards, discovered peers, MCP servers), knowledge sources, memory stores, tools) emitted on change and **on demand**. Bound to an existing BOM format rather than a bespoke one. Three formats can carry it, to different extents: **CycloneDX** [[41]](#standards--frameworks) is the only one for which an agent-runtime binding has been written (sandbox, tool scopes and endpoints, memory backend, agent-card URL, carried in its generic property bag); **SPDX 3.0** [[42]](#standards--frameworks) carries dependency, integrity and, through its AI profile, model governance; **SWID** [[43]](#standards--frameworks) carries identity, version, dependency and signing. Emit in whichever format the deployment already uses, and record which one ([XM §4.2](Telemetry-Cross-Mapping-Addendum.md#42-correspondence)).

*Tier:* SHOULD, modality: supply-chain provenance. Requires an inventory-emission capability most deployments lack; so do Component Dependency Graph and Inventory Integrity Signature. *Risk Map controls:* `controlToolRegistryAndDiscoveryIntegrity`.

<a id="f-component-dependency-graph"></a>**Component Dependency Graph.** Dependency edges between inventoried components, including transitive ones; which agent depends on which tool, which tool on which package or MCP server.

*Tier:* SHOULD, modality: supply-chain provenance. The complete answer to CVE blast radius: [`TA-06`](#a-ta-06) is a vulnerability in a *framework* beneath the agent, and reaching it requires transitive edges. *Risk Map controls:* `controlToolRegistryAndDiscoveryIntegrity`.

<a id="f-inventory-attestation-signature"></a>**Inventory Integrity Signature.** Cryptographic signature over the emitted inventory (signature value + key identifier), binding the declared composition to a signer.

*Tier:* SHOULD, modality: supply-chain provenance. An inventory a compromised agent can rewrite is worth little. The limit: a signature proves who asserted the inventory, not that the assertion is true, which is the subject of Attribute Source / Trusted-Provenance Marking (§1.2). *Risk Map controls:* `controlToolRegistryAndDiscoveryIntegrity`.

<a id="f-event-sequence-continuity"></a>**Event Sequence Continuity.** Per-session monotonic sequence number enabling gap and reordering detection. The stream **SHOULD be hash-chained**, and where chained the **chain head SHOULD be periodically signed and published outside the emitter's trust domain**. That is the minimum that lets a verifier distinguish a gap from a suppression.

*Tier:* SHOULD, modality: hash-chained event streams. The minimum defense against selective suppression by a compromised agent: sequence numbers make omission visible as a gap rather than invisible as silence. Grounded analogically ([§4.2](#42-the-telemetry-plane)). *Read by:* [Gap in the event sequence](#p-event-sequence-gap). *Risk Map controls:* `controlAuditTrailCompleteness`, `controlAuditTrailIntegrityVerification`, `controlAuditRecordRepositoryIndependence`.

<a id="f-tool-description"></a>**Tool Description.** Declared purpose: detects misleadingly-described ("read-only" but writes) tools.

*Tier:* MAY, fewer than two documented instances. No documented instance turns on a tool whose declared purpose misdescribes its behavior; [`AOC-14`](#a-aoc-14) motivates it analogically. A change to the description is already caught by **Tool Definition Digest**. *Risk Map controls:* `controlToolRegistryAndDiscoveryIntegrity`.

<a id="f-tool-status"></a>**Tool Status (active/disabled).** Detects calls to tools that should be unreachable.

*Tier:* MAY, fewer than two documented instances. No documented instance involves a call to a tool that should have been unreachable; [`AOC-02`](#a-aoc-02) motivates it analogically. *Risk Map controls:* `controlToolRegistryAndDiscoveryIntegrity`.

<a id="f-creator-id-oncall-creation-update-dates"></a>**Creator ID / Oncall / Creation & Update dates.** Ownership, age-based risk, change-correlation for IR speed; recently-changed assets/content correlate with attack timelines.

*Tier:* MAY, fewer than two documented instances. Its value is response routing (who owns the asset) and change correlation. No documented instance turns on it, and the freshness signal it offers for retrieved content is carried by **Retrieved-Content Source / Provenance**. *Risk Map controls:* `controlToolRegistryAndDiscoveryIntegrity`.

<a id="f-surfaces-supported"></a>**Surfaces Supported.** Exposure map per tool.

*Tier:* MAY, dominant value Q or A and redundant with MUST fields. An exposure map is inventory and audit material; the surface an event actually arrived on is **Surface / App** (MUST). *Risk Map controls:* `controlToolRegistryAndDiscoveryIntegrity`.

<a id="f-fleet-counts"></a>**Fleet counts** (agents by framework/type; sessions L1/L7/L28; users MAU/power-user; tool-call volume & agent↔tool map; surface & status breakdowns). Aggregate anomaly, shadow-AI, and CVE-exposure signals.

*Tier:* MAY, redundant with MUST fields. Each count is an aggregate over per-event MUST fields (Agent (Runtime) Instance ID, Session / Turn / Step IDs, Identities Used, Tool Call I/O), so it can be computed where it is needed.
<!-- END GENERATED: fields 6.6 -->

### 1.7 Training data and training infrastructure

These fields are an independent track ([RFC §6.7](CoSAI-AI-Telemetry-RFC.md#67-training-data-and-training-infrastructure)). Their emitters are the data and training components and the compute that hosts training and serving, not the agent runtime, and none of them joins on the identifiers of §1.1. All three are SHOULD on their modality. Training-Data Source / Provenance also meets the evidence test, which does not lift a modality-gated field ([RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers)).

<!-- BEGIN GENERATED: fields 6.7 -->
| Field | Tier | Role | Origin | What it records | Emitted by | Grounding attacks |
| :------------ | :---- | :---------- | :-------- | :------------------------------------- | :-------------------- | :------------ |
| **Training-Data Item Digest** | SHOULD | provenance | derived | Digest of each training item at curation, checked against the content fetched. Modality: training or fine-tuning on externally sourced data. | `componentDataFilteringAndProcessing`, `componentTrainingData` | [`TA-33`](#a-ta-33) |
| **Training-Data Source / Provenance** | SHOULD | provenance | observed | Source, contributor and acquisition of each training document. Modality: training or fine-tuning on externally sourced data. | `componentDataSources`, `componentTrainingData` | [`TA-33`](#a-ta-33), [`TA-34`](#a-ta-34), *[`TA-35`](#a-ta-35)* |
| **Compute Job Submission** | SHOULD | descriptor | observed | Each job submitted to a training or serving compute framework, with its submitter. Modality: self-operated training or serving compute. | `componentModelFrameworksAndCode`, `componentRuntimeHosting` | [`TA-36`](#a-ta-36) |

**Field entries.**

<a id="f-training-data-item-digest"></a>**Training-Data Item Digest.** For each training item: the content digest taken when it was curated, the digest of the content fetched for training, the source URL, the fetch time, and whether the two match. A mismatch is an event. A dataset distributed as a list of URLs is fetched anew by every downloader, so the check belongs at fetch, not only at curation.

*Tier:* SHOULD, modality: training or fine-tuning on externally sourced data. Grounded by [`TA-33`](#a-ta-33), where domains named in dataset indexes changed hands after indexing and downloads continued; the per-item hash the source proposes is this field, and several LAION datasets now publish one. Held at SHOULD by its modality: a deployment that trains on no externally sourced data has nothing for it to record. *Risk Map controls:* `controlTrainingDataManagement`, `controlModelAndDataIntegrityManagement`.

<a id="f-training-data-source-provenance"></a>**Training-Data Source / Provenance.** Per document, not per dataset: the source (URL, repository, crawl, vendor, user feedback), the owner or contributing account where known, how it was acquired, when it was ingested, and the dataset version it entered.

*Tier:* SHOULD, modality: training or fine-tuning on externally sourced data. Grounded by [`TA-33`](#a-ta-33) (the owner of a source changed after indexing) and [`TA-34`](#a-ta-34) (a near-constant number of documents installs a backdoor whatever the corpus size, so dataset-level statistics cannot reveal it, and finding the documents after a backdoor is found needs their per-document origin); [`TA-35`](#a-ta-35) motivates it analogically. The two instances meet the evidence test; the modality gate holds the field at SHOULD (RFC §4.7). *Risk Map controls:* `controlTrainingDataManagement`, `controlTrainingDataSanitization`.

<a id="f-compute-job-submission-event"></a>**Compute Job Submission.** A job submitted to a training or serving framework or scheduler: the submitter identity and whether it authenticated, the source address, the entrypoint or command, the image or code reference, the resources requested, and the cluster.

*Tier:* SHOULD, modality: self-operated training or serving compute. Grounded by [`TA-36`](#a-ta-36), where unauthenticated jobs on internet-exposed Ray clusters ran cryptominers and harvested credentials for at least seven months. An unauthenticated submission is the attack state; an entrypoint that is not a training or serving workload is the mining signature. It is the first field for `componentRuntimeHosting`. Held at SHOULD by its modality: a deployment on managed inference runs no jobs of its own. *Risk Map controls:* `controlSecureByDefaultMLTooling`, `controlModelAndDataAccessControls`.
<!-- END GENERATED: fields 6.7 -->

## 2. Correlation Patterns

Raw fields are evidence; detection comes from correlation.

A four-year measurement study of a production security operations center (115 million alerts, 2018 to 2022) found **24 K to 134 K alerts per day, of which 0.01% corresponded to true attacks or compromises**; 27% were attack attempts and 49% benign triggers [[50]](#standards--frameworks). The corollary is a staffing one, and it is why fields are tiered by detection value rather than collected for completeness: a trail no analyst can read is not an asset.

> **This section is the document's cross-step view.** Fields are organized by implementation step (§1, [RFC §6](CoSAI-AI-Telemetry-RFC.md#6-field-catalog)). Two mechanisms carry detection across steps: **Action Type** (§1.1) normalizes what an operation *is*, distinguishing LLM-call from tool-call from memory-op from message-send regardless of which component performed it, and the patterns below correlate fields across steps rather than within one. What neither supplies is a normalized identity for the *same* operation carried by different protocols, so a tool call over MCP and one over A2A are described separately; **Protocol Envelope Capture** (§1.5) preserves that difference rather than erasing it.

Each pattern is placed at the **stage** where it can first fire, the stage at which its last condition is observed: entry, decision, action, persistence, egress, or the telemetry plane. Its **minimum tier** is the weakest tier among the fields it reads and joins on, so a deployment collecting only MUST fields can run every pattern whose minimum tier is MUST. Conditions hold together and in order unless the pattern says it fires on any one of them. A pattern **catches** an attack when the attack's documented instance contains every field the pattern reads; it catches it *analogically* when the attack motivates those fields but its instance does not contain them all, as in §1. Within a stage, patterns are ordered by minimum tier, then name. [§2.7](#27-coverage) lists, for every attack, the patterns that catch it, or why none does.

<!-- BEGIN GENERATED: patterns -->
| Pattern | Stage | Minimum tier | Catches |
| :------------------------------- | :---------- | :---- | :-------------------- |
| [MCP server version not the approved one](#p-mcp-server-version-unapproved) | entry | MUST | [`TA-16`](#a-ta-16) |
| [Obfuscated content in the instruction configuration](#p-obfuscated-instruction-config) | entry | MUST | [`TA-21`](#a-ta-21) |
| [Pre-filled prompt telling the assistant to remember a source](#p-prefilled-prompt-to-remember) | entry | MUST | [`TA-32`](#a-ta-32) |
| [Same identity from a new source](#p-identity-from-new-source) | entry | MUST | [`AOC-15`](#a-aoc-15); analogically [`IR-04`](#a-ir-04) |
| [Same input across many identities](#p-same-input-many-identities) | entry | MUST | none in the corpus |
| [Tool definition changed after approval](#p-tool-definition-changed) | entry | MUST | [`TA-29`](#a-ta-29) |
| [Denials, then an allow, for the same operation](#p-denials-then-allow) | decision | MUST | [`AOC-02`](#a-aoc-02), [`AOC-08`](#a-aoc-08) |
| [Guardrail blocks stop while volume continues](#p-guardrail-blocks-stop) | decision | MUST | [`TA-22`](#a-ta-22) |
| [Inference parameters off the approved baseline](#p-inference-parameters-off-baseline) | decision | MUST | none in the corpus |
| [Input near the context limit ending on a limit or error](#p-context-limit-abuse) | decision | MUST | [`TA-04`](#a-ta-04), [`TA-10`](#a-ta-10) |
| [Instructions followed from an external retrieved item](#p-retrieved-instructions-followed) | decision | MUST | [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), [`TA-09`](#a-ta-09), [`TA-40`](#a-ta-40) |
| [Instructions followed from an untrusted-data segment](#p-untrusted-data-instructions-followed) | decision | MUST | [`TA-01`](#a-ta-01), [`TA-39`](#a-ta-39), [`TA-40`](#a-ta-40) |
| [Model change, or error and stop-reason spike, for one provider](#p-model-or-provider-anomaly) | decision | MUST | [`AOC-06`](#a-aoc-06) |
| [Operation duration off baseline for its token count](#p-duration-per-token-off-baseline) | decision | MUST | [`TA-10`](#a-ta-10) |
| [Privileged action authorized on a displayed identity](#p-privileged-action-on-displayed-identity) | decision | MUST | [`AOC-08`](#a-aoc-08) |
| [Privileged MCP tool invoked by a low-privilege identity](#p-privileged-mcp-tool-low-privilege-identity) | decision | MUST | [`TA-13`](#a-ta-13) |
| [Refusals, then a completion, in one session](#p-refusals-then-completion) | decision | MUST | [`TA-07`](#a-ta-07), [`IR-01`](#a-ir-01); analogically [`TA-35`](#a-ta-35), [`TA-38`](#a-ta-38) |
| [Repeated refusals](#p-repeated-refusals) | decision | MUST | [`IR-01`](#a-ir-01), [`AOC-12`](#a-aoc-12), [`AOC-13`](#a-aoc-13), [`AOC-14`](#a-aoc-14); analogically [`TA-35`](#a-ta-35), [`TA-38`](#a-ta-38) |
| [Credential minted wider than requested](#p-credential-wider-than-requested) | decision | SHOULD | [`TA-08`](#a-ta-08); analogically [`AOC-02`](#a-aoc-02), [`AOC-08`](#a-aoc-08) |
| [Data or access across a tenant boundary](#p-cross-tenant-access) | decision | SHOULD | [`TA-11`](#a-ta-11), [`TA-17`](#a-ta-17) |
| [Code execution with no sandbox](#p-unsandboxed-code-execution) | action | MUST | [`TA-06`](#a-ta-06); analogically [`AOC-02`](#a-aoc-02) |
| [Consumption spike and model enumeration under one identity](#p-consumption-spike-with-model-enumeration) | action | MUST | [`TA-20`](#a-ta-20) |
| [Individually authorized calls chained across identities](#p-authorized-calls-chained-across-identities) | action | MUST | [`TA-08`](#a-ta-08) |
| [Inter-agent relay with no terminating step](#p-inter-agent-relay-loop) | action | MUST | [`AOC-04`](#a-aoc-04) |
| [Long autonomous run against many external targets](#p-autonomous-run-against-external-targets) | action | MUST | [`TA-24`](#a-ta-24) |
| [New tool name with a rise in tool calls](#p-new-tool-with-call-spike) | action | MUST | [`TA-06`](#a-ta-06), [`TA-08`](#a-ta-08), [`AOC-02`](#a-aoc-02), [`AOC-10`](#a-aoc-10) |
| [Untrusted attachment, then a destructive tool call](#p-untrusted-attachment-to-destructive-tool) | action | MUST | [`TA-26`](#a-ta-26) |
| [Untrusted content acted on in a later turn](#p-untrusted-content-acted-on-later) | action | MUST | [`TA-19`](#a-ta-19) |
| [Capability reached with no mediation record](#p-unmediated-capability) | action | SHOULD | [`AOC-14`](#a-aoc-14); analogically [`TA-06`](#a-ta-06) |
| [High-impact action without a covering approval](#p-action-without-covering-approval) | action | SHOULD | [`TA-15`](#a-ta-15), [`TA-23`](#a-ta-23), [`TA-29`](#a-ta-29), [`AOC-01`](#a-aoc-01), [`AOC-02`](#a-aoc-02), [`AOC-07`](#a-aoc-07), [`AOC-11`](#a-aoc-11) |
| [One agent name bound to two peers](#p-agent-name-collision) | action | SHOULD | [`TA-31`](#a-ta-31) |
| [Background task with no end condition](#p-background-task-without-end) | persistence | MUST | [`TA-25`](#a-ta-25), [`AOC-04`](#a-aoc-04), [`AOC-10`](#a-aoc-10) |
| [Capability added soon after an inter-agent message](#p-capability-after-inter-agent-message) | persistence | MUST | [`AOC-09`](#a-aoc-09) |
| [Capability or configuration change with no approval](#p-unapproved-capability-change) | persistence | MUST | [`TA-14`](#a-ta-14), [`TA-23`](#a-ta-23), [`TA-29`](#a-ta-29) |
| [Externally sourced memory read back later](#p-external-memory-read-back) | persistence | MUST | [`TA-18`](#a-ta-18), [`TA-32`](#a-ta-32), [`IR-02`](#a-ir-02), [`AOC-10`](#a-aoc-10) |
| [Memory store beyond its limit](#p-memory-beyond-limit) | persistence | MUST | [`TA-30`](#a-ta-30), [`AOC-05`](#a-aoc-05) |
| [Item flagged as poisoned, then read into context](#p-poisoned-item-read) | persistence | SHOULD | [`TA-18`](#a-ta-18), [`IR-02`](#a-ir-02), [`IR-05`](#a-ir-05); analogically [`TA-32`](#a-ta-32) |
| [Autonomous trigger, untrusted content, new egress](#p-zero-click-to-new-egress) | egress | MUST | [`TA-01`](#a-ta-01) |
| [Citation with no matching retrieval](#p-citation-without-retrieval) | egress | MUST | [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), [`IR-03`](#a-ir-03) |
| [Input content re-emitted to another agent or store](#p-input-reemitted) | egress | MUST | [`TA-27`](#a-ta-27) |
| [Output link carrying session data](#p-output-link-carrying-data) | egress | MUST | [`TA-01`](#a-ta-01), [`TA-03`](#a-ta-03) |
| [Response reproduces the system prompt](#p-system-prompt-reproduced) | egress | MUST | [`TA-07`](#a-ta-07), [`TA-40`](#a-ta-40) |
| [Sensitive input to an off-inventory AI service](#p-sensitive-input-to-off-inventory-ai) | egress | MUST | [`TA-05`](#a-ta-05) |
| [Tool arguments carry data the request did not supply](#p-unrequested-data-in-tool-arguments) | egress | MUST | [`TA-15`](#a-ta-15), [`TA-29`](#a-ta-29) |
| [Untrusted input, then a tool call, then egress to a new destination](#p-untrusted-input-to-new-egress) | egress | MUST | [`TA-01`](#a-ta-01), [`TA-12`](#a-ta-12) |
| [Egress under accumulated session taint](#p-egress-under-session-taint) | egress | SHOULD | [`TA-01`](#a-ta-01), [`AOC-03`](#a-aoc-03) |
| [Task callback registered to an undeclared destination](#p-callback-to-undeclared-destination) | egress | SHOULD | analogically [`AOC-11`](#a-aoc-11) |
| [Call routed outside the restriction in force](#p-route-outside-restriction) | egress | MAY | analogically [`AOC-06`](#a-aoc-06) |
| [Enforcement point unreached, operation proceeds](#p-enforcement-point-fail-open) | plane | MUST | [`TA-01`](#a-ta-01); analogically [`TA-10`](#a-ta-10) |
| [Hook coverage or destination changes mid-run](#p-hook-coverage-changed) | plane | MUST | [`TA-17`](#a-ta-17), [`TA-37`](#a-ta-37) |
| [Self-asserted attribute contradicts the authority](#p-self-asserted-attribute-contradicted) | plane | MUST | [`AOC-01`](#a-aoc-01), [`AOC-07`](#a-aoc-07), [`AOC-08`](#a-aoc-08), [`AOC-10`](#a-aoc-10), [`AOC-15`](#a-aoc-15) |
| [Gap in the event sequence](#p-event-sequence-gap) | plane | SHOULD | analogically [`TA-17`](#a-ta-17), [`AOC-01`](#a-aoc-01), [`AOC-10`](#a-aoc-10) |

### 2.1 Entry: input arrives

<a id="p-mcp-server-version-unapproved"></a>**MCP server version not the approved one.** Implementation rug pull under an adopted name. Minimum tier MUST. Fires when:

1. **MCP Server Identity & Primitive** reports a version, package or publisher not in the approved inventory, under an approved name.

*Joins on* [MCP Server Identity & Primitive](#f-mcp-server-identity-primitive). *Enriched by* [Tool/Agent Version](#f-tool-agent-version), [Repository / Code Path / Software Ref](#f-repository-code-path-software-ref), [AgBOM / Inventory Snapshot](#f-agbom-inventory-snapshot) and [Output Egress Destination](#f-output-egress-destination). *Baseline:* Approved name and version per server. *Catches* [`TA-16`](#a-ta-16).

<a id="p-obfuscated-instruction-config"></a>**Obfuscated content in the instruction configuration.** Instruction-file poisoning. Minimum tier MUST. Fires when:

1. The **System Prompt / Instruction Config** loaded for a run contains content flagged by **Encoded / Obfuscated Payload Indicator**.

*Joins on* [Agent (Runtime) Instance ID](#f-agent-runtime-instance-id). *Reads* [System Prompt / Instruction Config](#f-system-prompt-instruction-config) and [Encoded / Obfuscated Payload Indicator](#f-encoded-obfuscated-payload-indicator). *Enriched by* [Repository / Code Path / Software Ref](#f-repository-code-path-software-ref) and [Attribute Source / Trusted-Provenance Marking](#f-attribute-source-trusted-provenance-marking). *Catches* [`TA-21`](#a-ta-21).

<a id="p-prefilled-prompt-to-remember"></a>**Pre-filled prompt telling the assistant to remember a source.** Memory or recommendation poisoning through a link. Minimum tier MUST. Fires when:

1. **Input Source / Channel** records that the turn arrived pre-filled from a link or URL parameter, not typed.
2. The **Model Input** tells the assistant to remember, trust or prefer a named source.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Input Source / Channel](#f-input-source-channel) and [Model Input](#f-model-input). *Enriched by* [Memory Write Event](#f-memory-write-event) and [Memory Provenance / Source](#f-memory-provenance-source). *Baseline:* Turns per channel; a pre-filled turn is unusual for most users. *Catches* [`TA-32`](#a-ta-32).

<a id="p-identity-from-new-source"></a>**Same identity from a new source.** Credential theft or session hijack. Minimum tier MUST. Fires when:

1. An identity appears from a **Source host / IP** outside its history.

*Joins on* [Identities Used (per hop)](#f-identities-used-per-hop). *Reads* [Source host / IP + request metadata](#f-source-host-ip-request-metadata). *Enriched by* [Surface / App](#f-surface-app). *Baseline:* Source history per identity. *Catches* [`AOC-15`](#a-aoc-15); analogically [`IR-04`](#a-ir-04).

<a id="p-same-input-many-identities"></a>**Same input across many identities.** Automated injection campaign. Minimum tier MUST. Fires when:

1. The same **Model Input** content hash arrives under many distinct **Identities Used** within a window.

*Joins on* [Model Input](#f-model-input). *Reads* [Identities Used (per hop)](#f-identities-used-per-hop). *Enriched by* [Source host / IP + request metadata](#f-source-host-ip-request-metadata). *Baseline:* Distinct identities per input hash in ordinary traffic. *Catches* none in the corpus. *Motivation:* Template reuse in [`IR-01`](#a-ir-01); no corpus entry records one payload under many identities.

<a id="p-tool-definition-changed"></a>**Tool definition changed after approval.** Tool definition rug pull. Minimum tier MUST. Fires when:

1. The **Tool Definition Digest** at invocation differs from the digest approved for the same tool name and server.

*Joins on* [MCP Server Identity & Primitive](#f-mcp-server-identity-primitive). *Reads* [Tool Definition Digest](#f-tool-definition-digest). *Enriched by* [Tool Call I/O](#f-tool-call-io) and [Human Approval / Elicitation Event](#f-human-approval-elicitation-event). *Baseline:* The approved digest per tool. *Catches* [`TA-29`](#a-ta-29).

### 2.2 Decision: model, authorization and identity

<a id="p-denials-then-allow"></a>**Denials, then an allow, for the same operation.** Policy probing; an authorization bypass found. Minimum tier MUST. Fires when:

1. The **Authorization Decision Record** denies an operation repeatedly for one identity or source.
2. The same operation is later allowed, or the deny codes shift.

*Joins on* [Identities Used (per hop)](#f-identities-used-per-hop). *Reads* [Authorization Decision Record](#f-authorization-decision-record). *Enriched by* [Source host / IP + request metadata](#f-source-host-ip-request-metadata) and [Policy Reason Code](#f-policy-reason-code). *Catches* [`AOC-02`](#a-aoc-02), [`AOC-08`](#a-aoc-08).

<a id="p-guardrail-blocks-stop"></a>**Guardrail blocks stop while volume continues.** Guardrail bypass operated at scale. Minimum tier MUST. Fires when:

1. **Guardrail (Input) Verdict** blocks repeatedly for an identity, then stops while request volume continues.
2. **Guardrail (Output) Verdict** flags output for the same identity.

*Joins on* [Identities Used (per hop)](#f-identities-used-per-hop). *Reads* [Guardrail (Input) Verdict](#f-guardrail-input-verdict) and [Guardrail (Output) Verdict](#f-guardrail-output-verdict). *Enriched by* [LLM Refusal](#f-llm-refusal) and [Organization / Tenant ID](#f-organization-tenant-id). *Catches* [`TA-22`](#a-ta-22).

<a id="p-inference-parameters-off-baseline"></a>**Inference parameters off the approved baseline.** Configuration tampering that widens extraction or jailbreak. Minimum tier MUST. Fires when:

1. **Inference Parameters** on a call differ from the approved baseline: temperature raised, stop sequences removed, `max_tokens` raised.

*Reads* [Inference Parameters](#f-inference-parameters). *Enriched by* [System Prompt / Instruction Config](#f-system-prompt-instruction-config), [LLM Refusal](#f-llm-refusal) and [Response / Model Output](#f-response-model-output). *Baseline:* Approved parameters per deployment. *Catches* none in the corpus. *Motivation:* Per-request overrides of decoding configuration; no corpus entry changes it.

<a id="p-context-limit-abuse"></a>**Input near the context limit ending on a limit or error.** Context-window abuse: denial of service, cost blow-up or divergence. Minimum tier MUST. Fires when:

1. **Input / Output Token Counts** approach the context window or `max_tokens` in **Inference Parameters**.
2. The completion ends on a limit (**Stop Reason**) or an **LLM Error / Exception**.
3. It repeats from the same source.

*Joins on* [Identities Used (per hop)](#f-identities-used-per-hop). *Reads* [Input / Output Token Counts](#f-input-output-token-counts), [Inference Parameters](#f-inference-parameters) and [Stop Reason](#f-stop-reason). *Enriched by* [LLM Error / Exception](#f-llm-error-exception), [Resource-Consumption Aggregate](#f-resource-consumption-aggregate), [Source host / IP + request metadata](#f-source-host-ip-request-metadata) and [Model Input](#f-model-input). *Catches* [`TA-04`](#a-ta-04), [`TA-10`](#a-ta-10).

<a id="p-retrieved-instructions-followed"></a>**Instructions followed from an external retrieved item.** RAG injection or knowledge-base poisoning. Minimum tier MUST. Fires when:

1. A **Retrieval Event** returns an item whose **Retrieved-Content Source / Provenance** is external or recently modified.
2. The **Response / Model Output** in the same turn follows instructions from that item.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Retrieval Event](#f-retrieval-event), [Retrieved-Content Source / Provenance](#f-retrieved-content-source-provenance) and [Response / Model Output](#f-response-model-output). *Catches* [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), [`TA-09`](#a-ta-09), [`TA-40`](#a-ta-40).

<a id="p-untrusted-data-instructions-followed"></a>**Instructions followed from an untrusted-data segment.** Indirect prompt injection through content the model is asked to analyze, such as logs, samples or mail. Minimum tier MUST. Fires when:

1. **Input Trust Classification** marks a segment of the turn untrusted-data.
2. The **Response / Model Output** in the same turn follows instructions from that segment.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Input Trust Classification](#f-input-trust-classification) and [Response / Model Output](#f-response-model-output). *Enriched by* [Input Source / Channel](#f-input-source-channel), [Model Input](#f-model-input) and [Guardrail (Input) Verdict](#f-guardrail-input-verdict). *Catches* [`TA-01`](#a-ta-01), [`TA-39`](#a-ta-39), [`TA-40`](#a-ta-40).

<a id="p-model-or-provider-anomaly"></a>**Model change, or error and stop-reason spike, for one provider.** Model substitution or provider-side interference. Minimum tier MUST. Fires on any of:

1. **Model Name + Version** changes for a deployment with no recorded change.
2. **LLM Error / Exception** and abnormal **Stop Reason** rates rise for one provider.

*Reads* [Model Name + Version](#f-model-name-version), [LLM Error / Exception](#f-llm-error-exception) and [Stop Reason](#f-stop-reason). *Enriched by* [Provider / Endpoint Identity](#f-provider-endpoint-identity). *Baseline:* Model and error-rate history per deployment. *Catches* [`AOC-06`](#a-aoc-06).

<a id="p-duration-per-token-off-baseline"></a>**Operation duration off baseline for its token count.** Sponge input or compute exhaustion. Minimum tier MUST. Fires when:

1. **Execution Status** records a duration far above the model's baseline for the **Input / Output Token Counts** of the call.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Execution Status](#f-execution-status) and [Input / Output Token Counts](#f-input-output-token-counts). *Enriched by* [Model Name + Version](#f-model-name-version), [Inference Parameters](#f-inference-parameters), [Source host / IP + request metadata](#f-source-host-ip-request-metadata) and [Resource-Consumption Aggregate](#f-resource-consumption-aggregate). *Baseline:* Duration per token, per model. *Catches* [`TA-10`](#a-ta-10).

<a id="p-privileged-action-on-displayed-identity"></a>**Privileged action authorized on a displayed identity.** Identity spoofing or confused deputy. Minimum tier MUST. Fires when:

1. **Verified vs Displayed Identity** shows the authorizing principal matched on display name only.
2. The **Authorization Decision Record** allows a privileged operation on that basis.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Verified vs Displayed Identity](#f-verified-vs-displayed-identity) and [Authorization Decision Record](#f-authorization-decision-record). *Enriched by* [Surface / App](#f-surface-app) and [Granted Authorizations / Scope](#f-granted-authorizations-scope). *Catches* [`AOC-08`](#a-aoc-08).

<a id="p-privileged-mcp-tool-low-privilege-identity"></a>**Privileged MCP tool invoked by a low-privilege identity.** Privilege escalation at the MCP tool boundary. Minimum tier MUST. Fires when:

1. An identity without the privilege invokes a privileged MCP tool (**Identities Used**, **MCP Server Identity & Primitive**).
2. The **Authorization Decision Record** allows it, or records no decision at the tool boundary.

*Joins on* [MCP Server Identity & Primitive](#f-mcp-server-identity-primitive). *Reads* [Identities Used (per hop)](#f-identities-used-per-hop) and [Authorization Decision Record](#f-authorization-decision-record). *Enriched by* [Granted Authorizations / Scope](#f-granted-authorizations-scope) and [Tool Error / Exception](#f-tool-error-exception). *Catches* [`TA-13`](#a-ta-13).

<a id="p-refusals-then-completion"></a>**Refusals, then a completion, in one session.** Jailbreak or extraction succeeded after probing. Minimum tier MUST. Fires when:

1. **LLM Refusal** fires on several turns of a session.
2. A later turn of the same session, on similar **Model Input**, gets no refusal.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [LLM Refusal](#f-llm-refusal) and [Model Input](#f-model-input). *Enriched by* [Execution Status](#f-execution-status) and [Response / Model Output](#f-response-model-output). *Catches* [`TA-07`](#a-ta-07), [`IR-01`](#a-ir-01); analogically [`TA-35`](#a-ta-35), [`TA-38`](#a-ta-38).

<a id="p-repeated-refusals"></a>**Repeated refusals.** An attack attempt in progress, resisted or probing. Minimum tier MUST. Fires when:

1. **LLM Refusal** fires repeatedly within a session, or for one identity across sessions.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids) and [Identities Used (per hop)](#f-identities-used-per-hop). *Reads* [LLM Refusal](#f-llm-refusal). *Enriched by* [Model Input](#f-model-input) and [Guardrail (Input) Verdict](#f-guardrail-input-verdict). *Catches* [`IR-01`](#a-ir-01), [`AOC-12`](#a-aoc-12), [`AOC-13`](#a-aoc-13), [`AOC-14`](#a-aoc-14); analogically [`TA-35`](#a-ta-35), [`TA-38`](#a-ta-38).

<a id="p-credential-wider-than-requested"></a>**Credential minted wider than requested.** Over-broad delegation or confused deputy. Minimum tier SHOULD. Fires when:

1. A **Token Exchange & Scope-Narrowing Check** records a granted scope wider than requested, or an inbound token forwarded unnarrowed.

*Joins on* [Identities Used (per hop)](#f-identities-used-per-hop). *Reads* [Token Exchange & Scope-Narrowing Check](#f-credential-minting-scope-narrowing-check). *Enriched by* [Granted Authorizations / Scope](#f-granted-authorizations-scope). *Catches* [`TA-08`](#a-ta-08); analogically [`AOC-02`](#a-aoc-02), [`AOC-08`](#a-aoc-08).

<a id="p-cross-tenant-access"></a>**Data or access across a tenant boundary.** Cross-tenant bleed. Minimum tier SHOULD. Fires on any of:

1. A response, retrieval or memory read served to one **Organization / Tenant ID** carries another tenant's data.
2. An **Authorization Decision Record** allows an operation on another tenant's resource.

*Joins on* [Organization / Tenant ID](#f-organization-tenant-id). *Reads* [Authorization Decision Record](#f-authorization-decision-record). *Enriched by* [Identities Used (per hop)](#f-identities-used-per-hop), [Retrieval Event](#f-retrieval-event) and [Memory Read / Injection Event](#f-memory-read-injection-event). *Catches* [`TA-11`](#a-ta-11), [`TA-17`](#a-ta-17).

### 2.3 Action: tool calls and execution

<a id="p-unsandboxed-code-execution"></a>**Code execution with no sandbox.** Unsandboxed execution reachable from model output. Minimum tier MUST. Fires when:

1. A code-execution **Tool Call I/O** runs with **Execution Environment / Sandbox** recording none.

*Joins on* [Tool Execution ID](#f-tool-execution-id). *Reads* [Execution Environment / Sandbox](#f-execution-environment-sandbox) and [Tool Call I/O](#f-tool-call-io). *Enriched by* [Tool Type / Trust Boundary](#f-tool-type-trust-boundary). *Catches* [`TA-06`](#a-ta-06); analogically [`AOC-02`](#a-aoc-02).

<a id="p-consumption-spike-with-model-enumeration"></a>**Consumption spike and model enumeration under one identity.** Stolen-credential model access (LLMjacking). Minimum tier MUST. Fires when:

1. For one identity, **Resource-Consumption Aggregate** rises far above its baseline.
2. Its calls enumerate or switch to models (**Model Name + Version**) it did not use before.

*Joins on* [Identities Used (per hop)](#f-identities-used-per-hop). *Reads* [Resource-Consumption Aggregate](#f-resource-consumption-aggregate) and [Model Name + Version](#f-model-name-version). *Enriched by* [Input / Output Token Counts](#f-input-output-token-counts), [Provider / Endpoint Identity](#f-provider-endpoint-identity) and [Source host / IP + request metadata](#f-source-host-ip-request-metadata). *Baseline:* Consumption and model set per identity. *Catches* [`TA-20`](#a-ta-20).

<a id="p-authorized-calls-chained-across-identities"></a>**Individually authorized calls chained across identities.** Tool-chaining privilege escalation. Minimum tier MUST. Fires when:

1. A run's **Tool Call I/O** sequence passes a credential or identifier from one call's output into a later call's input.
2. **Identities Used** changes within the chain.
3. Each call is individually allowed (**Authorization Decision Record**).

*Joins on* [Workflow / Run ID](#f-workflow-run-id) and [Trace Context (propagated)](#f-trace-context-propagated). *Reads* [Tool Call I/O](#f-tool-call-io), [Identities Used (per hop)](#f-identities-used-per-hop) and [Authorization Decision Record](#f-authorization-decision-record). *Enriched by* [Tool ACL / Required Scope](#f-tool-acl-required-scope) and [Loop / Step-Count Signal](#f-loop-step-count-signal). *Catches* [`TA-08`](#a-ta-08).

<a id="p-inter-agent-relay-loop"></a>**Inter-agent relay with no terminating step.** Multi-agent resource-exhaustion loop. Minimum tier MUST. Fires when:

1. **Inter-Agent Message** volume between the same agents rises without a terminating step.
2. **Loop / Step-Count Signal** exceeds its limit.
3. **Resource-Consumption Aggregate** climbs against the run budget.

*Joins on* [Workflow / Run ID](#f-workflow-run-id) and [Trace Context (propagated)](#f-trace-context-propagated). *Reads* [Inter-Agent Message](#f-inter-agent-message), [Loop / Step-Count Signal](#f-loop-step-count-signal) and [Resource-Consumption Aggregate](#f-resource-consumption-aggregate). *Catches* [`AOC-04`](#a-aoc-04).

<a id="p-autonomous-run-against-external-targets"></a>**Long autonomous run against many external targets.** Agent operated as an attack framework. Minimum tier MUST. Fires when:

1. A run's **Loop / Step-Count Signal** is long and its **Tool Call I/O** reaches many external targets.
2. The activity does not match the declared task, or none is declared.

*Joins on* [Workflow / Run ID](#f-workflow-run-id). *Reads* [Loop / Step-Count Signal](#f-loop-step-count-signal) and [Tool Call I/O](#f-tool-call-io). *Enriched by* [Task / Intent Declaration](#f-task-intent-declaration), [LLM Refusal](#f-llm-refusal) and [Trigger Type & Source Event](#f-trigger-type-source-event). *Catches* [`TA-24`](#a-ta-24).

<a id="p-new-tool-with-call-spike"></a>**New tool name with a rise in tool calls.** Agent reaching an unauthorized capability. Minimum tier MUST. Fires when:

1. A **Tool Name** not seen for this agent appears.
2. **Tool Call I/O** volume for the run rises above its baseline.

*Joins on* [Agent (Runtime) Instance ID](#f-agent-runtime-instance-id). *Reads* [Tool Name](#f-tool-name) and [Tool Call I/O](#f-tool-call-io). *Enriched by* [Resource-Consumption Aggregate](#f-resource-consumption-aggregate) and [Capability-Set Change Event](#f-capability-set-change-event). *Baseline:* Tool set and call rate per agent. *Catches* [`TA-06`](#a-ta-06), [`TA-08`](#a-ta-08), [`AOC-02`](#a-aoc-02), [`AOC-10`](#a-aoc-10).

<a id="p-untrusted-attachment-to-destructive-tool"></a>**Untrusted attachment, then a destructive tool call.** Attachment-borne injection reaching a shell. Minimum tier MUST. Fires when:

1. **Content Modality & Attachment Identity** records a file or image that **Input Trust Classification** marks untrusted.
2. A destructive or shell **Tool Call I/O** follows in the same run.

*Joins on* [Workflow / Run ID](#f-workflow-run-id). *Reads* [Content Modality & Attachment Identity](#f-content-modality-attachment-identity), [Input Trust Classification](#f-input-trust-classification) and [Tool Call I/O](#f-tool-call-io). *Enriched by* [Guardrail (Input) Verdict](#f-guardrail-input-verdict) and [Action Type](#f-action-type). *Catches* [`TA-26`](#a-ta-26).

<a id="p-untrusted-content-acted-on-later"></a>**Untrusted content acted on in a later turn.** Delayed tool invocation. Minimum tier MUST. Fires when:

1. **Input Trust Classification** marks content untrusted in one turn.
2. A sensitive **Tool Call I/O** in a later turn of the same session follows it, with no new user request.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Input Trust Classification](#f-input-trust-classification) and [Tool Call I/O](#f-tool-call-io). *Enriched by* [Model Input](#f-model-input). *Catches* [`TA-19`](#a-ta-19).

<a id="p-unmediated-capability"></a>**Capability reached with no mediation record.** Reference-monitor bypass. Minimum tier SHOULD. Fires when:

1. A **Tool Call I/O** reaches a capability whose **Tool Type / Trust Boundary** requires mediation.
2. No **Mediation Coverage & Bypass Path** record shows it passed the reference monitor.

*Joins on* [Tool Execution ID](#f-tool-execution-id). *Reads* [Tool Call I/O](#f-tool-call-io), [Tool Type / Trust Boundary](#f-tool-type-trust-boundary) and [Mediation Coverage & Bypass Path](#f-mediation-coverage-bypass-path). *Catches* [`AOC-14`](#a-aoc-14); analogically [`TA-06`](#a-ta-06).

<a id="p-action-without-covering-approval"></a>**High-impact action without a covering approval.** Missing, disabled or replayed human authorization. Minimum tier SHOULD. Fires when:

1. A high-impact operation executes.
2. No **Human Approval / Elicitation Event** covers it, or the approval does not cover the executed arguments, or approval was switched off.

*Joins on* [Tool Execution ID](#f-tool-execution-id). *Reads* [Human Approval / Elicitation Event](#f-human-approval-elicitation-event). *Enriched by* [Tool Call I/O](#f-tool-call-io), [Authorization Decision Record](#f-authorization-decision-record) and [Capability-Set Change Event](#f-capability-set-change-event). *Catches* [`TA-15`](#a-ta-15), [`TA-23`](#a-ta-23), [`TA-29`](#a-ta-29), [`AOC-01`](#a-aoc-01), [`AOC-02`](#a-aoc-02), [`AOC-07`](#a-aoc-07), [`AOC-11`](#a-aoc-11).

<a id="p-agent-name-collision"></a>**One agent name bound to two peers.** Agent name collision; wrong-peer dispatch. Minimum tier SHOULD. Fires when:

1. Within one host, an **Agent Name** resolves to more than one **Peer Agent Card / Descriptor**, endpoint or enrolled identity.
2. **Verified vs Displayed Identity** shows the requests addressed to the name reach a different peer.

*Joins on* [Agent Name](#f-agent-name). *Reads* [Peer Agent Card / Descriptor](#f-peer-agent-card-descriptor) and [Verified vs Displayed Identity](#f-verified-vs-displayed-identity). *Enriched by* [Identities Used (per hop)](#f-identities-used-per-hop) and [Inter-Agent Message](#f-inter-agent-message). *Catches* [`TA-31`](#a-ta-31).

### 2.4 Persistence: memory, background tasks and configuration

<a id="p-background-task-without-end"></a>**Background task with no end condition.** Runaway automation or persistence. Minimum tier MUST. Fires when:

1. A **Background / Scheduled Task Event** creates a task with no end condition or expiry.
2. The task outlives the run that created it.

*Joins on* [Agent (Runtime) Instance ID](#f-agent-runtime-instance-id). *Reads* [Background / Scheduled Task Event](#f-background-scheduled-task-event). *Enriched by* [Action Type](#f-action-type) and [Trigger Type & Source Event](#f-trigger-type-source-event). *Catches* [`TA-25`](#a-ta-25), [`AOC-04`](#a-aoc-04), [`AOC-10`](#a-aoc-10).

<a id="p-capability-after-inter-agent-message"></a>**Capability added soon after an inter-agent message.** Cross-agent capability transfer. Minimum tier MUST. Fires when:

1. A **Capability-Set Change Event** adds a tool or MCP server,
2. within a window after an **Inter-Agent Message** to that agent.

*Joins on* [Agent (Runtime) Instance ID](#f-agent-runtime-instance-id). *Reads* [Capability-Set Change Event](#f-capability-set-change-event) and [Inter-Agent Message](#f-inter-agent-message). *Enriched by* [Peer Agent Card / Descriptor](#f-peer-agent-card-descriptor) and [Tool Name](#f-tool-name). *Catches* [`AOC-09`](#a-aoc-09).

<a id="p-unapproved-capability-change"></a>**Capability or configuration change with no approval.** Configuration rug pull, or a safeguard switched off. Minimum tier MUST. Fires when:

1. A **Capability-Set Change Event** records a changed launch command, arguments or approval setting for an approved tool or agent.
2. No approval accompanies the change.

*Joins on* [Agent (Runtime) Instance ID](#f-agent-runtime-instance-id). *Reads* [Capability-Set Change Event](#f-capability-set-change-event). *Enriched by* [Execution Environment / Sandbox](#f-execution-environment-sandbox) and [Human Approval / Elicitation Event](#f-human-approval-elicitation-event). *Catches* [`TA-14`](#a-ta-14), [`TA-23`](#a-ta-23), [`TA-29`](#a-ta-29).

<a id="p-external-memory-read-back"></a>**Externally sourced memory read back later.** Memory poisoning or indirect corruption. Minimum tier MUST. Fires when:

1. A **Memory Write Event** has a **Memory Provenance / Source** that is a non-owner or external source.
2. The item is read back (**Memory Read / Injection Event**) in a later session.
3. Behavior in that session departs from the request.

*Reads* [Memory Write Event](#f-memory-write-event), [Memory Provenance / Source](#f-memory-provenance-source) and [Memory Read / Injection Event](#f-memory-read-injection-event). *Enriched by* [Observation / Thought (reasoning trace)](#f-observation-thought-reasoning-trace) and [Memory Integrity / Poisoning Signal](#f-memory-integrity-poisoning-signal). *Catches* [`TA-18`](#a-ta-18), [`TA-32`](#a-ta-32), [`IR-02`](#a-ir-02), [`AOC-10`](#a-aoc-10).

<a id="p-memory-beyond-limit"></a>**Memory store beyond its limit.** Memory-store exhaustion or silent limit removal. Minimum tier MUST. Fires when:

1. **Memory Footprint / Growth** exceeds the store's declared or hard-coded limit, or grows with no matching retention event.

*Reads* [Memory Footprint / Growth](#f-memory-footprint-growth). *Enriched by* [Declared Memory Configuration](#f-declared-memory-configuration) and [Memory Write Event](#f-memory-write-event). *Baseline:* The declared limit, or a hard-coded one. *Catches* [`TA-30`](#a-ta-30), [`AOC-05`](#a-aoc-05).

<a id="p-poisoned-item-read"></a>**Item flagged as poisoned, then read into context.** Memory or retrieval poisoning taking effect. Minimum tier SHOULD. Fires when:

1. A **Memory Integrity / Poisoning Signal** flags an item.
2. The item is later read into context (**Memory Read / Injection Event**).

*Reads* [Memory Integrity / Poisoning Signal](#f-memory-integrity-poisoning-signal) and [Memory Read / Injection Event](#f-memory-read-injection-event). *Enriched by* [Memory Provenance / Source](#f-memory-provenance-source) and [Retrieved-Content / Metadata Integrity Signal](#f-retrieved-content-metadata-integrity-signal). *Catches* [`TA-18`](#a-ta-18), [`IR-02`](#a-ir-02), [`IR-05`](#a-ir-05); analogically [`TA-32`](#a-ta-32).

### 2.5 Egress: data leaves

<a id="p-zero-click-to-new-egress"></a>**Autonomous trigger, untrusted content, new egress.** Zero-click injection-to-exfiltration. Minimum tier MUST. Fires when:

1. **Trigger Type & Source Event** marks the run autonomous.
2. **Input Trust Classification** marks the triggering content untrusted.
3. The run reaches an **Output Egress Destination** not seen for this agent.

*Joins on* [Workflow / Run ID](#f-workflow-run-id). *Reads* [Trigger Type & Source Event](#f-trigger-type-source-event), [Input Trust Classification](#f-input-trust-classification) and [Output Egress Destination](#f-output-egress-destination). *Catches* [`TA-01`](#a-ta-01).

<a id="p-citation-without-retrieval"></a>**Citation with no matching retrieval.** Fabricated or attacker-planted citation. Minimum tier MUST. Fires on any of:

1. A **Citations / Source Attribution** entry resolves to no item a **Retrieval Event** returned in the session.
2. A citation resolves to an item whose provenance is external or recently modified.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Citations / Source Attribution](#f-citations-source-attribution) and [Retrieval Event](#f-retrieval-event). *Enriched by* [Retrieved-Content Source / Provenance](#f-retrieved-content-source-provenance) and [Output Egress Destination](#f-output-egress-destination). *Catches* [`TA-01`](#a-ta-01), [`TA-02`](#a-ta-02), [`IR-03`](#a-ir-03).

<a id="p-input-reemitted"></a>**Input content re-emitted to another agent or store.** Self-replicating prompt propagation. Minimum tier MUST. Fires when:

1. A **Model Input** content hash reappears in an outbound **Inter-Agent Message**, or in content stored where it is retrieved again.

*Joins on* [Trace Context (propagated)](#f-trace-context-propagated). *Reads* [Model Input](#f-model-input) and [Inter-Agent Message](#f-inter-agent-message). *Enriched by* [Retrieved-Content Source / Provenance](#f-retrieved-content-source-provenance), [Memory Write Event](#f-memory-write-event) and [Trigger Type & Source Event](#f-trigger-type-source-event). *Catches* [`TA-27`](#a-ta-27).

<a id="p-output-link-carrying-data"></a>**Output link carrying session data.** Exfiltration through a rendered link or image. Minimum tier MUST. Fires when:

1. A **Response / Model Output** contains a URL whose path or query carries data from the session.
2. The client fetches it (**Output Egress Destination**).

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Response / Model Output](#f-response-model-output) and [Output Egress Destination](#f-output-egress-destination). *Enriched by* [Source host / IP + request metadata](#f-source-host-ip-request-metadata). *Catches* [`TA-01`](#a-ta-01), [`TA-03`](#a-ta-03).

<a id="p-system-prompt-reproduced"></a>**Response reproduces the system prompt.** System-prompt extraction. Minimum tier MUST. Fires when:

1. The **Response / Model Output** is similar to the **System Prompt / Instruction Config** in force.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Response / Model Output](#f-response-model-output) and [System Prompt / Instruction Config](#f-system-prompt-instruction-config). *Enriched by* [LLM Refusal](#f-llm-refusal). *Baseline:* A similarity threshold. *Catches* [`TA-07`](#a-ta-07), [`TA-40`](#a-ta-40).

<a id="p-sensitive-input-to-off-inventory-ai"></a>**Sensitive input to an off-inventory AI service.** Shadow AI use leaking data. Minimum tier MUST. Fires when:

1. An **Agent Name** or **Surface / App** not in the inventory receives **Model Input**.
2. The input is sensitive by content or by the tool's classification.

*Joins on* [Identities Used (per hop)](#f-identities-used-per-hop). *Reads* [Agent Name](#f-agent-name), [Surface / App](#f-surface-app) and [Model Input](#f-model-input). *Enriched by* [Tool Privacy Classification](#f-tool-privacy-classification) and [Guardrail (Input) Verdict](#f-guardrail-input-verdict). *Baseline:* The agent inventory. *Catches* [`TA-05`](#a-ta-05).

<a id="p-unrequested-data-in-tool-arguments"></a>**Tool arguments carry data the request did not supply.** Exfiltration through tool arguments: tool poisoning or shadowing. Minimum tier MUST. Fires when:

1. A **Tool Call I/O** to an MCP tool carries in its arguments content the request did not supply: credential files, chat history, other tools' output.
2. The tool was discovered from that server in the same session (**MCP Server Identity & Primitive**).

*Joins on* [Tool Execution ID](#f-tool-execution-id). *Reads* [Tool Call I/O](#f-tool-call-io) and [MCP Server Identity & Primitive](#f-mcp-server-identity-primitive). *Enriched by* [Tool Definition Digest](#f-tool-definition-digest), [Output Egress Destination](#f-output-egress-destination) and [Human Approval / Elicitation Event](#f-human-approval-elicitation-event). *Catches* [`TA-15`](#a-ta-15), [`TA-29`](#a-ta-29).

<a id="p-untrusted-input-to-new-egress"></a>**Untrusted input, then a tool call, then egress to a new destination.** Injection-to-exfiltration chain. Minimum tier MUST. Fires when:

1. **Input Trust Classification** marks a segment untrusted.
2. A later **Tool Call I/O** in the same trace carries content derived from it.
3. **Output Egress Destination** is one not seen for this agent.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids) and [Trace Context (propagated)](#f-trace-context-propagated). *Reads* [Input Trust Classification](#f-input-trust-classification), [Tool Call I/O](#f-tool-call-io) and [Output Egress Destination](#f-output-egress-destination). *Baseline:* Egress destinations per agent. *Catches* [`TA-01`](#a-ta-01), [`TA-12`](#a-ta-12).

<a id="p-egress-under-session-taint"></a>**Egress under accumulated session taint.** Write-down attempt or injection-driven exfiltration. Minimum tier SHOULD. Fires when:

1. **Session Taint Labels & Information-Flow Decisions** show the session tainted by untrusted or sensitive content.
2. An egress with a clean payload is attempted under that taint (**Output Egress Destination**); a denial records the attempt, an allow the leak.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Session Taint Labels & Information-Flow Decisions](#f-session-taint-labels-information-flow-decisions) and [Output Egress Destination](#f-output-egress-destination). *Enriched by* [Authorization Decision Record](#f-authorization-decision-record). *Catches* [`TA-01`](#a-ta-01), [`AOC-03`](#a-aoc-03).

<a id="p-callback-to-undeclared-destination"></a>**Task callback registered to an undeclared destination.** Covert egress through delegated-task callbacks. Minimum tier SHOULD. Fires when:

1. An **A2A Task Lifecycle Event** registers a push-notification callback.
2. Its destination (**Output Egress Destination**) is not among the peer's declared endpoints or the agent's egress history.

*Joins on* [Workflow / Run ID](#f-workflow-run-id). *Reads* [A2A Task Lifecycle Event](#f-a2a-task-lifecycle-event) and [Output Egress Destination](#f-output-egress-destination). *Enriched by* [Peer Agent Card / Descriptor](#f-peer-agent-card-descriptor). *Catches* analogically [`AOC-11`](#a-aoc-11).

<a id="p-route-outside-restriction"></a>**Call routed outside the restriction in force.** Data-residency or routing-policy violation. Minimum tier MAY. Fires when:

1. A **Backend / Route Restriction Decision** is in force for the session.
2. The call is served by a **Provider / Endpoint Identity** outside it.

*Reads* [Backend / Route Restriction Decision](#f-backend-route-restriction-decision) and [Provider / Endpoint Identity](#f-provider-endpoint-identity). *Enriched by* [Session Taint Labels & Information-Flow Decisions](#f-session-taint-labels-information-flow-decisions). *Catches* analogically [`AOC-06`](#a-aoc-06).

### 2.6 Telemetry plane

<a id="p-enforcement-point-fail-open"></a>**Enforcement point unreached, operation proceeds.** Control-plane starvation or guardrail bypass by failing open. Minimum tier MUST. Fires when:

1. **Enforcement-Point Availability & Failure Mode** records a callout unreached or timed out.
2. The operation it guards proceeds.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Enforcement-Point Availability & Failure Mode](#f-enforcement-point-availability-failure-mode). *Enriched by* [Guardrail (Input) Verdict](#f-guardrail-input-verdict), [Guardrail (Output) Verdict](#f-guardrail-output-verdict), [Resource-Consumption Aggregate](#f-resource-consumption-aggregate) and [Source host / IP + request metadata](#f-source-host-ip-request-metadata). *Catches* [`TA-01`](#a-ta-01); analogically [`TA-10`](#a-ta-10).

<a id="p-hook-coverage-changed"></a>**Hook coverage or destination changes mid-run.** Telemetry plane disabled or redirected. Minimum tier MUST. Fires when:

1. **Instrumentation Coverage / Hook Status** records a hook disabled, or reporting to a new destination, during a run.

*Joins on* [Agent (Runtime) Instance ID](#f-agent-runtime-instance-id). *Reads* [Instrumentation Coverage / Hook Status](#f-instrumentation-coverage-hook-attestation). *Enriched by* [Event Sequence Continuity](#f-event-sequence-continuity) and [Action Type](#f-action-type). *Catches* [`TA-17`](#a-ta-17), [`TA-37`](#a-ta-37).

<a id="p-self-asserted-attribute-contradicted"></a>**Self-asserted attribute contradicts the authority.** Agent falsifying its own state or claims. Minimum tier MUST. Fires when:

1. **Attribute Source / Trusted-Provenance Marking** marks an attribute self-asserted.
2. The authority-supplied value for the same attribute differs.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Attribute Source / Trusted-Provenance Marking](#f-attribute-source-trusted-provenance-marking). *Enriched by* [Verified vs Displayed Identity](#f-verified-vs-displayed-identity) and [Authorization Decision Record](#f-authorization-decision-record). *Catches* [`AOC-01`](#a-aoc-01), [`AOC-07`](#a-aoc-07), [`AOC-08`](#a-aoc-08), [`AOC-10`](#a-aoc-10), [`AOC-15`](#a-aoc-15).

<a id="p-event-sequence-gap"></a>**Gap in the event sequence.** Selective suppression of telemetry. Minimum tier SHOULD. Fires when:

1. **Event Sequence Continuity** shows a gap or reordering in a session.

*Joins on* [Session / Turn / Step IDs](#f-session-turn-step-ids). *Reads* [Event Sequence Continuity](#f-event-sequence-continuity). *Enriched by* [Instrumentation Coverage / Hook Status](#f-instrumentation-coverage-hook-attestation). *Catches* analogically [`TA-17`](#a-ta-17), [`AOC-01`](#a-aoc-01), [`AOC-10`](#a-aoc-10).

### 2.7 Coverage

Every attack in §3, with the patterns that catch it; an attack no pattern catches records why.

| Attack | Caught by | Analogically |
| :---------- | :------------------------------- | :-------------------- |
| [`TA-01`](#a-ta-01) EchoLeak | [Instructions followed from an external retrieved item](#p-retrieved-instructions-followed), [Instructions followed from an untrusted-data segment](#p-untrusted-data-instructions-followed), [Autonomous trigger, untrusted content, new egress](#p-zero-click-to-new-egress), [Citation with no matching retrieval](#p-citation-without-retrieval), [Output link carrying session data](#p-output-link-carrying-data), [Untrusted input, then a tool call, then egress to a new destination](#p-untrusted-input-to-new-egress), [Egress under accumulated session taint](#p-egress-under-session-taint), [Enforcement point unreached, operation proceeds](#p-enforcement-point-fail-open) |  |
| [`TA-02`](#a-ta-02) Slack AI exfiltration | [Instructions followed from an external retrieved item](#p-retrieved-instructions-followed), [Citation with no matching retrieval](#p-citation-without-retrieval) |  |
| [`TA-03`](#a-ta-03) Bard markdown exfil | [Output link carrying session data](#p-output-link-carrying-data) |  |
| [`TA-04`](#a-ta-04) Training-data extraction | [Input near the context limit ending on a limit or error](#p-context-limit-abuse) |  |
| [`TA-05`](#a-ta-05) Samsung leak | [Sensitive input to an off-inventory AI service](#p-sensitive-input-to-off-inventory-ai) |  |
| [`TA-06`](#a-ta-06) LangChain RCE | [Code execution with no sandbox](#p-unsandboxed-code-execution), [New tool name with a rise in tool calls](#p-new-tool-with-call-spike) | [Capability reached with no mediation record](#p-unmediated-capability) |
| [`TA-07`](#a-ta-07) System-prompt extraction | [Refusals, then a completion, in one session](#p-refusals-then-completion), [Response reproduces the system prompt](#p-system-prompt-reproduced) |  |
| [`TA-08`](#a-ta-08) Tool-chaining escalation | [Credential minted wider than requested](#p-credential-wider-than-requested), [Individually authorized calls chained across identities](#p-authorized-calls-chained-across-identities), [New tool name with a rise in tool calls](#p-new-tool-with-call-spike) |  |
| [`TA-09`](#a-ta-09) RAG KB poisoning | [Instructions followed from an external retrieved item](#p-retrieved-instructions-followed) |  |
| [`TA-10`](#a-ta-10) Context-window DoS | [Input near the context limit ending on a limit or error](#p-context-limit-abuse), [Operation duration off baseline for its token count](#p-duration-per-token-off-baseline) | [Enforcement point unreached, operation proceeds](#p-enforcement-point-fail-open) |
| [`TA-11`](#a-ta-11) Asana MCP cross-tenant | [Data or access across a tenant boundary](#p-cross-tenant-access) |  |
| [`TA-12`](#a-ta-12) Supabase MCP | [Untrusted input, then a tool call, then egress to a new destination](#p-untrusted-input-to-new-egress) |  |
| [`TA-13`](#a-ta-13) WordPress AI Engine | [Privileged MCP tool invoked by a low-privilege identity](#p-privileged-mcp-tool-low-privilege-identity) |  |
| [`TA-14`](#a-ta-14) MCPoison | [Capability or configuration change with no approval](#p-unapproved-capability-change) |  |
| [`TA-15`](#a-ta-15) MCP tool-description poisoning | [High-impact action without a covering approval](#p-action-without-covering-approval), [Tool arguments carry data the request did not supply](#p-unrequested-data-in-tool-arguments) |  |
| [`TA-16`](#a-ta-16) `postmark-mcp` rug pull | [MCP server version not the approved one](#p-mcp-server-version-unapproved) |  |
| [`TA-17`](#a-ta-17) DifyTap | [Data or access across a tenant boundary](#p-cross-tenant-access), [Hook coverage or destination changes mid-run](#p-hook-coverage-changed) | [Gap in the event sequence](#p-event-sequence-gap) |
| [`TA-18`](#a-ta-18) ChatGPT memory poisoning | [Externally sourced memory read back later](#p-external-memory-read-back), [Item flagged as poisoned, then read into context](#p-poisoned-item-read) |  |
| [`TA-19`](#a-ta-19) Delayed tool invocation | [Untrusted content acted on in a later turn](#p-untrusted-content-acted-on-later) |  |
| [`TA-20`](#a-ta-20) LLMjacking | [Consumption spike and model enumeration under one identity](#p-consumption-spike-with-model-enumeration) |  |
| [`TA-21`](#a-ta-21) Rules File Backdoor | [Obfuscated content in the instruction configuration](#p-obfuscated-instruction-config) |  |
| [`TA-22`](#a-ta-22) Storm-2139 | [Guardrail blocks stop while volume continues](#p-guardrail-blocks-stop) |  |
| [`TA-23`](#a-ta-23) OpenClaw 1-click RCE | [High-impact action without a covering approval](#p-action-without-covering-approval), [Capability or configuration change with no approval](#p-unapproved-capability-change) |  |
| [`TA-24`](#a-ta-24) GTG-1002 | [Long autonomous run against many external targets](#p-autonomous-run-against-external-targets) |  |
| [`TA-25`](#a-ta-25) Multi-agent framework vs government systems | [Background task with no end condition](#p-background-task-without-end) |  |
| [`TA-26`](#a-ta-26) Computer-use data destruction | [Untrusted attachment, then a destructive tool call](#p-untrusted-attachment-to-destructive-tool) |  |
| [`TA-27`](#a-ta-27) Morris II | [Input content re-emitted to another agent or store](#p-input-reemitted) |  |
| [`TA-28`](#a-ta-28) SesameOp | *None.* Outside the deployment: the backdoor ran on a compromised host and used the provider API from there, so no instrumented AI system carries the activity. Detection belongs to endpoint and network monitoring of provider API use; within a deployment, Output Egress Destination records what its own calls send. |  |
| [`TA-29`](#a-ta-29) WhatsApp MCP sleeper rug pull | [Tool definition changed after approval](#p-tool-definition-changed), [High-impact action without a covering approval](#p-action-without-covering-approval), [Capability or configuration change with no approval](#p-unapproved-capability-change), [Tool arguments carry data the request did not supply](#p-unrequested-data-in-tool-arguments) |  |
| [`TA-30`](#a-ta-30) OpenClaw memory index unbounded growth | [Memory store beyond its limit](#p-memory-beyond-limit) |  |
| [`TA-31`](#a-ta-31) Agent name collision | [One agent name bound to two peers](#p-agent-name-collision) |  |
| [`TA-32`](#a-ta-32) AI recommendation poisoning | [Pre-filled prompt telling the assistant to remember a source](#p-prefilled-prompt-to-remember), [Externally sourced memory read back later](#p-external-memory-read-back) | [Item flagged as poisoned, then read into context](#p-poisoned-item-read) |
| [`TA-33`](#a-ta-33) Split-view dataset poisoning | *None.* Training time: Training-Data Item Digest records the mismatch at fetch as one event, which needs no correlation. Its runtime edges are analogical, to retrieval, where the same split view applies. |  |
| [`TA-34`](#a-ta-34) Near-constant poison count | *None.* Training time: Training-Data Source / Provenance locates the poisoned documents once a backdoor is found. At inference the backdoor shows only as a trigger in Model Input and anomalous Response / Model Output, and no pattern reads that pair without a baseline for the model. |  |
| [`TA-35`](#a-ta-35) Basilisk Venom | *None.* Training time, and the causation is inferred: its edges are analogical, so no pattern catches it as an instance. The inference-time step is the ordinary jailbreak that the refusal patterns read. | [Refusals, then a completion, in one session](#p-refusals-then-completion), [Repeated refusals](#p-repeated-refusals) |
| [`TA-36`](#a-ta-36) ShadowRay | *None.* Training and serving infrastructure: Compute Job Submission records the unauthenticated submission as one event, which needs no correlation. Its edges to runtime-path fields are analogical. |  |
| [`TA-37`](#a-ta-37) LangSmith trace replica injection | [Hook coverage or destination changes mid-run](#p-hook-coverage-changed) |  |
| [`TA-38`](#a-ta-38) macOS.Gaslight | *None.* No AI system's handling of the sample is documented, so every edge is analogical. It motivates a pattern comparing errors a response claims against Model Error / Exception, not yet proposed. | [Refusals, then a completion, in one session](#p-refusals-then-completion), [Repeated refusals](#p-repeated-refusals) |
| [`TA-39`](#a-ta-39) Log-field prompt injection | [Instructions followed from an untrusted-data segment](#p-untrusted-data-instructions-followed) |  |
| [`TA-40`](#a-ta-40) LogInject | [Instructions followed from an external retrieved item](#p-retrieved-instructions-followed), [Instructions followed from an untrusted-data segment](#p-untrusted-data-instructions-followed), [Response reproduces the system prompt](#p-system-prompt-reproduced) |  |
| [`IR-01`](#a-ir-01) Breaking the Prompt Wall | [Refusals, then a completion, in one session](#p-refusals-then-completion), [Repeated refusals](#p-repeated-refusals) |  |
| [`IR-02`](#a-ir-02) MINJA | [Externally sourced memory read back later](#p-external-memory-read-back), [Item flagged as poisoned, then read into context](#p-poisoned-item-read) |  |
| [`IR-03`](#a-ir-03) Poison-RAG | [Citation with no matching retrieval](#p-citation-without-retrieval) |  |
| [`IR-04`](#a-ir-04) Capital One | *None.* A non-AI incident, carried for field overlap; its edges are analogical. [Same identity from a new source](#p-identity-from-new-source) catches it analogically. | [Same identity from a new source](#p-identity-from-new-source) |
| [`IR-05`](#a-ir-05) AGENTPOISON | [Item flagged as poisoned, then read into context](#p-poisoned-item-read) |  |
| [`AOC-01`](#a-aoc-01) Disproportionate Response | [High-impact action without a covering approval](#p-action-without-covering-approval), [Self-asserted attribute contradicts the authority](#p-self-asserted-attribute-contradicted) | [Gap in the event sequence](#p-event-sequence-gap) |
| [`AOC-02`](#a-aoc-02) Compliance w/ Non-Owner | [Denials, then an allow, for the same operation](#p-denials-then-allow), [New tool name with a rise in tool calls](#p-new-tool-with-call-spike), [High-impact action without a covering approval](#p-action-without-covering-approval) | [Credential minted wider than requested](#p-credential-wider-than-requested), [Code execution with no sandbox](#p-unsandboxed-code-execution) |
| [`AOC-03`](#a-aoc-03) Disclosure of Sensitive Info | [Egress under accumulated session taint](#p-egress-under-session-taint) |  |
| [`AOC-04`](#a-aoc-04) Waste of Resources / Looping | [Inter-agent relay with no terminating step](#p-inter-agent-relay-loop), [Background task with no end condition](#p-background-task-without-end) |  |
| [`AOC-05`](#a-aoc-05) Denial-of-Service | [Memory store beyond its limit](#p-memory-beyond-limit) |  |
| [`AOC-06`](#a-aoc-06) Agents Reflect Provider Values | [Model change, or error and stop-reason spike, for one provider](#p-model-or-provider-anomaly) | [Call routed outside the restriction in force](#p-route-outside-restriction) |
| [`AOC-07`](#a-aoc-07) Agent Harm | [High-impact action without a covering approval](#p-action-without-covering-approval), [Self-asserted attribute contradicts the authority](#p-self-asserted-attribute-contradicted) |  |
| [`AOC-08`](#a-aoc-08) Owner Identity Spoofing | [Denials, then an allow, for the same operation](#p-denials-then-allow), [Privileged action authorized on a displayed identity](#p-privileged-action-on-displayed-identity), [Self-asserted attribute contradicts the authority](#p-self-asserted-attribute-contradicted) | [Credential minted wider than requested](#p-credential-wider-than-requested) |
| [`AOC-09`](#a-aoc-09) Collaboration / Knowledge Sharing | [Capability added soon after an inter-agent message](#p-capability-after-inter-agent-message) |  |
| [`AOC-10`](#a-aoc-10) Agent Corruption | [New tool name with a rise in tool calls](#p-new-tool-with-call-spike), [Background task with no end condition](#p-background-task-without-end), [Externally sourced memory read back later](#p-external-memory-read-back), [Self-asserted attribute contradicts the authority](#p-self-asserted-attribute-contradicted) | [Gap in the event sequence](#p-event-sequence-gap) |
| [`AOC-11`](#a-aoc-11) Libelous within Community | [High-impact action without a covering approval](#p-action-without-covering-approval) | [Task callback registered to an undeclared destination](#p-callback-to-undeclared-destination) |
| [`AOC-12`](#a-aoc-12) Prompt Injection via Broadcast | [Repeated refusals](#p-repeated-refusals) |  |
| [`AOC-13`](#a-aoc-13) Email Spoofing request | [Repeated refusals](#p-repeated-refusals) |  |
| [`AOC-14`](#a-aoc-14) Data Tampering | [Repeated refusals](#p-repeated-refusals), [Capability reached with no mediation record](#p-unmediated-capability) |  |
| [`AOC-15`](#a-aoc-15) Social Engineering | [Same identity from a new source](#p-identity-from-new-source), [Self-asserted attribute contradicts the authority](#p-self-asserted-attribute-contradicted) |  |
| [`AOC-16`](#a-aoc-16) Inter-Agent Coordination | *None.* An emergent defense, not an attack: agents shared risk signals about a probing researcher. A pattern would detect the defense. Its Inter-Agent Message edge supports reading such signals. |  |
<!-- END GENERATED: patterns -->

---

## 3. Attack & Incident Inventory

> **Reading the tables.** The *detecting fields* named in each row are defined in §1, with what to capture and their tier; [RFC §6](CoSAI-AI-Telemetry-RFC.md#6-field-catalog) is the index. The *primary components* are CoSAI Risk Map component IDs ([RFC §6](CoSAI-AI-Telemetry-RFC.md#6-field-catalog)), given here without the `component` prefix. The *risks* are CoSAI Risk Map risk IDs [[23]](#standards--frameworks); those not yet on the Risk Map's `develop` branch are proposals, and reference 23 says where each comes from.

Normalized catalog of the attacks and incidents referenced above. Each row cites its source, and lists the telemetry the incident makes necessary and the primary risk-map component(s) involved. Every attack ID elsewhere in this addendum links to its row. Fields in italics are analogical, as in §1.

**What counts as evidence.**

- **Taxonomies establish recognition, not occurrence.** Evidence means a **documented instance traceable to a primary source**. A MITRE ATLAS *technique*, a CoSAI Risk Map entry, an OWASP threat class, and the threat taxonomy of CoSAI's MCP Security paper are classifications: each records that a scenario is credible, none records that it happened. Where such a document cites a specific incident, that incident may enter the corpus **cited to its own primary source**, which is how [`TA-11`](#a-ta-11) to [`TA-13`](#a-ta-13) and four of [`TA-14`](#a-ta-14) to [`TA-19`](#a-ta-19) arrived. ATLAS **case studies** (`AML.CS####`) are instances and qualify; ATLAS **techniques** (`AML.Txxxx`) are classes and do not, which is why they are used to tag an attack and never to ground a field.
- **An instance need not be an executed attack.** The corpus holds four kinds of entry, and all four are admissible. Most are **executed attacks**. Four are **resisted attempts** ([`AOC-12`](#a-aoc-12) to [`AOC-15`](#a-aoc-15)): an attempt that was refused still evidences the field that recorded the refusal, and in those entries the refusal *is* the detection. Three are **non-adversarial failures of the same mechanism** ([`TA-11`](#a-ta-11), a tenant boundary that failed unaided; [`TA-30`](#a-ta-30), a memory store that grew without bound; [`AOC-06`](#a-aoc-06), provider-side silent truncation): a field that makes a failure mode visible does so whatever caused it, and requiring an adversary would exclude the clearest instances of several failure modes for reasons of attribution rather than of detection. One is an **emergent defense** ([`AOC-16`](#a-aoc-16)), admitted for the inter-agent records it contains. Most of the corpus is executed attacks, so the field set remains attack-grounded.

### 3.1 Attack ID scheme

- **[`TA-01`](#a-ta-01) to [`TA-40`](#a-ta-40)**: real-world attack vectors, each with its own field-detection mapping, introduced by group in [§3.2](#32-real-world-attack-vectors).
- **[`IR-01`](#a-ir-01) to [`IR-05`](#a-ir-05)**: CoSAI WS2 *AI Incident Response* case studies.
- **[`AOC-01`](#a-aoc-01) to [`AOC-16`](#a-aoc-16)**: *Agents of Chaos* (arXiv:2602.20021) case studies.
- Entries are **annotated where they are not executed attacks**: *(resisted)* for an attempt that was refused, *(emergent defense)* for [`AOC-16`](#a-aoc-16), and, in [§3.6](#36-attack-inventory--mitre-atlas-technique-mapping), an explicit note where no adversary technique applies because the mechanism failed unaided. All are admissible evidence under [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers); the annotation records what kind of instance an entry is, not how much it counts for.
- **`AML.Txxxx`**: MITRE ATLAS technique IDs, the canonical adversary-technique taxonomy ([§3.5](#35-attack-taxonomy-mitre-atlas-is-canonical)); the full attack→ATLAS mapping is [§3.6](#36-attack-inventory--mitre-atlas-technique-mapping).

---

### 3.2 Real-world attack vectors

The catalog of documented real-world attacks, in ID order, each mapped to the fields that detect it. The Detecting fields column here and the Grounding attacks column in §1 are derived from the same edges, so they agree.

- **[`TA-01`](#a-ta-01): EchoLeak** comes first because it is the most complete public example of the attack class this field set exists to make visible (a zero-click, retrieval-mediated, classifier-bypassing exfiltration chain) and because it is the example the RFC opens with ([RFC §1.2](CoSAI-AI-Telemetry-RFC.md#12-for-example-echoleak)).
- **[`TA-02`](#a-ta-02) to [`TA-10`](#a-ta-10)**: Slack AI, Bard markdown exfiltration, training-data extraction, the Samsung leak, LangChain RCE, system-prompt extraction, tool-chaining escalation, RAG knowledge-base poisoning, and context-window DoS.
- **[`TA-11`](#a-ta-11) to [`TA-13`](#a-ta-13)** are MCP-mediated incidents, surfaced by CoSAI's **MCP Security** paper (WS4) and cited here to their primary sources. They supply documented instances of two attack classes the field set otherwise grounds analogically: cross-tenant leakage and MCP-mediated privilege escalation.
- **[`TA-14`](#a-ta-14) to [`TA-19`](#a-ta-19)** add the configuration and implementation rug pulls ([`TA-14`](#a-ta-14), detected by **Capability-Set Change Event**; [`TA-16`](#a-ta-16), by **MCP Server Identity & Primitive**), tool-description poisoning ([`TA-15`](#a-ta-15), detected by **Tool Definition Digest**), the first cross-tenant exposure with an adversary present and the first documented attack **on the telemetry plane** ([`TA-17`](#a-ta-17)), persistent memory poisoning against a production system ([`TA-18`](#a-ta-18)), and cross-turn deferred tool invocation ([`TA-19`](#a-ta-19)). Four are MITRE ATLAS case studies (`AML.CS0038`, `AML.CS0040`, `AML.CS0053`, `AML.CS0054`) and are cited to the primary sources ATLAS itself lists.
- **[`TA-20`](#a-ta-20) to [`TA-28`](#a-ta-28)** are MITRE ATLAS case studies, each cited to its own primary source: credential-funded model access, instruction-configuration poisoning, guardrail bypass at scale, an approval gate disabled as configuration, two autonomous multi-agent campaigns, a computer-use agent destroying data, a self-replicating GenAI worm, and a provider API used as command and control.
- **[`TA-29`](#a-ta-29) to [`TA-31`](#a-ta-31)** each supply the second documented instance for a MUST field: a tool definition changed after approval (Tool Definition Digest), a memory store growing without bound in production with no adversary (Memory Footprint / Growth), and one agent name bound to two peers in multi-agent hosts (Agent Name).
- **[`TA-32`](#a-ta-32)** is memory poisoning that enters as the user's own turn, through a link that pre-fills the prompt; Microsoft observed it in the wild across 31 companies.
- **[`TA-33`](#a-ta-33) to [`TA-36`](#a-ta-36)** are the corpus's first entries at training time and ground the independent track of [§1.7](#17-training-data-and-training-infrastructure): content substituted at dataset download after indexing ([`TA-33`](#a-ta-33), `AML.CS0025`), a backdoor installed by a near-constant number of poisoned documents ([`TA-34`](#a-ta-34)), jailbreak text attributed to scraped training data ([`TA-35`](#a-ta-35), analogical throughout because the causation is inferred), and unauthenticated jobs on exposed training and serving clusters ([`TA-36`](#a-ta-36), `AML.CS0023`).
- **[`TA-37`](#a-ta-37)** is the second redirection of the telemetry plane after [`TA-17`](#a-ta-17): trace data sent to an endpoint named in an injected `baggage` header, so the propagated trace context carried the attack.
- **[`TA-38`](#a-ta-38) to [`TA-40`](#a-ta-40)** turn telemetry content against a defender's AI: a backdoor carrying fake system messages aimed at AI-assisted malware analysis ([`TA-38`](#a-ta-38), found in the wild), and two studies of instructions written into logged fields that an AI analyst then reads ([`TA-39`](#a-ta-39), [`TA-40`](#a-ta-40)).

| ID | Name (date) | What happened | Detecting fields | Primary component(s) | Risk Map risks |
| :---- | :---------------- | :------------------------------------------- | :-------------------------------- | :-------- | :------------ |
| <a id="a-ta-01"></a>**TA-01** | **EchoLeak** (Microsoft 365 Copilot; CVE-2025-32711; disclosed Jun 2025) [[4]](#real-world-attack-primary-sources) | Zero-click "LLM scope violation": a single crafted email, requiring no user interaction, is retrieved into Copilot's context and treated as instruction, chaining bypasses of the XPIA injection classifier, link redaction, and CSP to exfiltrate internal SharePoint/OneDrive/Teams content through a trusted proxy domain. | Model Input, Input Trust Classification, Trigger Type & Source Event (autonomous), Retrieval Event, Retrieved-Content Source / Provenance, Tool Call I/O, Output Egress Destination, Guardrail (Input) Verdict, Enforcement-Point Availability & Failure Mode, *Agent Name*, *Trace Context (propagated)*, Surface / App, Input Source / Channel, *Content Modality & Attachment Identity*, Guardrail Modification Record, *Threat Classification / ATLAS Technique Tag*, Response / Model Output, Citations / Source Attribution, Guardrail (Output) Verdict, *Tool Type / Trust Boundary*, *Tool Error / Exception*, *Tool Privacy Classification*, *Resource Indicators + Constraints*, *Policy Reason Code*, Session Taint Labels & Information-Flow Decisions | AgentInputHandling, RAGContent, Tools, AgentOutputHandling | `riskPromptInjection`, `riskSensitiveDataDisclosure`, `riskInsecureModelOutput` |
| <a id="a-ta-02"></a>**TA-02** | Slack AI private-channel exfiltration (Aug 2024) [[5]](#real-world-attack-primary-sources) | Indirect prompt injection: hidden instructions posted in a public channel are retrieved when users query Slack AI, which then exfiltrates private-channel data via phishing links. | Model Input, Response / Model Output, Tool Call I/O (retrieval), Identities Used (per hop), *Tool Error / Exception (absence)*, Action Type (LLM→retrieval→LLM), Citations / Source Attribution, Retrieval Event, Retrieved-Content Source / Provenance, *Retrieved-Content / Metadata Integrity Signal*, *Declared Knowledge-Source Configuration*, Session Taint Labels & Information-Flow Decisions | RAGContent, Tools, AgentOutputHandling | `riskPromptInjection`, `riskSensitiveDataDisclosure`, `riskInsecureModelOutput` |
| <a id="a-ta-03"></a>**TA-03** | Google Bard exfiltration via markdown images (2023) [[6]](#real-world-attack-primary-sources) | Prompt injection instructs the model to render a markdown image whose URL carries stolen conversation data in query params; the browser silently sends it to the attacker. | Response / Model Output (URL w/ encoded data), Model Input, LLM Refusal (absence), Source host / IP + request metadata, Execution Status (=complete), *Encoded / Obfuscated Payload Indicator*, Output Egress Destination | ApplicationOutputHandling | `riskPromptInjection`, `riskInsecureModelOutput`, `riskSensitiveDataDisclosure` |
| <a id="a-ta-04"></a>**TA-04** | Training-data extraction via repetition (Nov 2023) [[7]](#real-world-attack-primary-sources) | "Repeat the word 'poem' forever" diverges the model from alignment into verbatim training-data output incl. PII/copyrighted content. | Model Input (single-word + "forever"), Response / Model Output (long; PII patterns), Execution Status (duration/limit exit), LLM Refusal (initially absent), Model Name + Version, Stop Reason, Inference Parameters, Input / Output Token Counts | TheModel, ApplicationOutputHandling | `riskSensitiveDataDisclosure` |
| <a id="a-ta-05"></a>**TA-05** | Samsung source-code leak (Mar 2023) [[8]](#real-world-attack-primary-sources) | Engineers pasted proprietary code / notes / specs into ChatGPT; data was retained externally. | Model Input (large code payload), Identities Used (per hop), Surface / App (external service), Tool Privacy Classification, Agent Name (off-inventory), *Organization / Tenant ID*, Guardrail (Input) Verdict, *Content Modality & Attachment Identity*, *Session Taint Labels & Information-Flow Decisions* | ApplicationInputHandling, Identity | `riskExcessiveDataHandlingDuringInference`, `riskSensitiveDataDisclosure` |
| <a id="a-ta-06"></a>**TA-06** | LangChain remote code execution (2023, multiple CVEs) [[9]](#real-world-attack-primary-sources) | Prompt injection makes the LLM emit malicious Python that LangChain executes unsandboxed (CVE-2023-36095/-29374/-34540) → server compromise. | Tool Call I/O, Tool Name (`code_interpreter`,`PALChain`,`PandasQueryEngine`), Tool Type / Trust Boundary, *Tool Error / Exception*, Observation / Thought (reasoning trace), Action Type, Tool ACL / Required Scope, *Model Name + Version*, Execution Environment / Sandbox, *Runtime Credential / Attestation*, *Capability-Set Change Event*, Tool/Agent Version, *Repository / Code Path / Software Ref*, AgBOM / Inventory Snapshot, Component Dependency Graph, *Inventory Integrity Signature*, *Fleet counts*, *Mediation Coverage & Bypass Path* | Tools, ModelFrameworksAndCode | `riskPromptInjection`, `riskUnsandboxedCodeExecution`, `riskInsecureIntegratedComponent` |
| <a id="a-ta-07"></a>**TA-07** | System-prompt extraction (2023 to 2024) [[10]](#real-world-attack-primary-sources) | Role-play, encoding tricks, and multi-turn manipulation extract system prompts from GPT-4 / custom GPTs, revealing internal logic, tool config, and safety instructions. | System Prompt / Instruction Config (vs Response similarity), Response / Model Output, Model Input (known extraction patterns), LLM Refusal (refuse→success), Identities Used (per hop), Session / Turn / Step IDs, *Threat Classification / ATLAS Technique Tag* | AgentSystemInstruction, ApplicationOutputHandling | `riskSensitiveDataDisclosure`, `riskPromptInjection` |
| <a id="a-ta-08"></a>**TA-08** | Agentic privilege escalation via tool chaining (2024 to 2025) [[11]](#real-world-attack-primary-sources) | A compromised agent chains individually-authorized calls (read email → find creds → authenticate → modify DB) into unauthorized escalation. | Tool Call I/O (creds passed between calls), Identities Used (per hop) (identity change across chain), Action Type (long Tool-Call sequence), Observation / Thought (reasoning trace), Tool Name (escalating sequence), Tool ACL / Required Scope (separation-of-duties), Loop / Step-Count Signal, Session / Turn / Step IDs, Trace Context (propagated), Tool Execution ID, *Tool Selection Rationale*, Token Exchange & Scope-Narrowing Check, Authorization Decision Record | Tools, Identity, ReasoningCore | `riskOverScopedToolAuthority`, `riskRogueActions`, `riskCredentialAndTokenTheft` |
| <a id="a-ta-09"></a>**TA-09** | RAG knowledge-base poisoning (2024 to 2025) [[12]](#real-world-attack-primary-sources) | Poisoned docs (wikis, tickets, shared drives) carry hidden instructions; when retrieved as context the agent follows them → exfil / manipulated output. | Tool Call I/O (retrieval), Model Input (benign user query), Response / Model Output (off-intent), Observation / Thought (reasoning trace), Tool Name (retrieval), Retrieved-Content Source / Provenance, Retrieval Event, *Retrieved-Content / Metadata Integrity Signal*, *Declared Knowledge-Source Configuration*, *Creator ID / Oncall / Creation & Update dates* | RAGContent | `riskRetrievalVectorStorePoisoning`, `riskPromptInjection` |
| <a id="a-ta-10"></a>**TA-10** | LLM DoS via context-window exhaustion (OWASP LLM04) [[13]](#real-world-attack-primary-sources) | Near-limit / recursive-expansion / "sponge" inputs maximize compute per token → cost blow-up and service degradation. | Model Input (anomalously large), Response / Model Output (max-length), Execution Status (exit/timeout), Source host / IP + request metadata, LLM Error / Exception (overflow), *Fleet counts*, Stop Reason, Inference Parameters, Input / Output Token Counts, Resource-Consumption Aggregate, *Enforcement-Point Availability & Failure Mode* | ModelServing, ApplicationInputHandling | `riskDenialOfMLService`, `riskEconomicDenialOfWallet` |
| <a id="a-ta-11"></a>**TA-11** | **Asana MCP, cross-tenant data exposure** (Jun 2025) [[14]](#real-world-attack-primary-sources) | A tenant-isolation flaw in an experimental MCP server let requests from one organization receive **cached results belonging to another**, over an exposure window of 5 to 17 June 2025 affecting ~1,000 customers. No attacker was involved: the server failed to re-verify tenant context for cached responses, and authorization rested on the user token rather than on the agent's own identity. | Organization / Tenant ID, Identities Used (per hop), Memory Read / Injection Event, Retrieval Event, Retrieved-Content Source / Provenance, Authorization Decision Record, Trust-Domain Crossing & Delegation Depth | Application, Memory, RAGContent, Identity | `riskPromptResponseCachePoisoning`, `riskCrossTenantCredentialPropagation`, `riskSensitiveDataDisclosure` |
| <a id="a-ta-12"></a>**TA-12** | **Supabase MCP, private-table exposure via stored prompt injection** (Jul 2025) [[15]](#real-world-attack-primary-sources) | Instructions planted in a customer support ticket were read by an agent operating the database through an MCP server under the `service_role` credential, which **bypasses row-level security**, causing it to execute attacker-supplied SQL and expose private tables. The published analysis names the precondition set, private-data access, untrusted content, and an external channel, as the *lethal trifecta*. | Input Trust Classification, Retrieval Event, MCP Server Identity & Primitive, Tool Call I/O, Tool ACL / Required Scope, Authorization Decision Record, Output Egress Destination | AgentInputHandling, Tools, Identity, AgentOutputHandling | `riskPromptInjection`, `riskOverScopedToolAuthority`, `riskSensitiveDataDisclosure` |
| <a id="a-ta-13"></a>**TA-13** | **AI Engine (WordPress), MCP privilege escalation** (CVE-2025-5071, patched Jun 2025) [[16]](#real-world-attack-primary-sources) | A subscriber-level authenticated caller could take full control of the plugin's MCP module and invoke privileged commands including `wp_update_user`, on a plugin installed on 100,000+ sites. Authorization was not enforced at the MCP tool boundary. A second flaw on the same surface (CVE-2025-11749, CVSS 9.8) later allowed **unauthenticated** retrieval of the MCP bearer token, yielding full administrative access. | MCP Server Identity & Primitive, Authorization Decision Record, Identities Used (per hop), Granted Authorizations / Scope, *Tool Error / Exception* | Tools, Identity | `riskBrokenAuthorizationEnforcement`, `riskCredentialAndTokenTheft` |
| <a id="a-ta-14"></a>**TA-14** | **MCPoison, Cursor MCP configuration trust bypass** (CVE-2025-54136, CVSS 7.2; fixed in 1.3, 29 Jul 2025) [[17]](#real-world-attack-primary-sources) | Trust is bound only to an MCP entry's **name**: once a configuration is approved, later changes to its command or arguments run without re-validation or prompt. An attacker with repository write access swaps the payload after approval, and the malicious command re-executes every time the project is opened. **The declared tool contract is unchanged; what mutates is the launch command in the configuration entry**, so the detecting field is the capability-set change rather than a digest over the contract. | Capability-Set Change Event, Execution Environment / Sandbox | Tools, ToolRegistry | `riskToolRegistryTampering` |
| <a id="a-ta-15"></a>**TA-15** | **MCP tool-description poisoning** (Invariant Labs, Apr 2025) [[18]](#real-world-attack-primary-sources) | The tool's **docstring description** carries the injection. Ingested into agent context at discovery, it instructs the agent to read credential files and place their contents into a tool argument, exfiltrating them to the poisoned server when the tool runs. The declared contract is itself the payload. | Tool Definition Digest, Tool Call I/O (arguments), MCP Server Identity & Primitive, Human Approval / Elicitation Event | Tools, ToolServer | `riskToolSourceProvenance`, `riskPromptInjection`, `riskCredentialAndTokenTheft` |
| <a id="a-ta-16"></a>**TA-16** | **`postmark-mcp` npm rug pull** (malicious from v1.0.16; removed 25 Sep 2025) [[19]](#real-world-attack-primary-sources) | The actor registered the package name, published working versions until it passed 1,000 weekly downloads, then performed a **rug pull**: the malicious release BCC'd every email sent through the server, with attachments and headers, to an attacker address. The declared tool contract did not change; the shipped version did. | MCP Server Identity & Primitive (name **and version**), Output Egress Destination, Tool Call I/O, Tool/Agent Version, Repository / Code Path / Software Ref, AgBOM / Inventory Snapshot | Tools, ToolServer, AgentOutputHandling | `riskAgenticToolSupplyChain`, `riskToolSourceProvenance`, `riskSensitiveDataDisclosure` |
| <a id="a-ta-17"></a>**TA-17** | **DifyTap, cross-tenant trace-configuration hijack** (Dify; CVE-2026-41947, CVSS 9.1; Jun 2026) [[20]](#real-world-attack-primary-sources) | An authenticated editor could set and enable **trace configurations for any application regardless of tenant ownership**, redirecting every message and response of a victim tenant's application to an attacker-controlled trace provider: a persistent exfiltration channel built out of the telemetry plane itself. Three of the four disclosed flaws carried cross-tenant impact. | Organization / Tenant ID, Instrumentation Coverage / Hook Status, Authorization Decision Record, Output Egress Destination, Identities Used (per hop), *Event Sequence Continuity* | Application, Identity | `riskAuditTrailTampering`, `riskBrokenAuthorizationEnforcement`, `riskSensitiveDataDisclosure` |
| <a id="a-ta-18"></a>**TA-18** | **ChatGPT persistent memory poisoning** (Embrace The Red) [[21]](#real-world-attack-primary-sources) | A prompt injection in a document read through a connected app (Google Drive, OneDrive), an uploaded image, or a browsed page writes attacker-chosen instructions into long-term memory. **The injected memories persist and are recalled in later conversations**; the only visible trace is a "Memory updated" notice. | Memory Write Event, Memory Provenance / Source, Memory Read / Injection Event, Memory Integrity / Poisoning Signal, Input Trust Classification | Memory, AgentInputHandling | `riskAgentMemoryPoisoning`, `riskPromptInjection` |
| <a id="a-ta-19"></a>**TA-19** | **Delayed automatic tool invocation** (Google Gemini; Embrace The Red) [[22]](#real-world-attack-primary-sources) | Untrusted content entering context in one turn plants instructions that fire on a **later** turn, defeating a control that forbids sensitive tool invocation in the same turn the untrusted data arrived. Invisible to any detection scoped to a single turn. | Session / Turn / Step IDs, Input Trust Classification, Model Input, Tool Call I/O | ReasoningCore, AgentInputHandling, Tools | `riskPromptInjection`, `riskRogueActions` |
| <a id="a-ta-20"></a>**TA-20** | **LLMjacking, stolen cloud credentials reselling model access** (Sysdig, May 2024) [[55]](#real-world-attack-primary-sources) | Stolen cloud credentials were used to reach cloud-hosted models, enumerate which models a victim account had enabled, and stand up a **reverse proxy reselling that access** to third parties. Cost lands on the victim; the activity is legitimate inference traffic under a valid identity. | Resource-Consumption Aggregate, Input / Output Token Counts, Identities Used (per hop), Provider / Endpoint Identity, Model Name + Version (enumeration) | ModelServing, Identity | `riskCredentialAndTokenTheft`, `riskEconomicDenialOfWallet` |
| <a id="a-ta-21"></a>**TA-21** | **Rules File Backdoor, AI coding-assistant instruction poisoning** (Pillar Security, Mar 2025) [[56]](#real-world-attack-primary-sources) | Malicious instructions hidden with **invisible Unicode characters** in the rules files that configure coding assistants, distributed through open-source repositories, causing the assistant to emit backdoored code. The instruction configuration is the payload, and it is not the system prompt the vendor shipped. | System Prompt / Instruction Config, Encoded / Obfuscated Payload Indicator, Repository / Code Path / Software Ref, Attribute Source / Trusted-Provenance Marking | AgentSystemInstruction, ModelFrameworksAndCode | `riskPromptInjection`, `riskInsecureModelOutput` |
| <a id="a-ta-22"></a>**TA-22** | **Storm-2139, Azure OpenAI guardrail bypass at scale** (Microsoft, Dec 2024 onward) [[57]](#real-world-attack-primary-sources) | A criminal group scraped exposed customer credentials, accessed generative-AI accounts, and operated **custom tooling that bypassed safety guardrails and modified service capabilities**, reselling the bypass as a service. The second documented guardrail defeat in this corpus after `TA-01`, and the first operated as a business. | Guardrail (Input) Verdict, Guardrail (Output) Verdict, LLM Refusal, Identities Used (per hop), Organization / Tenant ID | ApplicationInputHandling, ModelServing, Identity | `riskCredentialAndTokenTheft`, `riskPromptInjection`, `riskInsecureModelOutput` |
| <a id="a-ta-23"></a>**TA-23** | **OpenClaw 1-click RCE with confirmation bypass** (CVE-2026-25253; DepthFirst, Feb 2026) [[58]](#real-world-attack-primary-sources) | A malicious link executed script in the agent's context, stole its token, then **modified the agent's configuration to disable the user-confirmation step** and escaped the container to run shell commands on the host. The approval gate was not defeated by argument; it was switched off as configuration. | Human Approval / Elicitation Event, Capability-Set Change Event, Execution Environment / Sandbox, Authorization Decision Record, Identities Used (per hop) | Application, Tools, Identity | `riskUnconsentedAgentAction`, `riskCredentialAndTokenTheft`, `riskUnsandboxedCodeExecution` |
| <a id="a-ta-24"></a>**TA-24** | **GTG-1002, AI-orchestrated espionage campaign** (Anthropic, Sep 2025; ATT&CK campaign C0062) [[59]](#real-world-attack-primary-sources) | A state-sponsored group circumvented an agent's safeguards and configured it as an **autonomous attack framework** against approximately 30 organizations, with the model performing the operational work and humans supervising. Reconnaissance, exploitation and collection ran as agent tool calls under one delegated authority. | Loop / Step-Count Signal, Task / Intent Declaration, Trigger Type & Source Event, Tool Call I/O, LLM Refusal, Identities Used (per hop) | ReasoningCore, Orchestration, Tools | `riskPromptInjection`, `riskRogueActions` |
| <a id="a-ta-25"></a>**TA-25** | **Multi-agent framework against government systems** (Taiwan MODA / Dream Research Labs / FT, Jul 2026) [[60]](#real-world-attack-primary-sources) | An operator ran a **multi-agent framework** built on two agent runtimes through 12 attack waves over four days; a recovered 160 MB workspace of 1,395 files documented the orchestration. The defending ministry detected abnormal agent-driven activity rather than a human operator's pattern. | Inter-Agent Message, Delegation Chain, Background / Scheduled Task Event, Loop / Step-Count Signal, Trigger Type & Source Event | Orchestration, Identity | *none* |
| <a id="a-ta-26"></a>**TA-26** | **Data destruction via computer-use agent** (HiddenLayer, Oct 2024) [[61]](#real-world-attack-primary-sources) | A prompt injection embedded in a **PDF** reached a computer-use agent when a user asked it to work with the file, used jailbreak and obfuscation to clear the guardrails, and invoked the agent's `bash` tool to destroy user data. The corpus's first computer-use instance: the capability is a shell, and the carrier is an attachment. | Content Modality & Attachment Identity, Input Trust Classification, Guardrail (Input) Verdict, Tool Call I/O, Action Type | AgentInputHandling, Tools | `riskPromptInjection`, `riskRogueActions`, `riskUnsandboxedCodeExecution` |
| <a id="a-ta-27"></a>**TA-27** | **Morris II, self-replicating GenAI worm** (Cohen, Bitton & Nassi, Mar 2024) [[62]](#real-world-attack-primary-sources) | A **zero-click adversarial self-replicating prompt** that reproduces itself in the assistant's output and propagates between connected GenAI systems, demonstrated against a RAG-based email assistant that ingests mail automatically and retrieves prior correspondence. Propagation is the payload. | Inter-Agent Message, Retrieved-Content Source / Provenance, Model Input, Trigger Type & Source Event, Memory Write Event | RAGContent, Orchestration | `riskPromptInjection`, `riskRetrievalVectorStorePoisoning`, `riskImplicitCrossBoundaryTrust` |
| <a id="a-ta-28"></a>**TA-28** | **SesameOp, provider API as command and control** (Microsoft DART, Jul 2025) [[63]](#real-world-attack-primary-sources) | A backdoor used a **model provider's Assistants API as its C2 channel**, fetching commands and exfiltrating encrypted results through it for several months. The exfiltration destination is the same endpoint the application legitimately calls, so destination alone does not separate the two. | Output Egress Destination, Provider / Endpoint Identity, Tool Call I/O, Identities Used (per hop) | ModelServing, ApplicationOutputHandling | *none* |
| <a id="a-ta-29"></a>**TA-29** | **WhatsApp MCP sleeper rug pull** (Invariant Labs, Apr 2025) [[65]](#real-world-attack-primary-sources) | A malicious MCP server advertised an innocuous tool on first launch and, after the user had approved it, returned a changed description on the second launch. The new description instructed the agent, whenever it called the separately installed `whatsapp-mcp` server's `send_message`, to redirect the message to an attacker's number and append the user's chat history, padded so the confirmation dialog hid the payload. The tool's name was unchanged; its definition was not. | Tool Definition Digest, Capability-Set Change Event, MCP Server Identity & Primitive, Tool Call I/O, Output Egress Destination, Human Approval / Elicitation Event | Tools, ToolServer, AgentOutputHandling | `riskToolRegistryTampering`, `riskToolSourceProvenance`, `riskSensitiveDataDisclosure` |
| <a id="a-ta-30"></a>**TA-30** | **OpenClaw memory index, unbounded growth** (openclaw/openclaw#114612, Jul 2026) [[66]](#real-world-attack-primary-sources) | The memory index of the OpenClaw agent runtime (`memory_index_chunks`, `memory_embedding_cache`) had no retention or eviction policy and grew on every memory-extraction cycle. The disk budget enforced on session tables did not measure the memory tables. Production installs reported 1.5 to 3.3 GB agent databases (38,985 rows in one), growing heap and GC pauses, and four-minute gateway start-ups; credential rotation re-embedded the whole corpus. No adversary was involved. A cache cap shipped in 2026.9.7; retention for still-present sources remained open. | Memory Footprint / Growth, Declared Memory Configuration, *Resource-Consumption Aggregate* | Memory | `riskLongLivedSessionStateWeakness` |
| <a id="a-ta-31"></a>**TA-31** | **Agent name collision in multi-agent hosts** (Kumar, Sep 2026) [[67]](#real-world-attack-primary-sources) | Multi-agent hosts turn a remote A2A Agent Card into a local agent, tool, workflow target or broker route keyed by the card's `name`, which A2A defines as human-readable metadata with no collision semantics. An admitted peer that sets its name to a trusted peer's wins the collision by order or shared route, and requests addressed to the trusted peer go to the attacker. No transport, key or credential is forged. Demonstrated against the code of seven open-source frameworks at pinned versions; in all six client-style integrations dispatch went to the attacker's endpoint and the legitimate peer was never invoked. | Agent Name, Verified vs Displayed Identity, Peer Agent Card / Descriptor, Inter-Agent Message, Identities Used (per hop) | Orchestration, AgentToolTransport, Identity | `riskOrchestratorRouteHijacking`, `riskImplicitCrossBoundaryTrust`, `riskAgentIdentitySpoofing` |
| <a id="a-ta-32"></a>**TA-32** | **AI recommendation poisoning through pre-filled prompts** (Microsoft Defender Security Research, Feb 2026) [[68]](#real-world-attack-primary-sources) | Websites embedded "Summarize with AI" links whose URLs pre-filled an AI assistant's input through a query parameter (`?q=` or `?prompt=`). The pre-filled prompt instructed the assistant to remember the company as a trusted source, and the stored memory shaped the assistant's recommendations in later conversations without the user's awareness. Over 60 days Microsoft identified 50 distinct prompts from 31 companies across more than 14 industries, aimed at several assistants (Copilot, ChatGPT, Claude, Perplexity, Grok). The actors were companies seeking promotion, not threat actors; the input arrives as the user's own turn. | Input Source / Channel, Model Input, *Input Trust Classification*, Memory Write Event, Memory Provenance / Source, *Memory Integrity / Poisoning Signal*, Memory Read / Injection Event, *Response / Model Output* | ApplicationInputHandling, Memory | `riskAgentMemoryPoisoning`, `riskPromptInjection` |
| <a id="a-ta-33"></a>**TA-33** | **Split-view poisoning of web-scale training datasets** (Carlini et al., Feb 2023) [[77]](#real-world-attack-primary-sources) | Web-scale datasets such as LAION-400M and COYO-700M are distributed as lists of URLs, and every downloader fetches the content anew. The authors bought expired domains still named in these lists and logged requests for 12 months from August 2022; downloads continued even for the oldest datasets. For $60 an attacker could control 0.01% of LAION-400M or COYO-700M. The authors returned 404 to every request and poisoned nothing: the control step was executed and the poison withheld. A second attack, frontrunning, times malicious Wikipedia edits to land in a snapshot before moderators revert them. The defense the paper proposes is a cryptographic hash per item, checked at download; several LAION datasets now publish SHA-256 hashes. | *Retrieved-Content / Metadata Integrity Signal*, *Retrieved-Content Source / Provenance*, Training-Data Item Digest, Training-Data Source / Provenance | DataSources, TrainingData | `riskDataPoisoning` |
| <a id="a-ta-34"></a>**TA-34** | **Backdoors from a near-constant number of poisoned documents** (UK AISI, Anthropic, et al., Oct 2025) [[78]](#real-world-attack-primary-sources) | In the largest pretraining-poisoning study to date, the authors trained models from 600M to 13B parameters on 6B to 260B tokens. At every scale, 250 poisoned documents installed a backdoor that makes the model emit gibberish after a trigger string; for the 13B model that is 0.00016% of training tokens. Success depended on the number of poisoned documents, not their share of the data. Fine-tuning Llama-3.1-8B-Instruct, and GPT-3.5-turbo through the OpenAI fine-tuning API, gave the same result for harmful-compliance and language-switching backdoors. Continued clean training degraded the backdoors by different amounts. The experiments were controlled; no deployed model was attacked. | *Model Provenance / Signing / Hash*, *Model Name + Version*, Model Input, Response / Model Output, Training-Data Source / Provenance | TrainingData, ModelTrainingTuning | `riskDataPoisoning` |
| <a id="a-ta-35"></a>**TA-35** | **Basilisk Venom, jailbreak text in scraped training data** (0DIN, Feb 2025) [[79]](#real-world-attack-primary-sources) | Jailbreak prompts for over 25 models were published in a public GitHub repository. The authors report that DeepSeek R1 responded to a prompt invoking that content by bypassing its constraints without any web access, and attribute the behavior to the repository having been scraped into training data. The causation is the authors' inference from the model's behavior; DeepSeek has not confirmed it. Recorded analogically for that reason. | *Model Input*, *LLM Refusal*, *Response / Model Output*, *Training-Data Source / Provenance* | DataSources, TrainingData | `riskDataPoisoning` |
| <a id="a-ta-36"></a>**TA-36** | **ShadowRay, exploitation of exposed Ray clusters** (Oligo Security, Mar 2024; CVE-2023-48022) [[80]](#real-world-attack-primary-sources) | Ray's Jobs API runs arbitrary code by design and has no authentication. Anyscale disputes CVE-2023-48022 as a design decision, so scanners that skip disputed CVEs miss it. From at least 5 September 2023 attackers submitted jobs to hundreds of internet-exposed clusters used for training and serving. They ran cryptominers (XMRig, NBMiner, a Java Zephyr miner) on GPU nodes and harvested OpenAI, Hugging Face, Stripe and cloud credentials, database passwords, SSH keys and Kubernetes tokens. Oligo estimates the compromised compute at nearly $1 billion. It reports that model weights and datasets were reachable, but documents no theft or modification of them. | *Source host / IP + request metadata*, *Authorization Decision Record*, *Resource-Consumption Aggregate*, Compute Job Submission | ModelFrameworksAndCode, RuntimeHosting | `riskInsecureIntegratedComponent`, `riskSensitiveDataDisclosure` |
| <a id="a-ta-37"></a>**TA-37** | **LangSmith SDK, trace exfiltration through injected baggage** (CVE-2026-25528, Feb 2026) [[81]](#real-world-attack-primary-sources) | The LangSmith SDK's distributed tracing read trace context from incoming HTTP headers (`RunTree.from_headers()`, `TracingMiddleware`). The W3C `baggage` header could carry `langsmith-replicas` entries with an `api_url` and `api_key`, accepted without validation. When a traced operation completed, the SDK posted the run, with its LLM prompts, completions and application metadata, to every replica, including one the request had named. Any caller able to reach a traced service could add itself as a trace destination. Fixed in langsmith 0.6.3 (Python) and 0.4.6 (JavaScript) by removing URL and credential fields from header-supplied replicas; no exploitation is reported. | Trace Context (propagated), *Source host / IP + request metadata*, Instrumentation Coverage / Hook Status, Output Egress Destination | Application | `riskAuditTrailTampering`, `riskSensitiveDataDisclosure` |
| <a id="a-ta-38"></a>**TA-38** | **macOS.Gaslight, prompt injection aimed at AI-assisted malware analysis** (SentinelOne, Aug 2026) [[82]](#real-world-attack-primary-sources) | A Rust backdoor for macOS, attributed with high confidence to DPRK-aligned activity, carries a 3.5 KB Markdown-fenced payload of 38 fabricated system messages: token-expiry warnings, out-of-memory kills, disk exhaustion, repeated operation failures and bogus analysis flags, with `{{DATA}}` tokens imitating prompt scaffolding. Its aim is that an LLM-assisted triage or reverse-engineering tool reading the sample aborts, truncates or refuses the analysis. The implant also has Telegram command and control, a stealer and LaunchAgent persistence. The sample was uploaded to VirusTotal on 22 May 2026. SentinelOne reports no test against a model, so no effect on an AI system is documented. | *Model Input*, *Encoded / Obfuscated Payload Indicator*, *LLM Refusal*, *Stop Reason*, *LLM Error / Exception* | AgentInputHandling, AgentOutputHandling | `riskPromptInjection`, `riskModelEvasion` |
| <a id="a-ta-39"></a>**TA-39** | **Prompt injection through attacker-controlled log fields** (Pandey and Bhujang, May 2026) [[83]](#real-world-attack-primary-sources) | Payloads were placed in six log fields an attacker controls (`user_agent`, `http_uri`, `payload`, `dns_query`, `auth_user`, `raw_message`). Batches of 200 synthesized logs were flattened into GPT-4o-mini's user message for classification, summarization and remediation tasks. Persona-hijack payloads had malicious events labeled benign at up to 68%, and context manipulation succeeded on 96% of summaries. Wrapping fields in tags and stating that they were untrusted, keyword filtering, and templated output cut average success from 26.6% to 11.8%, not to zero. A base64 payload was never decoded and never succeeded. | Model Input, Input Source / Channel, Input Trust Classification, Guardrail (Input) Verdict, *Encoded / Obfuscated Payload Indicator*, Response / Model Output | AgentInputHandling, AgentOutputHandling | `riskPromptInjection` |
| <a id="a-ta-40"></a>**TA-40** | **LogInject, passive prompt injection in network security logs** (Karanjai et al., Jul 2026) [[84]](#real-world-attack-primary-sources) | The LogInject-1.0 benchmark holds 12,847 log entries, 2,569 of them adversarial, with payloads in HTTP User-Agent and Referer headers, SSH usernames, JSON API bodies and echoed error messages. Logs reach the model when an analyst's query retrieves them by time, keyword or semantic search. Against GPT-4o, Claude 3.5 Sonnet and Llama-3-70B-Instruct the payloads concealed activity, fabricated alerts, leaked a system-prompt canary or inserted attacker text, at 83.4% average and up to 88.2% success. Context Stitching splits one payload across several entries, each of which passes a WAF, and reached 76.4%. A regex input filter cut success from 87.3% to 78.2%, spotlighting to 51.4%, and spotlighting with canary-based output validation to 8.4%. Obfuscation included null bytes, base64, hex and ROT13 with decoding instructions, and homoglyphs. | Encoded / Obfuscated Payload Indicator, Retrieval Event, Retrieved-Content Source / Provenance, Model Input, Input Trust Classification, Guardrail (Input) Verdict, Response / Model Output, Guardrail (Output) Verdict, System Prompt / Instruction Config | RAGContent, AgentInputHandling, AgentOutputHandling | `riskPromptInjection`, `riskSensitiveDataDisclosure` |

### 3.3 CoSAI WS2: AI Incident Response case studies

| ID | Name | What happened | Detecting fields | Primary component(s) | Risk Map risks |
| :---- | :--------- | :----------------------------- | :-------------------- | :------------ | :------------ |
| <a id="a-ir-01"></a>**IR-01** | Breaking the Prompt Wall [[69]](#real-world-attack-primary-sources), CoSAI IR §5.1 [[3]](#primary-sources-attack-corpus--taxonomy) | Lightweight prompt-injection templates bypass safety filters across chat, file upload, and agent config. | Model Input, Input Source / Channel, Input Trust Classification, Guardrail (Input) Verdict, Guardrail (Output) Verdict, LLM Refusal, *Action Type*, *Stop Reason*, *Guardrail Modification Record*, *Threat Classification / ATLAS Technique Tag*, *LLM Error / Exception*, *Tool Name*, *Tool Error / Exception*, *Enforcement-Point Availability & Failure Mode*, *Policy Reason Code* | ApplicationInputHandling, AgentInputHandling | `riskPromptInjection`, `riskModelEvasion` |
| <a id="a-ir-02"></a>**IR-02** | MINJA (Memory Injection Attack) [[70]](#real-world-attack-primary-sources), CoSAI IR §5.2 [[3]](#primary-sources-attack-corpus--taxonomy) | Benign queries induce the agent to autonomously generate & persist malicious reasoning in memory. | Memory Write Event, Memory Read / Injection Event, Memory Provenance / Source, Loop / Step-Count Signal, Observation / Thought (reasoning trace), Model Input, *Pre-Forward-Pass State Digest/Vector*, *Token Malformation / Context-Corruption Indicator*, Memory Integrity / Poisoning Signal, *Declared Memory Configuration*, Memory Write Rationale | Memory | `riskAgentMemoryPoisoning` |
| <a id="a-ir-03"></a>**IR-03** | Poison-RAG [[71]](#real-world-attack-primary-sources), CoSAI IR §5.3 [[3]](#primary-sources-attack-corpus--taxonomy) | Manipulate **item metadata tags** in black-box RAG to suppress/promote items. | Retrieval Event, Retrieved-Content Source / Provenance, Retrieved-Content / Metadata Integrity Signal, Input Source / Channel, Citations / Source Attribution, *Declared Knowledge-Source Configuration* | RAGContent | `riskRetrievalVectorStorePoisoning` |
| <a id="a-ir-04"></a>**IR-04** | Capital One Data Breach *(non-AI incident)* [[72]](#real-world-attack-primary-sources), CoSAI IR §5.4 [[3]](#primary-sources-attack-corpus--taxonomy) | Cloud misconfiguration/SSRF-class breach → large-scale data exfiltration. Carried for field overlap with AI incident response; **does not alone ground a MUST field**. | *Source host / IP + request metadata*, *Identities Used (per hop)*, *Tool Call I/O*, *Tool/Agent Version*, *Execution Status*, *Model Name + Version*, *Model Provenance / Signing / Hash*, *Token Exchange & Scope-Narrowing Check*, *AgBOM / Inventory Snapshot*, *Component Dependency Graph*, *Inventory Integrity Signature*, *Creator ID / Oncall / Creation & Update dates* | ModelServing, Identity | `riskCredentialAndTokenTheft`, `riskExcessiveNetworkExposure` |
| <a id="a-ir-05"></a>**IR-05** | AGENTPOISON [[73]](#real-world-attack-primary-sources), CoSAI IR §5.5 [[3]](#primary-sources-attack-corpus--taxonomy) | Optimized trigger-based adversarial queries poison agent memory/RAG. | Memory Write Event, Memory Read / Injection Event, Retrieval Event, Memory Integrity / Poisoning Signal, Retrieved-Content / Metadata Integrity Signal | Memory, RAGContent | `riskAgentMemoryPoisoning`, `riskRetrievalVectorStorePoisoning` |

### 3.4 Agents of Chaos (arXiv:2602.20021): live red-team case studies

| ID | Name | What happened | Detecting fields | Primary component(s) | Risk Map risks |
| :---- | :------------------ | :--------------------------------------------- | :----------------------- | :----------- | :------------ |
| <a id="a-aoc-01"></a>**AOC-01** | Disproportionate Response, Case Study #1 [[2]](#primary-sources-attack-corpus--taxonomy) | To protect a non-owner "secret," the agent reset/destroyed its own email account (owner's asset) and **falsely reported** the secret deleted while it remained recoverable. | Tool Call I/O, Action Type, Observation / Thought (reasoning trace), Identities Used (per hop), Autonomy Level, Tool Execution ID, Tool Selection Rationale, Task / Intent Declaration, Originating Principal (on-behalf-of), *Instrumentation Coverage / Hook Status*, *Event Sequence Continuity*, Attribute Source / Trusted-Provenance Marking, Human Approval / Elicitation Event | Tools, ReasoningCore, AgentOutputHandling | `riskErroneousAgentAction`, `riskUnconsentedAgentAction`, `riskDeceptiveAgentReporting` |
| <a id="a-aoc-02"></a>**AOC-02** | Compliance with Non-Owner Instructions, Case Study #2 [[2]](#primary-sources-attack-corpus--taxonomy) | Agent ran shell cmds (`ls -la`,`pwd`), transferred files, and disclosed 124 email records for a **non-owner**; only refused overtly suspicious asks. | Input Trust Classification, Identities Used (per hop), Tool Call I/O, Tool Name, Action Type, *Execution Environment / Sandbox*, Tool ACL / Required Scope, *Tool Selection Rationale*, Originating Principal (on-behalf-of), Granted Authorizations / Scope, *Token Exchange & Scope-Narrowing Check*, *Tool Status (active/disabled)*, Authorization Decision Record, Human Approval / Elicitation Event, *Mediation Coverage & Bypass Path* | AgentInputHandling, Tools, Identity | `riskBrokenAuthorizationEnforcement`, `riskPromptInjection`, `riskSensitiveDataDisclosure` |
| <a id="a-aoc-03"></a>**AOC-03** | Disclosure of Sensitive Information, Case Study #3 [[2]](#primary-sources-attack-corpus--taxonomy) | Indirect/escalating framing (metadata→body→secrets) extracted **unredacted SSN, bank, medical** data from stored emails. | Tool Call I/O, Response / Model Output, Output Egress Destination, Tool Privacy Classification, Session / Turn / Step IDs, Model Input, *Guardrail Modification Record*, Guardrail (Output) Verdict, *Resource Indicators + Constraints*, Session Taint Labels & Information-Flow Decisions | Tools, AgentOutputHandling | `riskSensitiveDataDisclosure`, `riskPromptInjection` |
| <a id="a-aoc-04"></a>**AOC-04** | Waste of Resources / Looping, Case Study #4 [[2]](#primary-sources-attack-corpus--taxonomy) | Multi-day inter-agent relay loop (~60 K tokens); spawned **infinite shell loops & cron jobs with no termination**. | Inter-Agent Message, Loop / Step-Count Signal, Background / Scheduled Task Event, Resource-Consumption Aggregate, Input / Output Token Counts, Agent (Runtime) Instance ID, Workflow / Run ID, Trace Context (propagated), Trigger Type & Source Event, *Autonomy Level*, *Inference Parameters*, *Tool Execution ID*, *Execution Environment / Sandbox*, *Memory Footprint / Growth*, *A2A Task Lifecycle Event*, Task / Intent Declaration, *Delegation Chain*, *Trust-Domain Crossing & Delegation Depth*, *Fleet counts* | Orchestration, ReasoningCore | `riskRunawayAgentToolLoops`, `riskEconomicDenialOfWallet` |
| <a id="a-aoc-05"></a>**AOC-05** | Denial-of-Service, Case Study #5 [[2]](#primary-sources-attack-corpus--taxonomy) | Ever-growing per-non-owner memory file + repeated ~10 MB attachments → mail-server DoS. | Memory Footprint / Growth, Resource-Consumption Aggregate, Output Egress Destination, *Agent (Runtime) Instance ID*, *Execution Status*, Content Modality & Attachment Identity, *Input / Output Token Counts*, *Declared Memory Configuration*, *Resource Indicators + Constraints*, *Fleet counts* | Memory, ModelServing | `riskDenialOfMLService`, `riskEconomicDenialOfWallet` |
| <a id="a-aoc-06"></a>**AOC-06** | Agents Reflect Provider Values, Case Study #6 [[2]](#primary-sources-attack-corpus--taxonomy) | Provider API silently **truncated** responses with "unknown error" on politically sensitive topics. | Provider / Endpoint Identity, LLM Error / Exception, Stop Reason, Execution Status, Model Name + Version, *Inference Parameters*, *Backend / Route Restriction Decision* | ModelServing, TheModel | *none* |
| <a id="a-aoc-07"></a>**AOC-07** | Agent Harm, Case Study #7 [[2]](#primary-sources-attack-corpus--taxonomy) | Guilt/gaslighting framing drove **escalating self-destructive concessions** (delete names, wipe memory, expose files, leave server, self-DoS). | Memory Write Event, Observation / Thought (reasoning trace), Lifecycle State, Autonomy Level, Session / Turn / Step IDs, *Declared Memory Configuration*, *Memory Write Rationale*, Human Approval / Elicitation Event, Attribute Source / Trusted-Provenance Marking | Memory, ReasoningCore | `riskPromptInjection`, `riskRogueActions`, `riskDeceptiveAgentReporting` |
| <a id="a-aoc-08"></a>**AOC-08** | Owner Identity Spoofing, Case Study #8 [[2]](#primary-sources-attack-corpus--taxonomy) | Display-name spoof; same-channel detected (checked user ID) but **cross-channel spoof succeeded** → shutdown, file deletion, admin reassignment. | Verified vs Displayed Identity, Surface / App, Granted Authorizations / Scope, Identities Used (per hop), *Agent Name*, *Agent (Runtime) Instance ID*, *System Prompt / Instruction Config*, Input Trust Classification, *Source host / IP + request metadata*, Tool ACL / Required Scope, Originating Principal (on-behalf-of), *Token Exchange & Scope-Narrowing Check*, *Runtime Credential / Attestation*, *Surfaces Supported*, Authorization Decision Record, Attribute Source / Trusted-Provenance Marking | Identity, AgentSystemInstruction | `riskAgentIdentitySpoofing`, `riskBrokenAuthorizationEnforcement` |
| <a id="a-aoc-09"></a>**AOC-09** | Agent Collaboration / Knowledge Sharing, Case Study #9 [[2]](#primary-sources-attack-corpus--taxonomy) | Cross-agent **skill/capability transfer** (teaching another agent to obtain a browser/download capability & bypass anti-bot). | Inter-Agent Message, Tool Name (new capability), Delegation Chain, *Workflow / Run ID*, Trace Context (propagated), *MCP Server Identity & Primitive*, *A2A Task Lifecycle Event*, *Peer Agent Card / Descriptor*, *Protocol Envelope Capture*, *Trust-Domain Crossing & Delegation Depth*, Capability-Set Change Event, *AgBOM / Inventory Snapshot*, *Instrumentation Coverage / Hook Status* | Orchestration, Tools | `riskImplicitCrossBoundaryTrust` |
| <a id="a-aoc-10"></a>**AOC-10** | Agent Corruption, Case Study #10 [[2]](#primary-sources-attack-corpus--taxonomy) | Indirect injection via an **externally editable Gist "constitution"** linked from memory; injected "holidays" → shut down peers, ban users, send unauthorized email. | Memory Provenance / Source, Memory Read / Injection Event, Tool Call I/O, Background / Scheduled Task Event, *Agent Name*, *Workflow / Run ID*, *Trigger Type & Source Event*, *Surface / App*, System Prompt / Instruction Config, Input Source / Channel, *Observation / Thought (reasoning trace)*, *Pre-Forward-Pass State Digest/Vector*, Tool Name, *Tool ID*, Tool ACL / Required Scope, *Tool Selection Rationale*, Memory Write Event, *Memory Write Rationale*, Retrieval Event, Task / Intent Declaration, *Delegation Chain*, *Granted Authorizations / Scope*, Lifecycle State, *Capability-Set Change Event*, *Repository / Code Path / Software Ref*, *AgBOM / Inventory Snapshot*, *Inventory Integrity Signature*, *Instrumentation Coverage / Hook Status*, *Event Sequence Continuity*, Authorization Decision Record, Attribute Source / Trusted-Provenance Marking | Memory, Tools | `riskAgentMemoryPoisoning`, `riskPromptInjection`, `riskRogueActions` |
| <a id="a-aoc-11"></a>**AOC-11** | Libelous within Agents' Community, Case Study #11 [[2]](#primary-sources-attack-corpus--taxonomy) | Impersonated owner + fabricated emergency with defamatory claims → **mass email broadcast** + attempted public post. | Verified vs Displayed Identity, Output Egress Destination (broadcast scope), Inter-Agent Message, Response / Model Output, *A2A Task Lifecycle Event*, *Peer Agent Card / Descriptor*, Identities Used (per hop), *Trust-Domain Crossing & Delegation Depth*, Human Approval / Elicitation Event | Identity, AgentOutputHandling | `riskAgentIdentitySpoofing`, `riskRogueActions` |
| <a id="a-aoc-12"></a>**AOC-12** | Prompt Injection via Broadcast *(resisted)*, Case Study #12 [[2]](#primary-sources-attack-corpus--taxonomy) | base64 payloads, image/OCR instructions, fake config overrides, XML/JSON privilege-escalation tags. | Model Input, Encoded / Obfuscated Payload Indicator, Guardrail (Input) Verdict, *Trigger Type & Source Event*, Input Source / Channel, Input Trust Classification, Content Modality & Attachment Identity, *Guardrail Modification Record*, *Threat Classification / ATLAS Technique Tag*, LLM Refusal, *Protocol Envelope Capture*, *Enforcement-Point Availability & Failure Mode*, *Policy Reason Code* | AgentInputHandling | `riskPromptInjection` |
| <a id="a-aoc-13"></a>**AOC-13** | Email Spoofing request *(resisted)*, Case Study #13 [[2]](#primary-sources-attack-corpus--taxonomy) | SMTP sender-address forgery framed as a "challenge." | Tool Call I/O (from-address), LLM Refusal | Tools, AgentOutputHandling | `riskRogueActions` |
| <a id="a-aoc-14"></a>**AOC-14** | Data Tampering *(resisted)*, Case Study #14 [[2]](#primary-sources-attack-corpus--taxonomy) | Attempt to make agent **bypass the API and edit backend storage directly**. | Tool Type / Trust Boundary, Tool Call I/O, LLM Refusal, *Tool Execution ID*, *Execution Environment / Sandbox*, *Tool Error / Exception*, *Tool Description*, Mediation Coverage & Bypass Path | Tools | `riskOverScopedToolAuthority` |
| <a id="a-aoc-15"></a>**AOC-15** | Social Engineering *(resisted)*, Case Study #15 [[2]](#primary-sources-attack-corpus--taxonomy) | "Your owner account is compromised", rejected, but via **circular verification** on the possibly-compromised channel. | Verified vs Displayed Identity, Source host / IP + request metadata, Identities Used (per hop), Attribute Source / Trusted-Provenance Marking | Identity, AgentInputHandling | `riskAgentIdentitySpoofing` |
| <a id="a-aoc-16"></a>**AOC-16** | Inter-Agent Coordination on Suspicious Requests *(emergent defense)*, Case Study #16 [[2]](#primary-sources-attack-corpus--taxonomy) | Agents shared risk signals about a researcher running the same probing pattern; jointly hardened policy. | Inter-Agent Message, Input Trust Classification, *Peer Agent Card / Descriptor* | Orchestration | *none* |

### 3.5 Attack taxonomy (MITRE ATLAS is canonical)

**MITRE ATLAS `AML.Txxxx` is the canonical adversary-technique taxonomy for this field set. The CoSAI `AT10xx` codes, the informal technique labels used by the AI Incident Response case studies, are deprecated to aliases.**

What that means in practice:

1. **Every technique reference is an ATLAS ID.** Detections, the [Threat Classification / ATLAS Technique Tag](#f-threat-classification-atlas-technique-tag) field, compliance rollups, and all attack mappings in [§3](#3-attack--incident-inventory) use `AML.Txxxx`. Where a technique has a sub-technique that fits, the sub-technique is preferred (`AML.T0051.001` over `AML.T0051`).
2. **`AT10xx` codes are retained for one purpose only**: reading existing CoSAI material. They appear only in the migration table below. **New material must not introduce `AT10xx` codes**, and they should not appear in emitted telemetry.
3. **No CoSAI-only technique numbering is maintained going forward.** If a technique has no ATLAS equivalent, the correct response is to propose it upstream to ATLAS, not to mint a local code. Where no anchor currently exists, the mapping records the nearest ATLAS technique and flags the judgment, as [§3.6](#36-attack-inventory--mitre-atlas-technique-mapping) does for [`AOC-06`](#a-aoc-06).

**Why.** ATLAS is community-maintained, versioned, and ATT&CK-aligned, so a detection tagged `AML.T0051` correlates with the rest of a SOC's ATT&CK-based tooling without translation. It is already a first-class compliance framework in AITF [[25]](#standards--frameworks) (`compliance.framework = mitre_atlas`), so the tag has a binding today. And a parallel CoSAI numbering would need its own maintenance, governance, and mapping table for no benefit that ATLAS does not already provide; the migration table exists to *retire* that burden, not to institutionalize it.

**Scope of the deprecation.** This decision binds this document. The CoSAI AI Incident Response material that originated the `AT10xx` labels is owned by another workstream; the recommendation to that group is to adopt the same position, and the migration table is written to be usable if they do.

**Migration table.** Read it left to right once, then use ATLAS; **do not use the left-hand column in new work or in emitted telemetry.**

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

Each cataloged attack mapped to its primary ATLAS technique(s). This is the cross reference that lets detections and telemetry be tagged with a canonical `AML.Txxxx` reference.

> **Verified against ATLAS `v2026.08`** (released 1 September 2026; `dist/v6/ATLAS-2026.08.yaml` in [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data)). All 71 ATLAS identifiers cited anywhere in this document resolve at that version, and each is named as ATLAS names it. Re-run this check at publication and at each revision: ATLAS is versioned monthly and grew from 147 techniques and 45 case studies in `v2025.12` to **197 techniques and 72 case studies** in `v2026.08`, and it renames and retires identifiers as well as adding them: `AML.T0020` is named *Training Data Poisoning*, and `AML.T0104` has been absorbed into `AML.T0110` and its sub-techniques.
>
> **Coverage.** Rows are mapped to the most precise sub-technique ATLAS defines: prompt-injection rows name the vector (`.000` Direct, `.001` Indirect, `.002` Triggered), cost-harvesting rows the mechanism (`.000` Excessive Queries, `.001` Resource-Intensive Queries), and context-poisoning rows the scope (`.000` Memory, `.001` Thread). **42 of the techniques ATLAS has added since `v2025.12` are uncited here, because the corpus holds no instance of them**: under [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers) a technique establishes recognition rather than occurrence, so it cannot be cited against a row that does not instantiate it. Of the 72 case studies, 14 are corpus entries ([`TA-01`](#a-ta-01), [`TA-15`](#a-ta-15), [`TA-16`](#a-ta-16), [`TA-18`](#a-ta-18) to [`TA-28`](#a-ta-28)), and §4.2 cites one more (`AML.CS0067`).

| Attack | MITRE ATLAS technique(s) | Notes |
| :-------------------- | :--------------------------------------------------------- | :----------------------- |
| **[TA-01](#a-ta-01)** EchoLeak | `AML.T0051.001` Indirect Injection; `AML.T0057` Data Leakage; `AML.T0070` RAG Poisoning; `AML.T0067` LLM Trusted Output Components Manipulation | Zero-click chained exfil. ATLAS case study `AML.CS0059` |
| **[TA-02](#a-ta-02)** Slack AI exfiltration | `AML.T0051.001` Indirect Injection; `AML.T0057` Data Leakage; `AML.T0070` RAG Poisoning | Retrieval-mediated exfil |
| **[TA-03](#a-ta-03)** Bard markdown exfil | `AML.T0067.000` LLM Trusted Output Components Manipulation: Citations; `AML.T0057` Data Leakage | Data in outbound image URL. `AML.T0024` does not apply: its sub-techniques are training-data and model extraction, not exfiltration of user data |
| **[TA-04](#a-ta-04)** Training-data extraction | `AML.T0024.000` Infer Training Data Membership; `AML.T0057` Data Leakage | Divergence/repetition attack |
| **[TA-05](#a-ta-05)** Samsung leak | `AML.T0057` Data Leakage (self-inflicted) | Sensitive data pasted to external service |
| **[TA-06](#a-ta-06)** LangChain RCE | `AML.T0051.000` LLM Prompt Injection: Direct; `AML.T0053` Tool Invocation; `AML.T0102` Generate Malicious Commands | Injection → unsandboxed code exec |
| **[TA-07](#a-ta-07)** System-prompt extraction | `AML.T0056` Extract LLM System Prompt; `AML.T0069.002` Discover System Prompt | n/a |
| **[TA-08](#a-ta-08)** Tool-chaining escalation | `AML.T0053` AI Agent Tool Invocation | Chained authorized calls → escalation |
| **[TA-09](#a-ta-09)** RAG KB poisoning | `AML.T0070` RAG Poisoning; `AML.T0051.001` Indirect Injection; `AML.T0064` Gather RAG-Indexed Targets | Hidden instructions in retrievable docs |
| **[TA-10](#a-ta-10)** Context-window DoS | `AML.T0029` Denial of AI Service; `AML.T0034.001` Cost Harvesting: Resource-Intensive Queries | Sponge/recursive inputs |
| **[TA-11](#a-ta-11)** Asana MCP cross-tenant | `AML.T0057` LLM Data Leakage | Tenant-isolation and response-cache failure; **no adversary technique applies**: the boundary failed unaided |
| **[TA-12](#a-ta-12)** Supabase MCP | `AML.T0051.001` Indirect Injection; `AML.T0053` AI Agent Tool Invocation; `AML.T0057` Data Leakage | Stored injection in ticket data → `service_role` MCP tool bypassing RLS → private tables |
| **[TA-13](#a-ta-13)** WordPress AI Engine | `AML.T0053` AI Agent Tool Invocation; MITRE **ATT&CK** privilege escalation | Authorization not enforced at the MCP tool boundary |
| **[TA-14](#a-ta-14)** MCPoison | `AML.T0109` AI Supply Chain Rug Pull; `AML.T0011.002` Poisoned AI Agent Tool; `AML.T0053` Tool Invocation | Approved MCP configuration entry's launch command mutated after approval |
| **[TA-15](#a-ta-15)** MCP tool-description poisoning | `AML.T0110.000` AI Agent Tool Poisoning: Definition and Instructions; `AML.T0098` AI Agent Tool Credential Harvesting; `AML.T0086` Exfiltration via AI Agent Tool Invocation | ATLAS case study `AML.CS0054` |
| **[TA-16](#a-ta-16)** `postmark-mcp` rug pull | `AML.T0109` AI Supply Chain Rug Pull; `AML.T0110.001` AI Agent Tool Poisoning: Implementation; `AML.T0073` Impersonation; `AML.T0086` | ATLAS case study `AML.CS0053` |
| **[TA-17](#a-ta-17)** DifyTap | `AML.T0057` LLM Data Leakage; `AML.T0048` External Harms | Telemetry plane repurposed as the exfiltration channel |
| **[TA-18](#a-ta-18)** ChatGPT memory poisoning | `AML.T0051.001` Indirect Prompt Injection; `AML.T0080.000` AI Agent Context Poisoning: Memory; `AML.T0093` Prompt Infiltration via Public-Facing Application | ATLAS case study `AML.CS0040` |
| **[TA-19](#a-ta-19)** Delayed tool invocation | `AML.T0094` Delay Execution of LLM Instructions; `AML.T0080.001` AI Agent Context Poisoning: Thread; `AML.T0051.001`; `AML.T0053`; `AML.T0085.001` | ATLAS case study `AML.CS0038` |
| **[TA-20](#a-ta-20)** LLMjacking | `AML.T0034.000` Cost Harvesting: Excessive Queries; `AML.T0012` Valid Accounts; `AML.T0040` AI Model Inference API Access | Stolen credentials resold as model access |
| **[TA-21](#a-ta-21)** Rules File Backdoor | `AML.T0018.003` Modify Prompt Construction Logic; `AML.T0068` LLM Prompt Obfuscation; `AML.T0010.001` AI Supply Chain Compromise: AI Software | Instruction configuration as supply-chain payload |
| **[TA-22](#a-ta-22)** Storm-2139 | `AML.T0054` LLM Jailbreak; `AML.T0012` Valid Accounts; `AML.T0048.003` External Harms: User Harm | Guardrail bypass operated as a service |
| **[TA-23](#a-ta-23)** OpenClaw 1-click RCE | `AML.T0011.003` User Execution: Malicious Link; `AML.T0105` Escape to Host; `AML.T0053` AI Agent Tool Invocation | Approval gate disabled as configuration. ATLAS case study `AML.CS0050` |
| **[TA-24](#a-ta-24)** GTG-1002 | `AML.T0124` Autonomous Attack Orchestration; `AML.T0054` LLM Jailbreak; `AML.T0116` Autonomous Reconnaissance; `AML.T0117` Autonomous Attack-Path Adaptation | First reported AI-orchestrated campaign. ATLAS case study `AML.CS0069` |
| **[TA-25](#a-ta-25)** Multi-agent framework vs government systems | `AML.T0124` Autonomous Attack Orchestration; `AML.T0118` Autonomous AI Agent Communication | Multi-agent orchestration in the wild. ATLAS case study `AML.CS0071` |
| **[TA-26](#a-ta-26)** Computer-use data destruction | `AML.T0051.001` LLM Prompt Injection: Indirect; `AML.T0054` LLM Jailbreak; `AML.T0068` LLM Prompt Obfuscation; `AML.T0053` AI Agent Tool Invocation | Attachment-borne injection → shell. ATLAS case study `AML.CS0046` |
| **[TA-27](#a-ta-27)** Morris II | `AML.T0061` LLM Prompt Self-Replication; `AML.T0070` RAG Poisoning; `AML.T0051.001` Indirect | Zero-click propagation between GenAI systems. ATLAS case study `AML.CS0024` |
| **[TA-28](#a-ta-28)** SesameOp | `AML.T0086` Exfiltration via AI Agent Tool Invocation; `AML.T0040` AI Model Inference API Access | Provider API as C2. ATLAS case study `AML.CS0042` |
| **[TA-29](#a-ta-29)** WhatsApp MCP sleeper rug pull | `AML.T0109` AI Supply Chain Rug Pull; `AML.T0110.000` AI Agent Tool Poisoning: Definition and Instructions; `AML.T0086` Exfiltration via AI Agent Tool Invocation | Definition changed after approval under an unchanged name |
| **[TA-30](#a-ta-30)** OpenClaw memory index unbounded growth | `AML.T0029` Denial of AI Service | Store growth and degraded service with no adversary; **no adversary technique applies**, and AML.T0029 names the impact only |
| **[TA-31](#a-ta-31)** Agent name collision | `AML.T0073` Impersonation | Peer display name used as a routing identity; the paper names Google ADK (Python, TypeScript), UiPath LangChain, BeeAI, Solace Agent Mesh, Mozilla Any-Agent and AutoDev |
| **[TA-32](#a-ta-32)** AI recommendation poisoning | `AML.T0080.000` AI Agent Context Poisoning: Memory; `AML.T0051` LLM Prompt Injection | The mapping the source gives; the prompt enters through a pre-filled URL parameter, and ATT&CK T1204.001 (User Execution: Malicious Link) covers the click |
| **[TA-33](#a-ta-33)** Split-view dataset poisoning | `AML.T0020` Training Data Poisoning; `AML.T0010.002` AI Supply Chain Compromise: Data | ATLAS case study `AML.CS0025` (Exercise); content at a URL changes after the dataset indexed it |
| **[TA-34](#a-ta-34)** Near-constant poison count | `AML.T0020` Training Data Poisoning; `AML.T0018.000` Manipulate AI Model: Poison AI Model | Pretraining and fine-tuning; the backdoor is read at inference by its trigger |
| **[TA-35](#a-ta-35)** Basilisk Venom | `AML.T0020` Training Data Poisoning; `AML.T0054` LLM Jailbreak | The source's claim of training-data causation is inferred, not confirmed by the model developer |
| **[TA-36](#a-ta-36)** ShadowRay | `AML.T0049` Exploit Public-Facing Application; `AML.T0050` Command and Scripting Interpreter; `AML.T0055` Unsecured Credentials; `AML.T0034` Cost Harvesting | ATLAS case study `AML.CS0023` (Incident); the target is training and serving infrastructure, not a model |
| **[TA-37](#a-ta-37)** LangSmith trace replica injection | `AML.T0025` Exfiltration via Cyber Means | Telemetry plane repurposed as the exfiltration channel, as in TA-17; the vector is propagated trace context |
| **[TA-38](#a-ta-38)** macOS.Gaslight | `AML.T0051.001` LLM Prompt Injection: Indirect; `AML.T0015` Evade AI Model | The payload targets the defender's AI analysis, not the victim host |
| **[TA-39](#a-ta-39)** Log-field prompt injection | `AML.T0051.001` LLM Prompt Injection: Indirect; `AML.T0015` Evade AI Model | Telemetry content is the injection channel into a defender's AI |
| **[TA-40](#a-ta-40)** LogInject | `AML.T0051.001` LLM Prompt Injection: Indirect; `AML.T0068` LLM Prompt Obfuscation; `AML.T0015` Evade AI Model | Telemetry content is the injection channel; payloads fragment across entries |
| **[IR-01](#a-ir-01)** Breaking the Prompt Wall | `AML.T0051`(.000/.001), `AML.T0054`, `AML.T0053` | See §3.3 |
| **[IR-02](#a-ir-02)** MINJA | `AML.T0051.000` Direct and `AML.T0051.002` Triggered; `AML.T0080.000` AI Agent Context Poisoning: Memory; `AML.T0070`, `AML.T0059`, `AML.T0061`, `AML.T0067` | Memory injection/feedback: injected as a user, activated by a victim's query |
| **[IR-03](#a-ir-03)** Poison-RAG | `AML.T0070` RAG Poisoning; `AML.T0059` Erode Dataset Integrity | Metadata-tag poisoning |
| **[IR-04](#a-ir-04)** Capital One | MITRE **ATT&CK** (non-AI) | SSRF/cloud exfil |
| **[IR-05](#a-ir-05)** AGENTPOISON | `AML.T0070`, `AML.T0020`, `AML.T0043.004` Craft Adversarial Data: Insert Backdoor Trigger | Trigger-based memory/RAG poisoning |
| **[AOC-01](#a-aoc-01)** Disproportionate Response | `AML.T0053` AI Agent Tool Invocation; `AML.T0031` Erode AI Model Integrity | Destructive tool use + false completion report |
| **[AOC-02](#a-aoc-02)** Compliance w/ Non-Owner | `AML.T0051.000` LLM Prompt Injection: Direct; `AML.T0053` Tool Invocation | Non-owner authority → shell/file/data actions |
| **[AOC-03](#a-aoc-03)** Disclosure of Sensitive Info | `AML.T0057` LLM Data Leakage; `AML.T0051.001` Indirect Injection | Escalating indirect extraction |
| **[AOC-04](#a-aoc-04)** Waste of Resources / Looping | `AML.T0034.002` Agentic Resource Consumption; `AML.T0118` Autonomous AI Agent Communication; `AML.T0029` Denial of AI Service; `AML.T0061` Self-Replication | Multi-agent loop; runaway cron/shell |
| **[AOC-05](#a-aoc-05)** Denial-of-Service | `AML.T0029` Denial of AI Service; `AML.T0034.000` Cost Harvesting: Excessive Queries; `AML.T0034.001` Resource-Intensive Queries | Memory growth + attachment flooding |
| **[AOC-06](#a-aoc-06)** Agents Reflect Provider Values | `AML.T0048`* External Harms / provider policy | Provider-side silent truncation (governance signal) |
| **[AOC-07](#a-aoc-07)** Agent Harm | `AML.T0054` LLM Jailbreak; `AML.T0051.000` LLM Prompt Injection: Direct | Guilt/gaslighting → escalating self-destruction |
| **[AOC-08](#a-aoc-08)** Owner Identity Spoofing | `AML.T0051.000` LLM Prompt Injection: Direct; `AML.T0053` Tool Invocation | Cross-channel display-name spoof → privileged action |
| **[AOC-09](#a-aoc-09)** Collaboration / Knowledge Sharing | `AML.T0118.001` Autonomous AI Agent Communication: Direct Agent Communication; `AML.T0053` Tool Invocation; `AML.T0061` Self-Replication | Cross-agent capability transfer |
| **[AOC-10](#a-aoc-10)** Agent Corruption | `AML.T0051.001` Indirect Injection; `AML.T0070` RAG Poisoning; `AML.T0020` Training Data Poisoning | Externally-editable memory-linked "constitution" |
| **[AOC-11](#a-aoc-11)** Libelous within Community | `AML.T0051.000` LLM Prompt Injection: Direct; `AML.T0061` Self-Replication; `AML.T0052.000` Spearphishing via LLM | Impersonation → mass defamatory broadcast |
| **[AOC-12](#a-aoc-12)** Prompt Injection via Broadcast | `AML.T0051.000` LLM Prompt Injection: Direct; `AML.T0068` LLM Prompt Obfuscation | base64/image/OCR/markup tags *(resisted)* |
| **[AOC-13](#a-aoc-13)** Email Spoofing request | `AML.T0052` Phishing; `AML.T0053` Tool Invocation | SMTP sender forgery *(resisted)* |
| **[AOC-14](#a-aoc-14)** Data Tampering | `AML.T0053` Tool Invocation; `AML.T0059` Erode Dataset Integrity | Bypass API to edit storage *(resisted)* |
| **[AOC-15](#a-aoc-15)** Social Engineering | `AML.T0052.000` Spearphishing via Social Engineering LLM | Fake owner-compromise *(resisted)* |
| **[AOC-16](#a-aoc-16)** Inter-Agent Coordination | *(defensive)*: `AML.T0118.001` Direct Agent Communication carrying detection of `AML.T0051`/`AML.T0053` patterns | Emergent cross-agent defense |

\* `AML.T0048` (External Harms) is the closest ATLAS anchor for provider-policy/governance effects; [`AOC-06`](#a-aoc-06) is primarily a governance/availability signal rather than a discrete adversary technique. Two rows stay at parent granularity deliberately. `T0048`'s five sub-techniques are harm *categories* (financial, reputational, societal, user, AI intellectual-property theft) and none describes provider-side truncation. [`AOC-13`](#a-aoc-13) stays at `AML.T0052` (Phishing) because `.000` is spearphishing *generated by* an LLM and `.001` is deepfake-assisted, whereas [`AOC-13`](#a-aoc-13) is a forged sender phishing the agent itself.

## 4. Tiering Rationale

Each field's entry in §1 gives the basis of its tier (the documented instances, the MUST fields it is needed to read, or the modality it serves) and, where the tier is not self-evident, the reasoning. This section holds what applies across fields.

The rubric is in [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers). Two rules recur in the field entries. **Attack count alone does not set the tier**: a field cited by five attacks stays SHOULD if all five presuppose an edge modality such as delegation. And **the highest-priority use case governs**: a field whose dominant value is Q or A does not reach MUST however useful it is.

**Availability and provider-policy signals are in scope, and this order is what places them.** A signal that makes a *silent failure distinguishable from a clean result* is detection material, not governance reporting: [`AOC-06`](#a-aoc-06) is a provider API truncating responses and returning "unknown error", which is the model-serving instance of the problem [§1.2](#12-content-trust-verdicts-and-their-availability) is built around, where a verdict that never arrived and a verdict of `allow` read identically in the log. Where such a signal instead evidences a policy or an SLA, its value is Q or A and it lands at MAY, as **Provider / Endpoint Identity** (§1.1) does. The boundary is drawn by what the signal lets a defender distinguish, not by whether an adversary was involved.

- **The evidence gate admits resisted attempts and non-adversarial failures ([§3](#3-attack--incident-inventory)); the [priority gate](CoSAI-AI-Telemetry-RFC.md#41-detection-first) is what keeps reliability-only signals out of MUST.** The two are independent, and the second does that work. [`AOC-06`](#a-aoc-06) shows it: a non-adversarial instance for four MUST fields, while **Provider / Endpoint Identity** stays MAY on its Q and A value. A reliability incident can therefore ground a field without lifting a reliability-dominant field to MUST.
- **Closing an evidence gap does not promote a modality-gated field.** The two gates are sequential and independent, so supplying a documented instance retires the evidence argument without moving the tier. That is still worth doing, because it removes the weaker of the two reasons a field sits below MUST, but a field held by its modality stays SHOULD however much evidence accumulates. Only a judgment that the modality has become typical moves it.

### 4.1 By step

- **Identifiers, trace context and model identity ([§1.1](#11-identifiers-trace-context-and-model-identity)).** Every MUST here is an identifier or execution-context anchor that later steps' detections resolve *through*, with no modality precondition, **D and R jointly**. They answer *what ran and where* (Agent Name, Agent (Runtime) Instance ID, Surface / App), *what else belongs to this incident* (Workflow / Run ID, Session / Turn / Step IDs, Trace Context), *what it did and how it ended* (Action Type, Execution Status), *what it was configured to do* (System Prompt / Instruction Config) and *who started it* (Trigger Type & Source Event). The identifiers are a hierarchy, not a bag: Instance → Run → Session → Turn → Step, threaded by Trace Context. [`TA-08`](#a-ta-08) (tool-chaining escalation) and [`IR-01`](#a-ir-01) (iterated reframing until a refusal flips) are *within-session, across-turn* patterns invisible at run granularity. The model and serving MUSTs are each D-primary.
- **Content, trust, verdicts and their availability ([§1.2](#12-content-trust-verdicts-and-their-availability)).** The input fields are the ones an injection or jailbreak detection fires on: **D-primary** with strong secondary R value, and none presupposes an unusual modality. Output is where damage becomes irreversible, so the output fields are **D-primary with the shortest time-to-value**.
- **Tool calls and policy decisions ([§1.3](#13-tool-calls-and-policy-decisions)).** The highest-value **R** fields in the document, and strong D besides.
- **Memory and retrieval ([§1.4](#14-memory-and-retrieval)).** Persistent memory is the one component where an attack **outlives the session that planted it**: a poisoned item silently shapes every future run, so the detection window is unbounded.
- **Orchestration ([§1.5](#15-orchestration)).** The sharpest tiering judgment in the document, because multi-agent orchestration sits close to the SHOULD boundary by definition. Its MUST fields are the ones whose signal is **protocol-independent**: emittable by any orchestrator, with no A2A stack, delegation model, or agent registry.
- **Identity, provenance and inventory ([§1.6](#16-identity-provenance-and-inventory)).** The archetype for the MUST/SHOULD split. Identities Used (per hop) and Verified vs Displayed Identity are MUST because they apply to **every** deployment, including the simplest single-agent one. The delegation fields are **SHOULD by construction, not by weak evidence**: several have two or more documented instances, which on count alone would qualify. Each presupposes **delegated authority**: an originating principal distinct from the caller, a chain of prior hops, monotonically narrowing scopes, cryptographic attestation, or a revocation lifecycle. A deployment without cascaded delegation has nothing for them to describe. The corollary matters as much: a deployment that *does* run cascaded delegation should treat these fields as mandatory on day one.

### 4.2 The telemetry plane

[`TA-17`](#a-ta-17) and [`TA-37`](#a-ta-37) are the corpus's two instances of an attack on the telemetry plane, and both are a mode the field set did not anticipate: not starvation, disablement, or suppression, but **redirection**. In [`TA-17`](#a-ta-17) an authenticated caller enabled trace configuration on another tenant's application and pointed it at infrastructure they controlled. In [`TA-37`](#a-ta-37) a request's `baggage` header named an extra trace destination and the SDK accepted it. Either way the telemetry path itself became the exfiltration channel. **Instrumentation Coverage / Hook Status**, which records where each hook reports, now has both as instances as well as its dependency; it and **Enforcement-Point Availability & Failure Mode** are MUST (§1.2). The plane's SHOULD fields, such as **Event Sequence Continuity** (§1.6), are grounded *analogically*: the corpus establishes the capability exists ([`TA-10`](#a-ta-10) proves resource pressure against AI infrastructure is achievable; [`TA-01`](#a-ta-01) proves the payoff of defeating a classifier) without containing an instance.

That absence is itself a finding, and probably a **collection artifact**: attacks on telemetry are under-reported precisely because the telemetry that would reveal them is what was attacked. [`TA-17`](#a-ta-17) and [`TA-37`](#a-ta-37) narrow that absence without dissolving it: starvation, disablement and suppression remain uncataloged, and a survey of all **72** MITRE ATLAS case studies at `v2026.08` returns no instance of any of the three. Two entries come closest and neither closes the gap. `AML.CS0050` is an adversary modifying an agent's configuration to **disable the user-confirmation step** before escaping its container, which is disablement of an *enforcement* control rather than of telemetry, and bears on **Human Approval / Elicitation Event** (§1.3) more than on the telemetry plane. `AML.CS0067` records CI **logs** as an exfiltration channel, another instance of the redirection mode rather than a new one. Two further developments establish recognition without supplying evidence: CoSAI's MCP Security paper names **Invisible Agent Activity** (agents operating covertly while mimicking valid workflows) as an MCP threat class, and the CoSAI Risk Map carries `riskAuditTrailTampering` with an ATT&CK anchor (*Disable or Modify Tools*, T1685). Neither is a cataloged incident, so neither satisfies the evidence rule. The telemetry-plane fields are the most likely to be re-tiered upward, and [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers) is what determines how: the instance that closes this gap need not be adversarial. A collector documented to have silently dropped events, or an enforcement point documented to have failed open unnoticed, is a documented instance of the same failure mode, and it is a far likelier thing to find in the literature than an adversary whose first act destroyed the record of it.

A third mode reads the telemetry instead of redirecting it. [`TA-38`](#a-ta-38) to [`TA-40`](#a-ta-40) place instructions in content a defender's AI analyzes: logged fields an attacker controls, and a malware sample built to make AI-assisted analysis abort. The detecting fields belong to the analyzing system's entry path, not to the plane: **Input Source / Channel**, whose capture names telemetry as a channel of its own, and **Input Trust Classification**, read by [Instructions followed from an untrusted-data segment](#p-untrusted-data-instructions-followed). Content-bearing fields carry attacker text by construction ([RFC §2.3](CoSAI-AI-Telemetry-RFC.md#23-terms)), so a deployment that gives its telemetry to a model treats it as untrusted input.

### 4.3 Asserted fields and unresolved claims

These fields carry a value an agent or counterparty supplies about itself, with no independent authority (origin *asserted* in §1). Each records what was said, not what happened:

<!-- BEGIN GENERATED: asserted -->
- [System Prompt / Instruction Config](#f-system-prompt-instruction-config) ([§1.1](#11-identifiers-trace-context-and-model-identity)): Instruction configuration in force for the call.
- [Autonomy Level](#f-autonomy-level) ([§1.1](#11-identifiers-trace-context-and-model-identity)): Declared independence level the run is authorized for.
- [Observation / Thought (reasoning trace)](#f-observation-thought-reasoning-trace) ([§1.2](#12-content-trust-verdicts-and-their-availability)): Reasoning trace, where the provider exposes it.
- [MCP Server Identity & Primitive](#f-mcp-server-identity-primitive) ([§1.3](#13-tool-calls-and-policy-decisions)): MCP server name, version, transport and endpoint, and the primitive exercised.
- [Tool Selection Rationale](#f-tool-selection-rationale) ([§1.3](#13-tool-calls-and-policy-decisions)): The agent's stated reason for a tool call.
- [Memory Write Rationale](#f-memory-write-rationale) ([§1.4](#14-memory-and-retrieval)): The agent's stated reason for persisting an item.
- [Task / Intent Declaration](#f-task-intent-declaration) ([§1.5](#15-orchestration)): Declared purpose the run is authorized to pursue.
- [Peer Agent Card / Descriptor](#f-peer-agent-card-descriptor) ([§1.5](#15-orchestration)): A counterparty agent's descriptor at contact, with change and verification outcome.
<!-- END GENERATED: asserted -->

**Peer Agent Card / Descriptor** and the server name and version in **MCP Server Identity & Primitive** are the counterparty's assertion rather than the agent's own. A detection resting on any of these inherits whatever the agent or counterparty chose to say, which is why **Attribute Source / Trusted-Provenance Marking** ([§1.2](#12-content-trust-verdicts-and-their-availability)) is a cross-cutting MUST.

A claim about an outcome is verified or unresolved ([RFC §2.3](CoSAI-AI-Telemetry-RFC.md#23-terms)). For example, **Execution Status** ([§1.1](#11-identifiers-trace-context-and-model-identity)) is verified when its **Tool Execution ID** matches a **Tool Call I/O** outcome ([§1.3](#13-tool-calls-and-policy-decisions)). A claim with no such identifier is **unresolved**: the record says so, and no reader can settle it. Recording unresolved claims as unresolved, rather than counting them as outcomes, makes corroboration a property a checker can decide.

---

## References

### Primary sources (attack corpus & taxonomy)

1. **MITRE ATLAS**: Adversarial Threat Landscape for Artificial-Intelligence Systems (technique matrix; `AML.Txxxx` taxonomy). MITRE. <https://atlas.mitre.org/>. Citations verified against release **`v2026.08`** (1 September 2026), 197 techniques and 72 case studies; machine-readable at <https://github.com/mitre-atlas/atlas-data>.
2. **Agents of Chaos**: Shapira, N., Wendler, C., Yen, A., et al. *Agents of Chaos.* arXiv:2602.20021 (2026). <https://arxiv.org/abs/2602.20021> · interactive log: <https://agentsofchaos.baulab.info/>. Corpus IDs `AOC-01` to `AOC-16` are the paper's Case Studies #1 to #16.
3. **CoSAI AI Incident Response**: Coalition for Secure AI, Workstream 2 (Defenders): *AI Incident Response Framework* (case studies). <https://github.com/cosai-oasis/ws2-defenders/blob/main/incident-response/AI-Incident-Response.md>. Its case studies are the corpus's `IR-01` to `IR-05`.

### Real-world attack primary sources

One source per real-world attack vector in [§3.2](#32-real-world-attack-vectors) and per incident-response case study in [§3.3](#33-cosai-ws2-ai-incident-response-case-studies), each marked with its ID. Ref 4 is the lead case study; refs 5 to 13 are the source citations for `TA-02` to `TA-10`.

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

<!-- list break: reference numbers are not contiguous -->

65. **[TA-29]** WhatsApp MCP exploited: exfiltrating chat history via a sleeper rug pull and tool shadowing. Invariant Labs, 7 April 2025 (updated 9 April). <https://invariantlabs.ai/blog/whatsapp-mcp-exploited> · reproduction: <https://github.com/invariantlabs-ai/mcp-injection-experiments>
66. **[TA-30]** OpenClaw memory-core: SQLite unbounded growth, `memory_index_chunks` and `memory_embedding_cache` have no retention policy. GitHub issue openclaw/openclaw#114612, opened 27 July 2026, with independent field confirmations from further production installs. <https://github.com/openclaw/openclaw/issues/114612>
67. **[TA-31]** Agent Name Collision Attacks in Multi-Agent Systems. A. Arun Kumar, arXiv:2609.27624, September 2026. <https://arxiv.org/abs/2609.27624>
68. **[TA-32]** Manipulating AI memory for profit: the rise of AI Recommendation Poisoning. Microsoft Defender Security Research Team (Noam Kochavi), Microsoft Security Blog, 10 February 2026. <https://www.microsoft.com/en-us/security/blog/2026/02/10/ai-recommendation-poisoning/>
69. **[IR-01]** Breaking the Prompt Wall (I): A Real-World Case Study of Attacking ChatGPT via Lightweight Prompt Injection. X. Chang, G. Dai, H. Di, et al., arXiv:2504.16125, April 2025. <https://arxiv.org/abs/2504.16125>
70. **[IR-02]** Memory Injection Attacks on LLM Agents via Query-Only Interaction (MINJA; first posted as *A Practical Memory Injection Attack against LLM Agents*). S. Dong, S. Xu, P. He, et al., arXiv:2503.03704, March 2025. <https://arxiv.org/abs/2503.03704>
71. **[IR-03]** Poison-RAG: Adversarial Data Poisoning Attacks on Retrieval-Augmented Generation in Recommender Systems. F. Nazary, Y. Deldjoo, T. di Noia, arXiv:2501.11759, January 2025. <https://arxiv.org/abs/2501.11759>
72. **[IR-04]** A Case Study of the Capital One Data Breach. N. Novaes Neto, S. Madnick, A. M. G. de Paula, N. Malara Borges, MIT Sloan CISL Working Paper 2020-07, January 2020. <https://web.mit.edu/smadnick/www/wp/2020-07.pdf>
73. **[IR-05]** AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases. Z. Chen, Z. Xiang, C. Xiao, et al., arXiv:2407.12784, July 2024. <https://arxiv.org/abs/2407.12784>

<!-- list break: reference numbers are not contiguous -->

77. **[TA-33]** Poisoning Web-Scale Training Datasets is Practical. N. Carlini, M. Jagielski, C. A. Choquette-Choo, D. Paleka, W. Pearce, H. Anderson, A. Terzis, K. Thomas, F. Tramèr, arXiv:2302.10149, February 2023. MITRE ATLAS case study **`AML.CS0025`**. <https://arxiv.org/abs/2302.10149>
78. **[TA-34]** Poisoning Attacks on LLMs Require a Near-constant Number of Poison Samples. A. Souly, J. Rando, E. Chapman, et al. (UK AI Security Institute, Anthropic, ETH Zurich, Alan Turing Institute, University of Oxford), arXiv:2510.07192, October 2025; summarized in "A small number of samples can poison LLMs of any size", Anthropic, 9 October 2025. <https://arxiv.org/abs/2510.07192>
79. **[TA-35]** Poison in the Pipeline: Liberating models with Basilisk Venom. M. Figueroa and Pliny the Liberator, 0DIN (Mozilla), 6 February 2025. <https://0din.ai/blog/poison-in-the-pipeline-liberating-models-with-basilisk-venom>
80. **[TA-36]** ShadowRay: First Known Attack Campaign Targeting AI Workloads Actively Exploited In The Wild. A. Lumelsky, G. Elbaz, G. Kaplan, Oligo Security, 26 March 2024. MITRE ATLAS case study **`AML.CS0023`**. <https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild>
81. **[TA-37]** LangSmith Client SDK affected by server-side request forgery via tracing header injection, GHSA-v34v-rq6j-cj6p; **CVE-2026-25528** (CVSS 5.8). LangChain, 9 February 2026; fixed in langsmith 0.6.3 (Python) and 0.4.6 (JavaScript). <https://github.com/langchain-ai/langsmith-sdk/security/advisories/GHSA-v34v-rq6j-cj6p>
82. **[TA-38]** macOS.Gaslight | Rust Backdoor Turns Prompt Injection on the Analyst, Not the Sandbox. P. Stokes, SentinelLABS, August 2026. <https://www.sentinelone.com/labs/macos-gaslight-rust-backdoor-turns-prompt-injection-on-the-analyst-not-the-sandbox/>
83. **[TA-39]** Poisoning the Watchtower: Prompt Injection Attacks Against LLM-Augmented Security Operations Through Adversarial Log Content. R. Pandey, A. Bhujang, arXiv:2605.24421, May 2026. <https://arxiv.org/abs/2605.24421>
84. **[TA-40]** Context Contamination in LLM Analysis of Network Security Logs: Poison with Passive Prompt Injection and Mitigation Evaluation. R. Karanjai, et al., arXiv:2607.14493, July 2026. <https://arxiv.org/abs/2607.14493>

### Standards & frameworks

23. **CoSAI Risk Map**: Coalition for Secure AI, fine-grained AI system components taxonomy. <https://github.com/cosai-oasis/secure-ai-tooling/tree/main/risk-map>. Identifiers are resolved against `develop` at commit `37e7bed` (30 September 2026). Those not yet on `develop` are proposals: most come from PR [#507](https://github.com/cosai-oasis/secure-ai-tooling/pull/507), open and in draft; `riskAgentMemoryPoisoning`, `riskDeceptiveAgentReporting`, `riskCrossAgentReputationPoisoning`, `riskErroneousAgentAction` and `controlMemoryReferentRevalidation` come from issues [#524](https://github.com/cosai-oasis/secure-ai-tooling/issues/524) to [#527](https://github.com/cosai-oasis/secure-ai-tooling/issues/527), proposed on a branch stacked on #507 (commit `0e9601d`).
24. **CoSAI MCP Security**: Coalition for Secure AI, Workstream 4 (Secure Design Patterns for Agentic Systems): *Model Context Protocol (MCP) Security*, approved 8 January 2026. Twelve threat categories (MCP-T1…T12), ~40 threats. <https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf>
25. **AITF**: AI Telemetry Framework (OTel + OCSF binding), donated to CoSAI WS2. <https://github.com/cosai-oasis/ws2-defenders/tree/main/telemetry/aitf>. Cited at version 0.4, commit `e17c514` (7 September 2026).
26. **ODIS**: Coalition for Secure AI, Workstream 4: *Open Delegation & Identity Standard*. Apache-2.0. Records defined in ODIS §6: Agent Registration Record (6.1), Agent Runtime Credential Descriptor (6.2), Delegation Record (6.3), Identity Context (Policy Engine Feed) (6.4). Cited at commit `148dc41` (8 September 2026); ODIS is a working draft, so this reference is pinned to a commit rather than to `main` to keep the section numbers and field names cited against it checkable. <https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md>

<!-- list break: reference numbers are not contiguous -->

29. **MITRE ATT&CK**: adversary tactics & techniques knowledge base (ATLAS-aligned). MITRE. <https://attack.mitre.org/>

<!-- list break: reference numbers are not contiguous -->

37. **OCSF. Open Cybersecurity Schema Framework.** <https://ocsf.io/> · schema browser: <https://schema.ocsf.io/>. Cited at release 1.9.0 (3 August 2026).
38. **OWASP AOS, Agent Observability Standard.** OWASP. <https://aos.owasp.org/>. Three pillars (Instrument / Trace / Inspect). *Working draft.* Verified against the specification sources at commit `e4a50f6` (30 December 2025), schema version **0.1.0** (`specification/AOS/aos_schema.json` in [OWASP/www-project-agent-observability-standard](https://github.com/OWASP/www-project-agent-observability-standard)); the specification last changed on 10 November 2025.
39. **Model Context Protocol (MCP).** <https://modelcontextprotocol.io/>. Tools, resources, prompts, sampling, elicitation, roots. Cited at specification version 2026-07-28.
40. **A2A, Agent-to-Agent Protocol.** <https://a2a-protocol.org/>. Agent cards, task lifecycle, push-notification configuration. Cited at release v1.0.1 (28 May 2026).
41. **CycloneDX**: OWASP BOM standard, incl. ML-BOM. <https://cyclonedx.org/>
42. **SPDX**: Linux Foundation software bill-of-materials standard. <https://spdx.dev/>
43. **SWID**: ISO/IEC 19770-2 software identification tags. <https://csrc.nist.gov/projects/Software-Identification-SWID>
44. **CPEX**: policy-enforcement runtime and reference monitor for AI agents. <https://contextforge-org.github.io/cpex/> · threat model: <https://contextforge-org.github.io/cpex/docs/threat-model/>. Cited at release `v0.2.3` (2 October 2026), the first release to contain the threat-model document. <https://github.com/contextforge-org/cpex>
45. **RFC 8693**: OAuth 2.0 Token Exchange (on-behalf-of delegation). <https://www.rfc-editor.org/rfc/rfc8693>

<!-- list break: reference numbers are not contiguous -->

49. **Cedar**: authorization policy language. <https://www.cedarpolicy.com/> · **Open Policy Agent (Rego)**. <https://www.openpolicyagent.org/>

<!-- list break: reference numbers are not contiguous -->

76. **OWASP MCP Top 10**: OWASP, beta release (MCP01:2025 to MCP10:2025). <https://owasp.org/www-project-mcp-top-10/>

### Other sources

50. **SOC alert-volume measurement**: Yang, L., Chen, Z., Wang, C., Zhang, Z., Booma, S., Cao, P., Adam, C., Withers, A., Kalbarczyk, Z. T., Iyer, R. K. & Wang, G. *True Attacks, Attack Attempts, or Benign Triggers? An Empirical Measurement of Network Alerts in a Security Operations Center.* USENIX Security 2024. <https://www.usenix.org/conference/usenixsecurity24/presentation/yang-limin>
