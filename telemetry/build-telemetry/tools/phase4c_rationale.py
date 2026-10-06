#!/usr/bin/env python3
"""Phase 4c, one-shot (kept as record): move the per-field tier rationale of
AD §4 onto the fields, and the SHOULD modality out of `records`.

- `records` loses its trailing "Modality: X." or "Provider-gated."; the field
  gains `modality: X` or `provider_gated: true`. build.py renders them back.
- `rationale` carries the AD §4 reasoning for that field, reworded only where
  the generated tier line now states what the sentence used to (the tier, the
  basis). `rationale_see` points a field at another field's rationale where
  one argument covers both.
"""
import os
import re

from yamlio import dump, load

DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))   # the documents: telemetry/
PATH = os.path.join(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')), 'fields.yaml')
T47 = '[RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers)'
PLANE = '[§4.2](#42-the-telemetry-plane)'

RATIONALE = {
    # §1.1
    'agent_name': "Rests on `TA-05` (an agent nobody inventoried) and `TA-31` (one name bound to two peers, so requests reach the wrong one); both are found by comparing a name against what it should resolve to.",
    'agent_runtime_instance_id': "One identity across a fleet is otherwise ambiguous between sibling instances and a stolen credential, and capability sets and hook state are per process.",
    'workflow_run_id': "Loop / Step-Count Signal and Resource-Consumption Aggregate are both defined per run.",
    'trigger_type_source_event': "Zero-click is a telemetry category. `TA-01` starts an entire run from one inbound email with no human in the loop. Surface/App would record \"email\" for both that and an ordinary request; the autonomous flag is what separates them.",
    'action_type': "Marks the think→act boundary where `AOC-01` and `AOC-02` did their damage.",
    'stop_reason': f"Without it a **Response / Model Output** cut short by a provider content filter or a token limit reads the same as one that finished, so it also passes the dependency test of {T47}. A deployment's own guardrail verdict does not record the provider's filter, and token counts cannot infer it. Every major provider API returns a completion's stop reason, so it is implementable wherever a model is called.",
    'system_prompt_instruction_config': "Both a config-integrity baseline and the reference against which extraction is detected: `TA-07` succeeds when the response reproduces it.",
    'autonomy_level': "The oversight dial for delegated action. The corpus repeatedly shows agents operating *above* their intended autonomy (`AOC-04`, `AOC-01`, `AOC-07`); logging the claimed level is what makes that detectable.",
    'organization_tenant_id': f"Held by the modality gate, not the evidence gate. Its instances (`TA-11`, `TA-17`, `TA-22`) clear the evidence bar; what holds it below MUST is that multi-tenant hosting is a deployment modality, and a single-tenant deployment has nothing for the field to describe. **MUST for any multi-tenant deployment.** The two cross-tenant entries differ in a way worth recording: `TA-11` involved **no attacker**, the boundary failed unaided, which under {T47} is a documented instance of the failure mode and not a lesser kind of evidence, since the field detects the boundary failure whatever caused it. `TA-17` supplies the adversarial instance, an authenticated caller reaching another tenant's application deliberately. Evidence is therefore settled twice over, and only the modality gate remains.",
    'model_name_version': "The supply-chain pivot (*which agents used the compromised model*), and R-critical for scoping.",
    'inference_parameters': "Rests on a *denominator* argument rather than a tampering attack: \"max-length output\" (`TA-04`) and \"anomalously large input\" (`TA-10`) are the documented detection signatures, and neither is computable without `max_tokens` and the declared context window. It also gives decoding configuration the integrity baseline the system prompt has. Capture it per call: per-request overrides are the attack.",
    'input_output_token_counts': "The cheapest DoS and runaway-loop detector in the document (`AOC-04`'s ~60 k-token relay, `AOC-05`, `TA-10`), and it costs nothing to emit.",
    'llm_error_exception': "Fires precisely under adversarial conditions.",
    'model_provenance_signing_hash': "A supply-chain primitive; ties to model-signing work and ODIS `software_hash`.",
    'pre_forward_pass_state_digest_vector': "A research-grade signal.",
    'token_malformation_context_corruption_indicator': "A research-grade signal.",
    'provider_endpoint_identity': "`TA-28` is the case that tests the tier. `AOC-06` is a governance and availability signal rather than a discrete adversary technique, which makes the field Q- and A-dominant, and the D concern it is usually asked to carry, model substitution, belongs to Model Name + Version. `TA-28` is different: a backdoor using a provider's own API as its command-and-control channel, where the exfiltration destination is an endpoint the application legitimately calls. That is a detection argument rather than a governance one, and it is carried by **Output Egress Destination** (§1.2, MUST) recording the destination together with what left, not by provider identity alone, because a legitimate call and a C2 beacon share the provider. The field stays MAY because knowing *which* provider was called does not separate them; knowing what was sent does.",
    # §1.2
    'model_input': "Must cover *all* inputs, not the first user turn: injection arrives via tool outputs (`IR-01`), retrieved content (`IR-03`, `TA-01`, `TA-02`), memory (`IR-02`), or another agent (`AOC-12`).",
    'input_trust_classification': "Operationalizes the risk map's core agentic control. `AOC-02` disclosed 124 email records because it did not distinguish an owner instruction from a non-owner's; `TA-01` is untrusted email content promoted to instruction.",
    'guardrail_input_verdict': "`TA-01` *defeated* a prompt-injection classifier. A classifier bypass is undetectable if verdicts are never logged.",
    'content_modality_attachment_identity': "The corpus's obfuscation attacks are modality attacks: instructions in OCR'd images and base64 blobs (`AOC-12`), ~10 MB attachment floods (`AOC-05`). Text-only capture misses both.",
    'threat_classification_atlas_technique_tag': "Its value is D-portability into ATT&CK-aligned tooling plus A-rollup, but no documented instance turns on its absence and no MUST field depends on it, so it fails both MUST tests. This document still recommends stamping every fired detection with it.",
    'guardrail_modification_record': "Applies whenever an enforcement point or redaction pipeline rewrites rather than blocks. Without it, **Model Input**, **Response** and a guardrail verdict of `modify` record content that was not what the model or the recipient saw, so the record is *actively wrong*. Its value is R first and D second. `TA-01`, whose chain bypassed link redaction, is an instance, but the tier rests on the dependency.",
    'output_egress_destination': "Converts a detection from *\"something bad was generated\"* into *\"and here is where it went\"*: the difference between blocking and reporting. It would have caught `TA-01` and `TA-03` *before data left*: both smuggle data into an outbound URL on a trusted-looking domain. It also renders `AOC-03`, `AOC-11`, and `AOC-05` visible.",
    'llm_refusal': "An early-warning tripwire. `IR-01` is iterated reframing until a refusal flips; `AOC-12/13/14` are the mirror image, successful refusals whose telemetry documents attempted attacks even when blocked.",
    'citations_source_attribution': "Applies to deployments that emit citations, which is now the common RAG configuration. A citation is a *trusted* output component (`AML.T0067.000`), so three detections depend on it and none is reachable from response text alone: fabricated citations matching no retrieval, attacker-planted links (`TA-02`, `TA-01`), and suppression visible by comparing retrieved against cited (`IR-03`).",
    'observation_thought_reasoning_trace': "High-value forensics for separating a compromised agent from a misconfigured one (`AOC-01`, `AOC-07`), but frequently unavailable from provider APIs and privacy-sensitive.",
    'instrumentation_coverage_hook_status': f"Grounded by `TA-17`, where the telemetry plane was redirected ({PLANE}). Under sampling, an absent refusal, tool result or verdict cannot be read without the coverage and sampling record ([RFC §5](CoSAI-AI-Telemetry-RFC.md#5-conformance)). More generally it resolves the ambiguity undermining every absence-based detection in the document: no refusal, no termination condition, no matching request are each only interpretable if the relevant hook was instrumented. It is D-dominant, it is not modality-gated (every deployment has an instrumentation configuration), and recording *where each hook reports* is what separates a hijacked plane from a healthy one.",
    'enforcement_point_availability_failure_mode': "A verdict that never arrived and a verdict of `allow` are indistinguishable in the log, so without it the guardrail verdicts and the **Authorization Decision Record** cannot be read, and the control plane is a single point of silent failure. Deployments choose fail-open or fail-closed for availability reasons; **this document requires that the choice and the outcome be recorded**, and does not recommend either posture.",
    'attribute_source_trusted_provenance_marking': "The zero-trust principle applied to telemetry itself: it determines whether the rest of the field set can be believed. The document already applies the idea once (Verified vs Displayed Identity (§1.6)) and the generalization is that identity is not the only attribute an agent can assert. Autonomy Level, Task Declaration, System Prompt, and every reasoning field are agent-supplied, and `AOC-01` is the corpus's proof that agents *do* report falsely: it declared a secret deleted while the data remained recoverable. Cost is an enum per attribute group, not per event.",
    # §1.3
    'tool_call_io': "Without it and **Tool Name** a compromised agent's actions are invisible, and every destructive case in the corpus is reconstructed from them.",
    'tool_type_trust_boundary': "Earned via `AOC-14`, which tried to make the agent bypass the tool API and write to backend storage directly. \"API-mediated only\" is unenforceable unless telemetry distinguishes the two.",
    'execution_environment_sandbox': "`TA-06` is characterized as model-emitted Python executed **unsandboxed**: the isolation posture *is* the finding. Two calls to the same code-execution tool, one containerized and one not, are otherwise the same event.",
    'tool_execution_id': "Makes *a result with no matching request* a queryable condition, and is the only way to correlate asynchronous tool calls. `AOC-01`'s false completion report is precisely a request/result mismatch.",
    'tool_acl_required_scope': "Every attack that cites it presupposes meaningful delegation.",
    'tool_definition_digest': "`TA-15` and `TA-29` are the grounding instances. In `TA-15` the definition is malicious as published, the injection carried in the tool's own description, which is why the digest is taken **at invocation** rather than at registration and must cover the description, not only the argument and output schemas. In `TA-29` the description changed after approval under an unchanged name, which the comparison against the approved baseline detects. The adjacent rug pulls fall outside the digest: `TA-14` mutates an approved configuration's launch command and `TA-16` ships a malicious implementation under an adopted name; in both of those the *declared contract* is itself unchanged, so the detecting fields there are Capability-Set Change Event and MCP Server Identity & Primitive respectively. The modality gate then fell with MCP itself: the gate is third-party or dynamically-discovered tools, and an MCP `tools/list` exchange is dynamic discovery by construction.",
    'mcp_server_identity_primitive': f"Decided by prevalence rather than by evidence. The corpus's MCP incidents (`TA-11` to `TA-16`, `TA-29`) cleared the evidence gate several times over; `TA-16` is the sharpest, because the server's declared contract never changed and only its published **version** did, so name alone would not have distinguished the safe release from the malicious one. What held the field at SHOULD was the modality gate, and that gate turns on MCP being at the **edge of current agentic practice** ({T47}). It is not. The corpus's MCP-mediated entries all date from 2025 onward, and their share understates the point, because the remaining agentic entries are incidents of other kinds rather than counter-examples to MCP's prevalence; CoSAI's Workstream 4 devoted a paper to MCP security; OWASP publishes an MCP Top 10; and MITRE ATLAS has added `AML.T0109` AI Supply Chain Rug Pull and `AML.T0110` AI Agent Tool Poisoning, the latter with three sub-techniques (`.000` Definition and Instructions, `.001` Implementation, `.002` Runtime Response). A protocol acquires a dedicated top-ten list and a dedicated technique family once it is typical. **Server name and version are as cheap as Tool Name and should be adopted first.**",
    'tool_privacy_classification': "DLP and compliance governance metadata, A-dominant, and not modality-gated. Its D value is already carried by Tool ACL/Scope and Output Egress.",
    'authorization_decision_record': "Fills a structural hole the rest of the field set has by construction. The document logged what a *content classifier* concluded (Guardrail Verdict, §1.2) and what authority a tool *requires* (Tool ACL/Scope, §1.3), but never what the authorization layer **decided**, on which rule, or why, so a denied operation and a never-attempted one were indistinguishable. Among the attacks that turn on that record are `AOC-02` (non-owner compliance), `AOC-08` (privileged action after spoof), `AOC-10` (injected authority), and `TA-08` (individually-authorized calls escalating in aggregate; visible only if each link's decision and rule are recorded). Universal rather than modality-gated; D and R jointly.",
    'session_taint_labels_information_flow_decisions': "A genuinely different mechanism from Input Trust Classification (§1.2): that classifies a segment of one payload, while taint is **state accumulating across a session** that survives into operations whose own content is clean. That distinction is the whole attack in `TA-01` and `TA-02`, where the exfiltrating request is innocuous in isolation. Of everything in SHOULD this has the highest D value per unit of effort.",
    'human_approval_elicitation_event': "Covers the control the corpus most often shows *missing*: `AOC-01`, `AOC-07`, and `AOC-11` are all irreversible actions taken without human authorization. `TA-23` is the sharper case, because the gate was present and was **switched off as configuration** rather than argued past: the record that matters is not only the approval but the change to whether approval was required at all, which is why **Capability-Set Change Event** (§1.6, MUST) and this field are read together. **MUST wherever irreversible or high-impact actions are reachable.** Two sub-signals matter: approver identity must come from the identity provider, not the agent's claim; and approval scope must be re-validated against the arguments actually presented, or one sign-off can be replayed against a larger action.",
    'mediation_coverage_bypass_path': "The enforcement counterpart to Instrumentation Coverage (§1.2). That field asks *is the telemetry complete?*; this one asks *is the enforcement unbypassable?* `AOC-14` is precisely this attack. A control that can be routed around is not a control.",
    'backend_route_restriction_decision': "Paired with taint it is a D signal; standing alone it is closer to A (data-residency evidence) and Q.",
    'policy_reason_code': "A-dominant reporting convenience, not modality-gated, and the underlying decision is already captured by Guardrail Verdict and classified by the ATLAS tag.",
    # §1.4
    'memory_write_event': "MINJA (`IR-02`) poisons memory using only benign queries: the agent autonomously persists malicious reasoning. AGENTPOISON (`IR-05`) uses optimized triggers. `TA-18` is the production instance: injected ChatGPT memories persisted and were recalled in later conversations. None is detectable without Memory Write and Read plus **Memory Provenance**.",
    'memory_provenance_source': "Exposes `AOC-10`: a \"constitution\" stored as an externally editable Gist, later edited to make the agent shut down peers and send unauthorized mail. The signal is *a context-shaping memory item resolving to a mutable, non-owner-controlled source.*",
    'memory_footprint_growth': f"Catches `AOC-05` (ever-growing per-non-owner file → mail-server DoS) and `TA-30`, a production memory index that grew without bound because the disk budget measured other tables. `TA-30` involved no adversary, which {T47} admits: the field detects the growth whatever caused it.",
    'memory_write_rationale': "The analogue of Tool Selection Rationale, and `IR-02` is the case demanding it: the content looks innocuous and the write unremarkable; the tell is the justification the agent gives itself.",
    'declared_memory_configuration': "`TA-30` is an instance (a store with no retention policy), but the silently-raised-limit scenario is absent from the corpus, and the field's job (a baseline for Memory Footprint) can be met by hard-coding known limits.",
    'retrieval_event': "RAG is the document's most-cited injection channel (`TA-01`, `TA-02`, `TA-09`, `IR-03`, `AOC-10` are all retrieval-mediated). This field and **Retrieved-Content Source / Provenance** answer the halves a detection needs: *what came back*, and *where it came from and when it changed*. Together they connect \"what was retrieved\" to \"what the model then did\"; neither is sufficient alone.",
    'retrieved_content_metadata_integrity_signal': "Poison-RAG (`IR-03`) manipulates item *metadata tags* rather than content bodies, which is why the integrity signal must cover metadata. `TA-09` plants hidden instructions in wikis and tickets, and recently-modified retrievable documents deserve scrutiny, hence freshness folds into provenance.",
    'declared_knowledge_source_configuration': "On the same reasoning as Declared Memory Configuration: a silently altered retrieval config or repointed index is not in the corpus, and `IR-03` poisons metadata, not search configuration.",
    # §1.5
    'inter_agent_message': "The substrate of cross-agent propagation: `AOC-04` (nine-day mutual-relay loop), `AOC-09` (capability transfer), `AOC-11` (mass broadcast), and `AOC-16`: the positive case, agents sharing risk signals.",
    'background_scheduled_task_event': "Captures the corpus's most striking finding: agents spawning infinite shell loops and cron jobs with **no termination condition**, converting short-lived tasks into permanent infrastructure (`AOC-04`, `AOC-10`). With **Loop / Step-Count Signal** it clears the bar on D value rather than attack count.",
    'task_intent_declaration': "The goal-drift anchor; `AOC-04` shows agents inventing new goals beyond the requested task.",
    'a2a_task_lifecycle_event': "Held by the modality gate. Its evidence is generic multi-agent incidents, not A2A-protocol incidents: `AOC-04/09/11` predate A2A entirely. **MUST the moment A2A is in play**; push-notification configuration in particular registers an attacker-settable egress channel.",
    'peer_agent_card_descriptor': "Held by the modality gate. Its one A2A instance is `TA-31`, where hosts keyed routing on a card's `name`; the rest of its grounding is generic multi-agent incidents. **MUST the moment agent cards are in play.**",
    'protocol_envelope_capture': "Q-dominant, duplicates interpreted fields, carries raw-content privacy weight, and is not modality-gated.",
    # §1.6
    'identities_used_per_hop': "The accountability primitive: when an agent resets its own mail server (`AOC-01`), dumps 124 records (`AOC-02`), or mass-mails defamation (`AOC-11`), *which principal, which agent, which tool, which credential* is the first question of any response. It applies to every deployment, including the simplest single-agent one.",
    'verified_vs_displayed_identity': "MUST on a precise D argument rather than volume. `AOC-08` shows same-channel spoofing *detected* (the agent checked an immutable user ID) and cross-channel spoofing *succeeding* where only a display name was available. The difference between those outcomes is entirely a telemetry difference.",
    'trust_domain_crossing_delegation_depth': "Makes an **externally-operated** counterparty legible. ODIS treats `trust_domain` and `max_depth` as policy-engine inputs rather than telemetry, which is right only while a chain stays inside one domain. Once authority crosses out of the domain that issued it, or the acting agent sits several hops from the originating principal, both become detection-grade: `AOC-04`'s nine-day relay and `AOC-09`'s capability transfer are both depth phenomena, and `TA-11` is a domain-boundary failure. See [RFC §4.6](CoSAI-AI-Telemetry-RFC.md#46-record-your-boundary-not-their-internals).",
    'token_exchange_scope_narrowing_check': "Adds the *event* the surrounding fields only describe the state of. Forwarding a caller's inbound token is usually wrong (it is scoped for the agent, not the backend) so the **requested-vs-granted delta** is what makes a silently over-broad grant visible (`TA-08`).",
    'capability_set_change_event': "Every other inventory field describes a **state**; this one describes a **transition**, and transitions are where attacks are visible. Grounded directly in `AOC-09`, where one agent teaches another to acquire a browser/download capability. The security event is the *acquisition*; the previous inference path (\"tool-call spike + new Tool Name\") fires only once the capability is exercised, and never at all for one acquired and held in reserve. Removal matters symmetrically: a guardrail tool or logging sink quietly dropped is a defence-evasion signal. It is also cheap where least expected to fire: a static capability set emits nothing.",
    'tool_agent_version': "A supply-chain response primitive, with Repository / Code Path / Software Ref. The closest call among the inventory fields: documented instances and genuine R value (CVE blast radius), held below MUST because that value is realized through a fleet-inventory process rather than per-event detection, and because it is inseparable in practice from the AgBOM fields. The WG may reasonably promote it.",
    'agbom_inventory_snapshot': "Requires an inventory-emission capability most deployments lack; so do Component Dependency Graph and Inventory Attestation Signature.",
    'component_dependency_graph': "The complete answer to CVE blast radius: `TA-06` is a vulnerability in a *framework* beneath the agent, and reaching it requires transitive edges.",
    'inventory_integrity_signature': "An inventory a compromised agent can rewrite is worth little. The limit: a signature proves who asserted the inventory, not that the assertion is true, which is the subject of Attribute Source / Trusted-Provenance Marking (§1.2).",
    'event_sequence_continuity': f"The minimum defence against selective suppression by a compromised agent: sequence numbers make omission visible as a gap rather than invisible as silence. Grounded analogically ({PLANE}).",
}

SEE = {
    'tool_name': 'tool_call_io',
    'memory_read_injection_event': 'memory_write_event',
    'retrieved_content_source_provenance': 'retrieval_event',
    'loop_step_count_signal': 'background_scheduled_task_event',
    'repository_code_path_software_ref': 'tool_agent_version',
}

MOD = re.compile(r' (?:Modality: (?P<m>[^.]+)\.|(?P<p>Provider-gated)\.)$')

ORDER = ['id', 'name', 'name_note', 'tags', 'tier', 'tier_mark', 'role', 'record', 'origin', 'compound',
         'basis', 'records', 'modality', 'provider_gated', 'emitted_by', 'emitted_by_text', 'capture',
         'rationale', 'rationale_see']


def main():
    fields = load(PATH)
    ids = {f['id'] for f in fields}
    assert set(RATIONALE) <= ids and set(SEE) <= ids and set(SEE.values()) <= set(RATIONALE)
    assert not set(RATIONALE) & set(SEE)
    for f in fields:
        m = MOD.search(f['records'])
        if f['tier'] == 'SHOULD':
            assert m, f['id']
        if m:
            f['records'] = f['records'][:m.start()]
            if m['m']:
                f['modality'] = m['m']
            else:
                f['provider_gated'] = True
        if f['id'] in RATIONALE:
            f['rationale'] = RATIONALE[f['id']]
        if f['id'] in SEE:
            f['rationale_see'] = SEE[f['id']]
    fields = [{k: f[k] for k in ORDER if k in f} | {k: v for k, v in f.items() if k not in ORDER}
              for f in fields]
    dump(fields, PATH, '# Telemetry fields. Evidence is derived from attacks/ (tools/build.py).\n')
    print(f"rationale on {len(RATIONALE)} fields, {len(SEE)} shared; "
          f"modality on {sum('modality' in f for f in fields)}, provider-gated {sum('provider_gated' in f for f in fields)}")


if __name__ == '__main__':
    main()
