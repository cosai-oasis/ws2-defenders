#!/usr/bin/env python3
"""Phase 5, one-shot (kept as record): propose structured correlation patterns.

Writes data/candidates/2026-10-02-phase5-patterns.yaml:
  P:CP-nn   type pattern   the structured record that replaces (or adds) CP-nn
  V:<id>    type coverage  why an attack has no pattern

A pattern record:
  id                  a descriptive slug, as field IDs are (`tool_definition_changed`);
                      fixed once accepted and never reused. It carries no order:
                      AD §2 sorts by stage, then minimum tier, then name. The AD
                      anchor is `#p-` plus the slug with hyphens
  former_id           the provisional CP-nn of phase 1, for traceability
  name, indicates     as in AD §2
  stage               entry | decision | action | persistence | egress | plane, in
                      that reading order: the stage at which the pattern can first
                      fire, that is, where its last condition is observed
  match               all (default; conditions in order) or any (alternatives)
  join                fields the condition correlates on (identifiers are not
                      checked against attack edges: a pattern needs them to join,
                      the attack does not evidence them)
  conditions          ordered; each names the fields it reads
  requires            fields the conditions read; the pattern's minimum tier is
                      the weakest tier among requires and the non-identifier join
  enriches            fields that help triage but are not needed to fire
  baseline            what the condition is compared against, where it needs one
  catches             attacks on which the pattern fires, as an instance: the
                      attack has instance edges to every checked field
  catches_analogical  the attack has edges, of either class, to every checked field
  motivation          where no attack is caught

The checks below refuse to write a batch whose catches the edges do not support.
"""
import glob
import re
import os
import sys

from yamlio import dump, load

DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))   # the documents: telemetry/
DATA = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data'))   # build-telemetry/data/
OUT = os.path.join(DATA, 'candidates', '2026-10-02-phase5-patterns.yaml')
STAGES = ('entry', 'decision', 'action', 'persistence', 'egress', 'plane')


def P(id, name, indicates, stage, join, conditions, requires, enriches=(), baseline=None,
      catches=(), analogical=(), motivation=None, reason='', match='all'):
    rec = {'id': id, 'name': name, 'indicates': indicates, 'stage': stage}
    if match != 'all':
        rec['match'] = match
    rec |= {'join': list(join), 'conditions': list(conditions), 'requires': list(requires),
            'enriches': list(enriches)}
    if baseline:
        rec['baseline'] = baseline
    rec['catches'] = list(catches)
    if analogical:
        rec['catches_analogical'] = list(analogical)
    if motivation:
        rec['motivation'] = motivation
    return rec, reason


PATTERNS = [
    P('CP-01', 'Same input across many identities', 'Automated injection campaign', 'entry',
      ['model_input'],
      ['The same **Model Input** content hash arrives under many distinct **Identities Used** within a window.',
       'Optionally from several **Source host / IP** values.'],
      ['model_input', 'identities_used_per_hop'], ['source_host_ip_request_metadata'],
      baseline='Distinct identities per input hash in ordinary traffic.',
      motivation='Template reuse in `IR-01`; no corpus entry records one payload under many identities.',
      reason='stated evidence IR-01 has no Identities Used edge: IR-01 reuses templates across surfaces, not identities'),
    P('CP-02', 'Refusals, then a completion, in one session', 'Jailbreak or extraction succeeded after probing', 'decision',
      ['session_turn_step_ids'],
      ['**LLM Refusal** fires on several turns of a session.',
       'A later turn of the same session, on similar **Model Input**, gets no refusal.'],
      ['llm_refusal', 'model_input'], ['execution_status', 'response_model_output'],
      catches=['TA-07', 'IR-01'],
      reason='adds TA-07 (refuse then succeed); drops AOC-12, which was resisted and fires only the first condition (now CP-34). Success is read from the refusal stopping, so Execution Status moves to enriching'),
    P('CP-03', 'New tool name with a rise in tool calls', 'Agent reaching an unauthorized capability', 'action',
      ['agent_runtime_instance_id'],
      ['A **Tool Name** not seen for this agent appears.',
       '**Tool Call I/O** volume for the run rises above its baseline.'],
      ['tool_name', 'tool_call_io'], ['resource_consumption_aggregate', 'capability_set_change_event'],
      baseline='Tool set and call rate per agent.',
      catches=['TA-06', 'TA-08', 'AOC-02', 'AOC-10'],
      reason='Resource-Consumption Aggregate moves to enriching (no stated attack has an edge to it); adds TA-06 and TA-08'),
    P('CP-04', 'Untrusted input, then a tool call, then egress to a new destination', 'Injection-to-exfiltration chain', 'egress',
      ['session_turn_step_ids', 'trace_context_propagated'],
      ['**Input Trust Classification** marks a segment untrusted.',
       'A later **Tool Call I/O** in the same trace carries content derived from it.',
       '**Output Egress Destination** is one not seen for this agent.'],
      ['input_trust_classification', 'tool_call_io', 'output_egress_destination'],
      baseline='Egress destinations per agent.',
      catches=['TA-01', 'TA-12'],
      reason='adds TA-12; drops TA-03, which has no tool call or trust classification (now CP-46)'),
    P('CP-05', 'Externally sourced memory read back later', 'Memory poisoning or indirect corruption', 'persistence',
      [],
      ['A **Memory Write Event** has a **Memory Provenance / Source** that is a non-owner or external source.',
       'The item is read back (**Memory Read / Injection Event**) in a later session.',
       'Behaviour in that session departs from the request.'],
      ['memory_write_event', 'memory_provenance_source', 'memory_read_injection_event'],
      ['observation_thought_reasoning_trace', 'memory_integrity_poisoning_signal'],
      catches=['TA-18', 'IR-02', 'AOC-10'],
      reason='joins on the memory item; Observation / Thought (SHOULD) moves to enriching, so the minimum tier is MUST; adds TA-18'),
    P('CP-06', 'Instructions followed from an external retrieved item', 'RAG injection or knowledge-base poisoning', 'decision',
      ['session_turn_step_ids'],
      ['A **Retrieval Event** returns an item whose **Retrieved-Content Source / Provenance** is external or recently modified.',
       'The **Response / Model Output** in the same turn follows instructions from that item.'],
      ['retrieval_event', 'retrieved_content_source_provenance', 'response_model_output'],
      catches=['TA-01', 'TA-02', 'TA-09'],
      reason='unchanged evidence; structured'),
    P('CP-07', 'Response reproduces the system prompt', 'System-prompt extraction', 'egress',
      ['session_turn_step_ids'],
      ['The **Response / Model Output** is similar to the **System Prompt / Instruction Config** in force.'],
      ['response_model_output', 'system_prompt_instruction_config'], ['llm_refusal'],
      baseline='A similarity threshold.',
      catches=['TA-07'],
      reason='LLM Refusal moves to enriching'),
    P('CP-08', 'Individually authorized calls chained across identities', 'Tool-chaining privilege escalation', 'action',
      ['workflow_run_id', 'trace_context_propagated'],
      ["A run's **Tool Call I/O** sequence passes a credential or identifier from one call's output into a later call's input.",
       '**Identities Used** changes within the chain.',
       'Each call is individually allowed (**Authorization Decision Record**).'],
      ['tool_call_io', 'identities_used_per_hop', 'authorization_decision_record'],
      ['tool_acl_required_scope', 'loop_step_count_signal'],
      catches=['TA-08'],
      reason='reads the Authorization Decision Record instead of Tool ACL (SHOULD), so the minimum tier is MUST'),
    P('CP-09', 'Input near the context limit ending on a limit or error', 'Context-window abuse: denial of service, cost blow-up or divergence', 'decision',
      ['identities_used_per_hop'],
      ['**Input / Output Token Counts** approach the context window or `max_tokens` in **Inference Parameters**.',
       'The completion ends on a limit (**Stop Reason**) or an **LLM Error / Exception**.',
       'It repeats from the same source.'],
      ['input_output_token_counts', 'inference_parameters', 'stop_reason'],
      ['llm_error_exception', 'resource_consumption_aggregate', 'source_host_ip_request_metadata', 'model_input'],
      catches=['TA-04', 'TA-10'],
      reason='adds TA-04 (max-length output); reads the denominator fields the AD rationale for Inference Parameters names'),
    P('CP-10', 'Inter-agent relay with no terminating step', 'Multi-agent resource-exhaustion loop', 'action',
      ['workflow_run_id', 'trace_context_propagated'],
      ['**Inter-Agent Message** volume between the same agents rises without a terminating step.',
       '**Loop / Step-Count Signal** exceeds its limit.',
       '**Resource-Consumption Aggregate** climbs against the run budget.'],
      ['inter_agent_message', 'loop_step_count_signal', 'resource_consumption_aggregate'],
      catches=['AOC-04'],
      reason='unchanged evidence; structured'),
    P('CP-11', 'Background task with no end condition', 'Runaway automation or persistence', 'persistence',
      ['agent_runtime_instance_id'],
      ['A **Background / Scheduled Task Event** creates a task with no end condition or expiry.',
       'The task outlives the run that created it.'],
      ['background_scheduled_task_event'], ['action_type', 'trigger_type_source_event'],
      catches=['TA-25', 'AOC-04', 'AOC-10'],
      reason='adds TA-25; Action Type moves to enriching'),
    P('CP-12', 'Privileged action authorized on a displayed identity', 'Identity spoofing or confused deputy', 'decision',
      ['session_turn_step_ids'],
      ['**Verified vs Displayed Identity** shows the authorizing principal matched on display name only.',
       'The **Authorization Decision Record** allows a privileged operation on that basis.'],
      ['verified_vs_displayed_identity', 'authorization_decision_record'],
      ['surface_app', 'granted_authorizations_scope'],
      catches=['AOC-08'],
      reason='reads the Authorization Decision Record instead of Granted Authorizations (SHOULD), so the minimum tier is MUST; a new channel (Surface / App) moves to enriching'),
    P('CP-13', 'Model change, or error and stop-reason spike, for one provider', 'Model substitution or provider-side interference', 'decision',
      [],
      ['**Model Name + Version** changes for a deployment with no recorded change.',
       '**LLM Error / Exception** and abnormal **Stop Reason** rates rise for one provider.'],
      ['model_name_version', 'llm_error_exception', 'stop_reason'], ['provider_endpoint_identity'],
      baseline='Model and error-rate history per deployment.',
      catches=['AOC-06'],
      reason='drops TA-06 (analogical Model Name edge only); Provider / Endpoint Identity (MAY) moves to enriching, so the minimum tier is MUST. The conditions are alternatives', match='any'),
    P('CP-14', 'Same identity from a new source', 'Credential theft or session hijack', 'entry',
      ['identities_used_per_hop'],
      ['An identity appears from a **Source host / IP** outside its history.',
       'Optionally on a new **Surface / App**.'],
      ['source_host_ip_request_metadata', 'identities_used_per_hop'], ['surface_app'],
      baseline='Source history per identity.',
      catches=['AOC-15'], analogical=['IR-04'],
      reason='IR-04 is non-AI and its edges are analogical, so it moves to catches_analogical. TA-20 and TA-22 used stolen credentials but have no Source host / IP edge; the session note already holds that lead pending the primary sources'),
    P('CP-15', 'Citation with no matching retrieval', 'Fabricated or attacker-planted citation', 'egress',
      ['session_turn_step_ids'],
      ['A **Citations / Source Attribution** entry resolves to no item a **Retrieval Event** returned in the session.',
       'A citation resolves to an item whose provenance is external or recently modified.'],
      ['citations_source_attribution', 'retrieval_event'],
      ['retrieved_content_source_provenance', 'output_egress_destination'],
      catches=['TA-01', 'TA-02', 'IR-03'],
      reason='unchanged evidence; provenance and egress move to enriching. The conditions are alternatives', match='any'),
    P('CP-16', 'Enforcement point unreached, operation proceeds', 'Control-plane starvation or guardrail bypass by failing open', 'plane',
      ['session_turn_step_ids'],
      ['**Enforcement-Point Availability & Failure Mode** records a callout unreached or timed out.',
       'The operation it guards proceeds.'],
      ['enforcement_point_availability_failure_mode'],
      ['guardrail_input_verdict', 'guardrail_output_verdict', 'resource_consumption_aggregate', 'source_host_ip_request_metadata'],
      catches=['TA-01'], analogical=['TA-10'],
      reason='TA-10 has only an analogical edge to the enforcement-point field'),
    P('CP-17', 'Tool definition changed after approval', 'Tool definition rug pull', 'entry',
      ['mcp_server_identity_primitive'],
      ['The **Tool Definition Digest** at invocation differs from the digest approved for the same tool name and server.'],
      ['tool_definition_digest'], ['mcp_server_identity_primitive', 'tool_call_io', 'human_approval_elicitation_event'],
      baseline='The approved digest per tool.',
      catches=['TA-29'],
      reason='stated evidence (AOC-09, AOC-10, AOC-14) has no digest edge; TA-29 is the instance. TA-15 is malicious as published, so the digest never changes; it is caught by CP-36'),
    P('CP-18', 'Capability added soon after an inter-agent message', 'Cross-agent capability transfer', 'persistence',
      ['agent_runtime_instance_id'],
      ['A **Capability-Set Change Event** adds a tool or MCP server,',
       'within a window after an **Inter-Agent Message** to that agent.'],
      ['capability_set_change_event', 'inter_agent_message'], ['peer_agent_card_descriptor', 'tool_name'],
      catches=['AOC-09'],
      reason='drops AOC-04 (no Capability-Set Change edge); Peer Agent Card (SHOULD) moves to enriching, so the minimum tier is MUST'),
    P('CP-19', 'Code execution with no sandbox', 'Unsandboxed execution reachable from model output', 'action',
      ['tool_execution_id'],
      ['A code-execution **Tool Call I/O** runs with **Execution Environment / Sandbox** recording none.'],
      ['execution_environment_sandbox', 'tool_call_io'], ['tool_type_trust_boundary'],
      catches=['TA-06'], analogical=['AOC-02'],
      reason='AOC-02 has only an analogical sandbox edge'),
    P('CP-20', 'Task callback registered to an undeclared destination', 'Covert egress through delegated-task callbacks', 'egress',
      ['workflow_run_id'],
      ['An **A2A Task Lifecycle Event** registers a push-notification callback.',
       "Its destination (**Output Egress Destination**) is not among the peer's declared endpoints or the agent's egress history."],
      ['a2a_task_lifecycle_event', 'output_egress_destination'], ['peer_agent_card_descriptor'],
      analogical=['AOC-11'],
      reason='drops TA-01 (no A2A edge); AOC-11 has an analogical A2A edge. No corpus entry registers a callback'),
    P('CP-21', 'Inference parameters off the approved baseline', 'Configuration tampering that widens extraction or jailbreak', 'decision',
      [],
      ['**Inference Parameters** on a call differ from the approved baseline: temperature raised, stop sequences removed, `max_tokens` raised.'],
      ['inference_parameters'], ['system_prompt_instruction_config', 'llm_refusal', 'response_model_output'],
      baseline='Approved parameters per deployment.',
      motivation='Per-request overrides of decoding configuration; no corpus entry changes it.',
      reason='stated evidence TA-04 and TA-07 used ordinary prompts, not changed parameters'),
    P('CP-22', 'Autonomous trigger, untrusted content, new egress', 'Zero-click injection-to-exfiltration', 'egress',
      ['workflow_run_id'],
      ['**Trigger Type & Source Event** marks the run autonomous.',
       '**Input Trust Classification** marks the triggering content untrusted.',
       'The run reaches an **Output Egress Destination** not seen for this agent.'],
      ['trigger_type_source_event', 'input_trust_classification', 'output_egress_destination'],
      catches=['TA-01'],
      reason='drops AOC-10 (no trust-classification or egress edge)'),
    P('CP-23', 'Hook coverage or destination changes mid-run', 'Telemetry plane disabled or redirected', 'plane',
      ['agent_runtime_instance_id'],
      ['**Instrumentation Coverage / Hook Attestation** records a hook disabled, or reporting to a new destination, during a run.'],
      ['instrumentation_coverage_hook_status'], ['event_sequence_continuity', 'action_type'],
      catches=['TA-17'],
      reason='TA-17 (redirection) is the instance. The sequence-gap half becomes CP-37, so this pattern no longer needs a SHOULD field'),
    P('CP-24', 'Memory store beyond its limit', 'Memory-store exhaustion or silent limit removal', 'persistence',
      [],
      ['**Memory Footprint / Growth** exceeds the store\'s declared or hard-coded limit, or grows with no matching retention event.'],
      ['memory_footprint_growth'], ['declared_memory_configuration', 'memory_write_event'],
      baseline='The declared limit, or a hard-coded one.',
      catches=['TA-30', 'AOC-05'],
      reason='adds TA-30; drops AOC-07 (no footprint edge); Declared Memory Configuration (MAY) moves to enriching, so the minimum tier is MUST'),
    P('CP-25', 'Data or access across a tenant boundary', 'Cross-tenant bleed', 'decision',
      ['organization_tenant_id'],
      ["A response, retrieval or memory read served to one **Organization / Tenant ID** carries another tenant's data.",
       "An **Authorization Decision Record** allows an operation on another tenant's resource."],
      ['organization_tenant_id', 'authorization_decision_record'],
      ['identities_used_per_hop', 'retrieval_event', 'memory_read_injection_event'],
      catches=['TA-11', 'TA-17'],
      reason='stated evidence AOC-02 and AOC-05 has no tenant edge; TA-11 and TA-17 are the cross-tenant instances. The conditions are alternatives', match='any'),
    P('CP-26', 'Egress under accumulated session taint', 'Write-down attempt or injection-driven exfiltration', 'egress',
      ['session_turn_step_ids'],
      ['**Session Taint Labels & Information-Flow Decisions** show the session tainted by untrusted or sensitive content.',
       'An egress with a clean payload is attempted under that taint (**Output Egress Destination**); a denial records the attempt, an allow the leak.'],
      ['session_taint_labels_information_flow_decisions', 'output_egress_destination'], ['authorization_decision_record'],
      catches=['TA-01', 'AOC-03'],
      reason='drops TA-02 (no egress edge); reads egress, with the denial as enriching'),
    P('CP-27', 'Self-asserted attribute contradicts the authority', 'Agent falsifying its own state or claims', 'plane',
      ['session_turn_step_ids'],
      ['**Attribute Source / Trusted-Provenance Marking** marks an attribute self-asserted.',
       'The authority-supplied value for the same attribute differs.'],
      ['attribute_source_trusted_provenance_marking'],
      ['verified_vs_displayed_identity', 'authorization_decision_record'],
      catches=['AOC-01', 'AOC-08', 'AOC-10', 'AOC-15'],
      reason='adds AOC-15 (an owner-compromise claim made by a non-owner); the comparison fields move to enriching'),
    P('CP-28', 'High-impact action without a covering approval', 'Missing, disabled or replayed human authorization', 'action',
      ['tool_execution_id'],
      ['A high-impact operation executes.',
       'No **Human Approval / Elicitation Event** covers it, or the approval does not cover the executed arguments, or approval was switched off.'],
      ['human_approval_elicitation_event'],
      ['tool_call_io', 'authorization_decision_record', 'capability_set_change_event'],
      catches=['TA-15', 'TA-23', 'TA-29', 'AOC-01', 'AOC-02', 'AOC-07', 'AOC-11'],
      reason='adds TA-15, TA-23 (approval disabled as configuration), TA-29 (dialog padded to hide the arguments) and AOC-02'),
    P('CP-29', 'Denials, then an allow, for the same operation', 'Policy probing; an authorization bypass found', 'decision',
      ['identities_used_per_hop'],
      ['The **Authorization Decision Record** denies an operation repeatedly for one identity or source.',
       'The same operation is later allowed, or the deny codes shift.'],
      ['authorization_decision_record', 'identities_used_per_hop'],
      ['source_host_ip_request_metadata', 'policy_reason_code'],
      catches=['AOC-02', 'AOC-08'],
      reason='drops IR-01 (no authorization edge); AOC-08 was refused on one channel and succeeded on another'),
    P('CP-30', 'Credential minted wider than requested', 'Over-broad delegation or confused deputy', 'decision',
      ['identities_used_per_hop'],
      ['A **Credential Minting & Scope-Narrowing Check** records a granted scope wider than requested, or an inbound token forwarded unnarrowed.'],
      ['token_exchange_scope_narrowing_check'], ['granted_authorizations_scope', 'identities_used_per_hop'],
      catches=['TA-08'], analogical=['AOC-02', 'AOC-08'],
      reason='AOC-08 has only an analogical minting edge'),
    P('CP-31', 'Capability reached with no mediation record', 'Reference-monitor bypass', 'action',
      ['tool_execution_id'],
      ['A **Tool Call I/O** reaches a capability whose **Tool Type / Trust Boundary** requires mediation.',
       'No **Mediation Coverage & Bypass Path** record shows it passed the reference monitor.'],
      ['tool_call_io', 'tool_type_trust_boundary', 'mediation_coverage_bypass_path'],
      catches=['AOC-14'], analogical=['TA-06'],
      reason='AOC-02 has only an analogical mediation edge and no trust-boundary edge, so it is dropped; TA-06 is analogical'),
    P('CP-32', 'Call routed outside the restriction in force', 'Data-residency or routing-policy violation', 'egress',
      [],
      ['A **Backend / Route Restriction Decision** is in force for the session.',
       'The call is served by a **Provider / Endpoint Identity** outside it.'],
      ['backend_route_restriction_decision', 'provider_endpoint_identity'],
      ['session_taint_labels_information_flow_decisions'],
      analogical=['AOC-06'],
      reason='drops TA-01 (no route edge); AOC-06 is analogical'),
    # ---- new: coverage for attacks no pattern caught
    P('CP-33', 'One agent name bound to two peers', 'Agent name collision; wrong-peer dispatch', 'action',
      ['agent_name'],
      ['Within one host, an **Agent Name** resolves to more than one **Peer Agent Card / Descriptor**, endpoint or enrolled identity.',
       '**Verified vs Displayed Identity** shows the requests addressed to the name reach a different peer.'],
      ['peer_agent_card_descriptor', 'verified_vs_displayed_identity'],
      ['identities_used_per_hop', 'inter_agent_message'],
      catches=['TA-31'],
      reason='structures the accepted P:agent-name-collision (supersedes it)'),
    P('CP-34', 'Repeated refusals', 'An attack attempt in progress, resisted or probing', 'decision',
      ['session_turn_step_ids', 'identities_used_per_hop'],
      ['**LLM Refusal** fires repeatedly within a session, or for one identity across sessions.'],
      ['llm_refusal'], ['model_input', 'guardrail_input_verdict'],
      catches=['IR-01', 'AOC-12', 'AOC-13', 'AOC-14'],
      reason='the resisted entries: in them the refusal is the detection'),
    P('CP-35', 'Item flagged as poisoned, then read into context', 'Memory or retrieval poisoning taking effect', 'persistence',
      [],
      ['A **Memory Integrity / Poisoning Signal** flags an item.',
       'The item is later read into context (**Memory Read / Injection Event**).'],
      ['memory_integrity_poisoning_signal', 'memory_read_injection_event'],
      ['memory_provenance_source', 'retrieved_content_metadata_integrity_signal'],
      catches=['TA-18', 'IR-02', 'IR-05'],
      reason='covers IR-05 (optimized triggers), whose provenance is not recorded'),
    P('CP-36', 'Tool arguments carry data the request did not supply', 'Exfiltration through tool arguments: tool poisoning or shadowing', 'egress',
      ['tool_execution_id'],
      ['A **Tool Call I/O** to an MCP tool carries in its arguments content the request did not supply: credential files, chat history, other tools\' output.',
       'The tool was discovered from that server in the same session (**MCP Server Identity & Primitive**).'],
      ['tool_call_io', 'mcp_server_identity_primitive'],
      ['tool_definition_digest', 'output_egress_destination', 'human_approval_elicitation_event'],
      catches=['TA-15', 'TA-29'],
      reason='TA-15 is malicious as published, which no digest comparison catches; the arguments are where it shows'),
    P('CP-37', 'Gap in the event sequence', 'Selective suppression of telemetry', 'plane',
      ['session_turn_step_ids'],
      ['**Event Sequence Continuity** shows a gap or reordering in a session.'],
      ['event_sequence_continuity'], ['instrumentation_coverage_hook_status'],
      analogical=['TA-17', 'AOC-01', 'AOC-10'],
      reason='the sequence-gap half of the old CP-23; every edge to the field is analogical'),
    P('CP-38', 'MCP server version not the approved one', 'Implementation rug pull under an adopted name', 'entry',
      ['mcp_server_identity_primitive'],
      ['**MCP Server Identity & Primitive** reports a version, package or publisher not in the approved inventory, under an approved name.'],
      ['mcp_server_identity_primitive'],
      ['tool_agent_version', 'repository_code_path_software_ref', 'agbom_inventory_snapshot', 'output_egress_destination'],
      baseline='Approved name and version per server.',
      catches=['TA-16'],
      reason='covers TA-16; the declared contract did not change, the shipped version did'),
    P('CP-39', 'Capability or configuration change with no approval', 'Configuration rug pull, or a safeguard switched off', 'persistence',
      ['agent_runtime_instance_id'],
      ['A **Capability-Set Change Event** records a changed launch command, arguments or approval setting for an approved tool or agent.',
       'No approval accompanies the change.'],
      ['capability_set_change_event'], ['execution_environment_sandbox', 'human_approval_elicitation_event'],
      catches=['TA-14', 'TA-23', 'TA-29'],
      reason='covers TA-14 and TA-23'),
    P('CP-40', 'Consumption spike and model enumeration under one identity', 'Stolen-credential model access (LLMjacking)', 'action',
      ['identities_used_per_hop'],
      ['For one identity, **Resource-Consumption Aggregate** rises far above its baseline.',
       'Its calls enumerate or switch to models (**Model Name + Version**) it did not use before.'],
      ['identities_used_per_hop', 'resource_consumption_aggregate', 'model_name_version'],
      ['input_output_token_counts', 'provider_endpoint_identity', 'source_host_ip_request_metadata'],
      baseline='Consumption and model set per identity.',
      catches=['TA-20'],
      reason='covers TA-20'),
    P('CP-41', 'Guardrail blocks stop while volume continues', 'Guardrail bypass operated at scale', 'decision',
      ['identities_used_per_hop'],
      ['**Guardrail (Input) Verdict** blocks repeatedly for an identity, then stops while request volume continues.',
       '**Guardrail (Output) Verdict** flags output for the same identity.'],
      ['guardrail_input_verdict', 'guardrail_output_verdict', 'identities_used_per_hop'],
      ['llm_refusal', 'organization_tenant_id'],
      catches=['TA-22'],
      reason='covers TA-22'),
    P('CP-42', 'Untrusted content acted on in a later turn', 'Delayed tool invocation', 'action',
      ['session_turn_step_ids'],
      ['**Input Trust Classification** marks content untrusted in one turn.',
       'A sensitive **Tool Call I/O** in a later turn of the same session follows it, with no new user request.'],
      ['input_trust_classification', 'tool_call_io'], ['model_input'],
      catches=['TA-19'],
      reason='covers TA-19; a detection scoped to one turn misses it'),
    P('CP-43', 'Untrusted attachment, then a destructive tool call', 'Attachment-borne injection reaching a shell', 'action',
      ['workflow_run_id'],
      ['**Content Modality & Attachment Identity** records a file or image that **Input Trust Classification** marks untrusted.',
       'A destructive or shell **Tool Call I/O** follows in the same run.'],
      ['content_modality_attachment_identity', 'input_trust_classification', 'tool_call_io'],
      ['guardrail_input_verdict', 'action_type'],
      catches=['TA-26'],
      reason='covers TA-26'),
    P('CP-44', 'Input content re-emitted to another agent or store', 'Self-replicating prompt propagation', 'egress',
      ['trace_context_propagated'],
      ['A **Model Input** content hash reappears in an outbound **Inter-Agent Message**, or in content stored where it is retrieved again.'],
      ['model_input', 'inter_agent_message'],
      ['retrieved_content_source_provenance', 'memory_write_event', 'trigger_type_source_event'],
      catches=['TA-27'],
      reason='covers TA-27'),
    P('CP-45', 'Obfuscated content in the instruction configuration', 'Instruction-file poisoning', 'entry',
      ['agent_runtime_instance_id'],
      ['The **System Prompt / Instruction Config** loaded for a run contains content flagged by **Encoded / Obfuscated Payload Indicator**.'],
      ['system_prompt_instruction_config', 'encoded_obfuscated_payload_indicator'],
      ['repository_code_path_software_ref', 'attribute_source_trusted_provenance_marking'],
      catches=['TA-21'],
      reason='covers TA-21'),
    P('CP-46', 'Output link carrying session data', 'Exfiltration through a rendered link or image', 'egress',
      ['session_turn_step_ids'],
      ['A **Response / Model Output** contains a URL whose path or query carries data from the session.',
       'The client fetches it (**Output Egress Destination**).'],
      ['response_model_output', 'output_egress_destination'], ['source_host_ip_request_metadata'],
      catches=['TA-01', 'TA-03'],
      reason='takes TA-03 from CP-04, whose tool-call and trust conditions it does not meet'),
    P('CP-47', 'Long autonomous run against many external targets', 'Agent operated as an attack framework', 'action',
      ['workflow_run_id'],
      ['A run\'s **Loop / Step-Count Signal** is long and its **Tool Call I/O** reaches many external targets.',
       'The activity does not match the declared task, or none is declared.'],
      ['loop_step_count_signal', 'tool_call_io'],
      ['task_intent_declaration', 'llm_refusal', 'trigger_type_source_event'],
      catches=['TA-24'],
      reason='covers TA-24 from the operator of the agent runtime, where it was detected; the victims see ordinary intrusion traffic'),
    P('CP-48', 'Sensitive input to an off-inventory AI service', 'Shadow AI use leaking data', 'egress',
      ['identities_used_per_hop'],
      ['An **Agent Name** or **Surface / App** not in the inventory receives **Model Input**.',
       'The input is sensitive by content or by the tool\'s classification.'],
      ['agent_name', 'surface_app', 'model_input'],
      ['tool_privacy_classification', 'guardrail_input_verdict'],
      baseline='The agent inventory.',
      catches=['TA-05'],
      reason='covers TA-05. The plan expected no pattern because TA-05 has no adversary, but RFC §4.7 admits non-adversarial failures and this one is detectable'),
    P('CP-49', 'Privileged MCP tool invoked by a low-privilege identity', 'Privilege escalation at the MCP tool boundary', 'decision',
      ['mcp_server_identity_primitive'],
      ['An identity without the privilege invokes a privileged MCP tool (**Identities Used**, **MCP Server Identity & Primitive**).',
       'The **Authorization Decision Record** allows it, or records no decision at the tool boundary.'],
      ['identities_used_per_hop', 'mcp_server_identity_primitive', 'authorization_decision_record'],
      ['granted_authorizations_scope', 'tool_error_exception'],
      catches=['TA-13'],
      reason='covers TA-13'),
]

SLUG = {
    'CP-01': 'same_input_many_identities', 'CP-02': 'refusals_then_completion',
    'CP-03': 'new_tool_with_call_spike', 'CP-04': 'untrusted_input_to_new_egress',
    'CP-05': 'external_memory_read_back', 'CP-06': 'retrieved_instructions_followed',
    'CP-07': 'system_prompt_reproduced', 'CP-08': 'authorized_calls_chained_across_identities',
    'CP-09': 'context_limit_abuse', 'CP-10': 'inter_agent_relay_loop',
    'CP-11': 'background_task_without_end', 'CP-12': 'privileged_action_on_displayed_identity',
    'CP-13': 'model_or_provider_anomaly', 'CP-14': 'identity_from_new_source',
    'CP-15': 'citation_without_retrieval', 'CP-16': 'enforcement_point_fail_open',
    'CP-17': 'tool_definition_changed', 'CP-18': 'capability_after_inter_agent_message',
    'CP-19': 'unsandboxed_code_execution', 'CP-20': 'callback_to_undeclared_destination',
    'CP-21': 'inference_parameters_off_baseline', 'CP-22': 'zero_click_to_new_egress',
    'CP-23': 'hook_coverage_changed', 'CP-24': 'memory_beyond_limit',
    'CP-25': 'cross_tenant_access', 'CP-26': 'egress_under_session_taint',
    'CP-27': 'self_asserted_attribute_contradicted', 'CP-28': 'action_without_covering_approval',
    'CP-29': 'denials_then_allow', 'CP-30': 'credential_wider_than_requested',
    'CP-31': 'unmediated_capability', 'CP-32': 'route_outside_restriction',
    'CP-33': 'agent_name_collision', 'CP-34': 'repeated_refusals',
    'CP-35': 'poisoned_item_read', 'CP-36': 'unrequested_data_in_tool_arguments',
    'CP-37': 'event_sequence_gap', 'CP-38': 'mcp_server_version_unapproved',
    'CP-39': 'unapproved_capability_change', 'CP-40': 'consumption_spike_with_model_enumeration',
    'CP-41': 'guardrail_blocks_stop', 'CP-42': 'untrusted_content_acted_on_later',
    'CP-43': 'untrusted_attachment_to_destructive_tool', 'CP-44': 'input_reemitted',
    'CP-45': 'obfuscated_instruction_config', 'CP-46': 'output_link_carrying_data',
    'CP-47': 'autonomous_run_against_external_targets', 'CP-48': 'sensitive_input_to_off_inventory_ai',
    'CP-49': 'privileged_mcp_tool_low_privilege_identity',
}

NO_PATTERN = {
    'TA-28': 'Outside the deployment: the backdoor ran on a compromised host and used the provider API from there, so no instrumented AI system carries the activity. Detection belongs to endpoint and network monitoring of provider API use; within a deployment, Output Egress Destination records what its own calls send.',
    'AOC-16': 'An emergent defence, not an attack: agents shared risk signals about a probing researcher. A pattern would detect the defence. Its Inter-Agent Message edge supports reading such signals.',
    'IR-04': 'A non-AI incident, carried for field overlap; its edges are analogical. CP-14 catches it analogically.',
}


def main():
    fields = {f['id']: f for f in load(os.path.join(DATA, 'fields.yaml'))}
    attacks = {}
    for p in glob.glob(os.path.join(DATA, 'attacks', '*.yaml')):
        a = load(p)
        attacks[a['id']] = {(e if isinstance(e, str) else e['field']):
                            ('instance' if isinstance(e, str) else e.get('grounding', 'instance'))
                            for e in a.get('fields', [])}
    rank = {'MUST': 0, 'SHOULD': 1, 'MAY': 2}
    tier = lambda r: max((fields[f]['tier'] for f in r['requires'] + r['join']), key=rank.get)
    assert sorted(SLUG) == sorted(r['id'] for r, _ in PATTERNS), 'every pattern needs exactly one slug'
    assert len(set(SLUG.values())) == len(SLUG) and all(re.fullmatch(r'[a-z0-9_]+', s) for s in SLUG.values())
    new_id = SLUG
    relabel = lambda s: re.sub(r'CP-\d\d', lambda m: f'`{new_id[m[0]]}`', s)
    renamed = []
    for rec, reason in PATTERNS:
        rec = {'id': new_id[rec['id']], 'former_id': rec['id']} | {k: v for k, v in rec.items() if k != 'id'}
        if 'motivation' in rec:
            rec['motivation'] = relabel(rec['motivation'])
        renamed.append((rec, relabel(reason)))
    renamed.sort(key=lambda p: (STAGES.index(p[0]['stage']), rank[tier(p[0])], p[0]['name'].casefold()))
    for a in NO_PATTERN:
        NO_PATTERN[a] = relabel(NO_PATTERN[a])
    errors, out = [], []
    for rec, reason in renamed:
        pid = rec['id']
        for f in rec['join'] + rec['requires'] + rec['enriches']:
            if f not in fields:
                errors.append(f'{pid}: unknown field {f}')
        if rec['stage'] not in STAGES:
            errors.append(f'{pid}: stage {rec["stage"]}')
        checked = set(rec['requires']) | {f for f in rec['join'] if fields[f]['role'] != 'identifier'}
        for a in rec['catches']:
            bad = [f for f in checked if attacks[a].get(f) != 'instance']
            if bad:
                errors.append(f'{pid} catches {a}: no instance edge to {bad}')
        for a in rec.get('catches_analogical', []):
            bad = [f for f in checked if f not in attacks[a]]
            if bad:
                errors.append(f'{pid} analogically catches {a}: no edge to {bad}')
        if not rec['catches'] and not rec.get('catches_analogical') and not rec.get('motivation'):
            errors.append(f'{pid}: catches nothing and has no motivation')
        c = {'id': f'P:{pid}', 'type': 'pattern', 'subject': {'pattern': pid}, 'source': 'phase5',
             'proposal': rec, 'reason': reason, 'status': 'proposed'}
        if rec['former_id'] == 'CP-33':
            c['supersedes'] = 'P:agent-name-collision'
        out.append(c)
    caught = {a for rec, _ in renamed for a in rec['catches'] + rec.get('catches_analogical', [])}
    for a in sorted(attacks):
        if a not in caught and a not in NO_PATTERN:
            errors.append(f'{a}: no pattern and no recorded reason')
    for a, why in NO_PATTERN.items():
        out.append({'id': f'V:{a}', 'type': 'coverage', 'subject': {'attack': a}, 'source': 'phase5',
                    'proposal': {'no_pattern': why}, 'reason': 'no pattern proposed', 'status': 'proposed'})
    if errors:
        sys.exit('\n'.join(errors))
    read = {f for rec, _ in renamed for f in rec['requires'] + rec['join']}
    unread = [fields[f]['name'] for f in fields if fields[f]['tier'] == 'MUST' and f not in read]
    tiers = {}
    for rec, _ in renamed:
        tiers.setdefault(tier(rec), []).append(rec['id'])
    header = ('# Curation registry batch. Edit status only through tools/curate.py, or by hand\n'
              '# keeping decided_by and decided_on filled in. See curate.py for the schema.\n'
              '# Phase 5: structured correlation patterns (tools/phase5_propose.py documents the record).\n')
    dump(out, OUT, header)
    instance = {a for rec, _ in renamed for a in rec['catches']}
    print(f'{len(PATTERNS)} patterns, {len(NO_PATTERN)} no-pattern reasons -> {os.path.relpath(OUT, DIR)}')
    print(f'attacks caught as an instance: {len(instance)} of {len(attacks)}')
    print('minimum tier:', {t: len(v) for t, v in tiers.items()}, 'non-MUST:', tiers.get('SHOULD', []) + tiers.get('MAY', []))
    print(f'MUST fields read by no pattern ({len(unread)}):', ', '.join(unread))


if __name__ == '__main__':
    main()
