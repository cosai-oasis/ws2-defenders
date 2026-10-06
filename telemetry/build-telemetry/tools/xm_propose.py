#!/usr/bin/env python3
"""XM pass, one-shot (kept as record): propose data/mapping.yaml.

Writes data/candidates/2026-10-02-xm-mapping.yaml:
  Q:<ask id>                    type ask      a proposal to a publication
  M:<field>:<publication>       type mapping  how a publication carries a field
  C:<field>                     type controls the Risk Map controls the field helps implement

Sources: XM §2.2 (OpenTelemetry), §3.1 and §3.2 (OCSF), §4 (AITF and ODIS, already
per field; for AITF, the namespaces of AITF_gaps.md supersede §4 where AITF v0.4 closed a gap) and §1.2 (controls, per old cluster). OCSF and OpenTelemetry were mapped
by cluster, so each per-field entry is a judgement from the cluster row; a field the
row does not address is `unassessed`, never guessed. Every construct is resolved
against the publication pinned in sources.yaml (tools/vocab.py); a construct that
does not resolve is reported, and the batch is not written until each is either
removed or covered by an ask that proposes it.

A mapping entry:
  coverage    covered | partial | none | out_of_scope | unassessed
  constructs  names defined at the pin: OCSF `class:<uid|name>`, `object:`,
              `profile:`, `attribute:`; OpenTelemetry attribute, metric, span or
              event names; AITF attribute names (a trailing `.*` names a namespace);
              ODIS field names
  gap         what the publication cannot express (partial and none)
  asks        ask IDs that would close the gap
  note        anything else a reader needs
"""
import os
import re
import sys

import yaml

import rules
import vocab
from yamlio import dump, load

DIR, DATA = rules.DIR, rules.DATA
OUT = os.path.join(DATA, 'candidates', '2026-10-02-xm-mapping.yaml')
XM = os.path.join(DIR, 'Telemetry-Cross-Mapping-Addendum.md')

# ---------------------------------------------------------------- asks
ASKS = [
    # OCSF (XM §3.1, §3.2)
    ('ocsf_ai_agent_activity', 'ocsf', 'Ratify an AI Agent Activity class (9001) for agent-originated control-plane events: inter-agent messages, background tasks, loop and resource aggregates, capability changes.', ['class:9001'], ['ocsf-schema#1640'], 'open'),
    ('ocsf_ai_delegation_activity', 'ocsf', 'Ratify an AI Delegation Activity class (9002) for the delegation lifecycle.', ['class:9002'], ['ocsf-schema#1640'], 'open'),
    ('ocsf_ai_operation_identifiers', 'ocsf', 'Extend the ai_operation profile with run, turn and step identifiers, action type and trigger type.', [], [], 'proposed'),
    ('ocsf_stop_reason', 'ocsf', 'Merge ai_stop_reason_id on the ai_operation profile (End of Turn, Token Limit, Tool Use, Session Stop, Content Filter).', ['attribute:ai_stop_reason_id'], ['ocsf-schema#1704'], 'approved'),
    ('ocsf_message_context_content', 'ocsf', 'Extend message_context with prompt and response hashes, a redaction flag, the system prompt and its hash, and attachment identity, each hash with its canonicalization declaration.', ['attribute:prompt_hash', 'attribute:response_hash', 'attribute:is_redacted', 'attribute:system_prompt'], [], 'proposed'),
    ('ocsf_trust_level', 'ocsf', 'Add a trust_level enum usable on content and message objects.', ['attribute:trust_level'], [], 'proposed'),
    ('ocsf_autonomy_level', 'ocsf', 'Add an autonomy_level enum.', ['attribute:autonomy_level'], [], 'proposed'),
    ('ocsf_ai_guardrail', 'ocsf', 'Add an ai_guardrail object (type, verdict, score, blocked flag, threat reference), with enforcement availability and failure-mode attributes.', ['object:ai_guardrail'], [], 'proposed'),
    ('ocsf_egress_correlation', 'ocsf', 'Add an egress correlation attribute linking model output to its destination, recipient or URL.', [], [], 'proposed'),
    ('ocsf_model_provenance', 'ocsf', 'Standardize model provider and provenance or signing attributes in ai_operation.', [], [], 'proposed'),
    ('ocsf_ai_tool', 'ocsf', 'Land the ai_tool object with its mcp sub-block, primitive axis and transaction_uid join key; add a tool_trust_boundary enum and a scope attribute.', ['object:ai_tool', 'attribute:tool_trust_boundary', 'attribute:transaction_uid'], ['ocsf-schema#1729'], 'open'),
    ('ocsf_ai_memory', 'ocsf', 'Add an ai_memory object (operation, provenance, footprint, poisoning score, isolation verified).', ['object:ai_memory'], [], 'proposed'),
    ('ocsf_ai_retrieval', 'ocsf', 'Add an ai_retrieval object (query, items, source and provenance, integrity signal).', ['object:ai_retrieval'], [], 'proposed'),
    ('ocsf_delegation_lineage', 'ocsf', 'Extend delegation with scope, constraints and lifecycle state; require parent_uid where a parent exists; add a root or subtree identifier.', [], ['ocsf-schema#1739'], 'open'),
    ('ocsf_runtime_attestation', 'ocsf', 'Add a runtime_attestation object carrying independently issued evidence objects and an explicit not-available status with a reason.', ['object:runtime_attestation'], [], 'proposed'),
    ('ocsf_ai_asset', 'ocsf', 'Add an ai_asset object (version, software reference, ownership, status, instrumentation coverage).', ['object:ai_asset'], ['ocsf-schema#1724'], 'open'),
    ('ocsf_ai_bom', 'ocsf', 'Add an ai_bom object (BOM reference, format, signature, dependency edges) and a capability-change activity on Agent Activity.', ['object:ai_bom'], ['ocsf-schema#1724'], 'open'),
    ('ocsf_ai_authorization', 'ocsf', 'Add an ai_authorization object (decision, reason, code, deciding authority, rule, obligations, budget accounting and the principal or subtree join key).', ['object:ai_authorization'], [], 'proposed'),
    ('ocsf_ai_taint', 'ocsf', 'Add an ai_taint object (labels, scope, origin, taint-caused denial).', ['object:ai_taint'], [], 'proposed'),
    ('ocsf_ai_approval', 'ocsf', 'Add an ai_approval object (correlation ID, status, identity-provider-verified approver, channel, scope-binding result).', ['object:ai_approval'], [], 'proposed'),
    ('ocsf_attribute_source', 'ocsf', 'Add an attribute_source enum (idp, pdp, enforcement-state, platform, self-asserted) usable on identity, authorization and agent-state attributes.', ['attribute:attribute_source'], [], 'proposed'),
    # OpenTelemetry (XM §2.2, §2.3)
    ('otel_trust_level', 'otel_genai', 'Add gen_ai.input.trust_level on message parts (trusted or untrusted, crossed with instruction or data).', ['gen_ai.input.trust_level'], [], 'proposed'),
    ('otel_security_guardrail', 'otel_genai', 'Extend the evaluation event for security use (blocked or allowed, guardrail type, threat technique), or add gen_ai.guardrail.*.', [], [], 'proposed'),
    ('otel_memory_provenance_footprint', 'otel_genai', 'Add provenance and footprint attributes to gen_ai.memory.*.', [], [], 'proposed'),
    ('otel_retrieval_provenance', 'otel_genai', 'Add per-document source, owner, trust level and last-modified attributes to retrieval documents.', [], [], 'proposed'),
    ('otel_turn_step_ids', 'otel_genai', 'Add gen_ai.turn.id and gen_ai.step.id.', ['gen_ai.turn.id', 'gen_ai.step.id'], [], 'proposed'),
    ('otel_trigger', 'otel_genai', 'Add gen_ai.trigger.type (user_initiated or autonomous) and gen_ai.trigger.event; scheduled and self-triggered runs use it.', ['gen_ai.trigger.type', 'gen_ai.trigger.event'], [], 'proposed'),
    ('otel_tool_digest_mcp_primitive', 'otel_genai', 'Add gen_ai.tool.definitions.hash and an mcp.primitive value set (tool, resource, prompt, sampling, elicitation, roots).', ['gen_ai.tool.definitions.hash', 'mcp.primitive'], [], 'proposed'),
    ('otel_attachment_identity', 'otel_genai', 'Add attachment identity (name, size, hash) on message parts.', [], [], 'proposed'),
    ('otel_model_provenance', 'otel_genai', 'Add gen_ai.model.hash, gen_ai.model.signature and gen_ai.model.source.', ['gen_ai.model.hash', 'gen_ai.model.signature', 'gen_ai.model.source'], [], 'proposed'),
    ('otel_hash_only_capture', 'otel_genai', 'Ensure a hash-only content-capture mode exists for message content.', [], [], 'proposed'),
    ('otel_citations', 'otel_genai', 'Add citation attributes on output messages with a resolution flag against retrieval.', [], [], 'proposed'),
    ('otel_execution_environment', 'otel_genai', 'Add execution-environment attributes (sandbox, runtime, egress policy) for tool execution.', [], [], 'proposed'),
    ('otel_inter_agent_messaging', 'otel_genai', 'Add inter-agent messaging attributes.', [], [], 'proposed'),
    ('otel_run_budget', 'otel_genai', 'Add per-run budget and threshold semantics; document security use of the loop metrics.', [], [], 'proposed'),
    ('otel_capability_change', 'otel_genai', 'Add a capability-change event; reference an external BOM by URI or digest.', [], [], 'proposed'),
    ('otel_hook_coverage', 'otel_genai', 'Record instrumentation hook coverage as a resource attribute.', [], [], 'proposed'),
    ('otel_egress_pattern', 'otel_genai', 'Document correlating model output to its destination through the HTTP and network conventions on the child span.', [], [], 'proposed'),
    ('otel_authorization_reference', 'otel_genai', 'Let a span reference an authorization decision by ID, so OpenTelemetry and OCSF records join at query time.', [], [], 'proposed'),
]

U = 'unassessed'


def m(coverage, constructs=(), gap=None, asks=(), note=None):
    e = {'coverage': coverage}
    if constructs:
        e['constructs'] = list(constructs)
    if gap:
        e['gap'] = gap
    if asks:
        e['asks'] = list(asks)
    if note:
        e['note'] = note
    return e


# ---------------------------------------------------------------- OCSF, per field (XM §3.1)
AIOP = 'profile:ai_operation'
OCSF = {
    'agent_name': m('covered', [AIOP, 'object:ai_agent']),
    'agent_runtime_instance_id': m('covered', ['object:ai_agent', 'attribute:instance_uid']),
    'workflow_run_id': m('none', gap='No workflow or run identifier', asks=['ocsf_ai_operation_identifiers']),
    'session_turn_step_ids': m('partial', ['object:message_context'], 'A session identifier only; no turn or step', ['ocsf_ai_operation_identifiers']),
    'trace_context_propagated': m(U),
    'organization_tenant_id': m(U),
    'trigger_type_source_event': m('none', gap='No trigger type', asks=['ocsf_ai_operation_identifiers']),
    'action_type': m('none', gap='No action type', asks=['ocsf_ai_operation_identifiers']),
    'execution_status': m(U),
    'stop_reason': m('none', gap='ai_stop_reason_id is approved (#1704) but not in 1.9.0', asks=['ocsf_stop_reason']),
    'surface_app': m(U),
    'system_prompt_instruction_config': m('none', gap='No system prompt in message_context', asks=['ocsf_message_context_content']),
    'autonomy_level': m('none', gap='No autonomy level', asks=['ocsf_autonomy_level']),
    'model_input': m('partial', ['object:message_context', 'attribute:prompt_text'], 'No content hash or redaction flag', ['ocsf_message_context_content']),
    'input_source_channel': m(U),
    'input_trust_classification': m('partial', ['class:2004'], 'No trust-provenance enum', ['ocsf_trust_level']),
    'source_host_ip_request_metadata': m(U),
    'guardrail_input_verdict': m('partial', ['class:2004'], 'No guardrail-verdict object', ['ocsf_ai_guardrail']),
    'content_modality_attachment_identity': m('none', gap='No attachment identity', asks=['ocsf_message_context_content']),
    'guardrail_modification_record': m('none', gap='No record that an enforcement point rewrote a payload', asks=['ocsf_ai_guardrail', 'ocsf_message_context_content']),
    'threat_classification_atlas_technique_tag': m('covered', ['class:2004', 'attribute:attacks'], note='No schema change: populate attacks[].technique.uid with AML.Txxxx, the tactic, and attacks[].version with the ATLAS matrix version.'),
    'encoded_obfuscated_payload_indicator': m(U),
    'response_model_output': m('partial', ['object:message_context', 'attribute:response_text'], 'No content hash or redaction flag', ['ocsf_message_context_content']),
    'output_egress_destination': m('partial', ['class:http_activity', 'class:network_activity'], 'No link from model output to the egress channel or recipient', ['ocsf_egress_correlation']),
    'citations_source_attribution': m(U),
    'observation_thought_reasoning_trace': m(U),
    'guardrail_output_verdict': m('partial', ['class:2004'], 'No guardrail-verdict object', ['ocsf_ai_guardrail']),
    'llm_refusal': m(U),
    'model_name_version': m('covered', [AIOP, 'object:ai_model']),
    'provider_endpoint_identity': m('partial', ['object:ai_model'], 'Provider not standardized in the profile', ['ocsf_model_provenance']),
    'inference_parameters': m(U),
    'input_output_token_counts': m('covered', ['object:message_context']),
    'llm_error_exception': m(U),
    'model_provenance_signing_hash': m('none', gap='Provenance and signing not standardized in the profile', asks=['ocsf_model_provenance']),
    'pre_forward_pass_state_digest_vector': m(U),
    'token_malformation_context_corruption_indicator': m(U),
    'tool_call_io': m('partial', ['class:6003'], 'No tool object', ['ocsf_ai_tool']),
    'tool_name': m('none', gap='No tool object', asks=['ocsf_ai_tool']),
    'tool_type_trust_boundary': m('none', gap='No tool trust-boundary enum', asks=['ocsf_ai_tool']),
    'tool_id': m('none', gap='No tool object', asks=['ocsf_ai_tool']),
    'tool_execution_id': m('none', gap='No tool-call join key', asks=['ocsf_ai_tool']),
    'tool_definition_digest': m('none', gap='No tool-definition digest', asks=['ocsf_ai_tool']),
    'execution_environment_sandbox': m(U),
    'mcp_server_identity_primitive': m('none', gap='No MCP object or primitive axis', asks=['ocsf_ai_tool']),
    'tool_error_exception': m(U),
    'tool_acl_required_scope': m('none', gap='No tool scope attribute', asks=['ocsf_ai_tool']),
    'tool_privacy_classification': m(U),
    'tool_selection_rationale': m(U),
    'memory_write_event': m('partial', ['class:6005'], 'Datastore Activity fits loosely; no memory-operation object', ['ocsf_ai_memory']),
    'memory_read_injection_event': m('partial', ['class:6005'], 'Datastore Activity fits loosely; no memory-operation object', ['ocsf_ai_memory']),
    'memory_provenance_source': m('none', gap='No memory provenance', asks=['ocsf_ai_memory']),
    'memory_integrity_poisoning_signal': m('none', gap='No poisoning or isolation signal', asks=['ocsf_ai_memory']),
    'memory_footprint_growth': m('none', gap='No memory footprint', asks=['ocsf_ai_memory']),
    'declared_memory_configuration': m(U),
    'memory_write_rationale': m(U),
    'retrieval_event': m('partial', ['class:6005'], 'No retrieval object', ['ocsf_ai_retrieval']),
    'retrieved_content_source_provenance': m('none', gap='No retrieved-content source or provenance', asks=['ocsf_ai_retrieval']),
    'retrieved_content_metadata_integrity_signal': m('none', gap='No retrieved-content integrity signal', asks=['ocsf_ai_retrieval']),
    'declared_knowledge_source_configuration': m(U),
    'inter_agent_message': m('none', gap='No inter-agent message', asks=['ocsf_ai_agent_activity']),
    'a2a_task_lifecycle_event': m('none', gap='No delegated-task lifecycle', asks=['ocsf_ai_delegation_activity']),
    'peer_agent_card_descriptor': m(U),
    'background_scheduled_task_event': m('none', gap='No background-task event', asks=['ocsf_ai_agent_activity']),
    'loop_step_count_signal': m('none', gap='No loop or step signal', asks=['ocsf_ai_agent_activity']),
    'resource_consumption_aggregate': m('none', gap='No resource aggregate, and no budget accounting on the consuming action', asks=['ocsf_ai_agent_activity', 'ocsf_ai_authorization']),
    'task_intent_declaration': m(U),
    'protocol_envelope_capture': m(U),
    'identities_used_per_hop': m('partial', ['class:3002', 'object:delegation'], 'Credential events and the delegation context exist; per-hop identity is not tied to the AI operation', ['ocsf_delegation_lineage']),
    'verified_vs_displayed_identity': m(U),
    'originating_principal_on_behalf_of': m(U),
    'delegation_chain': m('partial', ['object:delegation', 'attribute:parent_uid'], 'parent_uid is optional, so one record without it breaks the walk; no root or subtree identifier', ['ocsf_delegation_lineage', 'ocsf_ai_delegation_activity']),
    'granted_authorizations_scope': m('none', gap='No granted scope on delegation', asks=['ocsf_delegation_lineage']),
    'resource_indicators_constraints': m('none', gap='No constraints on delegation', asks=['ocsf_delegation_lineage']),
    'token_exchange_scope_narrowing_check': m('partial', ['class:3002'], 'No requested-versus-granted scope', ['ocsf_delegation_lineage']),
    'trust_domain_crossing_delegation_depth': m('none', gap='No trust-domain crossing; depth derivable only if every hop carries parent_uid', asks=['ocsf_delegation_lineage']),
    'runtime_credential_attestation': m('none', gap='No runtime attestation (OCSF attestation means record integrity)', asks=['ocsf_runtime_attestation']),
    'lifecycle_state': m('none', gap='No lifecycle state on delegation', asks=['ocsf_delegation_lineage']),
    'capability_set_change_event': m('none', gap='No capability-change event', asks=['ocsf_ai_bom', 'ocsf_ai_agent_activity']),
    'tool_agent_version': m('partial', ['class:inventory_info'], 'No AI-asset object', ['ocsf_ai_asset']),
    'repository_code_path_software_ref': m('partial', ['class:inventory_info'], 'No AI-asset object', ['ocsf_ai_asset']),
    'agbom_inventory_snapshot': m('none', gap='No agent-composition BOM', asks=['ocsf_ai_bom']),
    'component_dependency_graph': m('none', gap='No dependency graph', asks=['ocsf_ai_bom']),
    'inventory_integrity_signature': m('none', gap='No BOM signature', asks=['ocsf_ai_bom']),
    'tool_description': m('partial', ['class:inventory_info'], 'No AI-asset object', ['ocsf_ai_asset']),
    'tool_status': m('partial', ['class:inventory_info'], 'No AI-asset object', ['ocsf_ai_asset']),
    'creator_id_oncall_creation_update_dates': m('partial', ['class:inventory_info'], 'No AI-asset object', ['ocsf_ai_asset']),
    'surfaces_supported': m(U),
    'fleet_counts': m('none', gap='Fleet aggregates are derived', note='Derived from per-event records; no ask.'),
    'enforcement_point_availability_failure_mode': m('none', gap='No enforcement availability or fail-open representation', asks=['ocsf_ai_guardrail']),
    'instrumentation_coverage_hook_status': m('none', gap='No hook-coverage representation', asks=['ocsf_ai_asset']),
    'event_sequence_continuity': m('covered', ['profile:record_integrity', 'object:attestation', 'attribute:prev_event', 'attribute:chain_uid'], note='No new schema: continuity maps to attestation.prev_event and attestation.chain_uid.'),
    'policy_reason_code': m('none', gap='No machine-readable enforcement reason code', asks=['ocsf_ai_authorization']),
    'authorization_decision_record': m('partial', ['class:3003'], 'No authorization-decision object for AI operations', ['ocsf_ai_authorization']),
    'attribute_source_trusted_provenance_marking': m('none', gap='No attribute-provenance marking', asks=['ocsf_attribute_source']),
    'session_taint_labels_information_flow_decisions': m('none', gap='No information-flow or taint labels', asks=['ocsf_ai_taint']),
    'human_approval_elicitation_event': m('none', gap='No human-approval lifecycle', asks=['ocsf_ai_approval']),
    'backend_route_restriction_decision': m(U),
    'mediation_coverage_bypass_path': m('none', gap='No mediation-coverage representation', note='XM names the gap and proposes no change; decide an ask or record why none.'),
}

# ---------------------------------------------------------------- OpenTelemetry, per field (XM §2.2)
OOS = 'An authorization-domain concern; carried by OCSF rather than pushed into OpenTelemetry (XM §2.3).'
OTEL = {
    'agent_name': m('covered', ['gen_ai.agent.name']),
    'agent_runtime_instance_id': m('covered', ['gen_ai.agent.id']),
    'workflow_run_id': m('partial', ['gen_ai.workflow.name'], 'A workflow name, not a run identifier; the run maps to the trace ID'),
    'session_turn_step_ids': m('partial', ['gen_ai.conversation.id'], 'No turn or step identifier', ['otel_turn_step_ids']),
    'trace_context_propagated': m('covered', note='OpenTelemetry trace context (W3C traceparent) is core to the specification.'),
    'organization_tenant_id': m('none', gap='No tenant attribute in the GenAI conventions', note='XM recommends adopting existing tenant and resource attributes rather than an ask.'),
    'trigger_type_source_event': m('none', gap='No trigger type or source event', asks=['otel_trigger']),
    'action_type': m(U),
    'execution_status': m('covered', ['error.type'], note='With the span status.'),
    'stop_reason': m('covered', ['gen_ai.response.finish_reasons']),
    'surface_app': m('none', gap='No surface attribute', note='XM names the gap and proposes no change; decide an ask or record why none.'),
    'system_prompt_instruction_config': m('covered', ['gen_ai.system_instructions'], note='Gated behind content-capture opt-in.', asks=['otel_hash_only_capture']),
    'autonomy_level': m(U),
    'model_input': m('covered', ['gen_ai.input.messages'], note='Gated behind content-capture opt-in.', asks=['otel_hash_only_capture']),
    'input_source_channel': m(U),
    'input_trust_classification': m('none', gap='No trust-provenance concept', asks=['otel_trust_level']),
    'source_host_ip_request_metadata': m(U),
    'guardrail_input_verdict': m('partial', ['gen_ai.evaluation.score.value'], 'The evaluation event is quality-oriented: no blocked flag, guardrail type or threat technique', ['otel_security_guardrail']),
    'content_modality_attachment_identity': m('partial', gap='Message parts carry types; no attachment name, size or hash', asks=['otel_attachment_identity']),
    'guardrail_modification_record': m(U),
    'threat_classification_atlas_technique_tag': m('none', gap='No threat-technique reference', asks=['otel_security_guardrail']),
    'encoded_obfuscated_payload_indicator': m(U),
    'response_model_output': m('covered', ['gen_ai.output.messages'], note='Gated behind content-capture opt-in.', asks=['otel_hash_only_capture']),
    'output_egress_destination': m('none', gap='No link from model output to its destination', asks=['otel_egress_pattern']),
    'citations_source_attribution': m('partial', ['gen_ai.retrieval.documents'], 'Output-side citations are not linked to retrieved items', ['otel_citations']),
    'observation_thought_reasoning_trace': m(U),
    'guardrail_output_verdict': m('partial', ['gen_ai.evaluation.score.value'], 'The evaluation event is quality-oriented', ['otel_security_guardrail']),
    'llm_refusal': m(U),
    'model_name_version': m('covered', ['gen_ai.request.model', 'gen_ai.response.model']),
    'provider_endpoint_identity': m('covered', ['gen_ai.provider.name']),
    'inference_parameters': m('covered', ['gen_ai.request.temperature', 'gen_ai.request.top_p', 'gen_ai.request.max_tokens', 'gen_ai.request.stop_sequences', 'gen_ai.request.seed']),
    'input_output_token_counts': m('covered', ['gen_ai.usage.input_tokens', 'gen_ai.usage.output_tokens', 'gen_ai.client.token.usage']),
    'llm_error_exception': m('covered', ['error.type']),
    'model_provenance_signing_hash': m('none', gap='No model provenance or signing', asks=['otel_model_provenance']),
    'pre_forward_pass_state_digest_vector': m(U),
    'token_malformation_context_corruption_indicator': m(U),
    'tool_call_io': m('covered', ['gen_ai.tool.call.arguments', 'gen_ai.tool.call.result']),
    'tool_name': m('covered', ['gen_ai.tool.name']),
    'tool_type_trust_boundary': m(U),
    'tool_id': m(U),
    'tool_execution_id': m('covered', ['gen_ai.tool.call.id']),
    'tool_definition_digest': m('partial', ['gen_ai.tool.definitions'], 'The definitions, not a stable digest of them', ['otel_tool_digest_mcp_primitive']),
    'execution_environment_sandbox': m('none', gap='No sandbox or isolation attributes', asks=['otel_execution_environment']),
    'mcp_server_identity_primitive': m('partial', ['mcp.method.name', 'mcp.protocol.version', 'mcp.session.id'], 'No primitive discriminator; mcp.method.name partly serves', ['otel_tool_digest_mcp_primitive']),
    'tool_error_exception': m('covered', ['error.type']),
    'tool_acl_required_scope': m('out_of_scope', note=OOS),
    'tool_privacy_classification': m(U),
    'tool_selection_rationale': m(U),
    'memory_write_event': m('covered', ['gen_ai.memory.store.id', 'gen_ai.memory.record.id', 'gen_ai.operation.name']),
    'memory_read_injection_event': m('covered', ['gen_ai.memory.query.text', 'gen_ai.memory.records']),
    'memory_provenance_source': m('none', gap='No provenance attribute in the gen_ai registry', asks=['otel_memory_provenance_footprint']),
    'memory_integrity_poisoning_signal': m(U),
    'memory_footprint_growth': m('none', gap='No footprint attribute in the gen_ai registry', asks=['otel_memory_provenance_footprint']),
    'declared_memory_configuration': m(U),
    'memory_write_rationale': m(U),
    'retrieval_event': m('covered', ['gen_ai.retrieval.query.text', 'gen_ai.retrieval.documents', 'gen_ai.data_source.id']),
    'retrieved_content_source_provenance': m('none', gap='No per-item source or provenance', asks=['otel_retrieval_provenance']),
    'retrieved_content_metadata_integrity_signal': m('none', gap='No per-item integrity signal or freshness', asks=['otel_retrieval_provenance']),
    'declared_knowledge_source_configuration': m(U),
    'inter_agent_message': m('none', gap='No inter-agent message attributes', asks=['otel_inter_agent_messaging']),
    'a2a_task_lifecycle_event': m(U),
    'peer_agent_card_descriptor': m(U),
    'background_scheduled_task_event': m('none', gap='No background-task or termination-condition signal', asks=['otel_trigger']),
    'loop_step_count_signal': m('partial', gap='Agent metrics count calls; no limit or termination semantics', asks=['otel_run_budget']),
    'resource_consumption_aggregate': m('partial', ['gen_ai.client.token.usage'], 'No per-run budget or threshold', ['otel_run_budget']),
    'task_intent_declaration': m(U),
    'protocol_envelope_capture': m(U),
    **{f: m('out_of_scope', note=OOS) for f in [
        'identities_used_per_hop', 'verified_vs_displayed_identity', 'originating_principal_on_behalf_of', 'delegation_chain',
        'granted_authorizations_scope', 'resource_indicators_constraints', 'token_exchange_scope_narrowing_check',
        'trust_domain_crossing_delegation_depth', 'runtime_credential_attestation', 'lifecycle_state',
        'attribute_source_trusted_provenance_marking', 'session_taint_labels_information_flow_decisions',
        'human_approval_elicitation_event', 'backend_route_restriction_decision', 'mediation_coverage_bypass_path',
        'enforcement_point_availability_failure_mode', 'policy_reason_code']},
    'authorization_decision_record': m('out_of_scope', note=OOS, asks=['otel_authorization_reference']),
    'capability_set_change_event': m('none', gap='No capability-change event', asks=['otel_capability_change']),
    'tool_agent_version': m(U),
    'repository_code_path_software_ref': m(U),
    'agbom_inventory_snapshot': m('none', gap='No BOM reference', asks=['otel_capability_change']),
    'component_dependency_graph': m(U),
    'inventory_integrity_signature': m(U),
    'tool_description': m(U),
    'tool_status': m(U),
    'creator_id_oncall_creation_update_dates': m(U),
    'surfaces_supported': m(U),
    'fleet_counts': m(U),
    'instrumentation_coverage_hook_status': m('none', gap='No instrumentation-coverage representation', asks=['otel_hook_coverage']),
    'event_sequence_continuity': m(U),
}


# ---------------------------------------------------------------- assessed against the pins, 2026-10-02
# The entries XM's cluster rows left unassessed, judged from each pinned schema's own
# definitions (OCSF 1.9.0 dictionary and objects; OpenTelemetry GenAI and core registries).
NOASK = 'No ask proposed; decide one or record why none.'
MAYR = 'A MAY research-grade signal; no ask.'
OCSF_ASSESSED = {
    'trace_context_propagated': m('covered', ['profile:trace', 'object:trace'], note='The trace profile carries the trace and span identifiers.'),
    'organization_tenant_id': m('partial', ['object:metadata', 'attribute:tenant_uid'], 'One tenant per event (metadata.tenant_uid), not the tenant of the agent, the session and the invoking user separately', note=NOASK),
    'execution_status': m('covered', ['attribute:status_id', 'attribute:duration'], note='Outcome and duration on the base event.'),
    'surface_app': m('partial', ['object:actor', 'attribute:app_name'], 'An application name; no entry-point type and no internal or external flag', note=NOASK),
    'input_source_channel': m('none', gap='No per-segment input source on message_context', note=NOASK),
    'source_host_ip_request_metadata': m('covered', ['attribute:src_endpoint']),
    'encoded_obfuscated_payload_indicator': m('none', gap='No obfuscation flag or decoded form', note=NOASK),
    'citations_source_attribution': m('none', gap='No citation, and no resolution of a citation against retrieval', note=NOASK),
    'observation_thought_reasoning_trace': m('none', gap='No reasoning trace', note=NOASK),
    'llm_refusal': m('none', gap='No refusal status or reason; a content-filter stop reason (#1704) records one cause only', asks=['ocsf_stop_reason']),
    'inference_parameters': m('none', gap='No decoding parameters or context window on ai_model or message_context', note=NOASK),
    'llm_error_exception': m('partial', ['attribute:status_id', 'attribute:status_detail'], 'A generic outcome; no AI-specific error type', note=NOASK),
    'pre_forward_pass_state_digest_vector': m('none', gap='No forward-pass digest', note=MAYR),
    'token_malformation_context_corruption_indicator': m('none', gap='No token-entropy signal', note=MAYR),
    'execution_environment_sandbox': m('partial', ['object:process', 'attribute:sandbox', 'object:container'], 'A sandbox name on a process, and container identity; no isolation mode, timeout or egress policy for a tool execution', note=NOASK),
    'tool_error_exception': m('partial', ['attribute:status_id', 'attribute:status_detail'], 'An outcome on API Activity, not tied to a tool call', ['ocsf_ai_tool']),
    'tool_privacy_classification': m('partial', ['profile:data_classification', 'object:data_classification', 'attribute:confidentiality'], 'Classification attaches to data, not to the tool that touches it', note=NOASK),
    'tool_selection_rationale': m('none', gap='No self-asserted rationale', note=NOASK),
    'memory_write_rationale': m('none', gap='No self-asserted rationale', note=NOASK),
    'declared_memory_configuration': m('none', gap='No memory-store declaration', note=NOASK),
    'declared_knowledge_source_configuration': m('none', gap='No knowledge-source declaration', note=NOASK),
    'peer_agent_card_descriptor': m('partial', ['object:ai_agent'], 'ai_agent can describe a counterparty; no descriptor change or verification outcome', note=NOASK),
    'task_intent_declaration': m('partial', ['object:ai_agent', 'attribute:charter'], "A charter defines the agent's role, scope and operating bounds, not the purpose declared for this run", note=NOASK),
    'protocol_envelope_capture': m('partial', ['attribute:raw_data'], 'raw_data holds the source record before normalization, not the envelope of each MCP or A2A message', note=NOASK),
    'verified_vs_displayed_identity': m('partial', ['object:actor', 'object:user'], 'A user identifier and name both exist; no record of which one authorized', note=NOASK),
    'originating_principal_on_behalf_of': m('none', gap='delegation records its issuer and lineage, not the originating principal', asks=['ocsf_delegation_lineage']),
    'surfaces_supported': m('none', gap='No per-tool exposure map', note='A MAY field; no ask.'),
    'backend_route_restriction_decision': m('none', gap='No routing constraint or candidate backends', note=NOASK),
    # corrected: ai_model carries the provider at 1.9.0
    'provider_endpoint_identity': m('covered', ['object:ai_model', 'attribute:ai_provider']),
}
OTEL_ASSESSED = {
    'action_type': m('partial', ['gen_ai.operation.name'], 'Operations include chat, execute_tool, invoke_agent and the memory operations; no inter-agent message send', ['otel_inter_agent_messaging']),
    'autonomy_level': m('none', gap='No autonomy level', note=NOASK),
    'input_source_channel': m('none', gap='No per-part input source', note=NOASK),
    'source_host_ip_request_metadata': m('covered', ['client.address', 'network.peer.address', 'user_agent.original']),
    'guardrail_modification_record': m('none', gap='No record that an enforcement point rewrote a payload', asks=['otel_security_guardrail']),
    'encoded_obfuscated_payload_indicator': m('none', gap='No obfuscation flag or decoded form', note=NOASK),
    'observation_thought_reasoning_trace': m('partial', ['gen_ai.usage.reasoning.output_tokens'], 'A count of reasoning tokens, not the trace', note=NOASK),
    'llm_refusal': m('partial', ['gen_ai.response.finish_reasons'], 'A content-filter finish reason where the provider returns one; no refusal status or reason', note=NOASK),
    'pre_forward_pass_state_digest_vector': m('none', gap='No forward-pass digest', note=MAYR),
    'token_malformation_context_corruption_indicator': m('none', gap='No token-entropy signal', note=MAYR),
    'tool_type_trust_boundary': m('partial', ['gen_ai.tool.type'], 'function, extension or datastore; no MCP, direct-storage or code-execution boundary', note=NOASK),
    'tool_id': m('none', gap='Tool name and call ID only; no implementation ID across servers', note='A MAY field; no ask.'),
    'tool_privacy_classification': m('none', gap='No data classification for a tool', note='A MAY field; no ask.'),
    'tool_selection_rationale': m('none', gap='No self-asserted rationale', note=NOASK),
    'memory_integrity_poisoning_signal': m('none', gap='No integrity or poisoning signal', note=NOASK),
    'declared_memory_configuration': m('partial', ['gen_ai.memory.store.id'], 'Store identity only; no limits or retrieval settings', note=NOASK),
    'memory_write_rationale': m('none', gap='No self-asserted rationale', note=NOASK),
    'declared_knowledge_source_configuration': m('partial', ['gen_ai.data_source.id'], 'Data-source identity only; no schema or search parameters', note=NOASK),
    'a2a_task_lifecycle_event': m('none', gap='No A2A conventions', note=NOASK),
    'peer_agent_card_descriptor': m('partial', ['gen_ai.agent.name', 'gen_ai.agent.id', 'gen_ai.agent.description', 'gen_ai.agent.version'], 'Describes the agent a span is about; no counterparty descriptor, change or verification', note=NOASK),
    'task_intent_declaration': m('none', gap='No declared purpose for the run', note=NOASK),
    'protocol_envelope_capture': m('none', gap='No raw protocol envelope', note='A MAY field; no ask.'),
    'tool_agent_version': m('partial', ['gen_ai.agent.version'], 'Agent version only; no tool or framework version', note=NOASK),
    'repository_code_path_software_ref': m('partial', ['vcs.repository.url.full', 'vcs.ref.head.revision'], 'Version-control attributes exist for CI/CD telemetry, not for tool and agent code', note=NOASK),
    'component_dependency_graph': m('none', gap='No dependency graph', asks=['otel_capability_change']),
    'inventory_integrity_signature': m('none', gap='No inventory signature', asks=['otel_capability_change']),
    'tool_description': m('covered', ['gen_ai.tool.description']),
    'tool_status': m('none', gap='No reachability status for a tool', note='A MAY field; no ask.'),
    'creator_id_oncall_creation_update_dates': m('none', gap='No ownership or change dates', note='A MAY field; no ask.'),
    'surfaces_supported': m('none', gap='No per-tool exposure map', note='A MAY field; no ask.'),
    'fleet_counts': m('none', gap='Fleet aggregates are derived', note='Derived from per-event records; no ask.'),
    'event_sequence_continuity': m('none', gap='No per-session sequence number or hash chain', note=NOASK),
}
OCSF.update(OCSF_ASSESSED)
OTEL.update(OTEL_ASSESSED)


# ---------------------------------------------------------------- asks for MUST gaps, 2026-10-02
# XM's own rule makes a field a standardization ask once two or more independent
# instances require it. These close the MUST gaps the assessment left without one;
# where AITF already defines the field, the ask names AITF's attributes so the
# bridge and the upstream proposal carry the same names.
ASKS += [
    ('ocsf_entry_point', 'ocsf', 'Add an entry point to ai_operation: the surface an operation arrived through (CLI, web, IDE, email, chat, scheduler) and whether it is internal or external.', [], [], 'proposed'),
    ('ocsf_input_segment_source', 'ocsf', 'Add a per-segment source to message_context: the surface, tool, agent or document each input segment came from, beside the proposed trust_level.', [], [], 'proposed'),
    ('ocsf_obfuscation', 'ocsf', 'Add an obfuscation finding (detected, encodings, decoded form or its hash) to ai_guardrail or Detection Finding, aligned with AITF security.obfuscation.*.', [], [], 'proposed'),
    ('ocsf_citations', 'ocsf', 'Add citations to message_context, each with its source and whether it resolves to an item an ai_retrieval record returned, aligned with AITF rag.citation.*.', [], [], 'proposed'),
    ('ocsf_inference_parameters', 'ocsf', 'Add the decoding parameters in force for a call (temperature, top_p, max_tokens, stop sequences, seed) and the declared context window to ai_model or message_context.', [], [], 'proposed'),
    ('ocsf_ai_error', 'ocsf', 'Add an AI error type to ai_operation beside status_id: provider error, context overflow, rate limit, content filter, silent truncation.', [], [], 'proposed'),
    ('ocsf_tool_execution_environment', 'ocsf', 'Add the execution environment of a tool call to ai_tool: isolation mode, runtime, timeout and egress policy, aligned with AITF supply_chain.runtime.*.', [], ['ocsf-schema#1729'], 'proposed'),
    ('ocsf_identity_verification', 'ocsf', 'Record which identity authorized an operation (a verified identifier or a display name) and the verification outcome, on actor or ai_authorization.', [], [], 'proposed'),
    ('otel_run_id', 'otel_genai', 'Add gen_ai.run.id, as AITF defines it; gen_ai.workflow.name names the workflow, not the run.', ['gen_ai.run.id'], [], 'proposed'),
    ('otel_entry_point', 'otel_genai', 'Add an entry-point attribute: the surface a request arrived through and whether it is internal or external.', [], [], 'proposed'),
    ('otel_input_part_source', 'otel_genai', 'Add a per-part source on input messages (the surface, tool, agent or document it came from), beside the proposed gen_ai.input.trust_level.', [], [], 'proposed'),
    ('otel_obfuscation', 'otel_genai', 'Add obfuscation indicators on input (detected, encodings, decoded hash), aligned with AITF security.obfuscation.*.', [], [], 'proposed'),
    ('otel_refusal', 'otel_genai', 'Add a refusal status and reason distinct from finish reasons, so a refusal that ends normally is still visible.', [], [], 'proposed'),
    ('otel_tool_trust_boundary', 'otel_genai', 'Extend gen_ai.tool.type, or add a trust-boundary attribute, to distinguish MCP, internal, direct-storage and code-execution tools.', [], [], 'proposed'),
]
MUST_GAP_ASKS = {
    'ocsf': {'surface_app': 'ocsf_entry_point', 'input_source_channel': 'ocsf_input_segment_source',
             'encoded_obfuscated_payload_indicator': 'ocsf_obfuscation', 'citations_source_attribution': 'ocsf_citations',
             'inference_parameters': 'ocsf_inference_parameters', 'llm_error_exception': 'ocsf_ai_error',
             'execution_environment_sandbox': 'ocsf_tool_execution_environment',
             'verified_vs_displayed_identity': 'ocsf_identity_verification'},
    'otel': {'workflow_run_id': 'otel_run_id', 'surface_app': 'otel_entry_point', 'input_source_channel': 'otel_input_part_source',
             'encoded_obfuscated_payload_indicator': 'otel_obfuscation', 'llm_refusal': 'otel_refusal',
             'tool_type_trust_boundary': 'otel_tool_trust_boundary'},
}
for pub, table in (('ocsf', OCSF), ('otel', OTEL)):
    for fid, ask in MUST_GAP_ASKS[pub].items():
        e = table[fid]
        e['asks'] = e.get('asks', []) + [ask]
        if e.get('note', '').startswith('No ask proposed'):
            del e['note']
# AITF entries that cite only a namespace, with no attribute behind it, are gaps in AITF too.
AITF_NAMESPACE_ONLY = {'surface_app', 'input_source_channel', 'llm_error_exception', 'llm_refusal', 'tool_type_trust_boundary'}


# ---------------------------------------------------------------- AITF and ODIS (XM §4, per field)
def xm_section(text, start, stop):
    a = text.index(start)
    b = text.index(stop, a)
    return text[a:b]


def aitf_odis_rows(fields):
    """{field id: (aitf cell, odis cell)} from XM §4, splitting rows that name several fields."""
    text = open(XM, encoding='utf-8').read()
    sec = xm_section(text, '## 4. AITF & ODIS Cross Reference', '## 5. ')
    by_name = {f['name']: fid for fid, f in fields.items()}
    out = {}
    for line in sec.split('\n'):
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells) != 4 or cells[0].startswith(':') or cells[0] == 'Conceptual field':
            continue
        names = [cells[0]] if cells[0] in by_name else [n.strip() for n in re.split(r', (?=[A-Z])', cells[0])]
        for n in names:
            if n not in by_name:
                sys.exit(f'XM §4 row names an unknown field: {n!r}')
            out[by_name[n]] = (cells[2], cells[3])
    return out


def expand(name):
    """`a.b.c/d/e` -> a.b.c, a.b.d, a.b.e; `x=y` -> x (XM compresses several names into one cell)."""
    name = name.split('=')[0]
    if '/' not in name:
        return [name]
    head, *rest = name.split('/')
    stem = head.rsplit('.', 1)[0] if '.' in head else ''
    return [head] + [f'{stem}.{r}' if stem else r for r in rest]


def aitf_gap_namespaces(fields):
    """{field id: [namespace.*]} from the resolution index of AITF_gaps.md (AITF v0.4 closed 27 gaps)."""
    by_name = {f['name']: fid for fid, f in fields.items()}
    text = open(os.path.join(DIR, 'aitf', 'AITF_gaps.md'), encoding='utf-8').read()
    sec = text[text.index('## Resolution index'):text.index('## New namespace decisions')]
    out = {}
    for line in sec.split('\n'):
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells) >= 6 and cells[0].isdigit():
            name = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', cells[1])
            if name not in by_name:
                sys.exit(f'AITF_gaps.md names an unknown field: {name!r}')
            out[by_name[name]] = re.findall(r'`([^`]+)`', cells[4])
    return out


def entry_from_cell(cell, kind):
    if cell.startswith('n/a') or cell == '(derived)':
        return m('none', note=cell if cell not in ('n/a',) else None)
    names = [x for n in re.findall(r'`([^`]+)`', cell) for x in expand(n)]
    if kind == 'odis':
        names = [n.split('.')[0] for n in names]
    sections = re.findall(r'\((\d\.\d(?:[/, ]+\d\.\d)?)(?:,? partial)?\)', cell)
    note = cell if (re.sub(r'`[^`]+`', '', cell).strip(' ,/+()') or not names) else None
    e = m('partial' if 'partial' in cell else 'covered', names, note=note)
    if kind == 'odis' and sections:
        e['sections'] = sections
    return e


# ---------------------------------------------------------------- Risk Map controls (XM §1.2, per old cluster)
OLD_CLUSTERS = {
    'Execution context & agent identity': ['agent_name', 'agent_runtime_instance_id', 'workflow_run_id', 'session_turn_step_ids', 'trace_context_propagated', 'organization_tenant_id', 'trigger_type_source_event', 'action_type', 'execution_status', 'stop_reason', 'surface_app', 'system_prompt_instruction_config', 'autonomy_level'],
    'Input handling & trust provenance': ['model_input', 'input_source_channel', 'input_trust_classification', 'source_host_ip_request_metadata', 'guardrail_input_verdict', 'content_modality_attachment_identity', 'guardrail_modification_record', 'threat_classification_atlas_technique_tag', 'encoded_obfuscated_payload_indicator'],
    'Output handling & egress': ['response_model_output', 'output_egress_destination', 'citations_source_attribution', 'observation_thought_reasoning_trace', 'guardrail_output_verdict', 'llm_refusal'],
    'Model & serving': ['model_name_version', 'provider_endpoint_identity', 'inference_parameters', 'input_output_token_counts', 'llm_error_exception', 'model_provenance_signing_hash', 'pre_forward_pass_state_digest_vector', 'token_malformation_context_corruption_indicator'],
    'Tools & MCP': ['tool_call_io', 'tool_name', 'tool_type_trust_boundary', 'tool_id', 'tool_execution_id', 'tool_definition_digest', 'execution_environment_sandbox', 'mcp_server_identity_primitive', 'tool_error_exception', 'tool_acl_required_scope', 'tool_privacy_classification', 'tool_selection_rationale'],
    'Memory': ['memory_write_event', 'memory_read_injection_event', 'memory_provenance_source', 'memory_integrity_poisoning_signal', 'memory_footprint_growth', 'declared_memory_configuration', 'memory_write_rationale'],
    'RAG / retrieval': ['retrieval_event', 'retrieved_content_source_provenance', 'retrieved_content_metadata_integrity_signal', 'declared_knowledge_source_configuration'],
    'Orchestration & multi-agent': ['inter_agent_message', 'a2a_task_lifecycle_event', 'peer_agent_card_descriptor', 'background_scheduled_task_event', 'loop_step_count_signal', 'resource_consumption_aggregate', 'task_intent_declaration', 'protocol_envelope_capture'],
    'Identity, delegation & attestation': ['identities_used_per_hop', 'verified_vs_displayed_identity', 'originating_principal_on_behalf_of', 'delegation_chain', 'granted_authorizations_scope', 'resource_indicators_constraints', 'token_exchange_scope_narrowing_check', 'trust_domain_crossing_delegation_depth', 'runtime_credential_attestation', 'lifecycle_state'],
    'Asset inventory & fleet': ['capability_set_change_event', 'tool_agent_version', 'repository_code_path_software_ref', 'agbom_inventory_snapshot', 'component_dependency_graph', 'inventory_integrity_signature', 'tool_description', 'tool_status', 'creator_id_oncall_creation_update_dates', 'surfaces_supported', 'fleet_counts'],
    'Observability-plane integrity': ['enforcement_point_availability_failure_mode', 'instrumentation_coverage_hook_status', 'event_sequence_continuity', 'policy_reason_code'],
    'Policy enforcement & mediation': ['authorization_decision_record', 'attribute_source_trusted_provenance_marking', 'session_taint_labels_information_flow_decisions', 'human_approval_elicitation_event', 'backend_route_restriction_decision', 'mediation_coverage_bypass_path'],
}
# XM §1.1 names these fields for these controls directly.
NAMED = {'instrumentation_coverage_hook_status': ['controlAuditTrailCompleteness'],
         'event_sequence_continuity': ['controlAuditTrailIntegrityVerification']}
RETIRED = {'controlAgentMemoryIntegrity': 'controlMemoryReferentRevalidation'}


def cluster_controls():
    text = open(XM, encoding='utf-8').read()
    sec = xm_section(text, '### 1.2 Telemetry cluster', '### 1.3 ')
    out = {}
    for line in sec.split('\n'):
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells) == 3 and '(AD §' in cells[0]:
            name = cells[0].split(' (AD')[0]
            out[name] = [RETIRED.get(c, c) for c in re.findall(r'`(control\w+)`', cells[2])]
    return out


def main():
    fields, attacks, patterns, layout = rules.load_data()
    src = load(os.path.join(DATA, 'sources.yaml'))
    pubs = src['publications']
    names = {k: vocab.RESOLVERS[k](pubs[k]) for k in ('ocsf', 'otel_genai', 'otel_semconv', 'aitf', 'odis')}
    names['otel'] = names['otel_genai'] | names['otel_semconv']
    names['aitf'] |= names['otel']   # AITF extends the OpenTelemetry conventions rather than restating them
    rm_controls = {}
    rm = src['riskmap']
    for pin in [rm['base']] + rm.get('layers', []):
        d = yaml.safe_load(open(vocab.checkout({'repository': pin.get('repository', rm['repository']),
                                                'commit': pin['commit']}) + '/risk-map/yaml/controls.yaml'))
        rm_controls |= {c['id']: c for c in d['controls']}

    proposes = {}
    for aid, pub, summary, prop, tracking, status in ASKS:
        for c in prop:
            proposes.setdefault('otel' if pub.startswith('otel') else pub, set()).add(c)
    problems, out = [], []

    def resolves(pub, c):
        if c.endswith('.*'):
            return any(n.startswith(c[:-1]) for n in names[pub])
        return c in names[pub]

    closes = {}
    for pub, table in (('ocsf', OCSF), ('otel', OTEL)):
        for fid, e in table.items():
            for a in e.get('asks', []):
                closes.setdefault(a, []).append(fid)
    for aid, pub, summary, prop, tracking, status in ASKS:
        ev = '; '.join(f"{fields[f]['name']} ({fields[f]['tier']}, {len(rules.instances(f, attacks))} instances)"
                       for f in closes.get(aid, []))
        out.append({'id': f'Q:{aid}', 'type': 'ask', 'subject': {'ask': aid}, 'source': 'xm-pass',
                    'proposal': {'id': aid, 'publication': pub, 'summary': summary, 'proposes': prop,
                                 'tracking': tracking, 'status': status},
                    'reason': ('drafted for a MUST gap XM left without an ask'
                               if aid in MUST_GAP_ASKS['ocsf'].values() or aid in MUST_GAP_ASKS['otel'].values()
                               else 'from XM §2.3' if pub.startswith('otel') else 'from XM §3.1 and §3.2')
                              + (f'. Closes: {ev}' if ev else '. Closes no field gap yet'), 'status': 'proposed'})
    ask_ids = {a[0] for a in ASKS}
    rows = aitf_odis_rows(fields)
    gaps = aitf_gap_namespaces(fields)
    clusters = cluster_controls()
    for fid in fields:
        per = {'ocsf': OCSF.get(fid), 'otel': OTEL.get(fid)}
        aitf_cell, odis_cell = rows.get(fid, ('n/a', 'n/a'))
        per['aitf'] = entry_from_cell(aitf_cell, 'aitf')
        if fid in ('session_turn_step_ids', 'trace_context_propagated'):
            # span and trace identifiers are OpenTelemetry trace context, not attributes
            e = per['aitf']
            e['constructs'] = [c for c in e.get('constructs', []) if c not in ('span_id', 'trace_id', 'traceparent')]
            e['note'] = (e.get('note', '') + ' Trace and span identifiers come from OpenTelemetry trace context (W3C traceparent).').strip()
        if fid == 'loop_step_count_signal':
            per['aitf'] = m('covered', ['gen_ai.agent.session.turn_count', 'gen_ai.agent.step.index', 'agent.steps_per_session'],
                            note='XM §4 names gen_ai.agent.turn_count; AITF defines gen_ai.agent.session.turn_count.')
        if fid in AITF_NAMESPACE_ONLY:
            e = per['aitf']
            e['coverage'] = 'partial'
            e['gap'] = 'XM §4 cites a namespace only; AITF defines no attribute for this field at the pin'
        if fid in gaps:   # closed in AITF v0.4: the namespace AITF_gaps.md records supersedes XM §4
            e = per['aitf']
            e['constructs'] = list(dict.fromkeys(gaps[fid] + e.get('constructs', [])))
            e['coverage'] = 'covered'
            e['note'] = 'Closed in AITF v0.4 (AITF_gaps.md).' + (' XM §4: ' + e['note'] if e.get('note') else '')
        per['odis'] = entry_from_cell(odis_cell, 'odis')
        for pub, e in per.items():
            if e is None:
                problems.append(f'{fid}: no {pub} entry')
                continue
            for c in e.get('constructs', []):
                if not resolves(pub, c) and c not in proposes.get(pub, set()):
                    e.setdefault('unresolved', []).append(c)
            for a in e.get('asks', []):
                if a not in ask_ids:
                    problems.append(f'{fid}/{pub}: unknown ask {a}')
            if e.get('unresolved'):
                e['constructs'] = [c for c in e['constructs'] if c not in e['unresolved']]
                if not e['constructs']:
                    del e['constructs']
            out.append({'id': f'M:{fid}:{pub}', 'type': 'mapping', 'subject': {'field': fid, 'publication': pub},
                        'source': 'xm-pass', 'proposal': {k: v for k, v in e.items() if k != 'unresolved'},
                        'reason': ({'ocsf': 'XM §3.1 cluster row, per field', 'otel': 'XM §2.2 cluster row, per field',
                                    'aitf': 'XM §4', 'odis': 'XM §4'}[pub]
                                   + (f"; XM names {e['unresolved']}, which do not exist at the pin" if e.get('unresolved') else '')),
                        **({'critical': True} if e.get('unresolved') else {}), 'status': 'proposed'})
        # controls: the old cluster's controls that apply to a component emitting the field
        cl = next(n for n, fs in OLD_CLUSTERS.items() if fid in fs)
        listed = clusters.get(cl, [])
        emit = set(fields[fid].get('emitted_by', []))
        keep = [c for c in listed if c in rm_controls and emit & set(rm_controls[c].get('components', []))]
        keep += [c for c in NAMED.get(fid, []) if c not in keep]
        unknown = [c for c in listed if c not in rm_controls]
        why = (f'XM §1.2 lists {len(listed)} controls for {cl}; kept those whose Risk Map components include an emitter of this field'
               + (f'; dropped {unknown}, which do not exist at the pin' if unknown else '')
               + ('' if emit else '; the field has no Risk Map emitter, so none is kept by the component test'))
        out.append({'id': f'C:{fid}', 'type': 'controls', 'subject': {'field': fid}, 'source': 'xm-pass',
                    'proposal': {'controls': keep}, 'reason': why, 'status': 'proposed'})
    if problems:
        sys.exit('\n'.join(problems))
    header = ('# Curation registry batch. Edit status only through tools/curate.py, or by hand\n'
              '# keeping decided_by and decided_on filled in. See curate.py for the schema.\n'
              '# XM pass: per-field mapping to OCSF, OpenTelemetry, AITF and ODIS, the asks, and\n'
              '# Risk Map controls (tools/xm_propose.py documents the record).\n')
    dump(out, OUT, header)
    maps = [c for c in out if c['type'] == 'mapping']
    cov = {}
    for c in maps:
        cov.setdefault(c['subject']['publication'], {}).setdefault(c['proposal']['coverage'], 0)
        cov[c['subject']['publication']][c['proposal']['coverage']] += 1
    print(f"{len(ASKS)} asks, {len(maps)} mapping entries, {len(fields)} control proposals -> {os.path.relpath(OUT, DIR)}")
    for p, d in cov.items():
        print(f'  {p}: {d}')
    flagged = [c['id'] for c in maps if c.get('critical')]
    print(f'{len(flagged)} entries name constructs that do not exist at the pin:')
    for c in maps:
        if c.get('critical'):
            print('  ', c['id'], '|', c['reason'].split('; ', 1)[1])
    print('controls kept per field:', sum(1 for c in out if c['type'] == 'controls' and c['proposal']['controls']),
          'of', len(fields), 'fields have at least one')


if __name__ == '__main__':
    main()
