#!/usr/bin/env python3
"""Phase 2: resolve the field names used in attack rows and patterns to field
IDs, and report where the two directions of the attack-field relation disagree.

  python3 tools/reconcile.py resolve       add `fields:` to attacks/ and patterns.yaml
  python3 tools/reconcile.py report OUT    write the discrepancy report to OUT
  python3 tools/reconcile.py propose       write data/candidates/2026-10-02-phase2.yaml

`resolve` leaves the verbatim *_text cells in place, so the documents are
unchanged until the reconciled edge set is applied.
"""
import glob
import os
import re
import sys
from collections import Counter, defaultdict

from yamlio import dump, load

DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))   # the documents: telemetry/
DATA = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data'))   # build-telemetry/data/

# Short and variant names found in attack rows and patterns. A list means the
# text names more than one field. `None` marks text that names no field.
ALIASES = {
    'Attribute Source Marking': 'attribute_source_trusted_provenance_marking',
    'Background Task Event': 'background_scheduled_task_event',
    'Citations': 'citations_source_attribution',
    'Credential Minting & Scope-Narrowing': 'credential_minting_scope_narrowing_check',
    'Encoded-Payload Indicator': 'encoded_obfuscated_payload_indicator',
    'Enforcement-Point Availability': 'enforcement_point_availability_failure_mode',
    'Execution Environment/Sandbox': 'execution_environment_sandbox',
    'Granted Authorizations': 'granted_authorizations_scope',
    'Guardrail(Input) Verdict': 'guardrail_input_verdict',
    'Identities Used': 'identities_used_per_hop',
    'Input Source/Trust': ['input_source_channel', 'input_trust_classification'],
    'Input Trust Class': 'input_trust_classification',
    'Instrumentation Coverage': 'instrumentation_coverage_hook_attestation',
    'LLM Error': 'llm_error_exception',
    'Loop Signal': 'loop_step_count_signal',
    'MCP Server Identity': 'mcp_server_identity_primitive',
    'Memory Footprint': 'memory_footprint_growth',
    'Memory Footprint/Growth': 'memory_footprint_growth',
    'Memory Provenance': 'memory_provenance_source',
    'Memory Read': 'memory_read_injection_event',
    'Memory Write': 'memory_write_event',
    'Memory Write/Read': ['memory_write_event', 'memory_read_injection_event'],
    'Metadata Integrity Signal': 'retrieved_content_metadata_integrity_signal',
    'Model Input + Input Trust Class': ['model_input', 'input_trust_classification'],
    'Model Name': 'model_name_version',
    'Observation/Thought': 'observation_thought_reasoning_trace',
    'Organization/Tenant ID': 'organization_tenant_id',
    'Output Egress': 'output_egress_destination',
    'Peer Agent Card': 'peer_agent_card_descriptor',
    'Provider Identity': 'provider_endpoint_identity',
    'Provider/Endpoint Identity': 'provider_endpoint_identity',
    'Resource Aggregate': 'resource_consumption_aggregate',
    'Response': 'response_model_output',
    'Retrieval Event + Retrieved-Content Source': ['retrieval_event', 'retrieved_content_source_provenance'],
    'Retrieved-Content Source': 'retrieved_content_source_provenance',
    'Session Taint Labels': 'session_taint_labels_information_flow_decisions',
    'Source IP': 'source_host_ip_request_metadata',
    'Surface': 'surface_app',
    'Surface/App': 'surface_app',
    'System Prompt': 'system_prompt_instruction_config',
    'Token Counts': 'input_output_token_counts',
    'Tool ACL/Scope': 'tool_acl_required_scope',
    'Tool Error': 'tool_error_exception',
    'Tool Error/Exception': 'tool_error_exception',
    'Tool Privacy Class': 'tool_privacy_classification',
    'Tool Type': 'tool_type_trust_boundary',
    'Tool Type/Trust Boundary': 'tool_type_trust_boundary',
    'Trigger Type': 'trigger_type_source_event',
    'Verified-vs-Displayed Identity': 'verified_vs_displayed_identity',
    'Version': 'tool_agent_version',
    'Version / Repository / Software Ref': ['tool_agent_version', 'repository_code_path_software_ref'],
    # Resolved by reading the attack, recorded in the report as judgements:
    'Guardrail Verdict': ['guardrail_input_verdict', 'guardrail_output_verdict'],
    'Integrity/Poisoning Signal': ['memory_integrity_poisoning_signal',
                                   'retrieved_content_metadata_integrity_signal'],
    'finish reason': 'stop_reason',
    '`last_update_date`': 'retrieved_content_source_provenance',
    '`creation_date`': 'retrieved_content_source_provenance',
    'sessions-per-agent': 'fleet_counts',
    'execution-status breakdowns': 'fleet_counts',
    'tool-call count': 'loop_step_count_signal',
}
JUDGED = {'Guardrail Verdict', 'Integrity/Poisoning Signal', 'finish reason', '`last_update_date`',
          '`creation_date`', 'sessions-per-agent', 'execution-status breakdowns', 'tool-call count'}

# Proposed grounding class for edges that are not 'instance' (see curate.py for
# the classes). Edges absent from this table are proposed as 'instance'.
A, R = 'analogical', 'reject'
NO_GAP = 'no instrumentation gap or suppression is documented'
J = {
 'AOC-01': {'instrumentation_coverage_hook_attestation': (A, NO_GAP), 'event_sequence_continuity': (A, NO_GAP)},
 'AOC-02': {'organization_tenant_id': (R, 'owner and non-owner act within one deployment; no tenant boundary is involved'),
            'execution_environment_sandbox': (A, 'shell commands ran, but isolation posture does not distinguish the attack'),
            'tool_selection_rationale': (A, 'no stated rationale is documented'),
            'credential_minting_scope_narrowing_check': (A, 'no credential exchange is documented'),
            'capability_set_change_event': (R, 'no capability was added or removed'),
            'tool_status': (A, 'no tool that should have been unreachable was called'),
            'mediation_coverage_bypass_path': (A, 'no unmediated path is documented')},
 'AOC-03': {'guardrail_modification_record': (A, 'no rewrite occurred'),
            'citations_source_attribution': (R, 'the disclosure is in the response, not in citations'),
            'resource_indicators_constraints': (A, 'no classification constraint was in force')},
 'AOC-04': {'autonomy_level': (A, 'no declared autonomy level is documented'),
            'inference_parameters': (A, 'token volume, not decoding parameters, distinguishes the loop'),
            'tool_execution_id': (A, 'no request/result mismatch is documented'),
            'execution_environment_sandbox': (A, 'isolation posture does not distinguish the loop'),
            'memory_footprint_growth': (A, 'the loop is not documented as growing memory; AD §4.6 relies on this edge'),
            'a2a_task_lifecycle_event': (A, 'predates A2A (AD §4.8)'),
            'delegation_chain': (A, 'no delegated authority is documented'),
            'trust_domain_crossing_delegation_depth': (A, 'the relay stays inside one domain'),
            'fleet_counts': (A, 'per-run signals, not fleet aggregates, distinguish the loop')},
 'AOC-05': {'agent_runtime_instance_id': (A, 'one agent; the instance does not distinguish the attack'),
            'organization_tenant_id': (R, 'no tenant boundary is involved'),
            'execution_status': (A, 'the outcome is server exhaustion, not an operation status'),
            'input_output_token_counts': (A, 'the flood is attachments and memory, not tokens'),
            'declared_memory_configuration': (A, 'no declared limit is documented'),
            'resource_indicators_constraints': (A, 'no constraint was in force'),
            'fleet_counts': (A, 'one agent; no fleet aggregate is involved'),
            'backend_route_restriction_decision': (R, 'no backend selection is involved')},
 'AOC-06': {'inference_parameters': (A, 'truncation was provider-side with parameters unchanged'),
            'backend_route_restriction_decision': (A, 'no routing constraint is documented')},
 'AOC-07': {'declared_memory_configuration': (A, 'memory was wiped, not reconfigured'),
            'event_sequence_continuity': (R, 'no gap or suppression in the record is involved'),
            'memory_write_rationale': (A, 'no stated rationale is documented')},
 'AOC-08': {'agent_name': (A, 'the spoof targets the owner, not the agent identity'),
            'agent_runtime_instance_id': (A, 'the instance does not distinguish the attack'),
            'system_prompt_instruction_config': (A, 'admin reassignment is documented, not an instruction change'),
            'source_host_ip_request_metadata': (A, 'the channel, not the origin address, distinguished the spoof'),
            'peer_agent_card_descriptor': (R, 'no peer agent is involved'),
            'credential_minting_scope_narrowing_check': (A, 'no credential exchange is documented'),
            'runtime_credential_attestation': (A, 'no runtime attestation is involved'),
            'surfaces_supported': (A, 'cross-channel exposure motivates it; no per-tool exposure map is involved')},
 'AOC-09': {'workflow_run_id': (A, 'the transfer is between agents, not within a run'),
            'tool_definition_digest': (R, 'no tool definition changed'),
            'mcp_server_identity_primitive': (A, 'no MCP server is documented'),
            'a2a_task_lifecycle_event': (A, 'predates A2A (AD §4.8)'),
            'peer_agent_card_descriptor': (A, 'no descriptor is documented'),
            'protocol_envelope_capture': (A, 'no protocol envelope is documented'),
            'trust_domain_crossing_delegation_depth': (A, 'no domain crossing is documented'),
            'agbom_inventory_snapshot': (A, 'Capability-Set Change carries the acquisition'),
            'instrumentation_coverage_hook_attestation': (A, NO_GAP)},
 'AOC-10': {'agent_name': (A, 'the agent identity does not distinguish the attack'),
            'workflow_run_id': (A, 'the run grouping does not distinguish the attack'),
            'trigger_type_source_event': (A, 'no autonomous trigger is documented as decisive'),
            'surface_app': (A, 'the entry surface does not distinguish the attack'),
            'observation_thought_reasoning_trace': (A, 'no reasoning trace is documented'),
            'pre_forward_pass_state_digest_vector': (A, 'research-grade; nothing documented'),
            'tool_id': (A, 'no attribution ambiguity is documented'),
            'tool_definition_digest': (R, 'the corrupted source is memory, not a tool definition'),
            'mcp_server_identity_primitive': (R, 'no MCP server is involved'),
            'tool_selection_rationale': (A, 'no stated rationale is documented'),
            'memory_write_rationale': (A, 'no stated rationale is documented'),
            'delegation_chain': (A, 'no delegated authority is documented'),
            'granted_authorizations_scope': (A, 'no delegated scope is documented'),
            'capability_set_change_event': (A, 'no capability was added or removed'),
            'repository_code_path_software_ref': (A, 'the Gist is memory content, not code'),
            'agbom_inventory_snapshot': (A, 'no inventory change is involved'),
            'inventory_attestation_signature': (A, 'no inventory change is involved'),
            'instrumentation_coverage_hook_attestation': (A, NO_GAP),
            'event_sequence_continuity': (A, NO_GAP)},
 'AOC-11': {'a2a_task_lifecycle_event': (A, 'predates A2A (AD §4.8)'),
            'peer_agent_card_descriptor': (A, 'no descriptor is documented'),
            'trust_domain_crossing_delegation_depth': (A, 'no domain crossing is documented')},
 'AOC-12': {'trigger_type_source_event': (A, 'the trigger does not distinguish the attempt'),
            'guardrail_modification_record': (A, 'no rewrite is documented'),
            'threat_classification_atlas_technique_tag': (A, 'derived tag; MUST by its conditional rule, not by instances'),
            'protocol_envelope_capture': (A, 'no protocol envelope is documented'),
            'enforcement_point_availability_failure_mode': (A, 'no enforcement failure is documented'),
            'policy_reason_code': (A, 'no enforcement decision is documented')},
 'AOC-14': {'tool_execution_id': (A, 'no request/result mismatch is documented'),
            'tool_definition_digest': (R, 'no tool definition changed'),
            'execution_environment_sandbox': (A, 'isolation posture does not distinguish the attempt'),
            'tool_error_exception': (A, 'the attempt was refused by the model, not failed by a tool'),
            'tool_description': (A, 'no misdescribed tool is documented')},
 'AOC-16': {'peer_agent_card_descriptor': (A, 'no descriptor is documented')},
 'IR-01': {f: (A, 'the case study documents injection templates and refusals, not this signal') for f in (
            'action_type', 'stop_reason', 'guardrail_modification_record', 'llm_error_exception', 'tool_name',
            'tool_error_exception', 'enforcement_point_availability_failure_mode', 'policy_reason_code')},
 'IR-02': {'pre_forward_pass_state_digest_vector': (A, 'research-grade; nothing documented'),
           'token_malformation_context_corruption_indicator': (A, 'research-grade; nothing documented'),
           'declared_memory_configuration': (A, 'no configuration change is involved')},
 'IR-03': {'declared_knowledge_source_configuration': (A, 'IR-03 poisons metadata, not search configuration (AD §4.7)')},
 'IR-04': {'*': (A, 'non-AI incident, carried for field overlap (AD §3.3)')},
 'TA-01': {'agent_name': (A, 'the agent identity does not distinguish the attack'),
           'trace_context_propagated': (A, 'one agent; no cross-hop reassembly is documented'),
           'organization_tenant_id': (R, 'the attack stays inside one tenant'),
           'content_modality_attachment_identity': (A, 'the payload is email text'),
           'tool_type_trust_boundary': (A, 'the trust boundary of the tool does not distinguish the attack'),
           'mcp_server_identity_primitive': (R, 'no MCP server is involved'),
           'tool_error_exception': (A, 'no tool error is documented'),
           'tool_privacy_classification': (A, 'governance metadata; nothing documented'),
           'a2a_task_lifecycle_event': (R, 'no A2A is involved'),
           'resource_indicators_constraints': (A, 'no constraint was in force'),
           'policy_reason_code': (A, 'no enforcement decision is documented'),
           'backend_route_restriction_decision': (R, 'no backend selection is involved')},
 'TA-02': {'retrieved_content_metadata_integrity_signal': (A, 'no integrity signal is documented'),
           'declared_knowledge_source_configuration': (A, 'no configuration change is involved'),
           'tool_error_exception': (A, 'an absence of tool errors does not distinguish the attack')},
 'TA-03': {'encoded_obfuscated_payload_indicator': (A, 'the encoding is in the output URL; the indicator is input-side')},
 'TA-05': {'organization_tenant_id': (A, 'data left the organization; no tenant boundary within the deployment'),
           'content_modality_attachment_identity': (A, 'the payload is pasted text'),
           'session_taint_labels_information_flow_decisions': (A, 'no information-flow decision is documented')},
 'TA-06': {'model_name_version': (A, 'the vulnerability is in the framework, not the model'),
           'model_provenance_signing_hash': (R, 'no model artefact is involved'),
           'tool_definition_digest': (R, 'no tool definition changed'),
           'mcp_server_identity_primitive': (R, 'predates MCP; the tools are framework chains'),
           'protocol_envelope_capture': (R, 'no MCP or A2A envelope is involved'),
           'runtime_credential_attestation': (A, 'no runtime attestation is involved'),
           'capability_set_change_event': (A, 'no capability was added or removed'),
           'repository_code_path_software_ref': (A, 'version, not source path, scopes the CVE'),
           'inventory_attestation_signature': (A, 'no inventory tampering is involved'),
           'fleet_counts': (A, 'CVE exposure motivates it; nothing documented'),
           'mediation_coverage_bypass_path': (A, 'no mediation layer is documented')},
 'TA-07': {'threat_classification_atlas_technique_tag': (A, 'derived tag; MUST by its conditional rule, not by instances')},
 'TA-08': {'tool_selection_rationale': (A, 'no stated rationale is documented')},
 'TA-09': {'declared_knowledge_source_configuration': (A, 'no configuration change is involved'),
           'creator_id_oncall_creation_update_dates': (A, 'document freshness is recorded by Retrieved-Content Source / Provenance'),
           'retrieved_content_metadata_integrity_signal': (A, 'no integrity signal is documented')},
 'TA-10': {'enforcement_point_availability_failure_mode': (A, 'TA-10 grounds the enforcement fields analogically (AD §4.11)'),
           'fleet_counts': (A, 'per-request signals, not fleet aggregates, distinguish the attack')},
}
for _f in ('threat_classification_atlas_technique_tag',):
    for _a in ('TA-01', 'IR-01'):
        J.setdefault(_a, {})[_f] = (A, 'derived tag; MUST by its conditional rule, not by instances')

# Tier basis for MUST fields that the proposals leave with <= 1 instance edge.
BASIS = {
 'threat_classification_atlas_technique_tag': ({'conditional': 'when a detection fires'},
    'a derived tag; RFC §6.2 makes it MUST when a detection fires, not on instances'),
 'agent_name': ({'required_to_read': 'every §6.1 identifier chain'},
    'RFC §6.1: every later detection resolves through these identifiers; one instance edge (TA-05)'),
 'agent_runtime_instance_id': ({'required_to_read': 'every §6.1 identifier chain'},
    'RFC §6.1 identifier; one instance edge (AOC-04)'),
 'workflow_run_id': ({'required_to_read': 'every §6.1 identifier chain'},
    'RFC §6.1 identifier; one instance edge (AOC-04)'),
 'guardrail_modification_record': ({'required_to_read': ['model_input', 'response_model_output',
                                                        'guardrail_input_verdict', 'guardrail_output_verdict']},
    'AD §4.2 already rests the tier on the dependency, not on an instance'),
 'enforcement_point_availability_failure_mode': ({'required_to_read': ['guardrail_input_verdict',
                                                   'guardrail_output_verdict', 'authorization_decision_record']},
    'AD §4.11 already rests the tier on the interpretation clause'),
 'instrumentation_coverage_hook_attestation': ({'required_to_read': 'absence-based detections'},
    'one instance (TA-17); AD §4.11 cites a single-attack clause RFC §4.7 no longer has. '
    'Dependency is the alternative: AD §4.11 says it resolves every absence-based detection'),
 'tool_definition_digest': ({'evidence': 'needs a second instance'},
    'one instance (TA-15); TA-14 and TA-16 do not change the declared contract (AD §4.5). '
    'Options: a second documented instance, a dependency argument, or SHOULD'),
 'memory_footprint_growth': ({'evidence': 'decide AOC-04'},
    'AOC-05 is the one clear instance; the tier turns on E:AOC-04:memory_footprint_growth'),
}


def proposal(aid, fid):
    t = J.get(aid, {})
    return t.get(fid) or t.get('*') or ('instance', '')


QUALIFIER = re.compile(r'^(?P<base>.+?)(?P<q> \(.+\)|=.+)$')


fields = {f['id']: f for f in load(os.path.join(DATA, 'fields.yaml'))}
by_name = {f['name']: f['id'] for f in fields.values()}


def resolve_item(text):
    """Map one comma-separated item to [(field id, qualifier)]."""
    base, q = text, None
    if text not in by_name and text not in ALIASES:
        m = QUALIFIER.match(text)
        if m:
            base, q = m['base'], m['q'].strip()
            q = q[1:-1] if q.startswith('(') else q
    target = by_name.get(base, ALIASES.get(base))
    if target is None:
        raise SystemExit(f'unresolved field name: {text!r}')
    ids = target if isinstance(target, list) else [target]
    return [(i, q) for i in ids], base


def resolve_cell(cell):
    out, judged = [], []
    for item in cell.split(', '):
        pairs, base = resolve_item(item)
        if base in JUDGED:
            judged.append((item, [p[0] for p in pairs]))
        for fid, q in pairs:
            if fid not in [o[0] for o in out]:
                out.append((fid, q))
    return [{'field': f, 'note': q} if q else f for f, q in out], judged


def attack_files():
    return sorted(glob.glob(os.path.join(DATA, 'attacks', '*.yaml')),
                  key=lambda p: (os.path.basename(p).split('-')[0], int(re.findall(r'\d+', p)[-1])))


def first_line(path):
    with open(path, encoding='utf-8') as f:
        return f.readline()


def cmd_resolve():
    for p in attack_files():
        a = load(p)
        refs, _ = resolve_cell(a['detecting_fields_text'])
        out = {}
        for k, v in a.items():
            out[k] = v
            if k == 'detecting_fields_text':
                out['fields'] = refs
        dump(out, p, first_line(p))
    pp = os.path.join(DATA, 'patterns.yaml')
    pats = load(pp)
    for i, pat in enumerate(pats):
        refs, _ = resolve_cell(pat['fields_text'])
        out = {}
        for k, v in pat.items():
            out[k] = v
            if k == 'fields_text':
                out['fields'] = refs
        pats[i] = out
    dump(pats, pp, first_line(pp))
    print('resolved field names in', len(attack_files()), 'attacks and', len(pats), 'patterns')


def ref_id(r):
    return r if isinstance(r, str) else r['field']


def cmd_report(out):
    attacks = {a['id']: a for a in map(load, attack_files())}
    pats = load(os.path.join(DATA, 'patterns.yaml'))
    cites = {(a, f['id']) for f in fields.values() for a in f['evidence']}          # field row -> attack
    names = {(aid, ref_id(r)) for aid, a in attacks.items() for r in a['fields']}  # attack row -> field
    only_field, only_attack, both = cites - names, names - cites, cites & names

    def tier_test(edges):
        """Fields passing the evidence half of the MUST test: two grounding attacks, IR-04 excluded."""
        n = defaultdict(set)
        for a, f in edges:
            if a != 'IR-04':
                n[f].add(a)
        return {f: len(n[f]) for f in fields}

    L = ['# Phase 2 reconciliation report', '',
         'Generated by `tools/reconcile.py report`. An edge is a pair (attack, field).',
         'The field rows of AD §1 cite attacks in their Evidence column; the attack rows of',
         'AD §3 name fields in their detecting-fields column. These are the two directions.', '',
         f'- Edges in both directions: **{len(both)}**',
         f'- Field row cites the attack, attack row does not name the field: **{len(only_field)}**',
         f'- Attack row names the field, field row does not cite the attack: **{len(only_attack)}**', '']

    L += ['## Names resolved by judgement', '',
          'Attack and pattern cells that did not name a field directly.', '',
          '| Where | Text | Resolved to |', '| :--- | :--- | :--- |']
    for aid, a in attacks.items():
        for item, ids in resolve_cell(a['detecting_fields_text'])[1]:
            L.append(f"| {aid} | {item} | {', '.join(f'`{i}`' for i in ids)} |")
    for p in pats:
        for item, ids in resolve_cell(p['fields_text'])[1]:
            L.append(f"| {p['id']} | {item} | {', '.join(f'`{i}`' for i in ids)} |")
    L.append('')

    cur, uni, inter = tier_test(cites), tier_test(cites | names), tier_test(both)
    L += ['## Effect on the evidence test', '',
          'Grounding-attack counts per field under three edge sets: as AD cites today (field',
          'rows), the union of both directions, and only edges both directions agree on. IR-04',
          'is excluded. A MUST field below two may still hold MUST by dependency; a SHOULD or MAY',
          'field at two or more is held by its modality or priority gate. Listed: fields whose',
          'count crosses two between the sets, and MUST fields under two in any set.', '',
          '| Field | Tier | Today | Union | Agreed |', '| :--- | :--- | ---: | ---: | ---: |']
    for fid, f in fields.items():
        c = (cur[fid], uni[fid], inter[fid])
        crosses = len({x >= 2 for x in c}) > 1
        if crosses or (f['tier'] == 'MUST' and min(c) < 2):
            L.append(f"| {f['name']} | {f['tier']} | {c[0]} | {c[1]} | {c[2]} |")
    L.append('')

    def section(title, intro, edges):
        L.extend([f'## {title}', '', intro, ''])
        by_attack = defaultdict(list)
        for a, f in edges:
            by_attack[a].append(f)
        for aid in attacks:
            if aid in by_attack:
                a = attacks[aid]
                L.append(f"**{aid}** {a['name']}: " + ', '.join(
                    f"{fields[f]['name']} ({fields[f]['tier']})" for f in fields if f in by_attack[aid]))
                L.append('')

    section('Field cites the attack; attack row omits the field',
            'Grouped by attack. These are the edges the tier tests ran on today.', only_field)
    section('Attack names the field; field row omits the attack',
            'Grouped by attack.', only_attack)

    with open(out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(L))
    print(f'{len(both)} agreed, {len(only_field)} field-only, {len(only_attack)} attack-only -> {out}')


def cmd_propose():
    attacks = {a['id']: a for a in map(load, attack_files())}
    cites = {(a, f['id']) for f in fields.values() for a in f['evidence']}
    names = {(aid, ref_id(r)) for aid, a in attacks.items() for r in a['fields']}
    for key in J:
        assert key in attacks, key
        for fid in J[key]:
            assert fid == '*' or fid in fields, fid

    # Instance counts per MUST field under the proposals, IR-04 excluded.
    inst = Counter(f for a, f in cites | names if a != 'IR-04' and proposal(a, f)[0] == 'instance')
    weak = {f for f in fields if fields[f]['tier'] == 'MUST' and inst[f] <= 2}

    out = []
    order = list(attacks)
    for a, f in sorted(cites | names, key=lambda e: (order.index(e[0]), list(fields).index(e[1]))):
        cls, why = proposal(a, f)
        src = 'both' if (a, f) in cites and (a, f) in names else ('field' if (a, f) in cites else 'attack')
        c = {'id': f'E:{a}:{f}', 'type': 'edge', 'subject': {'attack': a, 'field': f},
             'source': src, 'proposal': {'grounding': cls}}
        if why:
            c['reason'] = why
        if f in weak:
            c['critical'] = True
            c['reason'] = (c.get('reason', '') + ('; ' if why else '') +
                           f"{fields[f]['name']} is MUST with {inst[f]} instance edge(s) under these proposals").strip()
        c['status'] = 'proposed'
        out.append(c)
    for where, cell in ([(aid, a['detecting_fields_text']) for aid, a in attacks.items()] +
                        [(p['id'], p['fields_text']) for p in load(os.path.join(DATA, 'patterns.yaml'))]):
        for item, ids in resolve_cell(cell)[1]:
            out.append({'id': f'N:{where}:{item.strip("`")}', 'type': 'alias',
                        'subject': {'where': where, 'text': item}, 'source': 'attack' if where[0] != 'C' else 'pattern',
                        'proposal': {'fields': ids}, 'status': 'proposed'})
    for fid, (b, why) in BASIS.items():
        out.append({'id': f'B:{fid}', 'type': 'basis', 'subject': {'field': fid}, 'source': 'tier',
                    'proposal': {'basis': b}, 'reason': why, 'critical': True, 'status': 'proposed'})
    os.makedirs(os.path.join(DATA, 'candidates'), exist_ok=True)
    path = os.path.join(DATA, 'candidates', '2026-10-02-phase2.yaml')
    dump(out, path, '# Phase 2 batch: grounding class for every attack-field edge, and judged name\n'
                    '# resolutions. Decide with tools/curate.py. Schema in curate.py.\n')
    print(f'{len(out)} candidates -> {os.path.relpath(path, DIR)}')
    print('MUST fields with <= 2 instance edges:')
    for f in sorted(weak, key=lambda f: inst[f]):
        print(f'  {inst[f]}  {fields[f]["name"]}')


if __name__ == '__main__':
    if sys.argv[1:2] == ['resolve']:
        cmd_resolve()
    elif sys.argv[1:2] == ['propose']:
        cmd_propose()
    elif sys.argv[1:2] == ['report'] and len(sys.argv) == 3:
        cmd_report(sys.argv[2])
    else:
        raise SystemExit(__doc__)
