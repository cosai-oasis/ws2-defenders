#!/usr/bin/env python3
"""Phase 4, one-shot: remap references to the old AD §1 component clusters
(§1.1 to §1.12) onto the new step sections (§1.1 to §1.6, one per RFC §6
step), in one atomic pass.

Old and new numbers overlap, so every reference is resolved from the
original text by a single regex pass; nothing is replaced twice. Clusters
1.1 to 1.10 each sit wholly in one step. Clusters 1.11 and 1.12 split, so a
reference to them takes the step of the field named just before it, and
falls back to the step holding most of the cluster's fields otherwise.

Usage: python3 tools/phase4_remap.py [--write]   (default: report only)
"""
import os
import re
import sys

import yaml

from mdtables import gh_anchor

DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))   # the documents: telemetry/
AD, RFC, XM = ('Telemetry-Attack-Detection-Addendum.md', 'CoSAI-AI-Telemetry-RFC.md',
               'Telemetry-Cross-Mapping-Addendum.md')
layout = yaml.safe_load(open(os.path.join(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')), 'sections.yaml'), encoding='utf-8'))
fields = {f['id']: f for f in yaml.safe_load(open(os.path.join(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')), 'fields.yaml'), encoding='utf-8'))}

STEP = {s['number']: '1.' + s['number'].split('.')[1] for s in layout['rfc_field_tables']}   # 6.k -> 1.k
field_step = {f: STEP[s['number']] for s in layout['rfc_field_tables'] for f in s['fields']}
cluster_of = {f: c['number'] for c in layout['ad_field_tables'] for f in c['fields']}
OLD_ANCHOR = {gh_anchor(f"{c['number']} {c['title']}"): c['number'] for c in layout['ad_field_tables']}
NEW_TITLE = {STEP[s['number']]: s['title'] for s in layout['rfc_field_tables']}
NEW_ANCHOR = {n: gh_anchor(f'{n} {t}') for n, t in NEW_TITLE.items()}

DEFAULT = {}
for c in layout['ad_field_tables']:
    steps = [field_step[f] for f in c['fields']]
    DEFAULT[c['number']] = max(set(steps), key=steps.count)
SPLIT = {c for c in DEFAULT if len({field_step[f] for f in layout['ad_field_tables'][[x['number'] for x in layout['ad_field_tables']].index(c)]['fields']}) > 1}

# Names by which prose refers to fields of the split clusters, longest first.
ALIAS = {}
for f in fields.values():
    if cluster_of[f['id']] in SPLIT:
        n = f['name']
        for v in {n, n.split(' / ')[0], n.split(' & ')[0], n.split(' (')[0]}:
            if len(v) > 6:
                ALIAS[v] = f['id']
ALIAS.update({  # short forms used in prose
    'event sequence continuity': 'event_sequence_continuity', 'event continuity': 'event_sequence_continuity',
    'sequence continuity': 'event_sequence_continuity', 'sequence number': 'event_sequence_continuity',
    'policy reason code': 'policy_reason_code', 'reason code': 'policy_reason_code',
    'attribute source': 'attribute_source_trusted_provenance_marking',
    'trusted-provenance marking': 'attribute_source_trusted_provenance_marking',
    'hook coverage': 'instrumentation_coverage_hook_attestation', 'hook-coverage': 'instrumentation_coverage_hook_attestation',
    'instrumentation coverage': 'instrumentation_coverage_hook_attestation',
    'enforcement-availability': 'enforcement_point_availability_failure_mode', 'fail-open': 'enforcement_point_availability_failure_mode',
    'authorization decision': 'authorization_decision_record', 'session taint': 'session_taint_labels_information_flow_decisions',
    'taint': 'session_taint_labels_information_flow_decisions', 'human approval': 'human_approval_elicitation_event',
    'mediation coverage': 'mediation_coverage_bypass_path', 'route restriction': 'backend_route_restriction_decision',
})
ALIAS = {k.lower(): v for k, v in ALIAS.items()}
ALIAS_RE = re.compile('|'.join(re.escape(a) for a in sorted(ALIAS, key=len, reverse=True)), re.I)

log = {'mapped': 0, 'by_field': 0, 'fallback': [], 'collapsed': 0}


def resolve(old, before):
    """New section for old cluster number `old`, given the text just before it."""
    if old not in SPLIT:
        return DEFAULT[old]
    names = [m for m in ALIAS_RE.finditer(before[-160:])]
    for m in reversed(names):
        fid = ALIAS[m.group(0).lower()]
        if cluster_of[fid] == old:
            log['by_field'] += 1
            return field_step[fid]
        break
    log['fallback'].append((old, before[-90:].replace('\n', ' ')))
    return DEFAULT[old]


NUM = r'1\.(?:1[0-2]|[1-9])'
LIST = rf'{NUM}(?:(?:\s*,\s*|\s+(?:to|and|or)\s+){NUM})*'


def render(nums, plural_was):
    nums = sorted(set(nums), key=lambda n: int(n.split('.')[1]))
    if len(nums) == 6:
        return '§1'
    if len(nums) == 1:
        return '§' + nums[0]
    k = [int(n.split('.')[1]) for n in nums]
    if k == list(range(k[0], k[-1] + 1)) and len(k) > 2:
        return f'§§1.{k[0]} to 1.{k[-1]}'
    return '§§' + (', '.join(nums[:-1]) + ' and ' + nums[-1] if len(nums) > 2 else ' and '.join(nums))


def expand(listtext):
    """'1.2 to 1.5' -> all clusters in the range; '1.1, 1.5' -> those."""
    parts = re.split(r'(\s*,\s*|\s+(?:to|and|or)\s+)', listtext)
    out, i = [], 0
    while i < len(parts):
        n = parts[i]
        if i + 2 < len(parts) and parts[i + 1].strip() == 'to':
            a, b = int(n.split('.')[1]), int(parts[i + 2].split('.')[1])
            out += [f'1.{j}' for j in range(a, b + 1)]
            i += 4
        else:
            out.append(n)
            i += 2
    return out


def remap_text(text, prefix_required):
    """prefix_required: references must read 'AD §…' (RFC, XM); in AD a bare '§…' counts,
    and 'RFC §'/'XM §' and other specifications' sections are left alone."""
    if prefix_required:
        pat = re.compile(rf'(AD )(§§?)\s?({LIST})(?![\d.])')
    else:
        pat = re.compile(rf'(?<!RFC )(?<!XM )(?<!ODIS )(?<!CPEX )(?<!AOS )(?<!OCSF )()(§§?)\s?({LIST})(?![\d.])')

    def sub(m):
        olds = expand(m.group(3))
        new = [resolve(o, text[:m.start()]) for o in olds]
        log['mapped'] += 1
        if len(set(new)) < len(olds):
            log['collapsed'] += 1
        return m.group(1) + render(new, m.group(2))

    text = pat.sub(sub, text)

    # Links to the old cluster anchors, in the same document or the addendum.
    def link(m):
        old = OLD_ANCHOR.get(m.group(2))
        if not old:
            return m.group(0)
        log['mapped'] += 1
        return m.group(1) + NEW_ANCHOR[resolve(old, text[:m.start()])]
    return re.sub(r'((?:Telemetry-Attack-Detection-Addendum\.md)?#)(1\d*-[a-z0-9-]+)', link, text)


SPECIAL = [  # sentences whose meaning is the old order itself; rewritten, not remapped
    (AD, 'Ordered to match the field tables, §1.1 through §1.12.', 'Ordered by component cluster.'),
]


def main():
    write = '--write' in sys.argv
    out = {}
    for name, req in ((AD, False), (RFC, True), (XM, True)):
        t = open(os.path.join(DIR, name), encoding='utf-8').read()
        for doc, old, new in SPECIAL:
            if doc == name:
                assert t.count(old) == 1, old
                t = t.replace(old, new)
        if name == AD:   # §1 itself is rewritten by the new skeleton; remap the rest
            head, rest = t.split('## 1. Field Tables', 1)
            sec1, tail = rest.split('\n## 2. ', 1)
            t = remap_text(head, False) + '## 1. Field Tables' + sec1 + '\n## 2. ' + remap_text(tail, False)
        else:
            t = remap_text(t, req)
        out[name] = t
    fp = os.path.join(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')), 'fields.yaml')
    ftext = remap_text(open(fp, encoding='utf-8').read(), False)
    print(f"references remapped: {log['mapped']}; split clusters resolved by field: {log['by_field']}; "
          f"lists that collapsed: {log['collapsed']}")
    print(f"fallbacks to the majority step ({len(log['fallback'])}):")
    for old, ctx in log['fallback']:
        print(f'  §{old} -> §{DEFAULT[old]}   ...{ctx}')
    if write:
        for name, t in out.items():
            open(os.path.join(DIR, name), 'w', encoding='utf-8').write(t)
        open(fp, 'w', encoding='utf-8').write(ftext)
        print('written')


if __name__ == '__main__':
    main()
