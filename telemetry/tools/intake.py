#!/usr/bin/env python3
"""Intake of a new attack into the corpus (data/README.md describes the process).

  intake.py new TA-32        write data/candidates/<date>-intake-TA-32.yaml: an
                             A:TA-32 candidate holding a template record with the
                             next free reference number, to fill in by hand
  intake.py propose TA-32    turn the record's `chain` into E: candidates, one
                             per field a step names (status proposed)
  intake.py report TA-32     what adding the attack would change, computed from
                             the batch as it stands: fields whose tier test
                             changes, patterns that would fire, chain steps no
                             pattern covers, rules the attack would break

The report proposes nothing and promotes nothing. A field that comes to meet
the MUST evidence test stays at its tier until someone decides otherwise
(RFC §4.7: closing an evidence gap does not lift a modality-gated field).

The record's `chain` lists the attack's steps in order, each with the fields
that would record it:
    chain:
    - step: the agent reads the poisoned page
      fields:
      - {field: retrieval_event, reason: why the instance contains it}
      - {field: input_trust_classification, grounding: analogical, reason: ...}
"""
import argparse
import datetime
import glob
import os
import re
import sys

import rules
from yamlio import dump, load

DIR, DATA = rules.DIR, rules.DATA
CAND = os.path.join(DATA, 'candidates')
DOCS = ['CoSAI-AI-Telemetry-RFC.md', 'Telemetry-Attack-Detection-Addendum.md', 'Telemetry-Cross-Mapping-Addendum.md']
RETIRED_REFS = {27, 28, 46, 48}
HEADER = ('# Curation registry batch. Edit status only through tools/curate.py, or by hand\n'
          '# keeping decided_by and decided_on filled in. See curate.py for the schema.\n'
          '# Intake batch written by tools/intake.py; fill in every TODO, then run\n'
          '# `intake.py propose <ID>` and `intake.py report <ID>`.\n')
INSTANCE_KINDS = ('executed', 'resisted', 'failure')
TODO = 'TODO'


def batch_path(aid):
    found = glob.glob(os.path.join(CAND, f'*-intake-{aid}.yaml'))
    if len(found) > 1:
        sys.exit(f'more than one intake batch for {aid}: {found}')
    return found[0] if found else None


def next_reference():
    """The next free reference number across the three documents (numbers are never reused)."""
    used = set(RETIRED_REFS)
    for d in DOCS:
        with open(os.path.join(DIR, d), encoding='utf-8') as f:
            used |= {int(n) for n in re.findall(r'(?m)^(\d+)\. \*\*', f.read())}
    used |= {a.get('ref') for a in rules.load_data()[1].values() if a.get('ref')}
    return max(used) + 1


def cmd_new(aid):
    if not re.fullmatch(r'TA-\d+', aid):
        sys.exit('intake takes real-world attacks: an ID of the form TA-<n>')
    if aid in rules.load_data()[1] or batch_path(aid):
        sys.exit(f'{aid} already exists in data/attacks or has an intake batch')
    record = {
        'id': aid, 'name': TODO, 'label': TODO + ': **Name** (source, Mon YYYY)', 'ref': next_reference(),
        'instance': TODO + ': ' + ' | '.join(INSTANCE_KINDS), 'same_incident_as': [],
        'what_happened': TODO, 'reference': TODO + ': title, publisher, date. <URL>',
        'atlas': [TODO], 'atlas_text': TODO, 'atlas_notes': TODO,
        'risks': [TODO], 'components_text': TODO,
        'chain': [{'step': TODO, 'fields': [{'field': TODO, 'reason': TODO}]}],
    }
    c = {'id': f'A:{aid}', 'type': 'attack', 'subject': {'attack': aid}, 'source': 'intake',
         'proposal': {'record': record},
         'reason': TODO + ': why this is a documented instance traceable to a primary source (AD §3), '
                          'and whether it is independent of the corpus entries it resembles',
         'critical': True, 'status': 'proposed'}
    path = os.path.join(CAND, f'{datetime.date.today().isoformat()}-intake-{aid}.yaml')
    dump([c], path, HEADER)
    print(f'wrote {os.path.relpath(path, DIR)}; reference number {record["ref"]} reserved')


def load_batch(aid):
    path = batch_path(aid)
    if not path:
        sys.exit(f'no intake batch for {aid}; run `intake.py new {aid}`')
    batch = load(path)
    a = next((c for c in batch if c['id'] == f'A:{aid}'), None)
    if not a:
        sys.exit(f'{path} has no A:{aid} candidate')
    return path, batch, a


def todos(obj, where=''):
    if isinstance(obj, str):
        return [where] if obj.startswith(TODO) else []
    if isinstance(obj, dict):
        return [t for k, v in obj.items() for t in todos(v, f'{where}.{k}' if where else k)]
    if isinstance(obj, list):
        return [t for i, v in enumerate(obj) for t in todos(v, f'{where}[{i}]')]
    return []


def batch_edges(batch, aid):
    """The attack's edges as they would enter data/: E: candidates not rejected, decided grounding first."""
    out = []
    for c in batch:
        if c['type'] == 'edge' and c['subject']['attack'] == aid and c['status'] != 'rejected':
            g = c.get('decision', {}).get('grounding', c['proposal']['grounding'])
            out.append(c['subject']['field'] if g == 'instance' else {'field': c['subject']['field'], 'grounding': g})
    return out


def fires(p, rec, fields):
    """'instance' or 'analogical' if the attack's edges support every field the pattern reads, else None."""
    checked = set(p['requires']) | {x for x in p['join'] if fields[x]['role'] != 'identifier'}
    e = rules.edges(rec)
    if all(e.get(x) == 'instance' for x in checked):
        return 'instance'
    return 'analogical' if all(x in e for x in checked) else None


def batch_patterns(batch, patterns):
    """Patterns as they would stand if the batch's pattern and catch candidates were accepted."""
    out = {p['id']: dict(p) for p in patterns}
    for c in batch:
        if c['status'] == 'rejected':
            continue
        if c['type'] == 'pattern':
            out[c['proposal']['id']] = dict(c['proposal'])
        elif c['type'] == 'catch' and c['subject']['pattern'] in out:
            p = out[c['subject']['pattern']]
            key = 'catches' if c['proposal']['grounding'] == 'instance' else 'catches_analogical'
            p[key] = list(dict.fromkeys(p.get(key, []) + [c['subject']['attack']]))
    return list(out.values())


def cmd_propose(aid):
    path, batch, a = load_batch(aid)
    fields = rules.load_data()[0]
    have = {c['id'] for c in batch}
    added, problems = 0, []
    for step in a['proposal']['record'].get('chain', []):
        for e in step.get('fields', []):
            fid = e.get('field')
            if fid not in fields:
                problems.append(f'unknown field {fid!r} in step {step.get("step")!r}')
                continue
            cid = f'E:{aid}:{fid}'
            if cid in have:
                continue
            batch.append({'id': cid, 'type': 'edge', 'subject': {'attack': aid, 'field': fid}, 'source': 'intake',
                          'proposal': {'grounding': e.get('grounding', 'instance')},
                          'reason': e.get('reason', TODO), 'requires': f'A:{aid}', 'status': 'proposed'})
            have.add(cid)
            added += 1
    # Patterns the attack's edges support, as catch candidates (the report shows the same list).
    rec = dict(a['proposal']['record'], fields=batch_edges(batch, aid))
    caught = 0
    for p in rules.load_data()[2]:
        g = fires(p, rec, fields)
        cid = f'K:{p["id"]}:{aid}'
        if g and cid not in have:
            batch.append({'id': cid, 'type': 'catch', 'subject': {'pattern': p['id'], 'attack': aid},
                          'source': 'intake', 'proposal': {'grounding': g},
                          'reason': f'the edges support every field the pattern reads ({g})',
                          'requires': f'A:{aid}', 'status': 'proposed'})
            have.add(cid)
            caught += 1
    dump(batch, path, open(path, encoding='utf-8').read().split('- id:')[0])
    print(f'{added} edge and {caught} catch candidates added to {os.path.relpath(path, DIR)}')
    for p in problems:
        print('  problem:', p)


def cmd_report(aid):
    path, batch, a = load_batch(aid)
    fields, attacks, patterns, layout = rules.load_data()
    rec = dict(a['proposal']['record'])
    print(f'Intake report for {aid}: {rec.get("name")}  ({os.path.relpath(path, DIR)})\n')

    open_items = todos(rec) + (['reason'] if str(a.get('reason', '')).startswith(TODO) else [])
    if rec.get('instance') not in INSTANCE_KINDS and 'instance' not in open_items:
        open_items.append('instance')
    print('To fill in:', ', '.join(open_items) if open_items else 'nothing')

    edges = batch_edges(batch, aid)
    rec['fields'] = edges
    patterns = batch_patterns(batch, patterns)
    if not edges:
        print('No edge candidates yet: run `intake.py propose` after filling in the chain.')
    after = dict(attacks) | {aid: rec}
    indep = not rec.get('same_incident_as')

    print('\nTier tests the attack changes (nothing is promoted automatically):')
    shown = False
    for fid in sorted({rules.edge(e)[0] for e in edges if rules.edge(e)[1] == 'instance'}):
        f = fields[fid]
        n0 = len(rules.instances(fid, attacks))
        n1 = n0 + 1 if indep else n0
        may = f.get('basis', {}).get('may', [])
        note = None
        if f['tier'] == 'SHOULD' and n0 < 2 <= n1:
            note = (f'now has {n1} instances; stays SHOULD on its modality ({f.get("modality", "provider-gated")}) '
                    'unless the modality is judged typical')
        elif f['tier'] == 'MAY' and n0 < 2 <= n1:
            note = (f'now has {n1} instances; MAY basis {may} ' +
                    ('breaks: "thin" no longer holds; record another MAY reason or propose a tier'
                     if 'thin' in may and not set(may) - {'thin'} else 'still holds on its other reasons'))
        elif f['tier'] == 'MUST' and 'required_to_read' in f.get('basis', {}) and n0 < 2 <= n1:
            note = f'MUST on a dependency; now also meets the evidence test ({n1} instances)'
        if note:
            print(f'  {f["name"]}: {note}')
            shown = True
    if not indep:
        print(f'  same_incident_as {rec["same_incident_as"]}: its edges add no independent instance')
    if not shown and indep:
        print('  none')

    print('\nPatterns that would fire (instance edges to every field they read), with or without a catch candidate:')
    firing = []
    for p in patterns:
        g = fires(p, rec, fields)
        recorded = aid in p.get('catches', []) + p.get('catches_analogical', [])
        mark = '' if recorded else '  [no catch candidate: run propose]'
        if g == 'instance':
            firing.append(p)
            print(f'  {p["id"]}: {p["name"]}{mark}')
        elif g:
            print(f'  {p["id"]}: {p["name"]} (analogically){mark}')
    if not firing:
        print('  none: the attack needs a new pattern, or a recorded no_pattern reason')

    print('\nChain steps no firing pattern reads:')
    read = {x for p in firing for x in p['requires'] + p['join']}
    gaps = [s.get('step') for s in rec.get('chain', []) if not {e.get('field') for e in s.get('fields', [])} & read]
    print('  ' + '\n  '.join(gaps) if gaps else '  none')

    print('\nRules the attack would break:')
    before = set(rules.attack_problems(fields, attacks) + rules.tier_problems(fields, attacks))
    new = [p for p in rules.attack_problems(fields, after) + rules.tier_problems(fields, after) if p not in before]
    cov = [p for p in rules.pattern_problems(fields, after, patterns) if p.startswith(aid + ':')]
    print('  ' + '\n  '.join(new + cov) if new + cov else '  none')


def main():
    ap = argparse.ArgumentParser(allow_abbrev=False, description='Intake of a new attack.')
    ap.add_argument('command', choices=['new', 'propose', 'report'])
    ap.add_argument('attack', help='the attack ID, e.g. TA-32')
    args = ap.parse_args()
    {'new': cmd_new, 'propose': cmd_propose, 'report': cmd_report}[args.command](args.attack)


if __name__ == '__main__':
    main()
