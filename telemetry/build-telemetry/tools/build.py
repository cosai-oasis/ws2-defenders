#!/usr/bin/env python3
"""Regenerate the data-driven regions of the RFC and the Attack Detection
Addendum (AD) from data/.

Regions: AD §1 field tables and their field entries (capture definition, tier
basis, rationale, the patterns that read the field; between GENERATED markers,
one per step), §2 patterns (summary, an entry per pattern by stage, coverage;
between GENERATED markers), §3.2 to §3.4 inventory
tables, §3.6 ATLAS table and the attack-source reference list; RFC §6 field
tables, which link to each field's AD entry, and the tier totals the RFC states.
Everything else in both documents is hand-written and left untouched.

Usage:
  python3 tools/build.py           rewrite the documents in place
  python3 tools/build.py --check   exit 1 if a document differs from the data
"""
import argparse
import difflib
import glob
import os
import re
import sys

import yaml

import rules
from mdtables import find_tables, gh_anchor, row

DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))   # the documents: telemetry/
DATA = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data'))   # build-telemetry/data/
RFC, AD = 'CoSAI-AI-Telemetry-RFC.md', 'Telemetry-Attack-Detection-Addendum.md'


def load(path):
    with open(os.path.join(DATA, path), encoding='utf-8') as f:
        return yaml.safe_load(f)


fields = {f['id']: f for f in load('fields.yaml')}
patterns = load('patterns.yaml')
attacks = {a['id']: a for a in map(load, (os.path.relpath(p, DATA)
                                           for p in glob.glob(os.path.join(DATA, 'attacks', '*.yaml'))))}
layout = load('sections.yaml')
RANK = rules.RANK
STAGES = [s['stage'] for s in layout['pattern_stages']]

steps = layout['field_steps']


def anchor(fid):
    """The explicit anchor of a field's entry in AD §1."""
    return 'f-' + fid.replace('_', '-')

PREFIX = {'TA': 0, 'IR': 1, 'AOC': 2}
corpus_order = sorted(attacks, key=lambda a: (PREFIX[a.split('-')[0]], int(a.split('-')[1])))


def edge(e):
    """(field id, grounding, note) for one `fields:` entry of an attack."""
    if isinstance(e, str):
        return e, 'instance', None
    return e['field'], e.get('grounding', 'instance'), e.get('note')


# Grounding attacks per field, derived from the attacks' edges.
grounds = {fid: [] for fid in fields}
for aid in corpus_order:
    for e in attacks[aid].get('fields', []):
        fid, g, _ = edge(e)
        grounds[fid].append((aid, g))


def min_tier(p):
    return max((fields[f]['tier'] for f in p['requires'] + p['join']), key=RANK.get)


patterns.sort(key=lambda p: (STAGES.index(p['stage']), RANK[min_tier(p)], p['name'].casefold()))
pmap = {p['id']: p for p in patterns}
read_by = {fid: [p['id'] for p in patterns if fid in p['requires'] + p['join']] for fid in fields}


def ticks(ids):
    return ','.join(f'`{i}`' for i in ids)


# ---------------------------------------------------------------- renderers
def emitted(f):
    return (', '.join(f'`{e}`' for e in f['emitted_by']) if 'emitted_by' in f else f['emitted_by_text'])


def records(f):
    """The one-line definition, with the SHOULD modality appended as RFC §6 shows it."""
    if 'modality' in f:
        return f"{f['records']} Modality: {f['modality']}."
    return f"{f['records']} Provider-gated." if f.get('provider_gated') else f['records']


def link(fid):
    return f"[{fields[fid]['name']}](#{anchor(fid)})"


def panchor(pid):
    return 'p-' + pid.replace('_', '-')


def plink(pid):
    return f"[{pmap[pid]['name']}](#{panchor(pid)})"


def prose(s):
    """Hand-written text that names a pattern by slug, with the slug shown as its linked name."""
    return re.sub(r'`([a-z0-9_]+)`', lambda m: plink(m[1]) if m[1] in pmap else m[0], s)


def series(items):
    return items[0] if len(items) == 1 else ', '.join(items[:-1]) + ' and ' + items[-1]


def tier_basis(f):
    """The basis of a field's tier under RFC §4.7 (rules.tier_problems has checked it)."""
    b = f.get('basis', {})
    if f['tier'] == 'MUST':
        if 'required_to_read' in b:
            return 'MUST, needed to read ' + series([link(x) for x in b['required_to_read']])
        return f"MUST, on {len(rules.instances(f['id'], attacks))} documented instances"
    if f['tier'] == 'SHOULD':
        return f"SHOULD, modality: {f['modality']}" if 'modality' in f else 'SHOULD, provider-gated'
    return 'MAY, ' + series([MAY_REASON[r] for r in b['may']])


MAY_REASON = {'qa': 'dominant value Q or A', 'thin': 'fewer than two documented instances',
              'research': 'research-grade signal', 'redundant': 'redundant with MUST fields'}


def ad_field_row(f):
    name = f"**{f['name']}**" + ''.join(f' **[{t}]**' for t in f.get('tags', []))
    tier = f['tier'] + (' ' + f['tier_mark'] if 'tier_mark' in f else '')
    ev = ','.join(f'`{a}`' if g == 'instance' else f'*`{a}`*' for a, g in grounds[f['id']])
    return row([name, tier, f['role'], records(f), emitted(f), ev])


def capture_entry(f):
    name = (f"**{f['name']}** {f['name_note']}." if 'name_note' in f else f"**{f['name']}.**")
    tier = f'*Tier:* {tier_basis(f)}.'
    if 'rationale' in f:
        tier += ' ' + f['rationale']
    elif 'rationale_see' in f:
        tier += f" See {link(f['rationale_see'])}."
    if read_by[f['id']]:
        tier += ' *Read by:* ' + series([plink(p) for p in read_by[f['id']]]) + '.'
    return f'<a id="{anchor(f["id"])}"></a>{name} {f["capture"]}\n\n{tier}'


def ad_step(st):
    out = list(layout['ad_field_header']) + [ad_field_row(fields[i]) for i in st['fields']]
    out += ['', '**Field entries.**']
    for i in st['fields']:
        out += ['', capture_entry(fields[i])]
    return out


def rfc_field_row(f):
    link = f"[{f['name']}]({AD}#{anchor(f['id'])})"
    return row([link, f['tier'], records(f), emitted(f)])


def catches(p):
    order = lambda ids: sorted(ids, key=corpus_order.index)
    out = ticks(order(p['catches']))
    if p.get('catches_analogical'):
        out += ('; ' if out else '') + 'analogically ' + ticks(order(p['catches_analogical']))
    return out or 'none in the corpus'


def pattern_entry(p):
    lead = 'Fires on any of:' if p.get('match') == 'any' else 'Fires when:'
    out = [f'<a id="{panchor(p["id"])}"></a>**{p["name"]}.** {p["indicates"]}. '
           f'Minimum tier {min_tier(p)}. {lead}', '']
    out += [f'{i}. {c}' for i, c in enumerate(p['conditions'], 1)]
    meta = []
    if p['join']:
        meta.append('*Joins on* ' + series([link(f) for f in p['join']]) + '.')
    reads = [f for f in p['requires'] if f not in p['join']]
    if reads:
        meta.append('*Reads* ' + series([link(f) for f in reads]) + '.')
    if p['enriches']:
        meta.append('*Enriched by* ' + series([link(f) for f in p['enriches']]) + '.')
    if p.get('baseline'):
        meta.append('*Baseline:* ' + p['baseline'])
    meta.append('*Catches* ' + catches(p) + '.')
    if p.get('motivation'):
        meta.append('*Motivation:* ' + prose(p['motivation']))
    return out + ['', ' '.join(meta)]


def ad_patterns():
    out = ['| Pattern | Stage | Minimum tier | Catches |', '| :------------------------------- | :---------- | :---- | :-------------------- |']
    out += [row([plink(p['id']), p['stage'], min_tier(p), catches(p)]) for p in patterns]
    for n, st in enumerate(layout['pattern_stages'], 1):
        out += ['', f"### 2.{n} {st['title']}"]
        for p in patterns:
            if p['stage'] == st['stage']:
                out += [''] + pattern_entry(p)
    out += ['', f'### 2.{len(STAGES) + 1} Coverage', '',
            'Every attack in §3, with the patterns that catch it; an attack no pattern catches records why.', '',
            '| Attack | Caught by | Analogically |', '| :---------- | :------------------------------- | :-------------------- |']
    for aid in corpus_order:
        inst = [plink(p['id']) for p in patterns if aid in p['catches']]
        anal = [plink(p['id']) for p in patterns if aid in p.get('catches_analogical', [])]
        a = attacks[aid]
        first = ', '.join(inst) if inst else '*None.* ' + prose(a['no_pattern'])
        out.append(row([f"`{aid}` {a['name']}", first, ', '.join(anal)]))
    return out


def detecting(a):
    out = []
    for e in a.get('fields', []):
        fid, g, note = edge(e)
        text = fields[fid]['name'] + (f' ({note})' if note else '')
        out.append(text if g == 'instance' else f'*{text}*')
    return ', '.join(out)


def inventory_row(section, a):
    aid = f"**{a['id']}**"
    if section == '3.2':
        label = f"{a['label']} [[{a['ref']}]](#real-world-attack-primary-sources)"
        return row([aid, label, a['what_happened'], detecting(a), a['components_text']])
    if section == '3.3':
        return row([aid, a['label'], a['what_happened'], a['taxonomy_text'],
                    detecting(a), a['components_text']])
    return row([aid, a['label'], a['what_happened'], detecting(a), a['components_text']])


def atlas_row(a):
    return row([f"**{a['id']}** {a['name']}", a['atlas_text'], a['atlas_notes']])


def table(header, rows):
    return list(header) + rows


# ---------------------------------------------------------------- splicing
def splice(lines, heading_re, stop_re, render):
    """Replace the first table under each matching heading with render(match)."""
    found = list(find_tables(lines, heading_re, stop_re))
    for m, start, end in reversed(found):
        lines[start:end] = render(m)
    return len(found)


def markers(text, key, body):
    """Replace the region between the GENERATED markers for `key` with `body` lines."""
    begin, end = f'<!-- BEGIN GENERATED: {key} -->', f'<!-- END GENERATED: {key} -->'
    assert text.count(begin) == 1 and text.count(end) == 1, key
    pre, rest = text.split(begin, 1)
    _, post = rest.split(end, 1)
    return pre + begin + '\n' + '\n'.join(body) + '\n' + end + post


def build_ad(text):
    for st in steps:
        text = markers(text, f"fields {st['number']}", ad_step(st))
    text = markers(text, 'patterns', ad_patterns())
    lines = text.split('\n')
    inv = {t['number']: t for t in layout['ad_inventory_tables']}
    n = splice(lines, r'^### (3\.[234]) ', r'^### 3\.5',
               lambda m: table(inv[m[1]]['header'],
                               [inventory_row(m[1], attacks[i]) for i in inv[m[1]]['attacks']]))
    assert n == len(inv), n
    at = layout['ad_atlas_table']
    n = splice(lines, r'^### 3\.6 ', r'^## 4\.',
               lambda m: table(at['header'], [atlas_row(attacks[i]) for i in at['attacks']]))
    assert n == 1, n
    return attack_references('\n'.join(lines))


def attack_references(text):
    """The AD list of attack primary sources, in reference-number order."""
    head = '### Real-world attack primary sources\n'
    before, rest = text.split(head, 1)
    _, after = rest.split('\n### ', 1)
    refs = sorted((a['ref'], a['id'], a['reference']) for a in attacks.values() if 'reference' in a)
    out, prev = [layout['ad_attack_references_intro'], ''], None
    for n, aid, ref in refs:
        if prev is not None and n != prev + 1:
            out += ['', '<!-- list break: reference numbers are not contiguous -->', '']
        out.append(f'{n}. **[{aid}]** {ref}')
        prev = n
    return before + head + '\n' + '\n'.join(out) + '\n\n### ' + after


TOTALS = [  # (pattern, rendering): the RFC's hand-written sentences that state the tier totals
    (r'\d+ in all: \d+ MUST, \d+ SHOULD and \d+ MAY',
     lambda n: f"{sum(n.values())} in all: {n['MUST']} MUST, {n['SHOULD']} SHOULD and {n['MAY']} MAY"),
    (r'The catalogue contains \d+ MUST fields', lambda n: f"The catalogue contains {n['MUST']} MUST fields"),
]


def build_rfc(text):
    n = {t: sum(f['tier'] == t for f in fields.values()) for t in rules.TIERS}
    for pat, render in TOTALS:
        assert len(re.findall(pat, text)) == 1, pat
        text = re.sub(pat, render(n), text)
    lines = text.split('\n')
    st = {t['number']: t for t in steps}
    n = splice(lines, r'^### (6\.\d+) ', r'^## 7\.',
               lambda m: table(st[m[1]]['rfc_header'], [rfc_field_row(fields[i]) for i in st[m[1]]['fields']]))
    assert n == len(st), n
    return '\n'.join(lines)


# ---------------------------------------------------------------- main
def main():
    # argparse rejects unknown options and handles -h, so a mistyped flag exits before anything is written.
    ap = argparse.ArgumentParser(allow_abbrev=False, description='Regenerate the data-driven regions of the RFC and AD.')
    ap.add_argument('--check', action='store_true', help='exit 1 if a document differs from data/; write nothing')
    check = ap.parse_args().check
    # Refuse to render data that breaks the rules; tools/validate.py reports the same problems.
    problems = (rules.tier_problems(fields, attacks) + rules.layout_problems(fields, layout)
                + rules.attack_problems(fields, attacks) + rules.pattern_problems(fields, attacks, patterns))
    if problems:
        sys.exit('data/ breaks the rules (tools/rules.py):\n  ' + '\n  '.join(problems))
    drift = False
    for name, build in ((AD, build_ad), (RFC, build_rfc)):
        path = os.path.join(DIR, name)
        with open(path, encoding='utf-8') as f:
            old = f.read()
        new = build(old)
        if new == old:
            print(f'{name}: up to date')
        elif check:
            drift = True
            print(f'{name}: differs from data/')
            sys.stdout.writelines(difflib.unified_diff(
                old.splitlines(True), new.splitlines(True), name, name + ' (from data/)', n=0))
        else:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(new)
            print(f'{name}: rewritten')
    sys.exit(1 if drift else 0)


if __name__ == '__main__':
    main()
