#!/usr/bin/env python3
"""Regenerate the data-driven regions of the RFC and the Attack Detection
Addendum (AD) from data/.

Regions: AD §1 field tables, §2 pattern table, §3.2 to §3.4 inventory tables,
§3.6 ATLAS table and the attack-source reference list; RFC §6 field tables.
Everything else in both documents is hand-written and left untouched.

Usage:
  python3 tools/build.py           rewrite the documents in place
  python3 tools/build.py --check   exit 1 if a document differs from the data
"""
import difflib
import glob
import os
import sys

import yaml

from mdtables import find_tables, gh_anchor, row

DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
DATA = os.path.join(DIR, 'data')
RFC, AD = 'CoSAI-AI-Telemetry-RFC.md', 'Telemetry-Attack-Detection-Addendum.md'


def load(path):
    with open(os.path.join(DATA, path), encoding='utf-8') as f:
        return yaml.safe_load(f)


fields = {f['id']: f for f in load('fields.yaml')}
patterns = load('patterns.yaml')
attacks = {a['id']: a for a in map(load, (os.path.relpath(p, DATA)
                                           for p in glob.glob(os.path.join(DATA, 'attacks', '*.yaml'))))}
layout = load('sections.yaml')

# The AD subsection that defines each field: the target of every RFC link.
home = {fid: c for c in layout['ad_field_tables'] for fid in c['fields']}

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


def ticks(ids):
    return ','.join(f'`{i}`' for i in ids)


# ---------------------------------------------------------------- renderers
def ad_field_row(f):
    name = f"**{f['name']}**" + ''.join(f' **[{t}]**' for t in f.get('tags', []))
    if 'name_note' in f:
        name += ' ' + f['name_note']
    tier = f['tier'] + (' ' + f['tier_mark'] if 'tier_mark' in f else '')
    ev = ','.join(f'`{a}`' if g == 'instance' else f'*`{a}`*' for a, g in grounds[f['id']])
    return row([name, tier, f['capture'], ev])


def rfc_field_row(f):
    c = home[f['id']]
    link = f"[{f['name']}]({AD}#{gh_anchor(c['number'] + ' ' + c['title'])})"
    emitted = (', '.join(f'`{e}`' for e in f['emitted_by']) if 'emitted_by' in f
               else f['emitted_by_text'])
    return row([link, f['tier'], f['records'], emitted])


def pattern_row(p):
    return row([p['pattern'], p['indicates'], p['fields_text'], ticks(p['evidence'])])


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


def build_ad(text):
    lines = text.split('\n')
    by_num = lambda key: {t['number']: t for t in layout[key]}
    ft, inv = by_num('ad_field_tables'), by_num('ad_inventory_tables')

    n = splice(lines, r'^### (1\.\d+) ', r'^## 2\.',
               lambda m: table(ft[m[1]]['header'], [ad_field_row(fields[i]) for i in ft[m[1]]['fields']]))
    assert n == len(ft), n
    n = splice(lines, r'^## 2\. Correlation Patterns$', r'^## 3\.',
               lambda m: table(layout['ad_pattern_table']['header'], [pattern_row(p) for p in patterns]))
    assert n == 1, n
    n = splice(lines, r'^### (3\.[234]) ', r'^### 3\.5',
               lambda m: table(inv[m[1]]['header'],
                               [inventory_row(m[1], attacks[i]) for i in inv[m[1]]['attacks']]))
    assert n == len(inv), n
    at = layout['ad_atlas_table']
    n = splice(lines, r'^### 3\.6 ', r'^### 3\.7',
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


def build_rfc(text):
    lines = text.split('\n')
    st = {t['number']: t for t in layout['rfc_field_tables']}
    n = splice(lines, r'^### (6\.\d+) ', r'^## 7\.',
               lambda m: table(st[m[1]]['header'], [rfc_field_row(fields[i]) for i in st[m[1]]['fields']]))
    assert n == len(st), n
    return '\n'.join(lines)


# ---------------------------------------------------------------- main
def main():
    check = '--check' in sys.argv
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
