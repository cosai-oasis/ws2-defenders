#!/usr/bin/env python3
"""Phase 1: extract the tables of the Attack Detection Addendum (AD) and the
RFC field catalogue (§6) into data/.

One-shot. Values are copied verbatim: attack cells that name fields are kept
as text (``*_text``) until they are reconciled to field IDs. Run build.py
--check afterwards; it must reproduce both documents byte for byte.

Usage: python3 tools/extract.py [telemetry-dir]
"""
import os
import re
import sys

import yaml

from mdtables import cells, find_tables, gh_anchor

DIR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..')
RFC, AD = 'CoSAI-AI-Telemetry-RFC.md', 'Telemetry-Attack-Detection-Addendum.md'
DATA = os.path.join(DIR, 'data')

ATTACK = r'(?:TA|IR|AOC)-\d+'


def read(name):
    with open(os.path.join(DIR, name), encoding='utf-8') as f:
        return f.read().split('\n')


def slug(name):
    return re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')


def tables_under(lines, heading_re, stop_re):
    for m, start, end in find_tables(lines, heading_re, stop_re):
        yield m, lines[start], lines[start + 1], lines[start + 2:end]


def evidence(cell):
    ids = re.findall(r'`(' + ATTACK + r')`', cell)
    assert cell.strip() == ','.join(f'`{a}`' for a in ids), cell
    return ids


# ---------------------------------------------------------------- AD §1 fields
ad = read(AD)
fields, clusters = {}, []
NAME = re.compile(r'^\*\*(?P<name>.+?)\*\*(?P<tags>(?: \*\*\[[A-Z]+\]\*\*)*)(?P<note> .*)?$')
for m, header, sep, rows in tables_under(ad, r'^### (1\.\d+) (.*)$', r'^## 2\.'):
    ids = []
    for r in rows:
        name_cell, tier_cell, capture, ev = cells(r)
        n = NAME.match(name_cell)
        assert n, name_cell
        tier, _, mark = tier_cell.partition(' ')
        fid = slug(n['name'])
        f = {'id': fid, 'name': n['name']}
        tags = re.findall(r'\[([A-Z]+)\]', n['tags'])
        if tags:
            f['tags'] = tags
        if n['note']:
            f['name_note'] = n['note'].strip()
        f['tier'] = tier
        if mark:
            f['tier_mark'] = mark
        f['capture'] = capture
        if ev.startswith(' '):          # one row carries a stray leading space
            f['evidence_pad'] = True
        f['evidence'] = evidence(ev)
        assert fid not in fields, fid
        fields[fid] = f
        ids.append(fid)
    clusters.append({'number': m[1], 'title': m[2], 'header': [header, sep], 'fields': ids})

# ---------------------------------------------------------------- RFC §6
rfc = read(RFC)
by_name = {f['name']: f for f in fields.values()}
steps = []
LINK = re.compile(r'^\[(?P<name>.+)\]\(Telemetry-Attack-Detection-Addendum\.md#(?P<anchor>[^)]+)\)$')
for m, header, sep, rows in tables_under(rfc, r'^### (6\.\d+) (.*)$', r'^## 7\.'):
    ids = []
    for r in rows:
        link, tier, records, emitted = cells(r)
        lk = LINK.match(link)
        f = by_name[lk['name']]
        assert f['tier'] == tier, (f['name'], tier)
        f['records'] = records
        comps = emitted.split(', ')
        if all(re.fullmatch(r'`component[A-Za-z]+`', c) for c in comps):
            f['emitted_by'] = [c.strip('`') for c in comps]
        else:                            # emitters outside the Risk Map: "every hop", "enforcement points"
            assert '`' not in emitted, emitted
            f['emitted_by_text'] = emitted
        home = next(c for c in clusters if f['id'] in c['fields'])
        assert lk['anchor'] == gh_anchor(f"{home['number']} {home['title']}"), lk['anchor']
        ids.append(f['id'])
    steps.append({'number': m[1], 'title': m[2], 'header': [header, sep], 'fields': ids})
assert sum(len(s['fields']) for s in steps) == len(fields) == 98

# ---------------------------------------------------------------- AD §2 patterns
patterns = []
for m, header, sep, rows in tables_under(ad, r'^## (2)\. (Correlation Patterns)$', r'^## 3\.'):
    pattern_header = [header, sep]
    for n, r in enumerate(rows, 1):
        pat, indicates, fl, ev = cells(r)
        patterns.append({'id': f'CP-{n:02d}', 'pattern': pat, 'indicates': indicates,
                         'fields_text': fl, 'evidence': evidence(ev)})

# ---------------------------------------------------------------- AD §3 attacks
attacks, inventory = {}, []
ROW_ID = re.compile(r'^\*\*(' + ATTACK + r')\*\*$')
REF = re.compile(r'^(?P<label>.*) \[\[(?P<n>\d+)\]\]\(#real-world-attack-primary-sources\)$')
for m, header, sep, rows in tables_under(ad, r'^### (3\.[234]) (.*)$', r'^### 3\.5'):
    ids = []
    for r in rows:
        c = cells(r)
        aid = ROW_ID.match(c[0])[1]
        a = {'id': aid}
        if m[1] == '3.2':
            ref = REF.match(c[1])
            a.update(label=ref['label'], ref=int(ref['n']), what_happened=c[2],
                     detecting_fields_text=c[3], components_text=c[4])
        elif m[1] == '3.3':
            a.update(label=c[1], what_happened=c[2], taxonomy_text=c[3],
                     detecting_fields_text=c[4], components_text=c[5])
        else:
            a.update(label=c[1], what_happened=c[2], detecting_fields_text=c[3],
                     components_text=c[4])
        attacks[aid] = a
        ids.append(aid)
    inventory.append({'number': m[1], 'title': m[2], 'header': [header, sep], 'attacks': ids})
assert len(attacks) == 49

for m, header, sep, rows in tables_under(ad, r'^### (3\.6) (.*)$', r'^### 3\.7'):
    atlas_table = {'number': m[1], 'title': m[2], 'header': [header, sep], 'attacks': []}
    for r in rows:
        label, techniques, notes = cells(r)
        lm = re.match(r'^\*\*(' + ATTACK + r')\*\* (.+)$', label)
        a = attacks[lm[1]]
        a['name'] = lm[2]
        a['atlas_text'] = techniques
        a['atlas_notes'] = notes
        atlas_table['attacks'].append(lm[1])
assert len(atlas_table['attacks']) == 49

# Attack-source reference entries from AD's reference list.
text = '\n'.join(ad)
refs_block = text.split('### Real-world attack primary sources\n', 1)[1].split('\n### ', 1)[0]
for line in refs_block.split('\n'):
    rm = re.match(r'^(\d+)\. \*\*\[(' + ATTACK + r')\]\*\* (.*)$', line)
    if rm:
        a = attacks[rm[2]]
        assert a.get('ref', int(rm[1])) == int(rm[1]), (rm[2], rm[1])
        a['ref'] = int(rm[1])
        a['reference'] = rm[3]
refs_intro = refs_block.strip('\n').split('\n\n')[0]

# ---------------------------------------------------------------- write
class Dumper(yaml.SafeDumper):
    pass


def _list(d, v):
    flow = all(isinstance(x, str) and len(x) < 40 for x in v) and v
    return d.represent_sequence('tag:yaml.org,2002:seq', v, flow_style=bool(flow))


Dumper.add_representer(list, _list)


def dump(obj, path, comment):
    with open(os.path.join(DATA, path), 'w', encoding='utf-8') as f:
        f.write(comment)
        yaml.dump(obj, f, Dumper=Dumper, sort_keys=False, allow_unicode=True, width=10**6)


ORDER = ['id', 'name', 'name_note', 'tags', 'tier', 'tier_mark', 'records', 'emitted_by',
         'emitted_by_text', 'capture', 'evidence_pad', 'evidence']
dump([{k: f[k] for k in ORDER if k in f} for f in fields.values()], 'fields.yaml',
     '# Telemetry fields. Extracted verbatim from AD §1 and RFC §6 (phase 1).\n'
     '# evidence: grounding attacks as cited in AD; to be derived from attacks/ in phase 2.\n')
dump(patterns, 'patterns.yaml',
     '# AD §2 correlation patterns. Extracted verbatim (phase 1); fields_text is unreconciled.\n')
A_ORDER = ['id', 'name', 'label', 'ref', 'what_happened', 'taxonomy_text', 'detecting_fields_text',
           'components_text', 'atlas_text', 'atlas_notes', 'reference']
for a in attacks.values():
    dump({k: a[k] for k in A_ORDER if k in a}, f"attacks/{a['id']}.yaml",
         f"# {a['id']}. Extracted verbatim from AD §3 (phase 1); *_text cells are unreconciled.\n")
dump({'ad_field_tables': clusters, 'rfc_field_tables': steps,
      'ad_pattern_table': {'header': pattern_header},
      'ad_inventory_tables': inventory, 'ad_atlas_table': atlas_table,
      'ad_attack_references_intro': refs_intro},
     'sections.yaml',
     '# Table layout and row order for the generated regions (phase 1: mirrors the current documents).\n')
print(f'{len(fields)} fields, {len(patterns)} patterns, {len(attacks)} attacks')
