#!/usr/bin/env python3
"""Apply decided candidates from data/candidates/ to data/.

Only accepted candidates are applied; each is stamped `applied: <date>` so a
second run changes nothing. Undecided and deferred candidates are skipped and
listed.

  attack   writes data/attacks/<ID>.yaml and appends the attack to the AD
           inventory and ATLAS tables
  edge     sets the attack's `fields:` entry with its grounding class
           (instance or analogical); reject removes it
  alias    already reflected in `fields:` by reconcile.py; stamped only
  basis    sets `basis:` on the field
  capture  appends the accepted clause to the field's capture definition

After the edges are applied, a field's evidence is derived from the attacks
that name it (build.py), so `evidence:` is removed from fields.yaml.

Usage: python3 tools/apply.py [--dry-run]
"""
import datetime
import glob
import os
import sys

from yamlio import dump, load

DATA = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data'))
TODAY = datetime.date.today().isoformat()
HEADER = ('# Curation registry batch. Edit status only through tools/curate.py, or by hand\n'
          '# keeping decided_by and decided_on filled in. See curate.py for the schema.\n')
ATTACK_HEADER = '# {id}. Data for AD §3; `fields:` lists its edges (grounding instance unless marked).\n'

# Values an intake record does not carry but the AD tables need. Kept here so the
# accepted records stay as decided; move them into intake.py's template later.
INTAKE_EXTRA = {
    'TA-29': {'components_text': 'Tools, ToolServer, AgentOutputHandling',
              'atlas_text': '`AML.T0109` AI Supply Chain Rug Pull; `AML.T0110.000` AI Agent Tool Poisoning: '
                            'Definition and Instructions; `AML.T0086` Exfiltration via AI Agent Tool Invocation',
              'atlas_notes': 'Definition changed after approval under an unchanged name'},
    'TA-30': {'components_text': 'Memory',
              'atlas_text': '`AML.T0029` Denial of AI Service'},
}


def attack_path(aid):
    return os.path.join(DATA, 'attacks', f'{aid}.yaml')


def entry_field(e):
    return e if isinstance(e, str) else e['field']


def set_edge(attack, fid, grounding, note=None):
    """Set or remove one edge on an attack, keeping existing order and notes."""
    entries = attack.setdefault('fields', [])
    idx = next((i for i, e in enumerate(entries) if entry_field(e) == fid), None)
    if grounding == 'reject':
        if idx is not None:
            entries.pop(idx)
        return
    old = entries[idx] if idx is not None else fid
    note = note or (old.get('note') if isinstance(old, dict) else None)
    new = {'field': fid}
    if note:
        new['note'] = note
    if grounding != 'instance':
        new['grounding'] = grounding
    new = fid if list(new) == ['field'] else new
    if idx is None:
        entries.append(new)
    else:
        entries[idx] = new


def main():
    dry = '--dry-run' in sys.argv
    fields_path = os.path.join(DATA, 'fields.yaml')
    fields = load(fields_path)
    fmap = {f['id']: f for f in fields}
    layout_path = os.path.join(DATA, 'sections.yaml')
    layout = load(layout_path)
    attacks = {os.path.basename(p)[:-5]: load(p) for p in glob.glob(os.path.join(DATA, 'attacks', '*.yaml'))}

    batches = [(p, load(p) or []) for p in sorted(glob.glob(os.path.join(DATA, 'candidates', '*.yaml')))]
    all_c = {c['id']: c for _, cs in batches for c in cs}
    skipped, applied = [], 0

    def ready(c):
        if c['status'] != 'accepted' or c.get('applied'):
            if c['status'] != 'accepted':
                skipped.append(c)
            return False
        req = c.get('requires')
        return not req or all_c.get(req, {}).get('status') == 'accepted'

    # Field-row evidence that was cited but not yet curated would be lost when
    # evidence becomes derived; refuse rather than drop it silently.
    edges = {(c['subject']['attack'], c['subject']['field']) for c in all_c.values() if c['type'] == 'edge'}
    uncurated = [(a, f['id']) for f in fields for a in f.get('evidence', []) if (a, f['id']) not in edges]
    if uncurated:
        sys.exit(f'{len(uncurated)} cited edges have no candidate, e.g. {uncurated[:3]}; run reconcile.py propose')

    order = ('attack', 'edge', 'alias', 'basis', 'capture')
    for kind in order:
        for _, cs in batches:
            for c in cs:
                if c['type'] != kind or not ready(c):
                    continue
                s = c['subject']
                if kind == 'attack':
                    rec = dict(c['proposal']['record'])
                    rec.update(INTAKE_EXTRA.get(rec['id'], {}))
                    rec.setdefault('fields', [])
                    attacks[rec['id']] = rec
                    inv = next(t for t in layout['ad_inventory_tables'] if t['number'] == '3.2')
                    if rec['id'] not in inv['attacks']:
                        inv['attacks'].append(rec['id'])
                    at = layout['ad_atlas_table']['attacks']
                    if rec['id'] not in at:
                        last_ta = max(i for i, a in enumerate(at) if a.startswith('TA-'))
                        at.insert(last_ta + 1, rec['id'])
                elif kind == 'edge':
                    g = c.get('decision', {}).get('grounding', c['proposal']['grounding'])
                    set_edge(attacks[s['attack']], s['field'], g)
                elif kind == 'basis':
                    fmap[s['field']]['basis'] = c['proposal']['basis']
                elif kind == 'capture':
                    f = fmap[s['field']]
                    f['capture'] = f['capture'].rstrip() + ' ' + c['proposal']['capture_addition']
                c['applied'] = TODAY
                applied += 1

    for f in fields:
        f.pop('evidence', None)
        f.pop('evidence_pad', None)
    for a in attacks.values():
        a.pop('detecting_fields_text', None)     # rendered from `fields:` from now on

    waiting = [c['id'] for c in all_c.values() if c['status'] == 'accepted' and not c.get('applied')
               and c['type'] not in order]
    if waiting:
        print('accepted, no apply rule yet (phase 5):', ', '.join(waiting))
    print(f'applied {applied}; skipped {len(skipped)} undecided or deferred:',
          ', '.join(c['id'] for c in skipped) or 'none')
    if dry:
        return
    for p, cs in batches:
        dump(cs, p, HEADER)
    dump(fields, fields_path, '# Telemetry fields. Evidence is derived from attacks/ (tools/build.py).\n')
    dump(layout, layout_path, '# Table layout and row order for the generated regions.\n')
    for aid, a in attacks.items():
        dump(a, attack_path(aid), ATTACK_HEADER.format(id=aid))


if __name__ == '__main__':
    main()
