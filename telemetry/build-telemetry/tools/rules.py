"""The rules the data must satisfy, shared by build.py (which refuses to render
data that breaks them) and validate.py (which reports every breach).

Each function returns a list of problems as strings; an empty list passes.
"""
import glob
import os
import re

from yamlio import load

DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))   # the documents: telemetry/
DATA = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data'))   # build-telemetry/data/
TIERS = ('MUST', 'SHOULD', 'MAY')
RANK = {t: i for i, t in enumerate(TIERS)}
ROLES = {'identifier', 'content', 'outcome', 'label', 'descriptor', 'measure', 'provenance'}
RECORDS = {'event', 'state', 'aggregate'}
ORIGINS = {'observed', 'declared', 'asserted', 'derived'}
MAY_REASONS = {'qa', 'thin', 'research', 'redundant'}
STAGES = ('entry', 'decision', 'action', 'persistence', 'egress', 'plane')
SLUG = re.compile(r'[a-z0-9]+(?:_[a-z0-9]+)*')


def load_data():
    """fields, attacks, patterns, layout, as the tools read them."""
    fields = {f['id']: f for f in load(os.path.join(DATA, 'fields.yaml'))}
    attacks = {a['id']: a for a in (load(p) for p in glob.glob(os.path.join(DATA, 'attacks', '*.yaml')))}
    patterns = load(os.path.join(DATA, 'patterns.yaml'))
    layout = load(os.path.join(DATA, 'sections.yaml'))
    return fields, attacks, patterns, layout


def edge(e):
    """(field id, grounding, note) for one `fields:` entry of an attack."""
    if isinstance(e, str):
        return e, 'instance', None
    return e['field'], e.get('grounding', 'instance'), e.get('note')


def edges(attack):
    """{field id: grounding} for one attack."""
    return {edge(e)[0]: edge(e)[1] for e in attack.get('fields', [])}


def instances(fid, attacks):
    """Independent attacks with an instance edge to the field: the evidence the MUST test
    counts. An attack recorded `same_incident_as` another counted one adds nothing."""
    found = sorted(a for a, rec in attacks.items() if edges(rec).get(fid) == 'instance')
    return [a for a in found if not set(attacks[a].get('same_incident_as', [])) & set(found)]


def tier_problems(fields, attacks):
    """RFC §4.7, as recorded: every tier against its basis."""
    out = []
    read_by_must = {x for f in fields.values() if f['tier'] == 'MUST'
                    for x in f.get('basis', {}).get('required_to_read', [])}
    for fid, f in fields.items():
        b, inst = f.get('basis', {}), instances(fid, attacks)
        if f['tier'] not in TIERS:
            out.append(f'{fid}: tier {f["tier"]!r}')
            continue
        for x in b.get('required_to_read', []):
            if x not in fields or fields[x]['tier'] != 'MUST':
                out.append(f'{fid}: required_to_read names {x}, which is not a MUST field')
        if not set(b.get('evidence', [])) <= set(inst):
            out.append(f'{fid}: basis evidence {sorted(set(b["evidence"]) - set(inst))} are not instance edges')
        if f['tier'] == 'MUST':
            if 'required_to_read' not in b and len(inst) < 2:
                out.append(f'{fid}: MUST with {len(inst)} instance(s) and no dependency')
        elif f['tier'] == 'SHOULD':
            if 'modality' not in f and not f.get('provider_gated'):
                out.append(f'{fid}: SHOULD with no modality and not provider-gated')
        else:
            may = b.get('may', [])
            if not may:
                out.append(f'{fid}: MAY with no recorded MAY basis')
            if set(may) - MAY_REASONS:
                out.append(f'{fid}: unknown MAY reason {sorted(set(may) - MAY_REASONS)}')
            if 'thin' in may and (len(inst) >= 2 or fid in read_by_must):
                out.append(f'{fid}: MAY on thin evidence, but it has {len(inst)} instances'
                           + (' and a MUST field depends on it' if fid in read_by_must else ''))
            if len(inst) >= 2 and not set(may) - {'thin'}:
                out.append(f'{fid}: MAY with {len(inst)} instances needs a reason other than thin')
        for facet, allowed in (('role', ROLES), ('record', RECORDS), ('origin', ORIGINS)):
            if f.get(facet) not in allowed:
                out.append(f'{fid}: {facet} {f.get(facet)!r}')
        if 'rationale_see' in f and f['rationale_see'] not in fields:
            out.append(f'{fid}: rationale_see names unknown field {f["rationale_see"]}')
    return out


def layout_problems(fields, layout):
    """Every field sits in exactly one RFC step, MUST before SHOULD before MAY."""
    out, seen = [], []
    for st in layout['field_steps']:
        seen += st['fields']
        tiers = [RANK[fields[f]['tier']] for f in st['fields'] if f in fields]
        if tiers != sorted(tiers):
            out.append(f"step {st['number']}: fields not ordered MUST, SHOULD, MAY")
    out += [f'{f}: in no step' for f in fields if f not in seen]
    out += [f'{f}: in more than one step' for f in set(seen) if seen.count(f) > 1]
    out += [f'{f}: in a step but not a field' for f in set(seen) - set(fields)]
    return out


def attack_problems(fields, attacks):
    out, refs = [], {}
    for aid, a in attacks.items():
        if not re.fullmatch(r'(TA|IR|AOC)-\d+', aid):
            out.append(f'{aid}: malformed attack ID')
        for fid, g, _ in map(edge, a.get('fields', [])):
            if fid not in fields:
                out.append(f'{aid}: edge to unknown field {fid}')
            if g not in ('instance', 'analogical'):
                out.append(f'{aid}: edge to {fid} has grounding {g!r}')
        if 'ref' in a:
            if a['ref'] in refs:
                out.append(f'{aid}: reference {a["ref"]} also used by {refs[a["ref"]]}')
            refs[a['ref']] = aid
    return out


def pattern_problems(fields, attacks, patterns):
    """Pattern records, and each catch against the attack's edges (AD §2)."""
    out, ids = [], [p.get('id') for p in patterns]
    out += [f'{i}: duplicate pattern ID' for i in set(ids) if ids.count(i) > 1]
    for p in patterns:
        pid = p.get('id')
        if not pid or not SLUG.fullmatch(pid):
            out.append(f'{pid}: pattern ID is not a slug')
            continue
        if p.get('stage') not in STAGES:
            out.append(f'{pid}: stage {p.get("stage")!r}')
        if p.get('match', 'all') not in ('all', 'any'):
            out.append(f'{pid}: match {p.get("match")!r}')
        if not p.get('conditions') or not p.get('requires'):
            out.append(f'{pid}: needs conditions and required fields')
        unknown = [f for f in p.get('join', []) + p.get('requires', []) + p.get('enriches', []) if f not in fields]
        if unknown:
            out.append(f'{pid}: unknown fields {unknown}')
            continue
        checked = set(p['requires']) | {f for f in p['join'] if fields[f]['role'] != 'identifier'}
        for a in p.get('catches', []):
            if a not in attacks:
                out.append(f'{pid}: catches unknown attack {a}')
                continue
            bad = sorted(f for f in checked if edges(attacks[a]).get(f) != 'instance')
            if bad:
                out.append(f'{pid}: catches {a}, which has no instance edge to {bad}')
        for a in p.get('catches_analogical', []):
            if a not in attacks:
                out.append(f'{pid}: analogically catches unknown attack {a}')
                continue
            bad = sorted(f for f in checked if f not in edges(attacks[a]))
            if bad:
                out.append(f'{pid}: analogically catches {a}, which has no edge to {bad}')
        if not p.get('catches') and not p.get('catches_analogical') and not p.get('motivation'):
            out.append(f'{pid}: catches nothing and records no motivation')
    caught = {a for p in patterns for a in p.get('catches', [])}
    for aid, a in attacks.items():
        if aid not in caught and not a.get('no_pattern'):
            out.append(f'{aid}: no pattern catches it as an instance and no reason is recorded')
        if aid in caught and a.get('no_pattern'):
            out.append(f'{aid}: records no_pattern, but a pattern catches it')
    return out


def candidate_problems(batches, known_types):
    """The registry: decided candidates are signed and dated; accepted ones are applied."""
    out = []
    ids = [c['id'] for _, cs in batches for c in cs]
    out += [f'{i}: duplicate candidate ID' for i in set(ids) if ids.count(i) > 1]
    for path, cs in batches:
        for c in cs:
            if c['status'] not in ('proposed', 'accepted', 'rejected', 'deferred'):
                out.append(f'{c["id"]}: status {c["status"]!r}')
            if c['status'] != 'proposed' and not (c.get('decided_by') and c.get('decided_on')):
                out.append(f'{c["id"]}: {c["status"]} but decided_by or decided_on is missing')
            if c['status'] == 'accepted' and not c.get('applied'):
                why = 'no apply rule for its type' if c['type'] not in known_types else 'run tools/apply.py'
                out.append(f'{c["id"]}: accepted but not applied ({why})')
    return out
