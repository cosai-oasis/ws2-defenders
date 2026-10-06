#!/usr/bin/env python3
"""Build risk-map-explorer.html: one self-contained page for exploring
Attacks -> Risks -> Controls -> Telemetry -> Detection patterns.

Reads data/ and the three documents, and the CoSAI Risk Map at the commits
pinned in data/sources.yaml from the validator's cache (~/.cache/cosai-telemetry;
run tools/validate.py once to fill it). Writes telemetry/risk-map-explorer.html
from tools/risk_map_explorer.template.html.

    python3 tools/build_explorer.py [-o PATH]
"""
import argparse
import datetime
import glob
import html
import json
import re
import subprocess
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
WS = HERE.parents[2]
DATA = HERE.parent / 'data'
CACHE = Path.home() / '.cache/cosai-telemetry'
DOCS = 'https://github.com/cosai-oasis/ws2-defenders/blob/edits/telemetry/'
AD = DOCS + 'Telemetry-Attack-Detection-Addendum.md'
RFC = DOCS + 'CoSAI-AI-Telemetry-RFC.md'

def load(p):
    with open(p) as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------- markdown

REFS = {}


def attr(s):
    return html.escape(s, quote=True)


def link(m):
    text, url = m[1], m[2]
    if url.startswith('#'):
        url = AD + url
    elif not re.match(r'https?://', url):
        url = DOCS + url
    return f'<a href="{url}" target="_blank" rel="noopener">{text}</a>'


def md(s):
    """Inline markdown subset used in the data: code, bold, italic, links, refs."""
    if s is None:
        return ''
    s = html.escape(str(s).strip(), quote=False)
    codes = []

    def keep(m):
        codes.append(m[1])
        return f'\x00{len(codes) - 1}\x00'
    s = re.sub(r'`([^`]+)`', keep, s)
    s = re.sub(r'&lt;(https?://.+?)&gt;',
               r'<a href="\1" target="_blank" rel="noopener">\1</a>', s)
    s = re.sub(r'\[\[(\d+)\]\]\([^)]*\)',
               lambda m: f'<span class="ref" title="{attr(strip(REFS.get(m[1], "")))}">[{m[1]}]</span>', s)
    s = re.sub(r'\[([^\]]+)\]\(([^)\s]+)\)', link, s)
    s = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', s)
    s = re.sub(r'(?<![\w*])\*(?![\s*])(.+?)(?<![\s*])\*(?![\w*])', r'<i>\1</i>', s)
    return re.sub(r'\x00(\d+)\x00', lambda m: f'<code>{codes[int(m[1])]}</code>', s)


def strip(s):
    """Plain text for tooltips."""
    s = re.sub(r'<(https?://[^>]+)>', r'\1', str(s))
    s = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', s)
    return re.sub(r'[*`]', '', s).strip()


# ---------------------------------------------------------------- Risk Map

def cache_dir(repo, commit):
    owner, name = repo.rstrip('/').split('/')[-2:]
    return CACHE / f'{owner}__{name}@{commit[:12]}' / 'risk-map/yaml'


def riskmap(src):
    rm = src['riskmap']
    pins = [(rm['repository'], rm['base'])] + [(l['repository'], l) for l in rm.get('layers', [])]
    risks, controls, components, cats = {}, {}, {}, {}
    seen_in = {}
    for repo, pin in pins:
        d = cache_dir(repo, pin['commit'])
        if not d.exists():
            raise SystemExit(f'missing {d}; run tools/validate.py once to fetch the pinned Risk Map')
        label = f"{repo.split('/')[-2]}:{pin['branch']}@{pin['commit'][:7]}"
        r, c, k = (load(d / f) for f in ('risks.yaml', 'controls.yaml', 'components.yaml'))
        for x in r['risks']:
            risks[x['id']] = x
        for x in c['controls']:
            controls[x['id']] = x
        for x in k['components']:
            components[x['id']] = x
        for x in c.get('categories', []):
            cats[x['id']] = x['title']
        seen_in[label] = {x['id'] for x in r['risks'] + c['controls']}
    labels = list(seen_in)
    # IDs the base has and a layer drops: retired or renamed by the layer.
    dropped = set()
    for lab in labels[1:]:
        dropped |= seen_in[labels[0]] - seen_in[lab]
    return risks, controls, components, cats, dropped, labels


def rm_text(paras, refs, titles):
    """Risk Map description: list of paragraphs, nested lists allowed, {{...}} tokens."""
    def tok(m):
        key = m[1]
        if key.startswith('ref:'):
            r = refs.get(key[4:])
            return f'[{r["title"]}]({r["url"]})' if r and r.get('url') else key[4:]
        return titles.get(key, key)
    out = []
    for p in paras or []:
        if isinstance(p, list):
            out.append('<ul>' + ''.join(f'<li>{md(re.sub(r"{{([^}]+)}}", tok, str(i)))}</li>' for i in p) + '</ul>')
        else:
            out.append(f'<p>{md(re.sub(r"{{([^}]+)}}", tok, str(p)))}</p>')
    return ''.join(out)


def humanize(cat, prefix):
    words = re.sub(r'(?<!^)(?=[A-Z])', ' ', cat[len(prefix):]).split()
    return ' '.join([words[0]] + [w.lower() for w in words[1:]]).replace(' and ', ' and ')


# ---------------------------------------------------------------- build

def build():
    src = load(DATA / 'sources.yaml')
    sections = load(DATA / 'sections.yaml')
    fields = load(DATA / 'fields.yaml')
    patterns = load(DATA / 'patterns.yaml')
    mapping = load(DATA / 'mapping.yaml')
    attacks = {d['id']: d for d in (load(p) for p in sorted(glob.glob(str(DATA / 'attacks/*.yaml'))))}

    ad_text = (WS / 'telemetry/Telemetry-Attack-Detection-Addendum.md').read_text()
    refs_part = ad_text.split('\n## References', 1)[-1]
    for m in re.finditer(r'^(\d+)\. (.+)$', refs_part, re.M):
        REFS.setdefault(m[1], m[2])

    risks, controls, components, ccats, dropped, rm_labels = riskmap(src)
    titles = {k: v['title'] for d in (risks, controls, components) for k, v in d.items()}

    nodes, groups = {}, {t: [] for t in 'ARCFP'}
    edges = {k: [] for k in ('AR', 'RC', 'CF', 'FP', 'AF', 'PA')}

    def group(t, gid, title, items):
        groups[t].append({'id': gid, 'title': title, 'items': items})

    # Attacks
    titles_a = {'3.2': 'Real-world attack vectors', '3.3': 'CoSAI WS2 incident response case studies',
                '3.4': 'Agents of Chaos red-team case studies'}
    for tab in sections['ad_inventory_tables']:
        gid = 'gA' + tab['number']
        group('A', gid, titles_a.get(tab['number'], tab['title']), ['A:' + a for a in tab['attacks']])
        for aid in tab['attacks']:
            a = attacks[aid]
            if a.get('reference'):
                source = md(a['reference'])
            elif a.get('cites'):
                source = md(REFS.get(str(a['cites']), '')) + (f' <b>{md(a["locator"])}</b>' if a.get('locator') else '')
            else:
                source = ''
            chain = [{'step': md(s['step']),
                      'fields': [{'id': 'F:' + x['field'], 'g': x.get('grounding', 'instance'),
                                  'why': md(x.get('reason', ''))} for x in s.get('fields', [])]}
                     for s in a.get('chain', [])]
            nodes['A:' + aid] = {
                't': 'A', 'g': gid, 'code': aid, 'n': a['name'],
                'tip': strip(a['what_happened'])[:300],
                'label': md(a['label']), 'what': md(a['what_happened']),
                'kind': a.get('instance', ''), 'same': a.get('same_incident_as') or [],
                'atlas': md(a.get('atlas_text', '')), 'atlasNote': md(a.get('atlas_notes', '')),
                'comp': a.get('components_text', ''), 'source': source,
                'ref': a.get('ref') or a.get('cites'), 'chain': chain,
                'noPattern': md(a.get('no_pattern', '')),
                'url': f'{AD}#a-{aid.lower()}',
            }
            for r in a.get('risks', []):
                edges['AR'].append(['A:' + aid, 'R:' + r])
            for x in a['fields']:
                fid, g = (x, 'instance') if isinstance(x, str) else (x['field'], x.get('grounding', 'instance'))
                note = '' if isinstance(x, str) else x.get('note', '')
                edges['AF'].append(['A:' + aid, 'F:' + fid, g, note])

    # Risks (only Risk Map categories; order by lifecycle)
    rorder = ['risksSupplyChainAndDevelopment', 'risksRuntimeInputSecurity', 'risksRuntimeDataSecurity',
              'risksRuntimeOutputSecurity', 'risksDeploymentAndInfrastructure']
    rcats = sorted({r['category'] for r in risks.values()}, key=lambda c: (rorder.index(c) if c in rorder else 99, c))
    for cat in rcats:
        ids = [k for k, r in risks.items() if r['category'] == cat]
        group('R', 'gR' + cat, humanize(cat, 'risks'), ['R:' + k for k in ids])
        for k in ids:
            r = risks[k]
            refs = {e['id']: e for e in r.get('externalReferences', []) or []}
            m = r.get('mappings') or {}
            nodes['R:' + k] = {
                't': 'R', 'g': 'gR' + cat, 'n': r['title'], 'code': k,
                'tip': strip(' '.join(str(p) for p in r.get('shortDescription', []) if isinstance(p, str)))[:300],
                'short': rm_text(r.get('shortDescription'), refs, titles),
                'long': rm_text(r.get('longDescription'), refs, titles),
                'atlas': [x.split('@')[0] for x in m.get('mitre-atlas', [])],
                'life': r.get('lifecycleStage', []), 'impact': r.get('impactType', []),
                'dropped': k in dropped,
            }
            for c in r.get('controls', []) or []:
                if c in controls:
                    edges['RC'].append(['R:' + k, 'C:' + c])
    # Retired IDs that attacks still use and the merged map lacks (none expected).
    for a, r in [(a, r) for a, r in edges['AR'] if r not in nodes]:
        raise SystemExit(f'{a} names {r}, not in the pinned Risk Map')

    # Controls
    for cat, ctitle in ccats.items():
        ids = [k for k, c in controls.items() if c['category'] == cat]
        if not ids:
            continue
        group('C', 'gC' + cat, ctitle.replace(' Controls', ''), ['C:' + k for k in ids])
        for k in ids:
            c = controls[k]
            universal = c.get('risks') == 'all'
            nodes['C:' + k] = {
                't': 'C', 'g': 'gC' + cat, 'n': c['title'], 'code': k,
                'tip': strip(' '.join(str(p) for p in c.get('description', []) if isinstance(p, str)))[:300],
                'desc': rm_text(c.get('description'), {}, titles),
                'comp': [titles.get(x, x) for x in c.get('components', []) or [] if isinstance(x, str)],
                'u': universal, 'dropped': k in dropped,
            }
            if not universal:
                for r in c.get('risks', []) or []:
                    if 'R:' + r in nodes:
                        edges['RC'].append(['R:' + r, 'C:' + k])
    edges['RC'] = [list(e) for e in sorted({tuple(e) for e in edges['RC']})]

    # Fields
    fmap = mapping['fields']
    asks = {a['id']: a for a in mapping['asks']}
    pubs = [('ocsf', 'OCSF'), ('otel', 'OpenTelemetry'), ('aitf', 'AITF'), ('odis', 'ODIS')]
    fbyid = {f['id']: f for f in fields}
    for st in sections['field_steps']:
        gid = 'gF' + st['number']
        group('F', gid, f"§{st['number']} {st['title']}", ['F:' + f for f in st['fields']])
        for fid in st['fields']:
            f, mp = fbyid[fid], fmap.get(fid, {})
            carriers = []
            for key, name in pubs:
                p = mp.get(key)
                if not p:
                    continue
                carriers.append({
                    'pub': name, 'cov': p.get('coverage', ''),
                    'con': p.get('constructs', []), 'gap': md(p.get('gap', '')), 'note': md(p.get('note', '')),
                    'asks': [{'id': a, 's': md(asks[a]['summary']) if a in asks else '',
                              'st': asks.get(a, {}).get('status', '')} for a in p.get('asks', [])],
                })
            emit = [titles.get(x, x) for x in f.get('emitted_by', [])] or ([f['emitted_by_text']] if f.get('emitted_by_text') else [])
            nodes['F:' + fid] = {
                't': 'F', 'g': gid, 'n': f['name'], 'code': fid, 'tier': f['tier'],
                'tip': strip(f['records']), 'records': md(f['records']), 'capture': md(f['capture']),
                'why': md(f.get('rationale', '')), 'role': f['role'], 'origin': f['origin'],
                'record': f['record'], 'modality': f.get('modality', ''),
                'gated': bool(f.get('provider_gated')), 'emit': emit, 'carriers': carriers,
                'step': f"RFC §{st['number']}", 'url': f'{AD}#f-{fid.replace("_", "-")}',
            }
            for c in mp.get('controls', []):
                edges['CF'].append(['C:' + c, 'F:' + fid])

    # Patterns
    stitle = {s['stage']: s['title'] for s in sections['pattern_stages']}
    for stage in stitle:
        ids = [p['id'] for p in patterns if p['stage'] == stage]
        group('P', 'gP' + stage, stitle[stage], ['P:' + i for i in ids])
    for p in patterns:
        pid = 'P:' + p['id']
        nodes[pid] = {
            't': 'P', 'g': 'gP' + p['stage'], 'n': p['name'], 'code': p['id'],
            'tip': strip(p['indicates']), 'ind': md(p['indicates']),
            'cond': [md(c) for c in p['conditions']], 'match': p.get('match', 'all'),
            'base': md(p.get('baseline', '')), 'motive': md(p.get('motivation', '')),
            'url': f'{AD}#p-{p["id"].replace("_", "-")}',
        }
        kinds = {}
        for kind in ('enriches', 'requires', 'join'):
            for f in p.get(kind, []) or []:
                kinds[f] = kind
        for f, kind in kinds.items():
            edges['FP'].append(['F:' + f, pid, kind])
        for a in p.get('catches', []) or []:
            edges['PA'].append([pid, 'A:' + a, 'instance'])
        for a in p.get('catches_analogical', []) or []:
            edges['PA'].append([pid, 'A:' + a, 'analogical'])

    for k, es in edges.items():
        for e in es:
            for n in e[:2]:
                if n not in nodes:
                    raise SystemExit(f'{k} edge {e[:2]}: {n} unknown')

    def rev(path):
        try:
            return subprocess.run(['git', '-C', str(WS), 'rev-parse', '--short', 'HEAD'],
                                  capture_output=True, text=True, check=True).stdout.strip()
        except Exception:
            return '?'
    rfc_h1 = (WS / 'telemetry/CoSAI-AI-Telemetry-RFC.md').read_text().split('\n', 1)[0]
    m = re.match(r'# (.+?) \{\*\*Working Draft v([\d.]+)\*\*\}', rfc_h1)
    if not m:
        raise SystemExit(f'RFC H1 not recognized: {rfc_h1}')
    meta = {
        'title': m[1], 'version': m[2],
        'ws2': f'ws2-defenders edits@{rev(WS)}',
        'riskmap': rm_labels,
        'atlas': src['atlas']['release'],
        'built': datetime.date.today().isoformat(),
        'docs': {'rfc': RFC, 'ad': AD, 'xm': DOCS + 'Telemetry-Cross-Mapping-Addendum.md'},
    }
    return {'nodes': nodes, 'groups': groups, 'edges': edges, 'meta': meta}


def main():
    ap = argparse.ArgumentParser(allow_abbrev=False)
    ap.add_argument('-o', '--output', default=str(WS / 'telemetry/risk-map-explorer.html'))
    args = ap.parse_args()
    data = build()
    page = (HERE / 'risk_map_explorer.template.html').read_text()
    blob = json.dumps(data, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/')
    Path(args.output).write_text(page.replace('/*DATA*/null', blob))
    n = data['nodes']
    count = {t: sum(1 for v in n.values() if v['t'] == t) for t in 'ARCFP'}
    print(f"wrote {args.output}: {count}, edges {{{', '.join(f'{k}: {len(v)}' for k, v in data['edges'].items())}}}")


if __name__ == '__main__':
    main()
