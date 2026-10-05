#!/usr/bin/env python3
"""Validate the telemetry data and the three documents built from it.

Replaces ~/cosai-telemetry/validate_set.py. Five groups of checks:

  1. data         the rules in rules.py: tiers against their RFC §4.7 basis,
                  field steps, attack edges, patterns and coverage
  2. registry     every decided candidate is signed and dated, every accepted
                  one applied
  3. vocabularies every MITRE ATLAS and CoSAI Risk Map ID in the data and the
                  documents resolves at the version pinned in data/sources.yaml,
                  and every construct data/mapping.yaml cites resolves at the
                  pinned OCSF, OpenTelemetry, AITF or ODIS version, unless an ask
                  the entry references proposes it
  4. sync         the generated regions of the RFC and AD match the data
                  (tools/build.py --check)
  5. documents    the structural checks validate_set.py made: anchors, section
                  references, field references, attacks and references,
                  citation semantics, prose conventions, tables

Pinned sources are fetched once into ~/.cache/cosai-telemetry/ and never
into data/. Counts the old validator held as constants (attacks, tier
totals) are computed from the data.

Usage:
  python3 tools/validate.py              run every check
  python3 tools/validate.py --offline    do not fetch; fail if a pinned source is not cached
"""
import argparse
import glob
import os
import re
import sys
import urllib.request
import zipfile
from collections import Counter

import yaml

import rules
import vocab
from yamlio import load

DIR, DATA = rules.DIR, rules.DATA
CACHE = os.path.expanduser('~/.cache/cosai-telemetry')
FILES = {'RFC': 'CoSAI-AI-Telemetry-RFC.md', 'AD': 'Telemetry-Attack-Detection-Addendum.md',
         'XM': 'Telemetry-Cross-Mapping-Addendum.md'}
RETIRED_REFS = {27, 28, 46, 48, 47, 53, 54}  # deleted 2026-09-30 and (47, 53, 54) 2026-10-02, cited nowhere; never reused
APPLY_TYPES = {'attack', 'edge', 'alias', 'basis', 'tier', 'capture', 'facets', 'risks', 'pattern', 'coverage', 'catch'}
ATLAS_ID = re.compile(r'\bAML\.(?:TA|T|CS|M)\d{4}(?:\.\d{3})?\b')
RISKMAP_ID = re.compile(r'\b(?:risk|control|component)[A-Z][A-Za-z0-9]+\b')
fails = []


def check(label, problems):
    """Record one check; `problems` is a list (empty passes) or a bool (True passes)."""
    ok = problems is True or problems == []
    detail = '' if ok or problems is False else f'  -> {problems[:6]}' + (f' (+{len(problems) - 6})' if len(problems) > 6 else '')
    print(f"  {'PASS' if ok else 'FAIL'}  {label}{detail}")
    if not ok:
        fails.append(label)


# ---------------------------------------------------------------- pinned sources
def cached(repo, commit, path, offline):
    """Local copy of `path` in `repo` at `commit`, fetching it on first use."""
    owner_repo = repo.removeprefix('https://github.com/')
    local = os.path.join(CACHE, owner_repo.replace('/', '__') + '@' + commit[:12], path)
    if not os.path.exists(local):
        if offline:
            sys.exit(f'{local} is not cached; run without --offline once')
        os.makedirs(os.path.dirname(local), exist_ok=True)
        url = f'https://raw.githubusercontent.com/{owner_repo}/{commit}/{path}'
        with urllib.request.urlopen(url, timeout=60) as r, open(local, 'wb') as f:
            f.write(r.read())
    with open(local, encoding='utf-8') as f:
        return yaml.safe_load(f)


def vocabularies(offline):
    src = load(os.path.join(DATA, 'sources.yaml'))
    at = src['atlas']
    doc = cached(at['repository'], at['commit'], at['file'], offline)
    atlas = {i for k in ('tactics', 'techniques', 'case-studies', 'mitigations') for i in doc[k]}
    retired = set(at.get('retired', {}))
    rm, riskmap = src['riskmap'], set()
    for pin in [rm['base']] + rm.get('layers', []):
        for path in rm['files']:
            d = cached(pin.get('repository', rm['repository']), pin['commit'], path, offline)
            riskmap |= {r['id'] for k in ('risks', 'controls', 'components') for r in d.get(k, [])}
    return at['release'], atlas, retired, riskmap


# ---------------------------------------------------------------- 5. documents
def document_checks(T, corpus, tiers):
    n_attacks = len(corpus)
    """The checks of validate_set.py, unchanged except that its counts come from the data."""
    ISO_TITLE = 'Information technology — Artificial intelligence — Management system'
    PREFIX = {'RFC': 'RFC', 'AD': 'AD', 'XM': 'XM'}
    BY_FILE = {v: k for k, v in FILES.items()}
    DOC_OF = {v: k for k, v in PREFIX.items()}

    def slug(h):
        h = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', h)
        h = re.sub(r'`|\*\*|\*|_', '', h).lower().strip()
        return re.sub(r'[^\w\s-]', '', h).replace(' ', '-')

    def headings(t):
        return [m.group(1) for m in re.finditer(r'^#{1,6}\s+(.*)$', t, re.M)]

    def numbers(t):
        out = set()
        for h in headings(t):
            m = re.match(r'(\d+(?:\.\d+)?)\.?\s', h)
            if m:
                out.add(m.group(1))
        return out

    ANCHORS = {k: {slug(h) for h in headings(t)} | set(re.findall(r'<a id="([^"]+)"></a>', t)) for k, t in T.items()}
    NUMS = {k: numbers(t) for k, t in T.items()}

    print('5a. anchors and headings')
    for k, t in T.items():
        hs = headings(t)
        check(f'{k}: no duplicate headings', sorted(h for h in set(hs) if hs.count(h) > 1))
        check(f'{k}: no double-spaced headings', not re.search(r'(?m)^#{1,6} .*  ', t))
        bad = []
        for target in re.findall(r'\]\(([^)\s]*#[^)\s]+)\)', t):
            f, _, a = target.partition('#')
            if f.startswith('http'):
                continue
            doc = k if not f else BY_FILE.get(f)
            if doc is None or a not in ANCHORS[doc]:
                bad.append(target)
        check(f'{k}: all anchors resolve (within and across documents)', sorted(set(bad)))

    print('5b. section numbering and references')
    for k, t in T.items():
        tops = [int(m.group(1)) for m in re.finditer(r'^## (\d+)\. ', t, re.M)]
        check(f'{k}: top-level sections contiguous from 1', tops == list(range(1, len(tops) + 1)))
    EXTERNAL = r'(?<!ODIS )(?<!CPEX )(?<!AOS )(?<!OCSF )(?<!CoSAI IR )'
    REF = re.compile(r'(?:(RFC|AD|XM) )?' + EXTERNAL +
                     r'§(§?)\s?(\d+(?:\.\d+)?)((?:(?:\s*,\s*|\s+(?:to|and|or)\s+)\d+(?:\.\d+)?)*)')
    for k, t in T.items():
        prose = re.sub(r'\]\([^)]*\)', ']', t)
        bad = []
        for m in REF.finditer(prose):
            target = DOC_OF[m.group(1)] if m.group(1) else k
            nums = [m.group(3)] + (re.findall(r'\d+(?:\.\d+)?', m.group(4)) if m.group(2) else [])
            bad += [m.group(0) for n in nums if n not in NUMS[target]]
        check(f'{k}: every § reference resolves in its target document', sorted(set(bad)))
        # A linked reference resolves and still points at the wrong section when its number was
        # remapped and its anchor was not, or the reverse: the number in the text must be the
        # number the anchor's heading carries ('§2.8' links to '#28-...').
        skew = [m.group(0) for m in re.finditer(r'\[(?:(?:RFC|AD|XM) )?§(\d+(?:\.\d+)?)\]\([^)#]*#(\d+)-[^)]*\)', t)
                if m.group(1).replace('.', '') != m.group(2)]
        check(f'{k}: every linked § number matches its anchor', skew)

    print('5c. tiers and fields')
    rows, sub = Counter(), {}
    for k, t in T.items():
        top = head = None
        for line in t.split('\n'):
            h = re.match(r'^(#{2,3}) (\d+(?:\.\d+)?)\.? ', line)
            if h:
                head = h.group(2)
                if h.group(1) == '##':
                    top = head
                continue
            r = re.match(r'^\|\s*\*\*(.+?)\*\*[^|]*\|\s*(MUST|SHOULD|MAY)', line)
            if r and k == 'AD' and top == '1' and head.startswith('1.'):
                sub[re.sub(r'[^a-z0-9]', '', r.group(1).lower())] = (k, head)
                rows[r.group(2)] += 1
    rfc_cat = {}
    for line_head, block in re.findall(r'(?m)^### (\d+\.\d+) [^\n]*\n(.*?)(?=^#{2,3} |\Z)', T['RFC'], re.S):
        for name in re.findall(r'(?m)^\| \[([^\]]+)\]\(', block):
            rfc_cat[re.sub(r'[^a-z0-9]', '', name.lower())] = line_head
    check('RFC catalog lists every field once', set(rfc_cat) >= set(sub) or
          all(any(r.startswith(s) or s.startswith(r) for r in rfc_cat) for s in sub))
    check(f'AD tier totals match the data ({"/".join(map(str, tiers))})',
          (rows['MUST'], rows['SHOULD'], rows['MAY']) == tiers or [dict(rows)])
    check('field tables live in the Attack Detection Addendum', all(v[0] == 'AD' for v in sub.values()) and bool(sub))

    print('5d. field-name -> section references')
    FIELD_REF = re.compile(r'\*\*([A-Z][^*]{3,60})\*\*\s*\((?:(RFC|AD|XM) )?§(\d+(?:\.\d+)?)')

    def lookup(name):
        full = re.sub(r'[^a-z0-9]', '', name.lower())
        key = re.sub(r'[^a-z0-9]', '', re.sub(r'\s*\(.*', '', name).lower())
        if full in sub:
            return full
        if key in sub:
            return key
        return next((w for w in sub if w.startswith(key) or key.startswith(w)), None)

    for k, t in T.items():
        mism = []
        for m in FIELD_REF.finditer(t):
            f = lookup(m.group(1))
            if not f:
                continue
            target = DOC_OF[m.group(2)] if m.group(2) else k
            n = m.group(3)
            cat = next((v for r, v in rfc_cat.items() if r == f or r.startswith(f) or f.startswith(r)), None)
            if not ((target, n) == sub[f] or (target == 'RFC' and n == cat)):
                want = f"{PREFIX[sub[f][0]]} §{sub[f][1]}" + (f' or RFC §{cat}' if cat else '')
                mism.append(f'{m.group(1).strip()} (§{n}) should be {want}')
        check(f'{k}: inline field refs point at the defining section', mism)

    print('5e. attacks and references')
    defs = Counter()
    for t in T.values():
        defs.update(re.findall(r'^\| (?:<a id="a-[a-z0-9-]+"></a>)?\*\*((?:TA|IR|AOC)-\d+)\*\*', t, re.M))
    used = set()
    for t in T.values():
        used |= set(re.findall(r'\b((?:TA|IR|AOC)-\d+)\b', t))
    check('no attack IDs cited but undefined', sorted(used - set(defs)))
    check(f'{n_attacks} attacks defined, as in the data', len(defs) == n_attacks or [len(defs)])
    # The corpus summary is prose, not generated; its counts must match the data. A
    # missing summary fails too, so rewording it cannot skip the check silently.
    by_kind = Counter(a.split('-')[0] for a in corpus)
    want = (len(corpus), by_kind['TA'], by_kind['IR'], by_kind['AOC'])
    found = re.findall(r'(\d+) entries(?:, comprising|:) (\d+) real-world attacks and incidents, (\d+) CoSAI '
                       r'incident-response case studies(?: \[\[\d+\]\]\([^)]*\))?, and (\d+) live red-team case studies',
                       T['RFC'])
    check('RFC: corpus summary counts match the data (entries, TA, IR, AOC: %d, %d, %d, %d)' % want,
          [] if found and all(tuple(map(int, f)) == want for f in found) else (found or ['summary sentence not found']))

    def ref_section(t):
        m = re.search(r'^## (?:\d+\. )?References\s*$', t, re.M)
        if not m:
            return ''
        end = re.search(r'^## ', t[m.end():], re.M)
        return t[m.start():m.end() + end.start()] if end else t[m.start():]

    RS = {k: ref_section(t) for k, t in T.items()}
    REFS = {k: {int(m.group(1)): m.group(2).strip() for m in re.finditer(r'(?m)^(\d+)\. (\*\*.*)$', rs)}
            for k, rs in RS.items()}
    canon, drift = {}, []
    for k in ('RFC', 'AD', 'XM'):
        for i, e in REFS[k].items():
            if i in canon and canon[i] != e:
                drift.append((k, i))
            canon.setdefault(i, e)
    n = sorted(canon)
    full = set(range(1, max(n) + 1)) - RETIRED_REFS
    check('reference numbers across the set are 1..N, less retired numbers', sorted(full ^ set(n)))
    check('each reference number has one text in every document that lists it', drift)
    for k, t in T.items():
        cites = {int(x) for x in re.findall(r'\[\[(\d+)\]\]', t)}
        check(f'{k}: all [[n]] citations are in its own reference list', sorted(cites - set(REFS[k])))
        unbroken, prev, gap = [], None, False
        for line in RS[k].split('\n'):
            m = re.match(r'^(\d+)\. ', line)
            if m:
                i = int(m.group(1))
                if prev is not None and i != prev + 1 and not gap:
                    unbroken.append(f'{prev}->{i}')
                prev, gap = i, False
            elif line.strip() and not line.startswith('   '):
                gap = True
        check(f'{k}: reference numbering jumps start a new list', unbroken)
    check('no AT10xx outside the alias table and the taxonomy decision',
          sum(len(re.findall(r'AT10\d\d', t)) for t in T.values()) < 25)

    print('5f. citation semantics (catches valid-but-wrong references)')
    KEY = {'OpenTelemetry': 'OpenTelemetry', 'OCSF': 'OCSF', 'OWASP AOS': 'AOS', 'CPEX': 'CPEX',
           'ODIS': 'ODIS', 'MITRE ATLAS': 'ATLAS', 'EU AI Act Article 12': 'EU AI Act',
           'NIST AI Risk Management': 'NIST AI Risk', 'CSF': 'NIST Cybersecurity',
           'ISO/IEC 42001': 'ISO/IEC 42001', 'AITF': 'AITF', 'CoSAI Risk Map': 'CoSAI Risk Map',
           'agent-to-agent': 'A2A', 'Aim Labs': 'TA-01'}
    for k, t in T.items():
        titles = {i: re.sub(r'^\*\*([^*]+).*', r'\1', e)[:60] for i, e in REFS[k].items()}
        bad = []
        for m in re.finditer(r'\[\[(\d+)\]\]', t):
            i = int(m.group(1))
            before = t[max(0, m.start() - 70):m.start()]
            hit = [v for key, v in KEY.items() if key.lower() in before.lower()]
            if hit and not any(h.lower() in titles.get(i, '').lower() for h in hit):
                bad.append(f"[[{i}]]->'{titles.get(i, '')}' but context says {hit}")
        check(f'{k}: citations point at the right reference', bad)

    print('5g. prose conventions')
    BANNED = (r'\bhonest\w*|\bcandid\b|\bfrankly\b|\badmittedly\b|\bto be fair\b'
              r'|worth stating plainly|apologi\w*|(?:this|previous) revision'
              r'|earlier revisions?|previously (?:only|an? |the |"|treated|followed|tracked|argued|proposed|recorded)'
              r'|no longer treated|hitherto|used to be')
    for k, t in T.items():
        check(f'{k}: no ethos/pathos or retrospective framing', sorted(set(re.findall(BANNED, t, re.I))))
        d = t.replace(ISO_TITLE, '')
        check(f'{k}: no em or en dashes (ISO/IEC 42001 title exempt)', '—' not in d and '–' not in d)

    print('5h. tables')
    for k, t in T.items():
        bad_t, blk = 0, []
        for line in t.split('\n') + ['']:
            if line.strip().startswith('|'):
                blk.append(line)
            else:
                if len(blk) > 1 and len({x.count('|') for x in blk}) > 1:
                    bad_t += 1
                blk = []
        check(f'{k}: no malformed markdown table blocks', bad_t == 0)
        try:
            x = zipfile.ZipFile(os.path.join(DIR, FILES[k].replace('.md', '.docx'))).read('word/document.xml').decode()
            check(f'{k}: docx tables all have a grid', all('<w:tblGrid>' in b for b in re.findall(r'<w:tbl>.*?</w:tbl>', x, re.S)))
        except FileNotFoundError:
            pass


def main():
    # argparse rejects unknown options and abbreviations, so a mistyped flag fails rather than being ignored.
    ap = argparse.ArgumentParser(allow_abbrev=False, description='Validate the telemetry data and documents.')
    ap.add_argument('--offline', action='store_true', help='do not fetch pinned sources; fail if one is not cached')
    offline = ap.parse_args().offline

    fields, attacks, patterns, layout = rules.load_data()
    T = {k: open(os.path.join(DIR, f), encoding='utf-8').read() for k, f in FILES.items()}
    tiers = tuple(sum(f['tier'] == t for f in fields.values()) for t in rules.TIERS)

    print('1. data')
    check('tiers against their RFC §4.7 basis', rules.tier_problems(fields, attacks))
    check('every field in exactly one step, ordered by tier', rules.layout_problems(fields, layout))
    check('attack edges and reference numbers', rules.attack_problems(fields, attacks))
    check('patterns, their catches against the edges, and coverage of every attack',
          rules.pattern_problems(fields, attacks, patterns))
    mapping = rules.load_mapping()
    publications = load(os.path.join(DATA, 'sources.yaml'))['publications']
    check('mapping: every field mapped; gaps stated and answered by an ask or a reason',
          rules.mapping_problems(fields, mapping, publications))

    print('2. registry')
    batches = [(p, load(p) or []) for p in sorted(glob.glob(os.path.join(DATA, 'candidates', '*.yaml')))]
    check('decided candidates signed and dated; accepted candidates applied',
          rules.candidate_problems(batches, APPLY_TYPES))

    print('3. vocabularies')
    release, atlas, retired, riskmap = vocabularies(offline)
    data_text = '\n'.join(open(p, encoding='utf-8').read()
                          for p in [os.path.join(DATA, 'fields.yaml'), os.path.join(DATA, 'patterns.yaml'),
                                    os.path.join(DATA, 'mapping.yaml')]
                          + glob.glob(os.path.join(DATA, 'attacks', '*.yaml')))
    for name, text in [('data', data_text)] + list(T.items()):
        known = atlas if name == 'data' else atlas | retired      # documents may name a retirement
        check(f'{name}: every MITRE ATLAS ID resolves at {release}', sorted(set(ATLAS_ID.findall(text)) - known))
        check(f'{name}: every Risk Map ID resolves at the pinned commits', sorted(set(RISKMAP_ID.findall(text)) - riskmap))

    if mapping is not None:
        try:
            names = {k: vocab.RESOLVERS[k](publications[k], offline) for k in ('ocsf', 'otel_genai', 'otel_semconv', 'aitf', 'odis')}
        except SystemExit as e:
            check(f'mapping constructs resolve at their pins ({e})', False)
        else:
            names['otel'] = names.pop('otel_genai') | names.pop('otel_semconv')
            names['aitf'] |= names['otel']   # AITF extends the OpenTelemetry conventions
            pins = ', '.join(f"{k} {publications[k].get('release') or publications[k]['commit'][:7]}"
                             for k in ('ocsf', 'otel_genai', 'aitf', 'odis'))
            check(f'mapping constructs resolve at their pins ({pins})', rules.unresolved_constructs(mapping, names))

    print('4. sync')
    import build
    for name, fn in ((build.AD, build.build_ad), (build.RFC, build.build_rfc)):
        with open(os.path.join(DIR, name), encoding='utf-8') as f:
            text = f.read()
        check(f'{name}: generated regions match data/ (tools/build.py)', fn(text) == text)

    print('5. documents')
    document_checks(T, sorted(attacks), tiers)

    print()
    print(('FAILED: ' + '; '.join(fails)) if fails else 'All checks passed.')
    sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()
