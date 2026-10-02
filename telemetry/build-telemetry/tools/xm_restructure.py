#!/usr/bin/env python3
"""XM pass, one-shot (kept as record): restructure the Cross-Mapping Addendum.

New layout (Josiah, 2026-10-02): an introduction stating the template; 1 OCSF,
2 OpenTelemetry, 3 AITF (the bridge), then the cross references 4 OWASP AOS,
5 CPEX, 6 ODIS, 7 NIST, 8 ISO/IEC 42001. The CoSAI Risk Map section is removed.
OCSF, OpenTelemetry, AITF and ODIS correspondence, the asks and the pins are
generated from data/ (tools/build.py); hand-written text is carried over from the
old sections, not rewritten, except where this script says so.

Section references move in one mapped pass (old number -> new number) over XM,
the RFC, AD and the data, never by sequential replacement. Old §1 has no new
home; old §4 splits into AITF (§3) and ODIS (§6). The few references to them are
rewritten by hand below.

Usage: python3 tools/xm_restructure.py [--write]   (default: report only)
"""
import argparse
import os
import re
import sys

import rules
from yamlio import dump, load

DIR, DATA = rules.DIR, rules.DATA
RFC, AD, XM = 'CoSAI-AI-Telemetry-RFC.md', 'Telemetry-Attack-Detection-Addendum.md', 'Telemetry-Cross-Mapping-Addendum.md'

# old section number -> new section number (None: removed)
SECTIONS = {'1': None, '1.1': None, '1.2': None, '1.3': None,
            '2': '2', '2.1': '2.1', '2.2': '2.2', '2.3': '2.4', '2.4': '2.7', '2.5': '2.8',
            '3': '1', '3.1': '1.2', '3.2': '1.4', '3.3': '3.4',
            '4': '3',     # AITF; the ODIS reference (26) is rewritten to §6 by hand
            **{f'5{s}': f'4{s}' for s in ['', '.1', '.2', '.3', '.4', '.5', '.6']},
            **{f'6{s}': f'5{s}' for s in ['', '.1', '.2', '.3', '.4', '.5']},
            **{f'7{s}': f'7{s}' for s in ['', '.1', '.2', '.3', '.4']},
            **{f'8{s}': f'8{s}' for s in ['', '.1', '.2', '.3']}}


def slug(h):
    h = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', h)
    h = re.sub(r'`|\*\*|\*|_', '', h).lower().strip()
    return re.sub(r'[^\w\s-]', '', h).replace(' ', '-')


def blocks(text):
    """{heading line: body} for every ## and ### heading, body up to the next ## or ###."""
    parts = re.split(r'(?m)^(#{2,3} .*)$', text)
    return {h: b for h, b in zip(parts[1::2], parts[2::2])}


def heading(old, num):
    return next(h for h in old if re.match(rf'#{{2,3}} {re.escape(num)}\.? ', h))


def strip_rule(b):
    return re.sub(r'\n---\s*$', '\n', b.rstrip() + '\n').rstrip() + '\n'


def main():
    ap = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split('\n')[0])
    ap.add_argument('--write', action='store_true', help='write the documents and data; default: report only')
    write = ap.parse_args().write
    xm = open(os.path.join(DIR, XM), encoding='utf-8').read()
    old = blocks(xm)
    H = {n: heading(old, n) for n in SECTIONS}
    head_end = xm.index('### For the open source security community')
    agents = old['### Agents you do not operate']
    refs = xm[xm.index('## References'):]

    # ---- old §2.3: each OTel ask's rationale moves onto the ask in mapping.yaml
    s23 = old[H['2.3']]
    items = re.findall(r'(?ms)^(\d+)\. \*\*(.+?)\*\*\s*(.*?)(?=^\d+\. |\n\*\*Two clusters|\Z)', s23)
    OTEL_ITEM = {'1': 'otel_trust_level', '2': 'otel_security_guardrail', '3': 'otel_memory_provenance_footprint',
                 '4': 'otel_retrieval_provenance', '5': 'otel_turn_step_ids', '6': 'otel_trigger',
                 '7': 'otel_tool_digest_mcp_primitive', '8': 'otel_attachment_identity', '9': 'otel_model_provenance'}
    mapping = load(os.path.join(DATA, 'mapping.yaml'))
    asks = {a['id']: a for a in mapping['asks']}
    for num, title, body in items:
        asks[OTEL_ITEM[num]]['rationale'] = ' '.join(body.split())
    otel_intro = s23.split('\n\n1. ')[0].strip()
    two_clusters = s23[s23.index('**Two clusters'):].strip()

    # ---- old §2 intro and §2.1
    s2 = strip_rule(old[H['2']]).strip()
    s21 = old[H['2.1']].strip()
    s21_list, s21_close = s21.rsplit('\n\nThree existing GenAI attributes', 1)
    s21_close = 'Three existing GenAI attributes' + s21_close

    # ---- old §3 and its parts
    s3_intro = old[H['3']].strip()
    s31 = old[H['3.1']]
    rows = {r.split('|')[1].strip(): [c.strip() for c in r.strip().strip('|').split('|')]
            for r in s31.split('\n') if r.startswith('| ') and not r.startswith('| :')}
    deleg_gap = rows['Identity & delegation (SHOULD)'][2]
    policy_gap = rows['Policy enforcement & mediation (MUST / SHOULD)'][2]
    agent_cls = rows['Execution context & agent identity (MUST / SHOULD)'][4]
    s32 = old[H['3.2']]
    s32_items = dict(re.findall(r'(?ms)^(\d+)\. (.*?)(?=^\d+\. |\Z)', s32))
    s33 = strip_rule(old[H['3.3']]).strip()
    s33 = s33.replace(
        "**Governance rule for promotion:** a field graduates from AITF-proposed to an OCSF standardization ask when **≥ 2 independent documented instances in [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory)** require it, the same evidence rule that sets the MUST tier ([RFC §5.1](CoSAI-AI-Telemetry-RFC.md#51-tiers)).",
        "**Governance rule for promotion:** a field graduates from AITF-proposed to an OCSF or OpenTelemetry standardization ask once it is MUST under [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers): two independent documented instances in [AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory), or a MUST field that cannot be read without it.")
    assert 'once it is MUST under' in s33, 'governance rule not restated'

    # ---- old §4: the AITF identifier note to §3, the ODIS material to §6
    s4 = strip_rule(old[H['4']])
    s4_intro = s4.split('\n\n>')[0].strip()
    ident_note = re.search(r'(?ms)^> \*\*Note on the identifier mapping\.\*\*.*?(?=\n\n)', s4).group(0)
    odis_notes = s4[s4.index('> **Policy-engine consumption'):].strip()

    def renumbered(num_old, num_new):
        h = H[num_old]
        return re.sub(rf'^(#{{2,3}}) {re.escape(num_old)}(\.?) ', rf'\1 {num_new}\2 ', h)

    def carry(num_old):
        out = []
        for n in [k for k in SECTIONS if k == num_old or k.startswith(num_old + '.')]:
            out += [renumbered(n, SECTIONS[n]), strip_rule(old[H[n]]).rstrip(), '']
        return '\n'.join(out)

    header = xm[:head_end].replace('{**Working Draft v0.5**}', '{**Working Draft v0.6**}').replace(
        '**Status:** Request for Comments, revision 0.5', '**Status:** Request for Comments, revision 0.6')
    assert 'v0.6' in header and 'revision 0.6' in header

    G = lambda key: f'<!-- BEGIN GENERATED: {key} -->\n<!-- END GENERATED: {key} -->'
    doc = header + f'''### How this addendum is organized

This addendum maps the field set onto the specifications that carry security telemetry, and states what each would need to carry the rest. **OCSF** and **OpenTelemetry** are its two target audiences, in that order: OCSF is how a SIEM consumes the telemetry, OpenTelemetry how instrumentation emits it. **AITF** is the bridge: it carries the fields today and stages the changes proposed to the other two. The remaining sections are cross references, included for completeness.

Every section answers the same questions, under the same headings, and skips one only where it does not apply:

1. **What it is, and the version mapped.** Each mapping is pinned to a commit or a published version.
2. **Correspondence.** Which construct carries each field, and how fully: *covered*, *partial*, *none*, or *out of scope*.
3. **Gaps.** What the publication cannot express, and what a defender loses as a result.
4. **Asks.** What CoSAI proposes, each ask tied to the fields it would close and the evidence for them.
5. **What it contributes.** What this field set takes from it.
6. **Divergences and open items.**

For OCSF, OpenTelemetry, AITF and ODIS the correspondence and the asks are generated from the field data, and every construct named resolves at the pinned version.

**The pins.**

{G('xm pins')}

**Coverage and asks, by publication.**

{G('xm summary')}

- **The proposals are evidence-gated and therefore small.** A field becomes a standardization ask only once it is MUST under [RFC §4.7](CoSAI-AI-Telemetry-RFC.md#47-tiers). Nothing is proposed speculatively.
- **Emission and consumption move together.** A field OpenTelemetry emits but OCSF cannot represent arrives at the SIEM as unstructured overflow; a field OCSF defines but no instrumentation produces stays theoretical. Paired asks are the intent.

CoSAI is engaging the **OpenTelemetry** and **OCSF** communities directly on this work, and welcomes input from the wider open source security community in turn. What is wanted in return: corrections to the mappings, and attacks the corpus is missing.

### Agents you do not operate
{agents.rstrip()}

---

## 1. OCSF

### 1.1 What it is, and the version mapped

{G('xm pin ocsf')}

{s3_intro.replace('This appendix covers the OCSF consumption side of the standards bridge and AITF' + "'" + 's role as the interim binding. ', 'This section covers the OCSF consumption side of the standards bridge; AITF carries the interim binding ([§⟨3⟩](#3-aitf)). ')}

OCSF 1.9.0 already carries an `ai_operation` profile on API Activity (6003): `ai_agent`, `ai_model`, `delegation` and `message_context`, with record integrity on the base event. The correspondence below is against that release; constructs proposed in open pull requests are asks, not coverage.

### 1.2 Correspondence

{G('xm correspondence ocsf')}

### 1.3 Gaps

The table states each gap. Two need more than a cell.

**Delegation lineage.** {deleg_gap}

**Authorization and accounting.** {policy_gap}

### 1.4 Asks

{G('xm asks ocsf')}

**How the asks fit together.**

1. {s32_items['1'].strip()}
2. {s32_items['2'].strip()}
3. {s32_items['3'].strip()}
4. {s32_items['4'].strip()}

### 1.5 What it contributes

{s32_items['5'].strip()}

The `record_integrity` profile and the `attestation` object on the base event carry **Event Sequence Continuity** with no new schema, and `ai_agent` already separates a stable agent identifier from a restart-sensitive instance identifier.

### 1.6 Divergences and open items

{s32_items['6'].strip()}

On the agentic classes: {agent_cls}

---

## 2. OpenTelemetry

### 2.1 What it is, and the version mapped

{G('xm pin otel')}

{s2.replace('[§3](#3-implications-for-ocsf--aitf-the-standardization-bridge)', '[§⟨1⟩](#1-ocsf)')}

{s21_list.strip()}

### 2.2 Correspondence

{G('xm correspondence otel')}

### 2.3 Gaps

The table states each gap. The security-specific ones are where the conventions were never shaped to go: trust provenance on input, guardrail verdicts, memory and retrieval provenance, and the run, turn and step identifiers between a conversation and a span.

### 2.4 Asks

{otel_intro}

{G('xm asks otel')}

### 2.5 What it contributes

{s21_close}

### 2.6 Divergences and open items

{two_clusters}

'''
    doc += carry('2.4').replace('### 2.7 ', '### 2.7 ', 1) + '\n'
    doc += carry('2.5') + '\n---\n\n'
    doc += f'''## 3. AITF

### 3.1 What it is, and the version mapped

{G('xm pin aitf')}

AITF, the AI Telemetry Framework, was donated to CoSAI Workstream 2. It carries these fields as OpenTelemetry attributes today and emits them into OCSF ahead of formal ratification, so adopters are not blocked on either standards body. AITF v0.4 closed the 27 gaps RFC v0.4 recorded for it, adding 390 attributes ([`aitf/AITF_gaps.md`](aitf/AITF_gaps.md)).

{ident_note}

### 3.2 Correspondence

{G('xm correspondence aitf')}

### 3.3 Gaps

AITF defines an attribute for every field except those the table marks *partial* or *none*. For five MUST fields (Surface / App, Input Source / Channel, LLM Error / Exception, LLM Refusal, Tool Type / Trust Boundary) an earlier mapping cited only a namespace, and AITF defines no attribute for them at the pin.

### 3.4 Path to OCSF and OpenTelemetry

{s33}

---

'''
    doc += carry('5') + '\n---\n\n' + carry('6') + '\n---\n\n'
    doc += f'''## 6. ODIS

### 6.1 What it is, and the version mapped

{G('xm pin odis')}

{s4_intro}

### 6.2 Correspondence

{G('xm correspondence odis')}

### 6.3 Notes on the mapping

{odis_notes}

---

'''
    doc += carry('7') + '\n---\n\n' + carry('8') + '\n---\n\n' + refs

    # ---- one mapped pass over every reference into XM
    new_headings = {m.group(2): m.group(0)[m.group(0).index(' ') + 1:] for m in re.finditer(r'(?m)^(#{2,3}) (\d+(?:\.\d+)?)\.? .*$', doc)}
    old_slug = {n: slug(H[n][H[n].index(' ') + 1:]) for n in SECTIONS}
    new_slug = {n: slug(h) for n, h in new_headings.items()}
    anchor_map = {old_slug[o]: new_slug[n] for o, n in SECTIONS.items() if n}
    anchor_map[old_slug['4']] = new_slug['3']

    def remap_num(n):
        if n not in SECTIONS:
            return n
        if SECTIONS[n] is None:
            SURVIVING.append(n)
            return n
        return SECTIONS[n]

    SURVIVING = []
    REF = re.compile(r'§(§?)(\d+(?:\.\d+)?)((?:(?:\s*,\s*|\s+(?:to|and|or)\s+)\d+(?:\.\d+)?)*)')

    def remap_refs(text, prefixed_only):
        """Remap XM section numbers: 'XM §n' everywhere; unprefixed §n too when inside XM."""
        pat = r'(XM )' + (r'' if prefixed_only else r'?') + r'(?<!RFC )(?<!AD )(?<!ODIS )(?<!CPEX )(?<!AOS )(?<!OCSF )(?<!§)' + REF.pattern

        def sub(m):
            prefix = m.group(1) or ''
            before = text[max(0, m.start() - 4):m.start()]
            if not prefix and re.search(r'(RFC|AD|ODIS|CPEX|AOS|OCSF|EU|42001) $', before):
                return m.group(0)
            lst = m.group(4)
            nums = [m.group(3)] + (re.findall(r'\d+(?:\.\d+)?', lst) if m.group(2) else [])
            out = m.group(0)
            new = [remap_num(n) for n in nums]
            head = f'{prefix}§{m.group(2)}{new[0]}'
            rest = lst
            for a, b in zip(nums[1:], new[1:]):
                rest = re.sub(rf'(?<![\d.]){re.escape(a)}(?![\d.])', b, rest, count=1)
            if SURVIVING and SURVIVING[-1] in nums:
                SURVIVING[-1] = (SURVIVING[-1], text[max(0, m.start() - 90):m.end() + 30].replace('\n', ' '))
            return head + rest
        return re.sub(pat, sub, text)

    def remap_anchors(text, file_prefix):
        def sub(m):
            a = m.group(2)
            if a in anchor_map:
                return m.group(1) + anchor_map[a]
            if a in old_slug.values() and a not in anchor_map:
                raise SystemExit(f'a link to removed anchor #{a} survives')
            return m.group(0)
        return re.sub(rf'({re.escape(file_prefix)}#)([a-z0-9-]+)', sub, text)

    # hand rewrites for the references old §1 and old §4 cannot keep
    rfc = open(os.path.join(DIR, RFC), encoding='utf-8').read()
    ad = open(os.path.join(DIR, AD), encoding='utf-8').read()
    HAND = [
        (RFC, 'Fields are organized under the fine-grained components of the CoSAI Risk Map [[23]](#standards--frameworks), using the canonical IDs in [`risk-map/yaml/components.yaml`](https://github.com/cosai-oasis/secure-ai-tooling/blob/main/risk-map/yaml/components.yaml). The "Emitted by" column documents which component produces each field; events do not carry a risk-map component identifier ([XM §1.3](Telemetry-Cross-Mapping-Addendum.md#13-component--control-refinements) explains why).',
         'The "Emitted by" column names the CoSAI Risk Map [[23]](#standards--frameworks) component that produces each field, using the canonical IDs in [`risk-map/yaml/components.yaml`](https://github.com/cosai-oasis/secure-ai-tooling/blob/main/risk-map/yaml/components.yaml). Events do not carry a component identifier: attribution is a mapping, which costs nothing at runtime, whereas an emitted identifier would need a resolvable namespace and a deprecation policy, since events are immutable and a component renamed upstream would invalidate every event already carrying it.'),
        (AD, 'the controls and standards that address them are in [XM §1.3](Telemetry-Cross-Mapping-Addendum.md#13-component--control-refinements).',
         'the CoSAI Risk Map addresses them in its audit-trail controls (`controlAuditTrailCompleteness`, `controlAuditTrailIntegrityVerification`, `controlAuditRecordRepositoryIndependence`).'),
        (RFC, 'to keep the section numbers and field names in [XM §4](Telemetry-Cross-Mapping-Addendum.md#4-aitf--odis-cross-reference)',
         'to keep the section numbers and field names in [XM §⟨6⟩](Telemetry-Cross-Mapping-Addendum.md#6-odis)'),
        (XM, 'Component taxonomy (AD §1 organized by [CoSAI Risk Map](#1-mapping-to-the-cosai-risk-map-risks--controls))',
         'Component taxonomy (the CoSAI Risk Map [[23]](#standards--frameworks) component that emits each field, AD §1)'),
        (XM, '[AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) attack corpus; [§1](#1-mapping-to-the-cosai-risk-map-risks--controls) risk mapping;',
         '[AD §3](Telemetry-Attack-Detection-Addendum.md#3-attack--incident-inventory) attack corpus;'),
    ]
    texts = {RFC: rfc, AD: ad, XM: doc}
    for name, o, n in HAND:
        assert texts[name].count(o) >= 1, (name, o[:60])
        texts[name] = texts[name].replace(o, n)
    # reference 26 (ODIS) appears in the RFC and in XM's reference list: the same rewrite in both
    texts[XM] = texts[XM].replace('to keep the section numbers and field names in [XM §4](Telemetry-Cross-Mapping-Addendum.md#4-aitf--odis-cross-reference)',
                                  'to keep the section numbers and field names in [XM §⟨6⟩](Telemetry-Cross-Mapping-Addendum.md#6-odis)')

    # mapped pass: XM internal links and § numbers (unprefixed in XM's own prose; the reference
    # list is written in the RFC's voice and uses 'XM §'), then the RFC and AD
    body, reflist = texts[XM].split('## References', 1)
    gen = re.compile(r'(?s)<!-- BEGIN GENERATED: .*?-->.*?<!-- END GENERATED: .*?-->')
    keep = gen.findall(body)
    body = gen.sub('\x00', body)
    body = remap_anchors(body, '')
    body = remap_refs(body, prefixed_only=False)
    for k in keep:
        body = body.replace('\x00', k, 1)
    reflist = remap_anchors(reflist, 'Telemetry-Cross-Mapping-Addendum.md')
    reflist = remap_refs(reflist, prefixed_only=True)
    texts[XM] = (body + '## References' + reflist).replace('§⟨', '§').replace('⟩]', ']')   # new-numbered references, kept out of the remap
    for name in (RFC, AD):
        texts[name] = remap_refs(remap_anchors(texts[name], 'Telemetry-Cross-Mapping-Addendum.md'), prefixed_only=True)
        texts[name] = texts[name].replace('§⟨', '§').replace('⟩]', ']')   # new-numbered references, kept out of the remap
    for name, t_ in texts.items():
        assert '⟨' not in t_ and '⟩' not in t_, f'{name}: a placeholder survives'
    data_files = [os.path.join(DATA, 'fields.yaml')]
    data = {p: remap_refs(remap_anchors(open(p, encoding='utf-8').read(), 'Telemetry-Cross-Mapping-Addendum.md'), True) for p in data_files}

    if SURVIVING:
        sys.exit('references to removed sections survive:\n' + '\n'.join(map(str, SURVIVING)))
    print('new sections:', ', '.join(sorted(new_headings, key=lambda n: [int(x) for x in n.split('.')])))
    for name in (RFC, AD, XM):
        old_t = {RFC: rfc, AD: ad, XM: xm}[name]
        print(f'{name}: {len(old_t.split())} -> {len(texts[name].split())} words')
    if not write:
        print('report only; run with --write')
        return
    for name, t in texts.items():
        with open(os.path.join(DIR, name), 'w', encoding='utf-8') as f:
            f.write(t)
    for p, t in data.items():
        with open(p, 'w', encoding='utf-8') as f:
            f.write(t)
    dump(mapping, os.path.join(DATA, 'mapping.yaml'), open(os.path.join(DATA, 'mapping.yaml'), encoding='utf-8').read().split('asks:')[0])
    print('written')


if __name__ == '__main__':
    main()
