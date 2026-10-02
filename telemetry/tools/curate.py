#!/usr/bin/env python3
"""The curation registry: proposed changes to data/ that need a human decision.

Tools propose; people decide; only decided candidates are applied. Candidates
live in data/candidates/<batch>.yaml. Each has a stable id, a type, the
subject it changes, the proposal, a reason, and a status:

  proposed   awaiting a decision
  accepted   decided as proposed (or as amended by --as)
  rejected   decided against
  deferred   parked, with a note

Types: edge (an attack-field pair and its grounding class), alias (a name in
an attack or pattern cell resolved by judgement), and, from intake, tier,
field and pattern.

`amend` replaces the proposal of an undecided candidate and keeps the old one
under `amended:`, so the registry records what was proposed before.

Grounding classes for edges, following RFC §4.7:
  instance    the documented attack contains the event or state the field
              records, and the field's value distinguishes the attack; counts
              toward the MUST evidence test
  analogical  the attack motivates the field, but the instance does not
              contain what it records, or its value is not distinguishing;
              admissible for SHOULD, not for MUST
  reject      no basis; the edge is removed

Usage:
  curate.py list [--status S] [--type T] [--attack A] [--field F] [--critical] [--source X]
  curate.py accept ID... [--as CLASS] --by NAME [--note TEXT]
  curate.py reject ID... --by NAME [--note TEXT]
  curate.py defer  ID... --by NAME --note TEXT
  curate.py amend  ID --proposal YAML [--reason TEXT] --by NAME
  curate.py summary

ID may be a glob (E:IR-04:*). Filters on list also select for accept/reject
when given in place of IDs: `curate.py accept --source both --by Josiah`.
"""
import argparse
import datetime
import fnmatch
import glob
import os
import sys
from collections import Counter

import yaml

from yamlio import dump, load

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')
CAND = os.path.join(DATA, 'candidates')
HEADER = ('# Curation registry batch. Edit status only through tools/curate.py, or by hand\n'
          '# keeping decided_by and decided_on filled in. See curate.py for the schema.\n')


def batches():
    for p in sorted(glob.glob(os.path.join(CAND, '*.yaml'))):
        yield p, load(p) or []


def matches(c, a):
    s = c.get('subject', {})
    return ((not a.status or c['status'] == a.status) and
            (not a.type or c['type'] == a.type) and
            (not a.attack or s.get('attack') == a.attack) and
            (not a.field or s.get('field') == a.field) and
            (not a.critical or c.get('critical')) and
            (not a.source or c.get('source') == a.source))


def show(c):
    s = c['subject']
    subj = f"{s.get('attack', '')} -> {s.get('field', '')}" if c['type'] == 'edge' else s
    prop = c['proposal'].get('grounding', c['proposal'])
    flag = ' [critical]' if c.get('critical') else ''
    line = f"{c['id']:<60} {c['status']:<9} {str(prop):<11} {c.get('source', ''):<8}{flag}"
    if c.get('reason'):
        line += f"\n    {c['reason']}"
    return line


def cmd_list(a):
    n = 0
    for _, cs in batches():
        for c in cs:
            if matches(c, a):
                print(show(c))
                n += 1
    print(f'-- {n} candidates')


def cmd_decide(a, status):
    if a.status is None and not a.ids:
        a.status = 'proposed'          # filters alone select undecided candidates only
    today = datetime.date.today().isoformat()
    changed = 0
    for path, cs in batches():
        hit = False
        for c in cs:
            chosen = (any(fnmatch.fnmatchcase(c['id'], i) for i in a.ids) if a.ids else matches(c, a))
            if not chosen:
                continue
            c['status'] = status
            if status == 'accepted' and a.as_:
                c['decision'] = {'grounding': a.as_}
            c['decided_by'], c['decided_on'] = a.by, today
            if a.note:
                c['note'] = a.note
            hit, changed = True, changed + 1
        if hit:
            dump(cs, path, HEADER)
    print(f'{status}: {changed}')


def cmd_amend(a):
    if len(a.ids) != 1 or not a.proposal:
        sys.exit('amend takes one ID and --proposal')
    new = yaml.safe_load(a.proposal)
    if not isinstance(new, dict):
        sys.exit('--proposal must be a YAML mapping, e.g. "{basis: {required_to_read: [x, y]}}"')
    for path, cs in batches():
        for c in cs:
            if c['id'] != a.ids[0]:
                continue
            if c['status'] != 'proposed':
                sys.exit(f"{c['id']} is {c['status']}; only proposed candidates can be amended")
            c.setdefault('amended', []).append({'proposal': c['proposal'], 'reason': c.get('reason'),
                                                'by': a.by, 'on': datetime.date.today().isoformat()})
            c['proposal'] = new
            if a.reason:
                c['reason'] = a.reason
            dump(cs, path, HEADER)
            print('amended:', c['id'])
            return
    sys.exit(f'no candidate {a.ids[0]}')


def cmd_summary(_):
    for path, cs in batches():
        print(os.path.basename(path))
        st = Counter(c['status'] for c in cs)
        print('  status:', dict(st))
        pend = [c for c in cs if c['status'] == 'proposed']
        print('  proposed by class:', dict(Counter(str(c['proposal'].get('grounding', c['type'])) for c in pend)))
        print('  critical, undecided:', sum(1 for c in pend if c.get('critical')))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('command', choices=['list', 'accept', 'reject', 'defer', 'amend', 'summary'])
    p.add_argument('ids', nargs='*')
    for f in ('status', 'type', 'attack', 'field', 'source', 'by', 'note', 'proposal', 'reason'):
        p.add_argument('--' + f)
    p.add_argument('--as', dest='as_', choices=['instance', 'analogical', 'reject'])
    p.add_argument('--critical', action='store_true')
    a = p.parse_args()
    if a.command in ('accept', 'reject', 'defer', 'amend') and not a.by:
        sys.exit('--by is required for a decision')
    if a.command == 'defer' and not a.note:
        sys.exit('--note is required to defer')
    {'list': cmd_list, 'summary': cmd_summary, 'amend': cmd_amend,
     'accept': lambda x: cmd_decide(x, 'accepted'),
     'reject': lambda x: cmd_decide(x, 'rejected'),
     'defer': lambda x: cmd_decide(x, 'deferred')}[a.command](a)


if __name__ == '__main__':
    main()
