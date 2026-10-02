"""Names defined by the publications pinned in data/sources.yaml, for resolving
the constructs data/mapping.yaml cites.

Each pinned repository is fetched once, as an archive of the pinned commit,
into ~/.cache/cosai-telemetry/ and never into data/.

  ocsf(pin)    {'class:<uid>', 'class:<name>', 'object:<name>', 'profile:<name>',
                'attribute:<name>'} defined at the pinned OCSF release
  otel(pin)    attribute keys, metric names and span or event names in the pinned
               semantic-convention registries (model/**.yaml)
  aitf(pin)    attribute names in AITF's spec/schema/*.json at the pinned commit
  odis(pin)    field names in the record tables of the pinned ODIS.md
"""
import glob
import io
import json
import os
import re
import sys
import tarfile
import urllib.request

import yaml

CACHE = os.path.expanduser('~/.cache/cosai-telemetry')


def checkout(pin, offline=False):
    """Local directory holding the pinned repository at its commit."""
    owner_repo = pin['repository'].removeprefix('https://github.com/')
    root = os.path.join(CACHE, owner_repo.replace('/', '__') + '@' + pin['commit'][:12] + '.tree')
    if not os.path.isdir(root):
        if offline:
            sys.exit(f'{root} is not cached; run without --offline once')
        url = f'https://codeload.github.com/{owner_repo}/tar.gz/{pin["commit"]}'
        with urllib.request.urlopen(url, timeout=120) as r:
            data = r.read()
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
            tar.extractall(root + '.tmp', filter='data')
        top = os.listdir(root + '.tmp')
        os.rename(os.path.join(root + '.tmp', top[0]), root)
        os.rmdir(root + '.tmp')
    return root


def ocsf(pin, offline=False):
    root = checkout(pin, offline)
    names = set()
    for kind, sub in (('class', 'events'), ('object', 'objects'), ('profile', 'profiles')):
        for p in glob.glob(os.path.join(root, sub, '**', '*.json'), recursive=True):
            with open(p, encoding='utf-8') as f:
                d = json.load(f)
            if d.get('name'):
                names.add(f'{kind}:{d["name"]}')
            if kind == 'class' and 'uid' in d:
                names.add(f'class:{d["uid"]}')
    with open(os.path.join(root, 'dictionary.json'), encoding='utf-8') as f:
        names |= {f'attribute:{a}' for a in json.load(f)['attributes']}
    # Class UIDs in events/ are category-relative; OCSF publishes class_uid = category * 1000 + uid.
    with open(os.path.join(root, 'categories.json'), encoding='utf-8') as f:
        cats = {k: v['uid'] for k, v in json.load(f)['attributes'].items()}
    for p in glob.glob(os.path.join(root, 'events', '*', '*.json')):
        with open(p, encoding='utf-8') as f:
            d = json.load(f)
        cat = d.get('category') or os.path.basename(os.path.dirname(p))
        if 'uid' in d and cat in cats:
            names.add(f'class:{cats[cat] * 1000 + d["uid"]}')
    return names


def otel(pin, offline=False):
    root = checkout(pin, offline)
    names = set()
    for p in glob.glob(os.path.join(root, 'model', '**', '*.yaml'), recursive=True):
        with open(p, encoding='utf-8') as f:
            d = yaml.safe_load(f) or {}
        for a in d.get('attributes', []) or []:
            if isinstance(a, dict) and a.get('key'):
                names.add(a['key'])
        for g in d.get('groups', []) or []:
            for a in g.get('attributes', []) or []:
                k = isinstance(a, dict) and (a.get('id') or a.get('key') or a.get('ref'))
                if isinstance(k, str):
                    names.add(k)
            for k in ('metric_name', 'name', 'id'):
                if isinstance(g.get(k), str):
                    names.add(g[k])
        for kind in ('metrics', 'spans', 'events', 'entities'):
            for g in d.get(kind, []) or []:
                for k in ('name', 'key', 'type', 'id'):
                    if isinstance(g, dict) and isinstance(g.get(k), str):
                        names.add(g[k])
    return names


def aitf(pin, offline=False):
    root = checkout(pin, offline)
    names = set()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == 'properties' and isinstance(v, dict):
                    names.update(v)
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    for p in glob.glob(os.path.join(root, pin.get('path', ''), 'spec', 'schema', '*.json')):
        with open(p, encoding='utf-8') as f:
            walk(json.load(f))
    return names


def odis(pin, offline=False):
    root = checkout(pin, offline)
    with open(os.path.join(root, pin['path']), encoding='utf-8') as f:
        text = f.read()
    # ODIS defines its fields as the first column of its record tables.
    return set(re.findall(r'(?m)^\| *`?([a-z_][a-z0-9_]*)`? *\|', text)) - {'field', 'name'}


RESOLVERS = {'ocsf': ocsf, 'otel_genai': otel, 'otel_semconv': otel, 'aitf': aitf, 'odis': odis}
