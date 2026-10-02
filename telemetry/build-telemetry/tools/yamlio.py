"""YAML layout shared by the data tools: block mappings, short lists inline, no wrapping."""
import yaml


class Dumper(yaml.SafeDumper):
    pass


def _list(d, v):
    flow = bool(v) and all(isinstance(x, str) and len(x) < 40 for x in v)
    return d.represent_sequence('tag:yaml.org,2002:seq', v, flow_style=flow)


Dumper.add_representer(list, _list)


def load(path):
    with open(path, encoding='utf-8') as f:
        return yaml.safe_load(f)


def dump(obj, path, comment=''):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(comment)
        yaml.dump(obj, f, Dumper=Dumper, sort_keys=False, allow_unicode=True, width=10**6)
