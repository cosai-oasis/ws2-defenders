"""Markdown table helpers shared by extract.py and build.py."""
import re


def cells(line):
    """Split a table row into cells. No cell in the documents contains a pipe."""
    assert line.startswith('| ') and line.endswith(' |'), line
    return line[2:-2].split(' | ')


def row(values):
    return '| ' + ' | '.join(values) + ' |'


def gh_anchor(heading):
    """GitHub heading anchor: one hyphen per space, runs not collapsed."""
    h = re.sub(r'[`*_]', '', heading).lower().strip()
    return re.sub(r'[^\w\s-]', '', h).replace(' ', '-')


def find_tables(lines, heading_re, stop_re):
    """Yield (heading match, start, end) for the first table under each matching heading.

    start is the header line; end is one past the last row.
    """
    i = 0
    while i < len(lines):
        if re.match(stop_re, lines[i]):
            return
        m = re.match(heading_re, lines[i])
        if m:
            k = i + 1
            while k < len(lines) and not lines[k].startswith('|') and not re.match(r'^#{2,3} ', lines[k]):
                k += 1
            if k < len(lines) and lines[k].startswith('|'):
                j = k
                while j < len(lines) and lines[j].startswith('|'):
                    j += 1
                yield m, k, j
                i = j
                continue
        i += 1
