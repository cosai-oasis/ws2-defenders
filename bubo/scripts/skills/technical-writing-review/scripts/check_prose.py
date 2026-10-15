#!/usr/bin/env python3
"""Check Markdown documents against the technical writing conventions.

Usage:  python3 check_prose.py [--allow TEXT]... [--rfc2119] [--json] FILE...

Rule IDs match the technical-writing-style and technical-writing-review skills:

  P1  logos only: no appeals to ethos or pathos
  P2  no retrospective framing
  P3  no work notes in the body
  P4  RFC 2119 keywords in capitals only (--rfc2119; reported as warnings)
  P5  no subsection x.1 without an x.2
  P6  no em or en dashes
  S1  intra-document anchors resolve
  S2  no duplicate headings
  S3  no double-spaced headings
  S4  table rows have a consistent column count
  S5  numbered sections are contiguous and every section reference resolves

Fenced code blocks and inline code are not scanned, so a rule can quote the word it
bans. --allow exempts a verbatim string, such as an official title that contains an
em dash, from P1, P2, P3 and P6. P3 and P4 are heuristics: a hit asks for judgment,
and a clean run does not prove the rule holds.

Standard library only. Exit status is 1 if any failure is found, 0 otherwise;
warnings never fail.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict

ETHOS_PATHOS = re.compile(
    r"\bhonest\w*|\bcandid(?:ly)?\b|\bfrankly\b|\badmittedly\b|\bto be fair\b"
    r"|\bworth stating plainly\b|\bapologi\w*", re.I)
RETROSPECTIVE = re.compile(
    r"\b(?:this|previous|prior|last) revision\b|\bearlier (?:revisions?|drafts?|versions?)\b"
    r"|\bpreviously (?:only|an? |the |\"|treated|followed|tracked|argued|proposed|recorded)"
    r"|\bno longer treated\b|\bhitherto\b|\bused to be\b", re.I)
WORK_NOTE = re.compile(
    r"\bTODO\b|\bTBD\b|\bFIXME\b|\bXXX\b|\bto be (?:verified|confirmed|checked)\b"
    r"|\bpre-publication\b|\bbefore publication\b|\bnote to (?:editors?|reviewers?)\b", re.I)
LOWER_2119 = re.compile(
    r"\b(?:must not|must|shall not|shall|should not|should|required|recommended)\b")
DASHES = re.compile("[–—]")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
NUMBERED = re.compile(r"^(?:§\s*)?((?:\d+|[A-Z])(?:\.\d+)+)\.?(?:\s|$)")
TOP_SECTION = re.compile(r"^## (\d+)\. ")


def blank(match: re.Match) -> str:
    return " " * len(match.group(0))


def unfenced_lines(text: str) -> list[str]:
    """The document with fenced code blocks blanked, line numbers preserved."""
    out, fence = [], None
    for line in text.split("\n"):
        opener = re.match(r"^\s*(`{3,}|~{3,})", line)
        if fence:
            if opener and opener.group(1)[0] == fence[0] and len(opener.group(1)) >= len(fence):
                fence = None
            out.append("")
            continue
        if opener:
            fence = opener.group(1)
            out.append("")
            continue
        out.append(line)
    return out


def slug(heading: str) -> str:
    heading = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    heading = re.sub(r"\{#[^}]*\}", "", heading)
    heading = re.sub(r"`|\*\*|\*|_", "", heading).lower().strip()
    return re.sub(r"[^\w\s-]", "", heading).replace(" ", "-")


def check(path: str, text: str, allow: list[str], rfc2119: bool) -> list[dict]:
    findings: list[dict] = []

    def add(rule: str, line: int, message: str, level: str = "fail") -> None:
        findings.append({"file": path, "line": line, "rule": rule,
                         "level": level, "message": message})

    # Headings, anchors and tables are read with inline code intact, because code is
    # part of a heading's text and its slug; only the prose rules skip inline code.
    lines = unfenced_lines(text)
    prose = [re.sub(r"(`+).+?\1", blank, line) for line in lines]
    scan = []
    for line in prose:
        for phrase in allow:
            line = line.replace(phrase, " " * len(phrase))
        scan.append(line)

    for n, line in enumerate(scan, 1):
        for m in ETHOS_PATHOS.finditer(line):
            add("P1", n, f"ethos or pathos word: {m.group(0)!r}")
        for m in RETROSPECTIVE.finditer(line):
            add("P2", n, f"retrospective framing: {m.group(0)!r}")
        for m in WORK_NOTE.finditer(line):
            add("P3", n, f"work note in the body: {m.group(0)!r}")
        if DASHES.search(line):
            add("P6", n, "em or en dash; use a comma, colon, parentheses, or 'to' for ranges")
        if rfc2119:
            for m in LOWER_2119.finditer(prose[n - 1]):
                add("P4", n, f"lowercase {m.group(0)!r}: capitalize it if it is normative, "
                             "otherwise rephrase so it cannot be read as a requirement",
                    level="warn")

    headings = []
    for n, line in enumerate(lines, 1):
        m = HEADING.match(line)
        if m:
            headings.append((n, m.group(2), line))

    children = defaultdict(list)
    for n, title, _ in headings:
        m = NUMBERED.match(title)
        if m:
            number = m.group(1)
            children[number.rsplit(".", 1)[0]].append((n, number))
    for parent, kids in children.items():
        if len(kids) == 1:
            n, number = kids[0]
            add("P5", n, f"subsection {number} is the only child of {parent}; "
                         "add a sibling or fold it into its parent")

    anchors, seen = set(), defaultdict(int)
    for _, title, _ in headings:
        base = slug(title)
        anchors.add(base if not seen[base] else f"{base}-{seen[base]}")
        seen[base] += 1
    anchors |= set(re.findall(r"\{#([^}\s]+)\}", text))
    anchors |= set(re.findall(r"<a\s+(?:name|id)=\"([^\"]+)\"", text))
    for n, line in enumerate(prose, 1):
        for target in re.findall(r"\]\(#([^)\s]+)\)", line):
            if target not in anchors:
                add("S1", n, f"broken anchor: #{target}")

    first = {}
    for n, title, raw in headings:
        if title in first:
            add("S2", n, f"duplicate heading {title!r} (first at line {first[title]})")
        else:
            first[title] = n
        if re.match(r"^#{1,6} .*\S  +\S", raw):
            add("S3", n, "double space inside heading")

    block: list[tuple[int, str]] = []
    for n, line in enumerate(lines + [""], 1):
        if line.strip().startswith("|"):
            block.append((n, line))
            continue
        widths = {re.sub(r"\\\|", "", row).count("|") for _, row in block}
        if len(block) > 1 and len(widths) > 1:
            add("S4", block[0][0], f"table rows have differing column counts: {sorted(widths)}")
        block = []

    sections = [(n, int(m.group(1))) for n, line in enumerate(lines, 1)
                if (m := TOP_SECTION.match(line))]
    if sections:
        numbers = [s for _, s in sections]
        if numbers != list(range(1, len(numbers) + 1)):
            add("S5", sections[0][0], f"numbered sections are not contiguous from 1: {numbers}")
        for n, line in enumerate(prose, 1):
            for ref in re.findall(r"§§?\s*(\d+)", line):
                if int(ref) not in numbers:
                    add("S5", n, f"§{ref} does not match any numbered section")

    return sorted(findings, key=lambda f: (f["line"], f["rule"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("files", nargs="+")
    parser.add_argument("--allow", action="append", default=[], metavar="TEXT",
                        help="verbatim text exempt from P1, P2, P3 and P6; repeatable")
    parser.add_argument("--rfc2119", action="store_true",
                        help="warn on lowercase requirement keywords (P4)")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = parser.parse_args(argv)

    findings = []
    for path in args.files:
        with open(path, encoding="utf-8") as handle:
            findings += check(path, handle.read(), args.allow, args.rfc2119)

    if args.json:
        print(json.dumps(findings, indent=2, ensure_ascii=False))
    else:
        for f in findings:
            print(f"{f['file']}:{f['line']}: {f['rule']} {f['level'].upper()} {f['message']}")
        fails = sum(f["level"] == "fail" for f in findings)
        warns = len(findings) - fails
        print(f"{fails} failure(s), {warns} warning(s)")
    return 1 if any(f["level"] == "fail" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
