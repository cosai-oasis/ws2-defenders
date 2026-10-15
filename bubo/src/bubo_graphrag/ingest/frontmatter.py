"""Parse document-declared metadata.

What a document *claims* about itself is recorded separately from what
registry/publications.yaml asserts, so discrepancies stay visible rather than being
silently reconciled. The known discrepancy: the WS3 Shared Responsibility Framework
declares `author: "Workstream 2: ..."` while living in ws3-ai-risk-governance. The
registry (i.e. the repo) wins; the claim is retained as evidence.

Two metadata styles exist in the corpus:

  yaml-frontmatter   11 documents -- a `---` delimited YAML block
  bold-header-block  CoSAI-AI-Telemetry-RFC.md -- an h1 with the version inline
                     (`# Telemetry for AI Security {**Working Draft v0.5**}`) followed
                     by `**Status:**` / `**Origin:**` / `**Disclosure:**` lines
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

FRONT_MATTER = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*\r?\n", re.S)
H1_WITH_VERSION = re.compile(r"^#\s+(?P<title>.+?)\s*\{\*\*(?P<version>[^}]+?)\*\*\}\s*$", re.M)
BOLD_FIELD = re.compile(r"^\*\*(?P<key>[A-Za-z][A-Za-z ]{2,30}):\*\*\s*(?P<value>.+?)\s*$", re.M)

MONTHS = {
    m.lower(): i
    for i, m in enumerate(
        ["January", "February", "March", "April", "May", "June", "July",
         "August", "September", "October", "November", "December"], start=1)
}
# Accept the abbreviated forms too, defensively.
MONTHS.update({m[:3]: i for m, i in list(MONTHS.items())})

_DMY = re.compile(r"^(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})$")
_MDY = re.compile(r"^([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})$")
_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")


def parse_date(value: Any) -> dt.date | None:
    """Parse the four date shapes in the corpus, tolerantly.

    `12 June 2025`, `8 January 2026`, `2026-09-05`, and already-parsed dates (PyYAML
    coerces unquoted ISO dates to datetime.date on its own). Returns None rather than
    raising, because a missing or unparseable date is a data-quality finding for
    reports/unresolved.md, not a crash.
    """
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    text = str(value).strip().strip('"').strip()
    if not text:
        return None
    if m := _ISO.match(text):
        y, mo, d = (int(g) for g in m.groups())
        return _safe_date(y, mo, d)
    if m := _DMY.match(text):
        d, month, y = m.group(1), m.group(2).lower(), m.group(3)
        if (mo := MONTHS.get(month)) :
            return _safe_date(int(y), mo, int(d))
    if m := _MDY.match(text):
        month, d, y = m.group(1).lower(), m.group(2), m.group(3)
        if (mo := MONTHS.get(month)) :
            return _safe_date(int(y), mo, int(d))
    return None


def _safe_date(y: int, m: int, d: int) -> dt.date | None:
    try:
        return dt.date(y, m, d)
    except ValueError:
        return None


@dataclass
class DeclaredMetadata:
    """Metadata as the document declares it. Not authoritative; evidence."""

    style: str
    title: str | None = None
    author: str | None = None
    date: dt.date | None = None
    last_updated: dt.date | None = None
    version: str | None = None
    status: str | None = None
    revision_note: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    body_offset: int = 0

    @property
    def declared_workstream_number(self) -> int | None:
        """Workstream number the `author`/`Origin` field claims, if any.

        Only used to detect disagreement with the registry; never to set the value.
        """
        for text in (self.author, self.raw.get("Origin")):
            if not text:
                continue
            if m := re.search(r"[Ww]orkstream\s*(\d)", str(text)):
                return int(m.group(1))
        return None


def parse(text: str) -> DeclaredMetadata:
    """Extract declared metadata, dispatching on style."""
    if m := FRONT_MATTER.match(text):
        return _parse_yaml_front_matter(m)
    return _parse_bold_header_block(text)


def _parse_yaml_front_matter(match: re.Match[str]) -> DeclaredMetadata:
    try:
        data = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return DeclaredMetadata(
        style="yaml-frontmatter",
        title=_str(data.get("title")),
        author=_str(data.get("author")),
        date=parse_date(data.get("date")),
        last_updated=parse_date(data.get("last_updated")),
        version=_str(data.get("version")),
        status=_str(data.get("status")),
        revision_note=_str(data.get("revision_note")),
        raw=data,
        body_offset=match.end(),
    )


def _parse_bold_header_block(text: str) -> DeclaredMetadata:
    head = text[:4000]
    title = version = None
    if m := H1_WITH_VERSION.search(head):
        title = m.group("title").strip()
        version = m.group("version").strip()
    elif m := re.search(r"^#\s+(.+?)\s*$", head, re.M):
        title = m.group(1).strip()

    fields = {m.group("key").strip(): m.group("value").strip()
              for m in BOLD_FIELD.finditer(head)}
    if not fields and title is None:
        return DeclaredMetadata(style="none")

    # `Status: Request for Comments, revision 0.5` carries the version when the h1
    # brace form is absent.
    if version is None and (status := fields.get("Status")):
        if m := re.search(r"revision\s*([\d.]+)", status, re.I):
            version = m.group(1)

    return DeclaredMetadata(
        style="bold-header-block",
        title=title,
        author=fields.get("Origin"),
        date=parse_date(fields.get("Date")),
        version=version,
        status=fields.get("Status"),
        raw=fields,
    )


def _str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).strip() or None
