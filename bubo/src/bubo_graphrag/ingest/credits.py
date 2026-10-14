"""Parse contribution credit from publication markdown.

Three structural formats exist in the corpus:

  bold-label     ``**Workstream Leads**`` paragraph labels under a single
                 ``## Contributors and Acknowledgements`` heading. 7 documents.
                 WS3 puts the colon inside the emphasis (``**Editors:**``) and the TSC
                 label puts it outside (``**...Co-Chairs**:``); both occur.
  heading-label  role names are themselves headings: ``## 7.1. Workstream Leads``
                 (AI-Incident-Response) or ``## Contributors`` (Zero Trust).
  none           Addendum-MCP-and-PQC and the Telemetry RFC have no credit section;
                 ODIS names authors in front matter only.

Everything here is deliberately conservative. A line that cannot be parsed with
confidence is emitted as a ``Finding`` for reports/unresolved.md rather than guessed
at, because a wrong merge or a wrong split is a wrong attribution, and that is the one
class of error this tool must not ship.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --- Region location -------------------------------------------------------------

_HEADING = re.compile(r"^(?P<hashes>#{1,6})[ \t]+(?P<text>.+?)[ \t]*$", re.M)
# Leading section numbering, with markdown-escaped dots: "6\. ", "7.1. ", "12. "
_NUMBERING = re.compile(r"^[\d]+(?:\\?\.[\d]*)*\\?\.?[ \t]*")
_ACK_HEADING = re.compile(r"^(?:contributors\s+and\s+)?acknowledge?ments?$", re.I)
_CONTRIB_HEADING = re.compile(r"^contributors?$", re.I)

# --- Role labels -----------------------------------------------------------------

# `**Label**`, `**Label:**`, `**Label**:` -- all three occur.
_BOLD_LABEL = re.compile(r"^\*\*(?P<text>[^*]{3,60}?):?\*\*:?[ \t]*$", re.M)
_ROLE_WORDS = re.compile(r"workstream lead|editor|contributor|reviewer|co-?chair|author", re.I)

# --- Person lines ----------------------------------------------------------------

_BULLET = re.compile(r"^[ \t]*[-*][ \t]+(?P<body>.+?)[ \t]*$")
_MD_LINK = re.compile(r"\[(?P<label>[^\]]*)\]\((?P<href>[^)]*)\)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\.[A-Za-z]{2,}")
_GH_HANDLE = re.compile(r"@(?P<login>[A-Za-z0-9][A-Za-z0-9-]{0,38})")
_PAREN_NOTE = re.compile(r"\(([^()]*)\)")
_DAGGER = re.compile(r"[*_]*[†‡][*_]*")
_EMPHASIS = re.compile(r"[*_]{1,3}")

# Prose that leaked in from the boilerplate following a credit section. Deliberately
# NOT keyed on sentence punctuation: "J.R. Rao, IBM" contains ". R" and a punctuation
# rule silently dropped a TSC co-chair from eight documents. Token count plus lowercase
# function words separate a name from a sentence without touching initials.
_PROSE_STOPWORDS = frozenset(
    "a an and are as at be been but by can for from has have if in is it its must not "
    "of on or should that the their there these this to was were which will with would "
    "you your".split()
)
_MAX_NAME_TOKENS = 9

_ORG_KEYWORDS = re.compile(
    r"\b(?:inc|llc|ltd|corp|corporation|technologies|technology|labs?|"
    r"university|institute|foundation|group|systems|software|security|"
    r"ai|io|studio|consulting|independent|indepedent)\b",
    re.I,
)


@dataclass
class Credit:
    """One credited person on one publication, as literally stated."""

    publication_id: str
    source_label: str          # verbatim role heading, e.g. "TSC reviewers"
    raw_line: str              # verbatim bullet body, for audit
    name: str | None = None
    organization: str | None = None
    emails: list[str] = field(default_factory=list)
    github_login: str | None = None
    equal_contribution: bool = False
    scope_note: str | None = None   # e.g. "§4", "named 2026-08-25"
    format: str = "bold-label"


@dataclass
class Finding:
    """A parse decision a human should confirm."""

    publication_id: str
    kind: str
    detail: str
    raw_line: str = ""


@dataclass
class CreditParse:
    publication_id: str
    format: str
    credits: list[Credit] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def _strip_numbering(text: str) -> str:
    return _NUMBERING.sub("", text).strip()


def _is_stop_heading(text: str, stop_headings: list[str]) -> bool:
    plain = _strip_numbering(text).lower().rstrip(":")
    return any(plain.startswith(s.lower()) for s in stop_headings)


def find_credit_region(text: str, stop_headings: list[str]) -> tuple[int, int] | None:
    """Return (start, end) offsets of the credit section, or None.

    Takes the LAST matching heading: every document with an auto-generated table of
    contents repeats the acknowledgements heading near the top, and in
    agentic-identity-and-access-control.md the TOC entry sits at offset 2788 while the
    real section is at 43614.
    """
    matches = [
        m for m in _HEADING.finditer(text)
        if _ACK_HEADING.match(_strip_numbering(m.group("text")))
    ]
    if not matches:
        return None
    start_match = matches[-1]
    level = len(start_match.group("hashes"))
    start = start_match.end()

    for m in _HEADING.finditer(text, start):
        heading = m.group("text")
        if _is_stop_heading(heading, stop_headings):
            return start, m.start()
        plain = _strip_numbering(heading)
        # A role name as a heading continues the region; anything else at the same or
        # shallower level ends it.
        if _ROLE_WORDS.search(plain) or _CONTRIB_HEADING.match(plain):
            continue
        if len(m.group("hashes")) <= level:
            return start, m.start()
    return start, len(text)


# --- Person-line parsing ---------------------------------------------------------

def _looks_like_prose(text: str) -> bool:
    """True if a line reads as a sentence rather than a credit.

    Three independent signals, none of which fires on a personal name:
    a colon introducing a clause, an excessive token count, and lowercase function
    words. "J.R. Rao, IBM" and "Asmae Mhassni , Intel" pass; "Selection of AI systems:
    CoSAI recommends the use of reputable AI systems" does not.
    """
    if len(text) > 90:
        return True
    if ": " in text:
        return True
    tokens = text.replace(",", " ").split()
    if len(tokens) > _MAX_NAME_TOKENS:
        return True
    # Function words only count as prose in quantity, and only on a line long enough to
    # be a sentence. A single hit would reject real names: "An Nguyen" and "Le Van Do"
    # both open with a token that is also an English function word.
    if len(tokens) < 5:
        return False
    hits = {t.lower().strip(".") for t in tokens} & _PROSE_STOPWORDS
    return len(hits) >= 2


def _looks_like_person_name(segment: str) -> bool:
    """Heuristic: 2-4 tokens that look like a personal name."""
    s = segment.strip()
    if not s or any(ch.isdigit() for ch in s):
        return False
    if _ORG_KEYWORDS.search(s):
        return False
    tokens = s.split()
    if not 2 <= len(tokens) <= 4:
        return False
    # Every token starts uppercase, or is an initial pattern like "J.R." / "R."
    return all(t[0].isupper() or re.match(r"^[A-Z]\.", t) for t in tokens if t)


def parse_person_line(
    body: str,
    publication_id: str,
    source_label: str,
    fmt: str,
) -> tuple[list[Credit], list[Finding]]:
    """Parse one bullet body into one or more credits.

    Handles every variant observed in the corpus: markdown mailto links, bare
    parenthesised emails, markdown-escaped underscores in addresses, equal-contribution
    daggers, GitHub handles with section scopes, stray commas and spaces, and lines
    naming several people at once.
    """
    raw = body
    findings: list[Finding] = []

    # 1. Emails, from markdown links and from bare text. Unescape `\_` before
    #    capturing, or `Josiah\_Hagen@trendmicro.com` hashes differently from
    #    `josiah_hagen@trendmicro.com`.
    emails: list[str] = []
    def _take_link(m: re.Match[str]) -> str:
        href, label = m.group("href"), m.group("label")
        if href.lower().startswith("mailto:"):
            emails.append(href[7:])
            return ""
        if "@" in label:
            emails.append(label)
            return ""
        return label
    work = _MD_LINK.sub(_take_link, body)
    for m in _EMAIL.finditer(work):
        emails.append(m.group(0))
    work = _EMAIL.sub("", work)
    emails = _dedupe([e.replace("\\_", "_").replace("\\.", ".").strip().lower() for e in emails])

    # 2. Equal-contribution marker.
    equal = bool(_DAGGER.search(work))
    work = _DAGGER.sub("", work)

    # 3. GitHub handle.
    github_login = None
    if m := _GH_HANDLE.search(work):
        github_login = m.group("login")
        work = work[: m.start()] + work[m.end():]

    # 4. Parenthetical notes: `(§4)`, `(named 2026-08-25)`. Emails are already gone, so
    #    anything left in parentheses is an annotation.
    scope_note = None
    notes = [n.strip() for n in _PAREN_NOTE.findall(work) if n.strip()]
    if notes:
        scope_note = "; ".join(notes)
    work = _PAREN_NOTE.sub("", work)

    # 5. Residual emphasis and whitespace.
    work = _EMPHASIS.sub("", work).replace("\\", "")
    work = re.sub(r"\s+", " ", work).strip().strip(",").strip()

    if not work and github_login:
        return [Credit(publication_id, source_label, raw, name=None,
                       github_login=github_login, equal_contribution=equal,
                       scope_note=scope_note, emails=emails, format=fmt)], findings

    if not work:
        findings.append(Finding(publication_id, "empty-credit-line",
                                "no name recoverable", raw))
        return [], findings

    # 6. Reject prose that bled in from the boilerplate after the credit section.
    if _looks_like_prose(work):
        findings.append(Finding(publication_id, "rejected-as-prose",
                                f"did not look like a person: {work[:80]!r}", raw))
        return [], findings

    # 7. Arity. `Name, Org` is overwhelmingly the common case; three or more segments
    #    that all look like personal names is the multi-person line.
    segments = [s.strip() for s in work.split(",")]
    segments = [s for s in segments if s]

    if len(segments) >= 3 and all(_looks_like_person_name(s) for s in segments):
        findings.append(Finding(
            publication_id, "multi-person-line",
            f"read as {len(segments)} people, no organization: {segments}", raw))
        return [
            Credit(publication_id, source_label, raw, name=s, organization=None,
                   emails=emails if len(segments) == 1 else [],
                   equal_contribution=equal, scope_note=scope_note, format=fmt)
            for s in segments
        ], findings

    if len(segments) > 2:
        # e.g. "Name, Dell, Inc" -- rejoin the tail as one organization.
        name, organization = segments[0], ", ".join(segments[1:])
        findings.append(Finding(
            publication_id, "ambiguous-arity",
            f"read as name={name!r} organization={organization!r}", raw))
    elif len(segments) == 2:
        name, organization = segments[0], segments[1]
    else:
        name, organization = segments[0], None

    if not _looks_like_person_name(name) and " " not in name:
        findings.append(Finding(publication_id, "unusual-name",
                                f"single-token name {name!r}", raw))

    return [Credit(publication_id, source_label, raw, name=name,
                   organization=organization, emails=emails,
                   github_login=github_login, equal_contribution=equal,
                   scope_note=scope_note, format=fmt)], findings


def _dedupe(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for i in items:
        if i:
            seen.setdefault(i, None)
    return list(seen)


# --- Section walk ----------------------------------------------------------------

def parse(
    text: str,
    publication_id: str,
    role_labels: set[str],
    stop_headings: list[str],
) -> CreditParse:
    """Parse the credit section of one document."""
    region = find_credit_region(text, stop_headings)
    if region is None:
        return CreditParse(publication_id, format="none")

    start, end = region
    body = text[start:end]
    fmt = "heading-label" if _uses_heading_labels(body) else "bold-label"
    result = CreditParse(publication_id, format=fmt)

    current: str | None = None
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if m := _HEADING.match(line):
            label = _strip_numbering(m.group("text")).rstrip(":").strip()
            current = label if _is_role(label, role_labels) else None
            continue

        if m := _BOLD_LABEL.match(line):
            label = m.group("text").strip().rstrip(":").strip()
            current = label if _is_role(label, role_labels) else None
            continue

        if not current:
            continue

        if m := _BULLET.match(line):
            credits, findings = parse_person_line(
                m.group("body"), publication_id, current, fmt)
            result.credits.extend(credits)
            result.findings.extend(findings)

    if not result.credits:
        result.findings.append(Finding(
            publication_id, "empty-credit-section",
            "credit heading found but no credits parsed"))
    return result


def _uses_heading_labels(body: str) -> bool:
    for m in _HEADING.finditer(body):
        if _ROLE_WORDS.search(_strip_numbering(m.group("text"))):
            return True
    return False


def _is_role(label: str, role_labels: set[str]) -> bool:
    """A label is a role if the registry knows it, or it clearly reads as one.

    Registry misses are reported by the caller rather than silently accepted, so a new
    CoSAI role label becomes a human decision.
    """
    if label in role_labels:
        return True
    return bool(_ROLE_WORDS.search(label)) and len(label) <= 60


def parse_frontmatter_authors(
    author_field: str, publication_id: str
) -> tuple[list[Credit], list[Finding]]:
    """Parse ODIS-style front-matter authorship: `Name (Org), Name (Org)`.

    Distinct from credit-section parsing: organizations are parenthesised rather than
    comma-separated, so commas here always separate people.
    """
    credits: list[Credit] = []
    findings: list[Finding] = []
    if not author_field or re.match(r"^\s*Workstream\s*\d", author_field, re.I):
        return credits, findings

    for chunk in re.split(r",(?![^(]*\))", author_field):
        chunk = chunk.strip()
        if not chunk:
            continue
        organization = None
        if m := re.match(r"^(?P<name>[^(]+?)\s*\((?P<org>[^)]+)\)\s*$", chunk):
            name, organization = m.group("name").strip(), m.group("org").strip()
        else:
            name = chunk
        if not _looks_like_person_name(name):
            findings.append(Finding(publication_id, "frontmatter-author-unclear",
                                    f"not parsed as a person: {chunk!r}", author_field))
            continue
        credits.append(Credit(publication_id, "Authors", chunk, name=name,
                              organization=organization, format="frontmatter"))
    return credits, findings
