"""Link governance mail to the works it approves, and check the registry against it.

The input is the governance events ``ingest/maillist.py`` already extracts: calls for
consensus, review periods, ballots, and "approved by TSC and PGB" notices. Each is a
subject, a date, a list and a Message-ID, plus an outcome label read from the body.

## What counts as approval

A CoSAI release is approved in two stages, and the mail records both:

  1. The TSC approves, by a call for consensus on ``cosai-tsc`` or by a ballot. A
     ballot has no closing message of its own; the only record of its result is the
     PGB call that follows, which restates that the TSC approved.
  2. The PGB approves, by a call for consensus on ``cosai-pgb`` that closes with no
     objections registered.

The closing message of the PGB call is the authoritative record of approval. A
workstream list's "approved by TSC and PGB" notice reports the same decision second
hand, and a document's own approval date is the document's claim about it.

## Why the thread-to-work link is curated

Subjects name works inconsistently -- "WS4 paper on Agentic Identity and Access
Control" is the Agentic Identity and Access Management paper -- and one call can approve
two papers. So a thread is linked to works through ``registry/approvals.yaml``, the
same review gate the series and person registries use. This module proposes links in
``registry/approvals.seed.yaml``; it never writes the curated file.

## What the archive cannot show

The archive shows a call only if one was sent to a list we fetch. The papers released
before September 2025 have no call in it, although the lists' coverage reaches back to
2024. The report therefore says "no approval evidence in the archive", never "not
approved", and the registry records the exception rather than the report guessing.

Run:  python -m bubo_graphrag.ingest.approvals
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from . import maillist as M

# The lists whose calls are decisions. A workstream list only relays them.
DECIDING_LISTS = {"cosai-tsc": "TSC", "cosai-pgb": "PGB"}

# Reply prefixes as observed in the archive: "回复" (Chinese for "reply", with the
# full-width colon) comes from a mail client set to Chinese.
_PREFIX = re.compile(r"^\s*(?:(?:re|fwd?|reply|回复)\s*[:：]\s*|\[[^\]]*\]+\s*"
                     r"|(?:(?:important|urgent)\s+)?reminder\s*[-:]\s*|urgent\s*:\s*"
                     r"|(?:cosai\s+)?action required\s*\]?\s*[:\]]?\s*)+", re.I)
# A reminder restates its call's deadline, which would otherwise split the thread.
_DEADLINE = re.compile(r"\s+(?:due|open until)\b.*$", re.I)
_STAGES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("approval-notice", re.compile(r"\bapproved by\b", re.I)),
    ("review-period", re.compile(r"\breview period\b", re.I)),
    ("ballot", re.compile(r"\bballot\b|\bplease vote\b|\bvote (?:on|for)\b", re.I)),
    ("call-for-consensus", re.compile(r"\bcall for consensus\b", re.I)),
    ("nomination", re.compile(r"\bcall for nominations\b", re.I)),
)
SUBJECT_MATTERS = ("publication", "blog", "people", "governance", "other")
# What a call does to each work it names:
#   new       approves the work itself, first time
#   revision  approves an update to an approved work; never its original approval
#   addition  approves a work as an addition `to` another approved work, which it takes
#             its standing from. The MCP v2 call revised MCP Security and, by addition,
#             approved the PQC Addendum that the same pull request added.
LINK_ROLES = ("new", "revision", "addition")


def thread_key(subject: str) -> str:
    """One call's subject reduced to lowercase words: list tags, reply and forward
    prefixes, "Action Required", reminders and restated deadlines removed. Punctuation
    goes too, so "5 day" and "5-day", or straight and typographic quotes, share a key.
    Every message about one call has the same key."""
    stripped = _PREFIX.sub("", subject)
    stripped = re.sub(r"\[[^\]]*\]\s*", "", stripped)      # an inner [Action Required]
    stripped = _DEADLINE.sub("", stripped)
    return re.sub(r"[^0-9a-z]+", " ", stripped.lower()).strip()


def stage_of(key: str) -> str:
    for stage, pattern in _STAGES:
        if pattern.search(key):
            return stage
    return "other"


def deciding_body(event: M.GovernanceEvent) -> str | None:
    """The body whose call this is. The subject tag wins over the list it arrived on,
    because a TSC call forwarded to a workstream list is still the TSC's."""
    tag = M._SUBJECT_TAG.search(event.subject)
    if tag and tag.group(1).lower() in M.KNOWN_LISTS:
        return DECIDING_LISTS.get(M.KNOWN_LISTS[tag.group(1).lower()][0])
    return DECIDING_LISTS.get(event.list_name)


@dataclass
class Thread:
    key: str
    subject: str                          # first seen, list tag and prefixes removed
    stage: str
    body: str | None = None               # the deciding body the call is keyed on
    bodies: set[str] = field(default_factory=set)
    lists: set[str] = field(default_factory=set)
    opened: str | None = None
    closed: str | None = None
    closing_message_id: str | None = None
    states_tsc_approval: bool = False
    deadline: str | None = None          # the objection deadline the call states
    message_ids: list[str] = field(default_factory=list)

    def as_seed(self, proposed: list[str]) -> dict:
        return {
            "key": self.key, "subject": self.subject, "stage": self.stage,
            "bodies": sorted(self.bodies), "lists": sorted(self.lists),
            "opened": self.opened, "closed": self.closed,
            "deadline": self.deadline, "states_tsc_approval": self.states_tsc_approval,
            "messages": len(self.message_ids), "proposed_works": proposed,
        }


def threads(parse: M.MailParse) -> list[Thread]:
    """Governance events grouped into calls, oldest first.

    A call is its subject key AND its deciding body. The TSC and the PGB are sent
    identically titled review periods, and merged they would give the PGB's close the
    TSC's date. Curation is by subject key, so it covers every body's call alike.
    """
    out: dict[tuple[str, str | None], Thread] = {}
    for event in sorted(parse.governance, key=lambda e: (e.occurred_at or "", e.subject)):
        key = thread_key(event.subject)
        body = deciding_body(event)
        thread = out.get((key, body))
        if thread is None:
            thread = out[(key, body)] = Thread(key=key,
                                               subject=_PREFIX.sub("", event.subject),
                                               stage=stage_of(key), body=body)
        thread.lists.add(event.list_name)
        thread.message_ids.append(event.source_message_id)
        if body:
            thread.bodies.add(body)
        day = (event.occurred_at or "")[:10] or None
        if day and (thread.opened is None or day < thread.opened):
            thread.opened = day
        if event.outcome == "closed" and day and (thread.closed is None or day < thread.closed):
            thread.closed, thread.closing_message_id = day, event.source_message_id
        thread.states_tsc_approval |= event.states_tsc_approval
        if event.deadline and (thread.deadline is None or event.deadline < thread.deadline):
            thread.deadline = event.deadline
    for thread in out.values():
        if thread.stage == "approval-notice":
            # The notice is the report of a decision, so it carries its own date as
            # the close, and names its bodies in the subject rather than by list.
            thread.bodies |= {b for b in ("TSC", "PGB") if b.lower() in thread.key}
            thread.closed = thread.closed or thread.opened
    return sorted(out.values(), key=lambda t: (t.opened or "", t.key))


# --- proposals for the seed --------------------------------------------------------

def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def known_titles() -> dict[str, str]:
    """Normalized title -> work id, over publications, citation-form short titles and
    citation stubs. Used only to propose links; the curated file decides."""
    from ..paths import load_registry, publications

    table: dict[str, str] = {}
    for pub in publications():
        table[_norm(pub["title"].split(",")[0])] = pub["id"]
    forms = load_registry("citation-forms").get("publications") or {}
    for pid, entry in forms.items():
        for title in (entry or {}).get("titles") or []:
            if len(_norm(title)) > 8:                 # "ODIS" alone would match noise
                table.setdefault(_norm(title), pid)
    for title, stub in (load_registry("work-aliases").get("stubs") or {}).items():
        table.setdefault(_norm(title), stub["id"])
    return table


def propose(thread: Thread, titles: dict[str, str]) -> list[str]:
    key = f" {_norm(thread.key)} "
    hits = {pid for title, pid in titles.items() if f" {title} " in key}
    return sorted(hits)


# --- the consistency check ---------------------------------------------------------

@dataclass
class Evidence:
    """What the archive shows about one work's approval."""

    tsc: str | None = None                # date, from a TSC close or a notice
    tsc_basis: str | None = None          # "call closed", "stated in PGB call", "notice"
    tsc_deadline: str | None = None       # when the approving call took effect
    pgb: str | None = None
    pgb_basis: str | None = None
    pgb_deadline: str | None = None
    open_calls: list[tuple[str, frozenset[str]]] = field(default_factory=list)
    revisions: list[str] = field(default_factory=list)   # "2026-08-03 TSC"
    reviews: list[str] = field(default_factory=list)
    # (the work added to, close date, bodies, deadline) for each closed addition call
    additions: list[tuple[str, str, str, str | None]] = field(default_factory=list)

    @property
    def approved(self) -> bool:
        return bool(self.tsc and self.pgb)


def _earlier(current: str | None, candidate: str | None) -> bool:
    """Whether a dated close should replace what is known. A restated "before ..."
    approval is always replaced by a dated one, whatever order the calls are read in."""
    if not candidate:
        return False
    return current is None or current.startswith("before") or candidate < current


def by_key(all_threads: list[Thread]) -> dict[str, list[Thread]]:
    """Curation key -> every body's call under that subject."""
    out: dict[str, list[Thread]] = defaultdict(list)
    for thread in all_threads:
        out[thread.key].append(thread)
    return out


def evidence_by_work(all_threads: list[Thread], curation: dict) -> dict[str, Evidence]:
    grouped = by_key(all_threads)
    out: dict[str, Evidence] = defaultdict(Evidence)
    for key, entry in (curation.get("threads") or {}).items():
        if entry.get("subject_matter") != "publication":
            continue
        for thread in grouped.get(key, []):
            _add_evidence(out, thread, entry)
    return out


def _add_evidence(out: dict[str, Evidence], thread: Thread, entry: dict) -> None:
    """Fold one call into the evidence of each work it names."""
    for link in entry.get("works") or []:
        if not isinstance(link, dict):
            continue                    # reported by findings(), not guessed at
        ev = out[link["id"]]
        if link.get("as") == "revision":
            # Approved by the TSC alone ("not a new work item"); it does not stand
            # in for the work's original approval.
            if thread.closed:
                ev.revisions.append(f"{thread.closed} {'+'.join(sorted(thread.bodies))}")
            continue
        if link.get("as") == "addition":
            if thread.closed and link.get("to"):
                ev.additions.append((link["to"], thread.closed,
                                     "+".join(sorted(thread.bodies)), thread.deadline))
            continue
        if link.get("as") != "new":
            continue
        if thread.stage == "review-period":
            ev.reviews.append(f"{thread.opened} {'+'.join(sorted(thread.bodies))}")
            continue
        if thread.closed is None:
            ev.open_calls.append((thread.subject, frozenset(thread.bodies)))
        basis = "notice" if thread.stage == "approval-notice" else "call closed"
        if "TSC" in thread.bodies and _earlier(ev.tsc, thread.closed):
            ev.tsc, ev.tsc_basis, ev.tsc_deadline = thread.closed, basis, thread.deadline
        if "PGB" in thread.bodies and _earlier(ev.pgb, thread.closed):
            ev.pgb, ev.pgb_basis, ev.pgb_deadline = thread.closed, basis, thread.deadline
        if "PGB" in thread.bodies and thread.states_tsc_approval and ev.tsc is None:
            # The ballot's result is known only from this restatement, and its date
            # only as "before the PGB call opened".
            ev.tsc, ev.tsc_basis = f"before {thread.opened}", "stated in PGB call"


def has_standing(pid: str, evidence: dict[str, Evidence], exceptions: dict,
                 _seen: frozenset[str] = frozenset()) -> bool:
    """Approved in its own right, accepted as an exception, or added by a closed call
    to a work that itself has standing. `_seen` stops an addition cycle."""
    if pid in _seen:
        return False
    ev = evidence.get(pid, Evidence())
    if ev.approved or pid in exceptions:
        return True
    return any(has_standing(parent, evidence, exceptions, _seen | {pid})
               for parent, *_ in ev.additions)


def findings(all_threads: list[Thread], curation: dict, pubs: list[dict],
             stub_ids: set[str]) -> list[str]:
    """Every disagreement between the registry, the curation and the archive."""
    out: list[str] = []
    keys = {t.key for t in all_threads}
    curated = curation.get("threads") or {}
    pub_ids = {p["id"] for p in pubs}
    evidence = evidence_by_work(all_threads, curation)
    exceptions = curation.get("no_archive_evidence") or {}

    unregistered: dict[str, list[str]] = defaultdict(list)
    for key, calls in by_key(all_threads).items():
        if key not in curated:
            out.append(f"uncurated thread: {calls[0].subject!r} ({calls[0].opened})")
    for key, entry in curated.items():
        if key not in keys:
            out.append(f"curated thread not in the archive: {key!r}")
        matter = entry.get("subject_matter")
        if matter not in SUBJECT_MATTERS:
            out.append(f"unknown subject_matter {matter!r} for {key!r}")
        for link in entry.get("works") or []:
            if not isinstance(link, dict) or "id" not in link:
                out.append(f"work link without an id and role in {key!r}: {link!r}")
                continue
            if link.get("as") not in LINK_ROLES:
                out.append(f"work link {link['id']!r} in {key!r} needs `as:` one of "
                           f"{', '.join(LINK_ROLES)}")
            if link["id"] not in pub_ids and link["id"] not in stub_ids:
                out.append(f"unknown work id {link['id']!r} in {key!r}")
            if link.get("as") == "addition":
                parent = link.get("to")
                if parent not in pub_ids and parent not in stub_ids:
                    out.append(f"addition {link['id']!r} in {key!r} needs `to:` a known "
                               f"work, not {parent!r}")
                elif parent == link["id"]:
                    out.append(f"addition {link['id']!r} in {key!r} is added to itself")
        for link in entry.get("unregistered") or []:
            if not isinstance(link, dict) or "title" not in link:
                out.append(f"unregistered link without a title and role in {key!r}")
                continue
            unregistered[link["title"]].append(key)

    for title, thread_keys in unregistered.items():
        out.append(f"governance calls name a work not in the registry: {title!r} "
                   f"({len(thread_keys)} threads)")

    for pub in pubs:
        ev = evidence.get(pub["id"], Evidence())
        status = pub.get("approval_status")
        if status == "approved" and not ev.approved:
            if has_standing(pub["id"], evidence, exceptions):
                continue
            for parent, *_ in ev.additions:
                out.append(f"{pub['id']}: approved as an addition to {parent}, which has "
                           "no approval in the archive")
            if ev.additions:
                continue
            missing = " and ".join(b for b, d in (("TSC", ev.tsc), ("PGB", ev.pgb)) if not d)
            out.append(f"{pub['id']}: registry says approved; no {missing} approval "
                       "in the archive")
        if status != "approved" and ev.approved:
            out.append(f"{pub['id']}: approved in the archive; registry says {status}")
        for subject, bodies in ev.open_calls:
            # Only a gap if nothing else shows that body's decision: an SRF ballot with
            # no close is settled by the PGB call restating the TSC approval.
            if ("TSC" in bodies and not ev.tsc) or ("PGB" in bodies and not ev.pgb):
                out.append(f"{pub['id']}: no closing message found for {subject!r}")
    for pid in exceptions:
        if pid not in pub_ids:
            out.append(f"no_archive_evidence names an unknown publication: {pid!r}")
        elif evidence.get(pid, Evidence()).approved:
            out.append(f"{pid}: listed in no_archive_evidence but the archive now shows "
                       "approval; remove the exception")
    return out


# --- the report ---------------------------------------------------------------------

def _cell(closed: str | None, basis: str | None, deadline: str | None) -> str:
    if not closed:
        return "—"
    return f"{closed} ({basis}{', deadline ' + deadline if deadline else ''})"


def _date_relation(original: str | None, ev: Evidence) -> str:
    if not original:
        return "—"
    # A deadline first: consent takes effect when it passes, so a document dated then
    # is dated correctly even though the closing message came later.
    for label, value in (("= PGB deadline", ev.pgb_deadline), ("= PGB close", ev.pgb),
                         ("= TSC deadline", ev.tsc_deadline), ("= TSC close", ev.tsc)):
        if value == original:
            return label
    import datetime as dt
    addition = ev.additions[0][1] if ev.additions else None
    for label, value in (("PGB", ev.pgb), ("TSC", ev.tsc), ("addition", addition)):
        if value and not value.startswith("before"):
            delta = (dt.date.fromisoformat(original) - dt.date.fromisoformat(value)).days
            return f"{label} {delta:+d} d"
    return "no approval in archive"


def write_report(parse: M.MailParse, all_threads: list[Thread], curation: dict,
                 pubs: list[dict], stub_ids: set[str]) -> str:
    """Subjects, dates and labels only -- no message body reaches this file."""
    evidence = evidence_by_work(all_threads, curation)
    curated = curation.get("threads") or {}
    exceptions = curation.get("no_archive_evidence") or {}
    problems = findings(all_threads, curation, pubs, stub_ids)
    lines = [
        "# Approvals -- governance mail against the publication registry",
        "",
        f"- governance messages: **{len(parse.governance)}**, in "
        f"**{len(all_threads)}** threads ({len(curated)} curated)",
        f"- findings: **{len(problems)}**",
        "",
        "## Coverage",
        "",
        "Approval can be shown only inside these windows, and only for calls sent to a",
        "list we fetch. Outside them, no evidence is not evidence of no approval.",
        "",
        "| list | earliest | latest |",
        "| --- | --- | --- |",
    ]
    for name in sorted(DECIDING_LISTS):
        window = parse.coverage.get(name, {})
        lines.append(f"| `{name}` | {window.get('earliest', '—')} | "
                     f"{window.get('latest', '—')} |")

    lines += ["", "## Publications", "",
              "| id | registry | original_date | TSC | PGB | original_date vs approval |",
              "| --- | --- | --- | --- | --- | --- |"]
    for pub in pubs:
        ev = evidence.get(pub["id"], Evidence())
        tsc = _cell(ev.tsc, ev.tsc_basis, ev.tsc_deadline)
        pgb = _cell(ev.pgb, ev.pgb_basis, ev.pgb_deadline)
        if ev.additions and not ev.approved:
            parent, closed, bodies, deadline = ev.additions[0]
            if "TSC" in bodies.split("+"):
                tsc = _cell(closed, "addition call closed", deadline)
            pgb = f"not required: addition to `{parent}`"
        if pub["id"] in exceptions and not ev.approved:
            pgb = "exception recorded" if pgb == "—" else f"{pgb}; exception recorded"
        original = str(pub.get("original_date") or "") or None
        lines.append(f"| `{pub['id']}` | {pub.get('approval_status')} | {original or '—'} "
                     f"| {tsc} | {pgb} | {_date_relation(original, ev)} |")

    revised = [(pid, ev) for pid, ev in sorted(evidence.items()) if ev.revisions]
    if revised:
        lines += ["", "## Revision approvals", ""]
        lines += [f"- `{pid}`: {', '.join(ev.revisions)}" for pid, ev in revised]

    blogs = [(k, e) for k, e in curated.items() if e.get("subject_matter") == "blog"]
    if blogs:
        grouped = by_key(all_threads)
        lines += ["", "## Blog approvals", "",
                  "TSC calls for consensus on blog posts. Linked to posts once the blog",
                  "layer exists.", ""]
        for key, entry in blogs:
            closes = sorted(t.closed for t in grouped.get(key, []) if t.closed)
            closed = closes[0] if closes else None
            lines.append(f"- {closed or 'no close found'}: "
                         f"{'; '.join(entry.get('blogs') or [key])}")

    if exceptions:
        lines += ["", "## Recorded exceptions", "",
                  "Approved works whose approval is not in the archive, with the reason.", ""]
        lines += [f"- `{pid}`: {reason}" for pid, reason in exceptions.items()]

    lines += ["", "## Findings", ""]
    lines += [f"- {problem}" for problem in problems] or ["- none"]
    return "\n".join(lines) + "\n"


def stub_ids() -> set[str]:
    from ..paths import load_registry
    return {s["id"] for s in (load_registry("work-aliases").get("stubs") or {}).values()}


def main(argv: list[str] | None = None) -> int:
    import yaml

    from ..paths import MAIL, REGISTRY, REPORTS, load_registry, publications

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", nargs="?", type=Path, default=MAIL,
                        help=f"an mbox, or a directory of them (default: {MAIL})")
    args = parser.parse_args(argv)

    paths = M.mbox_paths(args.source)
    if not paths:
        print(f"no .mbox files in {args.source}. Fetch them first:\n"
              "    python -m bubo_graphrag.ingest.groupsio", file=sys.stderr)
        return 1

    parse = M.parse_mboxes(paths)
    all_threads = threads(parse)
    curation = load_registry("approvals") if (REGISTRY / "approvals.yaml").exists() else {}
    titles = known_titles()

    seed = REGISTRY / "approvals.seed.yaml"
    seed.write_text(yaml.safe_dump(
        {"threads": [t.as_seed(propose(t, titles)) for t in all_threads]},
        sort_keys=False, allow_unicode=True, width=100), encoding="utf-8")

    REPORTS.mkdir(parents=True, exist_ok=True)
    report = REPORTS / "approvals.md"
    stubs = stub_ids()
    report.write_text(write_report(parse, all_threads, curation, publications(), stubs),
                      encoding="utf-8")
    problems = findings(all_threads, curation, publications(), stubs)
    print(f"{len(parse.governance)} governance messages -> {len(all_threads)} threads, "
          f"{len(problems)} findings")
    print(f"  {seed}")
    print(f"  {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
