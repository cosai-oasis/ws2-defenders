"""Parse CoSAI meeting occurrences from list-mail archives.

The input is the set of mboxes written by ``ingest/groupsio.py``, one per list, pulled
from the groups.io API with each list's full history. Any mbox works, so a single
archive can also be parsed directly.

## What this source does and does not contain

  * Meeting **occurrences** are here: ``Now:`` and ``Event:`` calendar notices and
    cancellations, dated from an iCalendar part where one exists, else from the body's
    "When:" line, else from the subject.
  * Meeting **summaries** are *not* here. The summary messages are notifications whose
    body is two links and a signature pointing at Google Docs and Drive. Those docs
    return HTTP 401 to an anonymous fetch, so they are ACL-restricted to CoSAI members,
    not link-shared.
  * **Attendance is not available at all.** No summary body names attendees, and
    iCalendar parts carry no ``ATTENDEE`` lines, so not even an invitee list exists
    here. A meeting therefore gets a ``MeetingSummary`` node flagged
    ``accessRestricted``, recording that a record exists and where, and the graph says
    attendance is unknown rather than implying nobody came.

## Why iCalendar is preferred over the subject line

iCalendar gives the series/occurrence split directly: ``UID`` is stable per series and
``RECURRENCE-ID`` identifies the occurrence within it, with ``DTSTART``/``DTEND`` in UTC
and ``STATUS:CANCELLED`` on the cancellations. The body's "When:" line gives the same
start and end without the UID. Subject strings are the last resort, and they drift --
``CoSAI WS1 Meeting (updated link)`` and ``CoSAI WS1 Weekly Meeting`` are one series --
so series identity resolves through ``registry/meeting-series.yaml`` aliases, the same
curated-registry discipline the person and organization registries use.

## The privacy boundary

The filter is an **allowlist applied before anything is retained**: a message is read
only if its ``List-Id`` is a known CoSAI list, or its subject carries a ``[cosai-*]``
tag (replies and forwards lose ``List-Id`` but keep the tag). Anything else is counted
and discarded, never parsed, cached or logged. The allowlist is
``registry/mail-lists.yaml``, the same file that selects what gets fetched.

A per-group archive is CoSAI mail by construction. The allowlist is kept, and kept
strict, for two reasons: it is what assigns each message to a canonical list and
workstream, and an mbox from any other source is filtered the same way.

Addresses are hashed, never stored. The graph needs a matching key, not an address, so
this module emits ``sha256`` only and no module above it ever sees an address.
"""

from __future__ import annotations

import functools
import hashlib
import mailbox
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.header import decode_header, make_header
from email.message import Message
from pathlib import Path
from typing import Iterable

# --- The list allowlist ----------------------------------------------------------

# CoSAI is an OASIS *Open Project*, so its lists are groups.io-hosted at
# lists.oasis-open-projects.org -- not the lists.oasis-open.org TC archive.
LIST_DOMAIN = "lists.oasis-open-projects.org"


def _known_lists() -> dict[str, tuple[str, str]]:
    """Every recognized list spelling -> (canonical list, workstream).

    The `-ws` suffix appears in `List-Id` but is dropped from the subject tag, so the
    same list arrives under two spellings depending on whether a message was posted to
    the list or replied/forwarded. Both map to one canonical list, or the coverage
    window splits in half and every per-list count is wrong.

    Read from `registry/mail-lists.yaml`, which is also what `ingest/groupsio.py`
    fetches -- one source, so a list cannot be downloadable but unparseable. Unlike
    `series_aliases`, a missing registry raises rather than degrading to empty: this
    is the privacy boundary, and an empty allowlist discards every message silently,
    which looks identical to an archive with no CoSAI mail in it.
    """
    from ..paths import mail_lists

    table: dict[str, tuple[str, str]] = {}
    for entry in mail_lists():
        for spelling in entry["spellings"]:
            table[spelling.lower()] = (entry["canonical"], entry["workstream"])
    return table


KNOWN_LISTS = _known_lists()

_SUBJECT_TAG = re.compile(r"\[(cosai[-\w]*)\]", re.I)
_LIST_ID = re.compile(r"<?([\w-]+)\." + re.escape(LIST_DOMAIN) + r">?")

# --- Message classification ------------------------------------------------------

# Ordered: the first match wins, so the specific patterns precede the general ones.
_KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cancellation", re.compile(r"\bcancelled event\b", re.I)),
    ("cancellation", re.compile(r"^\s*(?:\[[^\]]+\]\s*)?No\b.{0,70}?"
                                r"\b(?:meeting|this week|next week|today)\b", re.I)),
    ("summary", re.compile(r"\]\s*\d{4}-\d{2}-\d{2}\b")),
    ("summary", re.compile(r"\b(?:summar(?:y|ies)|minutes|meeting records)\b", re.I)),
    ("agenda", re.compile(r"\bagenda\b", re.I)),
    ("occurrence", re.compile(r"\bNow:\s", re.I)),
    ("invitation", re.compile(r"you'?re invited|#cal-invite|\bEvent:\s", re.I)),
    ("schedule-change", re.compile(r"new meeting invite|changes? to .{0,40}"
                                   r"(?:meeting|schedule)|meeting schedule", re.I)),
    ("governance", re.compile(r"call for consensus|action required|review period"
                              r"|call for nominations|please vote"
                              r"|approved by (?:the )?(?:tsc|pgb)", re.I)),
)

# "Now: CoSAI TSC meeting - Tuesday, 18 August 2026 #cal-notice", and the same shape
# after "Event:" or "Cancelled Event:". Those two used to arrive with a calendar part
# and never reached the subject rules; from getmessages they have none.
_NOW_SUBJECT = re.compile(r"\]\s*(?:Now|(?:Cancelled |Updated )?Event):\s*"
                          r"(?:HOLD\s*-\s*)?(?P<name>.+?)\s+-\s+\w+day,\s*"
                          r"(?P<date>[^#]+?)\s*(?:#|$)")

# The groups.io calendar notice body: "When: Friday, 27 September 2024 1:00pm to
# 2:00pm (UTC-04:00) America/New York". The offset makes it exact in UTC, which is
# what the calendar part would have given, minus UID, RRULE and RECURRENCE-ID.
_TIME = r"\d{1,2}(?::\d{2})?\s*[ap]m"
_WHEN = re.compile(r"When:\s*(?:\w+day,\s*)?(?P<date>\d{1,2} \w+ \d{4})\s+"
                   rf"(?P<start>{_TIME})\s+to\s+"
                   r"(?:(?:\w+day,\s*)?(?P<date2>\d{1,2} \w+ \d{4})\s+)?"
                   rf"(?P<end>{_TIME})\s*\((?:UTC|GMT)(?P<offset>[+-]\d{{2}}:\d{{2}})\)",
                   re.I)
# "Event: CoSAI WS2 - Zero Trust SIG": a calendar notice for a new or changed series,
# with no date in the subject. The name is everything after the prefix; the date comes
# from the body's "When:" line, or failing that the send date.
_EVENT_SUBJECT = re.compile(r"\]\s*(?:Cancelled |Updated )?Event:\s*(?:HOLD\s*-\s*)?"
                            r"(?P<name>.+?)\s*$", re.I)
# "2026-09-03 WS4 General Meeting"
_DATED_SUBJECT =re.compile(r"\]\s*(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<name>.+?)\s*$")

_CADENCE = (
    (re.compile(r"\bbi-?weekly\b", re.I), "FREQ=WEEKLY;INTERVAL=2"),
    (re.compile(r"\bweekly\b", re.I), "FREQ=WEEKLY"),
    (re.compile(r"\bmonthly\b", re.I), "FREQ=MONTHLY"),
)

_DOC_URL = re.compile(r"https://(?:docs|drive)\.google\.com/\S*?[\w-]{20,}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


# --- Records ---------------------------------------------------------------------

@dataclass
class Occurrence:
    """One meeting that was scheduled, held, or canceled."""

    series_uid: str | None            # iCalendar UID: stable per series
    series_name: str                  # verbatim, for registry resolution
    workstream: str | None
    list_name: str
    starts_at: str | None             # ISO-8601 UTC
    ends_at: str | None
    recurrence_id: str | None
    canceled: bool = False
    cadence: str | None = None        # RRULE, from the calendar part or the subject
    organizer_sha256: str | None = None
    source_message_id: str = ""
    source_kind: str = "occurrence"
    evidence: str = "ics"             # ics, body-when, subject, subject-sent-date


@dataclass
class SummaryRef:
    """A meeting record exists somewhere else. We record that, not its contents."""

    series_name: str
    workstream: str | None
    list_name: str
    meeting_date: str | None
    urls: list[str] = field(default_factory=list)
    access_restricted: bool = True
    source_message_id: str = ""


@dataclass
class GovernanceEvent:
    """A call for consensus, review period, nomination call or vote."""

    subject: str
    list_name: str
    workstream: str | None
    occurred_at: str | None
    source_message_id: str = ""
    # Read from the body and kept as labels only, so no body text leaves this module:
    # "opened" for a call asking for objections, "closed" for one reporting none.
    outcome: str | None = None
    # A PGB call restates that the TSC already approved the document, which is the only
    # record of a TSC decision taken by ballot rather than by a call of its own.
    states_tsc_approval: bool = False
    deadline: str | None = None           # the stated objection deadline, ISO date


@dataclass
class MailParse:
    occurrences: list[Occurrence] = field(default_factory=list)
    summaries: list[SummaryRef] = field(default_factory=list)
    governance: list[GovernanceEvent] = field(default_factory=list)
    agendas: list[GovernanceEvent] = field(default_factory=list)
    schedule_changes: list[GovernanceEvent] = field(default_factory=list)
    coverage: dict[str, dict[str, str]] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    dropped_not_cosai: int = 0
    total_seen: int = 0


# --- Helpers ---------------------------------------------------------------------

def sha256(value: str) -> str:
    """Hash an address. Unescaped and lowercased first, per resolve.identity."""
    return hashlib.sha256(value.strip().lower().replace("\\", "").encode()).hexdigest()


def _header(msg: Message, name: str) -> str:
    """A decoded header. Subjects in this corpus include RFC 2047 base64 forms."""
    raw = msg.get(name)
    if not raw:
        return ""
    try:
        decoded = str(make_header(decode_header(raw)))
    except Exception:                       # malformed encodings must not abort a run
        decoded = str(raw)
    # Long subjects are folded across lines by the transport, and an unfolded newline
    # inside a series name corrupts both the registry key and the report table.
    return re.sub(r"\s+", " ", decoded).strip()


def list_of(msg: Message) -> str | None:
    """The CoSAI list a message belongs to, or None if it is not list mail.

    This is the privacy boundary: a message that does not resolve to a known CoSAI
    list is never parsed. `List-Id` is authoritative; the subject tag is the fallback
    because replies and forwards keep the tag but lose the header.
    """
    for field_name in ("List-Id", "List-Post", "X-Mailing-List"):
        raw = msg.get(field_name) or ""
        found = _LIST_ID.search(raw)
        if found and found.group(1).lower() in KNOWN_LISTS:
            return KNOWN_LISTS[found.group(1).lower()][0]
    tag = _SUBJECT_TAG.search(_header(msg, "Subject"))
    if tag and tag.group(1).lower() in KNOWN_LISTS:
        return KNOWN_LISTS[tag.group(1).lower()][0]
    return None


def classify(subject: str) -> str:
    for kind, pattern in _KINDS:
        if pattern.search(subject):
            return kind
    return "other"


def cadence_of(text: str) -> str | None:
    for pattern, rrule in _CADENCE:
        if pattern.search(text):
            return rrule
    return None


def _plain_body(msg: Message) -> str:
    for part in (msg.walk() if msg.is_multipart() else [msg]):
        if part.get_content_type() == "text/plain":
            try:
                return part.get_payload(decode=True).decode(
                    part.get_content_charset() or "utf-8", "replace")
            except Exception:
                return ""
    return ""


# A reply quotes the call it closes. Only the reply's own text says how the call ended,
# so quoted lines and everything after an attribution line are dropped first.
_ATTRIBUTION = re.compile(r"^\s*(?:On .{5,200}wrote:|-+\s*Original Message\s*-+|From: .+)$",
                          re.M)
_CLOSED = re.compile(r"\b(?:is|has|was) (?:now )?closed\b|no objections were registered"
                     r"|received no objections|ended and no objections"
                     r"|approved by (?:both )?(?:the )?(?:cosai )?(?:tsc|pgb)\b[^.]{0,40}"
                     r"without objections|has (?:now )?been (?:officially )?approved"
                     r"|(?:is|are) now approved", re.I)
_OPENED = re.compile(r"register (?:any|your) objections?", re.I)
_STATES_TSC = re.compile(r"approved by the TSC", re.I)
# "register any objections ... no later than Friday, September 4, 2026 at 6pm ET". The
# year is required, so "by the end of the day on Monday, March 9nd" yields no date
# rather than a guessed one.
_DEADLINE = re.compile(r"objections?\b[^.]{0,80}?\b(?:no later than|by)\s+(?:\w+day,?\s+)?"
                       r"(?P<month>[A-Z][a-z]+)\.?\s+(?P<day>\d{1,2})(?:st|nd|rd|th)?,?\s+"
                       r"(?P<year>\d{4})")


def _own_text(body: str) -> str:
    """A message's own text: quoted lines and everything after an attribution dropped."""
    fresh = "\n".join(line for line in body.splitlines()
                      if not line.lstrip().startswith(">"))
    return _ATTRIBUTION.split(fresh, maxsplit=1)[0]


def call_deadline(body: str) -> str | None:
    """The objection deadline a call states, as an ISO date in the call's own time zone.

    Consent is assumed when the deadline passes without objection, so this is when a
    call takes effect; the closing message only reports it, often days later.
    """
    found = _DEADLINE.search(re.sub(r"\s+", " ", _own_text(body)))
    if not found:
        return None
    try:
        month = datetime.strptime(found["month"][:3], "%b").month
        return f"{int(found['year']):04d}-{month:02d}-{int(found['day']):02d}"
    except ValueError:                       # a capitalized word that is not a month
        return None


def governance_outcome(body: str) -> tuple[str | None, bool]:
    """How a governance message reports its call, and whether it restates TSC approval.

    Closing wins over opening, since a closing reply may repeat the call's instructions.
    """
    fresh = _own_text(body)
    if _CLOSED.search(fresh):
        outcome = "closed"
    elif _OPENED.search(fresh):
        outcome = "opened"
    else:
        outcome = None
    return outcome, bool(_STATES_TSC.search(fresh))


def _ics_blocks(msg: Message) -> list[str]:
    """VEVENT bodies from a message.

    Deduplicated because every calendar message here carries the same event twice, as
    `text/calendar` and as `application/ics`. VTIMEZONE is excluded deliberately: it
    carries its own DTSTART and RRULE for daylight-saving rules, which would otherwise
    be read as the meeting's schedule.
    """
    seen, blocks = set(), []
    for part in (msg.walk() if msg.is_multipart() else [msg]):
        if part.get_content_type() not in ("text/calendar", "application/ics"):
            continue
        try:
            text = part.get_payload(decode=True).decode(
                part.get_content_charset() or "utf-8", "replace")
        except Exception:
            continue
        for block in re.findall(r"BEGIN:VEVENT(.*?)END:VEVENT", text, re.S):
            unfolded = re.sub(r"\r?\n[ \t]", "", block)      # RFC 5545 line folding
            key = _ics_prop(unfolded, "UID"), _ics_prop(unfolded, "RECURRENCE-ID")
            if key in seen:
                continue
            seen.add(key)
            blocks.append(unfolded)
    return blocks


def _ics_prop(block: str, name: str) -> str | None:
    found = re.search(rf"^{name}(?:;[^:\n]*)?:(.*)$", block, re.M)
    return found.group(1).strip() if found else None


def _ics_datetime(value: str | None) -> str | None:
    """An iCalendar timestamp as ISO-8601 UTC. Naive values are left unqualified."""
    if not value:
        return None
    raw = value.strip().rstrip("Z")
    for fmt in ("%Y%m%dT%H%M%S", "%Y%m%d"):
        try:
            parsed = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        if value.strip().endswith("Z"):
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.isoformat()
    return None


def when_of(body: str) -> tuple[str, str] | None:
    """Start and end in ISO-8601 UTC from a notice's "When:" line, if it has one."""
    found = _WHEN.search(re.sub(r"\s+", " ", body))
    if not found:
        return None
    sign = -1 if found.group("offset")[0] == "-" else 1
    hours, minutes = (int(n) for n in found.group("offset")[1:].split(":"))
    zone = timezone(sign * timedelta(hours=hours, minutes=minutes))

    def instant(day: str, clock: str) -> datetime | None:
        clock = clock.replace(" ", "").lower()
        for fmt in ("%d %B %Y %I:%M%p", "%d %B %Y %I%p"):
            try:
                return datetime.strptime(f"{day} {clock}", fmt).replace(tzinfo=zone)
            except ValueError:
                continue
        return None

    start = instant(found.group("date"), found.group("start"))
    end = instant(found.group("date2") or found.group("date"), found.group("end"))
    if not start or not end:
        return None
    return (start.astimezone(timezone.utc).isoformat(),
            end.astimezone(timezone.utc).isoformat())


def _subject_date(value: str) -> str | None:
    """A date from a subject line: '18 August 2026' or '2026-08-18'."""
    value = value.strip()
    for fmt in ("%Y-%m-%d", "%d %B %Y", "%d %b %Y", "%B %d %Y", "%b %d %Y"):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            continue
    return None


# --- The parse -------------------------------------------------------------------

def parse_mbox(path: Path) -> MailParse:
    """Parse one mbox into meeting records, discarding non-CoSAI mail."""
    out = MailParse()
    _read_into(out, path)
    return out


def parse_mboxes(paths: Iterable[Path]) -> MailParse:
    """Parse several mboxes into one result.

    The groups.io fetcher writes one archive per group, so the corpus is now a
    directory rather than a single mailbox. Merging at parse time rather than
    concatenating the files keeps each list's coverage window separate, which is the
    thing that distinguishes "this list held no meeting that week" from "this list was
    not fetched that week". Sorted, so a run is reproducible and the report's row
    order does not depend on the filesystem.
    """
    out = MailParse()
    for path in sorted(paths):
        _read_into(out, path)
    return out


def _read_into(out: MailParse, path: Path) -> None:
    """Accumulate one mbox's records into an existing result."""
    box = mailbox.mbox(str(path))

    for msg in box:
        out.total_seen += 1
        list_name = list_of(msg)
        if list_name is None:
            out.dropped_not_cosai += 1
            continue                       # not list mail: never parsed

        workstream = KNOWN_LISTS[list_name][1]
        subject = _header(msg, "Subject")
        message_id = (msg.get("Message-ID") or "").strip("<> ")
        sent = _mail_date(msg)
        if sent:
            window = out.coverage.setdefault(list_name, {})
            window["earliest"] = min(window.get("earliest", sent), sent)
            window["latest"] = max(window.get("latest", sent), sent)

        kind = classify(subject)
        blocks = _ics_blocks(msg)

        if blocks:
            for block in blocks:
                out.occurrences.append(_from_ics(block, list_name, workstream,
                                                 message_id, kind))
            continue

        if kind in ("occurrence", "cancellation", "invitation"):
            occurrence = _from_subject(subject, list_name, workstream, message_id,
                                       kind, fallback_date=sent)
            when = when_of(_plain_body(msg)) if occurrence else None
            if when:                   # a stated time beats a date read off a subject
                occurrence.starts_at, occurrence.ends_at = when
                occurrence.evidence = "body-when"
            if occurrence:
                out.occurrences.append(occurrence)
            else:
                out.findings.append(f"unparsed {kind} subject: {subject!r}")
        elif kind == "summary":
            out.summaries.append(_from_summary(msg, subject, list_name, workstream,
                                               message_id, sent))
        elif kind == "schedule-change":
            # Affects a series rather than one occurrence: a cadence or link change.
            out.schedule_changes.append(
                GovernanceEvent(subject=subject, list_name=list_name,
                                workstream=workstream, occurred_at=sent,
                                source_message_id=message_id))
        elif kind == "agenda":
            out.agendas.append(GovernanceEvent(subject=subject, list_name=list_name,
                                               workstream=workstream, occurred_at=sent,
                                               source_message_id=message_id))
        elif kind == "governance":
            body = _plain_body(msg)
            outcome, states_tsc = governance_outcome(body)
            out.governance.append(GovernanceEvent(subject=subject, list_name=list_name,
                                                  workstream=workstream,
                                                  occurred_at=sent,
                                                  source_message_id=message_id,
                                                  outcome=outcome,
                                                  states_tsc_approval=states_tsc,
                                                  deadline=call_deadline(body)))
        else:
            out.findings.append(f"no rule matched this subject: {subject!r}")


def _mail_date(msg: Message) -> str | None:
    import email.utils
    raw = msg.get("Date")
    if not raw:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(raw)
    except Exception:
        return None
    return parsed.date().isoformat() if parsed else None


def _from_ics(block: str, list_name: str, workstream: str, message_id: str,
              kind: str) -> Occurrence:
    organizer = _ics_prop(block, "ORGANIZER") or ""
    address = _EMAIL.search(organizer)
    status = (_ics_prop(block, "STATUS") or "").upper()
    name = _ics_prop(block, "SUMMARY") or ""
    return Occurrence(
        series_uid=_ics_prop(block, "UID"),
        series_name=name,
        workstream=workstream,
        list_name=list_name,
        starts_at=_ics_datetime(_ics_prop(block, "DTSTART")),
        ends_at=_ics_datetime(_ics_prop(block, "DTEND")),
        recurrence_id=_ics_datetime(_ics_prop(block, "RECURRENCE-ID")),
        canceled=(status == "CANCELLED" or kind == "cancellation"),
        cadence=_ics_prop(block, "RRULE") or cadence_of(name),
        organizer_sha256=sha256(address.group(0)) if address else None,
        source_message_id=message_id,
        source_kind=kind,
        evidence="ics",
    )


def _from_subject(subject: str, list_name: str, workstream: str, message_id: str,
                  kind: str, fallback_date: str | None = None) -> Occurrence | None:
    found = _NOW_SUBJECT.search(subject) or _DATED_SUBJECT.search(subject)
    if found:
        name = found.group("name").strip()
        starts, evidence = _subject_date(found.group("date")), "subject"
    elif event := _EVENT_SUBJECT.search(subject):
        name = event.group("name").strip()
        starts, evidence = fallback_date, "subject-sent-date"
    elif kind in ("cancellation", "invitation"):
        # "No WS1 Meeting today" -- the series is named but the date is only the day
        # the notice was sent. Recorded as weaker evidence, not as a scheduled start.
        # The list tag is stripped whatever follows it, or it becomes part of the name.
        bare = re.sub(r"^\s*(?:Fwd:|Re:)?\s*(?:\[[^\]]+\]\s*)?"
                      r"(?:No\s+|You'?re Invited:\s*)?", "", subject, flags=re.I)
        name = re.sub(r"\b(this week|next week|today)\b.*$", "", bare, flags=re.I).strip()
        starts, evidence = fallback_date, "subject-sent-date"
    else:
        return None
    return Occurrence(
        series_uid=None,
        series_name=name,
        workstream=workstream,
        list_name=list_name,
        starts_at=starts,
        ends_at=None,
        recurrence_id=None,
        canceled=(kind == "cancellation"),
        cadence=cadence_of(subject),
        source_message_id=message_id,
        source_kind=kind,
        evidence=evidence,
    )


def _from_summary(msg: Message, subject: str, list_name: str, workstream: str,
                  message_id: str, sent: str | None) -> SummaryRef:
    found = _DATED_SUBJECT.search(subject)
    name = found.group("name").strip() if found else subject
    date = _subject_date(found.group("date")) if found else sent
    urls = sorted(set(_DOC_URL.findall(_plain_body(msg))))
    return SummaryRef(series_name=name, workstream=workstream, list_name=list_name,
                      meeting_date=date, urls=urls, source_message_id=message_id)


# --- Series seeding and reporting ------------------------------------------------

def _slug(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", value.lower())).strip("-")


@functools.cache
def series_aliases() -> dict[str, str]:
    """Normalized name variant -> canonical series id, from the curated registry.

    Mechanical normalization can only reach what looks alike. ``CoSAI-RM meeting`` and
    ``CoSAI-RM SIG weekly meeting`` are one series and no rule relates them, while
    ``WS3 Bi-weekly Meeting`` and ``WS3 SIG: ...`` look similar and are two. So the
    merge is a curated decision, corroborated where possible against the upstream
    fetcher's own title patterns, and this is the lookup for it.

    A missing registry is not an error: the parser still works, falling back to the
    normalized name, which is how the registry was seeded in the first place.
    """
    try:
        from ..paths import load_registry

        entries = load_registry("meeting-series")["meeting_series"]
    except (FileNotFoundError, KeyError):
        return {}
    aliases: dict[str, str] = {}
    for entry in entries:
        names = [entry["label"], *entry.get("name_variants", [])]
        for name in names:
            if name:
                aliases[_normalize(name)] = entry["id"]
    return aliases


@functools.cache
def series_labels() -> dict[str, str]:
    """Canonical series id -> curated label.

    The registry's label wins over the first observed variant, which is whichever
    spelling happened to arrive first: the code SIG's short form appears only in
    cancellation notices ("No Security of AI-Assisted Code Development this week"),
    and labeling the series with it would name a group after the notice that called
    off one of its meetings.
    """
    try:
        from ..paths import load_registry

        entries = load_registry("meeting-series")["meeting_series"]
    except (FileNotFoundError, KeyError):
        return {}
    return {entry["id"]: entry["label"] for entry in entries if entry.get("label")}


@functools.cache
def series_curation() -> dict[str, dict]:
    """Canonical series id -> the registry's workstream, kind, cadence and lists.

    Curated facts win over what the mail implies. A seed group takes its workstream
    from its first occurrence, which for the WS3 SRF & GRC SIG is a cancellation on
    the project-wide `cosai-op` list: without this the SIG has no convener. And a
    series merged across a rename carries each era's RRULE, so the registry's cadence
    is the one that describes it now. The same holds for the source list: the WS1
    meeting's first message is a cancellation cross-posted to `cosai-op`, which is
    not where WS1 announces.
    """
    try:
        from ..paths import load_registry

        entries = load_registry("meeting-series")["meeting_series"]
    except (FileNotFoundError, KeyError):
        return {}
    return {entry["id"]: {key: entry.get(key)
                          for key in ("workstream", "kind", "cadence", "lists", "status",
                                      "status_as_of", "succeeded_by")}
            for entry in entries}


def _normalize(name: str) -> str:
    """The comparison form: parenthetical qualifiers dropped, then slugged.

    ``CoSAI WS1 Meeting (updated link)`` and ``(updated)`` are administrative
    annotations on one series, not distinct series.
    """
    return _slug(re.sub(r"\([^)]*\)", " ", name))


def _series_key(name: str) -> str:
    """A canonical series key from a meeting name.

    Resolved through the registry where it knows the name, so drifted spellings land
    on one series. Otherwise the normalized name, so a series nobody has curated yet
    still appears -- as itself, visibly, rather than being merged into a neighbour.
    """
    normalized = _normalize(name)
    return series_aliases().get(normalized, normalized)


def seed_series(parse: MailParse) -> list[dict]:
    """Group occurrences into candidate series for `registry/meeting-series.yaml`.

    Two passes, because neither key alone is sufficient. iCalendar ``UID`` is stable
    but only 11 of 51 occurrences carry one; the name is always present but drifts. So
    occurrences group by UID where available and by name key otherwise, and those
    groups are then merged on the name key -- without the merge, one series appears
    once per UID *and* once for its subject-only notices.

    The result is a *seed* for review, not a finished registry: remaining variants
    such as ``CoSAI WS1 Weekly Meeting`` versus ``CoSAI WS1 Meeting`` are real drift a
    human must confirm, the same gate the person and organization registries pass.
    """
    by_uid: dict[str, list[Occurrence]] = {}
    for occurrence in parse.occurrences:
        key = occurrence.series_uid or f"name:{_series_key(occurrence.series_name)}"
        by_uid.setdefault(key, []).append(occurrence)

    merged: dict[str, dict] = {}
    for key, occurrences in by_uid.items():
        name_key = _series_key(occurrences[0].series_name)
        group = merged.setdefault(name_key, {
            "id": name_key,
            "ics_uids": [],
            "workstream": occurrences[0].workstream,
            "list": occurrences[0].list_name,
            "name_variants": [],
            "cadence": None,
            "occurrences": 0,
            "cancellations": 0,
        })
        if not key.startswith("name:") and key not in group["ics_uids"]:
            group["ics_uids"].append(key)
        for occurrence in occurrences:
            if occurrence.series_name not in group["name_variants"]:
                group["name_variants"].append(occurrence.series_name)
            # An RRULE from a calendar part beats one inferred from a subject word.
            if occurrence.cadence and (group["cadence"] is None
                                       or occurrence.evidence == "ics"):
                group["cadence"] = occurrence.cadence
            group["occurrences"] += 1
            group["cancellations"] += 1 if occurrence.canceled else 0
    for group in merged.values():
        curated = series_curation().get(group["id"])
        if curated:
            group["workstream"] = curated["workstream"]
            group["kind"] = curated["kind"]
            group["cadence"] = curated["cadence"] or group["cadence"]
            if curated["lists"]:
                group["list"] = curated["lists"][0]
            for key in ("status", "status_as_of", "succeeded_by"):
                if curated[key]:
                    group[key] = curated[key]
    return sorted(merged.values(), key=lambda g: (-g["occurrences"], g["id"]))


def write_report(parse: MailParse, series: list[dict]) -> str:
    """A reviewable report. Subjects only -- no message bodies reach this file."""
    lines = [
        "# Meeting ingest -- list mail",
        "",
        f"- messages read: **{parse.total_seen}**",
        f"- discarded as not CoSAI list mail: **{parse.dropped_not_cosai}**",
        f"- occurrences: **{len(parse.occurrences)}** "
        f"({sum(1 for o in parse.occurrences if o.evidence == 'ics')} from iCalendar, "
        f"{sum(1 for o in parse.occurrences if o.canceled)} canceled)",
        f"- summary pointers: **{len(parse.summaries)}** (all access-restricted)",
        f"- governance events: **{len(parse.governance)}**, agendas: "
        f"{len(parse.agendas)}, schedule changes: {len(parse.schedule_changes)}",
        "",
        "## Coverage",
        "",
        "Each window runs from a list's earliest fetched message to its latest.",
        "Outside these windows attendance and occurrence are **not asserted**, never",
        "denied.",
        "",
        "| list | earliest | latest |",
        "| --- | --- | --- |",
    ]
    for name, window in sorted(parse.coverage.items()):
        lines.append(f"| `{name}` | {window['earliest']} | {window['latest']} |")

    lines += ["", "## Candidate series", "",
              "| id | occurrences | canceled | cadence | name variants |",
              "| --- | --- | --- | --- | --- |"]
    for group in series:
        variants = "<br>".join(f"`{v}`" for v in group["name_variants"])
        lines.append(f"| `{group['id']}` | {group['occurrences']} | "
                     f"{group['cancellations']} | {group['cadence'] or '—'} | {variants} |")

    lines += ["", "## Unmatched subjects", "",
              "Left unclassified deliberately rather than guessed at. Each is either a",
              "discussion thread or a kind not yet modeled.", ""]
    lines += [f"- {finding}" for finding in parse.findings] or ["- none"]
    return "\n".join(lines) + "\n"


def mbox_paths(source: Path) -> list[Path]:
    """Every mbox under `source`, or `source` itself if it is a file.

    A directory is the normal case now -- `ingest/groupsio.py` writes one archive per
    list. A single file still works, so an mbox from anywhere (a manual archive
    download, an old export) can be parsed without a directory ceremony.
    """
    if source.is_dir():
        return sorted(source.glob("*.mbox"))
    return [source]


def main(argv: list[str] | None = None) -> int:
    """Parse the fetched archives, write the seed registry and the report."""
    import argparse

    import yaml

    from ..paths import MAIL, REGISTRY, REPORTS

    parser = argparse.ArgumentParser(
        description="Parse CoSAI list archives into meeting records.")
    parser.add_argument("source", nargs="?", type=Path, default=MAIL,
                        help=f"an mbox, or a directory of them (default: {MAIL})")
    args = parser.parse_args(argv)

    paths = mbox_paths(args.source)
    if not paths:
        print(f"no .mbox files in {args.source}. Fetch them first:\n"
              "    python -m bubo_graphrag.ingest.groupsio", file=sys.stderr)
        return 1

    parse = parse_mboxes(paths)
    series = seed_series(parse)

    REPORTS.mkdir(parents=True, exist_ok=True)
    report = REPORTS / "meetings.md"
    report.write_text(write_report(parse, series), encoding="utf-8")

    seed = REGISTRY / "meeting-series.seed.yaml"
    seed.write_text(yaml.safe_dump({"meeting_series": series}, sort_keys=False,
                                   allow_unicode=True), encoding="utf-8")
    print(f"{len(paths)} archives, {parse.total_seen} messages -> "
          f"{len(parse.occurrences)} occurrences, {len(series)} series, "
          f"{len(parse.findings)} unmatched")
    print(f"  {report}")
    print(f"  {seed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
