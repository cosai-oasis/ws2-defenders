"""Ingest the CoSAI meeting calendar into its own named graph.

Source: the groups.io calendar of the project-wide ``cosai-op`` list, which the CoSAI
site links as "the CoSAI meeting calendar". Every workstream and SIG schedules its
meetings there. It is read through ``GET /api/v1/getevents`` with your own key, the
same key ``ingest/groupsio.py`` uses; the web calendar is never scraped.

## Entries, not meetings

Each event becomes a ``cosaic:ScheduledMeeting``: a calendar entry prescribing a meeting
at a time. It is not a ``cosaic:Meeting``, because in BFO a meeting is a process and a
process that has not happened does not exist. An entry whose start falls on a later day
than the calendar was read is also a ``cosaic:PlannedMeeting``: a meeting scheduled for
a future date, judged from the read, not from whenever a query runs.

An entry links to its series only where the curated series registry knows its name
(``scheduleOf``), and to a mail-recorded meeting only where one exists for that series
on that UTC day (``correspondsTo``). Neither link is guessed; unresolved names are
reported for curation.

## What is never kept

The API returns an organizer's name, email and phone, the creator's name, a location
that holds the meeting link, and a free-text description. None of it is written to disk:
the cache keeps an allowlist of fields only. ``extended=true`` is never sent, because it
makes the API return the caller's own account record.

## What the calendar cannot show

It carries no iCalendar UID and no repeat rule, so series identity comes from names, as
it does for mail. It holds nothing before 2026. And a canceled occurrence may simply be
deleted, so an absent entry is not evidence of anything; the mail records cancellations.

Run:  python -m bubo_graphrag.ingest.calendar            # build from the cache
      python -m bubo_graphrag.ingest.calendar --refresh  # read the calendar again first
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from rdflib import Graph, Literal, Namespace, RDF, RDFS, URIRef, XSD

from ..paths import MAIL, ONTOLOGY, REPORTS

COSAIC = Namespace("https://cosai-oasis.github.io/ontology/cosai-contrib#")
OBO = Namespace("http://purl.obolibrary.org/obo/")

GROUP = "cosai-op"
CACHE = MAIL / f"calendar-{GROUP}.json"
CALENDAR_TTL = ONTOLOGY / "calendar.ttl"
# The day CoSAI launched. The calendar holds nothing that early, but asking from here
# makes the window say so rather than start wherever the first entry happens to be.
DEFAULT_START = dt.date(2024, 7, 18)
LOOKAHEAD_DAYS = 366

# The only event fields ever kept. Organizer and creator identity, the location (the
# meeting link) and the description are not among them.
KEPT_FIELDS = ("id", "name", "start_time", "end_time", "timezone", "all_day",
               "created", "updated")


@dataclass
class Entry:
    event_id: str
    name: str
    start: dt.datetime                      # UTC
    end: dt.datetime | None                 # UTC
    timezone: str | None


@dataclass
class Calendar:
    entries: list[Entry]
    source: str                             # the API's group name
    range_start: str                        # ISO dates
    range_end: str
    fetched_at: dt.datetime                 # UTC

    @property
    def fetched_on(self) -> str:
        return self.fetched_at.date().isoformat()


# --- reading the calendar -------------------------------------------------------------

def fetch(start: dt.date = DEFAULT_START, end: dt.date | None = None,
          cache: Path = CACHE, opener=None) -> Path:
    """Read every event in [start, end] into `cache`, keeping allowlisted fields only.

    The API's pages repeat rows -- 3,528 rows for 791 events on 2026-09-26, every repeat
    identical -- so events are kept once per ID, and the count is checked against the
    API's own total_count: a shortfall means an event was skipped, and fails the read.
    """
    from . import groupsio as G

    now = dt.datetime.now(dt.timezone.utc)
    end = end or (now.date() + dt.timedelta(days=LOOKAHEAD_DAYS))
    opener = opener or G._urlopen
    headers = {"Authorization": f"Bearer {G.api_key()}", "Accept": "application/json"}
    group = G.api_group_name(GROUP)
    events: dict[str, dict] = {}
    token, total = None, None
    while True:
        # Plain dates: the API answers every timestamp form with invalid_start_time.
        params = {"group_name": group, "start": start.isoformat(),
                  "end": end.isoformat(), "limit": "100"}
        if token:
            params["page_token"] = token
        status, body = opener(f"{G.site()}/api/v1/getevents?"
                              + urllib.parse.urlencode(params), headers)
        page = json.loads(body)
        if status != 200 or not isinstance(page, dict) or page.get("object") == "error":
            reason = page.get("type") if isinstance(page, dict) else "unexpected response"
            raise RuntimeError(f"getevents failed for {group}: HTTP {status}, {reason}")
        total = page.get("total_count", total)
        for e in page.get("data") or []:
            events.setdefault(str(e["id"]), {k: e.get(k) for k in KEPT_FIELDS})
        if not page.get("has_more"):
            break
        token = page["next_page_token"]
    if total is not None and len(events) < total:
        raise RuntimeError(f"getevents for {group} returned {len(events)} distinct events "
                           f"of the {total} it reports; not writing a partial calendar")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({
        "group": group, "range_start": start.isoformat(), "range_end": end.isoformat(),
        "fetched_at": now.isoformat(timespec="seconds"), "events": list(events.values()),
    }, indent=1) + "\n", encoding="utf-8")
    return cache


def _utc(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc)


def parse(data: dict) -> Calendar:
    entries, seen = [], set()
    for event in data["events"]:
        start = _utc(event.get("start_time"))
        if start is None or str(event["id"]) in seen:     # an older cache may repeat rows
            continue
        seen.add(str(event["id"]))
        entries.append(Entry(event_id=str(event["id"]), name=(event.get("name") or "").strip(),
                             start=start, end=_utc(event.get("end_time")),
                             timezone=event.get("timezone") or None))
    entries.sort(key=lambda e: (e.start, e.event_id))
    return Calendar(entries=entries, source=data["group"], range_start=data["range_start"],
                    range_end=data["range_end"], fetched_at=_utc(data["fetched_at"]))


def load_cache(cache: Path = CACHE) -> Calendar:
    return parse(json.loads(cache.read_text(encoding="utf-8")))


def is_planned(entry: Entry, calendar: Calendar) -> bool:
    """Scheduled for a future date: its start falls on a later day than the read."""
    return entry.start.date() > calendar.fetched_at.date()


# --- what the entries link to ---------------------------------------------------------

def curated_series() -> dict[str, str]:
    """Normalized curated name -> series id. Only the registry's names: an entry the
    registry does not know stays unlinked rather than matched by resemblance."""
    from .maillist import series_aliases
    return series_aliases()


def resolve_series(name: str, aliases: dict[str, str]) -> str | None:
    from .maillist import _normalize
    return aliases.get(_normalize(name))


def mail_meetings(path: Path = ONTOLOGY / "maillist.ttl") -> tuple[set[str], dict]:
    """The series ids and the (series id, UTC day) -> meeting IRI the maillist graph
    holds, so a link is made only to a node that exists."""
    if not path.exists():
        return set(), {}
    g = Graph().parse(path, format="turtle")
    series = {str(s).rsplit("#series-", 1)[1]
              for s in g.subjects(RDF.type, COSAIC.MeetingSeries) if "#series-" in str(s)}
    meetings = {}
    for meeting in g.subjects(RDF.type, COSAIC.Meeting):
        in_series = g.value(meeting, COSAIC.inSeries)
        instant = g.value(meeting, OBO.BFO_0000199)
        day = g.value(instant, COSAIC.date) if instant is not None else None
        if in_series is not None and day is not None and "#series-" in str(in_series):
            meetings[(str(in_series).rsplit("#series-", 1)[1], str(day))] = meeting
    return series, meetings


# --- the graph ------------------------------------------------------------------------

def _datetime(value: dt.datetime) -> Literal:
    return Literal(value.isoformat(), datatype=XSD.dateTime)


def build(calendar: Calendar, aliases: dict[str, str] | None = None,
          known_series: set[str] | None = None,
          meetings: dict | None = None) -> Graph:
    aliases = aliases or {}
    known_series = known_series or set()
    meetings = meetings or {}
    g = Graph()
    g.bind("cosaic", COSAIC)
    source = Literal(calendar.source)
    for entry in calendar.entries:
        node = COSAIC[f"calevent-{entry.event_id}"]
        g.add((node, RDF.type, COSAIC.ScheduledMeeting))
        if is_planned(entry, calendar):
            g.add((node, RDF.type, COSAIC.PlannedMeeting))
        g.add((node, RDFS.label,
               Literal(f"{entry.name}, scheduled {entry.start.date()}", lang="en")))
        g.add((node, COSAIC.sourceEventId, Literal(entry.event_id)))
        g.add((node, COSAIC.sourceCalendar, source))
        g.add((node, COSAIC.scheduledStart, _datetime(entry.start)))
        if entry.end:
            g.add((node, COSAIC.scheduledEnd, _datetime(entry.end)))
        if entry.timezone:
            g.add((node, COSAIC.scheduledTimeZone, Literal(entry.timezone)))
        series = resolve_series(entry.name, aliases)
        if series and series in known_series:
            g.add((node, COSAIC.scheduleOf, COSAIC[f"series-{series}"]))
            if not is_planned(entry, calendar) and \
                    (meeting := meetings.get((series, entry.start.date().isoformat()))):
                g.add((node, COSAIC.correspondsTo, meeting))

    window = COSAIC[f"coverage-calendar-{GROUP}"]
    g.add((window, RDF.type, COSAIC.CoverageWindow))
    g.add((window, RDF.type, COSAIC.CalendarCoverageWindow))
    g.add((window, RDFS.label,
           Literal(f"{calendar.source} calendar: asked {calendar.range_start}.."
                   f"{calendar.range_end}, read {calendar.fetched_on}", lang="en")))
    g.add((window, COSAIC.sourceCalendar, source))
    g.add((window, COSAIC.rangeStart, Literal(calendar.range_start, datatype=XSD.date)))
    g.add((window, COSAIC.rangeEnd, Literal(calendar.range_end, datatype=XSD.date)))
    g.add((window, COSAIC.fetchedOn, Literal(calendar.fetched_on, datatype=XSD.date)))
    if calendar.entries:
        g.add((window, COSAIC.earliestItem,
               Literal(calendar.entries[0].start.date().isoformat(), datatype=XSD.date)))
        g.add((window, COSAIC.latestItem,
               Literal(calendar.entries[-1].start.date().isoformat(), datatype=XSD.date)))
    g.add((window, COSAIC.boundsKnown, Literal(False)))
    return g


# --- the report -----------------------------------------------------------------------

def write_report(calendar: Calendar, aliases: dict[str, str], known_series: set[str],
                 meetings: dict) -> str:
    """Names, dates and counts only; no organizer, location or description exists here
    to report."""
    past = [e for e in calendar.entries if not is_planned(e, calendar)]
    planned = [e for e in calendar.entries if is_planned(e, calendar)]
    resolved = {e.event_id: resolve_series(e.name, aliases) for e in calendar.entries}
    corresponding = sum(
        1 for e in past
        if (s := resolved[e.event_id]) and (s, e.start.date().isoformat()) in meetings)
    first = calendar.entries[0].start.date() if calendar.entries else "—"
    last = calendar.entries[-1].start.date() if calendar.entries else "—"
    lines = [
        "# Calendar -- the CoSAI meeting calendar (groups.io, cosai-op)",
        "",
        f"- calendar: `{calendar.source}`, asked {calendar.range_start} to "
        f"{calendar.range_end}, read **{calendar.fetched_on}**",
        f"- entries: **{len(calendar.entries)}**, {first} to {last}",
        f"- scheduled for a past or current date: **{len(past)}**, of which "
        f"**{corresponding}** correspond to a meeting the list mail records",
        f"- planned (a future date): **{len(planned)}**",
        "",
        "No organizer, location or description is kept. Nothing before the first",
        "entry is in the calendar, so its absence is not evidence of no meeting.",
        "",
        "## Entries by name",
        "",
        "| name | series | past | planned |",
        "| --- | --- | --- | --- |",
    ]
    by_name: dict[str, Counter] = {}
    for e in calendar.entries:
        by_name.setdefault(e.name, Counter())["planned" if is_planned(e, calendar)
                                              else "past"] += 1
    for name in sorted(by_name):
        series = resolve_series(name, aliases)
        cell = (f"`{series}`" if series and series in known_series
                else f"`{series}` (not in the maillist graph)" if series
                else "**not in the series registry**")
        lines.append(f"| {name} | {cell} | {by_name[name]['past']} "
                     f"| {by_name[name]['planned']} |")
    unresolved = sorted(n for n in by_name if not resolve_series(n, aliases))
    lines += ["", "## Names to curate", "",
              "Add each as a name variant of its series in registry/meeting-series.yaml,",
              "or as a new series. Until then its entries link to no series.", ""]
    lines += [f"- {name}" for name in unresolved] or ["- none"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--refresh", action="store_true",
                        help="read the calendar again before building")
    parser.add_argument("--no-store", action="store_true",
                        help="write calendar.ttl only, skip reloading the store")
    args = parser.parse_args(argv)

    if args.refresh or not CACHE.exists():
        fetch()
    calendar = load_cache()
    aliases = curated_series()
    known_series, meetings = mail_meetings()
    graph = build(calendar, aliases, known_series, meetings)
    CALENDAR_TTL.write_text(
        "# GENERATED by `python -m bubo_graphrag.ingest.calendar` -- do not hand-edit.\n"
        f"# From the groups.io calendar of {calendar.source}, read {calendar.fetched_on}.\n"
        "# Entries, not meetings; no organizer, location or description is kept.\n\n"
        + graph.serialize(format="turtle"), encoding="utf-8")
    REPORTS.mkdir(parents=True, exist_ok=True)
    report = REPORTS / "calendar.md"
    report.write_text(write_report(calendar, aliases, known_series, meetings),
                      encoding="utf-8")
    planned = sum(1 for e in calendar.entries if is_planned(e, calendar))
    print(f"{len(calendar.entries)} entries ({planned} planned), read "
          f"{calendar.fetched_on} -> {len(graph)} triples")
    print(f"  {CALENDAR_TTL}")
    print(f"  {report}")
    if not args.no_store:
        from ..store import load_store
        print(f"  store reloaded: {load_store()} quads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
