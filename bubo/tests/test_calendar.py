"""Calendar ingest tests.

Fixtures are synthetic API responses written inline; no test calls groups.io. The rules
under test: entries are never meetings, a planned meeting is judged from the read,
organizer and location fields never reach disk or the graph, links are made only to
curated series and existing meetings, and the window records what was asked.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest
from rdflib import Literal, Namespace, RDF, XSD

from bubo_graphrag.ingest import calendar as C

COSAIC = Namespace("https://cosai-oasis.github.io/ontology/cosai-contrib#")
READ = "2026-09-26T11:52:22+00:00"


def event(event_id: int, name: str, start: str, end: str | None = None, **extra) -> dict:
    return {"id": event_id, "name": name, "start_time": start, "end_time": end,
            "timezone": "America/New_York", "all_day": False,
            "created": "2026-01-05T10:00:00Z", "updated": "2026-01-05T10:00:00Z", **extra}


def calendar(*events: dict, fetched_at: str = READ) -> C.Calendar:
    return C.parse({"group": "open-projects+cosai-op", "range_start": "2024-07-18",
                    "range_end": "2027-09-27", "fetched_at": fetched_at,
                    "events": list(events)})


# --- entries are not meetings ----------------------------------------------------------

def test_an_entry_is_a_scheduled_meeting_never_a_meeting():
    graph = C.build(calendar(event(1, "WS1 Weekly Meeting", "2026-09-02T10:00:00-07:00")))
    node = COSAIC["calevent-1"]
    assert (node, RDF.type, COSAIC.ScheduledMeeting) in graph
    assert not list(graph.subjects(RDF.type, COSAIC.Meeting))


@pytest.mark.parametrize("start,planned", [
    ("2026-09-27T09:00:00-07:00", True),     # the day after the read
    ("2026-09-26T20:00:00-07:00", True),     # 03:00 UTC on the 27th: a later UTC day
    ("2026-09-26T09:00:00-07:00", False),    # the read's own day is not the future
    ("2026-09-25T09:00:00-07:00", False),
])
def test_a_planned_meeting_is_one_for_a_later_day_than_the_read(start, planned):
    graph = C.build(calendar(event(2, "WS1 Weekly Meeting", start)))
    node = COSAIC["calevent-2"]
    assert ((node, RDF.type, COSAIC.PlannedMeeting) in graph) is planned
    assert (node, RDF.type, COSAIC.ScheduledMeeting) in graph


def test_prescribed_times_are_kept_in_utc_with_their_zone():
    graph = C.build(calendar(event(3, "WS1 Weekly Meeting", "2026-09-02T10:00:00-07:00",
                                   "2026-09-02T11:00:00-07:00")))
    node = COSAIC["calevent-3"]
    assert graph.value(node, COSAIC.scheduledStart) == \
        Literal("2026-09-02T17:00:00+00:00", datatype=XSD.dateTime)
    assert graph.value(node, COSAIC.scheduledEnd) == \
        Literal("2026-09-02T18:00:00+00:00", datatype=XSD.dateTime)
    assert graph.value(node, COSAIC.scheduledTimeZone) == Literal("America/New_York")


# --- what is never kept ----------------------------------------------------------------

PERSONAL = {"organizer_email": "organizer@example.test", "organizer_phone": "+1 555 0100",
            "organizer_name": "Olive Organizer", "creator_name": "Carl Creator",
            "location": "https://zoom.example.test/j/123?pwd=secret",
            "description": "Agenda and dial-in details"}


def test_organizer_location_and_description_never_reach_the_cache(tmp_path, monkeypatch):
    from bubo_graphrag.ingest import groupsio as G
    monkeypatch.setattr(G, "api_key", lambda: "test-key")
    monkeypatch.setattr(G, "site", lambda: "https://lists.example.test")
    sent = []

    def opener(url, headers):
        sent.append(url)
        page = {"object": "list", "has_more": False,
                "data": [event(4, "WS1 Weekly Meeting", "2026-09-02T10:00:00-07:00",
                               **PERSONAL)]}
        return 200, json.dumps(page).encode()

    path = C.fetch(dt.date(2026, 9, 1), dt.date(2026, 9, 30), tmp_path / "cal.json", opener)
    text = path.read_text()
    assert not any(value in text for value in PERSONAL.values())
    assert set(json.loads(text)["events"][0]) == set(C.KEPT_FIELDS)
    # Plain dates, and never `extended`, which returns the caller's own account record.
    assert "start=2026-09-01" in sent[0] and "extended" not in sent[0]


def test_an_api_error_fails_the_fetch_rather_than_writing_an_empty_calendar(tmp_path,
                                                                        monkeypatch):
    from bubo_graphrag.ingest import groupsio as G
    monkeypatch.setattr(G, "api_key", lambda: "test-key")
    monkeypatch.setattr(G, "site", lambda: "https://lists.example.test")
    opener = lambda url, headers: (400, b'{"object": "error", "type": "invalid_start_time"}')
    with pytest.raises(RuntimeError, match="invalid_start_time"):
        C.fetch(dt.date(2026, 9, 1), dt.date(2026, 9, 30), tmp_path / "cal.json", opener)
    assert not (tmp_path / "cal.json").exists()


def _stub_api(monkeypatch):
    from bubo_graphrag.ingest import groupsio as G
    monkeypatch.setattr(G, "api_key", lambda: "test-key")
    monkeypatch.setattr(G, "site", lambda: "https://lists.example.test")


def test_rows_the_api_repeats_across_pages_are_kept_once(tmp_path, monkeypatch):
    _stub_api(monkeypatch)
    row = event(11, "WS1 Weekly Meeting", "2026-09-02T10:00:00-07:00")
    pages = iter([{"object": "list", "has_more": True, "next_page_token": 7,
                   "total_count": 1, "data": [row]},
                  {"object": "list", "has_more": False, "total_count": 1, "data": [row]}])
    opener = lambda url, headers: (200, json.dumps(next(pages)).encode())
    path = C.fetch(dt.date(2026, 9, 1), dt.date(2026, 9, 30), tmp_path / "cal.json", opener)
    assert len(json.loads(path.read_text())["events"]) == 1


def test_fewer_distinct_events_than_the_api_reports_fails_the_read(tmp_path, monkeypatch):
    _stub_api(monkeypatch)
    page = {"object": "list", "has_more": False, "total_count": 2,
            "data": [event(12, "WS1 Weekly Meeting", "2026-09-02T10:00:00-07:00")]}
    opener = lambda url, headers: (200, json.dumps(page).encode())
    with pytest.raises(RuntimeError, match="1 distinct events of the 2"):
        C.fetch(dt.date(2026, 9, 1), dt.date(2026, 9, 30), tmp_path / "cal.json", opener)


def test_a_cache_with_repeated_rows_parses_to_one_entry_each():
    row = event(13, "WS1 Weekly Meeting", "2026-09-02T10:00:00-07:00")
    assert [e.event_id for e in calendar(row, row).entries] == ["13"]


# --- links -----------------------------------------------------------------------------

ALIASES = {"ws1-weekly-meeting": "ws1-meeting"}
MEETING = COSAIC["meeting-ws1-meeting-2026-09-02"]


def test_a_past_entry_links_its_series_and_the_mails_meeting_that_day():
    graph = C.build(calendar(event(5, "WS1 Weekly Meeting", "2026-09-02T10:00:00-07:00")),
                    ALIASES, {"ws1-meeting"}, {("ws1-meeting", "2026-09-02"): MEETING})
    node = COSAIC["calevent-5"]
    assert graph.value(node, COSAIC.scheduleOf) == COSAIC["series-ws1-meeting"]
    assert graph.value(node, COSAIC.correspondsTo) == MEETING


def test_a_planned_entry_corresponds_to_no_meeting():
    """A meeting that has not happened has no mail record to correspond to."""
    graph = C.build(calendar(event(6, "WS1 Weekly Meeting", "2026-10-07T10:00:00-07:00")),
                    ALIASES, {"ws1-meeting"}, {("ws1-meeting", "2026-10-07"): MEETING})
    node = COSAIC["calevent-6"]
    assert graph.value(node, COSAIC.scheduleOf) == COSAIC["series-ws1-meeting"]
    assert graph.value(node, COSAIC.correspondsTo) is None


@pytest.mark.parametrize("aliases,known", [
    ({}, {"ws1-meeting"}),                   # a name the registry does not know
    (ALIASES, set()),                        # a series the maillist graph does not hold
])
def test_nothing_is_linked_by_resemblance_or_to_a_missing_node(aliases, known):
    graph = C.build(calendar(event(7, "WS1 Weekly Meeting", "2026-09-02T10:00:00-07:00")),
                    aliases, known, {("ws1-meeting", "2026-09-02"): MEETING})
    assert graph.value(COSAIC["calevent-7"], COSAIC.scheduleOf) is None
    assert graph.value(COSAIC["calevent-7"], COSAIC.correspondsTo) is None


# --- the window ------------------------------------------------------------------------

def test_the_window_records_what_was_asked_what_was_found_and_when():
    graph = C.build(calendar(event(8, "A", "2026-02-25T10:00:00-07:00"),
                             event(9, "B", "2027-09-24T10:00:00-07:00")))
    window = COSAIC["coverage-calendar-cosai-op"]
    assert {COSAIC.CoverageWindow, COSAIC.CalendarCoverageWindow} <= \
        set(graph.objects(window, RDF.type))
    assert graph.value(window, COSAIC.rangeStart) == Literal("2024-07-18", datatype=XSD.date)
    assert graph.value(window, COSAIC.earliestItem) == Literal("2026-02-25", datatype=XSD.date)
    assert graph.value(window, COSAIC.latestItem) == Literal("2027-09-24", datatype=XSD.date)
    assert graph.value(window, COSAIC.fetchedOn) == Literal("2026-09-26", datatype=XSD.date)
    assert graph.value(window, COSAIC.boundsKnown) == Literal(False)


def test_an_empty_range_still_says_what_was_asked():
    graph = C.build(calendar())
    window = COSAIC["coverage-calendar-cosai-op"]
    assert graph.value(window, COSAIC.rangeEnd) == Literal("2027-09-27", datatype=XSD.date)
    assert graph.value(window, COSAIC.earliestItem) is None


def test_the_report_names_unresolved_series_and_nothing_personal():
    cal = calendar(event(10, "WS2 Defenders – Telemetry SIG", "2026-09-03T10:00:00-07:00"))
    report = C.write_report(cal, ALIASES, {"ws1-meeting"}, {})
    assert "- WS2 Defenders – Telemetry SIG" in report
    assert not any(value in report for value in PERSONAL.values())
