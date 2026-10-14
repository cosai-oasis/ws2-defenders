"""List-mail ingest tests.

Fixtures are synthetic and written inline. The real input is fetched with a personal
groups.io key into a gitignored path, so no test may depend on it: a test that reads it
would pass only on a machine that had run the fetch.
Every message below is hand-built to carry exactly one observed variant.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from bubo_graphrag.ingest import maillist as M

FROM = "Claudia Rauch <claudia.rauch@oasis-open.org>"


def write_mbox(tmp_path: Path, *messages: str) -> Path:
    """An mbox from raw message texts, each with the required From_ separator."""
    path = tmp_path / "test.mbox"
    body = ""
    for message in messages:
        body += "From MAILER-DAEMON Mon Aug 10 00:00:00 2026\n"
        body += textwrap.dedent(message).lstrip("\n")
        if not body.endswith("\n"):
            body += "\n"
        body += "\n"
    path.write_text(body, encoding="utf-8")
    return path


def simple(subject: str, list_id: str | None = "cosai-tsc", date: str = "Tue, 11 Aug 2026 10:00:00 +0000",
           body: str = "text") -> str:
    headers = [f"From: {FROM}", f"Subject: {subject}", f"Date: {date}",
               f"Message-ID: <{abs(hash(subject))}@example.test>"]
    if list_id:
        headers.append(f"List-Id: <{list_id}.{M.LIST_DOMAIN}>")
    return "\n".join(headers) + "\n\n" + body


# --- the privacy boundary --------------------------------------------------------

def test_list_id_identifies_a_known_list(tmp_path):
    parse = M.parse_mbox(write_mbox(tmp_path, simple("[cosai-tsc] Now: CoSAI TSC meeting - Tuesday, 11 August 2026")))
    assert parse.dropped_not_cosai == 0
    assert parse.occurrences[0].list_name == "cosai-tsc"


def test_subject_tag_is_the_fallback_when_list_id_is_stripped(tmp_path):
    """Replies and forwards lose List-Id but keep the [cosai-*] tag."""
    parse = M.parse_mbox(write_mbox(
        tmp_path, simple("Re: [cosai-tsc] Call for Consensus to Approve a Blog Post", list_id=None)))
    assert parse.dropped_not_cosai == 0
    assert len(parse.governance) == 1


def test_non_cosai_mail_is_discarded_and_never_parsed(tmp_path):
    """The allowlist is the whole privacy control: private mail must not be read."""
    parse = M.parse_mbox(write_mbox(
        tmp_path,
        simple("Dinner on Friday?", list_id=None),
        simple("[some-other-list] Now: Unrelated meeting - Tuesday, 11 August 2026",
               list_id="some-other-list"),
    ))
    assert parse.dropped_not_cosai == 2
    assert parse.occurrences == [] and parse.governance == [] and parse.findings == []


def test_the_ws_suffix_does_not_split_one_list_in_two(tmp_path):
    """`List-Id` says cosai-defenders-ws, the subject tag says cosai-defenders."""
    parse = M.parse_mbox(write_mbox(
        tmp_path,
        simple("[cosai-defenders] Now: CoSAI WS2 regular meeting, bi-weekly - Tuesday, 11 August 2026",
               list_id="cosai-defenders-ws"),
        simple("Fwd: [cosai-defenders] Now: CoSAI WS2 regular meeting, bi-weekly - Tuesday, 25 August 2026",
               list_id=None, date="Tue, 25 Aug 2026 10:00:00 +0000"),
    ))
    assert set(parse.coverage) == {"cosai-defenders"}, "one canonical list, not two"
    assert parse.coverage["cosai-defenders"] == {"earliest": "2026-08-11",
                                                 "latest": "2026-08-25"}


def test_addresses_are_hashed_never_stored(tmp_path):
    ics = ICS_TEMPLATE.format(uid="u1@x", summary="CoSAI TSC meeting", dtstart="20260811T150000Z",
                              extra="")
    parse = M.parse_mbox(write_mbox(tmp_path, with_calendar("[cosai-tsc] Now: CoSAI TSC meeting", ics)))
    occurrence = parse.occurrences[0]
    assert occurrence.organizer_sha256 == M.sha256("claudia.rauch@oasis-open.org")
    assert "@" not in (occurrence.organizer_sha256 or "")


# --- classification ---------------------------------------------------------------

@pytest.mark.parametrize("subject,expected", [
    ("[cosai-risk-governance] Cancelled Event: WS3 SIG: Security of Code", "cancellation"),
    ("[cosai-supply-chain] No WS1 Meeting today", "cancellation"),
    ("[cosai-risk-governance] No Security of AI-Assisted Code Development this week", "cancellation"),
    ("[cosai-risk-governance] 2026-09-03 WS3 Meeting", "summary"),
    ("[cosai-defenders] 2026-09-08 WS2 bi-weekly meeting records", "summary"),
    ("[cosai-tsc] Draft Minutes for August 18 TSC Meeting", "summary"),
    ("[cosai-tsc] OASIS CoSAI TSC Meeting Agenda", "agenda"),
    ("[cosai-tsc] Now: CoSAI TSC meeting - Tuesday, 18 August 2026 #cal-notice", "occurrence"),
    ("[cosai-defenders] You're Invited: CoSAI Agentic Identity Session", "invitation"),
    ("[cosai-tsc] Call for Consensus to Approve Blog Post", "governance"),
    ("[cosai-defenders] Zero Trust Paper approved by TSC and PGB", "governance"),
    ("[cosai-supply-chain] New meeting invite for WS1 meetings", "schedule-change"),
    ("[cosai-tsc] Help us plan CoSAI events at Singapore Cyber Week", "other"),
])
def test_classification(subject, expected):
    assert M.classify(subject) == expected


def test_a_cancellation_outranks_the_summary_rule():
    """"Cancelled Event: ... Summary" must not be read as a summary; order matters."""
    assert M.classify("[cosai-tsc] Cancelled Event: TSC Meeting Summary") == "cancellation"


def test_unmatched_subjects_become_findings_not_guesses(tmp_path):
    parse = M.parse_mbox(write_mbox(tmp_path, simple("[cosai-tsc] AI Jailbreak Framework Meetings")))
    assert parse.occurrences == []
    assert len(parse.findings) == 1 and "no rule matched" in parse.findings[0]


# --- iCalendar --------------------------------------------------------------------

ICS_TEMPLATE = """\
BEGIN:VCALENDAR
BEGIN:VTIMEZONE
TZID:America/New_York
BEGIN:DAYLIGHT
DTSTART:19700308T020000
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=2SU
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
UID:{uid}
SUMMARY:{summary}
ORGANIZER;CN=Claudia Rauch;SENT-BY="mailto:claudia.rauch@oasis-open.org":mailto:claudia.rauch@oasis-open.org
DTSTART:{dtstart}
DTEND:20260811T160000Z
SEQUENCE:1
{extra}END:VEVENT
END:VCALENDAR
"""


def with_calendar(subject: str, ics: str, list_id: str = "cosai-tsc",
                  date: str = "Tue, 11 Aug 2026 10:00:00 +0000") -> str:
    """A multipart message carrying the same VEVENT twice, as the corpus does."""
    return "\n".join([
        f"From: {FROM}", f"Subject: {subject}", f"Date: {date}",
        f"Message-ID: <{abs(hash(subject))}@example.test>",
        f"List-Id: <{list_id}.{M.LIST_DOMAIN}>",
        "MIME-Version: 1.0",
        'Content-Type: multipart/mixed; boundary="B"', "", "--B",
        "Content-Type: text/plain", "", "see calendar", "", "--B",
        "Content-Type: text/calendar; method=REQUEST", "", ics, "", "--B",
        "Content-Type: application/ics; name=invite.ics", "", ics, "", "--B--", ""])


def test_vtimezone_rrule_is_not_read_as_the_meeting_cadence(tmp_path):
    """VTIMEZONE carries its own DTSTART and a yearly RRULE for daylight saving.

    Reading it as the meeting's schedule would date every meeting to 1970 and label
    every series yearly, so only VEVENT is parsed.
    """
    ics = ICS_TEMPLATE.format(uid="u1@x", summary="CoSAI TSC meeting",
                              dtstart="20260811T150000Z", extra="RRULE:FREQ=WEEKLY\n")
    parse = M.parse_mbox(write_mbox(tmp_path, with_calendar("[cosai-tsc] Now: CoSAI TSC meeting", ics)))
    occurrence = parse.occurrences[0]
    assert occurrence.starts_at == "2026-08-11T15:00:00+00:00"
    assert occurrence.cadence == "FREQ=WEEKLY"


def test_duplicate_calendar_parts_yield_one_occurrence(tmp_path):
    """Each notice carries the event as text/calendar *and* application/ics."""
    ics = ICS_TEMPLATE.format(uid="u1@x", summary="CoSAI TSC meeting",
                              dtstart="20260811T150000Z", extra="")
    parse = M.parse_mbox(write_mbox(tmp_path, with_calendar("[cosai-tsc] Now: CoSAI TSC meeting", ics)))
    assert len(parse.occurrences) == 1


def test_canceled_status_is_carried(tmp_path):
    ics = ICS_TEMPLATE.format(uid="u1@x", summary="WS3 SIG", dtstart="20260901T150000Z",
                              extra="STATUS:CANCELLED\nRECURRENCE-ID:20260901T150000Z\n")
    parse = M.parse_mbox(write_mbox(
        tmp_path, with_calendar("[cosai-risk-governance] Cancelled Event: WS3 SIG", ics,
                                list_id="cosai-risk-governance")))
    occurrence = parse.occurrences[0]
    assert occurrence.canceled is True
    assert occurrence.recurrence_id == "2026-09-01T15:00:00+00:00"


# --- subject fallbacks ------------------------------------------------------------

@pytest.mark.parametrize("subject,date", [
    ("[cosai-tsc] Now: CoSAI TSC meeting - Tuesday, 18 August 2026 #cal-notice", "2026-08-18"),
    ("[cosai-risk-governance] 2026-09-03 WS3 Meeting", "2026-09-03"),
])
def test_subject_dates(tmp_path, subject, date):
    parse = M.parse_mbox(write_mbox(tmp_path, simple(subject, list_id="cosai-tsc")))
    record = (parse.occurrences or parse.summaries)[0]
    assert getattr(record, "starts_at", None) == date or record.meeting_date == date


def test_informal_cancellation_falls_back_to_the_send_date_and_says_so(tmp_path):
    """"No WS1 Meeting today" names no date; the send date is weaker evidence."""
    parse = M.parse_mbox(write_mbox(tmp_path, simple(
        "[cosai-supply-chain] No WS1 Meeting today", list_id="cosai-supply-chain",
        date="Wed, 12 Aug 2026 09:00:00 +0000")))
    occurrence = parse.occurrences[0]
    assert occurrence.canceled is True
    assert occurrence.starts_at == "2026-08-12"
    assert occurrence.evidence == "subject-sent-date", "must not pose as a scheduled start"


@pytest.mark.parametrize("subject,list_id,name", [
    ("[cosai-marketing] Event: CoSAI Marketing Group Meeting",
     "cosai-marketing", "CoSAI Marketing Group Meeting"),
    ("[cosai-marketing] Updated Event: CoSAI Marketing Group Meeting",
     "cosai-marketing", "CoSAI Marketing Group Meeting"),
    ("[cosai-marketing] Cancelled Event: Content Subcommittee Meeting",
     "cosai-marketing", "Content Subcommittee Meeting"),
    ("[cosai-defenders] Updated Event: CoSAI WS2 - Zero Trust SIG",
     "cosai-defenders-ws", "CoSAI WS2 - Zero Trust SIG"),
])
def test_a_dateless_calendar_notice_keeps_neither_tag_nor_prefix(tmp_path, subject,
                                                                  list_id, name):
    """Without a date in the subject, the tag and "Event:" prefix leaked into the name,
    so each prefix split one series into several."""
    parse = M.parse_mbox(write_mbox(tmp_path, simple(subject, list_id=list_id)))
    occurrence = parse.occurrences[0]
    assert occurrence.series_name == name
    assert occurrence.evidence == "subject-sent-date"


def test_prefixed_and_dated_notices_of_one_meeting_share_a_series(tmp_path):
    body = "When: Wednesday, 19 August 2026 3:00pm to 4:00pm (UTC+00:00)"
    parse = M.parse_mbox(write_mbox(
        tmp_path,
        simple("[cosai-marketing] Updated Event: CoSAI Marketing Group Meeting",
               list_id="cosai-marketing", body=body),
        simple("[cosai-marketing] Now: CoSAI Marketing Group Meeting - Wednesday, 26 August 2026",
               list_id="cosai-marketing"),
    ))
    assert parse.occurrences[0].evidence == "body-when"
    # One series, under the id curation gave the 2024 name: the Marketing Group
    # meeting is the Committee meeting before its rename.
    assert [s["id"] for s in M.seed_series(parse)] == ["marketing-committee-meeting"]


def test_a_tagged_invitation_never_keeps_its_tag(tmp_path):
    parse = M.parse_mbox(write_mbox(tmp_path, simple(
        "[cosai-tsc] You're Invited: CoSAI Agentic Identity Working Session")))
    assert parse.occurrences[0].series_name == "CoSAI Agentic Identity Working Session"


# --- summaries --------------------------------------------------------------------

def test_summary_records_the_pointer_and_its_restriction(tmp_path):
    body = ("Hi WS4, you can now review the summary\n"
            "<https://docs.google.com/document/d/1UCgvZarSuComABCDEFGHIJKLMNOP>and recording\n"
            "<https://drive.google.com/file/d/1PuQeoM6vzHURQHABCDEFGHIJKLMNOP>\n")
    parse = M.parse_mbox(write_mbox(tmp_path, simple(
        "[cosai-agentic-systems] 2026-09-03 WS4 General Meeting",
        list_id="cosai-agentic-systems-ws", body=body)))
    summary = parse.summaries[0]
    assert summary.meeting_date == "2026-09-03"
    assert len(summary.urls) == 2
    assert summary.access_restricted is True, "the docs return 401 to anonymous fetch"


# --- series seeding ---------------------------------------------------------------

def test_uid_and_subject_groups_merge_into_one_series(tmp_path):
    """Without the merge, one series appears once per UID and once for its notices."""
    ics = ICS_TEMPLATE.format(uid="u1@x", summary="CoSAI WS1 Meeting",
                              dtstart="20260819T150000Z", extra="")
    parse = M.parse_mbox(write_mbox(
        tmp_path,
        with_calendar("[cosai-supply-chain] Now: CoSAI WS1 Meeting", ics,
                      list_id="cosai-supply-chain"),
        simple("[cosai-supply-chain] Now: CoSAI WS1 Meeting (updated link) - Wednesday, 26 August 2026",
               list_id="cosai-supply-chain"),
    ))
    series = M.seed_series(parse)
    assert len(series) == 1, [s["id"] for s in series]
    assert series[0]["occurrences"] == 2
    assert len(series[0]["name_variants"]) == 2, "both verbatim spellings are kept"


def test_parenthetical_qualifiers_do_not_create_a_second_series():
    assert M._series_key("CoSAI WS1 Meeting (updated link)") == M._series_key("CoSAI WS1 Meeting")


def test_genuine_name_drift_stays_visible_for_review():
    """Normalization alone must not collapse these: that would be a guess. They are
    one series only because the registry says so, after review of their dates."""
    assert M._normalize("WS3 Bi-weekly Meeting") != M._normalize("WS3 Meeting")
    assert M._series_key("WS3 Bi-weekly Meeting") == M._series_key("WS3 Meeting")


def test_calendar_rrule_wins_over_a_subject_word(tmp_path):
    """A subject saying "weekly" is weaker than an explicit RRULE with a BYDAY.

    An uncurated name, because a curated series takes the registry's cadence over
    either: see test_a_curated_cadence_wins_over_the_mail."""
    ics = ICS_TEMPLATE.format(uid="u1@x", summary="Example SIG weekly meeting",
                              dtstart="20260819T150000Z",
                              extra="RRULE:FREQ=WEEKLY;INTERVAL=1;BYDAY=TU\n")
    parse = M.parse_mbox(write_mbox(
        tmp_path,
        simple("[cosai-tsc] Now: Example SIG weekly meeting - Wednesday, 12 August 2026"),
        with_calendar("[cosai-tsc] Now: Example SIG weekly meeting", ics),
    ))
    assert M.seed_series(parse)[0]["cadence"] == "FREQ=WEEKLY;INTERVAL=1;BYDAY=TU"


def test_a_curated_cadence_wins_over_the_mail(tmp_path):
    """A series merged across a rename carries each era's RRULE, so whichever
    calendar part came last would otherwise decide. WS3's weekly-era RRULE must not
    describe its bi-weekly plenary."""
    ics = ICS_TEMPLATE.format(uid="u2@x", summary="CoSAI WS3 recurring weekly meeting",
                              dtstart="20251120T150000Z",
                              extra="RRULE:FREQ=WEEKLY;BYDAY=TH\n")
    parse = M.parse_mbox(write_mbox(tmp_path, with_calendar(
        "[cosai-risk-governance] Now: CoSAI WS3 recurring weekly meeting", ics,
        list_id="cosai-risk-governance")))
    assert M.seed_series(parse)[0]["cadence"] == "FREQ=WEEKLY;INTERVAL=2;BYDAY=TH"


def test_folded_subject_whitespace_is_normalized(tmp_path):
    """A newline inside a series name corrupts the registry key and the report table."""
    raw = ("From: x@example.test\nSubject: [cosai-tsc] Now: CoSAI Agentic Identity\n"
           " Working Session - Tuesday, 11 August 2026\n"
           "Date: Tue, 11 Aug 2026 10:00:00 +0000\nMessage-ID: <a@b>\n"
           f"List-Id: <cosai-tsc.{M.LIST_DOMAIN}>\n\nbody\n")
    parse = M.parse_mbox(write_mbox(tmp_path, raw))
    assert "\n" not in parse.occurrences[0].series_name
    assert parse.occurrences[0].series_name == "CoSAI Agentic Identity Working Session"


# --- the body's "When:" line, for notices with no calendar part -------------------

def test_a_when_line_gives_start_and_end_in_utc():
    from bubo_graphrag.ingest.maillist import when_of

    body = ("When:\n\nFriday, 27 September 2024\n\n 1:00pm to 2:00pm\n\n"
            "(UTC-04:00) America/New York\n")
    assert when_of(body) == ("2024-09-27T17:00:00+00:00", "2024-09-27T18:00:00+00:00")


def test_a_when_line_without_minutes_or_crossing_days_still_parses():
    from bubo_graphrag.ingest.maillist import when_of

    body = "When: Monday, 31 August 2026 11pm to Tuesday, 1 September 2026 1am (GMT+02:00)"
    assert when_of(body) == ("2026-08-31T21:00:00+00:00", "2026-08-31T23:00:00+00:00")


def test_no_when_line_is_none_not_a_guess():
    from bubo_graphrag.ingest.maillist import when_of

    assert when_of("When: sometime next week") is None
    assert when_of("") is None
