"""Meetings graph builder tests.

Built from synthetic mbox fixtures, never from the fetched archives: see
test_maillist.py for why. These assert the modeling decisions, not just that triples appear -- the
series/occurrence split, the SIG part-of relation, and the two invariants that keep
this source honest (no attendance, and no triple owned by another named graph).
"""

from __future__ import annotations

from rdflib import RDF, RDFS, XSD, Literal, Namespace, URIRef

from bubo_graphrag.build.meetings import CONVENERS, MeetingsBuilder, build
from bubo_graphrag.ingest.maillist import parse_mbox, seed_series
from test_maillist import ICS_TEMPLATE, simple, with_calendar, write_mbox

COSAIC = Namespace("https://cosai-oasis.github.io/ontology/cosai-contrib#")
OBO = Namespace("http://purl.obolibrary.org/obo/")


def graph_for(tmp_path, *messages):
    path = write_mbox(tmp_path, *messages)
    graph, parse, series, unlinked = build(path)
    return graph, parse, series


# --- series and occurrences -------------------------------------------------------

def test_series_is_a_schedule_and_the_meeting_is_a_process(tmp_path):
    """The BFO split: a recurring meeting is not one occurrent.

    The series prescribes; each occurrence is its own process occupying an instant.
    """
    ics = ICS_TEMPLATE.format(uid="u1@x", summary="CoSAI TSC meeting",
                              dtstart="20260811T150000Z", extra="RRULE:FREQ=WEEKLY\n")
    graph, _, _ = graph_for(tmp_path, with_calendar("[cosai-tsc] Now: CoSAI TSC meeting", ics))

    series = next(graph.subjects(RDF.type, COSAIC.MeetingSeries))
    meeting = next(graph.subjects(RDF.type, COSAIC.Meeting))
    assert (series, COSAIC.cadence, Literal("FREQ=WEEKLY")) in graph
    assert (meeting, COSAIC.inSeries, series) in graph
    assert graph.value(meeting, OBO.BFO_0000199) == COSAIC["instant-2026-08-11"]


def test_series_keeps_every_observed_name_verbatim(tmp_path):
    """Name drift is the audit trail, as sourceLabel is for credited roles."""
    graph, _, _ = graph_for(
        tmp_path,
        simple("[cosai-supply-chain] Now: CoSAI WS1 Meeting - Wednesday, 19 August 2026",
               list_id="cosai-supply-chain"),
        simple("[cosai-supply-chain] Now: CoSAI WS1 Meeting (updated link) - Wednesday, 26 August 2026",
               list_id="cosai-supply-chain"),
    )
    series = next(graph.subjects(RDF.type, COSAIC.MeetingSeries))
    variants = {str(v) for v in graph.objects(series, COSAIC.seriesNameVariant)}
    assert variants == {"CoSAI WS1 Meeting", "CoSAI WS1 Meeting (updated link)"}
    assert len(list(graph.subjects(RDF.type, COSAIC.MeetingSeries))) == 1


def test_one_occurrence_per_series_and_day(tmp_path):
    """Two messages can announce the same meeting; that is one occurrence."""
    ics = ICS_TEMPLATE.format(uid="u1@x", summary="CoSAI WS2 regular meeting",
                              dtstart="20260811T150000Z", extra="")
    graph, _, _ = graph_for(
        tmp_path,
        with_calendar("[cosai-defenders] Now: CoSAI WS2 regular meeting", ics,
                      list_id="cosai-defenders-ws"),
        simple("[cosai-defenders] Now: CoSAI WS2 regular meeting - Tuesday, 11 August 2026",
               list_id="cosai-defenders-ws"),
    )
    assert len(list(graph.subjects(RDF.type, COSAIC.Meeting))) == 1


def test_a_canceled_occurrence_is_retained_with_its_own_event(tmp_path):
    """Dropping it would lose evidence that the series was scheduled that week."""
    ics = ICS_TEMPLATE.format(uid="u1@x", summary="WS3 SIG: Security of Code",
                              dtstart="20260901T150000Z",
                              extra="STATUS:CANCELLED\n")
    graph, _, _ = graph_for(tmp_path, with_calendar(
        "[cosai-risk-governance] Cancelled Event: WS3 SIG: Security of Code", ics,
        list_id="cosai-risk-governance"))

    meeting = next(graph.subjects(RDF.type, COSAIC.Meeting))
    assert (meeting, COSAIC.canceled, Literal(True)) in graph
    cancellation = next(graph.subjects(RDF.type, COSAIC.MeetingCancellation))
    assert (cancellation, COSAIC.cancels, meeting) in graph


def test_date_evidence_travels_with_the_meeting(tmp_path):
    """A date taken from the send date must not pass as a scheduled start."""
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-supply-chain] No WS1 Meeting today", list_id="cosai-supply-chain",
        date="Wed, 12 Aug 2026 09:00:00 +0000"))
    meeting = next(graph.subjects(RDF.type, COSAIC.Meeting))
    assert graph.value(meeting, COSAIC.dateEvidence) == Literal("subject-sent-date")
    assert graph.value(meeting, COSAIC.startsAt) is None, "no false precision"


# --- groups -----------------------------------------------------------------------

def test_a_sig_is_part_of_its_workstream(tmp_path):
    """SIGs announce on the parent workstream's list, so the name identifies them."""
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-risk-governance] Now: WS3 SIG: Security of AI-Assisted Code Development"
        " - Tuesday, 18 August 2026", list_id="cosai-risk-governance"))
    sig = next(graph.subjects(RDF.type, COSAIC.SpecialInterestGroup))
    assert (sig, OBO.BFO_0000050, COSAIC["ws-ws3"]) in graph      # part of
    series = next(graph.subjects(RDF.type, COSAIC.MeetingSeries))
    assert (series, COSAIC.convenedBy, sig) in graph


def test_a_non_sig_series_is_convened_by_the_workstream_itself(tmp_path):
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-defenders] Now: CoSAI WS2 regular meeting, bi-weekly - Tuesday, 11 August 2026",
        list_id="cosai-defenders-ws"))
    series = next(graph.subjects(RDF.type, COSAIC.MeetingSeries))
    assert (series, COSAIC.convenedBy, COSAIC["ws-ws2"]) in graph
    assert not list(graph.subjects(RDF.type, COSAIC.SpecialInterestGroup))


def test_conveners_are_the_nodes_the_publication_graph_declares():
    """Meetings must attach to the same ws-*, gov-* and com-* nodes, not a parallel
    set."""
    from bubo_graphrag.paths import committees, governing_bodies, workstreams

    declared = ({f"ws-{key}" for key in workstreams()}
                | {f"gov-{key}" for key in governing_bodies()}
                | {f"com-{key}" for key in committees()})
    assert set(CONVENERS.values()) == declared


def test_a_tsc_series_is_convened_by_the_governing_body_it_only_references(tmp_path):
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-tsc] Now: CoSAI TSC meeting - Tuesday, 11 August 2026"))
    series = next(graph.subjects(RDF.type, COSAIC.MeetingSeries))
    assert (series, COSAIC.convenedBy, COSAIC["gov-tsc"]) in graph
    assert (COSAIC["gov-tsc"], RDF.type, COSAIC.GoverningBody) not in graph, \
        "the publications graph owns the declaration"


# --- the two invariants -----------------------------------------------------------

def test_no_attendance_is_ever_asserted(tmp_path):
    """There is no attendee data in this source, so there must be no attendance.

    Asserting an empty or inferred attendance would turn "unknown" into "nobody", and
    would risk attendance being read as contribution credit.
    """
    ics = ICS_TEMPLATE.format(uid="u1@x", summary="CoSAI TSC meeting",
                              dtstart="20260811T150000Z", extra="")
    graph, _, _ = graph_for(
        tmp_path,
        with_calendar("[cosai-tsc] Now: CoSAI TSC meeting", ics),
        simple("[cosai-tsc] 2026-08-11 TSC Meeting Summary"),
    )
    assert not list(graph.subjects(RDF.type, COSAIC.AttendanceRole))
    assert not list(graph.subjects(RDF.type, COSAIC.CreditedRole))


def test_workstream_type_is_not_re_declared(tmp_path):
    """The publications graph owns it; a duplicate doubles rows under union queries."""
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-defenders] Now: CoSAI WS2 regular meeting - Tuesday, 11 August 2026",
        list_id="cosai-defenders-ws"))
    assert (COSAIC["ws-ws2"], RDF.type, COSAIC.Workstream) not in graph
    assert (None, COSAIC.convenedBy, COSAIC["ws-ws2"]) in graph, "still referenced"


def test_instants_already_owned_by_the_catalog_are_not_redeclared():
    builder = MeetingsBuilder(existing_instants=frozenset({"2026-08-11"}))
    shared = builder.instant("2026-08-11")
    fresh = builder.instant("2026-08-12")
    assert (shared, RDF.type, COSAIC.Instant) not in builder.g
    assert (fresh, RDF.type, COSAIC.Instant) in builder.g


# --- coverage and summaries -------------------------------------------------------

def test_coverage_window_is_recorded_with_open_bounds(tmp_path):
    """Outside the window, no meeting is not evidence of no meeting."""
    graph, _, _ = graph_for(
        tmp_path,
        simple("[cosai-tsc] Now: CoSAI TSC meeting - Tuesday, 11 August 2026",
               date="Tue, 11 Aug 2026 10:00:00 +0000"),
        simple("[cosai-tsc] Call for Consensus on a Blog Post",
               date="Wed, 09 Sep 2026 10:00:00 +0000"),
    )
    window = next(graph.subjects(RDF.type, COSAIC.CoverageWindow))
    assert graph.value(window, COSAIC.earliestMessage) == Literal(
        "2026-08-11", datatype=URIRef("http://www.w3.org/2001/XMLSchema#date"))
    assert graph.value(window, COSAIC.latestMessage) == Literal(
        "2026-09-09", datatype=URIRef("http://www.w3.org/2001/XMLSchema#date"))
    assert graph.value(window, COSAIC.boundsKnown) == Literal(False)


def test_summary_is_a_pointer_flagged_restricted(tmp_path):
    """Verified by fetch: three summary docs returned HTTP 401 anonymously."""
    body = ("review the summary\n"
            "<https://docs.google.com/document/d/1UCgvZarSuComABCDEFGHIJKLMNOP>\n")
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-agentic-systems] 2026-09-03 WS4 General Meeting",
        list_id="cosai-agentic-systems-ws", body=body))
    summary = next(graph.subjects(RDF.type, COSAIC.MeetingSummary))
    assert graph.value(summary, COSAIC.accessRestricted) == Literal(True)
    assert list(graph.objects(summary, COSAIC.sourceUrl))


def test_every_assertion_carries_its_source_message(tmp_path):
    """Provenance is the reason raw mail beats the web archive."""
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-tsc] Now: CoSAI TSC meeting - Tuesday, 11 August 2026"))
    meeting = next(graph.subjects(RDF.type, COSAIC.Meeting))
    assert graph.value(meeting, COSAIC.sourceMessageId) is not None


def test_governance_events_are_captured(tmp_path):
    """They record why a publication reached its approval status."""
    graph, _, _ = graph_for(
        tmp_path,
        simple("[cosai-defenders] Zero Trust Paper approved by TSC and PGB",
               list_id="cosai-defenders-ws"),
    )
    events = list(graph.subjects(RDF.type, COSAIC.GovernanceEvent))
    assert len(events) == 1
    assert (events[0], COSAIC.announcedOn, COSAIC["ws-ws2"]) in graph


# --- summary attachment -----------------------------------------------------------

def test_summary_attaches_on_workstream_and_day_not_on_name(tmp_path):
    """Notice titles and summary titles never agree; matching on names linked 0 of 26.

    The notice says "CoSAI WS2 regular meeting, bi-weekly"; its summary says
    "WS2 bi-weekly meeting records". The reliable join is the list it arrived on plus
    the date.
    """
    body = "summary <https://docs.google.com/document/d/1UCgvZarSuComABCDEFGHIJKLMN>\n"
    graph, _, _ = graph_for(
        tmp_path,
        simple("[cosai-defenders] Now: CoSAI WS2 regular meeting, bi-weekly"
               " - Tuesday, 11 August 2026", list_id="cosai-defenders-ws"),
        simple("[cosai-defenders] 2026-08-11 WS2 bi-weekly meeting records",
               list_id="cosai-defenders-ws", body=body),
    )
    meeting = next(graph.subjects(RDF.type, COSAIC.Meeting))
    summary = next(graph.subjects(RDF.type, COSAIC.MeetingSummary))
    assert (meeting, COSAIC.summarizedBy, summary) in graph


def test_an_ambiguous_summary_is_left_unattached_and_reported(tmp_path):
    """Two meetings on one workstream's day: attributing the summary would be a guess."""
    path = write_mbox(
        tmp_path,
        simple("[cosai-risk-governance] Now: WS3 Bi-weekly Meeting - Tuesday, 18 August 2026",
               list_id="cosai-risk-governance"),
        simple("[cosai-risk-governance] Now: WS3 SIG: Security of Code - Tuesday, 18 August 2026",
               list_id="cosai-risk-governance"),
        simple("[cosai-risk-governance] 2026-08-18 WS3 Meeting", list_id="cosai-risk-governance",
               body="summary <https://docs.google.com/document/d/1UCgvZarSuComABCDEFGHIJ>"),
    )
    graph, _, _, unlinked = build(path)
    assert not list(graph.subject_objects(COSAIC.summarizedBy))
    assert len(unlinked) == 1 and "2 candidate meetings" in unlinked[0]
    assert list(graph.subjects(RDF.type, COSAIC.MeetingSummary)), "still recorded"


def test_instants_use_the_same_class_as_the_publication_graph(tmp_path):
    """One concept, one spelling. `cosaic:Instant` subclasses obo:BFO_0000148, and the
    publications graph types its dates that way; emitting the BFO class directly here
    would split every temporal query across two type names."""
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-tsc] Now: CoSAI TSC meeting - Tuesday, 11 August 2026"))
    instants = list(graph.subjects(RDF.type, COSAIC.Instant))
    assert instants
    assert not list(graph.subjects(RDF.type, OBO.BFO_0000148))


# --- the curated series registry (A-double-prime.0) -------------------------------

def test_registry_merges_spellings_no_rule_could_relate():
    """Mechanical normalization reaches only what looks alike.

    "CoSAI-RM meeting" and "CoSAI-RM SIG weekly meeting" are one series and no rule
    relates them; "WS3 Bi-weekly Meeting" and "WS3 SIG: ..." look similar and are two.
    That is why the merge is curated rather than derived.
    """
    from bubo_graphrag.ingest.maillist import _series_key

    assert _series_key("CoSAI-RM meeting") == _series_key("CoSAI-RM SIG weekly meeting")
    assert _series_key("Security of AI-Assisted Code Development") == \
           _series_key("WS3 SIG: Security of AI-Assisted Code Development")
    assert _series_key("WS1 Meeting") == _series_key("CoSAI WS1 Weekly Meeting") == \
           _series_key("CoSAI WS1 Meeting (updated link)")
    assert _series_key("WS3 Bi-weekly Meeting") != \
           _series_key("WS3 SIG: Security of AI-Assisted Code Development")


def test_an_uncurated_series_still_appears_as_itself():
    """A series nobody has curated must not be merged into a neighbour."""
    from bubo_graphrag.ingest.maillist import _series_key

    assert _series_key("Some Brand New WS9 Meeting") == "some-brand-new-ws9-meeting"


def test_the_curated_label_wins_over_the_first_observed_spelling(tmp_path):
    """The code SIG's short form appears only in cancellation notices, so labeling
    the series with it would name a group after the notice calling off its meeting."""
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-risk-governance] No Security of AI-Assisted Code Development this week",
        list_id="cosai-risk-governance"))
    series = next(graph.subjects(RDF.type, COSAIC.MeetingSeries))
    assert str(graph.value(series, RDFS.label)) == \
        "WS3 SIG: Security of AI-Assisted Code Development"


def test_every_registry_entry_is_well_formed():
    from bubo_graphrag.paths import load_registry

    entries = load_registry("meeting-series")["meeting_series"]
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids)), "duplicate series id"
    for entry in entries:
        assert entry["label"] and entry["kind"] and entry["workstream"]
        assert entry["kind"] in {"workstream-meeting", "sig", "topic-meeting",
                                 "governance-meeting", "committee-meeting",
                                 "one-off"}
        # "general" is the one deliberate exception: a project-wide event cross-posted
        # to every list, which no single group convenes.
        assert entry["workstream"] in CONVENERS or entry["workstream"] == "general", \
            f"{entry['id']} names no group the graph declares"
        # A series with neither an observed name nor an upstream title form could
        # never be matched to anything, so it would be a dead entry.
        assert entry.get("name_variants") or entry.get("drive_title_forms") \
            or entry.get("minutes_repo"), f"{entry['id']} is unreachable"


def test_a_curated_series_seen_first_on_the_project_list_keeps_its_workstream(tmp_path):
    """The registry's workstream wins over the list a message happened to arrive on.

    `cosai-op` is project-wide, so a cancellation posted there says nothing about which
    group the series belongs to. Taking the convener from the first message left the
    SRF & GRC SIG with none.
    """
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-op] Cancelled Event: CoSAI WS3 SRF & GRC SIG - Monday, 8 June 2026",
        list_id="cosai-op"))
    series = COSAIC["series-ws3-srf-grc-sig"]
    sig = graph.value(series, COSAIC.convenedBy)
    assert sig is not None, "the SIG lost its convener"
    assert (sig, OBO.BFO_0000050, COSAIC["ws-ws3"]) in graph


def test_a_cross_posted_cancellation_does_not_become_the_series_list(tmp_path):
    """The source list is what how_to_get_involved tells a newcomer to join. A WS1
    cancellation on the project-wide list must not make `cosai-op` a WS1 list."""
    graph, _, _ = graph_for(
        tmp_path,
        simple("[cosai-op] Cancelled Event: WS1 Weekly Meeting - Wednesday, 25 March 2026",
               list_id="cosai-op", date="Mon, 23 Mar 2026 10:00:00 +0000"),
        simple("[cosai-supply-chain] Now: CoSAI WS1 Meeting - Wednesday, 1 April 2026",
               list_id="cosai-supply-chain", date="Wed, 01 Apr 2026 10:00:00 +0000"))
    assert [str(o) for o in graph.objects(COSAIC["series-ws1-meeting"],
                                          COSAIC.sourceList)] == ["cosai-supply-chain"]


def test_no_curated_series_names_the_project_wide_list():
    from bubo_graphrag.paths import load_registry

    for entry in load_registry("meeting-series")["meeting_series"]:
        assert "cosai-op" not in entry.get("lists", []), entry["id"]
        if entry["workstream"] != "general":
            assert entry.get("lists"), f"{entry['id']} names no list to join"


def test_a_curated_kind_decides_sig_status_over_the_name(tmp_path):
    """Neither calendar title below contains "SIG", and both series are SIGs'. The
    Telemetry SIG announces as "WS2 Defenders – Telemetry"; only its summaries name
    it a SIG."""
    graph, _, _ = graph_for(
        tmp_path,
        simple("[cosai-defenders] Now: WS2 Defenders – Telemetry"
               " - Thursday, 17 September 2026", list_id="cosai-defenders"),
        simple("[cosai-agentic-systems] Now: WS4 Multimodal Agentic Security Weekly"
               " Meeting - Monday, 31 August 2026", list_id="cosai-agentic-systems"))
    for series, parent in (("ws2-defenders-telemetry", "ws-ws2"),
                           ("ws4-multimodal-agentic-security", "ws-ws4")):
        sig = graph.value(COSAIC[f"series-{series}"], COSAIC.convenedBy)
        assert (sig, RDF.type, COSAIC.SpecialInterestGroup) in graph, series
        assert (sig, OBO.BFO_0000050, COSAIC[parent]) in graph


def test_a_renamed_series_is_one_series_across_the_rename(tmp_path):
    """WS3's weekly plenary became a bi-weekly one in December 2025, with no overlap.
    One group's plenary across the change, so cadence is measured over its whole
    history rather than per name."""
    graph, _, series = graph_for(
        tmp_path,
        simple("[cosai-risk-governance] Now: CoSAI WS3 recurring weekly meeting"
               " - Thursday, 20 November 2025", list_id="cosai-risk-governance",
               date="Thu, 20 Nov 2025 10:00:00 +0000"),
        simple("[cosai-risk-governance] Now: WS3 Bi-weekly Meeting"
               " - Thursday, 17 September 2026", list_id="cosai-risk-governance",
               date="Thu, 17 Sep 2026 10:00:00 +0000"))
    assert [s["id"] for s in series] == ["ws3-meeting"]
    assert graph.value(COSAIC["series-ws3-meeting"], COSAIC.convenedBy) == COSAIC["ws-ws3"]


def test_a_marketing_series_is_convened_by_the_committee_it_only_references(tmp_path):
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-marketing] Now: CoSAI Content Subcommittee Meeting"
        " - Wednesday, 19 February 2025", list_id="cosai-marketing"))
    series = next(graph.subjects(RDF.type, COSAIC.MeetingSeries))
    assert (series, COSAIC.convenedBy, COSAIC["com-marketing"]) in graph
    assert (COSAIC["com-marketing"], RDF.type, COSAIC.Committee) not in graph, \
        "the publications graph owns the declaration"


# --- curator statements -----------------------------------------------------------

def test_a_stated_status_is_asserted_on_the_sig_and_dated(tmp_path):
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-defenders] Now: CoSAI WS2 - Zero Trust SIG - Thursday, 18 June 2026",
        list_id="cosai-defenders"))
    sig = graph.value(COSAIC["series-ws2-zero-trust-sig"], COSAIC.convenedBy)
    assert str(graph.value(sig, COSAIC.activityStatus)) == "inactive"
    assert graph.value(sig, COSAIC.statusAsOf).datatype == XSD.date


def test_no_status_is_inferred_from_a_quiet_group(tmp_path):
    """The SIG below last met in 2025 and has no stated status, so it gets none."""
    graph, _, _ = graph_for(tmp_path, simple(
        "[cosai-supply-chain] Now: CoSAI WS1 Model Cards SIG - Wednesday, 11 June 2025",
        list_id="cosai-supply-chain", date="Wed, 11 Jun 2025 10:00:00 +0000"))
    assert not list(graph.subject_objects(COSAIC.activityStatus))


def test_a_moved_sig_is_two_groups_linked_by_succession(tmp_path):
    """The SRM SIG moved from WS2 to WS3 as the SRF & GRC SIG. Each node stays part
    of the workstream it met under; one node would place a WS3 SIG in 2025."""
    graph, _, _ = graph_for(
        tmp_path,
        simple("[cosai-defenders] Now: WS2 Shared Responsibility Model SIG"
               " - Wednesday, 3 June 2026", list_id="cosai-defenders",
               date="Wed, 03 Jun 2026 10:00:00 +0000"),
        simple("[cosai-risk-governance] Now: CoSAI WS3 SRF & GRC SIG"
               " - Monday, 8 June 2026", list_id="cosai-risk-governance",
               date="Mon, 08 Jun 2026 10:00:00 +0000"))
    srm = graph.value(COSAIC["series-ws2-shared-responsibility-model-sig"],
                      COSAIC.convenedBy)
    srf = graph.value(COSAIC["series-ws3-srf-grc-sig"], COSAIC.convenedBy)
    assert (srm, COSAIC.succeededBy, srf) in graph
    assert (srm, OBO.BFO_0000050, COSAIC["ws-ws2"]) in graph
    assert (srf, OBO.BFO_0000050, COSAIC["ws-ws3"]) in graph


def test_a_curated_series_without_mail_is_declared_only_when_asked(tmp_path):
    """The calendar schedules WS3's threat modeling sync, whose meetings the lists never
    announce; its series node must exist for the calendar to link to, but a build of a
    few test messages must reflect only those messages."""
    from bubo_graphrag.build import meetings as B
    series = B.curated_only_series([])
    assert "ws3-agentic-coding-threat-modeling-sync" in {s["id"] for s in series}
    present = B.curated_only_series([{"id": "ws3-agentic-coding-threat-modeling-sync"}])
    assert "ws3-agentic-coding-threat-modeling-sync" not in {s["id"] for s in present}


# --- governance calls and approval links -------------------------------------------

OPEN_CALL = "Please register any objections no later than Friday, September 4, 2026 at 6pm ET."
CLOSED_CALL = "This call for consensus is now closed. No objections were registered."
V2 = "[cosai-tsc] Call for Consensus to approve version 2 of Paper X"
V2_KEY = "call for consensus to approve version 2 of paper x"


def calls_graph(tmp_path, *messages, curation=None):
    graph, parse, _, _ = build(write_mbox(tmp_path, *messages), approval_curation=curation)
    return graph, parse


def test_a_call_groups_its_messages_and_records_its_dates(tmp_path):
    graph, parse = calls_graph(
        tmp_path,
        simple(V2, body=OPEN_CALL, date="Tue, 01 Sep 2026 10:00:00 +0000"),
        simple(f"Re: {V2}", body=CLOSED_CALL, date="Mon, 07 Sep 2026 10:00:00 +0000"),
    )
    [call] = list(graph.subjects(RDF.type, COSAIC.GovernanceCall))
    assert {graph.value(COSAIC[f"govevent-{i:03d}"], COSAIC.partOfCall)
            for i in range(len(parse.governance))} == {call}
    assert graph.value(call, COSAIC.decidedBy) == COSAIC["gov-tsc"]
    assert graph.value(call, COSAIC.openedOn) == Literal("2026-09-01", datatype=XSD.date)
    assert graph.value(call, COSAIC.objectionDeadline) == Literal("2026-09-04", datatype=XSD.date)
    assert graph.value(call, COSAIC.closedOn) == Literal("2026-09-07", datatype=XSD.date)
    # A message is not a call: only the grouping node carries the class.
    assert (COSAIC["govevent-000"], RDF.type, COSAIC.GovernanceCall) not in graph


def test_curated_roles_become_role_properties(tmp_path):
    curation = {"threads": {V2_KEY: {"subject_matter": "publication", "works": [
        {"id": "paper-x", "as": "revision"},
        {"id": "addendum-y", "as": "addition", "to": "paper-x"}]}}}
    graph, _ = calls_graph(tmp_path, simple(V2, body=CLOSED_CALL), curation=curation)
    [call] = list(graph.subjects(RDF.type, COSAIC.GovernanceCall))
    assert graph.value(call, COSAIC.callsToApproveRevision) == COSAIC["pub-paper-x"]
    assert graph.value(call, COSAIC.callsToApproveAddition) == COSAIC["pub-addendum-y"]
    assert graph.value(COSAIC["pub-addendum-y"], COSAIC.isAdditionTo) == COSAIC["pub-paper-x"]
    assert graph.value(call, COSAIC.callsToApproveNew) is None
    assert graph.value(call, COSAIC.subjectMatter) == Literal("publication")


def test_a_review_period_links_its_work_by_review_not_approval(tmp_path):
    key = "5 day review period for paper x starts now"
    curation = {"threads": {key: {"subject_matter": "publication",
                                  "works": [{"id": "paper-x", "as": "new"}]}}}
    graph, _ = calls_graph(tmp_path, simple("[cosai-tsc] 5-Day Review Period for Paper X starts now"),
                           curation=curation)
    [call] = list(graph.subjects(RDF.type, COSAIC.GovernanceCall))
    assert graph.value(call, COSAIC.callsToReview) == COSAIC["pub-paper-x"]
    assert graph.value(call, COSAIC.callsToApproveNew) is None


def test_a_tsc_and_a_pgb_call_on_one_subject_are_two_calls(tmp_path):
    graph, _ = calls_graph(
        tmp_path,
        simple("[cosai-tsc] Call for Consensus to approve Paper X", body=CLOSED_CALL),
        simple("[cosai-pgb] Call for Consensus to approve Paper X", list_id="cosai-pgb",
               body=CLOSED_CALL),
    )
    bodies = {str(graph.value(c, COSAIC.decidedBy)).rsplit("#", 1)[1]
              for c in graph.subjects(RDF.type, COSAIC.GovernanceCall)}
    assert bodies == {"gov-tsc", "gov-pgb"}


def test_an_uncurated_call_is_kept_but_links_nothing(tmp_path):
    graph, _ = calls_graph(tmp_path, simple(V2, body=CLOSED_CALL))
    [call] = list(graph.subjects(RDF.type, COSAIC.GovernanceCall))
    assert graph.value(call, COSAIC.subjectMatter) is None
    assert not [o for p in (COSAIC.callsToApproveNew, COSAIC.callsToApproveRevision,
                            COSAIC.callsToApproveAddition, COSAIC.callsToReview)
                for o in graph.objects(call, p)]


def test_a_work_not_yet_in_the_registry_is_a_title_not_a_node(tmp_path):
    curation = {"threads": {V2_KEY: {"subject_matter": "publication", "works": [],
                                     "unregistered": [{"title": "AIMM", "as": "new"}]}}}
    graph, _ = calls_graph(tmp_path, simple(V2, body=CLOSED_CALL), curation=curation)
    [call] = list(graph.subjects(RDF.type, COSAIC.GovernanceCall))
    assert graph.value(call, COSAIC.concernsTitle) == Literal("AIMM")
    assert not any("aimm" in str(o).lower() for o in graph.objects(call, None)
                   if isinstance(o, URIRef))


def test_an_announced_then_canceled_meeting_is_canceled_once_with_its_own_event(tmp_path):
    """A notice then a cancellation: one meeting, canceled, and a separate event."""
    graph, _, _ = graph_for(
        tmp_path,
        simple("[cosai-tsc] Now: CoSAI TSC meeting - Tuesday, 11 August 2026"),
        simple("[cosai-tsc] No TSC meeting this week", date="Tue, 11 Aug 2026 09:00:00 +0000"),
    )
    [meeting] = list(graph.subjects(RDF.type, COSAIC.Meeting))
    assert list(graph.objects(meeting, COSAIC.canceled)) == [Literal(True)]
    [event] = list(graph.subjects(RDF.type, COSAIC.MeetingCancellation))
    assert graph.value(event, COSAIC.cancels) == meeting
