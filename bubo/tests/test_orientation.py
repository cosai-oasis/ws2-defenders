"""The newcomer-facing tools.

These answer "what is CoSAI doing", "how do I get involved" and "when are the meetings
on X" -- questions whose unit is a *group* someone can join, not a person or a document.
The tests pin two things: that the answers are shaped for someone with no prior
knowledge, and that the tools stay honest about what this graph cannot tell them.
"""

from __future__ import annotations

import pytest

from bubo_graphrag import queries as Q
from bubo_graphrag import server as S


@pytest.fixture(autouse=True)
def _built(store):
    return store


# --- cosai_overview ---------------------------------------------------------------

def test_overview_answers_what_is_cosai_doing():
    overview = S.cosai_overview()
    assert overview["workstreams"], "a newcomer needs the groups"
    assert overview["special_interest_groups"]
    assert overview["recent_publications"]
    assert overview["meeting_coverage"], "and the window those meeting counts cover"


def test_overview_declares_what_it_cannot_answer():
    """Attendance is the question this graph most obviously invites and cannot answer.

    Saying so in the payload is what stops a caller inferring it from meeting counts.
    """
    unanswerable = S.cosai_overview()["not_yet_answerable"]
    assert "attendance" in unanswerable
    assert "names no attendees" in unanswerable["attendance"]
    assert "discussion" in unanswerable


def test_overview_warns_that_meeting_counts_are_partial():
    caveats = " ".join(S.cosai_overview()["caveats"]).lower()
    assert "not totals" in caveats
    assert "no cadence" in caveats, "a missing cadence must not read as 'does not meet'"


def test_every_group_appears_once():
    """Regression: grouping by cadence and list produced a row per series, so a
    workstream with three series appeared three times."""
    overview = S.cosai_overview()
    ids = [g["group_id"] for g in overview["workstreams"]] + \
          [g["group_id"] for g in overview["governing_bodies"]] + \
          [g["group_id"] for g in overview["special_interest_groups"]]
    assert len(ids) == len(set(ids)), f"duplicated groups: {ids}"


def test_the_tsc_and_pgb_are_governing_bodies_not_workstreams():
    """They convene meetings and approve work, but produce no publication."""
    overview = S.cosai_overview()
    assert {g["group_id"] for g in overview["governing_bodies"]} == {"tsc", "pgb"}
    assert not {"tsc", "pgb"} & {g["group_id"] for g in overview["workstreams"]}
    pgb = next(g for g in overview["governing_bodies"] if g["group_id"] == "pgb")
    assert pgb["meetings_seen"] > 0, "PGB series must attach to the PGB node"


def test_meeting_timeline_accepts_a_governing_body():
    assert S.meeting_timeline("tsc")["meetings"]


def test_a_series_without_a_cadence_does_not_erase_its_siblings(store):
    """Regression: GROUP_CONCAT over a group containing an unbound value returns
    unbound, so WS2's one cadence-less series erased the RRULE of the other."""
    rows = store.select(Q.render(Q.GROUP_DIRECTORY))
    ws2 = next(r for r in rows if r.get("groupId") == "ws2")
    assert "FREQ=" in str(ws2.get("cadences")), ws2
    group = next(g for g in S.cosai_overview()["workstreams"]
                 if g["group_id"] == "ws2")
    assert group["cadence"] == ["FREQ=WEEKLY;INTERVAL=2"], "blanks must be stripped"


def test_sigs_report_their_parent_workstream():
    sigs = S.cosai_overview()["special_interest_groups"]
    assert sigs
    assert all(s["part_of"] for s in sigs), "a SIG is only meaningful under its parent"


# --- find_meetings ----------------------------------------------------------------

def test_find_meetings_by_series_name_outranks_a_publication_match():
    """Rank 1 is the series itself; rank 3 only means its *group* published on the
    topic, which promotes every series that group runs."""
    result = S.find_meetings("code")
    assert result["count"]
    best = result["series"][0]
    assert best["match_rank"] == 1
    assert "code" in best["series"].lower()
    assert result["series"] == sorted(result["series"], key=lambda s: s["match_rank"])


def test_find_meetings_explains_why_each_series_matched():
    for entry in S.find_meetings("supply chain")["series"]:
        assert entry["matched_on"], "an unexplained match is not actionable"


def test_find_meetings_gives_a_route_when_nothing_matches():
    result = S.find_meetings("quantum basket weaving")
    assert result["count"] == 0
    assert "how_to_get_involved" in result["note"]


def test_find_meetings_does_not_promise_future_dates():
    """The graph holds meetings that were announced, not a forward schedule."""
    note = S.find_meetings("code")["note"].lower()
    assert "not specific future dates" in note or "not a forward schedule" in note


# --- how_to_get_involved ----------------------------------------------------------

def test_get_involved_lists_every_group_without_a_topic():
    result = S.how_to_get_involved()
    assert len(result["groups"]) >= 9
    assert "workstream" in result["how_it_works"]


def test_get_involved_narrows_to_the_topic():
    result = S.how_to_get_involved("supply chain")
    assert [g["group_id"] for g in result["groups"]] == ["ws1"]
    assert result["series_on_topic"]


def test_get_involved_falls_back_and_says_so():
    result = S.how_to_get_involved("quantum basket weaving")
    assert len(result["groups"]) >= 9
    assert "No group matched" in result["note"]


def test_subscribe_links_point_at_a_group_that_exists():
    """The canonical list name is not the group name, and the difference is a 404.

    The parser's canonical spelling is suffix-less (`cosai-defenders`) because that is
    what a forwarded message's subject tag carries. Only the `-ws` form is a real
    group, so a link built from the canonical name is dead for all four workstreams --
    which is the newcomer path this tool exists to serve. Checked against the registry
    rather than the network, so the guard costs nothing and never flakes.
    """
    from bubo_graphrag.paths import mail_lists

    real = {entry["group"] for entry in mail_lists()}
    seen = 0
    for group in S.how_to_get_involved()["groups"]:
        for link in group["subscribe"]:
            assert link.rsplit("/", 1)[-1] in real, f"dead subscribe link: {link}"
            seen += 1
    assert seen, "no group carried a subscribe link, so this proved nothing"


def test_subscribe_links_are_derived_from_the_list_id():
    """Derived, not asserted -- the pattern came from the list mail footer."""
    group = next(g for g in S.how_to_get_involved()["groups"] if g["mailing_lists"])
    assert group["subscribe"] == [
        f"https://lists.oasis-open-projects.org/g/{name}"
        for name in group["mailing_lists"]]


def test_no_tool_prints_a_list_address_even_though_it_is_public():
    """The no-"@" guard is blunt on purpose; a list address would be the first crack."""
    group = next(g for g in S.how_to_get_involved()["groups"] if g["mailing_lists"])
    assert "list_address" not in group


def test_find_meetings_subscribe_links_resolve_too():
    """The same defect, second site: find_meetings builds its own link."""
    from bubo_graphrag.paths import mail_lists

    real = {entry["group"] for entry in mail_lists()}
    for series in S.find_meetings("telemetry")["series"]:
        if series["subscribe"]:
            assert series["subscribe"].rsplit("/", 1)[-1] in real


# --- meeting_timeline and governance_timeline -------------------------------------

def test_meeting_timeline_includes_a_workstreams_sigs():
    """Three of WS3's four series are SIGs, so a plenary-only answer hides most of
    the activity someone asking about WS3 wants to see."""
    result = S.meeting_timeline("ws3", limit=50)
    assert result["announced"] >= result["canceled"] > 0
    series = {m["series"] for m in result["meetings"]}
    assert any("Bi-weekly" in s for s in series), "the plenary"
    assert any("SIG" in s for s in series), "and its SIGs"
    assert "part of it" in result["note"]


def test_meeting_timeline_group_filter_excludes_other_workstreams():
    series = {m["series"] for m in S.meeting_timeline("ws1", limit=50)["meetings"]}
    assert series and all("WS1" in s for s in series), series


def test_meeting_timeline_reports_date_evidence_per_meeting():
    """So a date known only from a send date cannot pass as a scheduled start."""
    strengths = {m["evidence"] for m in S.meeting_timeline(limit=80)["meetings"]}
    assert strengths <= {"ics", "body-when", "subject", "subject-sent-date"}


def test_meeting_timeline_keeps_cancellations_and_explains_why():
    note = S.meeting_timeline("ws3")["note"].lower()
    assert "canceled meeting is kept" in note
    assert "not evidence" in note


def test_meeting_timeline_rejects_an_injected_group_id():
    with pytest.raises(ValueError, match="invalid identifier"):
        S.meeting_timeline("../etc/passwd")


def test_governance_timeline_is_dated_and_ordered():
    result = S.governance_timeline(limit=20)
    assert result["count"] > 0
    days = [e["day"] for e in result["events"]]
    assert days == sorted(days, reverse=True)


def test_governance_timeline_does_not_claim_outcomes():
    """The mail records that a step happened, not how it resolved."""
    assert "not its outcome" in S.governance_timeline()["note"]


# --- meeting_rhythm ---------------------------------------------------------------

def test_rhythm_is_measured_from_dates_and_agrees_with_a_stated_schedule():
    """WS3's bi-weekly series states INTERVAL=2; the dates must say the same."""
    series = S.meeting_rhythm("ws3")["series"]
    biweekly = next(s for s in series if "INTERVAL=2" in " ".join(s["stated_cadence"]))
    assert biweekly["observed_cadence"] == "every two weeks"


def test_rhythm_counts_are_consistent_across_series_and_periods():
    result = S.meeting_rhythm("ws3")
    assert sum(s["announced"] for s in result["series"]) == \
        sum(t["announced"] for t in result["totals_by_period"])
    for period in result["totals_by_period"]:
        assert period["held"] + period["canceled"] == period["announced"]


def test_rhythm_flags_periods_only_partly_inside_the_coverage_window():
    """A list's first and last quarters are cut by its window, so a low count there
    must not read as a slowdown."""
    totals = S.meeting_rhythm("ws3")["totals_by_period"]
    assert totals[0]["partial_coverage"] and totals[-1]["partial_coverage"]
    assert not all(t["partial_coverage"] for t in totals)


def test_rhythm_detects_a_change_between_periods(monkeypatch):
    """Weekly for a quarter, then monthly: one change, dated to the periods."""
    weekly = ["2025-01-06", "2025-01-13", "2025-01-20", "2025-01-27"]
    monthly = ["2025-04-07", "2025-05-05", "2025-06-02"]
    rows = [{"seriesId": "s", "series": "S", "day": d, "canceled": "false",
             "evidence": "subject", "list": "cosai-tsc"} for d in weekly + monthly]

    class Fake:
        def select(self, query, limit=None):
            if "CoverageWindow" in query:
                return [{"list": "cosai-tsc", "earliest": "2025-01-01",
                         "latest": "2025-06-30"}]
            return rows

    monkeypatch.setattr(S, "store", lambda: Fake())
    changes = S.meeting_rhythm()["series"][0]["rhythm_changes"]
    assert changes == [{"from_period": "2025-Q1", "to_period": "2025-Q2",
                        "from": "weekly", "to": "monthly"}]


@pytest.mark.parametrize("gap,label", [
    (7, "weekly"), (14, "every two weeks"), (21, "every three weeks"),
    (28, "monthly"), (31, "monthly"), (60, "irregular"), (None, None)])
def test_cadence_bands(gap, label):
    assert S._cadence_label(gap) == label


def test_period_bounds_cover_whole_months():
    assert S._period_bounds("2024-Q1") == ("2024-01-01", "2024-03-31")
    assert S._period_bounds("2024-02") == ("2024-02-01", "2024-02-29")


def test_rhythm_rejects_an_unknown_period_and_an_injected_group():
    with pytest.raises(ValueError, match="invalid period"):
        S.meeting_rhythm("ws3", by="decade")
    with pytest.raises(ValueError, match="invalid identifier"):
        S.meeting_rhythm("ws3) } #")


# --- meeting_records --------------------------------------------------------------

def test_records_split_every_held_meeting_into_with_and_without_a_record():
    result = S.meeting_records("tsc", limit=1000)
    assert result["held"] == result["with_a_record"] + len(result["held_without_record"])
    assert result["with_a_record"] > 0 and result["held_without_record"]


def test_records_are_restricted_pointers_never_contents():
    meetings = S.meeting_records("tsc", limit=1000)["meetings"]
    records = [r for m in meetings for r in m["records"]]
    assert records and all(r["access_restricted"] for r in records)
    assert all(url.startswith("https://") for r in records for url in r["urls"])


def test_records_respect_the_date_range():
    result = S.meeting_records("tsc", since="2026-01-01", until="2026-06-30", limit=1000)
    assert result["meetings"]
    assert all("2026-01-01" <= m["day"] <= "2026-06-30" for m in result["meetings"])


def test_records_count_what_could_not_be_attached():
    """So a held meeting without a record is not read as one that has none."""
    assert 0 < S.meeting_records("tsc")["unattached_records"] \
        <= S.meeting_records()["unattached_records"]


def test_records_reject_a_date_that_is_not_iso():
    with pytest.raises(ValueError, match="invalid date"):
        S.meeting_records("tsc", since='2026-01-01"^^xsd:date) } #')


# --- the standing invariants -------------------------------------------------------

def test_no_orientation_tool_returns_an_email_address():
    import json

    payloads = json.dumps([S.cosai_overview(), S.how_to_get_involved(),
                           S.find_meetings("code"), S.meeting_timeline(limit=80),
                           S.governance_timeline(), S.meeting_rhythm(),
                           S.meeting_records(limit=200)])
    assert "@" not in payloads.replace("@example", ""), "addresses must stay hashed"


def test_the_new_tools_are_registered_and_documented():
    for name in ("cosai_overview", "how_to_get_involved", "find_meetings",
                 "meeting_timeline", "governance_timeline"):
        tool = getattr(S, name)
        assert tool.__doc__ and len(tool.__doc__) > 120, f"{name} needs a usable docstring"


def test_the_server_registers_exactly_the_public_tools():
    """What a model is offered, read from the server rather than the module.

    A decorator left above a new helper registers the helper and silently unregisters
    the tool below it: `_stub` was offered to models while who_contributed_to was not,
    and every test calling S.who_contributed_to directly still passed.
    """
    import asyncio
    offered = {t.name for t in asyncio.run(S.mcp.list_tools())}
    assert offered == {
        "find_person", "what_did_person_do", "affiliation_timeline", "list_people",
        "list_publications", "who_contributed_to", "org_contributions",
        "list_organizations", "what_cited_this", "citation_summary", "sparql",
        "cosai_overview", "how_to_get_involved", "find_meetings", "meeting_timeline",
        "meeting_rhythm", "meeting_records", "approval_record", "upcoming_meetings",
        "what_announced_this", "governance_timeline", "graph_schema"}


# --- writing SPARQL: the escape hatch must be usable without guessing -------------
#
# These exist because a model given only class and property names invents the wiring.
# In one observed session seventeen sparql calls answered one question: eight were
# schema discovery, and eight used predicates that do not exist -- which return zero
# rows rather than an error, so a wrong answer is as likely as a noticed mistake.

def test_graph_schema_ships_worked_queries(store):
    """Every documented example must actually return rows.

    An example that returns nothing is worse than none: it teaches a traversal that
    looks right and yields silence.
    """
    examples = S.graph_schema()["example_queries"]
    assert len(examples) >= 5
    for name, query in examples.items():
        rows = store.select(query, limit=5)
        assert rows, f"example {name!r} returned no rows"


def test_graph_schema_names_the_credit_path_explicitly(store):
    """The specific thing that was guessed wrong: there is no person-to-publication
    edge, because a credit is a reified role node."""
    guidance = " ".join(S.graph_schema()["writing_sparql"])
    assert "reified" in guidance
    assert "obo:BFO_0000197" in guidance and "cosaic:onPublication" in guidance
    assert "zero rows, not an error" in guidance


def test_the_predicates_a_model_invented_still_do_not_exist(store):
    """Guards the premise of the guidance above rather than the guidance itself."""
    for term in ("cco:contributedBy", "cco:hasPerson", "cosaic:contributedBy"):
        rows = store.select(f"SELECT * WHERE {{ ?s {term} ?o }}", limit=1)
        assert rows == [], f"{term} exists now; the schema guidance needs updating"


# --- list_people ranking ----------------------------------------------------------

def test_excluding_governance_changes_who_ranks_highest():
    """The question that had no tool. Steering-committee service is not work on a
    document, and including it puts different people at the top."""
    everyone = S.list_people(limit=200)["people"]
    working = S.list_people(exclude_roles=["governance"], limit=200)["people"]
    assert everyone[0]["person"] != working[0]["person"], "the filter must bite"
    assert all("TSCCoChairRole" not in p["roles"] and "TSCReviewerRole" not in p["roles"]
               for p in working)


def test_governance_shorthand_expands_to_both_tsc_roles():
    out = S.list_people(exclude_roles=["governance"])
    assert out["excluded_roles"] == ["TSCCoChairRole", "TSCReviewerRole"]
    assert "Roles excluded" in out["note"]


def test_exclude_roles_accepts_plain_words():
    out = S.list_people(exclude_roles=["editor", "reviewer"])
    assert out["excluded_roles"] == ["EditorRole", "ReviewerRole"]


def test_publications_and_credits_are_distinguished():
    """A person credited twice on one document counts once in publications, twice in
    credits -- reported separately so neither reads as the other."""
    out = S.list_people(limit=200)
    assert any(int(p["credits"]) > int(p["publications"]) for p in out["people"])
    assert "counts once in publications and twice in credits" in out["note"]


def test_role_and_exclude_roles_are_mutually_exclusive():
    with pytest.raises(ValueError, match="not both"):
        S.list_people(role="editor", exclude_roles=["governance"])


def test_an_unknown_excluded_role_is_rejected():
    with pytest.raises(ValueError, match="unknown role"):
        S.list_people(exclude_roles=["nonsense"])


# --- approvals, announcements and the forward schedule ------------------------------

def test_approval_record_gives_each_bodys_first_approval_and_its_deadline():
    result = S.approval_record("zero-trust-for-ai-systems")
    assert result["approval"]["tsc"]["closed"] == "2026-09-01"
    assert result["approval"]["pgb"] == {"closed": "2026-09-07", "basis": "call closed",
                                         "deadline": "2026-09-04"}
    assert result["registry_status"] == "approved"


def test_approval_record_takes_a_ballots_result_from_the_pgb_call():
    """SRF's TSC ballot has no closing message; the PGB call restates it."""
    tsc = S.approval_record("ai-shared-responsibility-framework")["approval"]["tsc"]
    assert tsc == {"closed": "before 2026-05-20", "basis": "stated in the PGB call"}


def test_approval_record_keeps_a_revision_apart_from_the_original_approval():
    result = S.approval_record("model-context-protocol-security")
    assert result["approval"]["pgb"]["closed"] == "2026-01-09"
    assert [(c["closed"], c["bodies"]) for c in result["revisions"]] == [("2026-08-03", ["tsc"])]


def test_approval_record_gives_an_addition_its_parents_standing():
    result = S.approval_record("addendum-mcp-and-pqc")
    assert result["approval"] == {}
    assert result["addition_to"] == "model-context-protocol-security"
    assert result["approved_as_addition"]["closed"] == "2026-08-03"
    assert result["approved_as_addition"]["parent_approval"]["pgb"]["closed"] == "2026-01-09"


def test_approval_record_names_a_recorded_exception():
    result = S.approval_record("preparing-defenders-of-ai-systems")
    assert "pgb" not in result["approval"]
    assert result["recorded_exception"] == "PGB approval not found in mail."


def test_upcoming_meetings_are_planned_entries_soonest_first_after_the_read():
    result = S.upcoming_meetings(group="ws4", until="2026-10-31")
    starts = [m["start"] for m in result["meetings"]]
    assert starts and starts == sorted(starts)
    assert all(m["start"][:10] > result["calendar_read"] for m in result["meetings"])
    assert all(m["start"][:10] <= "2026-10-31" for m in result["meetings"])
    # A workstream includes its SIGs.
    assert {"ws4-recurring-meeting", "ws4-sig-agent-development-lifecycle"} <= \
        {m.get("series_id") for m in result["meetings"]}
    assert "not held" in result["note"]


def test_upcoming_meetings_rejects_a_malformed_date():
    with pytest.raises(ValueError, match="expected YYYY-MM-DD"):
        S.upcoming_meetings(until="next week")


def test_what_announced_this_finds_a_post_linking_only_the_website_copy():
    posts = S.what_announced_this("ai-shared-responsibility-framework")["posts"]
    blog = next(p for p in posts if p["title"].startswith("Who"))
    assert "Blog Post" in blog["categories"]
    assert blog["tsc_approval"]["deadline"] == "2026-05-26"
    assert not any(key in blog for key in ("author", "creator", "byline"))


def test_who_contributed_to_reports_a_stubs_organizational_author():
    result = S.who_contributed_to("principles-secure-by-design-agentic-systems")
    assert result["stub"] is True and result["title"]
    [credit] = result["by_role"]["OrganizationalAuthorRole"]
    assert credit["organization"] == "CoSAI" and "person" not in credit


def test_affiliation_timeline_without_a_person_lists_every_inferred_change():
    result = S.affiliation_timeline()
    assert {r["personId"] for r in result["inferred_changes"]} >= {"josiah-hagen", "bill-stout"}
    assert result["people"] == len({r["personId"] for r in result["inferred_changes"]})


def test_meeting_tools_carry_the_calendars_scheduled_time():
    meetings = S.meeting_timeline("ws4", limit=5)["meetings"]
    assert any(m.get("scheduledStart") and m.get("timeZone") for m in meetings)
    records = S.meeting_records("ws4", since="2026-09-01")["meetings"]
    assert any(m.get("scheduled_start") for m in records)
