"""Every SPARQL query has at least one test, and that stays true.

Two kinds of coverage are enforced here rather than merely achieved once:

  * `test_every_query_constant_is_covered` discovers the query constants in
    bubo_graphrag.queries by introspection and fails if one has no entry in CASES.
  * `test_every_rq_file_is_covered` does the same for queries/*.rq.

So adding a query without a test breaks the build, which is the only way "every query is
tested" survives contact with future changes.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from bubo_graphrag import queries as Q
from bubo_graphrag.ingest.groupsio import fetch_groups
from bubo_graphrag.paths import QUERIES

# --- discovery ------------------------------------------------------------------

def discover_query_constants() -> set[str]:
    """Public upper-case string constants in the queries module."""
    return {
        name for name, value in vars(Q).items()
        if name.isupper() and isinstance(value, str) and not name.startswith("_")
    }


def discover_rq_files() -> set[str]:
    return {p.name for p in QUERIES.glob("*.rq")}


# --- one case per parameterised query -------------------------------------------
# Each entry: query name -> (format kwargs, assertion on the returned rows).

CASES: dict[str, tuple[dict, callable]] = {
    "FIND_PERSON": (
        {"needle": Q.literal("rao")},
        # Matches J.R. Rao and Siddhartha Rao; the abbreviated form must be found.
        lambda rows: {r["matchedName"] for r in rows} >= {"J.R. Rao", "Siddhartha Rao"},
    ),
    "FIND_PERSON_BY_ADDRESS": (
        {"needle": Q.literal("trendmicro.com")},
        # Four Trend Micro addresses appear in the corpus.
        lambda rows: len(rows) >= 4
        and all("trendmicro.com" in r["address"] for r in rows),
    ),
    "PERSON_CREDITS": (
        {"person": "josiah-hagen"},
        # Seven credits; the MCP Security one must be dated to the ORIGINAL publication
        # (2026-01-08), not the 2026-08-12 revision that carried the same credit list.
        lambda rows: len(rows) == 7
        and any(r["pubId"] == "model-context-protocol-security"
                and r["date"] == "2026-01-08" for r in rows),
    ),
    "PERSON_CREDIT_COUNT": (
        {"person": "j-r-rao"},
        lambda rows: rows and int(rows[0]["credits"]) == 8,
    ),
    "PERSON_AFFILIATION": (
        {"person": "josiah-hagen"},
        # Two spans, and every one must declare its bounds are unknown.
        lambda rows: len(rows) == 2
        and all(r["boundsKnown"] in ("false", False) for r in rows),
    ),
    "PERSON_AFFILIATION_CHANGES": (
        {"person": "bill-stout"},
        lambda rows: len(rows) == 1
        and rows[0]["notBefore"] == "2026-03-20"
        and rows[0]["notAfter"] == "2026-09-04"
        and rows[0]["inferred"] in ("true", True),
    ),
    "PERSON_ADDRESSES": (
        {"person": "jason-garman"},
        # Two distinct Amazon addresses for one person: multiples are allowed.
        lambda rows: {r["address"] for r in rows}
        == {"garmaja@amazon.com", "jason.garman@amazon.com"},
    ),
    "PUBLICATION_CREDITS": (
        {"publication": "zero-trust-for-ai-systems"},
        lambda rows: len(rows) == 20
        and sum(1 for r in rows if r["role"] == "EditorRole") == 4,
    ),
    "LIST_PUBLICATIONS": (
        {"filters": ""},
        # All 12, including the two with zero credits. A sub-select that was not a left
        # join used to drop those, so the count is asserted explicitly.
        lambda rows: len(rows) == 12
        and all("status" in r for r in rows)
        and {r["id"] for r in rows if r["creditCount"] == "0"}
        == {"addendum-mcp-and-pqc", "cosai-ai-telemetry-rfc"},
    ),
    "ORG_CONTRIBUTIONS": (
        {"organization": "ibm"},
        lambda rows: len(rows) > 0 and all("person" in r for r in rows),
    ),
    "LIST_ORGANIZATIONS": (
        {},
        lambda rows: len(rows) >= 29
        and any(r["name"] == "Trend Micro" for r in rows),
    ),
    "PEOPLE_BY_ROLE": (
        {"role_class": "TSCCoChairRole", "extra": ""},
        # Only two people co-chair the TSC across the corpus.
        lambda rows: {r["person"] for r in rows} == {"Akila Srinivasan", "J.R. Rao"},
    ),
    "WHAT_CITED": (
        {"publication": "model-context-protocol-security"},
        # 28 distinct citing publications, including the NSA.
        lambda rows: len({r["citingPublication"] for r in rows}) == 28
        and any("National Security Agency" in r.get("publisher", "") for r in rows),
    ),
    "CITATION_SUMMARY": (
        {},
        # All 12 works, with the 5 out-of-scope ones flagged.
        lambda rows: len(rows) == 12
        and sum(1 for r in rows if r["inScope"] in ("false", False)) == 5,
    ),
    "CITATION_BREAKDOWN": (
        {"filters": ""},
        lambda rows: sum(int(r["n"]) for r in rows) == 146,
    ),
    "PEOPLE_RANKED": (
        {"filters": "FILTER(?roleClass NOT IN (cosaic:TSCCoChairRole, "
                    "cosaic:TSCReviewerRole))"},
        # Excluding steering-committee service changes who leads: the top two overall
        # rank there largely through TSC roles, so the filter must actually bite.
        lambda rows: len(rows) >= 50
        and all("TSCCoChairRole" not in r.get("roles", "")
                and "TSCReviewerRole" not in r.get("roles", "") for r in rows)
        and [int(r["publications"]) for r in rows]
        == sorted((int(r["publications"]) for r in rows), reverse=True),
    ),
    # --- orientation queries ------------------------------------------------------
    # These run against both backends through test_backend_portability, which is the
    # point: the GROUP_CONCAT aggregation below behaves differently when a group
    # contains an unbound value, and that difference has to stay caught.
    "GROUP_DIRECTORY": (
        {},
        # Each group once. The four workstreams, both governing bodies and the
        # committee are fixed; the SIG count moves with the series registry, so it is
        # not pinned.
        lambda rows: len(rows) == len({r["groupId"] for r in rows})
        and {r["kind"] for r in rows} == {"workstream", "governing-body", "committee",
                                          "sig"}
        and {r["groupId"] for r in rows if r["kind"] == "committee"} == {"marketing"}
        and {r["groupId"] for r in rows if r["kind"] == "workstream"}
            == {"ws1", "ws2", "ws3", "ws4"}
        and {r["groupId"] for r in rows if r["kind"] == "governing-body"}
            == {"tsc", "pgb"}
        # WS2 runs a series with no cadence and one with an RRULE; concatenating
        # without COALESCE returns unbound and erases the RRULE entirely.
        and any("FREQ=" in str(r.get("cadences")) for r in rows if r["groupId"] == "ws2")
        # Every SIG names its parent workstream.
        and all(r.get("parent") for r in rows if r["kind"] == "sig")
        # Curator statements survive the GROUP BY, and link in both directions.
        and any(r.get("status") == "inactive" and r.get("statusAsOf")
                for r in rows if r["kind"] == "sig")
        and {(r["groupId"], r.get("succeededBy")) for r in rows if r.get("succeededBy")}
            == {(r.get("continues"), r["groupId"]) for r in rows if r.get("continues")},
    ),
    "SERIES_BY_TOPIC": (
        {"term": Q.literal("code")},
        # Ranked: the series whose own name carries the topic must come first, ahead of
        # series that match only because their workstream published on it.
        lambda rows: rows and int(rows[0]["rank"]) == 1
        and "code" in rows[0]["series"].lower()
        and [int(r["rank"]) for r in rows] == sorted(int(r["rank"]) for r in rows)
        and all(r.get("matchedOn") for r in rows),
    ),
    "MEETING_TIMELINE": (
        {"filters": ""},
        # Newest first, every row carrying one of the four date-evidence strengths. The
        # calendar join adds no row even where two entries correspond to one meeting:
        # rows stay distinct on the meeting's own values.
        lambda rows: len(rows) >= 40
        and [r["day"] for r in rows] == sorted((r["day"] for r in rows), reverse=True)
        and {r["evidence"] for r in rows}
            <= {"ics", "body-when", "subject", "subject-sent-date"}
        and any(r.get("scheduledStart") for r in rows)
        and len({(r["day"], r["series"], r["canceled"], r["evidence"]) for r in rows})
            == len(rows),
    ),
    "MEETING_ROWS": (
        {"filters": ""},
        # Oldest first within each series, so the caller can take gaps pairwise.
        lambda rows: len(rows) >= 40
        and all(r["seriesId"] and r["day"] for r in rows)
        and [(r["seriesId"], r["day"]) for r in rows]
            == sorted((r["seriesId"], r["day"]) for r in rows),
    ),
    "MEETING_RECORDS": (
        {"filters": ""},
        # Meetings with and without a record both appear; "no record" is a finding. The
        # calendar's scheduled time reaches the rows it matches.
        lambda rows: any(r.get("summary") for r in rows)
        and any(not r.get("summary") for r in rows)
        and [r["day"] for r in rows] == sorted((r["day"] for r in rows), reverse=True)
        and any(r.get("scheduledStart") and r.get("timeZone") for r in rows),
    ),
    "UNATTACHED_RECORDS": (
        {"filters": ""},
        lambda rows: len(rows) == 1 and int(rows[0]["unattached"]) > 0,
    ),
    "GOVERNANCE_TIMELINE": (
        {},
        lambda rows: len(rows) >= 20
        and [r["day"] for r in rows] == sorted((r["day"] for r in rows), reverse=True),
    ),
    "RECENT_PUBLICATIONS": (
        {},
        # Newest first; the 2026-09-04 Zero Trust paper is the most recent approved one.
        lambda rows: len(rows) >= 10
        and [r["date"] for r in rows] == sorted((r["date"] for r in rows), reverse=True)
        and all(r.get("status") for r in rows),
    ),
    "CORPUS_COUNTS": (
        {},
        # One row of scale figures for the overview.
        lambda rows: len(rows) == 1 and int(rows[0]["publications"]) >= 12
        and int(rows[0]["people"]) >= 80,
    ),
    "COVERAGE": (
        {},
        # One window per fetched list, each bounded -- the caveat for every meeting
        # count.
        lambda rows: len(rows) == len(fetch_groups())
        and all(r["earliest"] <= r["latest"] for r in rows),
    ),
}

# Expectation per standalone .rq file: (minimum rows, optional extra assertion).

CASES.update({
    "APPROVAL_CALLS": (
        {"publication": "zero-trust-for-ai-systems"},
        # A TSC ballot closed 2026-09-01 and a PGB call with a deadline of 2026-09-04
        # closed 2026-09-07; its review periods appear as review, not approval.
        lambda rows: any(r["body"] == "tsc" and r["stage"] == "ballot"
                         and r.get("closed") == "2026-09-01" for r in rows)
        and any(r["body"] == "pgb" and r["stage"] == "call-for-consensus"
                and r.get("deadline") == "2026-09-04" and r.get("closed") == "2026-09-07"
                for r in rows)
        and any(r["role"] == "review" for r in rows),
    ),
    "ADDITION_TO": (
        {"publication": "addendum-mcp-and-pqc"},
        lambda rows: [r["parent"] for r in rows] == ["model-context-protocol-security"],
    ),
    "UPCOMING_MEETINGS": (
        {"filters": ""},
        # Soonest first; every entry has a UTC start, and most resolve to a series.
        lambda rows: len(rows) >= 100
        and [r["start"] for r in rows] == sorted(r["start"] for r in rows)
        and sum(1 for r in rows if r.get("seriesId")) > len(rows) / 2,
    ),
    "SOURCE_WINDOW": (
        {"window_class": "CalendarCoverageWindow"},
        lambda rows: len(rows) == 1 and rows[0]["fetched"]
        and rows[0]["rangeStart"] <= rows[0]["earliest"] <= rows[0]["latest"],
    ),
    "POSTS_LINKING": (
        {"publication": "ai-shared-responsibility-framework"},
        # The SRF blog links only the website's PDF copy; it must still be found.
        lambda rows: any(r["title"].startswith("Who") and "Blog Post" in r["categories"]
                         for r in rows),
    ),
    "BLOG_CALLS": (
        {},
        lambda rows: any(r["title"].startswith("Treat Your Agent Like an Insider Threat")
                         and r.get("closed") == "2026-08-21" for r in rows),
    ),
    "ALL_AFFILIATION_CHANGES": (
        {},
        # Both inferred changes, each carrying its person and its window.
        lambda rows: {r["personId"] for r in rows} >= {"josiah-hagen", "bill-stout"}
        and all(r["inferred"] in ("true", True) and r["notBefore"] <= r["notAfter"]
                for r in rows),
    ),
})

RQ_CASES: dict[str, tuple[int, callable | None]] = {
    "who-did-what.rq": (183, None),
    "affiliation-timeline.rq": (
        1, lambda rows: all(r["boundsKnown"] in ("false", False) for r in rows)),
    "inferred-affiliation-changes.rq": (
        2, lambda rows: all(r["inferred"] in ("true", True) for r in rows)),
    "publication-credits.rq": (
        20, lambda rows: any(r.get("statedOrganization") == "indepedent" for r in rows)),
    "what-cited-this.rq": (28, None),
    "citation-impact.rq": (
        12, lambda rows: int(rows[0]["citingPublications"]) == 28),
    "organization-contributions.rq": (10, None),
    "bfo-placement.rq": (
        20, lambda rows: any(r["parent"] == "BFO_0000023" for r in rows)),
    "drafts-vs-approved.rq": (
        3, lambda rows: {r["status"] for r in rows}
        == {"approved", "working-draft", "unapproved-draft"}),
}


# --- coverage enforcement -------------------------------------------------------

def test_every_query_constant_is_covered():
    """A query constant with no test case fails the build."""
    discovered = discover_query_constants()
    untested = discovered - set(CASES)
    assert not untested, (
        f"SPARQL query constants without a test: {sorted(untested)}. "
        "Add an entry to CASES in tests/test_queries.py.")


def test_no_stale_query_cases():
    """A test case for a query that no longer exists also fails the build."""
    stale = set(CASES) - discover_query_constants()
    assert not stale, f"CASES entries for removed queries: {sorted(stale)}"


def test_every_rq_file_is_covered():
    discovered = discover_rq_files()
    untested = discovered - set(RQ_CASES)
    assert not untested, (
        f"queries/*.rq files without a test: {sorted(untested)}. "
        "Add an entry to RQ_CASES in tests/test_queries.py.")


def test_no_stale_rq_cases():
    stale = set(RQ_CASES) - discover_rq_files()
    assert not stale, f"RQ_CASES entries for missing files: {sorted(stale)}"


# --- the query tests themselves -------------------------------------------------

@pytest.mark.parametrize("name", sorted(CASES))
def test_query_constant(store, name):
    """Run one parameterised query and check its result."""
    template, check = CASES[name][0], CASES[name][1]
    sparql = Q.render(getattr(Q, name), **template)
    rows = store.select(sparql)
    assert check(rows), f"{name} returned unexpected rows: {rows[:5]}"


@pytest.mark.parametrize("filename", sorted(RQ_CASES))
def test_rq_file(store, filename):
    """Run one standalone .rq file and check its result."""
    minimum, extra = RQ_CASES[filename]
    sparql = (QUERIES / filename).read_text(encoding="utf-8")
    rows = store.select(sparql)
    assert len(rows) >= minimum, (
        f"{filename} returned {len(rows)} rows, expected at least {minimum}")
    if extra is not None:
        assert extra(rows), f"{filename} failed its assertion: {rows[:3]}"


def test_rq_files_have_no_prefixes():
    """Prefixes are injected by Store.select; a file declaring its own would double up."""
    for path in QUERIES.glob("*.rq"):
        text = path.read_text(encoding="utf-8")
        assert "PREFIX " not in text.upper(), (
            f"{path.name} declares PREFIX; Store.select already injects them")


def test_rq_files_are_documented():
    """Every query file carries a leading comment explaining what it answers."""
    for path in QUERIES.glob("*.rq"):
        first = path.read_text(encoding="utf-8").lstrip().splitlines()[0]
        assert first.startswith("#"), f"{path.name} has no explanatory header comment"
