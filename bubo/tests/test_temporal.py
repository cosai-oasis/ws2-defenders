"""Temporal model tests.

These encode the project's central claim: that the corpus supports statements about
when a claim was *attested*, and nothing stronger. Each test below corresponds to a way
a naive model gets this wrong.
"""

from __future__ import annotations

import datetime as dt

import pytest

from bubo_graphrag.ingest.seed import assertion_date
from bubo_graphrag.resolve.identity import OrgAssertion, Person
from bubo_graphrag.temporal import (
    INDEPENDENT,
    affiliation_at,
    build_timeline,
    describe,
)


def person(*assertions) -> Person:
    """Build a person from (date, org, independent, source) tuples."""
    p = Person(id="test", display_name="Test Person")
    for i, (date, org, independent, *rest) in enumerate(assertions):
        source = rest[0] if rest else "credit-line"
        p.org_evidence.append(OrgAssertion(
            publication_id=f"pub{i}", organization=org, is_independent=independent,
            assertion_date=date, source=source, stated_as=org))
    return p


D = dt.date


# --- spans ----------------------------------------------------------------------

def test_consecutive_same_state_collapses_to_one_span():
    tl = build_timeline(person(
        (D(2025, 7, 14), "Trend Micro", False),
        (D(2025, 10, 27), "Trend Micro", False),
        (D(2026, 1, 8), "Trend Micro", False)))
    assert len(tl.spans) == 1
    assert tl.spans[0].earliest_evidence == D(2025, 7, 14)
    assert tl.spans[0].latest_evidence == D(2026, 1, 8)


def test_every_span_has_open_bounds():
    """The flag consumers must respect: an evidence date is not a start or end date."""
    tl = build_timeline(person((D(2025, 7, 14), "Trend Micro", False)))
    assert tl.spans[0].bounds_known is False


def test_independence_is_a_state_not_an_absence():
    tl = build_timeline(person(
        (D(2025, 7, 14), "Trend Micro", False),
        (D(2026, 9, 4), None, True)))
    assert [s.state for s in tl.spans] == ["Trend Micro", INDEPENDENT]
    assert tl.spans[1].is_independent


# --- change inference -----------------------------------------------------------

def test_change_produces_an_uncertainty_window_not_a_date():
    tl = build_timeline(person(
        (D(2026, 1, 8), "ServiceNow", False),
        (D(2026, 3, 20), "ServiceNow", False),
        (D(2026, 9, 4), None, True)))
    assert len(tl.changes) == 1
    change = tl.changes[0]
    assert change.not_before == D(2026, 3, 20)     # last evidence for the old state
    assert change.not_after == D(2026, 9, 4)       # first evidence for the new one
    assert change.inferred is True
    assert change.window_days == 168


def test_unstated_employer_yields_no_change_event():
    """Sarah Novotny's case. Absence of a claim is not a claim about leaving."""
    tl = build_timeline(person(
        (D(2025, 6, 12), "GenLab", False),
        (D(2025, 10, 27), None, False),
        (D(2026, 3, 20), None, False),
        (D(2026, 9, 5), None, False)))
    assert len(tl.spans) == 1
    assert tl.spans[0].state == "GenLab"
    assert tl.changes == []
    assert len(tl.unstated_dates) == 3


def test_no_changes_when_affiliation_is_stable():
    tl = build_timeline(person(
        (D(2025, 6, 12), "Anthropic", False),
        (D(2026, 9, 4), "Anthropic", False)))
    assert tl.changes == []


# --- precedence within one date -------------------------------------------------

def test_named_organization_wins_over_unstated_on_the_same_date():
    tl = build_timeline(person(
        (D(2026, 9, 4), None, False),
        (D(2026, 9, 4), "Dell Technologies", False)))
    assert [s.state for s in tl.spans] == ["Dell Technologies"]


def test_independent_wins_over_unstated_on_the_same_date():
    """Josiah Hagen appears twice in Zero Trust: once with no employer, once as
    'indepedent'. The informative claim must win."""
    tl = build_timeline(person(
        (D(2026, 9, 4), None, False),
        (D(2026, 9, 4), None, True)))
    assert [s.state for s in tl.spans] == [INDEPENDENT]


def test_email_domain_evidence_does_not_establish_affiliation():
    """A work address may outlive the job, so domains corroborate rather than assert."""
    tl = build_timeline(person(
        (D(2026, 5, 26), "Trend Micro", False, "email-domain")))
    assert tl.spans == []


# --- point queries --------------------------------------------------------------

def test_affiliation_at_returns_the_attested_span():
    tl = build_timeline(person(
        (D(2026, 1, 8), "ServiceNow", False),
        (D(2026, 3, 20), "ServiceNow", False)))
    assert affiliation_at(tl, D(2026, 2, 1)).state == "ServiceNow"


def test_affiliation_at_refuses_to_extrapolate():
    """The golden case: 'Was Bill Stout at ServiceNow in August 2026?' -> not asserted."""
    tl = build_timeline(person(
        (D(2026, 1, 8), "ServiceNow", False),
        (D(2026, 3, 20), "ServiceNow", False),
        (D(2026, 9, 4), None, True)))
    assert affiliation_at(tl, D(2026, 8, 15)) is None


def test_affiliation_at_before_any_evidence_is_none():
    tl = build_timeline(person((D(2026, 1, 8), "ServiceNow", False)))
    assert affiliation_at(tl, D(2020, 1, 1)) is None


# --- the revision trap ----------------------------------------------------------

def test_credits_carried_across_a_revision_keep_the_original_date():
    """MCP Security: revised 2026-08-12 without refreshing its credit list.

    Dating those credits to the revision would read as two contributors returning to
    employers they had already left.
    """
    pub = {"original_date": D(2026, 1, 8), "revised_date": D(2026, 8, 12),
           "credits_refreshed_at_revision": False}
    assert assertion_date(pub) == D(2026, 1, 8)


def test_credits_refreshed_at_a_revision_use_the_revision_date():
    pub = {"original_date": D(2026, 1, 8), "revised_date": D(2026, 8, 12),
           "credits_refreshed_at_revision": True}
    assert assertion_date(pub) == D(2026, 8, 12)


def test_publication_without_a_revision_uses_its_own_date():
    assert assertion_date({"original_date": D(2025, 6, 12)}) == D(2025, 6, 12)


def test_registry_records_the_mcp_revision_as_not_refreshed():
    from bubo_graphrag.paths import publication
    pub = publication("model-context-protocol-security")
    assert pub["credits_refreshed_at_revision"] is False
    assert assertion_date(pub) == D(2026, 1, 8)


# --- rendering ------------------------------------------------------------------

def test_describe_marks_inference_and_uncertainty():
    tl = build_timeline(person(
        (D(2026, 1, 8), "ServiceNow", False),
        (D(2026, 9, 4), None, True)))
    text = describe(tl, "Bill Stout")
    assert "attested" in text
    assert "inferred" in text
    assert "day window" in text


def test_describe_handles_a_person_with_no_stated_employer():
    tl = build_timeline(person((D(2026, 1, 8), None, False)))
    assert "no employer stated" in describe(tl, "Someone")


# --- against the real corpus ----------------------------------------------------

def test_real_timelines_match_the_corpus(resolved):
    resolver, _, _, _ = resolved
    by_name = {p.display_name: p for p in resolver.people.values()}

    josiah = build_timeline(by_name["Josiah Hagen"])
    assert [s.state for s in josiah.spans] == ["Trend Micro", INDEPENDENT]
    assert josiah.spans[0].latest_evidence == D(2026, 1, 8)   # not the 2026-08-12 revision
    assert len(josiah.changes) == 1

    bill = build_timeline(by_name["Bill Stout"])
    assert [s.state for s in bill.spans] == ["ServiceNow", INDEPENDENT]
    assert bill.changes[0].not_before == D(2026, 3, 20)

    sarah = build_timeline(by_name["Sarah Novotny"])
    assert [s.state for s in sarah.spans] == ["GenLab"]
    assert sarah.changes == []
