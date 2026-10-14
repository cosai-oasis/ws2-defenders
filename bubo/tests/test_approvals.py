"""Approval-link and consistency-report tests.

Fixtures are synthetic and written inline, as in test_maillist: the real archives are
fetched with a personal key into a gitignored path, so no test may read them. The one
test that reads a real file checks registry/approvals.yaml, which is committed.
"""

from __future__ import annotations

import itertools
import textwrap
from pathlib import Path

import pytest

from bubo_graphrag.ingest import approvals as A
from bubo_graphrag.ingest import maillist as M

_ids = itertools.count()


def message(subject: str, body: str = "text", list_id: str | None = "cosai-tsc",
            date: str = "Tue, 11 Aug 2026 10:00:00 +0000") -> str:
    headers = [f"From: OASIS Staff <staff@oasis-open.org>", f"Subject: {subject}",
               f"Date: {date}", f"Message-ID: <{next(_ids)}@example.test>"]
    if list_id:
        headers.append(f"List-Id: <{list_id}.{M.LIST_DOMAIN}>")
    return "\n".join(headers) + "\n\n" + textwrap.dedent(body).strip() + "\n"


def parse(tmp_path: Path, *messages: str) -> M.MailParse:
    path = tmp_path / "test.mbox"
    path.write_text("".join(f"From MAILER-DAEMON Mon Aug 10 00:00:00 2026\n{m}\n"
                            for m in messages), encoding="utf-8")
    return M.parse_mbox(path)


OPEN = "Voting Members are asked to register any objections no later than Friday."
CLOSED = "This call for consensus is now closed. No objections were registered."
PGB_OPEN = ("This document was shared with the PGB and was approved by the TSC. "
            "Please register any objections by Friday.")


# --- reading a call's outcome from its body ------------------------------------------

@pytest.mark.parametrize("body,outcome", [
    (OPEN, "opened"),
    (CLOSED, "closed"),
    # A closing reply may repeat the instructions; how it ended is what counts.
    (f"{CLOSED}\n{OPEN}", "closed"),
    ("Thanks, noted.", None),
])
def test_outcome_labels(body, outcome):
    assert M.governance_outcome(body)[0] == outcome


def test_quoted_text_does_not_decide_the_outcome():
    """A "+1" reply quoting the closing mail must not read as the close itself."""
    body = f"+1, thanks!\n\nOn Tue, Aug 11, 2026 at 10:00 AM Staff wrote:\n{CLOSED}"
    assert M.governance_outcome(body) == (None, False)
    assert M.governance_outcome(f"+1\n> {CLOSED}") == (None, False)


def test_a_pgb_call_restating_tsc_approval_is_flagged():
    assert M.governance_outcome(PGB_OPEN) == ("opened", True)


@pytest.mark.parametrize("body,deadline", [
    ("register any objections no later than Friday, September 4, 2026 at 6pm ET.",
     "2026-09-04"),
    ("register any objections by Sunday, September 28, 2025 at 23:59 UTC.", "2025-09-28"),
    ("register any objections no later than Friday July 31, 2026 at 6pm ET.", "2026-07-31"),
    ("register any objections by Monday, May 25 2026 at 23:59 UTC.", "2026-05-25"),
    # No year: a date is not guessed.
    ("register any objections by the end of the day on Monday, March 9nd.", None),
    ("register your objection either to this list or by emailing me directly.", None),
])
def test_the_objection_deadline_is_read_as_a_date(body, deadline):
    assert M.call_deadline(body) == deadline


def test_a_deadline_in_quoted_text_is_not_the_replys(tmp_path):
    quoted = "> register any objections no later than Friday, September 4, 2026."
    assert M.call_deadline(f"Closed, thanks.\n{quoted}") is None


def test_a_document_dated_on_the_deadline_is_reported_as_such(tmp_path):
    result = parse(
        tmp_path,
        message("[cosai-pgb] Call for Consensus to approve Paper X",
                "Please register any objections no later than Friday, September 4, 2026.",
                "cosai-pgb", "Tue, 01 Sep 2026 10:00:00 +0000"),
        message("Re: [cosai-pgb] Call for Consensus to approve Paper X", CLOSED,
                "cosai-pgb", "Mon, 07 Sep 2026 10:00:00 +0000"),
    )
    ev = A.evidence_by_work(A.threads(result), curation_for(TSC_KEY))["paper-x"]
    assert (ev.pgb, ev.pgb_deadline) == ("2026-09-07", "2026-09-04")
    assert A._date_relation("2026-09-04", ev) == "= PGB deadline"


def test_outcomes_reach_the_parse_as_labels_only(tmp_path):
    result = parse(tmp_path, message("[cosai-tsc] Call for Consensus to Approve X", CLOSED))
    event = result.governance[0]
    assert event.outcome == "closed"
    assert CLOSED not in repr(event)


# --- grouping mail into calls ----------------------------------------------------------

@pytest.mark.parametrize("subject", [
    '[cosai-pgb] Call for Consensus to Approve CoSAI WS1 "Signing ML Artifacts" Paper',
    'Re: [cosai-pgb] Call for Consensus to Approve CoSAI WS1 “Signing ML Artifacts” Paper',
    'Fwd: Re: [cosai-pgb] [Action Required] Call for Consensus to Approve CoSAI WS1 '
    '"Signing ML Artifacts" Paper',
    '回复： [cosai-pgb] Reminder: Call for Consensus to Approve CoSAI WS1 '
    '"Signing ML Artifacts" Paper due Sept. 29',
])
def test_variants_of_one_call_share_a_thread_key(subject):
    assert A.thread_key(subject) == \
        "call for consensus to approve cosai ws1 signing ml artifacts paper"


def test_a_tsc_call_forwarded_to_a_workstream_list_is_still_the_tscs(tmp_path):
    result = parse(tmp_path, message("[cosai-tsc] Call for Consensus to approve version 2",
                                     OPEN, list_id="cosai-agentic-systems-ws"))
    assert A.deciding_body(result.governance[0]) == "TSC"


def test_a_workstream_relay_is_not_a_decision(tmp_path):
    result = parse(tmp_path, message("[cosai-defenders] Call for Consensus to approve X",
                                     OPEN, list_id="cosai-defenders-ws"))
    assert A.deciding_body(result.governance[0]) is None


def test_a_thread_closes_on_its_earliest_closing_message(tmp_path):
    subject = "[cosai-pgb] Call for Consensus to Approve Paper X"
    result = parse(
        tmp_path,
        message(subject, PGB_OPEN, "cosai-pgb", "Mon, 01 Sep 2026 10:00:00 +0000"),
        message(f"Re: {subject}", "+1", "cosai-pgb", "Tue, 02 Sep 2026 10:00:00 +0000"),
        message(f"Re: {subject}", CLOSED, "cosai-pgb", "Mon, 07 Sep 2026 10:00:00 +0000"),
    )
    [thread] = A.threads(result)
    assert (thread.opened, thread.closed) == ("2026-09-01", "2026-09-07")
    assert thread.bodies == {"PGB"} and thread.states_tsc_approval
    assert len(thread.message_ids) == 3


def test_an_approval_notice_names_its_bodies_and_dates_itself(tmp_path):
    result = parse(tmp_path, message("[cosai-defenders] Zero Trust Paper approved by TSC and PGB",
                                     "Congratulations.", "cosai-defenders-ws",
                                     "Mon, 07 Sep 2026 10:00:00 +0000"))
    [thread] = A.threads(result)
    assert thread.stage == "approval-notice"
    assert thread.bodies == {"TSC", "PGB"} and thread.closed == "2026-09-07"


# --- the consistency check -------------------------------------------------------------

def two_stage_mail(tmp_path: Path, title: str = "Paper X") -> M.MailParse:
    """A TSC call and a PGB call on one paper, both closed."""
    return parse(
        tmp_path,
        message(f"[cosai-tsc] Call for Consensus to approve {title}", CLOSED, "cosai-tsc",
                "Mon, 24 Aug 2026 10:00:00 +0000"),
        message(f"[cosai-pgb] Call for Consensus to approve {title}", CLOSED, "cosai-pgb",
                "Mon, 07 Sep 2026 10:00:00 +0000"),
    )


def curation_for(*keys: str, works=None, **extra) -> dict:
    links = works if works is not None else [{"id": "paper-x", "as": "new"}]
    return {"threads": {k: {"subject_matter": "publication", "works": links}
                        for k in keys}, **extra}


TSC_KEY = "call for consensus to approve paper x"


def pub(status: str = "approved", **fields) -> dict:
    return {"id": "paper-x", "approval_status": status, "original_date": "2026-09-07",
            **fields}


def test_two_closed_calls_make_an_approval_and_no_findings(tmp_path):
    all_threads = A.threads(two_stage_mail(tmp_path))
    # One subject, two bodies: two calls with their own closes, curated by one key.
    assert [sorted(t.bodies) for t in all_threads] == [["TSC"], ["PGB"]]
    curation = curation_for(TSC_KEY)
    ev = A.evidence_by_work(all_threads, curation)["paper-x"]
    assert (ev.tsc, ev.pgb) == ("2026-08-24", "2026-09-07") and ev.approved
    assert A.findings(all_threads, curation, [pub()], set()) == []


def test_registry_approval_without_archive_evidence_is_reported(tmp_path):
    result = parse(tmp_path, message("[cosai-tsc] Call for Consensus to approve Paper X",
                                     CLOSED))
    problems = A.findings(A.threads(result), curation_for(TSC_KEY), [pub()], set())
    assert problems == ["paper-x: registry says approved; no PGB approval in the archive"]


def test_an_exception_quiets_the_gap_and_goes_stale_once_evidence_appears(tmp_path):
    reason = {"paper-x": "approved before the call process; see TSC minutes"}
    one_call = parse(tmp_path, message("[cosai-tsc] Call for Consensus to approve Paper X",
                                       CLOSED))
    assert A.findings(A.threads(one_call), curation_for(TSC_KEY, no_archive_evidence=reason),
                      [pub()], set()) == []

    both = A.threads(two_stage_mail(tmp_path))
    problems = A.findings(both, curation_for(TSC_KEY, no_archive_evidence=reason),
                          [pub()], set())
    assert any("remove the exception" in p for p in problems)


def test_a_draft_with_an_approval_in_the_archive_is_reported(tmp_path):
    all_threads = A.threads(two_stage_mail(tmp_path))
    problems = A.findings(all_threads, curation_for(TSC_KEY), [pub("working-draft")], set())
    assert problems == ["paper-x: approved in the archive; registry says working-draft"]


def test_a_revision_never_stands_in_for_the_original_approval(tmp_path):
    all_threads = A.threads(two_stage_mail(tmp_path))
    curation = curation_for(TSC_KEY, works=[{"id": "paper-x", "as": "revision"}])
    ev = A.evidence_by_work(all_threads, curation)["paper-x"]
    assert not ev.approved and ev.revisions == ["2026-08-24 TSC", "2026-09-07 PGB"]


def test_one_call_can_revise_one_work_and_first_approve_another(tmp_path):
    all_threads = A.threads(two_stage_mail(tmp_path))
    curation = curation_for(TSC_KEY, works=[{"id": "paper-x", "as": "revision"},
                                            {"id": "addendum-y", "as": "new"}])
    evidence = A.evidence_by_work(all_threads, curation)
    assert evidence["addendum-y"].approved and not evidence["paper-x"].approved


def addendum_mail(tmp_path: Path) -> list[A.Thread]:
    """Paper X approved by both bodies; then one TSC call adding Addendum Y to it."""
    return A.threads(parse(
        tmp_path,
        message("[cosai-tsc] Call for Consensus to approve Paper X", CLOSED, "cosai-tsc",
                "Mon, 24 Aug 2026 10:00:00 +0000"),
        message("[cosai-pgb] Call for Consensus to approve Paper X", CLOSED, "cosai-pgb",
                "Mon, 07 Sep 2026 10:00:00 +0000"),
        message("[cosai-tsc] Call for Consensus to approve version 2 of Paper X", CLOSED,
                "cosai-tsc", "Mon, 21 Sep 2026 10:00:00 +0000"),
    ))


V2_KEY = "call for consensus to approve version 2 of paper x"
ADDENDUM = {"id": "addendum-y", "approval_status": "approved", "original_date": None}


def test_an_addition_takes_its_standing_from_the_work_it_is_added_to(tmp_path):
    curation = {"threads": {
        TSC_KEY: {"subject_matter": "publication", "works": [{"id": "paper-x", "as": "new"}]},
        V2_KEY: {"subject_matter": "publication", "works": [
            {"id": "paper-x", "as": "revision"},
            {"id": "addendum-y", "as": "addition", "to": "paper-x"}]},
    }}
    all_threads = addendum_mail(tmp_path)
    evidence = A.evidence_by_work(all_threads, curation)
    # Not approved in its own right: its approval runs through Paper X.
    assert not evidence["addendum-y"].approved
    assert A.has_standing("addendum-y", evidence, {})
    assert A.findings(all_threads, curation, [pub(), ADDENDUM], set()) == []


def test_an_addition_to_an_unapproved_work_is_reported(tmp_path):
    curation = {"threads": {V2_KEY: {"subject_matter": "publication", "works": [
        {"id": "addendum-y", "as": "addition", "to": "paper-x"}]}}}
    problems = A.findings(addendum_mail(tmp_path), curation,
                          [pub("working-draft"), ADDENDUM], set())
    assert "addendum-y: approved as an addition to paper-x, which has no approval in " \
           "the archive" in problems


@pytest.mark.parametrize("link,expected", [
    ({"id": "addendum-y", "as": "addition"}, "needs `to:` a known work"),
    ({"id": "addendum-y", "as": "addition", "to": "paper-z"}, "needs `to:` a known work"),
    ({"id": "addendum-y", "as": "addition", "to": "addendum-y"}, "is added to itself"),
])
def test_an_addition_must_name_another_known_work(tmp_path, link, expected):
    curation = {"threads": {V2_KEY: {"subject_matter": "publication", "works": [link]}}}
    problems = A.findings(addendum_mail(tmp_path), curation, [pub(), ADDENDUM], set())
    assert any(expected in p for p in problems), problems


def test_additions_to_each_other_give_neither_standing():
    evidence = {"a": A.Evidence(additions=[("b", "2026-09-01", "TSC", None)]),
                "b": A.Evidence(additions=[("a", "2026-09-01", "TSC", None)])}
    assert not A.has_standing("a", evidence, {})


def test_a_ballots_result_is_taken_from_the_pgb_calls_restatement(tmp_path):
    result = parse(
        tmp_path,
        message("[cosai-tsc] [ACTION REQUIRED] Ballot to approve Paper X", OPEN, "cosai-tsc",
                "Mon, 17 Aug 2026 10:00:00 +0000"),
        message("[cosai-pgb] Call for Consensus to approve Paper X", PGB_OPEN, "cosai-pgb",
                "Mon, 01 Sep 2026 10:00:00 +0000"),
        message("Re: [cosai-pgb] Call for Consensus to approve Paper X", CLOSED,
                "cosai-pgb", "Mon, 07 Sep 2026 10:00:00 +0000"),
    )
    curation = curation_for("ballot to approve paper x", TSC_KEY)
    all_threads = A.threads(result)
    ev = A.evidence_by_work(all_threads, curation)["paper-x"]
    assert (ev.tsc, ev.tsc_basis) == ("before 2026-09-01", "stated in PGB call")
    # The unclosed ballot is settled by the restatement, so it is not a finding.
    assert A.findings(all_threads, curation, [pub()], set()) == []


def test_a_review_period_links_its_work_without_approving_it(tmp_path):
    result = parse(tmp_path, message("[cosai-tsc] 5-Day Review Period for Paper X starts now",
                                     "Please review."))
    curation = curation_for("5 day review period for paper x starts now")
    ev = A.evidence_by_work(A.threads(result), curation)["paper-x"]
    assert ev.reviews and not ev.tsc


@pytest.mark.parametrize("links,expected", [
    (["paper-x"], "without an id and role"),
    ([{"id": "paper-x"}], "needs `as:`"),
    ([{"id": "paper-z", "as": "new"}], "unknown work id 'paper-z'"),
])
def test_every_work_link_must_name_a_known_work_and_its_role(tmp_path, links, expected):
    all_threads = A.threads(two_stage_mail(tmp_path))
    problems = A.findings(all_threads, curation_for(TSC_KEY, works=links), [pub()], set())
    assert any(expected in p for p in problems), problems


def test_uncurated_and_vanished_threads_are_both_reported(tmp_path):
    all_threads = A.threads(two_stage_mail(tmp_path))
    curation = {"threads": {"a call that is no longer in the archive":
                            {"subject_matter": "other"}}}
    problems = A.findings(all_threads, curation, [], set())
    assert any(p.startswith("uncurated thread:") for p in problems)
    assert any(p.startswith("curated thread not in the archive:") for p in problems)


def test_an_unregistered_work_is_reported_once_across_its_calls(tmp_path):
    result = parse(
        tmp_path,
        message("[cosai-tsc] [ACTION REQUIRED] Ballot to approve AIMM Paper", CLOSED),
        message("[cosai-pgb] Call for Consensus to approve AIMM Paper", CLOSED, "cosai-pgb"),
    )
    link = [{"title": "AIMM", "as": "new"}]
    curation = {"threads": {k: {"subject_matter": "publication", "works": [],
                                "unregistered": link}
                            for k in ("ballot to approve aimm paper",
                                      "call for consensus to approve aimm paper")}}
    problems = A.findings(A.threads(result), curation, [], set())
    assert problems == ["governance calls name a work not in the registry: 'AIMM' (2 threads)"]


def test_no_message_body_reaches_the_report(tmp_path):
    sentinel = "SENTINEL-body-text-that-must-stay-in-the-mbox"
    result = parse(tmp_path, message("[cosai-tsc] Call for Consensus to approve Paper X",
                                     f"{sentinel}\n{CLOSED}"))
    report = A.write_report(result, A.threads(result), curation_for(TSC_KEY), [pub()], set())
    assert sentinel not in report and "staff@oasis-open.org" not in report


# --- the committed curation ------------------------------------------------------------

def test_the_curated_registry_names_only_known_works_with_roles():
    """Checkable without the archives: every link resolves and states its role."""
    from bubo_graphrag.paths import load_registry, publications

    known = {p["id"] for p in publications()} | A.stub_ids()
    curated = load_registry("approvals")["threads"]
    for key, entry in curated.items():
        assert entry["subject_matter"] in A.SUBJECT_MATTERS, key
        assert key == A.thread_key(key), f"not a normalized thread key: {key!r}"
        for link in entry.get("works") or []:
            assert link["id"] in known and link["as"] in A.LINK_ROLES, (key, link)
            if link["as"] == "addition":
                assert link["to"] in known and link["to"] != link["id"], (key, link)
        for link in entry.get("unregistered") or []:
            assert link["title"] and link["as"] in A.LINK_ROLES, (key, link)
