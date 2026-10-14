"""Publication candidate seed tests.

The generator reads the built graph through a query function; here that is an
in-memory store over a small synthetic graph, so no fetched source is needed.
"""

from __future__ import annotations

import pytest
from rdflib import Graph, Literal, Namespace, RDF, RDFS, XSD

from bubo_graphrag.ingest import publication_candidates as PC
from bubo_graphrag.store import MAILLIST_GRAPH, WEBSITE_GRAPH, RdflibStore

COSAIC = Namespace("https://cosai-oasis.github.io/ontology/cosai-contrib#")


def call(g, name, label, stage, body, opened, closed=None, restates=False):
    node = COSAIC[name]
    g.add((node, RDF.type, COSAIC.GovernanceCall))
    g.add((node, COSAIC.subjectMatter, Literal("publication")))
    g.add((node, COSAIC.concernsTitle, Literal("AIMM: Artifact Integrity Maturity Model")))
    g.add((node, RDFS.label, Literal(label, lang="en")))
    g.add((node, COSAIC.callStage, Literal(stage)))
    g.add((node, COSAIC.decidedBy, COSAIC[f"gov-{body}"]))
    g.add((node, COSAIC.openedOn, Literal(opened, datatype=XSD.date)))
    if closed:
        g.add((node, COSAIC.closedOn, Literal(closed, datatype=XSD.date)))
    if restates:
        g.add((node, COSAIC.restatesTscApproval, Literal(True)))


def post(g, post_id, title, url):
    node = COSAIC[f"post-{post_id}"]
    g.add((node, RDF.type, COSAIC.WebsitePost))
    g.add((node, RDFS.label, Literal(title, lang="en")))
    g.add((node, COSAIC.publishedAt, Literal("2026-09-01T12:00:00+00:00", datatype=XSD.dateTime)))
    g.add((node, COSAIC.linksToUnregistered, Literal(url, datatype=XSD.anyURI)))


@pytest.fixture
def select(tmp_path):
    def make(maillist: Graph | None = None, website: Graph | None = None):
        files = []
        for graph, iri, name in ((maillist, MAILLIST_GRAPH, "m.ttl"),
                                 (website, WEBSITE_GRAPH, "w.ttl")):
            if graph is not None:
                path = tmp_path / name
                graph.serialize(path, format="turtle")
                files.append((path, iri))
        return RdflibStore(files=tuple(files)).select
    return make


def aimm_calls(closed_pgb: str | None = "2026-09-07") -> Graph:
    g = Graph()
    call(g, "c1", "Ballot to approve AIMM Paper, WS1", "ballot", "tsc", "2026-08-25", "2026-09-01")
    call(g, "c2", "Call for Consensus to Approve WS1 AIMM paper", "call-for-consensus", "pgb",
         "2026-09-01", closed_pgb, restates=True)
    return g


def test_a_work_the_calls_approve_is_proposed_with_its_approval_and_workstream(select):
    found, _ = PC.candidates(select(maillist=aimm_calls()), {})
    [aimm] = found
    assert aimm["proposed_id"] == "aimm"
    assert aimm["suggested"]["approval_status"] == "approved"
    assert aimm["suggested"]["workstream"] == "ws1"
    assert [c["body"] for c in aimm["evidence"]["approval_calls"]] == ["tsc", "pgb"]
    # What no evidence supplies is listed for the reviewer, the commit above all.
    assert "commit_sha" in aimm["missing"] and "title" not in aimm["missing"]


def test_a_call_still_open_is_not_reported_as_approved(select):
    found, _ = PC.candidates(select(maillist=aimm_calls(closed_pgb=None)), {})
    assert found[0]["suggested"]["approval_status"] == "approval in progress (TSC closed)"


def test_a_linked_file_is_proposed_with_its_repository_and_path(select):
    g = Graph()
    post(g, 1, "A Post", "https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/guides/a-guide.md")
    [guide], _ = PC.candidates(select(website=g), {})
    assert guide["proposed_id"] == "a-guide"
    assert guide["suggested"] == {"repo": "cosai-oasis/ws4-secure-design-agentic-systems",
                                  "md_path": "guides/a-guide.md", "workstream": "ws4"}


def test_a_path_on_a_branch_is_not_guessed(tmp_path, select):
    """feat/x/guides/a-guide.md is the path guides/a-guide.md on branch feat/x, or x/...
    on branch feat: the URL cannot say which."""
    g = Graph()
    post(g, 1, "A Post", "https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/feat/x/guides/a-guide.md")
    [guide], _ = PC.candidates(select(website=g), {})
    assert "md_path" not in guide["suggested"] and "md_path" in guide["missing"]
    assert "ref other than main" in guide["suggested"]["note"]


def test_files_sharing_a_name_get_their_repository_in_the_id(select):
    g = Graph()
    post(g, 1, "A", "https://github.com/cosai-oasis/cosai-tsc/blob/main/ONBOARDING.md")
    post(g, 2, "B", "https://github.com/cosai-oasis/oasis-open-project/blob/main/ONBOARDING.md")
    found, _ = PC.candidates(select(website=g), {})
    assert {c["proposed_id"] for c in found} == {"cosai-tsc-onboarding",
                                                 "oasis-open-project-onboarding"}


def test_a_dismissal_stops_a_candidate_and_goes_stale_when_unmatched(select):
    g = Graph()
    post(g, 1, "A", "https://github.com/cosai-oasis/cosai-tsc/blob/main/ONBOARDING.md")
    dismissed = {"github.com/cosai-oasis/cosai-tsc/blob/main/onboarding.md": "a guide",
                 "github.com/cosai-oasis/gone/blob/main/old.md": "no longer linked"}
    found, stale = PC.candidates(select(website=g), dismissed)
    assert found == [] and stale == ["github.com/cosai-oasis/gone/blob/main/old.md"]


def test_approved_candidates_come_first(select):
    g = Graph()
    post(g, 1, "A", "https://github.com/cosai-oasis/cosai-tsc/blob/main/zz-first-alphabetically.md")
    found, _ = PC.candidates(select(maillist=aimm_calls(), website=g), {})
    assert found[0]["proposed_id"] == "aimm"


def test_the_committed_dismissal_file_loads():
    assert isinstance(PC.load_dismissed(), dict)
