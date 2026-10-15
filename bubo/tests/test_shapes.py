"""SHACL validation of the provenance partitioning and the domain invariants.

Each named graph is validated **alone** against the allowlist of classes it may
introduce. That is the positive, per-graph form of "each graph records only triples
from its own provenance", and it catches the defect that prompted the shapes:
`cosaic:ws-ws2 a cosaic:Workstream` asserted inside the maillist graph fails
`MaillistGraphShape` whether or not the publications graph also holds that triple --
so the mistake is caught before duplication makes it visible as doubled query rows.

The cross-graph uniqueness rule itself is deliberately *not* here. It quantifies over
graphs while SHACL validates a data graph, so expressing it would need a `sh:sparql`
constraint with a GRAPH clause whose behavior depends on how an engine exposes the
dataset. It stays a dataset query in test_backend_portability.py.
"""

from __future__ import annotations

import pytest
from rdflib import Graph, Literal, Namespace, RDF, URIRef

from bubo_graphrag.paths import ONTOLOGY
from bubo_graphrag.store import (CITATIONS_GRAPH, GRAPH_FILES, MAILLIST_GRAPH,
                                  ONTOLOGY_GRAPH, PUBLICATIONS_GRAPH, WEBSITE_GRAPH,
                                  CALENDAR_GRAPH)

pyshacl = pytest.importorskip("pyshacl", reason="pyshacl is a dev dependency")

COSAIC = Namespace("https://cosai-oasis.github.io/ontology/cosai-contrib#")
SHAPES = ONTOLOGY / "shapes" / "provenance.ttl"

SHAPE_FOR = {
    PUBLICATIONS_GRAPH: "PublicationsGraphShape",
    CITATIONS_GRAPH: "CitationsGraphShape",
    MAILLIST_GRAPH: "MaillistGraphShape",
    WEBSITE_GRAPH: "WebsiteGraphShape",
    CALENDAR_GRAPH: "CalendarGraphShape",
    ONTOLOGY_GRAPH: "OntologyGraphShape",
}


SH = Namespace("http://www.w3.org/ns/shacl#")


@pytest.fixture(scope="module")
def all_shapes() -> Graph:
    graph = Graph()
    graph.parse(SHAPES, format="turtle")
    return graph


def focused(all_shapes: Graph, provenance_shape: str | None) -> Graph:
    """One provenance shape plus every domain invariant.

    The provenance shapes all target `sh:targetSubjectsOf rdf:type`, which cannot
    express "only in this graph" -- so loading the whole shapes file would run every
    allowlist against whichever graph is under validation, and only their intersection
    would pass. Selecting one at a time is what makes the allowlist mean "this
    partition". Every other shape is an invariant and always applies, whatever it
    targets: the mail coverage window shape targets subjects of cosaic:sourceList.
    """
    graph = Graph()
    for shape in all_shapes.subjects(RDF.type, SH.NodeShape):
        name = str(shape).rsplit("#", 1)[-1]
        keep = (not name.endswith("GraphShape")
                or (provenance_shape is not None and name == provenance_shape))
        if keep:
            graph += all_shapes.cbd(shape)
    return graph


@pytest.fixture(scope="module")
def shapes(all_shapes) -> Graph:
    """Invariants only -- for the hand-built cases that assert one shape's behavior."""
    return all_shapes


def graph_files_for(target: str) -> list:
    return [path for path, graph_iri in GRAPH_FILES
            if graph_iri == target and path.exists()]


def load(target: str) -> Graph | None:
    """One named graph, loaded alone -- which is what makes the allowlist meaningful."""
    files = graph_files_for(target)
    if not files:
        return None
    graph = Graph()
    for path in files:
        graph.parse(path, format="turtle")
    return graph


def conforms(data: Graph, shapes: Graph) -> tuple[bool, str]:
    ok, _, text = pyshacl.validate(data_graph=data, shacl_graph=shapes,
                                   advanced=True, inference="none")
    return ok, text


def test_shapes_file_is_valid_turtle(all_shapes):
    assert len(all_shapes) > 0
    declared = {str(s).rsplit("#", 1)[-1]
                for s in all_shapes.subjects(RDF.type, SH.NodeShape)}
    assert set(SHAPE_FOR.values()) <= declared


@pytest.mark.parametrize("target", sorted(SHAPE_FOR))
def test_each_named_graph_conforms_to_its_provenance_shape(target, all_shapes):
    data = load(target)
    if data is None:
        pytest.skip(f"{target} not built")
    ok, report = conforms(data, focused(all_shapes, SHAPE_FOR[target]))
    assert ok, f"{target} violated its provenance shape:\n{report[:2000]}"


def test_a_foreign_class_in_the_meetings_graph_is_rejected(all_shapes):
    """The regression this exists for, reproduced directly.

    A Workstream typed inside the maillist graph is the triple that doubled 7 credit
    rows into 9. The shape must reject it on its own, without reference to any other
    graph.
    """
    data = Graph()
    data.add((COSAIC["ws-ws2"], RDF.type, COSAIC.Workstream))
    ok, report = conforms(data, focused(all_shapes, "MaillistGraphShape"))
    assert not ok
    assert "list mail may introduce" in report


def test_a_person_in_the_meetings_graph_is_rejected(all_shapes):
    """List mail names no attendees, so it may not introduce people at all."""
    data = Graph()
    data.add((COSAIC["person-someone"], RDF.type, COSAIC.Person))
    ok, _ = conforms(data, focused(all_shapes, "MaillistGraphShape"))
    assert not ok


def test_instance_data_in_the_terminology_graph_is_rejected(all_shapes):
    data = Graph()
    data.add((COSAIC["meeting-x-2026-08-11"], RDF.type, COSAIC.Meeting))
    ok, report = conforms(data, focused(all_shapes, "OntologyGraphShape"))
    assert not ok
    assert "terminology graph" in report


# --- the domain invariants --------------------------------------------------------

def test_an_affiliation_interval_claiming_known_bounds_is_rejected(shapes):
    """ADR-WS2-001 D3: no fabricated bounds.

    The corpus records that someone was credited under an employer on given dates, not
    when they joined or left, so a bare start or end date would be false precision.
    """
    data = Graph()
    interval = COSAIC["interval-x-01"]
    data.add((interval, RDF.type, COSAIC.EvidenceInterval))
    data.add((interval, COSAIC.earliestEvidence,
              Literal("2025-07-14", datatype=URIRef(
                  "http://www.w3.org/2001/XMLSchema#date"))))
    data.add((interval, COSAIC.boundsKnown, Literal(True)))
    ok, report = conforms(data, shapes)
    assert not ok
    assert "boundsKnown false" in report


def test_an_inferred_change_must_bound_its_window(shapes):
    data = Graph()
    window = COSAIC["window-x-01"]
    data.add((window, RDF.type, COSAIC.UncertaintyWindow))
    ok, report = conforms(data, shapes)
    assert not ok
    assert "bound the window" in report


def test_a_coverage_window_may_not_claim_known_bounds(shapes):
    data = Graph()
    window = COSAIC["coverage-x"]
    data.add((window, RDF.type, COSAIC.CoverageWindow))
    data.add((window, COSAIC.boundsKnown, Literal(True)))
    ok, report = conforms(data, shapes)
    assert not ok
    assert "coverage bounds are never known" in report


def test_a_meeting_without_date_evidence_is_rejected(shapes):
    data = Graph()
    meeting = COSAIC["meeting-x-2026-08-11"]
    data.add((meeting, RDF.type, COSAIC.Meeting))
    data.add((meeting, COSAIC.sourceMessageId, Literal("a@b")))
    ok, report = conforms(data, shapes)
    assert not ok
    assert "how its date was established" in report


def test_an_unknown_date_evidence_value_is_rejected(shapes):
    """The three strengths are a closed set; a fourth would hide its own weakness."""
    data = Graph()
    meeting = COSAIC["meeting-x-2026-08-11"]
    data.add((meeting, RDF.type, COSAIC.Meeting))
    data.add((meeting, COSAIC.dateEvidence, Literal("guessed")))
    data.add((meeting, COSAIC.sourceMessageId, Literal("a@b")))
    data.add((meeting, URIRef("http://purl.obolibrary.org/obo/BFO_0000199"),
              COSAIC["instant-2026-08-11"]))
    data.add((COSAIC["instant-2026-08-11"], RDF.type, COSAIC.Instant))
    ok, _ = conforms(data, shapes)
    assert not ok


def test_fabricated_attendance_is_rejected(shapes):
    """No source names attendees, so any AttendanceRole is invented."""
    data = Graph()
    data.add((COSAIC["attend-x-01"], RDF.type, COSAIC.AttendanceRole))
    ok, report = conforms(data, shapes)
    assert not ok
    assert "attendance is unknown, not empty" in report


# --- union-level checks -----------------------------------------------------------
#
# Two levels are needed, and the split is forced by the partitioning itself. A
# per-graph shape can only see what that graph asserts, so a cross-partition reference
# -- a meeting pointing at an instant the publication catalog owns -- is unverifiable
# locally. Requiring each graph to re-declare the types it references would reintroduce
# the duplication that doubles rows. So: provenance allowlists per graph, referential
# integrity across the union.

def test_no_dangling_temporal_reference_across_the_union(store):
    """Every temporal region referenced anywhere is typed somewhere."""
    dangling = store.select("""
        SELECT ?subject ?region WHERE {
          ?subject obo:BFO_0000199 ?region .
          FILTER NOT EXISTS { ?region a cosaic:Instant }
          FILTER NOT EXISTS { ?region a cosaic:EvidenceInterval }
          FILTER NOT EXISTS { ?region a cosaic:UncertaintyWindow }
          FILTER NOT EXISTS { ?region a cosaic:CoverageWindow }
        }""")
    assert dangling == [], f"untyped temporal regions: {dangling[:5]}"


def test_no_dangling_series_or_workstream_reference(store):
    """Meetings reference series and workstreams that must exist in the union."""
    dangling = store.select("""
        SELECT ?meeting ?series WHERE {
          ?meeting cosaic:inSeries ?series .
          FILTER NOT EXISTS { ?series a cosaic:MeetingSeries }
        }""")
    assert dangling == [], f"meetings in a series that does not exist: {dangling[:5]}"
    orphan = store.select("""
        SELECT ?series ?group WHERE {
          ?series cosaic:convenedBy ?group .
          FILTER NOT EXISTS { ?group a cosaic:Workstream }
          FILTER NOT EXISTS { ?group a cosaic:GoverningBody }
          FILTER NOT EXISTS { ?group a cosaic:Committee }
          FILTER NOT EXISTS { ?group a cosaic:SpecialInterestGroup }
        }""")
    assert orphan == [], f"series convened by an unknown group: {orphan[:5]}"


# --- website ----------------------------------------------------------------------

def _website_graph():
    from bubo_graphrag.ingest import website as W
    body = ('<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">'
            "<channel><item><title>A Post</title>"
            "<link>https://www.coalitionforsecureai.org/a-post/</link>"
            "<pubDate>Mon, 21 Sep 2026 10:00:00 +0000</pubDate>"
            "<category>Blog Post</category>"
            "<guid>https://secureaistg.wpenginepowered.com/?p=42</guid>"
            "</item></channel></rss>").encode()
    return W.build(W.parse_pages([body], "2026-09-26"))


def test_a_built_website_graph_conforms_without_a_fetch(all_shapes):
    ok, report = conforms(_website_graph(), focused(all_shapes, "WebsiteGraphShape"))
    assert ok, report[:2000]


def test_a_person_in_the_website_graph_is_rejected(all_shapes):
    """The feed credits no author, so it may not introduce people or roles at all."""
    data = _website_graph()
    data.add((COSAIC["person-someone"], RDF.type, COSAIC.Person))
    data.add((COSAIC["credit-x"], RDF.type, COSAIC.AuthorRole))
    ok, report = conforms(data, focused(all_shapes, "WebsiteGraphShape"))
    assert not ok and "credits no author" in report


def test_a_post_without_its_post_id_is_rejected(shapes):
    data = _website_graph()
    data.remove((COSAIC["post-42"], COSAIC.sourcePostId, None))
    ok, report = conforms(data, focused(shapes, None))
    assert not ok and "post ID" in report


def test_a_feed_window_must_say_when_it_was_fetched(shapes):
    data = _website_graph()
    data.remove((COSAIC["coverage-feed-coalitionforsecureai"], COSAIC.fetchedOn, None))
    ok, report = conforms(data, focused(shapes, None))
    assert not ok and "when the feed was fetched" in report


def test_a_mail_window_still_needs_its_message_bounds(shapes):
    data = Graph()
    window = COSAIC["coverage-cosai-tsc"]
    data.add((window, RDF.type, COSAIC.CoverageWindow))
    data.add((window, COSAIC.boundsKnown, Literal(False)))
    data.add((window, COSAIC.sourceList, Literal("cosai-tsc")))
    ok, _ = conforms(data, focused(shapes, None))
    assert not ok


# --- calendar ---------------------------------------------------------------------

def _calendar_graph():
    from bubo_graphrag.ingest import calendar as C
    cal = C.parse({"group": "open-projects+cosai-op", "range_start": "2024-07-18",
                   "range_end": "2027-09-27", "fetched_at": "2026-09-26T11:52:22+00:00",
                   "events": [{"id": 1, "name": "WS1 Weekly Meeting",
                               "start_time": "2026-09-02T10:00:00-07:00",
                               "end_time": "2026-09-02T11:00:00-07:00",
                               "timezone": "America/New_York"},
                              {"id": 2, "name": "WS1 Weekly Meeting",
                               "start_time": "2026-10-07T10:00:00-07:00",
                               "end_time": "2026-10-07T11:00:00-07:00",
                               "timezone": "America/New_York"}]})
    return C.build(cal)


def test_a_built_calendar_graph_conforms_without_a_fetch(all_shapes):
    ok, report = conforms(_calendar_graph(), focused(all_shapes, "CalendarGraphShape"))
    assert ok, report[:2000]


@pytest.mark.parametrize("cls", ["Meeting", "Person"])
def test_a_meeting_or_person_in_the_calendar_graph_is_rejected(all_shapes, cls):
    """An entry is not a meeting, and the organizer is never kept."""
    data = _calendar_graph()
    data.add((COSAIC["x"], RDF.type, COSAIC[cls]))
    ok, report = conforms(data, focused(all_shapes, "CalendarGraphShape"))
    assert not ok and "entries are not meetings" in report


def test_a_scheduled_meeting_without_its_event_id_is_rejected(shapes):
    data = _calendar_graph()
    data.remove((COSAIC["calevent-1"], COSAIC.sourceEventId, None))
    ok, report = conforms(data, focused(shapes, None))
    assert not ok and "calendar event ID" in report


def test_a_planned_meeting_must_also_be_a_scheduled_meeting(shapes):
    data = _calendar_graph()
    data.remove((COSAIC["calevent-2"], RDF.type, COSAIC.ScheduledMeeting))
    ok, report = conforms(data, focused(shapes, None))
    assert not ok and "also be typed ScheduledMeeting" in report


def test_a_calendar_window_must_say_when_it_was_read(shapes):
    data = _calendar_graph()
    data.remove((COSAIC["coverage-calendar-cosai-op"], COSAIC.fetchedOn, None))
    ok, report = conforms(data, focused(shapes, None))
    assert not ok and "when the calendar was read" in report
