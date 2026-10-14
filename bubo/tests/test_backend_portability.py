"""Backend portability, demonstrated rather than asserted.

The whole query library runs against a second, independent backend. This is what makes
"swapping the store is easy" a checkable claim: if a query drifts into a
pyoxigraph-specific dialect, or a result shape stops being backend-neutral, these fail.

pyoxigraph is the default (persistent, embedded, fast SPARQL 1.1 aggregation). rdflib is
the portability witness and a viable fallback at this corpus size.
"""

from __future__ import annotations

import pytest

from bubo_graphrag import queries as Q
from bubo_graphrag.paths import CATALOG_TTL, QUERIES
from bubo_graphrag.store import (CITATIONS_GRAPH, GRAPH_FILES, GraphStore,
                                  MAILLIST_GRAPH, ONTOLOGY_GRAPH, WEBSITE_GRAPH,
                                  CALENDAR_GRAPH,
                                  OPTIONAL_GRAPH_FILES, OxigraphStore,
                                  PUBLICATIONS_GRAPH, RdflibStore)
from test_queries import CASES, RQ_CASES


@pytest.fixture(scope="module")
def rdflib_store():
    if not CATALOG_TTL.exists():
        pytest.skip("catalog not built; run python -m bubo_graphrag.build.graph")
    return RdflibStore()


def test_both_backends_satisfy_the_protocol(rdflib_store, store):
    """Structural typing check: the protocol is the entire contract."""
    assert isinstance(rdflib_store, GraphStore)
    assert isinstance(store, GraphStore)


def test_backends_agree_on_triple_count(rdflib_store, store):
    """Compared as distinct triples, because the two lengths mean different things.

    `len()` on the oxigraph store counts quads; on an rdflib Dataset with
    default_union it counts distinct triples in the union. Those agree only while no
    triple is repeated across graphs -- which is enforced separately above, so this
    compares the union both backends actually answer queries from.
    """
    sparql = "SELECT (COUNT(DISTINCT *) AS ?n) WHERE { ?s ?p ?o }"
    assert rdflib_store.select(sparql)[0]["n"] == store.select(sparql)[0]["n"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_parameterised_query_on_rdflib_backend(rdflib_store, name):
    """Every tool query must return the same answer on the other backend."""
    template, check = CASES[name][0], CASES[name][1]
    rows = rdflib_store.select(Q.render(getattr(Q, name), **template))
    assert check(rows), f"{name} differed on the rdflib backend: {rows[:3]}"


@pytest.mark.parametrize("filename", sorted(RQ_CASES))
def test_rq_file_on_rdflib_backend(rdflib_store, filename):
    minimum, extra = RQ_CASES[filename]
    rows = rdflib_store.select((QUERIES / filename).read_text(encoding="utf-8"))
    assert len(rows) >= minimum
    if extra is not None:
        assert extra(rows), f"{filename} differed on the rdflib backend"


def test_read_only_guard_is_backend_independent(rdflib_store):
    """The guard lives above the backend, so it protects both equally."""
    with pytest.raises(ValueError):
        rdflib_store.query_guarded("INSERT DATA { <a:b> <a:c> <a:d> }")
    assert rdflib_store.query_guarded(
        "SELECT ?s WHERE { ?s a cosaic:Person }", limit=3)["count"] == 3


def test_term_rendering_is_backend_neutral(rdflib_store, store):
    """Local IRIs shorten, literals stringify, identically on both.

    This is the one place backends genuinely differ (pyoxigraph and rdflib have
    different term types), so it is the seam most likely to leak.
    """
    sparql = """
        SELECT ?person ?earliest ?boundsKnown WHERE {
          ?r a cosaic:AffiliationRole ; obo:BFO_0000197 ?p ; obo:BFO_0000199 ?i .
          ?p rdfs:label ?person .
          ?i cosaic:earliestEvidence ?earliest ; cosaic:boundsKnown ?boundsKnown .
        } ORDER BY ?person ?earliest LIMIT 10
    """
    assert rdflib_store.select(sparql) == store.select(sparql)


def test_backend_selection_by_environment(monkeypatch):
    from bubo_graphrag import store as store_module

    monkeypatch.setenv("COSAI_GRAPH_BACKEND", "rdflib")
    assert store_module.backend_name() == "rdflib"
    monkeypatch.delenv("COSAI_GRAPH_BACKEND")
    assert store_module.backend_name() == "oxigraph"


def test_unknown_backend_is_rejected():
    from bubo_graphrag.store import Store

    with pytest.raises(ValueError, match="unknown backend"):
        Store(backend="neo4j")


def test_pyoxigraph_is_confined_to_the_store_module():
    """The coupling surface must stay one module, or portability quietly erodes."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src" / "bubo_graphrag"
    offenders = []
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import pyoxigraph", "from pyoxigraph")):
                if path.name != "store.py":
                    offenders.append(f"{path.relative_to(src)}: {stripped}")
    assert not offenders, (
        "pyoxigraph imported outside store.py, which breaks the backend seam: "
        + "; ".join(offenders))


def test_graph_files_are_declared_in_one_place():
    """A backend needs to know what to load; that list must not be duplicated.

    Each entry pairs a file with the named graph it loads into, so the partitioning is
    declared once here rather than inferred by either backend.
    """
    assert all(path.suffix == ".ttl" for path, _ in GRAPH_FILES)
    assert len({path for path, _ in GRAPH_FILES}) == len(GRAPH_FILES), "a file twice"
    graphs = {graph for _, graph in GRAPH_FILES}
    assert graphs == {ONTOLOGY_GRAPH, PUBLICATIONS_GRAPH, CITATIONS_GRAPH,
                      MAILLIST_GRAPH, WEBSITE_GRAPH, CALENDAR_GRAPH}


def test_no_triple_is_asserted_in_two_named_graphs(store):
    """The union default graph is a multiset union, not an RDF merge.

    So one triple in two graphs yields two solutions, and every query that joins
    through it silently returns each row twice. This caught exactly that: the meetings
    graph re-declaring `cosaic:ws-ws2 a cosaic:Workstream`, which the publications
    graph already owns, turned 7 credit rows into 9. A named graph asserts only what
    its own source establishes and references shared IRIs instead.
    """
    duplicated = store.select("""
        SELECT ?s ?p ?o WHERE { GRAPH ?g { ?s ?p ?o } }
        GROUP BY ?s ?p ?o HAVING (COUNT(DISTINCT ?g) > 1)""")
    assert duplicated == [], f"triples in multiple graphs: {duplicated[:5]}"


def test_every_loaded_file_lands_in_its_declared_graph(store):
    """Partitioning by provenance is the point; an empty partition means a build gap."""
    present = store.named_graphs()
    expected = {graph for path, graph in GRAPH_FILES
                if path.exists() and path not in OPTIONAL_GRAPH_FILES}
    assert expected <= set(present)
    assert all(count > 0 for count in present.values())
