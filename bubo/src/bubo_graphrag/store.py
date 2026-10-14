"""RDF store access, behind a backend-agnostic interface.

## Why pyoxigraph is the default

* **Embedded, no server.** The MCP server is launched over stdio on a user's machine.
  Requiring a running daemon, a port, or a container would be a real adoption cost for
  a tool whose whole job is answering questions locally. The store is one directory.
* **Complete SPARQL 1.1.** Every query in this project is aggregation-heavy
  (`COUNT(DISTINCT ...)` with `GROUP BY`, property paths, `OPTIONAL` left joins).
  Oxigraph implements SPARQL 1.1 fully and passes the W3C test suites; rdflib's engine
  is slower on exactly this shape of query.
* **Persistence.** Without it, every stdio launch re-parses five Turtle files. That is
  cheap at ~6,300 triples and stops being cheap once the Risk Map layer (step 5) and step 6
  GitHub events land.
* **Named graphs**, which step 5 needs to keep `cosai:` Risk Map triples separable
  from `cosaic:` contribution triples.

## What it deliberately does not do

* **No reasoning.** Oxigraph performs no RDFS or OWL inference, by design. This project
  does not currently need any -- subclass traversal is done with SPARQL property paths
  (`a/rdfs:subClassOf*`) rather than entailment. If step 5 wants real OWL reasoning it
  must be a *build* step (owlrl, or ELK/HermiT) materialised into the Turtle before
  load. That is an architectural constraint, not an oversight.
* **No graph algorithms.** Centrality or community detection would mean exporting to
  networkx or igraph.
* **An exclusive lock** on the store directory, so one process opens it once; hence
  `get_store`.

## Swapping backends

Everything above this module speaks SPARQL strings and plain dicts. `queries.py` holds
only strings; `server.py` and `build/graph.py` touch nothing but the three methods on
`GraphStore`. So a new backend is one class implementing that protocol.

This is not a claim -- `RdflibStore` below is a second, working backend, and
tests/test_queries.py runs the entire query suite against both. Select one with
`COSAI_GRAPH_BACKEND=rdflib|oxigraph`.

A property-graph target (Neo4j, Kùzu) is a different proposition: the protocol would be
satisfiable, but all 24 queries would need rewriting from SPARQL to Cypher, and the
BFO/CCO grounding that motivates the project would lose its native representation. The
cost there is the query library and the ontology fidelity, not the interface.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any, Iterator, Protocol, runtime_checkable

from .paths import CATALOG_TTL, GRAPH_DB, ONTOLOGY

PREFIXES = """
PREFIX cosaic: <https://cosai-oasis.github.io/ontology/cosai-contrib#>
PREFIX cco:    <https://www.commoncoreontologies.org/>
PREFIX obo:    <http://purl.obolibrary.org/obo/>
PREFIX rdf:    <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs:   <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl:    <http://www.w3.org/2002/07/owl#>
PREFIX skos:   <http://www.w3.org/2004/02/skos/core#>
PREFIX xsd:    <http://www.w3.org/2001/XMLSchema#>
"""

# --- Named graphs ----------------------------------------------------------------
#
# Data is partitioned by provenance, not by subject matter, because the partitions
# differ in ways a consumer has to be able to act on: the publication catalog is
# derived from repository markdown pinned by commit sha; citations come from the CoSAI
# TSC dataset and are refreshed weekly upstream; meetings and governance calls come from
# list mail, the maillist graph, whose coverage is a partial window. Mixing them would make "how do you know this?"
# unanswerable, and would leave no way to drop and rebuild one source alone.
#
# Every query is then run with the default graph as the *union* of these, so existing
# queries are unaffected -- verified: without that, a quad in a named graph is
# invisible to a default-graph query and every query in the suite returns nothing.
GRAPH_NS = "https://cosai-oasis.github.io/graph/"
ONTOLOGY_GRAPH = GRAPH_NS + "ontology"
PUBLICATIONS_GRAPH = GRAPH_NS + "publications"
CITATIONS_GRAPH = GRAPH_NS + "citations"
MAILLIST_GRAPH = GRAPH_NS + "maillist"
WEBSITE_GRAPH = GRAPH_NS + "website"
CALENDAR_GRAPH = GRAPH_NS + "calendar"

# Ordered: the ontology first, so labels for MIREOT'd CCO terms are available.
GRAPH_FILES: tuple[tuple[Path, str], ...] = (
    (ONTOLOGY / "alignments" / "cco.ttl", ONTOLOGY_GRAPH),
    (ONTOLOGY / "cosai-contrib.ttl", ONTOLOGY_GRAPH),
    (ONTOLOGY / "alignments" / "bridges.ttl", ONTOLOGY_GRAPH),
    (CATALOG_TTL, PUBLICATIONS_GRAPH),
    (ONTOLOGY / "citations.ttl", CITATIONS_GRAPH),
    (ONTOLOGY / "maillist.ttl", MAILLIST_GRAPH),
    (ONTOLOGY / "website.ttl", WEBSITE_GRAPH),
    (ONTOLOGY / "calendar.ttl", CALENDAR_GRAPH),
)

# The maillist graph is optional: it is built from list archives fetched with a personal
# groups.io key, which most consumers of this repository will not have run. The
# website graph is optional too: it is built from a fetch of the site's feed. So is
# the calendar graph, read with the same personal key as the mail. A missing file
# here is not an error.
OPTIONAL_GRAPH_FILES = frozenset({ONTOLOGY / "maillist.ttl", ONTOLOGY / "website.ttl",
                                  ONTOLOGY / "calendar.ttl"})

READ_ONLY_FORMS = ("select", "ask", "construct", "describe")
MAX_ROWS = 2000

# SPARQL keywords that make the engine open a network connection. Read-only is not
# enough on its own: a SELECT carrying `SERVICE <http://host/>` is a federated query,
# so the engine dials that host and streams matched bindings to it. Verified against
# this store by a one-off manual probe -- a SERVICE clause pointed at loopback returned
# ConnectionRefused, and one pointed at the cloud instance-metadata address hung for two
# minutes with no timeout. Under an escape hatch whose query text comes from a model
# that has read untrusted document content, that is an arbitrary egress and
# exfiltration primitive, refused at the boundary rather than range-limited.
#
# The regression tests do not repeat that probe. They scan query text, so they cannot
# dial anything even if this guard regresses; the engine-level cases use closed
# loopback ports only, never an address that answers on a cloud CI runner.
#
# MCP Security v2.0 §3.3.2 "SSRF and traversal defense" and §3.2.3 (allowlist
# validation at every trust boundary); threats MCP-T3, MCP-T4, MCP-T10.
FEDERATION_KEYWORDS = ("service", "load")

LOCAL_NS = "https://cosai-oasis.github.io/ontology/cosai-contrib#"


# --------------------------------------------------------------------- interface

@runtime_checkable
class GraphStore(Protocol):
    """The entire surface a backend must provide.

    Three methods and a length. Results are plain Python dicts of strings, so nothing
    above this module sees backend term types.
    """

    def __len__(self) -> int: ...

    def select(self, sparql: str, limit: int = MAX_ROWS) -> list[dict[str, Any]]: ...

    def ask(self, sparql: str) -> bool: ...

    def query_guarded(self, sparql: str, limit: int = MAX_ROWS) -> dict[str, Any]: ...

    def named_graphs(self) -> dict[str, int]: ...


class _QueryGuard:
    """Shared read-only enforcement, independent of backend."""

    def query_guarded(self, sparql: str, limit: int = MAX_ROWS) -> dict[str, Any]:
        """Validate and run a client-supplied query.

        Rejects anything that is not a read form, blocking INSERT, DELETE, DROP, LOAD
        and CLEAR rather than relying on the store being opened read-only.
        """
        stripped = _strip_prologue(sparql)
        form = stripped.split(None, 1)[0].lower() if stripped else ""
        if form not in READ_ONLY_FORMS:
            raise ValueError(
                f"only {', '.join(f.upper() for f in READ_ONLY_FORMS)} are permitted; "
                f"got {form.upper() or 'an empty query'}")
        if found := _federation_keyword(sparql):
            raise ValueError(
                f"{found.upper()} is not permitted: it would make the query engine "
                "connect to an external host. This store answers only from local data.")
        if form == "ask":
            return {"form": "ask", "result": self.ask(sparql)}
        rows = self.select(sparql, limit=limit)
        return {"form": form, "rows": rows, "count": len(rows),
                "truncated": len(rows) >= limit}


_LITERAL = re.compile(r'"""(?:\\.|[^\\])*?"""|\'\'\'(?:\\.|[^\\])*?\'\'\''
                      r'|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)
_IRI = re.compile(r'<[^<>"{}|^`\\\s]*>')
_COMMENT = re.compile(r"#[^\n]*")
# Not preceded by a word character or a colon, so `ex:service` and `myservice` are left
# alone. The store holds an organization literally named "ServiceNow", so the scan runs
# only after literals and IRIs have been removed -- matching raw text would refuse a
# legitimate query about that organization.
_FEDERATION = re.compile(rf"(?<![\w:])(?:{'|'.join(FEDERATION_KEYWORDS)})\b", re.I)


def _federation_keyword(sparql: str) -> str | None:
    """The first federation keyword in `sparql`, ignoring literals, IRIs and comments."""
    text = _COMMENT.sub(" ", _IRI.sub(" ", _LITERAL.sub(" ", sparql)))
    match = _FEDERATION.search(text)
    return match.group(0) if match else None


def _strip_prologue(sparql: str) -> str:
    """Remove comments and PREFIX/BASE declarations to find the query form."""
    lines = []
    for line in sparql.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.lower().startswith(("prefix ", "base ")):
            continue
        lines.append(line)
    return " ".join(lines).strip()


def _shorten(iri: str) -> str:
    """Local name for this project's namespace; full IRI otherwise.

    An external IRI is the useful thing to report; a local one is noise.
    """
    return iri.rsplit("#", 1)[1] if iri.startswith(LOCAL_NS) else iri


# ------------------------------------------------------------- oxigraph backend

class OxigraphStore(_QueryGuard):
    """Persistent, embedded backend. The default."""

    def __init__(self, path: Path | None = None) -> None:
        import pyoxigraph as ox

        self._ox = ox
        target = path or GRAPH_DB
        if not target.exists():
            raise FileNotFoundError(
                f"{target} missing. Run `python -m bubo_graphrag.build.graph` first.")
        self._store = ox.Store(str(target))

    def __len__(self) -> int:
        return len(self._store)

    def select(self, sparql: str, limit: int = MAX_ROWS) -> list[dict[str, Any]]:
        # use_default_graph_as_union: the data lives in named graphs, so without this
        # every query matching `?s ?p ?o` in the default graph returns nothing.
        results = self._store.query(PREFIXES + sparql, use_default_graph_as_union=True)
        rows: list[dict[str, Any]] = []
        for solution in results:
            if len(rows) >= limit:
                break
            rows.append({
                str(var).lstrip("?"): self._plain(solution[var])
                for var in results.variables
                if solution[var] is not None
            })
        return rows

    def ask(self, sparql: str) -> bool:
        return bool(self._store.query(PREFIXES + sparql, use_default_graph_as_union=True))

    def named_graphs(self) -> dict[str, int]:
        """Quad count per named graph. The provenance breakdown, for `graph_schema`."""
        rows = self._store.query(
            "SELECT ?g (COUNT(*) AS ?n) WHERE { GRAPH ?g { ?s ?p ?o } } GROUP BY ?g")
        return {str(row["g"].value): int(row["n"].value) for row in rows}

    def _plain(self, term: Any) -> Any:
        ox = self._ox
        if isinstance(term, ox.Literal):
            return term.value
        if isinstance(term, ox.NamedNode):
            return _shorten(term.value)
        if isinstance(term, ox.BlankNode):
            return f"_:{term.value}"
        return str(term)


# --------------------------------------------------------------- rdflib backend

class RdflibStore(_QueryGuard):
    """In-memory backend, kept working to prove the interface is portable.

    Viable in its own right at this corpus size, and the reason the backend seam is
    verified rather than assumed: the full query suite runs against it in CI.
    """

    def __init__(self, path: Path | None = None, files=GRAPH_FILES) -> None:
        from rdflib import Dataset, URIRef

        # default_union mirrors oxigraph's use_default_graph_as_union, so the same
        # query text behaves identically on both backends. That equivalence is what
        # tests/test_backend_portability.py exists to keep true.
        self._dataset = Dataset(default_union=True)
        for file, graph_iri in files:
            if not file.exists():
                if file in OPTIONAL_GRAPH_FILES:
                    continue
                raise FileNotFoundError(
                    f"{file} missing. Run `python -m bubo_graphrag.build.graph` first.")
            self._dataset.graph(URIRef(graph_iri)).parse(file, format="turtle")
        self._graph = self._dataset

    def named_graphs(self) -> dict[str, int]:
        return {str(context.identifier): len(context)
                for context in self._dataset.contexts() if len(context)}

    def __len__(self) -> int:
        return len(self._graph)

    def select(self, sparql: str, limit: int = MAX_ROWS) -> list[dict[str, Any]]:
        results = self._graph.query(PREFIXES + sparql)
        variables = [str(v) for v in (results.vars or [])]
        rows: list[dict[str, Any]] = []
        for row in results:
            if len(rows) >= limit:
                break
            rows.append({
                var: self._plain(getattr(row, var))
                for var in variables
                if getattr(row, var, None) is not None
            })
        return rows

    def ask(self, sparql: str) -> bool:
        return bool(self._graph.query(PREFIXES + sparql).askAnswer)

    @staticmethod
    def _plain(term: Any) -> Any:
        from rdflib import BNode, Literal, URIRef

        if isinstance(term, Literal):
            # str() rather than .value, so xsd:date and xsd:boolean render as the
            # lexical forms the oxigraph backend also returns.
            return str(term)
        if isinstance(term, URIRef):
            return _shorten(str(term))
        if isinstance(term, BNode):
            return f"_:{term}"
        return str(term)


# Backwards-compatible alias: `Store` is the configured default backend.
BACKENDS = {"oxigraph": OxigraphStore, "rdflib": RdflibStore}
DEFAULT_BACKEND = "oxigraph"


def backend_name() -> str:
    return os.environ.get("COSAI_GRAPH_BACKEND", DEFAULT_BACKEND).lower()


def Store(path: Path | None = None, backend: str | None = None) -> GraphStore:  # noqa: N802
    """Construct the configured backend. Kept callable-as-a-class for readability."""
    name = (backend or backend_name())
    try:
        cls = BACKENDS[name]
    except KeyError:
        raise ValueError(
            f"unknown backend {name!r}; expected one of {sorted(BACKENDS)}") from None
    return cls(path)


# ------------------------------------------------------------------ build / cache

def load_store(path: Path | None = None) -> int:
    """Rebuild the persistent store from the ontology and catalog files.

    Only meaningful for a persistent backend; the rdflib backend loads on construction.
    Returns the triple count.
    """
    import pyoxigraph as ox

    target = path or GRAPH_DB
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    store = ox.Store(str(target))
    for file, graph_iri in GRAPH_FILES:
        if not file.exists():
            if file in OPTIONAL_GRAPH_FILES:
                continue
            raise FileNotFoundError(
                f"{file} missing. Run `python -m bubo_graphrag.build.graph` first.")
        store.load(path=str(file), format=ox.RdfFormat.TURTLE,
                   to_graph=ox.NamedNode(graph_iri))
    store.optimize()
    count = len(store)
    del store
    reset_store_cache()
    return count


_INSTANCES: dict[tuple[str, Path], GraphStore] = {}


def get_store(path: Path | None = None, backend: str | None = None) -> GraphStore:
    """Return the process-wide store for a path, opening it at most once.

    pyoxigraph takes an exclusive lock on the store directory, so a second handle on the
    same path in one process fails with "No locks available". Routing every caller
    through here keeps the server and any in-process consumer sharing one handle.
    """
    name = backend or backend_name()
    key = (name, (path or GRAPH_DB).resolve())
    instance = _INSTANCES.get(key)
    if instance is None:
        instance = _INSTANCES[key] = Store(path, backend=name)
    return instance


def reset_store_cache() -> None:
    """Drop cached handles, so a rebuilt store is reopened rather than reused."""
    _INSTANCES.clear()


def iter_query_files(directory: Path) -> Iterator[tuple[str, str]]:
    """Yield (name, sparql) for each .rq file, for the canonical query library."""
    for file in sorted(directory.glob("*.rq")):
        yield file.stem, file.read_text(encoding="utf-8")
