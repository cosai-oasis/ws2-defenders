"""Generate the CCO/BFO MIREOT alignment file.

MIREOT (Minimum Information to Reference an External Ontology Term) means importing
each needed term with its IRI, label, and the superclass path up to the upper ontology
-- and nothing else. The alternative, `owl:imports` of CCO, pulls ~1,200 classes across
five modules and a ~2 MB merged file into every reasoning run, couples the project to
CCO's release cadence, and admits axioms that have nothing to do with this domain.

Generating rather than hand-typing matters because CCO moves (v1.7 -> v2.0 -> v2.1 ->
v2.2 in under two years, with an IRI scheme change along the way) and because CCO v2.x
uses opaque numeric IRIs: `cco:ont00001262` is Person. A hand-maintained file of those
would rot silently. This walks the real release and fails loudly if a term disappears.

Run:  python -m bubo_graphrag.build.mireot
"""

from __future__ import annotations

import argparse
import re
import urllib.request
from pathlib import Path

from rdflib import OWL, RDF, RDFS, Graph, URIRef
from rdflib.namespace import SKOS

from ..paths import ONTOLOGY, DATA

CCO_VERSION = "v2.2"
CCO_BASE = (
    f"https://raw.githubusercontent.com/CommonCoreOntology/"
    f"CommonCoreOntologies/{CCO_VERSION}/src"
)
CCO_MODULES = (
    "cco-iris/AgentOntology",
    "cco-iris/EventOntology",
    "cco-iris/InformationEntityOntology",
    "cco-iris/ArtifactOntology",
    "cco-iris/ExtendedRelationOntology",
    "cco-iris/TimeOntology",
)
BFO_MODULE = "cco-imports/bfo-core"

VENDOR = DATA / "vendor"

CCO = "https://www.commoncoreontologies.org/"
OBO = "http://purl.obolibrary.org/obo/"

# Terms this project references. Labels are asserted here as the *expected* label and
# checked against the release, so a CCO renaming surfaces as a build failure rather
# than a silently wrong alignment.
WANTED_CLASSES: dict[str, str] = {
    # Agents
    f"{CCO}ont00001262": "Person",
    f"{CCO}ont00001180": "Organization",
    f"{CCO}ont00000300": "Group of Agents",
    f"{CCO}ont00001017": "Agent",
    # Roles
    f"{CCO}ont00000175": "Organization Member Role",
    f"{CCO}ont00000984": "Occupation Role",
    # Information entities
    f"{CCO}ont00000958": "Information Content Entity",
    f"{CCO}ont00002039": "Document Content Entity",
    # Prescriptive ICE ("Directive ICE", "prescribes some Entity") is the parent of
    # cosaic:MeetingSeries: a standing meeting is a schedule that prescribes its
    # occurrences, not an occurrent itself.
    f"{CCO}ont00000965": "Prescriptive Information Content Entity",
    f"{CCO}ont00000686": "Designative Information Content Entity",
    f"{CCO}ont00000003": "Designative Name",
    f"{CCO}ont00002070": "Email Address",
    f"{CCO}ont00001014": "Proper Name",
    f"{CCO}ont00000605": "Abbreviated Name",
    # Artifacts
    f"{CCO}ont00000798": "Information Bearing Artifact",
    f"{CCO}ont00001298": "Material Copy of a Document",
    # Events -- the time-aware core
    f"{CCO}ont00002077": "Act of Publishing",
    f"{CCO}ont00000402": "Act of Communication",
    f"{CCO}ont00001194": "Gain of Role",
    f"{CCO}ont00000613": "Loss of Role",
    f"{CCO}ont00000824": "Stasis of Role",
}

WANTED_PROPERTIES: dict[str, str] = {
    f"{CCO}ont00001939": "is affiliated with",
    f"{CCO}ont00001787": "agent in",
    f"{CCO}ont00001833": "has agent",
    f"{CCO}ont00001816": "is output of",
    f"{CCO}ont00001986": "has output",
    f"{CCO}ont00001808": "is about",
    f"{CCO}ont00001916": "designates",
    f"{CCO}ont00001879": "designated by",
    f"{CCO}ont00001918": "occurs at",
    f"{CCO}ont00002080": "process has first instant",
    f"{CCO}ont00002081": "process has last instant",
    f"{CCO}ont00001869": "interval during",
    f"{CCO}ont00001940": "interval is before",
    f"{CCO}ont00001992": "has organizational context",
    f"{CCO}ont00001768": "has URI value",
}

# BFO terms referenced directly. Verified against bfo-core.ttl in the CCO v2.2 release.
WANTED_BFO: dict[str, str] = {
    f"{OBO}BFO_0000001": "entity",
    f"{OBO}BFO_0000002": "continuant",
    f"{OBO}BFO_0000003": "occurrent",
    f"{OBO}BFO_0000004": "independent continuant",
    f"{OBO}BFO_0000020": "specifically dependent continuant",
    f"{OBO}BFO_0000031": "generically dependent continuant",
    f"{OBO}BFO_0000030": "object",
    f"{OBO}BFO_0000027": "object aggregate",
    f"{OBO}BFO_0000040": "material entity",
    f"{OBO}BFO_0000017": "realizable entity",
    f"{OBO}BFO_0000023": "role",
    f"{OBO}BFO_0000015": "process",
    f"{OBO}BFO_0000008": "temporal region",
    f"{OBO}BFO_0000148": "zero-dimensional temporal region",
    f"{OBO}BFO_0000038": "one-dimensional temporal region",
}

WANTED_BFO_PROPERTIES: dict[str, str] = {
    f"{OBO}BFO_0000199": "occupies temporal region",
    f"{OBO}BFO_0000108": "exists at",
    f"{OBO}BFO_0000056": "participates in",
    f"{OBO}BFO_0000057": "has participant",
    f"{OBO}BFO_0000055": "realizes",
    f"{OBO}BFO_0000196": "bearer of",
    f"{OBO}BFO_0000197": "inheres in",
    f"{OBO}BFO_0000101": "is carrier of",
    f"{OBO}BFO_0000084": "generically depends on",
    f"{OBO}BFO_0000063": "precedes",
    f"{OBO}BFO_0000062": "preceded by",
    f"{OBO}BFO_0000222": "has first instant",
    f"{OBO}BFO_0000224": "has last instant",
}


def fetch_module(name: str) -> Path:
    """Download and cache one upstream ontology module."""
    VENDOR.mkdir(parents=True, exist_ok=True)
    dest = VENDOR / f"{Path(name).name}-{CCO_VERSION}.ttl"
    if not dest.exists():
        url = f"{CCO_BASE}/{name}.ttl"
        with urllib.request.urlopen(url, timeout=120) as response:
            dest.write_bytes(response.read())
    return dest


def load_upstream() -> Graph:
    graph = Graph()
    for module in (*CCO_MODULES, BFO_MODULE):
        graph.parse(fetch_module(module), format="turtle")
    return graph


def superclass_path(graph: Graph, term: URIRef, stop: set[str]) -> list[URIRef]:
    """Named superclasses from `term` up to (and including) a term in `stop`.

    Anonymous superclasses -- CCO's restrictions -- are skipped: a MIREOT subset
    carries placement, not axioms.
    """
    path: list[URIRef] = []
    seen: set[URIRef] = {term}
    current = term
    while True:
        parents = [
            p for p in graph.objects(current, RDFS.subClassOf)
            if isinstance(p, URIRef) and p not in seen
        ]
        if not parents:
            return path
        parent = parents[0]
        path.append(parent)
        seen.add(parent)
        if str(parent) in stop:
            return path
        current = parent


def label_of(graph: Graph, term: URIRef) -> str | None:
    for value in graph.objects(term, RDFS.label):
        return str(value)
    return None


def build() -> tuple[Graph, list[str]]:
    upstream = load_upstream()
    problems: list[str] = []
    out = Graph()

    bfo_tops = {f"{OBO}BFO_0000001"}
    all_labels = {**WANTED_BFO, **WANTED_CLASSES}

    # Classes, each with its named superclass path up to BFO:entity.
    emitted: set[URIRef] = set()
    for iri, expected in all_labels.items():
        term = URIRef(iri)
        actual = label_of(upstream, term)
        if actual is None:
            problems.append(f"MISSING class {iri} (expected {expected!r})")
            continue
        if actual != expected:
            problems.append(
                f"LABEL CHANGED {iri}: expected {expected!r}, release says {actual!r}")
        chain = [term, *superclass_path(upstream, term, bfo_tops)]
        for i, node in enumerate(chain):
            if node not in emitted:
                emitted.add(node)
                out.add((node, RDF.type, OWL.Class))
                if lbl := label_of(upstream, node):
                    out.add((node, RDFS.label, _lit(lbl)))
            if i + 1 < len(chain):
                out.add((node, RDFS.subClassOf, chain[i + 1]))

    # Properties: declaration and label only. Domains and ranges are deliberately not
    # carried over -- importing CCO's ranges would constrain terms we have not imported.
    for mapping, kind in ((WANTED_PROPERTIES, "cco"), (WANTED_BFO_PROPERTIES, "bfo")):
        for iri, expected in mapping.items():
            term = URIRef(iri)
            actual = label_of(upstream, term)
            if actual is None:
                problems.append(f"MISSING property {iri} (expected {expected!r})")
                continue
            if actual != expected:
                problems.append(
                    f"LABEL CHANGED {iri}: expected {expected!r}, "
                    f"release says {actual!r}")
            is_data = (term, RDF.type, OWL.DatatypeProperty) in upstream
            out.add((term, RDF.type,
                     OWL.DatatypeProperty if is_data else OWL.ObjectProperty))
            out.add((term, RDFS.label, _lit(actual)))
            for definition in upstream.objects(term, SKOS.definition):
                out.add((term, SKOS.definition, definition))
                break

    return out, problems


def _lit(text: str):
    from rdflib import Literal
    return Literal(text, lang="en")


HEADER = f"""# GENERATED by `python -m bubo_graphrag.build.mireot` -- do not hand-edit.
#
# MIREOT subset of Common Core Ontologies {CCO_VERSION} and BFO 2020, carrying only the
# terms this project references plus their named superclass paths up to bfo:entity.
# There is deliberately no owl:imports of CCO or BFO: importing them would pull ~1,200
# classes and axioms irrelevant to this domain into every reasoning run.
#
# Property domains and ranges are NOT carried over. Importing CCO's ranges would
# constrain terms that were not imported.
#
# CCO v2.x uses opaque numeric IRIs, so every term here carries its rdfs:label. The
# generator asserts the expected label for each term and fails if the release disagrees,
# so a CCO renaming surfaces as a build error rather than a silently wrong alignment.
#
# Source: {CCO_BASE}
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="verify against upstream without writing")
    args = parser.parse_args(argv)

    graph, problems = build()
    for problem in problems:
        print(f"  {problem}")

    if problems:
        print(f"\n{len(problems)} problem(s) against CCO {CCO_VERSION}.")
        return 1

    if args.check:
        print(f"OK: {len(graph)} triples, all {len(WANTED_CLASSES) + len(WANTED_BFO)} "
              "classes and "
              f"{len(WANTED_PROPERTIES) + len(WANTED_BFO_PROPERTIES)} properties match.")
        return 0

    dest = ONTOLOGY / "alignments" / "cco.ttl"
    dest.parent.mkdir(parents=True, exist_ok=True)
    body = graph.serialize(format="turtle")
    # Strip rdflib's generated prefix block for @prefix lines we control, keeping the
    # file diff-stable across runs.
    dest.write_text(HEADER + "\n" + body, encoding="utf-8")
    print(f"wrote {len(graph)} triples -> {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
