#!/usr/bin/env python3
"""Merge the named graphs into one ontology file for inspection in an editor.

## Why a merged copy rather than opening ontology/ directly

Protege saves over the file it opened, and its OWLAPI round-trip is not
identity-preserving: axioms are reordered, prefixes rewritten, and anything it does not
model as OWL can be dropped silently. `ontology/cosai-contrib.ttl` is hand-written and
is the most valuable artifact in this repository. So the editor is pointed at a
disposable export instead, and `ontology/**` is opened read-only here.

Treat the result as a viewer. To edit the ontology in Protege, export from Protege to a
*new* file and diff it against `cosai-contrib.ttl` rather than saving in place.

## What the merge costs

The store keeps these facts in named graphs partitioned by provenance -- publications,
citations, maillist, website, calendar, ontology -- because the partitions carry
different weight: one is deterministic from pinned registries, one drifts weekly
upstream, and the others cover only the window their fetched sources cover. **OWL has no named graphs**, so the
merge flattens that. A fact's source is not recoverable from the export; query the
store, or call `graph_schema`, when provenance matters.

The SHACL shapes are excluded deliberately: they are constraints, and would render as
stray individuals in a class browser.

## Subgraph views

`--graphs publications,citations` exports only those partitions, to a file named for
the selection, so several views can be open side by side. The `ontology` partition is
always included and is not selectable: it is the TBox, and without it Protege shows
untyped individuals and an empty class tree. Contributors -- people, organizations,
credited roles -- live in `publications`, so "publications + contributors" is one graph.

For individuals and their relationships use the OntoGraf tab. OWLViz draws only the
class hierarchy, and needs Graphviz's `dot` on PATH.

Run:  python scripts/protege_export.py [--graphs publications,citations] [--open]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from rdflib import Graph, Literal, OWL, RDF, RDFS, URIRef

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bubo_graphrag.store import GRAPH_FILES, OPTIONAL_GRAPH_FILES  # noqa: E402

OUTPUT_DIR = ROOT / "data" / "protege"
ONTOLOGY_IRI = "https://cosai-oasis.github.io/ontology/cosai-kg"
SELECTABLE = ("publications", "citations", "maillist", "website", "calendar")
PROTEGE = Path.home() / "Protege-5.6.9" / "run.sh"

PROVENANCE_NOTE = (
    "Merged for inspection in an ontology editor, and NOT the source of truth -- "
    "ontology/ is. The store keeps these facts in named graphs partitioned by "
    "provenance (publications, citations, maillist, website, calendar, ontology); OWL has no named "
    "graphs, so that partitioning is flattened here and a fact's source is not "
    "recoverable from this file. Regenerate with scripts/protege_export.py. Saving "
    "over this file loses nothing; saving over ontology/*.ttl would."
)


def parse_graphs(value: str) -> tuple[str, ...]:
    names = tuple(dict.fromkeys(n.strip() for n in value.split(",") if n.strip()))
    unknown = [n for n in names if n not in SELECTABLE]
    if "ontology" in unknown:
        raise argparse.ArgumentTypeError(
            "ontology is always included; select from " + ", ".join(SELECTABLE))
    if unknown or not names:
        raise argparse.ArgumentTypeError(
            f"unknown graph(s) {', '.join(unknown) or '(none)'}; "
            f"select from {', '.join(SELECTABLE)}")
    return names


def output_for(graphs: tuple[str, ...]) -> tuple[Path, URIRef]:
    """All partitions keep the original filename; a subset is named for its members."""
    if set(graphs) == set(SELECTABLE):
        return OUTPUT_DIR / "cosai-kg.ttl", URIRef(ONTOLOGY_IRI)
    suffix = "-".join(g for g in SELECTABLE if g in graphs)
    return OUTPUT_DIR / f"cosai-kg-{suffix}.ttl", URIRef(f"{ONTOLOGY_IRI}/{suffix}")


def build(graphs: tuple[str, ...] = SELECTABLE,
          ontology_iri: URIRef = URIRef(ONTOLOGY_IRI),
          ) -> tuple[Graph, list[tuple[str, str, int]]]:
    """Merge the ontology partition plus the selected ones. Reads only; writes nothing."""
    wanted = {"ontology", *graphs}
    merged = Graph()
    summary: list[tuple[str, str, int]] = []
    for path, graph_iri in GRAPH_FILES:
        if "shapes" in str(path) or graph_iri.rsplit("/", 1)[1] not in wanted:
            continue
        if not path.exists():
            if path in OPTIONAL_GRAPH_FILES:
                summary.append((path.name, graph_iri.rsplit("/", 1)[1], -1))
                continue
            raise SystemExit(
                f"missing {path}. Run `python -m bubo_graphrag.build.graph` first.")
        before = len(merged)
        merged.parse(path, format="turtle")
        summary.append((path.name, graph_iri.rsplit("/", 1)[1], len(merged) - before))

    label = "CoSAI contribution knowledge graph"
    if set(graphs) != set(SELECTABLE):
        label += " (" + " + ".join(g for g in SELECTABLE if g in graphs) + ")"
    merged.add((ontology_iri, RDF.type, OWL.Ontology))
    merged.add((ontology_iri, RDFS.label, Literal(label, lang="en")))
    merged.add((ontology_iri, RDFS.comment, Literal(PROVENANCE_NOTE, lang="en")))
    return merged, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", type=parse_graphs, default=SELECTABLE,
                        metavar="NAMES",
                        help="comma-separated subset of " + ",".join(SELECTABLE)
                        + " (default: all); ontology is always included")
    parser.add_argument("--open", action="store_true",
                        help="launch Protege on the export once written")
    args = parser.parse_args(argv)

    output, ontology_iri = output_for(args.graphs)
    merged, summary = build(args.graphs, ontology_iri)
    output.parent.mkdir(parents=True, exist_ok=True)
    merged.serialize(destination=str(output), format="turtle")

    print(f"{len(merged)} triples -> {output}")
    for name, graph, count in summary:
        print(f"  {'absent':>6} {name:24} ({graph})" if count < 0
              else f"  {count:6} {name:24} ({graph})")
    print("\nProvenance is flattened in this file. Query the store when it matters.")

    if args.open:
        if not PROTEGE.exists():
            raise SystemExit(f"no Protege launcher at {PROTEGE}")
        print(f"\nlaunching {PROTEGE} on {output.name}")
        subprocess.Popen([str(PROTEGE), str(output)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
