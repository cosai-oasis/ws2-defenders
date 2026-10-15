"""Ingest the CoSAI TSC citation-impact dataset.

Source: cosai-oasis/cosai-tsc, `TSC Deliverables/citation-impact/sources.json`, refreshed
weekly by a GitHub Action. It is authoritative and hand-verified, so it is ingested
rather than re-derived; bubo_graphrag.citation.discover only looks for citations the
dataset has not yet recorded.

Each row becomes one cosaic:CitationEvent per cited work, carrying the category
(formal reference vs substantive use vs organizational mention) and the verification
level (directly inspected vs search-index excerpt). Those distinctions are the point:
collapsing 146 relationships into a single number would overstate what is known.

Run:  python -m bubo_graphrag.ingest.citations
"""

from __future__ import annotations

import argparse
import json
import subprocess
import urllib.parse
from collections import Counter
from pathlib import Path

from rdflib import Graph, Literal, Namespace, RDF, RDFS, URIRef, XSD

from ..paths import DATA, ONTOLOGY, load_registry
from ..resolve.identity import slugify
from .fetch import find_gh

COSAIC = Namespace("https://cosai-oasis.github.io/ontology/cosai-contrib#")

SOURCE_REPO = "cosai-oasis/cosai-tsc"
SOURCE_PATH = "TSC Deliverables/citation-impact/sources.json"
VENDORED = DATA / "vendor" / "cosai-citation-sources.json"
CITATIONS_TTL = ONTOLOGY / "citations.ttl"


def fetch_dataset(force: bool = False) -> Path:
    """Cache the upstream dataset."""
    if VENDORED.exists() and not force:
        return VENDORED
    gh = find_gh()
    quoted = urllib.parse.quote(SOURCE_PATH)
    result = subprocess.run(
        [gh, "api", f"repos/{SOURCE_REPO}/contents/{quoted}",
         "-H", "Accept: application/vnd.github.raw"],
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"could not fetch {SOURCE_PATH}: "
            f"{result.stderr.decode('utf-8', 'replace')[:300]}")
    VENDORED.parent.mkdir(parents=True, exist_ok=True)
    VENDORED.write_bytes(result.stdout)
    return VENDORED


def build(rows: list[dict]) -> tuple[Graph, list[str], Counter]:
    """Convert dataset rows to citation events. Returns (graph, problems, stats)."""
    aliases = load_registry("work-aliases")
    mapped = {title: row["publication"] for title, row in aliases["works"].items()}
    stubs = aliases.get("stubs") or {}
    known_categories = set(aliases.get("categories") or {})
    known_verification = set(aliases.get("verification_levels") or {})

    g = Graph()
    g.bind("cosaic", COSAIC)
    problems: list[str] = []
    stats: Counter = Counter()

    # Stub works, so counts reconcile with the TSC report even for documents this
    # server does not hold.
    for title, row in stubs.items():
        node = COSAIC[f"pub-{row['id']}"]
        g.add((node, RDF.type, COSAIC.CoSAIWorkStub))
        g.add((node, RDFS.label, Literal(row.get("title") or title)))
        if row.get("title") and row["title"] != title:
            # The citation dataset's short form, kept so the title join stays traceable.
            g.add((node, RDFS.comment, Literal(f"Cited in the dataset as {title!r}.")))
        if ws := row.get("workstream"):
            g.add((node, COSAIC.producedBy, COSAIC[f"ws-{ws}"]))
        for key in ("announcement_url", "document_url"):
            if url := row.get(key):
                g.add((node, COSAIC.sourceUrl, Literal(url, datatype=XSD.anyURI)))
        if published := row.get("published"):
            date = str(published)
            instant = COSAIC[f"instant-{date}"]
            g.add((instant, RDF.type, COSAIC.Instant))
            g.add((instant, COSAIC.date, Literal(date, datatype=XSD.date)))
            event = COSAIC[f"pubevent-{row['id']}"]
            g.add((event, RDF.type, COSAIC.PublicationEvent))
            g.add((event, RDFS.label, Literal(f"publication of {row.get('title', title)}")))
            g.add((event, COSAIC.hasParticipantWork, node))
            g.add((event, URIRef("http://purl.obolibrary.org/obo/BFO_0000199"), instant))

        # Corporate authorship: a credited role borne by an organization rather than a
        # person. Without this the work reads as uncredited, which it is not.
        if org_name := row.get("authored_by_organization"):
            org = COSAIC[f"org-{slugify(org_name)}"]
            g.add((org, RDF.type, COSAIC.Organization))
            g.add((org, RDFS.label, Literal(org_name)))
            credit = COSAIC[f"credit-{row['id']}-org"]
            g.add((credit, RDF.type, COSAIC.OrganizationalAuthorRole))
            g.add((credit, RDFS.label,
                   Literal(f"{org_name} as author of {row.get('title', title)}")))
            g.add((credit, URIRef("http://purl.obolibrary.org/obo/BFO_0000197"), org))
            g.add((credit, COSAIC.onPublication, node))
            g.add((credit, COSAIC.sourceLabel, Literal("organizational attribution")))
        if note := row.get("note"):
            g.add((node, COSAIC.reviewNote, Literal(note.strip())))

    publishers: dict[str, URIRef] = {}

    for row in rows:
        row_id = row.get("id", "?")
        citing = COSAIC[f"extpub-{slugify(row_id + '-' + row.get('publisher', ''))}"]
        g.add((citing, RDF.type, COSAIC.ExternalPublication))
        g.add((citing, RDFS.label, Literal(row.get("citing_publication", row_id))))
        if url := row.get("source_url"):
            g.add((citing, COSAIC.sourceUrl, Literal(url, datatype=XSD.anyURI)))

        if publisher := row.get("publisher"):
            node = publishers.get(publisher)
            if node is None:
                node = COSAIC[f"publisher-{slugify(publisher)}"]
                publishers[publisher] = node
                g.add((node, RDF.type, COSAIC.Organization))
                g.add((node, RDFS.label, Literal(publisher)))
            g.add((citing, COSAIC.publishedBy, node))

        category = row.get("category", "")
        verification = row.get("verification", "")
        if category and category not in known_categories:
            problems.append(f"{row_id}: unknown category {category!r}")
        if verification and verification not in known_verification:
            problems.append(f"{row_id}: unknown verification {verification!r}")

        works = row.get("cosai_works") or []
        if not works:
            # Organizational mentions cite no specific work; recorded on the citing
            # publication so the 8 of them are not silently lost.
            stats["organizational-mention"] += 1
            g.add((citing, COSAIC.citationCategory, Literal(category)))
            continue

        for work_title in works:
            if work_title in mapped:
                target = COSAIC[f"pub-{mapped[work_title]}"]
                stats["in-scope"] += 1
            elif work_title in stubs:
                target = COSAIC[f"pub-{stubs[work_title]['id']}"]
                stats["stub"] += 1
            else:
                problems.append(
                    f"{row_id}: work title {work_title!r} is in neither works nor "
                    "stubs in work-aliases.yaml")
                continue

            event = COSAIC[f"cite-{slugify(row_id)}-{slugify(work_title)[:40]}"]
            g.add((event, RDF.type, COSAIC.CitationEvent))
            g.add((event, RDFS.label,
                   Literal(f"{row.get('publisher', '?')} cites {work_title}")))
            g.add((event, COSAIC.citingPublication, citing))
            g.add((event, COSAIC.citedWork, target))
            if category:
                g.add((event, COSAIC.citationCategory, Literal(category)))
            if verification:
                g.add((event, COSAIC.verification, Literal(verification)))
            if rel := row.get("publisher_relationship"):
                g.add((event, COSAIC.publisherRelationship, Literal(rel)))
            if signal := row.get("evidence_signal"):
                g.add((event, COSAIC.evidenceSignal, Literal(signal)))
            stats[f"category:{category}"] += 1
            stats[f"verification:{verification}"] += 1

    return g, problems, stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true",
                        help="re-fetch the dataset from cosai-tsc")
    args = parser.parse_args(argv)

    path = fetch_dataset(force=args.refresh)
    rows = json.loads(path.read_text(encoding="utf-8"))
    graph, problems, stats = build(rows)

    for problem in problems:
        print(f"  {problem}")
    if problems:
        print(f"\n{len(problems)} problem(s). work-aliases.yaml needs updating.")
        return 1

    CITATIONS_TTL.write_text(
        "# GENERATED by `python -m bubo_graphrag.ingest.citations` -- do not hand-edit.\n"
        f"# Source: {SOURCE_REPO} :: {SOURCE_PATH}\n\n"
        + graph.serialize(format="turtle"),
        encoding="utf-8")

    print(f"{len(rows)} citing publications -> {len(graph)} triples")
    print(f"  in-scope works {stats['in-scope']}, stub works {stats['stub']}, "
          f"organizational mentions {stats['organizational-mention']}")
    for key in sorted(k for k in stats if k.startswith(("category:", "verification:"))):
        print(f"  {key:48} {stats[key]}")
    print(f"-> {CITATIONS_TTL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
