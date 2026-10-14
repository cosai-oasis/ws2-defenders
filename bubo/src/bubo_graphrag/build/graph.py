"""Emit the contribution graph from the reviewed registries.

Reads registry/*.yaml plus the cached documents, and writes ontology/catalog.ttl and
data/graph.db. The registries are the source of truth: this step is deterministic and
adds no judgment of its own beyond the temporal inference in bubo_graphrag.temporal,
which is explicitly marked as inferred in the output.

Run:  python -m bubo_graphrag.build.graph
"""

from __future__ import annotations

import argparse
import datetime as dt
import re

from rdflib import Graph, Literal, Namespace, RDF, RDFS, URIRef, XSD

from ..ingest.seed import collect
from ..paths import (CATALOG_TTL, GRAPH_DB, committees, governing_bodies, publications,
                     workstreams)
from ..resolve.identity import Person, slugify
from ..temporal import INDEPENDENT, Timeline, build_timeline

COSAIC = Namespace("https://cosai-oasis.github.io/ontology/cosai-contrib#")
CCO = Namespace("https://www.commoncoreontologies.org/")
OBO = Namespace("http://purl.obolibrary.org/obo/")

# BFO 2020 relations, verified against bfo-core.ttl in the CCO v2.2 release.
OCCUPIES_TEMPORAL_REGION = OBO.BFO_0000199
HAS_PARTICIPANT = OBO.BFO_0000057
INHERES_IN = OBO.BFO_0000197
IS_CARRIER_OF = OBO.BFO_0000101

# CCO relations.
DESIGNATES = CCO.ont00001916
IS_AFFILIATED_WITH = CCO.ont00001939
HAS_OUTPUT = CCO.ont00001986

ROLE_CLASSES = {
    "WorkstreamLeadRole": COSAIC.WorkstreamLeadRole,
    "EditorRole": COSAIC.EditorRole,
    "ContributorRole": COSAIC.ContributorRole,
    "ReviewerRole": COSAIC.ReviewerRole,
    "TSCCoChairRole": COSAIC.TSCCoChairRole,
    "TSCReviewerRole": COSAIC.TSCReviewerRole,
    "AuthorRole": COSAIC.AuthorRole,
}


def _address_slug(address: str) -> str:
    return slugify(address.replace("@", "-at-"))


class GraphBuilder:
    def __init__(self) -> None:
        self.g = Graph()
        self.g.bind("cosaic", COSAIC)
        self.g.bind("cco", CCO)
        self.g.bind("obo", OBO)
        self._instants: set[dt.date] = set()

    # --- helpers ---------------------------------------------------------------

    def instant(self, date: dt.date) -> URIRef:
        """Mint (once) a zero-dimensional temporal region for a calendar date."""
        node = COSAIC[f"instant-{date.isoformat()}"]
        if date not in self._instants:
            self._instants.add(date)
            self.g.add((node, RDF.type, COSAIC.Instant))
            self.g.add((node, COSAIC.date, Literal(date, datatype=XSD.date)))
            self.g.add((node, RDFS.label, Literal(date.isoformat())))
        return node

    def lit(self, value: str) -> Literal:
        return Literal(value)

    # --- workstreams and publications -----------------------------------------

    def add_workstreams(self) -> dict[str, URIRef]:
        out = {}
        for key, row in workstreams().items():
            node = COSAIC[f"ws-{key}"]
            out[key] = node
            self.g.add((node, RDF.type, COSAIC.Workstream))
            self.g.add((node, RDFS.label, self.lit(row["title"])))
            self.g.add((node, COSAIC.repo, self.lit(row["repo"])))
        return out

    def add_governing_bodies(self) -> None:
        """The TSC and PGB. Declared here, alongside the workstreams, so the meetings
        graph only references them and no triple is asserted in two graphs."""
        for key, row in governing_bodies().items():
            node = COSAIC[f"gov-{key}"]
            self.g.add((node, RDF.type, COSAIC.GoverningBody))
            self.g.add((node, RDFS.label, self.lit(row["title"])))
            if repo := row.get("repo"):
                self.g.add((node, COSAIC.repo, self.lit(repo)))

    def add_committees(self) -> None:
        """The Marketing Committee, declared here for the same reason as the
        governing bodies: the maillist graph only references it."""
        for key, row in committees().items():
            node = COSAIC[f"com-{key}"]
            self.g.add((node, RDF.type, COSAIC.Committee))
            self.g.add((node, RDFS.label, self.lit(row["title"])))

    def add_publications(self, ws_nodes: dict[str, URIRef]) -> dict[str, URIRef]:
        out = {}
        for pub in publications():
            node = COSAIC[f"pub-{pub['id']}"]
            out[pub["id"]] = node
            self.g.add((node, RDF.type, COSAIC.Publication))
            self.g.add((node, RDFS.label, self.lit(pub["title"])))
            self.g.add((node, COSAIC.approvalStatus, self.lit(pub["approval_status"])))
            if ws := ws_nodes.get(pub["workstream"]):
                self.g.add((node, COSAIC.producedBy, ws))
            if version := pub.get("version"):
                self.g.add((node, COSAIC.version, self.lit(str(version))))

            original = _as_date(pub.get("original_date"))
            revised = _as_date(pub.get("revised_date"))

            # The publication event: a work is the output of a datable act, not a
            # standing record.
            md_node = COSAIC[f"man-{pub['id']}-md"]
            if original:
                event = COSAIC[f"pubevent-{pub['id']}"]
                self.g.add((event, RDF.type, COSAIC.PublicationEvent))
                self.g.add((event, RDFS.label,
                            self.lit(f"publication of {pub['title']}")))
                self.g.add((event, HAS_PARTICIPANT, node))
                self.g.add((event, OCCUPIES_TEMPORAL_REGION, self.instant(original)))
                self.g.add((event, HAS_OUTPUT, md_node))

            # A revision is a separate occurrent. Whether credits traveled with it is
            # recorded, because that determines what date the credits are evidence about.
            if revised:
                rev = COSAIC[f"revevent-{pub['id']}"]
                self.g.add((rev, RDF.type, COSAIC.RevisionEvent))
                self.g.add((rev, RDFS.label,
                            self.lit(f"revision of {pub['title']} to v{pub.get('version', '?')}")))
                self.g.add((rev, HAS_PARTICIPANT, node))
                self.g.add((rev, OCCUPIES_TEMPORAL_REGION, self.instant(revised)))
                refreshed = bool(pub.get("credits_refreshed_at_revision"))
                self.g.add((rev, COSAIC.creditsRefreshed,
                            Literal(refreshed, datatype=XSD.boolean)))
                if not refreshed:
                    self.g.add((rev, COSAIC.reviewNote, self.lit(
                        "Credit list not refreshed at this revision; credits are "
                        f"evidence about {original}.")))

            # Manifestations: the markdown at a pinned sha, and the derived PDF.
            self.g.add((md_node, RDF.type, COSAIC.Manifestation))
            self.g.add((md_node, RDFS.label, self.lit(pub["md_path"])))
            self.g.add((md_node, COSAIC.mediaType, self.lit("text/markdown")))
            self.g.add((md_node, COSAIC.repo, self.lit(pub["repo"])))
            self.g.add((md_node, COSAIC.path, self.lit(pub["md_path"])))
            self.g.add((md_node, COSAIC.commitSha, self.lit(pub["commit_sha"])))
            self.g.add((md_node, IS_CARRIER_OF, node))
            self.g.add((node, COSAIC.manifestedAs, md_node))

            if pdf_path := pub.get("pdf_path"):
                pdf_node = COSAIC[f"man-{pub['id']}-pdf"]
                self.g.add((pdf_node, RDF.type, COSAIC.Manifestation))
                self.g.add((pdf_node, RDFS.label, self.lit(pdf_path)))
                self.g.add((pdf_node, COSAIC.mediaType, self.lit("application/pdf")))
                self.g.add((pdf_node, COSAIC.repo, self.lit(pub["repo"])))
                self.g.add((pdf_node, COSAIC.path, self.lit(pdf_path)))
                self.g.add((pdf_node, IS_CARRIER_OF, node))
                self.g.add((pdf_node, COSAIC.derivedFrom, md_node))
                self.g.add((node, COSAIC.manifestedAs, pdf_node))
        return out

    # --- organizations --------------------------------------------------------

    def add_organizations(self, org_registry) -> dict[str, URIRef]:
        out: dict[str, URIRef] = {}
        if org_registry is None:
            return out
        for org in org_registry.organizations.values():
            node = COSAIC[f"org-{org.id}"]
            out[org.canonical_name] = node
            self.g.add((node, RDF.type, COSAIC.Organization))
            self.g.add((node, RDFS.label, self.lit(org.canonical_name)))
            for variant in org.variants:
                if variant != org.canonical_name:
                    self.g.add((node, COSAIC.statedOrganization, self.lit(variant)))
            for domain in org.email_domains:
                self.g.add((node, COSAIC.emailDomain, self.lit(domain)))
            for row in org.merge_provenance:
                self.g.add((node, COSAIC.mergeBasis, self.lit(
                    f"{row.get('variant')}: {row.get('basis')} "
                    f"({row.get('date')}) {row.get('note', '')}".strip())))
            # Variants resolve to the same node, so a lookup by any spelling works.
            for variant in org.variants:
                out.setdefault(variant, node)
        return out

    # --- people, designators, credits, affiliations ----------------------------

    def add_person(self, person: Person, org_nodes: dict[str, URIRef],
                   pub_nodes: dict[str, URIRef]) -> URIRef:
        node = COSAIC[f"person-{person.id}"]
        self.g.add((node, RDF.type, COSAIC.Person))
        self.g.add((node, RDFS.label, self.lit(person.display_name)))
        for login in sorted(person.github_logins):
            self.g.add((node, COSAIC.githubLogin, self.lit(login)))

        # Names as designators, so an abbreviated and a proper form can designate one
        # person without a bespoke alias field.
        for text, kind in sorted(person.names.items()):
            name_node = COSAIC[f"name-{slugify(text)}"]
            cls = COSAIC.AbbreviatedName if kind == "abbreviated" else COSAIC.ProperName
            self.g.add((name_node, RDF.type, cls))
            self.g.add((name_node, COSAIC.nameValue, self.lit(text)))
            self.g.add((name_node, RDFS.label, self.lit(text)))
            self.g.add((name_node, DESIGNATES, node))

        # Addresses as designators, each with the document and date asserting it.
        emitted: set[str] = set()
        for assertion in person.emails:
            addr_node = COSAIC[f"email-{_address_slug(assertion.address)}"]
            if assertion.address not in emitted:
                emitted.add(assertion.address)
                self.g.add((addr_node, RDF.type, COSAIC.EmailAddress))
                self.g.add((addr_node, COSAIC.addressValue, self.lit(assertion.address)))
                self.g.add((addr_node, RDFS.label, self.lit(assertion.address)))
                self.g.add((addr_node, DESIGNATES, node))
                if assertion.implies_organization:
                    if org := org_nodes.get(assertion.implies_organization):
                        self.g.add((addr_node, COSAIC.impliesOrganization, org))
            if pub := pub_nodes.get(assertion.publication_id):
                self.g.add((addr_node, COSAIC.assertedIn, pub))
            if isinstance(assertion.assertion_date, dt.date):
                self.g.add((addr_node, COSAIC.assertedAt,
                            self.instant(assertion.assertion_date)))
        return node

    def add_credit(self, index: int, credit, person_node: URIRef | None,
                   pub_nodes: dict[str, URIRef], role_class: str,
                   assertion_date: dt.date | None) -> None:
        node = COSAIC[f"credit-{credit.publication_id}-{index:03d}"]
        self.g.add((node, RDF.type, ROLE_CLASSES.get(role_class, COSAIC.CreditedRole)))
        self.g.add((node, COSAIC.sourceLabel, self.lit(credit.source_label)))
        self.g.add((node, RDFS.label, self.lit(
            f"{credit.name or '@' + (credit.github_login or '?')} "
            f"as {credit.source_label} on {credit.publication_id}")))
        if person_node is not None:
            self.g.add((node, INHERES_IN, person_node))
        if pub := pub_nodes.get(credit.publication_id):
            self.g.add((node, COSAIC.onPublication, pub))
            self.g.add((node, COSAIC.assertedIn, pub))
        if assertion_date:
            self.g.add((node, COSAIC.assertedAt, self.instant(assertion_date)))
        if credit.organization:
            self.g.add((node, COSAIC.statedOrganization, self.lit(credit.organization)))
        if credit.equal_contribution:
            self.g.add((node, COSAIC.equalContribution,
                        Literal(True, datatype=XSD.boolean)))
        if credit.scope_note:
            self.g.add((node, COSAIC.scopeNote, self.lit(credit.scope_note)))
        if credit.github_login:
            self.g.add((node, COSAIC.githubLogin, self.lit(credit.github_login)))

    def add_timeline(self, person: Person, person_node: URIRef,
                     timeline: Timeline, org_nodes: dict[str, URIRef],
                     pub_nodes: dict[str, URIRef]) -> None:
        """Affiliation spans as roles over open-bounded intervals, plus inferred changes."""
        for i, span in enumerate(timeline.spans):
            role = COSAIC[f"affil-{person.id}-{i:02d}"]
            interval = COSAIC[f"interval-{person.id}-{i:02d}"]
            self.g.add((role, RDF.type, COSAIC.AffiliationRole))
            self.g.add((role, INHERES_IN, person_node))
            label = "independent" if span.is_independent else span.state
            self.g.add((role, RDFS.label,
                        self.lit(f"{person.display_name} — {label}")))
            if not span.is_independent and (org := org_nodes.get(span.state)):
                self.g.add((role, COSAIC.withOrganization, org))
                self.g.add((person_node, IS_AFFILIATED_WITH, org))
            else:
                self.g.add((role, COSAIC.creditedWithoutEmployer,
                            Literal(True, datatype=XSD.boolean)))

            self.g.add((role, OCCUPIES_TEMPORAL_REGION, interval))
            self.g.add((interval, RDF.type, COSAIC.EvidenceInterval))
            self.g.add((interval, COSAIC.earliestEvidence,
                        Literal(span.earliest_evidence, datatype=XSD.date)))
            self.g.add((interval, COSAIC.latestEvidence,
                        Literal(span.latest_evidence, datatype=XSD.date)))
            # The flag that matters most: an evidence date is not a start or end date.
            self.g.add((interval, COSAIC.boundsKnown,
                        Literal(False, datatype=XSD.boolean)))
            for pub_id in span.publication_ids:
                if pub := pub_nodes.get(pub_id):
                    self.g.add((interval, COSAIC.evidencedBy, pub))

        for i, change in enumerate(timeline.changes):
            window = COSAIC[f"window-{person.id}-{i:02d}"]
            self.g.add((window, RDF.type, COSAIC.UncertaintyWindow))
            self.g.add((window, COSAIC.notBefore,
                        Literal(change.not_before, datatype=XSD.date)))
            self.g.add((window, COSAIC.notAfter,
                        Literal(change.not_after, datatype=XSD.date)))

            if change.from_state != INDEPENDENT:
                loss = COSAIC[f"affloss-{person.id}-{i:02d}"]
                self.g.add((loss, RDF.type, COSAIC.AffiliationLoss))
                self.g.add((loss, HAS_PARTICIPANT, person_node))
                self.g.add((loss, OCCUPIES_TEMPORAL_REGION, window))
                self.g.add((loss, COSAIC.inferred, Literal(True, datatype=XSD.boolean)))
                self.g.add((loss, RDFS.label, self.lit(
                    f"{person.display_name} left {change.from_state} "
                    f"(after {change.not_before}, by {change.not_after})")))
                if org := org_nodes.get(change.from_state):
                    self.g.add((loss, COSAIC.withOrganization, org))

            if change.to_state != INDEPENDENT:
                gain = COSAIC[f"affgain-{person.id}-{i:02d}"]
                self.g.add((gain, RDF.type, COSAIC.AffiliationGain))
                self.g.add((gain, HAS_PARTICIPANT, person_node))
                self.g.add((gain, OCCUPIES_TEMPORAL_REGION, window))
                self.g.add((gain, COSAIC.inferred, Literal(True, datatype=XSD.boolean)))
                self.g.add((gain, RDFS.label, self.lit(
                    f"{person.display_name} joined {change.to_state} "
                    f"(after {change.not_before}, by {change.not_after})")))
                if org := org_nodes.get(change.to_state):
                    self.g.add((gain, COSAIC.withOrganization, org))


def _as_date(value) -> dt.date | None:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        return dt.date.fromisoformat(value)
    return None


def build() -> Graph:
    from ..ingest.seed import assertion_date
    from ..paths import load_registry
    from ..resolve.organizations import OrgRegistry

    role_map = {label: row["class"]
                for label, row in load_registry("role-vocabulary")["roles"].items()}
    org_registry = OrgRegistry()

    resolver, all_credits, _, _ = collect()

    builder = GraphBuilder()
    ws_nodes = builder.add_workstreams()
    builder.add_governing_bodies()
    builder.add_committees()
    pub_nodes = builder.add_publications(ws_nodes)
    org_nodes = builder.add_organizations(org_registry)

    # Declared author fields, retained even where they disagree with the repository.
    from ..ingest import frontmatter as FM
    from ..paths import raw_path
    for pub in publications():
        declared = FM.parse(raw_path(pub).read_text(encoding="utf-8"))
        if declared.author:
            builder.g.add((pub_nodes[pub["id"]], COSAIC.declaredAuthorField,
                           Literal(declared.author)))

    person_nodes: dict[str, URIRef] = {}
    for person in resolver.people.values():
        person_nodes[person.id] = builder.add_person(person, org_nodes, pub_nodes)
        builder.add_timeline(person, person_nodes[person.id],
                            build_timeline(person), org_nodes, pub_nodes)

    # Credits, re-resolved to the person each belongs to.
    lookup = Resolved(resolver)
    dates = {pub["id"]: assertion_date(pub) for pub in publications()}
    counters: dict[str, int] = {}
    for credit in all_credits:
        index = counters[credit.publication_id] = counters.get(credit.publication_id, 0) + 1
        pid = lookup.person_id(credit)
        builder.add_credit(
            index, credit, person_nodes.get(pid) if pid else None, pub_nodes,
            role_map.get(credit.source_label, "CreditedRole"),
            dates.get(credit.publication_id))

    return builder.g


class Resolved:
    """Map a credit back to the person it was folded into."""

    def __init__(self, resolver) -> None:
        self._by_address: dict[str, str] = {}
        self._by_name: dict[str, str] = {}
        self._by_login: dict[str, str] = {}
        for person in resolver.people.values():
            for address in person.addresses:
                self._by_address.setdefault(address, person.id)
            for name in person.names:
                self._by_name.setdefault(name, person.id)
            for login in person.github_logins:
                self._by_login.setdefault(login, person.id)

    def person_id(self, credit) -> str | None:
        from ..resolve.identity import clean_email
        for address in credit.emails:
            if pid := self._by_address.get(clean_email(address)):
                return pid
        if credit.name and (pid := self._by_name.get(credit.name)):
            return pid
        if credit.github_login:
            return self._by_login.get(credit.github_login)
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-store", action="store_true",
                        help="write catalog.ttl only, skip loading the store")
    args = parser.parse_args(argv)

    graph = build()
    CATALOG_TTL.parent.mkdir(parents=True, exist_ok=True)
    CATALOG_TTL.write_text(
        "# GENERATED by `python -m bubo_graphrag.build.graph` -- do not hand-edit.\n"
        "# Derived deterministically from registry/*.yaml and the pinned documents.\n\n"
        + graph.serialize(format="turtle"),
        encoding="utf-8")
    print(f"{len(graph)} triples -> {CATALOG_TTL}")

    if not args.no_store:
        from ..store import load_store
        count = load_store()
        print(f"loaded {count} triples -> {GRAPH_DB}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
