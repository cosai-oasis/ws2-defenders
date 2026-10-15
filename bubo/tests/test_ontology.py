"""Ontology integrity and design-constraint tests.

The three constraints asserted here are the ones that keep the ontology cheap to reason
over and honest about what it claims: SKOS-only matching, no external imports, and a
MIREOT subset that still agrees with the upstream release.
"""

from __future__ import annotations

import pytest
from rdflib import OWL, RDF, RDFS, Graph, URIRef
from rdflib.namespace import SKOS

from bubo_graphrag.paths import ONTOLOGY

COSAIC = "https://cosai-oasis.github.io/ontology/cosai-contrib#"
CCO = "https://www.commoncoreontologies.org/"
OBO = "http://purl.obolibrary.org/obo/"

FILES = (
    ONTOLOGY / "cosai-contrib.ttl",
    ONTOLOGY / "alignments" / "cco.ttl",
    ONTOLOGY / "alignments" / "bridges.ttl",
)


@pytest.fixture(scope="module")
def graph():
    g = Graph()
    for path in FILES:
        g.parse(path, format="turtle")
    return g


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_each_file_parses(path):
    assert len(Graph().parse(path, format="turtle")) > 0


# --- design constraints ---------------------------------------------------------

@pytest.mark.parametrize("predicate,name", [
    (OWL.equivalentClass, "owl:equivalentClass"),
    (OWL.equivalentProperty, "owl:equivalentProperty"),
    (OWL.sameAs, "owl:sameAs"),
])
def test_no_equivalence_axioms(graph, predicate, name):
    """Matching is SKOS-only.

    Equivalence axioms are expensive under reasoning and would be false here: neither
    SPDX 3.1 nor PROV-O is BFO-grounded, so their classes do not carry the
    continuant/occurrent commitments these do.
    """
    offenders = list(graph.triples((None, predicate, None)))
    assert not offenders, f"{name} used: {offenders[:3]}"


def test_no_external_owl_imports(graph):
    """CCO, BFO, SPDX and D3FEND are referenced by IRI, never imported."""
    imports = [str(o) for o in graph.objects(None, OWL.imports)]
    external = [i for i in imports
                if any(k in i for k in
                       ("commoncoreontologies", "obolibrary", "spdx", "d3fend"))]
    assert not external, f"external imports found: {external}"


def test_bridges_use_skos_matching(graph):
    """The bridge file must actually assert something, via SKOS."""
    matches = list(graph.triples((None, SKOS.closeMatch, None)))
    matches += list(graph.triples((None, SKOS.relatedMatch, None)))
    assert len(matches) >= 10


# --- BFO placement --------------------------------------------------------------

@pytest.mark.parametrize("local,expected_ancestor", [
    ("Person", f"{OBO}BFO_0000030"),               # object
    ("Organization", f"{OBO}BFO_0000027"),         # object aggregate
    ("Workstream", f"{OBO}BFO_0000027"),
    ("GoverningBody", f"{OBO}BFO_0000027"),
    ("Committee", f"{OBO}BFO_0000027"),
    ("Publication", f"{OBO}BFO_0000031"),          # generically dependent continuant
    ("Manifestation", f"{OBO}BFO_0000040"),        # material entity
    ("EmailAddress", f"{OBO}BFO_0000031"),
    ("PersonName", f"{OBO}BFO_0000031"),
    ("CreditedRole", f"{OBO}BFO_0000023"),         # role
    ("AffiliationRole", f"{OBO}BFO_0000023"),
    ("PublicationEvent", f"{OBO}BFO_0000015"),     # process
    ("RevisionEvent", f"{OBO}BFO_0000015"),
    ("AffiliationGain", f"{OBO}BFO_0000015"),
    ("AffiliationLoss", f"{OBO}BFO_0000015"),
    ("CitationEvent", f"{OBO}BFO_0000015"),
    ("Instant", f"{OBO}BFO_0000008"),              # temporal region
    ("EvidenceInterval", f"{OBO}BFO_0000008"),
    ("UncertaintyWindow", f"{OBO}BFO_0000008"),
    ("OrganizationalAuthorRole", f"{OBO}BFO_0000023"),
    ("WebsitePost", f"{OBO}BFO_0000031"),          # generically dependent continuant
    ("BlogPost", f"{OBO}BFO_0000031"),
    ("PressRelease", f"{OBO}BFO_0000031"),
    ("FeedCoverageWindow", f"{OBO}BFO_0000008"),   # temporal region
    ("CalendarCoverageWindow", f"{OBO}BFO_0000008"),
    ("ScheduledMeeting", f"{OBO}BFO_0000031"),     # an entry, not a process
    ("PlannedMeeting", f"{OBO}BFO_0000031"),
])
def test_class_is_grounded_under_expected_bfo_category(graph, local, expected_ancestor):
    """Every class resolves to the right BFO category through the CCO layer."""
    ancestors = set()
    frontier = [URIRef(COSAIC + local)]
    seen = set(frontier)
    while frontier:
        node = frontier.pop()
        for parent in graph.objects(node, RDFS.subClassOf):
            if isinstance(parent, URIRef) and parent not in seen:
                seen.add(parent)
                ancestors.add(str(parent))
                frontier.append(parent)
    assert expected_ancestor in ancestors, (
        f"{local} ancestors were {sorted(a.rsplit('#', 1)[-1] for a in ancestors)}")


def test_continuants_and_occurrents_stay_disjoint(graph):
    """No class may descend from both branches of BFO's top-level split."""
    continuant, occurrent = f"{OBO}BFO_0000002", f"{OBO}BFO_0000003"
    for subject in set(graph.subjects(RDF.type, OWL.Class)):
        if not str(subject).startswith(COSAIC):
            continue
        ancestors = set()
        frontier, seen = [subject], {subject}
        while frontier:
            node = frontier.pop()
            for parent in graph.objects(node, RDFS.subClassOf):
                if isinstance(parent, URIRef) and parent not in seen:
                    seen.add(parent)
                    ancestors.add(str(parent))
                    frontier.append(parent)
        assert not (continuant in ancestors and occurrent in ancestors), (
            f"{subject} descends from both continuant and occurrent")


# --- MIREOT integrity -----------------------------------------------------------

def test_every_mireot_term_carries_a_label(graph):
    """CCO v2.x IRIs are opaque; without labels the file is unreadable."""
    unlabeled = [
        str(s) for s in set(graph.subjects(RDF.type, OWL.Class))
        if str(s).startswith((CCO, OBO)) and not list(graph.objects(s, RDFS.label))
    ]
    assert not unlabeled, f"MIREOT terms without a label: {unlabeled[:5]}"


def test_mireot_still_agrees_with_the_upstream_release():
    """Fails if CCO renames or removes a referenced term.

    Skipped when the vendored CCO modules are not cached, so the suite stays runnable
    offline.
    """
    from bubo_graphrag.build.mireot import VENDOR, build
    if not VENDOR.exists() or not any(VENDOR.glob("*.ttl")):
        pytest.skip("CCO modules not cached; run python -m bubo_graphrag.build.mireot")
    _, problems = build()
    assert not problems, "MIREOT drift against CCO: " + "; ".join(problems[:5])


def test_key_cco_terms_are_the_ones_documented(graph):
    """Spot-check the key CCO IRIs against the generated alignment."""
    expected = {
        f"{CCO}ont00001262": "Person",
        f"{CCO}ont00001180": "Organization",
        f"{CCO}ont00002070": "Email Address",
        f"{CCO}ont00002039": "Document Content Entity",
        f"{CCO}ont00001298": "Material Copy of a Document",
        f"{CCO}ont00002077": "Act of Publishing",
        f"{CCO}ont00001194": "Gain of Role",
        f"{CCO}ont00000613": "Loss of Role",
        f"{CCO}ont00000175": "Organization Member Role",
    }
    for iri, label in expected.items():
        labels = [str(o) for o in graph.objects(URIRef(iri), RDFS.label)]
        assert label in labels, f"{iri} should be {label!r}, found {labels}"


def test_every_local_class_has_a_label(graph):
    unlabeled = [
        str(s).rsplit("#", 1)[1] for s in set(graph.subjects(RDF.type, OWL.Class))
        if str(s).startswith(COSAIC) and not list(graph.objects(s, RDFS.label))
    ]
    assert not unlabeled, f"local classes without a label: {unlabeled}"


def test_the_ontology_version_is_consistent_and_recorded(graph):
    """ADR-WS2-001 D14: the number, the version IRI and the changelog agree."""
    import re
    ontology = URIRef("https://cosai-oasis.github.io/ontology/cosai-contrib")
    info = str(graph.value(ontology, OWL.versionInfo))
    assert re.fullmatch(r"\d+\.\d+\.\d+", info), f"not SemVer: {info}"
    assert str(graph.value(ontology, OWL.versionIRI)) == f"{ontology}/{info}"
    changelog = (ONTOLOGY / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## {info} " in changelog, f"{info} has no CHANGELOG entry"
    prior = graph.value(ontology, OWL.priorVersion)
    if prior is not None:
        assert f"## {str(prior).rsplit('/', 1)[1]} " in changelog
