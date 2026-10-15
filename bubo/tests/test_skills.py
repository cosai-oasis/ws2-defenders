"""Skill-level tests: the behaviors each SKILL.md promises.

These exercise the tools the way a skill would, and assert the guarantees the skill
documents rely on -- so if a tool stops honouring one, the skill's instructions become
false and a test fails rather than the model quietly reporting something wrong.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bubo_graphrag import server as S
from bubo_graphrag import store as store_mod

# The vendor-neutral canonical home (ADR-031 D5, ADR-033 D1). Deliberately not a
# product-named config directory: that would put a harness path inside the portable
# eval, and ADR-033 D2a excludes one from the shipped surface. Local discovery is an
# untracked symlink pointing here, which is the consumer's adaptation (D3).
SKILLS = Path(__file__).resolve().parents[1] / "scripts" / "skills"
SKILL_NAMES = ("who-did-what", "what-cited-this", "cosai-orientation")


@pytest.fixture(autouse=True)
def _built(store):
    """Every test here needs the store; reuse the session fixture's skip behavior."""
    return store


# --- skill files themselves -----------------------------------------------------

@pytest.mark.parametrize("name", SKILL_NAMES)
def test_skill_has_valid_frontmatter(name):
    text = (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert match, f"{name} has no YAML front matter"
    import yaml
    meta = yaml.safe_load(match.group(1))
    assert meta["name"] == name
    assert len(meta["description"]) > 80, "description must be specific enough to route on"
    # ADR-033 D2a enforces the Agent Skills required-field core as an *allowlist*: any
    # further key encodes one runtime's wiring, and a harness that does not know it
    # ignores it silently, so the skill ports cleanly only while this holds.
    assert set(meta) == {"name", "description"}, (
        f"{name} frontmatter must declare only name and description; "
        f"found {sorted(set(meta) - {'name', 'description'})}")


@pytest.mark.parametrize("name", SKILL_NAMES)
def test_skill_ships_a_portable_eval(name):
    """ADR-033 D6: an artifact with no eval is not admissible to the shipped set.

    The eval is the artifact's portable trust anchor -- what a consumer runs in their
    own runtime to confirm an adaptation preserved behavior -- so it has to travel
    inside the directory they clone, and it has to record what its expectations rest
    on (D7a) or a later failure cannot be told apart from ordinary corpus growth.
    """
    import json
    spec = json.loads((SKILLS / name / "evals" / "evals.json").read_text(encoding="utf-8"))
    assert spec["skill_name"] == name
    assert len(spec["evals"]) >= 3, "at least three cases per skill"
    assert spec.get("grounding", {}).get("note"), "must state how expectations are grounded"
    for case in spec["evals"]:
        assert {"id", "prompt", "expected_output", "expectations"} <= set(case)
        assert case["expectations"], f"case {case['id']} grades nothing"
        assert "depends_on" in case, f"case {case['id']} must record its dependencies"


@pytest.mark.parametrize("name", SKILL_NAMES)
def test_skill_names_only_tools_that_exist(name):
    """A skill referencing a renamed tool would send the model at nothing.

    Tools are discovered from the server module rather than hard-coded, so a rename
    fails here instead of silently invalidating the skill's instructions.
    """
    available = {
        attr for attr in dir(S)
        if not attr.startswith("_") and callable(getattr(S, attr))
        and getattr(S, attr).__module__ == S.__name__
        and not attr[0].isupper()
    }
    text = (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")
    # Only tokens presented as tools: a lone backticked identifier in a table cell.
    referenced = set()
    for line in text.splitlines():
        if line.startswith("|"):
            for cell in line.split("|"):
                token = cell.strip()
                if re.fullmatch(r"`[a-z][a-z_]*`", token):
                    referenced.add(token.strip("`"))
    assert referenced, f"{name} lists no tools in a table"
    unknown = referenced - available
    assert not unknown, (
        f"{name} references tools that do not exist: {sorted(unknown)}; "
        f"available: {sorted(available)}")


# --- who-did-what: three core guarantees ----------------------------------------

def test_who_did_what_resolves_name_variants():
    """The skill tells the model to call find_person first; it must actually work."""
    for query in ("rao", "J.R. Rao", "josiah", "Mhassni"):
        result = S.find_person(query)
        assert result["count"] >= 1, f"find_person({query!r}) found nobody"
        assert all("person_id" in p for p in result["people"])


def test_who_did_what_never_reports_a_current_employer():
    """Every affiliation row must carry bounds_known false and no start/end framing."""
    for person_id in ("josiah-hagen", "bill-stout", "sarah-novotny", "j-r-rao"):
        result = S.what_did_person_do(person_id)
        for row in result["affiliation"]:
            assert row["bounds_known"] is False
            assert set(row) == {"organization", "attested_from", "attested_to",
                                "bounds_known"}
        assert "open bounds" in result["note"] or "does not mean" in result["note"]


def test_who_did_what_marks_inference_on_affiliation_changes():
    result = S.affiliation_timeline("bill-stout")
    assert result["inferred_changes"], "Bill Stout's employer change must be present"
    for change in result["inferred_changes"]:
        assert change["inferred"] in ("true", True)
        assert "notBefore" in change and "notAfter" in change


def test_who_did_what_surfaces_draft_status():
    """The skill promises approval_status travels with every publication."""
    listed = S.list_publications()
    assert all("status" in p for p in listed["publications"])
    drafts = {p["id"] for p in listed["publications"] if p["status"] != "approved"}
    assert drafts == {"agent-containment", "cosai-ai-telemetry-rfc", "odis"}


def test_who_did_what_keeps_multiple_roles_on_one_document():
    """Akila Srinivasan is both Reviewer and TSC Co-Chair on the WS3 framework."""
    result = S.who_contributed_to("ai-shared-responsibility-framework")
    roles = {
        role for role, rows in result["by_role"].items()
        if any(r.get("person") == "Akila Srinivasan" for r in rows)
    }
    assert {"ReviewerRole", "TSCCoChairRole"} <= roles


def test_who_did_what_reports_zero_credits_as_a_fact_not_a_gap():
    result = S.who_contributed_to("cosai-ai-telemetry-rfc")
    assert result["credit_count"] == 0
    assert "note" in result, "a document with no credit section must say so"


def test_who_did_what_addresses_are_opt_in():
    """Addresses are published, but the skill says not to volunteer them."""
    default = S.what_did_person_do("josiah-hagen")
    assert "email_addresses" not in default
    opted = S.what_did_person_do("josiah-hagen", include_addresses=True)
    assert opted["email_addresses"]


# --- what-cited-this: three core guarantees -------------------------------------

def test_what_cited_this_splits_category_and_verification():
    """The skill forbids reporting a bare total; the tool must supply the split."""
    result = S.what_cited_this("model-context-protocol-security")
    assert result["citing_publication_count"] == 28
    assert set(result["by_category"]) == {"Formal reference", "Substantive work citation"}
    assert "Directly inspected" in result["by_verification"]


def test_what_cited_this_reports_publisher_relationship():
    """Independence of a citation matters; the field must be present."""
    result = S.what_cited_this("model-context-protocol-security")
    assert any(c.get("relationship") for c in result["citations"])


def test_what_cited_this_names_its_source():
    result = S.what_cited_this("signing-ml-artifacts")
    assert "cosai-tsc" in result["source"]


def test_citation_summary_includes_out_of_scope_works():
    """Omitting Principles and the Risk Map would misrepresent CoSAI's impact."""
    result = S.citation_summary()
    out_of_scope = {w["work"] for w in result["works"]
                    if w["inScope"] in ("false", False)}
    assert len(out_of_scope) == 5
    assert any("Principles for Secure-by-Design" in w for w in out_of_scope)
    assert any("Risk Map" in w for w in out_of_scope)


def test_citation_summary_explains_the_counting_rule():
    result = S.citation_summary()
    assert "does not sum" in result["note"]


def test_corporate_authorship_is_recorded(store):
    """Principles is authored by CoSAI the organization, not by named individuals."""
    rows = store.select("""
        SELECT ?author WHERE {
          ?c a cosaic:OrganizationalAuthorRole ;
             obo:BFO_0000197 ?o ;
             cosaic:onPublication cosaic:pub-principles-secure-by-design-agentic-systems .
          ?o rdfs:label ?author }""")
    assert {r["author"] for r in rows} == {"CoSAI"}


# --- shared: the SPARQL escape hatch --------------------------------------------

def test_graph_schema_documents_the_conventions():
    schema = S.graph_schema()
    joined = " ".join(schema["conventions"]).lower()
    assert "boundsknown" in joined
    assert "original publication" in joined
    assert "approvalstatus" in joined
    assert "activitystatus" in joined


def test_graph_schema_names_only_declared_relations():
    """A model copies these into SPARQL, and a predicate that does not exist returns
    zero rows rather than an error, so a wrong key misleads silently."""
    from rdflib import Graph, Namespace
    from bubo_graphrag.paths import ONTOLOGY

    cosaic = Namespace("https://cosai-oasis.github.io/ontology/cosai-contrib#")
    ontology = Graph().parse(ONTOLOGY / "cosai-contrib.ttl")
    declared = set(ontology.subjects())
    relations = S.graph_schema()["key_relations"]
    for key in relations:
        if key.startswith("cosaic:"):
            assert cosaic[key.removeprefix("cosaic:")] in declared, key
    # The group and meeting model is reachable from the schema, not only the credits.
    assert {"cosaic:convenedBy", "cosaic:succeededBy", "cosaic:activityStatus"} \
        <= set(relations)


@pytest.mark.parametrize("query", [
    "INSERT DATA { <a:b> <a:c> <a:d> }",
    "DELETE WHERE { ?s ?p ?o }",
    "DROP GRAPH <a:b>",
    "LOAD <http://example.com/x.ttl>",
    "CLEAR ALL",
])
def test_sparql_rejects_write_operations(query):
    assert "error" in S.sparql(query)


@pytest.mark.parametrize("target", [
    "http://169.254.169.254/latest/meta-data/",   # cloud instance metadata
    "http://[fd00:ec2::254]/latest/meta-data/",   # the IPv6 form of the same
    "http://metadata.google.internal/",
    "http://127.0.0.1:8099/sparql",
    "http://192.0.2.1/sparql",                    # RFC 5737 TEST-NET-1
    "https://example.com/sparql",
])
def test_federation_scan_flags_every_egress_target(target):
    """Scan the query text without running it.

    These are the targets that matter -- instance metadata first, since that is where
    a cloud host serves credentials. They are asserted against the scanner directly,
    never through `sparql`, because a test that reached the engine would *make* the
    request it is meant to prevent the moment the guard regressed. On a cloud CI
    runner (a GitHub Actions runner is an Azure VM) 169.254.169.254 answers.
    """
    assert store_mod._federation_keyword(
        f"SELECT * WHERE {{ SERVICE <{target}> {{ ?s ?p ?o }} }}")


@pytest.mark.parametrize("query", [
    "SELECT * WHERE { SERVICE <http://127.0.0.1:8099/sparql> { ?s ?p ?o } }",
    "SELECT * WHERE { service silent <http://127.0.0.1:8099/sparql> { ?s ?p ?o } }",
    "SELECT * WHERE { ?s ?p ?o\n  SERVICE\t<http://127.0.0.1:8099/s> { ?a ?b ?c } }",
])
def test_sparql_rejects_federation(query):
    """A read form is not enough: SERVICE dials the host and streams bindings to it,
    so the escape hatch would be an egress primitive driven by query text the model
    composed after reading untrusted documents.

    Every target here is a closed loopback port deliberately: if the guard regresses,
    this fails in milliseconds against nothing, instead of hanging on an unrouted
    address or reaching a real service.
    """
    assert "error" in S.sparql(query)


@pytest.mark.parametrize("query", [
    'SELECT ?o WHERE { ?o rdfs:label "ServiceNow" }',
    'SELECT ?l WHERE { ?o rdfs:label ?l FILTER(CONTAINS(?l, "Service")) }',
    "SELECT * WHERE { ?s <http://example.org/service> ?o }",
    "SELECT ?s WHERE { #SERVICE <http://127.0.0.1:8099/s>\n ?s a cosaic:Person }",
])
def test_federation_guard_does_not_false_fire(query):
    """The graph holds an organization named ServiceNow, so the guard must scan only
    outside literals, IRIs and comments -- or it refuses legitimate questions."""
    assert "error" not in S.sparql(query, limit=3)


def test_sparql_allows_reads_and_reports_truncation():
    result = S.sparql("SELECT ?s WHERE { ?s a cosaic:Person }", limit=5)
    assert result["form"] == "select"
    assert result["count"] == 5
    assert result["truncated"] is True


def test_sparql_ignores_prefixes_when_detecting_the_form():
    """A leading PREFIX block must not hide the query form from the guard."""
    result = S.sparql(
        "PREFIX x: <http://example.com/>\n# a comment\n"
        "SELECT ?s WHERE { ?s a cosaic:Publication }", limit=3)
    assert result["form"] == "select"
