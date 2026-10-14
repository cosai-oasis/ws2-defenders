"""Citation ingestion and discovery tests."""

from __future__ import annotations

import json

import pytest

from bubo_graphrag.citation import discover as DISC
from bubo_graphrag.ingest import citations as CIT
from bubo_graphrag.paths import load_registry, publication, publications


@pytest.fixture(scope="module")
def rows():
    if not CIT.VENDORED.exists():
        pytest.skip("citation dataset not cached; run "
                    "python -m bubo_graphrag.ingest.citations")
    return json.loads(CIT.VENDORED.read_text(encoding="utf-8"))


# --- ingestion ------------------------------------------------------------------

def test_every_dataset_work_title_is_mapped(rows):
    """An unmapped title would silently understate citation counts."""
    aliases = load_registry("work-aliases")
    known = set(aliases["works"]) | set(aliases["stubs"])
    titles = {w for r in rows for w in (r.get("cosai_works") or [])}
    assert titles <= known, f"unmapped work titles: {sorted(titles - known)}"


def test_totals_reconcile_with_the_tsc_report(rows):
    """146 relationships, 98 citing publications, 8 organizational mentions."""
    relationships = sum(len(r.get("cosai_works") or []) for r in rows)
    mentions = sum(1 for r in rows if not r.get("cosai_works"))
    assert relationships == 146
    assert mentions == 8
    assert len(rows) - mentions == 98


def test_build_emits_no_problems(rows):
    _, problems, _ = CIT.build(rows)
    assert not problems, problems[:5]


def test_organizational_mentions_are_not_dropped(rows):
    _, _, stats = CIT.build(rows)
    assert stats["organizational-mention"] == 8


def test_stub_works_are_emitted_with_provenance(rows):
    graph, _, stats = CIT.build(rows)
    assert stats["stub"] == 50
    text = graph.serialize(format="turtle")
    assert "CoSAIWorkStub" in text
    assert "principles-secure-by-design-agentic-systems" in text


def test_principles_carries_organizational_authorship(rows):
    """Corporately authored with no named contributors; must not read as uncredited."""
    graph, _, _ = CIT.build(rows)
    text = graph.serialize(format="turtle")
    assert "OrganizationalAuthorRole" in text
    assert "organizational attribution" in text


def test_unknown_category_would_be_reported():
    """A new category in a refreshed dataset must surface, not pass silently."""
    rows = [{"id": "X1", "publisher": "Someone", "citing_publication": "A thing",
             "source_url": "https://example.com/x", "category": "Brand New Category",
             "verification": "Directly inspected",
             "cosai_works": ["Signing ML Artifacts"]}]
    _, problems, _ = CIT.build(rows)
    assert any("unknown category" in p for p in problems)


def test_unknown_work_title_would_be_reported():
    rows = [{"id": "X2", "publisher": "Someone", "citing_publication": "A thing",
             "source_url": "https://example.com/x", "category": "Formal reference",
             "verification": "Directly inspected",
             "cosai_works": ["Some Paper Nobody Registered"]}]
    _, problems, _ = CIT.build(rows)
    assert any("neither works nor stubs" in p for p in problems)


# --- surface forms for discovery -------------------------------------------------

def test_surface_forms_cover_every_citation_shape():
    """A citation may use any of these; searching one form would miss most."""
    forms_registry = load_registry("citation-forms")
    pub = publication("signing-ml-artifacts")
    kinds = {f.kind for f in DISC.surface_forms(pub, forms_registry)}
    assert kinds == {"blob-url", "raw-url", "pdf-url", "repo-url", "landing", "title"}


def test_surface_forms_include_the_pinned_sha_variant():
    """Citations often link a blob at a specific commit rather than main."""
    forms_registry = load_registry("citation-forms")
    pub = publication("signing-ml-artifacts")
    values = [f.value for f in DISC.surface_forms(pub, forms_registry)]
    assert any(pub["commit_sha"] in v for v in values)
    assert any("/blob/main/" in v for v in values)


def test_generic_short_titles_require_cosai_context():
    """'MCP Security' alone matches far more unrelated material than real citations."""
    forms_registry = load_registry("citation-forms")
    pub = publication("model-context-protocol-security")
    forms = {f.value: f.needs_context for f in DISC.surface_forms(pub, forms_registry)}
    assert forms["MCP Security"] is True
    assert forms["Model Context Protocol (MCP) Security"] is False


def test_every_publication_has_surface_forms():
    forms_registry = load_registry("citation-forms")
    for pub in publications():
        forms = DISC.surface_forms(pub, forms_registry)
        assert len(forms) >= 4, f"{pub['id']} has too few forms to search on"
        assert any(f.kind == "title" for f in forms)


@pytest.mark.parametrize("a,b", [
    ("https://github.com/o/r/blob/abc1234def5678/p.md",
     "https://github.com/o/r/blob/main/p.md"),
    ("http://Example.com/X/", "https://example.com/x"),
])
def test_url_normalization_dedupes_equivalent_links(a, b):
    """The same document at a pinned sha and on main must dedupe to one key."""
    assert DISC._normalize_url(a) == DISC._normalize_url(b)


def test_self_references_are_excluded_from_candidates():
    assert "cosai-oasis" in DISC.SELF_OWNERS


def test_website_copies_and_former_addresses_are_forms_of_their_kind():
    """A website PDF is a pdf-url and a pre-rename path is a blob-url, not a landing page."""
    forms_registry = load_registry("citation-forms")
    forms = {(f.kind, f.value) for f in DISC.surface_forms(
        publication("model-context-protocol-security"), forms_registry)}
    assert ("pdf-url", "www.coalitionforsecureai.org/wp-content/uploads/2026/09/"
            "model-context-protocol-security-v2.0.pdf") in forms
    assert ("blob-url", "github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/mcp/"
            "model-context-protocol-security.md") in forms
    landing = {v for k, v in forms if k == "landing"}
    assert not any("github.com" in v for v in landing)
