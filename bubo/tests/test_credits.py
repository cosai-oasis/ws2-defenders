"""Credit parser tests.

Every fixture below is a line or structure observed in the real corpus. The parser is
the highest-risk component in the project -- a wrong split or a wrong merge is a wrong
attribution -- so each observed variant is encoded here case by case rather than
covered by a single happy-path test.
"""

from __future__ import annotations

import pytest

from bubo_graphrag.ingest import credits as C

ROLE_LABELS = {
    "Workstream Leads", "Editors", "Editor", "Contributors", "Reviewers",
    "Technical Steering Committee Co-Chairs", "TSC reviewers", "Authors",
}
STOPS = ["Disclosure", "Disclosures", "CoSAI Focus", "Appendix", "Appendices",
         "Copyright Notice", "Guidelines on usage"]


def parse_line(body: str, label: str = "Contributors"):
    return C.parse_person_line(body, "test-pub", label, "bold-label")


# --- format 1: bold labels -------------------------------------------------------

def test_bold_label_format_canonical():
    """WS1 shape: bold role labels under one acknowledgements heading."""
    text = (
        "## 6\\. Contributors and Acknowledgements\n\n"
        "**Workstream Leads**\n\n"
        "* Matt Maloney, Cohere\n"
        "* Jay White, Microsoft\n\n"
        "**Editors**\n\n"
        "* Mihai Maruseac, Google\n\n"
        "## 7\\. Appendix\n\nirrelevant prose here\n"
    )
    result = C.parse(text, "p", ROLE_LABELS, STOPS)
    assert result.format == "bold-label"
    assert [c.name for c in result.credits] == [
        "Matt Maloney", "Jay White", "Mihai Maruseac"]
    assert [c.source_label for c in result.credits] == [
        "Workstream Leads", "Workstream Leads", "Editors"]


def test_bold_label_with_colon_inside_emphasis():
    """WS3 shape: `**Editors:**` -- colon inside the bold markers."""
    text = ("# Acknowledgements\n\n"
            "**Workstream Leads:** \n\n* Vinay Bansal, Cisco\n\n"
            "**Editors:**\n\n* Bill Stout\n\n# Disclosures\n")
    result = C.parse(text, "p", ROLE_LABELS, STOPS)
    assert [(c.name, c.source_label) for c in result.credits] == [
        ("Vinay Bansal", "Workstream Leads"), ("Bill Stout", "Editors")]


def test_bold_label_with_colon_outside_emphasis():
    """Also WS3: `**Technical Steering Committee Co-Chairs**:`."""
    text = ("# Acknowledgements\n\n"
            "**Technical Steering Committee Co-Chairs**:\n\n"
            "* J.R. Rao, IBM\n\n# Disclosures\n")
    result = C.parse(text, "p", ROLE_LABELS, STOPS)
    assert len(result.credits) == 1
    assert result.credits[0].source_label == "Technical Steering Committee Co-Chairs"
    assert result.credits[0].name == "J.R. Rao"


def test_singular_editor_label_accepted():
    """agent-containment uses `**Editor**`, not `**Editors**`."""
    text = ("## 12. Contributors and acknowledgements\n\n"
            "**Editor**\n\n- Jeff Leva, AI Identity\n\n## Appendix A. Evidence\n")
    result = C.parse(text, "p", ROLE_LABELS, STOPS)
    assert [(c.name, c.source_label) for c in result.credits] == [
        ("Jeff Leva", "Editor")]


# --- format 2: heading labels ----------------------------------------------------

def test_heading_label_numbered():
    """AI-Incident-Response shape: `## 7.1. Workstream Leads`."""
    text = ("# 7. Acknowledgements\n\n"
            "## 7.1. Workstream Leads\n\n- Josiah Hagen, Trend Micro\n\n"
            "## 7.2. Editors\n\n- Michael Rash\n- Sarah Novotny\n\n"
            "# 8. Appendices\n\nprose\n")
    result = C.parse(text, "p", ROLE_LABELS, STOPS)
    assert result.format == "heading-label"
    assert [c.name for c in result.credits] == [
        "Josiah Hagen", "Michael Rash", "Sarah Novotny"]


def test_heading_label_unnumbered():
    """Zero Trust shape: `## Contributors` with no numbering."""
    text = ("# Acknowledgements\n\n"
            "## Workstream Leads\n\n* Vinay Bansal, Cisco\n\n"
            "## Contributors\n\n* Michael Epley, Red Hat\n\n"
            "# Disclosure\n\nprose\n")
    result = C.parse(text, "p", ROLE_LABELS, STOPS)
    assert result.format == "heading-label"
    assert len(result.credits) == 2


def test_escaped_heading_and_trailing_space():
    """agentic-identity uses `## 8\\. Acknowledgements ` with a trailing space."""
    text = ("## 8\\. Acknowledgements \n\n"
            "**Editors**\n\n* Asmae Mhassni, Intel\n\n## 9 CoSAI Focus\n")
    result = C.parse(text, "p", ROLE_LABELS, STOPS)
    assert [c.name for c in result.credits] == ["Asmae Mhassni"]


# --- format 3: none, and region location ----------------------------------------

def test_no_credit_section_returns_empty_not_error():
    """The MCP/PQC addendum and the Telemetry RFC have no credit section at all."""
    text = "# Some Paper\n\nBody text only.\n\n## Conclusion\n\nDone.\n"
    result = C.parse(text, "p", ROLE_LABELS, STOPS)
    assert result.format == "none"
    assert result.credits == []


def test_takes_last_heading_not_the_toc_entry():
    """Auto-generated TOCs repeat the heading; the real section is the last one."""
    text = (
        "# Paper\n\n"
        "## Acknowledgements\n\n"            # TOC-like early occurrence
        "[Acknowledgements\t18](#ack)\n\n"
        "## 1. Introduction\n\nbody\n\n"
        "## Acknowledgements\n\n"            # the real one
        "**Editors**\n\n* Real Person, Intel\n\n"
        "# Disclosure\n"
    )
    result = C.parse(text, "p", ROLE_LABELS, STOPS)
    assert [c.name for c in result.credits] == ["Real Person"]


def test_boilerplate_after_credits_is_not_ingested():
    """The AI-usage guidelines that follow every credit section are bulleted prose."""
    text = (
        "# Acknowledgements\n\n"
        "**Editors**\n\n* Real Person, Intel\n\n"
        "# Disclosure\n\n## CoSAI Focus\n\n"
        "**Guidelines on usage of more advanced AI systems**\n\n"
        "* Selection of AI systems: CoSAI recommends the use of reputable AI systems\n"
        "* Human-edited content and quality control: CoSAI mandates human-reviewed "
        "results for any final outputs.\n"
    )
    result = C.parse(text, "p", ROLE_LABELS, STOPS)
    assert [c.name for c in result.credits] == ["Real Person"]


# --- person-line variants --------------------------------------------------------

@pytest.mark.parametrize("body,name,org", [
    ("Josiah Hagen, Trend Micro", "Josiah Hagen", "Trend Micro"),
    ("Michael Rash", "Michael Rash", None),
    ("Asmae Mhassni , Intel", "Asmae Mhassni", "Intel"),          # stray space
    ("Sarah Novotny, ", "Sarah Novotny", None),                    # stray comma
    ("Josiah Hagen, indepedent", "Josiah Hagen", "indepedent"),    # typo preserved
    ("Judith Furlong, Dell Technologies", "Judith Furlong", "Dell Technologies"),
    ("J.R. Rao, IBM", "J.R. Rao", "IBM"),                          # initials
    ("Riggs Goodman III, Amazon", "Riggs Goodman III", "Amazon"),
])
def test_person_line_name_and_org(body, name, org):
    credits, _ = parse_line(body)
    assert len(credits) == 1
    assert credits[0].name == name
    assert credits[0].organization == org


def test_initials_are_not_mistaken_for_prose():
    """`J.R. Rao, IBM` contains '. R'; a punctuation-based prose rule dropped him."""
    credits, findings = parse_line("J.R. Rao, IBM")
    assert len(credits) == 1
    assert not [f for f in findings if f.kind == "rejected-as-prose"]


@pytest.mark.parametrize("body,expected", [
    ("Vinay Bansal, Cisco ([vibansal@cisco.com](mailto:vibansal@cisco.com))",
     "vibansal@cisco.com"),
    ("Zeal Somani, Evinova (zeal.somani@evinova.com)", "zeal.somani@evinova.com"),
    ("Josiah Hagen, Trend Micro (Josiah\\_Hagen@trendmicro.com)",
     "josiah_hagen@trendmicro.com"),
])
def test_email_extraction_and_unescaping(body, expected):
    """Markdown mailto links, bare parentheses, and escaped underscores."""
    credits, _ = parse_line(body)
    assert credits[0].emails == [expected]


def test_equal_contribution_dagger():
    body = "Bill Stout ([billbrietstout@gmail.com](mailto:billbrietstout@gmail.com))*†*"
    credits, _ = parse_line(body)
    assert credits[0].name == "Bill Stout"
    assert credits[0].equal_contribution is True


def test_github_handle_with_section_scope():
    """agent-containment credits `@skvcool-rgb (§4)`."""
    credits, _ = parse_line("@skvcool-rgb (§4)")
    assert len(credits) == 1
    assert credits[0].github_login == "skvcool-rgb"
    assert credits[0].scope_note == "§4"
    assert credits[0].name is None


def test_multi_person_line_splits_and_flags():
    """Three people on one line; 'David LaBianca' is not Akila's employer."""
    body = "Akila Srinivasan, David LaBianca, Jodi Middleton (named 2026-08-25)"
    credits, findings = parse_line(body, "TSC reviewers")
    assert [c.name for c in credits] == [
        "Akila Srinivasan", "David LaBianca", "Jodi Middleton"]
    assert all(c.organization is None for c in credits)
    assert any(f.kind == "multi-person-line" for f in findings)


def test_prose_line_is_rejected_with_a_finding():
    body = ("Iterative refinement: The use of AI systems in drafting standards should "
            "be seen as an iterative process")
    credits, findings = parse_line(body)
    assert credits == []
    assert any(f.kind == "rejected-as-prose" for f in findings)


def test_bullet_markers_both_accepted():
    dash = C.parse("# Acknowledgements\n\n**Editors**\n\n- Jane Roe, Intel\n\n# Disclosure\n",
                   "p", ROLE_LABELS, STOPS)
    star = C.parse("# Acknowledgements\n\n**Editors**\n\n* Jane Roe, Intel\n\n# Disclosure\n",
                   "p", ROLE_LABELS, STOPS)
    assert len(dash.credits) == len(star.credits) == 1


@pytest.mark.parametrize("body", [
    "An Nguyen, Intel",       # 'an' is an English function word
    "Le Van Do, Cisco",       # 'do' likewise
    "Be Tran",                # 'be' likewise
    "It Takahashi, Meta",     # 'it' likewise
])
def test_names_containing_function_words_are_kept(body):
    """A single function-word token must not reject a real name.

    Prose detection keyed on any one stopword dropped names that open with a token that
    is also an English function word. Real prose in this corpus is caught by the clause
    colon and the token count instead.
    """
    credits, findings = parse_line(body)
    assert len(credits) == 1, f"{body!r} was rejected: {findings}"


# --- front-matter authorship (ODIS) ---------------------------------------------

def test_frontmatter_authors_parsed():
    """ODIS names authors as `Name (Org), Name (Org)` -- commas separate people here."""
    field = "Nir Paz (NVIDIA), Mike Beiter (NVIDIA), Yu-Cheng Liang (NVIDIA)"
    credits, findings = C.parse_frontmatter_authors(field, "odis")
    assert [c.name for c in credits] == ["Nir Paz", "Mike Beiter", "Yu-Cheng Liang"]
    assert all(c.organization == "NVIDIA" for c in credits)
    assert all(c.source_label == "Authors" for c in credits)


def test_frontmatter_workstream_author_is_not_a_person():
    """Most documents put the workstream in `author`; that is not authorship."""
    credits, _ = C.parse_frontmatter_authors(
        "Workstream 1: Software Supply Chain Security for AI Systems", "p")
    assert credits == []


def test_frontmatter_single_author_without_org():
    credits, _ = C.parse_frontmatter_authors("Jane Roe", "p")
    assert [(c.name, c.organization) for c in credits] == [("Jane Roe", None)]


# --- whole-corpus invariants ----------------------------------------------------

def test_corpus_parses_with_expected_totals(corpus, role_registry):
    """The real corpus yields 180 credit-section credits and one finding."""
    labels = set(role_registry["roles"])
    stops = role_registry["stop_headings"]
    total, findings = 0, []
    for pub_id, text in corpus.items():
        result = C.parse(text, pub_id, labels, stops)
        total += len(result.credits)
        findings += result.findings
    assert total == 180
    # The only expected finding is the three-people-on-one-line in agent-containment.
    assert [f.kind for f in findings] == ["multi-person-line"]


def test_every_credit_has_a_recognized_role_label(corpus, role_registry):
    labels = set(role_registry["roles"])
    stops = role_registry["stop_headings"]
    for pub_id, text in corpus.items():
        for credit in C.parse(text, pub_id, labels, stops).credits:
            assert credit.source_label in labels, (
                f"{pub_id}: unmapped role label {credit.source_label!r}")


def test_documents_declared_without_credits_yield_none(corpus, role_registry):
    labels = set(role_registry["roles"])
    stops = role_registry["stop_headings"]
    for pub_id in ("addendum-mcp-and-pqc", "cosai-ai-telemetry-rfc"):
        result = C.parse(corpus[pub_id], pub_id, labels, stops)
        assert result.credits == [], f"{pub_id} should have no credit section"
