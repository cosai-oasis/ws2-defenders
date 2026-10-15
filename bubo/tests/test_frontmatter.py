"""Declared-metadata tests: two metadata styles and four date formats."""

from __future__ import annotations

import datetime as dt

import pytest

from bubo_graphrag.ingest import frontmatter as FM


# --- date parsing ---------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("12 June 2025", dt.date(2025, 6, 12)),          # risks-and-controls
    ("29 September 2025", dt.date(2025, 9, 29)),     # signing-ml-artifacts
    ("8 January 2026", dt.date(2026, 1, 8)),         # MCP Security, single digit
    ("2026-09-05", dt.date(2026, 9, 5)),             # agent-containment, ISO
    ("27 October 2025 ", dt.date(2025, 10, 27)),     # trailing space
    ("January 8, 2026", dt.date(2026, 1, 8)),        # month-first, defensive
    (dt.date(2026, 3, 20), dt.date(2026, 3, 20)),    # PyYAML pre-coerced
])
def test_parse_date_accepts_corpus_formats(raw, expected):
    assert FM.parse_date(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "   ", "not a date", "2026-13-45", "Q3 2026"])
def test_parse_date_returns_none_rather_than_raising(raw):
    """An unparseable date is a data-quality finding, not a crash."""
    assert FM.parse_date(raw) is None


# --- style 1: YAML front matter -------------------------------------------------

def test_yaml_frontmatter_basic():
    text = ('---\ntitle: "Zero Trust for AI Systems"\n'
            'author: "Workstream 2: Preparing Defenders"\ndate: 4 September 2026\n---\n\nBody\n')
    meta = FM.parse(text)
    assert meta.style == "yaml-frontmatter"
    assert meta.title == "Zero Trust for AI Systems"
    assert meta.date == dt.date(2026, 9, 4)
    assert meta.body_offset > 0


def test_yaml_frontmatter_revision_fields():
    """MCP Security carries date, last_updated, version and a revision note."""
    text = ('---\ntitle: Model Context Protocol (MCP) Security\n'
            'date: 8 January 2026\nlast_updated: 12 August 2026\nversion: 2.0\n'
            'revision_note: "Updated for the MCP 2026 spec"\n---\n\nBody\n')
    meta = FM.parse(text)
    assert meta.date == dt.date(2026, 1, 8)
    assert meta.last_updated == dt.date(2026, 8, 12)
    assert meta.version == "2.0"
    assert meta.revision_note.startswith("Updated")


def test_yaml_frontmatter_malformed_does_not_raise():
    text = "---\ntitle: [unclosed\n  bad: : :\n---\n\nBody\n"
    meta = FM.parse(text)
    assert meta.style == "yaml-frontmatter"
    assert meta.title is None


# --- style 2: bold header block (Telemetry RFC) ---------------------------------

def test_bold_header_block_style():
    """The Telemetry RFC has no YAML front matter; version is inline in the h1."""
    text = ("# Telemetry for AI Security {**Working Draft v0.5**}\n\n"
            "**Status:** Request for Comments, revision 0.5\n"
            "**Origin:** Coalition for Secure AI (CoSAI), Workstream 2 (Defenders)\n"
            "**Disclosure:** Prepared for open publication under CoSAI.\n\n---\n\n## 1. Introduction\n")
    meta = FM.parse(text)
    assert meta.style == "bold-header-block"
    assert meta.title == "Telemetry for AI Security"
    assert meta.version == "Working Draft v0.5"
    assert "Workstream 2" in meta.author


def test_bold_header_block_version_from_status():
    """Without the brace form, the version comes from `Status: ... revision N`."""
    text = ("# Some RFC\n\n**Status:** Request for Comments, revision 0.3\n\n## Body\n")
    meta = FM.parse(text)
    assert meta.style == "bold-header-block"
    assert meta.version == "0.3"


def test_no_metadata_at_all():
    meta = FM.parse("Just some text with no heading or fields.\n")
    assert meta.style == "none"
    assert meta.title is None


# --- workstream disagreement detection ------------------------------------------

def test_declared_workstream_extracted_from_author():
    meta = FM.parse('---\nauthor: "Workstream 3: AI Risk Governance"\n---\n\nBody\n')
    assert meta.declared_workstream_number == 3


def test_declared_workstream_from_origin_field():
    text = "# X\n\n**Origin:** Coalition for Secure AI (CoSAI), Workstream 2 (Defenders)\n"
    assert FM.parse(text).declared_workstream_number == 2


def test_declared_workstream_none_when_absent():
    meta = FM.parse('---\nauthor: "Nir Paz (NVIDIA), Mike Beiter (NVIDIA)"\n---\n\nBody\n')
    assert meta.declared_workstream_number is None


# --- against the real corpus ----------------------------------------------------

def test_every_document_yields_metadata(corpus):
    for pub_id, text in corpus.items():
        meta = FM.parse(text)
        assert meta.style in ("yaml-frontmatter", "bold-header-block"), pub_id
        assert meta.title, f"{pub_id} produced no title"


def test_telemetry_rfc_uses_the_bold_header_style(corpus):
    meta = FM.parse(corpus["cosai-ai-telemetry-rfc"])
    assert meta.style == "bold-header-block"


def test_ws3_document_declares_the_wrong_workstream(corpus):
    """The registry, not the document, decides the workstream.

    This disagreement is real and consequential: the Shared Responsibility Framework
    lives in ws3-ai-risk-governance but declares Workstream 2.
    """
    meta = FM.parse(corpus["ai-shared-responsibility-framework"])
    assert meta.declared_workstream_number == 2
    from bubo_graphrag.paths import publication
    assert publication("ai-shared-responsibility-framework")["workstream"] == "ws3"
