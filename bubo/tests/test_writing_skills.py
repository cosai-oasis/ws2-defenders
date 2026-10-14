"""Tests for the technical-writing skills and the prose checker they share.

These skills need no graph, so unlike test_skills.py they do not depend on the store.
Each rule is asserted to fire on a minimal violation *and* to stay quiet on the nearest
legitimate text, because a checker that over-fires teaches authors to ignore it.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest
import yaml

SKILLS = Path(__file__).resolve().parents[1] / "scripts" / "skills"
NAMES = ("technical-writing-style", "technical-writing-review")
REVIEW = SKILLS / "technical-writing-review"

_spec = importlib.util.spec_from_file_location("check_prose", REVIEW / "scripts" / "check_prose.py")
check_prose = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_prose)


def rules(text: str, allow=(), rfc2119: bool = False) -> set[str]:
    return {f["rule"] for f in check_prose.check("t.md", text, list(allow), rfc2119)}


# --- skill files themselves -----------------------------------------------------

@pytest.mark.parametrize("name", NAMES)
def test_frontmatter_declares_only_name_and_description(name):
    text = (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")
    meta = yaml.safe_load(re.match(r"^---\n(.*?)\n---\n", text, re.S).group(1))
    assert set(meta) == {"name", "description"}
    assert meta["name"] == name
    assert len(meta["description"]) > 80


@pytest.mark.parametrize("name", NAMES)
def test_ships_a_grounded_portable_eval(name):
    spec = json.loads((SKILLS / name / "evals" / "evals.json").read_text(encoding="utf-8"))
    assert spec["skill_name"] == name
    assert len(spec["evals"]) >= 3
    assert spec["grounding"]["note"]
    for fixture in spec["grounding"].get("fixtures", []):
        assert (SKILLS / name / fixture).is_file(), f"missing fixture {fixture}"
    for case in spec["evals"]:
        assert {"id", "prompt", "expected_output", "expectations", "depends_on"} <= set(case)
        assert case["expectations"]


@pytest.mark.parametrize("name", NAMES)
def test_skills_follow_their_own_rules(name):
    """A style guide that breaks its own rules teaches the wrong thing by example."""
    for path in (SKILLS / name).rglob("*.md"):
        if "fixtures" in path.parts:
            continue
        findings = check_prose.check(str(path), path.read_text(encoding="utf-8"), [], True)
        assert not findings, findings


def test_style_skill_defines_every_rule_the_checker_reports():
    text = (SKILLS / "technical-writing-style" / "SKILL.md").read_text(encoding="utf-8")
    for rule in ("P1", "P2", "P3", "P4", "P5", "P6"):
        assert re.search(rf"^## {rule}\. ", text, re.M), f"{rule} has no section"


# --- each rule: fires on the violation, quiet on the nearest legitimate text --------

@pytest.mark.parametrize("rule, bad, good", [
    ("P1", "Frankly, the rule drops events.", "The rule drops events below the threshold."),
    ("P1", "We are candidly unsure.", "The bound is not established."),
    ("P2", "This revision promotes the field.", "The field is a MUST field."),
    ("P2", "It was previously treated as optional.", "It is REQUIRED."),
    ("P3", "TODO: confirm the figure.", "The figure is 30 days."),
    ("P3", "Check this before publication.", "Publication follows TSC approval."),
    ("P6", "Exporters batch — see below.", "Exporters batch; see below."),
    ("P6", "Sections 5–16.", "Sections 5 to 16."),
])
def test_prose_rule(rule, bad, good):
    assert rule in rules(bad)
    assert rule not in rules(good)


def test_lone_subsection_is_flagged_but_siblings_are_not():
    assert "P5" in rules("## 2. A\n\n### 2.1 B\n")
    assert "P5" not in rules("## 2. A\n\n### 2.1 B\n\n### 2.2 C\n")
    assert "P5" in rules("## Appendix A\n\n### A.1 Only\n")
    assert "P5" in rules("### 4.1 X\n\n### 4.2 Y\n\n#### 4.2.1 Z\n")


def test_lowercase_keywords_warn_only_when_asked_and_never_fail():
    text = "Collectors must keep every event."
    assert "P4" not in rules(text)
    found = check_prose.check("t.md", text, [], True)
    assert [f["level"] for f in found if f["rule"] == "P4"] == ["warn"]
    assert "P4" not in rules("Collectors MUST keep every event.", rfc2119=True)


def test_code_is_exempt_from_prose_rules():
    text = "Ban `frankly` here.\n\n```\nFrankly — TODO\n```\n"
    assert not rules(text, rfc2119=True)


def test_allow_exempts_a_verbatim_title_only():
    title = "ISO/IEC 42001:2023 — Information technology"
    assert "P6" not in rules(f"Controls map to {title}.", allow=[title])
    assert "P6" in rules(f"Controls map to {title} — mostly.", allow=[title])


def test_heading_with_inline_code_is_neither_double_spaced_nor_unanchorable():
    """A heading's inline code is part of its text and its slug. Blanking it first
    faked a double space and broke every link to the heading."""
    text = "### A.4 Codes: `AT10xx` aliases\n\n### A.5 More\n\nSee [codes](#a4-codes-at10xx-aliases)."
    assert not rules(text) & {"S1", "S3"}


def test_structure_rules():
    assert "S1" in rules("## Intro\n\nSee [x](#missing).")
    assert "S1" not in rules("## Intro\n\nSee [x](#intro).")
    assert "S1" not in rules("## Notes\n\n## Notes\n\nSee [x](#notes-1).")
    assert "S2" in rules("## Notes\n\n## Notes\n")
    assert "S3" in rules("## Two  spaces\n")
    assert "S4" in rules("| a | b |\n| - | - |\n| 1 | 2 | 3 |\n")
    assert "S4" not in rules("| a | b |\n| - | - |\n| 1 \\| 2 | 3 |\n")
    assert "S5" in rules("## 1. A\n\n## 3. C\n")
    assert "S5" in rules("## 1. A\n\nSee §2.")
    assert "S5" not in rules("## 1. A\n\n## 2. B\n\nSee §2.")


# --- the review eval's expected findings are the checker's actual output ------------

def test_fixture_yields_exactly_the_findings_the_eval_expects():
    fixture = REVIEW / "evals" / "fixtures" / "sample-spec.md"
    title = ("ISO/IEC 42001:2023 — Information technology — "
             "Artificial intelligence — Management system")
    found = check_prose.check(str(fixture), fixture.read_text(encoding="utf-8"), [title], True)
    assert {(f["line"], f["rule"]) for f in found} == {
        (10, "P5"), (12, "P1"), (12, "P2"), (13, "P4"), (17, "P3"),
        (21, "P6"), (21, "S5"), (23, "S4"), (28, "S1")}


def test_cli_exit_status(tmp_path):
    clean, dirty = tmp_path / "clean.md", tmp_path / "dirty.md"
    clean.write_text("Collectors must keep events.\n", encoding="utf-8")
    dirty.write_text("Frankly, no.\n", encoding="utf-8")
    assert check_prose.main([str(clean), "--rfc2119"]) == 0, "warnings never fail"
    assert check_prose.main([str(dirty)]) == 1
