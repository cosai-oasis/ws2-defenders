---
name: technical-writing-review
description: Review a technical document, specification, RFC, whitepaper, ADR, or pull request diff against the CoSAI editorial conventions and report each violation by rule ID with its line. Runs a bundled checker for appeals to ethos or pathos, retrospective framing, work notes left in the body, lowercase RFC 2119 keywords, lone x.1 subsections, em and en dashes, broken anchors, duplicate headings, and malformed tables, then reviews by reading for what a checker cannot see. Triggers on "review this document", "check the style", "lint the prose", "does this follow the conventions", "style check", "editorial review", "check for em dashes".
---

# Technical writing review

Review against rules P1 to P6, which the `technical-writing-style` skill defines, plus
the structural checks S1 to S5 below. Report findings by rule ID so the author can find
the rule behind each one.

## 1. Run the checker

```
python3 scripts/check_prose.py [--rfc2119] [--allow "VERBATIM TITLE"]... FILE...
```

The path is relative to this skill's directory. It needs Python 3.9 or later and the
standard library only. Pass `--json` to get the findings as a list of objects with
`file`, `line`, `rule`, `level`, and `message`.

- Pass `--rfc2119` for any document that states requirements. Lowercase keywords are
  reported as warnings, because only a reader can tell whether a sentence is normative.
- Pass `--allow` once for each verbatim proper title that contains a dash or a banned
  word, such as an official standard's name. Never suggest altering such a title.
- Exit status 1 means at least one failure. Warnings never fail.

Fenced code and inline code are not scanned, so quoting a banned word in backticks is
not a violation.

## 2. Read for what the checker cannot see

A clean run does not prove the document follows the rules. Read the text and check:

| Rule | What to look for by reading |
| --- | --- |
| P1 | Appeals the word list misses: `clearly`, `obviously`, `of course`, claims of good faith, urgency or fear used in place of evidence |
| P2 | Any comparison with an earlier state of the document, however phrased; exempt a changelog, revision history, or migration table |
| P3 | Instructions to editors or reviewers phrased without a keyword; notes that mix lasting fact with an instruction (keep the fact, drop the instruction) |
| P4 | Each lowercase keyword warning: normative sentences need capitals; non-normative ones need rewording so they cannot be read as requirements. Also check lowercase `may`, which the checker does not report |
| P5 | Unnumbered headings that still subdivide into a single child |

## 3. Structural checks

| ID | Check |
| --- | --- |
| S1 | Every `](#anchor)` link resolves to a heading or an explicit anchor |
| S2 | No two headings share the same text |
| S3 | No double spaces inside a heading |
| S4 | Every row of a table has the same number of columns |
| S5 | `## N.` sections are contiguous from 1, and every `§N` reference names one of them |

## 4. Document-specific rules

Look for rules that the document itself declares binding: a conventions section, a
contributing guide, or handoff notes. If the document has its own validator, run that
too; the checker here covers only rules that apply to any document.

## 5. Report

List findings in document order as `line: RULE: problem`, then the fix. Separate
failures from warnings that need the author's judgment. Name every `--allow` exemption
you used so the author can confirm it was intended.

Report the findings without editing the document unless asked. When asked to fix them,
apply the `technical-writing-style` rules, rerun the checker, and report what is still
open.
