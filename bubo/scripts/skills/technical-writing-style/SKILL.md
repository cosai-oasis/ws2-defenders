---
name: technical-writing-style
description: Write or revise technical documents, specifications, RFCs, whitepapers, and ADRs to the CoSAI editorial conventions. Argue from evidence and reasoning only, never from credibility or feeling; describe the document as it stands, never its history; keep work notes out of the body; use RFC 2119 keywords in capitals only; never leave a lone x.1 subsection; use no em or en dashes. Use whenever drafting, editing, tightening, or restructuring normative or technical prose. Triggers on "draft a section", "rewrite this", "edit for style", "tighten this paragraph", "write the spec", "make this normative", "apply the style guide", "editorial conventions".
---

# Technical writing style

These conventions govern documents that make technical claims and state requirements.
Each rule has an ID (P1 to P6) that the `technical-writing-review` skill and its checker
report against, so a draft and its review use the same vocabulary.

Apply every rule while drafting. Fixing them afterwards costs more, because a sentence
built on an appeal or on a comparison with a past draft usually has to be restructured,
not just edited.

## P1. Logos only

Persuade with evidence and reasoning. Never lean on the writer's credibility (ethos) or
the reader's feelings (pathos).

Words that signal sincerity or concession are appeals to ethos. They imply that
unmarked sentences are less trustworthy, and they add no information. They are banned,
and once removed they stay out:

`honest`, `honestly`, `candid`, `candidly`, `frankly`, `admittedly`, `to be fair`,
`worth stating plainly`, `apologize`, `apologies`

- Wrong: `To be fair, the sampling rule loses some events.`
- Right: "The sampling rule drops events below the threshold; §18 bounds the loss."

A word list catches only the obvious cases. Also remove intensifiers that ask for trust
(`clearly`, `obviously`, `of course`) and framing that asks for sympathy. If a claim
needs support, cite the evidence or state the reasoning.

## P2. Describe the document as it stands

Write as if the current text is the only text that has ever existed. Do not refer to
other drafts or revisions, working papers, or what the document once said.
Readers of a published specification never saw the drafts, and change history belongs
in version control and changelogs.

Banned forms include `this revision`, `previous revision`, `earlier drafts`,
`previously treated as`, `no longer treated`, `hitherto`, and `used to be`.

- Wrong: `This revision promotes Stop Reason to MUST.`
- Right: "Stop Reason is a MUST field."

A changelog, an explicit revision history appendix, or a migration table exists to
describe change, so P2 does not apply inside one.

## P3. No work notes in the body

Notes about work left before publishing, verification reminders, open action items, and instructions to
editors or reviewers belong in the issue tracker, not in the document. That includes
`TODO`, `TBD`, `FIXME`, `to be verified`, and `note to reviewers`.

If a note contains lasting fact as well as an instruction, keep the fact, delete the
instruction, and retitle the passage for what remains. A note reading
`Verify the framework status before publication: NIST has not finalized X.` becomes a
subsection titled *Framework status* stating "NIST has not finalized X."

## P4. RFC 2119 keywords in capitals only

Requirement levels use the RFC 2119 and RFC 8174 keywords in capitals: MUST, MUST NOT,
SHALL, SHALL NOT, SHOULD, SHOULD NOT, REQUIRED, RECOMMENDED, MAY, OPTIONAL.

Only the capitalized form binds. State that in the document's conventions section. A
lowercase `must`, `should`, or `may` carries no obligation, so a normative statement
written in lowercase does not bind anyone. Two consequences:

- When moving or rewriting a requirement, keep its keyword capitalized. Rephrasing
  `Producers MUST sample at...` into `producers must sample at...` silently deletes it.
- In non-normative prose, avoid the lowercase keywords where a reader could take them as
  requirements. Use "needs to", "can", or "is expected to" instead, or restructure.

## P5. Never a subsection x.1 without an x.2

A heading that subdivides into only one part is not a subdivision. If a section has
only `4.1`, either add `4.2` or fold `4.1` into §4. The same applies at every depth
(`4.1.1` needs `4.1.2`) and to lettered appendices (`A.1` needs `A.2`).

## P6. No em or en dashes

Use no em dashes (U+2014) and no en dashes (U+2013). Replace each with the punctuation
that states the relationship:

| Purpose | Use instead |
| --- | --- |
| Aside or interruption | commas or parentheses |
| Introducing an explanation or list | a colon |
| Joining two independent clauses | a semicolon, or two sentences |
| A range | "to": "§§5 to 16", "2025 to 2026" |

The one exception is a verbatim proper title that contains a dash, such as an official
standard's name. Keep the title exact rather than altering it to satisfy the rule, and
tell the reviewer it is intentional.

## Document-specific conventions

A document can add its own binding rules on top of these, such as a fixed priority
order, a canonical identifier scheme, or field names that have to match exactly between
sections. Look for them in the document's conventions section, its contributing guide,
or its handoff notes, and treat them as binding. For the CoSAI AI Telemetry RFC, see
[references/telemetry-rfc.md](references/telemetry-rfc.md).

## Before handing over a draft

Check the draft against P1 to P6. If the `technical-writing-review` skill is available,
run its checker on the file and resolve every failure. Report any exemption you relied
on, such as a verbatim title kept with its dash, so the reviewer does not "fix" it.
