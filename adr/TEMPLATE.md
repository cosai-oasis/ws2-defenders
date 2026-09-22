# ADR-WS2-NNN: Short decision title

**Status:** Draft | Accepted | Superseded by [ADR-WS2-XXX](XXX-slug.md)
**Date:** YYYY-MM-DD
**Authors:** Name(s) or role(s)

---

## Context

What forces are at play? What problem, constraint or opportunity forced a decision? Link the
issue, PR or thread that surfaced it. Keep to the facts a future reader needs to understand
*why a decision had to be made* — not a history of everything considered.

State plainly what already exists and what does not, so the reader can tell build from wiring.

## Decision

What did we decide? Present tense, stated directly. If it has concrete shape — a file path, a
tool, a convention — name it.

More than one component means numbered sub-sections with a `D` prefix: `### D1. {Title}`,
`### D2. {Title}`, and `#### D3a.` only where a parent decision has internal layering that
earns its own heading. Internal cross-references use the same prefix (`D3`, `D3b`), never
`§3` or "decision (3)". The stable IDs let validators, CI error strings and other ADRs cite a
specific component without depending on heading text.

## Alternatives Considered

One short paragraph each: what it was, and the specific reason it was not chosen. Recording
rejected options prevents the same debate reopening without new information.

- **Option A** — summary; rejected because …
- **Option B** — summary; rejected because …

## Consequences

### Positive
What the decision provides.

### Negative
What it costs, what new failure modes it introduces, what debt it takes on. State these as
plainly as the Positive section.

### Follow-up
Work this decision implies but does not itself perform — later ADRs, issues, PRs.

---

# Project plan

*Optional, and a divergence from upstream.* Where the decision is discharged by a cohort that
turns over, the sequencing belongs in the record: team, cadence, milestones with committed and
stretch scope, gates, artifacts, risks. Omit for decisions that are simply true once taken.

---

### Authoring notes — delete before merging

- Filename `NNN-slug.md`, zero-padded sequential, kebab-case slug. The qualified `ADR-WS2-NNN`
  lives in the H1.
- Claim the number by adding its row to [`README.md`](README.md) **in the same commit**.
- One decision per ADR. Two decisions means two ADRs — except where they are genuinely one
  choice with parts, which is what `D1…Dn` is for.
- Cite commits, PRs and issues concretely. Retroactive ADRs need this most.
- Lead the title with what the decision achieves, not how it is implemented; the index is read
  as a list of titles.
