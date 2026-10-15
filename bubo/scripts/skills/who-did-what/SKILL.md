---
name: who-did-what
description: Answer questions about who has contributed what to CoSAI publications — a person's or organization's credited work, who worked on a given paper, and how affiliations changed over time. Use whenever a question names a CoSAI contributor, a member company, or a CoSAI whitepaper and asks about authorship, credit, roles, or involvement. Triggers on "who wrote", "who contributed", "what has X worked on", "which companies", "who edited", "who reviewed", "is X still at".
---

# Who did what in CoSAI

The `bubo` MCP server holds a graph of credited contribution built from the
acknowledgement sections of 12 CoSAI publications. Use its tools rather than reading the
documents — credit is spread across three different section formats and names are spelled
inconsistently.

## Always resolve the person first

Call `find_person` before any person-specific tool. It matches name fragments *and* email
addresses, and returns a canonical `person_id`. This matters because the corpus spells
the same person several ways:

- `J.R. Rao` is stored as an abbreviated name; searching `rao` finds him and Siddhartha Rao
- `Josiah Hagen` appears with three different employer strings, one of them a typo
- `Jason Garman` is credited under two different Amazon addresses

If `find_person` returns several people, ask which one rather than guessing.

## The affiliation rule — the one thing to get right

**Never state where someone currently works.** The graph does not know. It knows that a
person was credited under an employer in documents published on particular dates.

Every affiliation span comes back with `bounds_known: false`. Report it as an attested
range and nothing more:

- Good: "Credited under Trend Micro in documents published between 2025-07-14 and
  2026-01-08, and without an employer as of 2026-09-04."
- Wrong: "Works at Trend Micro." / "Left Trend Micro in January 2026."

Where someone worked *between* two attested spans has no answer here. `affiliation_at`
returns nothing for such dates deliberately. Say "not asserted" rather than interpolating.

Changes come back under `inferred_affiliation_changes` with `notBefore`/`notAfter` and
`inferred: true`. Quote the window: "left ServiceNow sometime after 2026-03-20 and by
2026-09-04."

A later document that omits an employer is **not** evidence someone left one. Sarah
Novotny is credited under GenLab once and with no employer in four later documents; the
graph records one span and no change, and so should you.

## Dates are about the original publication

`assertedAt` on a credit is the date the credit is evidence *about*. MCP Security was
revised to v2.0 on 2026-08-12 without refreshing its credit list, so its credits are
dated 2026-01-08. Two contributors appear there under employers they had already left.
Do not read those rows as employer changes.

## Approval status

Three documents are drafts: `agent-containment` (working draft, v0.2-skeleton),
`cosai-ai-telemetry-rfc` (working draft, v0.5) and `odis` (unapproved contributor draft).
`list_publications` and `who_contributed_to` both return `approval_status`. Surface it —
credit on an unapproved draft is not approved CoSAI work.

Two documents have no acknowledgements section at all (`addendum-mcp-and-pqc`,
`cosai-ai-telemetry-rfc`), so zero credits is a correct answer for them, not a gap. The
Telemetry RFC in particular has no credited contributors of any kind.

## Roles

Seven role types, from these verbatim labels in the source documents:

| Role class | Source labels |
| --- | --- |
| `WorkstreamLeadRole` | Workstream Leads |
| `EditorRole` | Editors, Editor |
| `ContributorRole` | Contributors |
| `ReviewerRole` | Reviewers |
| `TSCCoChairRole` | Technical Steering Committee Co-Chairs |
| `TSCReviewerRole` | TSC reviewers |
| `AuthorRole` | front-matter authors (ODIS only) |

`TSCReviewerRole` is a review role, not co-chairing. Tools accept plain words too:
`editor`, `lead`, `reviewer`.

One person can hold several roles on one document — Akila Srinivasan is both Reviewer and
TSC Co-Chair on the Shared Responsibility Framework, and Josiah Hagen is both Workstream
Lead and Editor on Zero Trust. Do not collapse these.

## Tools

| Need | Tool |
| --- | --- |
| Resolve a name or address to an id | `find_person` |
| A person's full credit record | `what_did_person_do` |
| Just the employer history | `affiliation_timeline` |
| Every inferred employer change, across people | `affiliation_timeline` |
| Credits on one publication | `who_contributed_to` |
| Everyone in a role | `list_people` |
| An organization's contributions | `org_contributions`, `list_organizations` |
| Documents in scope | `list_publications` |
| Anything else | `graph_schema` then `sparql` |

## Reporting

Cite the publication a claim comes from. `statedOrganization` is the employer verbatim as
printed — including `indepedent` in Zero Trust — and is the audit trail; use the canonical
name from the affiliation span when reporting, and mention the verbatim form only if the
discrepancy is the point.

Email addresses are in the graph and are returned by `what_did_person_do` only when
`include_addresses=true`. They are published in the source documents for contact, but do
not volunteer them unless asked.
