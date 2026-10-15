---
name: what-cited-this
description: Report who has cited CoSAI publications and how — external uptake, citation counts per work, and which organizations reference CoSAI guidance. Use for questions about impact, adoption, influence, or external references to CoSAI work. Triggers on "who cited", "what cites", "citation count", "impact", "who references", "uptake", "adoption", "is CoSAI cited by".
---

# What cited this

Citation data comes from the CoSAI TSC's own hand-verified dataset
(`cosai-oasis/cosai-tsc`, `TSC Deliverables/citation-impact/sources.json`, refreshed
weekly by a GitHub Action) via the `bubo` MCP server. It is authoritative —
prefer it over a web search, and cite it as the source.

As of the 2026-08-09 refresh: **146 citation relationships, 98 citing publications, 12
CoSAI works**, plus 8 publications that mention CoSAI without citing a specific work.

## Never report a bare total

Two distinctions in the data carry most of the meaning. Flattening them overstates what
is known.

**Category** — what kind of use:

| Category | Meaning |
| --- | --- |
| `Formal reference` | A numbered or linked bibliography entry |
| `Substantive work citation` | The citing work discusses or applies the content |
| `Organizational mention` | Names CoSAI but cites no specific work; contributes no work-level citation |

"28 publications cite MCP Security, 14 formally and 14 substantively" is a real answer.
"MCP Security has 28 citations" hides that half are applications rather than footnotes.

**Verification** — how strong the evidence:

| Level | Meaning |
| --- | --- |
| `Directly inspected` | Source retrieved and the citation read in place |
| `Search-index excerpt verified` | Established from a search excerpt; full text not retrievable |

Most are directly inspected. When a specific claim rests on a search excerpt, say so.

**Publisher relationship** matters for independence. The dataset marks whether a citing
publisher is a CoSAI sponsor, member-affiliated, contributor-affiliated, or unrelated. An
IBM document citing CoSAI is weaker evidence of external uptake than an unaffiliated one.
`what_cited_this` returns this per citation.

## Works outside this server's scope

The citation dataset covers 12 CoSAI works; this server holds documents for 7 of them.
`citation_summary` returns all 12 with `in_scope: false` on the other five:

- Principles for Secure-by-Design Agentic Systems — 26 citing publications
- CoSAI Risk Map — 14
- Project CodeGuard — 5
- The Future of Agentic Security: From Chatbots to Autonomous Swarms — 4
- Addressing What's Next in Securing Enterprise AI — 1

Principles is the second most cited CoSAI output overall. Omitting these would
misrepresent CoSAI's impact, so include them and note that this server does not hold
their text.

## Counting rule

Counts are **distinct citing publications per work**. A publication citing three works
appears under each, so the column does not sum to 98. When totalling, say which you mean:
relationships (146) or citing publications (98).

## Tools

| Need | Tool |
| --- | --- |
| Citations of one work, with full detail | `what_cited_this` |
| Counts across all 12 works | `citation_summary` |
| Anything else | `graph_schema` then `sparql` |

Publication ids for `what_cited_this` come from `list_publications`.

## Finding citations the dataset lacks

The dataset is authoritative for what is verified, not exhaustive. To look for
unrecorded citations:

```bash
python -m bubo_graphrag.citation.discover --only model-context-protocol-security --limit 10
```

This searches every surface form of a document — pinned and main-branch blob URLs, raw
URLs, the PDF, the repository root, OASIS and coalitionforsecureai.org announcements, and
registered short titles — and writes candidates to `reports/discovered-candidates.json` in
the TSC dataset's own schema so they can be contributed upstream.

Two caveats to pass on when reporting its output. Candidates are **search hits, not
verified citations** — the file marks them `Unverified candidate` and someone must inspect
them. And it uses GitHub code search, which indexes only a subset of repositories, so
finding nothing is weak evidence of absence. The tool prints hit accounting (hits,
self-references filtered, already-in-dataset) so a zero is interpretable; relay that
rather than a bare "none found".

## Reporting

Name the publisher and link the source URL. Distinguish government and standards-body
citations — the U.S. NSA formally cites MCP Security, and the App Defense Alliance applies
its threat model in an audit specification — from casual list inclusion. Note that a
government citation is not a government endorsement; the TSC report says so explicitly and
so should any summary of it.
