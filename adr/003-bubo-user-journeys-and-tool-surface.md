# ADR-WS2-003: bubo: critical user journeys and the MCP tool surface

**Status:** Draft
**Date:** 2026-11-20
**Authors:** Gavin Gucwa, Wenyi Li

---

## Context

[ADR-WS2-001 D12](001-bubo-graphrag-mcp.md) decides bubo's tool surface before its graph
store: "which reasoning profile do we need" is a question about which queries must work, so
the queries come first. This ADR records those queries as user journeys, and the tools
that serve them.

What exists: `bubo/src/bubo_graphrag/server.py` at `1b2a6a1` registers 22 MCP tools and two
resources (`cosai://ontology/cosai-contrib.ttl`, `cosai://registry/publications.yaml`).
`bubo/notebooks/prototype.ipynb` asks ten golden questions that between them reach all 22
tools, in the order a newcomer asks them. What does not exist: any statement of who the
tools are for, which tool each question needs, or what each tool must refuse. Without that,
a tool can be added or removed with nothing to test the change against.

The evidence behind every tool has limits that ADR-WS2-001 already fixes:

- Affiliation is attested on publication dates, with open bounds. No tool reports a
  current employer (ADR-WS2-001 D3).
- Identity resolves through curated registries; what cannot be resolved goes to a report,
  never to a guess (ADR-WS2-001 D5, D6).
- A rate without a named denominator does not ship (ADR-WS2-001 D8).
- The server is retrieval-only, and `sparql` refuses `SERVICE` and `LOAD` (ADR-WS2-001 D9,
  D10).

## Decision

### D1. Six critical user journeys

bubo serves six journeys. Each is anchored to golden questions in
`bubo/notebooks/prototype.ipynb` (numbered Q1 to Q10 as there), so a journey is a test, not
a description.

#### D1a. UJ-1 Orientation

- **Who:** a newcomer to CoSAI.
- **Goal:** find what the coalition is doing, which group fits, how to join it, and when it
  next meets.
- **Golden question:** Q1, "I'm joining CoSAI to work on agentic systems security. What is
  the coalition doing now, which group should I join, how do I subscribe, and when does it
  next meet?"
- **Tools:** `cosai_overview` → `how_to_get_involved` → `upcoming_meetings`.
- **Must refuse:** presenting a calendar entry as a meeting that will happen, or a derived
  subscribe link as confirmed.

#### D1b. UJ-2 Meetings

- **Who:** a contributor or workstream lead.
- **Goal:** find the group working on a topic, how often it actually meets, what it has
  announced, and which meetings have a record.
- **Golden questions:** Q2 (a group on AI-assisted code development, its rhythm and recent
  announcements), Q3 ("Which TSC meetings in 2026 have no minutes or recording, and how sure
  can you be?"), Q10 (whether WS3's cadence and cancellations changed).
- **Tools:** `find_meetings` → `meeting_rhythm` → `meeting_timeline` → `meeting_records`.
- **Must refuse:** reporting meeting counts as totals rather than as seen within the
  coverage window; treating a missing record pointer as proof that no record exists;
  reporting what a restricted record says.

#### D1c. UJ-3 A person's contributions

- **Who:** a member, a workstream lead, or the person themself.
- **Goal:** everything one person is credited with, and the affiliation each credit was
  made under.
- **Golden question:** Q4, "Brief me on Bill Stout: every credit, affiliation over time,
  what ServiceNow has contributed, and where Bill Stout works now."
- **Tools:** `find_person` → `what_did_person_do` → `affiliation_timeline` →
  `org_contributions`.
- **Must refuse:** naming a current employer. A grounded answer gives the last attested
  employer and the window an employer change fell in. Also refuses to pick one person when a
  name matches several.

#### D1d. UJ-4 Credit on a paper and by organization

- **Who:** an editor, a workstream lead, or a member organization.
- **Goal:** who is credited on a publication and in what role; which organizations and
  individuals have contributed most.
- **Golden questions:** Q5 (who edited Zero Trust for AI Systems, and everyone else credited,
  by role and credited affiliation), Q6 (organizations that contributed most, and the most
  prolific individuals outside governance and lead roles).
- **Tools:** `list_publications` → `who_contributed_to`; `list_organizations` →
  `org_contributions`; `list_people` → `what_did_person_do`.
- **Must refuse:** describing a draft's credits as approved work; reporting a credited
  affiliation as current.

#### D1e. UJ-5 Citation impact

- **Who:** a researcher or the TSC.
- **Goal:** which CoSAI works are cited outside the coalition, how, and by whom.
- **Golden question:** Q7, "Which CoSAI publication has the most external uptake, how does
  it split between formal references and substantive use, and who cites it?"
- **Tools:** `citation_summary` → `what_cited_this`.
- **Must refuse:** collapsing the category and verification split into one total, or
  presenting the TSC citation dataset as every citation that exists.

#### D1f. UJ-6 Governance and announcements

- **Who:** a TSC or PGB member, or a publication's editor.
- **Goal:** how a work was approved, what is in approval now, and how it was announced.
- **Golden questions:** Q8 (how the MCP Security paper was announced, which posts the TSC
  approved, and other blog posts this year), Q9 (how the PQC Addendum was approved, and what
  else is in approval).
- **Tools:** `approval_record` → `governance_timeline`; `what_announced_this`; for "other
  posts this year", `graph_schema` → `sparql`.
- **Must refuse:** treating no approval in the archive as no approval, outside the archive's
  coverage window; naming an author for a website post.

### D2. The tool surface is the 22 tools at `1b2a6a1`, and each serves a journey

A tool belongs on the surface only if a journey in D1 uses it. At `1b2a6a1` every tool
does:

| Tool | UJ-1 | UJ-2 | UJ-3 | UJ-4 | UJ-5 | UJ-6 |
| --- | :-: | :-: | :-: | :-: | :-: | :-: |
| `cosai_overview` | ✓ | | | | | |
| `how_to_get_involved` | ✓ | | | | | |
| `upcoming_meetings` | ✓ | | | | | |
| `find_meetings` | | ✓ | | | | |
| `meeting_rhythm` | | ✓ | | | | |
| `meeting_timeline` | | ✓ | | | | |
| `meeting_records` | | ✓ | | | | |
| `find_person` | | | ✓ | | | |
| `what_did_person_do` | | | ✓ | ✓ | | |
| `affiliation_timeline` | | | ✓ | | | |
| `org_contributions` | | | ✓ | ✓ | | |
| `list_publications` | | | | ✓ | | |
| `who_contributed_to` | | | | ✓ | | |
| `list_organizations` | | | | ✓ | | |
| `list_people` | | | | ✓ | | |
| `citation_summary` | | | | | ✓ | |
| `what_cited_this` | | | | | ✓ | |
| `approval_record` | | | | | | ✓ |
| `governance_timeline` | | | | | | ✓ |
| `what_announced_this` | | | | | | ✓ |
| `graph_schema` | | | | | | ✓ |
| `sparql` | | | | | | ✓ |

`graph_schema` and `sparql` are the escape hatch for questions no named tool answers. They
stay on the local surface for that reason, and a hosted build drops `sparql` (ADR-WS2-001
D11). A question that needs `sparql` more than once is a candidate for a named tool.

A new tool is added in the same change as the journey, or the golden question, that needs
it. A tool no journey uses is removed or given one.

### D3. A tool's refusal is part of its contract

What a tool must not claim is specified with the tool and tested with it, not left to the
client. The server's answers are read by different models (the notebook compares three), so
a limit stated only in a client prompt holds for one client at most.

| Tool | Returns | Must not claim |
| --- | --- | --- |
| `find_person` | canonical person id(s) for a name or address | one person, when the match is ambiguous |
| `what_did_person_do` | credits, and affiliation as attested ranges (`bounds_known: false`) | a current employer |
| `affiliation_timeline` | attested spans and inferred change windows | a change date, or an employer between two attested spans |
| `list_people` | people ranked by publications credited | participation beyond publication credit |
| `list_publications` | works with dates, version and approval status | a draft as approved work |
| `who_contributed_to` | credits on one work by role, with credited affiliation | that credited affiliation is current |
| `org_contributions` | credits made while affiliated with an organization | credits outside an attested span |
| `list_organizations` | organizations with credited-people counts | a complete directory of members |
| `what_cited_this` | citing works with category and verification | a single total; completeness |
| `citation_summary` | counts per work, out-of-scope works flagged | completeness beyond the TSC dataset |
| `cosai_overview` | groups, rhythm, recent work, and the coverage window | meeting counts as totals |
| `how_to_get_involved` | groups, lists, rhythm | a derived subscribe link as confirmed |
| `find_meetings` | series matching a topic, ranked by directness | that a rank-3 match works on the topic itself |
| `meeting_timeline` | announced meetings, cancellations, how each date was established | that an announced meeting was held |
| `meeting_rhythm` | observed cadence from held meetings, and changes | a stated schedule as observed cadence |
| `meeting_records` | which meetings have record pointers | what a restricted record says; that no pointer means no record |
| `upcoming_meetings` | calendar entries after the read date | that an entry will be held |
| `approval_record` | each governance call on a work, by body and stage | rejection, from a missing close |
| `governance_timeline` | review periods, ballots, approvals | outcomes the mail does not record |
| `what_announced_this` | posts linking a work, with a blog post's TSC approval | a post's author |
| `graph_schema` | vocabulary and data conventions | that a term implies a fact exists |
| `sparql` | read-only query results | anything from `SERVICE` or `LOAD`, which are refused |

### D4. Journeys bubo cannot yet serve

**UJ-7 Attendance and leadership** (who attended a group's meetings, at what rate, and who
leads it) needs meeting minutes, which `1b2a6a1` does not ingest. Three tools are reserved
for it: `meeting_attendance`, `attendance_rate` (which must name its denominator, the
eligible meetings and the coverage window, per ADR-WS2-001 D8) and `who_leads` (which must
not present past leadership as current). Until they land, `cosai_overview` and
`graph_schema` state that attendance is not held, and any attendance question gets that
answer.

### D5. What the journeys ask of the graph store

For ADR-WS2-004, the journeys in D1 need the store to answer:

- interval queries over attested spans with open bounds, returning no result between two
  spans rather than an interpolated one (UJ-3, UJ-4);
- one named graph per layer (`publications`, `citations`, `maillist`, `website`,
  `calendar`), queried as their union, with `maillist`, `website` and `calendar` optional:
  a journey that needs a missing layer says so rather than answering from the rest
  (UJ-1, UJ-2, UJ-6);
- read-only SPARQL 1.1 with `SERVICE` and `LOAD` refused at the boundary (UJ-6);
- every coverage window a tool reports, so a tool can bound its own answer (UJ-1, UJ-2,
  UJ-6).

Whether any journey needs OWL reasoning beyond what the build already materializes is left
to ADR-WS2-004.

## Alternatives Considered

- **Tools per data source** (one for credits, one for mail, one for citations): rejected
  because questions cut across sources. UJ-3 joins credits to affiliation spans and to
  organizations, and a source-shaped surface leaves that join to the model.
- **`sparql` and `graph_schema` only**, letting the model write every query: rejected
  because the query text is composed by a model that has just read untrusted prose
  (ADR-WS2-001 D10), and because conventions such as `bounds_known: false` and
  "counts are seen, not totals" live in the named tools' output. A raw query result carries
  neither.
- **Refusals in client skills or system prompts only:** rejected because bubo serves any
  MCP client, and the notebook already compares three model providers. A limit the tool
  states is seen by every client.

## Consequences

### Positive

- Each tool has a reason to exist that can be tested: a journey and a golden question.
- Each refusal is written down beside its tool, so Evals can test it directly.
- ADR-WS2-004 gets a concrete list of the queries the store must answer.

### Negative

- Users get "not held" for questions the evidence cannot support, such as a current
  employer or an attendance rate, even when a plausible guess exists.
- The journey list, the coverage table in D2 and `server.py` must change together. A
  tool added without a journey makes this ADR wrong.
- The journeys reflect a newcomer's and a member's questions. Questions from outside the
  coalition beyond citations (press, other standards bodies) are not yet represented.

### Follow-up

- **Evals:** one test per golden question, checking the tools reached; one test per row of
  the D3 table, checking the refusal.
- **Ingest:** minutes parsing for UJ-7, and the three reserved tools in D4.
- **ADR-WS2-004:** the graph store, from the requirements in D5.
- **This ADR:** re-check D2 against `server.py` whenever a tool is added or removed, and
  record the new commit.
