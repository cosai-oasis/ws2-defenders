# ADR-WS2-001: bubo-graphrag-mcp (Backed Up By Ontology): every answerable question about CoSAI, grounded in its own publications and data, served over MCP

**Status:** Draft - Pending Review
**Date:** 2026-09-21
**Authors:** Josiah Hagen (Lead), Vinay Bansal (Co-Lead)

---

## Context

This project builds a GraphRAG MCP server called bubo-graphrag-mcp (bubo), Backed Up By Ontology. Its primary
benefit is a tool that answers every answerable question about CoSAI from ground truth,
independent of any one model. An OWL/RDF representation supports lexical, semantic and
named-entity disambiguation, expresses the relationships between entities, indexes all of
CoSAI's knowledge content, and supports reasoning over the logic it represents. MITRE
D3FEND and SPDX 3.1 both use this representation, and the Risk Map should adopt it,
because its YAML is not expressive enough
([secure-ai-tooling#388](https://github.com/cosai-oasis/secure-ai-tooling/issues/388)).
Exposing the ontology through GraphRAG gives CoSAI's users a security tool that answers
truthfully what the CoSAI Risk Map implies for their specific needs. Along the way to the
full structured representation, the same graph answers other questions about CoSAI, such
as which groups are meeting and what they are doing, which delivers value immediately.

Two problems stand in the way. Contribution credit sits in prose "Contributors and
Acknowledgements" sections at the end of eleven whitepapers across five repositories, in
three structural formats, with inconsistent role labels, inconsistent organization names,
two email addresses for one person, and no stable identifiers — so "what has this person
worked on?" means reading eleven documents by hand. And the Risk Map is YAML that cannot
express the relationships #388 asks of it. Neither surface is queryable, and neither can
state what it does not know.

**Already built:** the contribution graph, the citation layer and the meetings layer
(`plan.md` §10.0). The meetings layer reads the archives of all eight CoSAI mailing lists,
which `ingest/groupsio.py` pages through with the groups.io `getmessages` API. That needs only the archive visibility an
open list grants, so any member's own key works. Each list is pulled with its full
history: 2,886 messages, back to June 2024 for the oldest list. The TSC and PGB are
modeled as governing bodies, distinct from the four workstreams that produce
publications. Steps 1 to 7 of `NEXT-STEPS.md` are designed and not built. Step 3
extracts what the archives hold and the graph does not yet emit: agendas,
schedule-change notices, the meeting date of each summary, and one governance action per
decision.

**Boundaries.** `plan.md` is the design record; `NEXT-STEPS.md` is canonical for the content
and ordering of steps 1 to 7; `TSC-QUESTIONS.md` holds what is not one person's to decide. This
ADR is canonical for the decisions below.

Those three, and the `registry/` and `reports/` paths cited throughout, live in the
`cosai-graphrag-mcp` working repository, which is private. The findings this ADR relies on
are restated here rather than left behind a link, so reviewing the decisions does not
require reading the repository.

**Data classification.** CoSAI is an open OASIS project. Its GitHub repositories,
including the contributor email addresses published in them, and its open groups.io
mailing lists and their archives are public repositories of **TLP:CLEAR** information.
Every source this ADR ingests is one of these, so no data here is restricted by its
classification. That includes workstream and SIG minutes once a group commits them to
its public repository: bubo reads the committed folder, never Drive, so it holds
no member-only source and no Drive credential.

## Decision

### D1. Ground in CCO v2.2 by MIREOT; bridge with SKOS only

BFO 2020 and CCO v2.2 supply the agent, role, event and temporal apparatus. About 35 terms
are MIREOT'd rather than importing ~1,200 classes, and every imported term carries an
`rdfs:label` and a comment naming it, because CCO IRIs are opaque numerics. Interoperability
with SPDX 3.1 Core and PROV-O is by `skos:closeMatch`. **No `owl:equivalentClass`, no
`owl:sameAs`, no `owl:imports` of CCO/BFO/SPDX/D3FEND.**

### D2. Nothing that can change is a bare edge

People, organizations, workstreams, publications and manifestations are continuants.
Publication, revision, authoring, affiliation-gain and -loss, citation and meeting events are
occurrents occupying temporal regions. Credited and affiliation roles are reified, so one
person can bear several at once. The effects are listed under Consequences.

### D3. No fabricated bounds

Affiliation intervals carry `earliestEvidence`, `latestEvidence` and `boundsKnown false`.
Derived change events carry `notBefore`, `notAfter` and `inferred true`. Neither carries a
bare start or end date, and nothing is interpolated between two attested spans.

### D4. A credit carried across a revision is dated to the original publication

The revision is a separate occurrent. This is what prevents the false "Bill Stout returned to
ServiceNow in August 2026" reading of the MCP Security v2.0 credit list.

### D5. Identity resolves through curated registries behind a human review gate

The parser emits a seed registry plus `reports/unresolved.md`; a human corrects it; every
build thereafter is deterministic. Upstream drift produces a reviewable diff, never a silent
overwrite. The person at the gate is never the person who wrote the parser.

### D6. Unresolved goes to a report, never to a guess

A person line, name variant or RM id that does not resolve is recorded as unresolved.
Attribution errors are the one class of defect this must not ship.

### D7. One OWL entry per Risk Map YAML id, never invented

A missing concept is fixed in the YAML upstream first. Validators and telemetry that look up
a `component_id` must resolve to a real entry. The catalog is regenerated rather than
curated, unlike the people and organization registries.

### D8. A rate without a named denominator does not ship

`Present ∪ Guests` over *what*? Attendance rates state their denominator in the tool output.

### D9. The server is retrieval-only, at MCP Security Level 1 / DP1

The server uses stdio transport, holds no credentials in the request path, exposes
purpose-built narrow tools, performs no writes, and writes diagnostics only to `stderr`,
because stdout carries the JSON-RPC stream. No tool calls a model; synthesis belongs to a
skill over the tools.

Credentials exist at **build** time only and the server holds none: `gh` for the corpus,
and a personal groups.io API key for the list archives. Each is the operator's own and
revocable; none is shared, and none reaches a request.

### D10. `SERVICE` and `LOAD` are refused at the `sparql` boundary

A `SELECT` carrying `SERVICE` is an arbitrary egress primitive — verified against this store,
where a probe at the cloud metadata address hung for two minutes. The query text is composed
by a model that has just read untrusted document prose. Read-only enforcement is not
sufficient.

### D11. Sources are TLP:CLEAR under OASIS policy; a hosted build has no `sparql` tool

Contributor addresses in GitHub and message content in the open list archives are
TLP:CLEAR (see Data classification under Context), so the graph, its tools and any hosted
build carry them as published. `emailSha256` is the identity matching key. The `data/mail/`
archives are untracked because they are fetched artifacts that anyone with a key can
reproduce.

If hosting happens, the boundary is the tool surface: `sparql` is absent from
the hosted profile because of what it can reach, not because of the data it reads.

### D12. The tool surface is decided before the store

The critical user journeys and the MCP tool surface land as **ADR-WS2-003**, ahead of the
graph-store choice in **ADR-WS2-004**, because "which reasoning profile do we need" is a
question about which queries must work. Hosting, if it happens, is **ADR-WS2-005**.

### D13. bubo is maintained, not only built

The graph, its OWL/RDF (the `cosaic:` ontology, its shapes and alignments, and the
`cosai:` Risk Map catalog) and the MCP server are kept current and correct after they
are built. Maintenance is event-driven, and each event has one
response:

- **An upstream source changes.** A new publication, a corpus pin advanced, or new list
  mail produces a registry diff for review under D5, never a silent overwrite. New
  people, affiliations and meeting series pass the same human gate as the first build.
- **The Risk Map YAML moves.** The catalog is regenerated under D7, and a renamed or
  removed id is deprecated before it is removed, under D14, so
  telemetry that recorded the old id still resolves.
- **A dependency or MCP SDK release.** The server's posture is re-verified before
  release: Level 1 / DP1 under D9, and the `SERVICE`/`LOAD` refusal under D10. The test
  suite is the gate; a failing test blocks the release.
- **A tool is added, renamed or removed.** The skills and their evals change in the same
  commit, and `graph_schema` names only relations the ontology declares; tests enforce
  both.

The Lead owns maintenance and holds merge authority for it. Handing it to another named
maintainer is a change to this decision, recorded as an amendment, so bubo always
has one.

### D14. Ontologies are versioned by SemVer, and the Risk Map's OWL/RDF form is `2.0.0`

Every ontology this project publishes carries a `MAJOR.MINOR.PATCH` version, the
standard `secure-ai-tooling#534` proposes for the Risk Map and CoSAI's other artifacts.
MAJOR is a change that invalidates data written against the previous version, or
changes what a term means, and a new schema is one. MINOR adds terms and leaves
existing data valid, as a new risk, control, component or persona does. PATCH changes
no entailment. `plan.md` §4.4 gives the rules in full.

- **Term IRIs carry no version.** The ontology header does: `owl:versionInfo`,
  `owl:versionIRI` as `<namespace>/<X.Y.Z>`, and `owl:priorVersion`, with each release
  recorded in a changelog.
- **A term is deprecated before it is removed**: `owl:deprecated` with
  `dcterms:isReplacedBy` in a MINOR release, removal only in a later MAJOR one. A
  renamed Risk Map id keeps resolving, to its replacement, so recorded telemetry does
  not break.
- **The Risk Map has one version line across its representations.** The YAML is
  `1.y.z` from its first tagged release; the OWL/RDF Risk Map is its major bump to
  **`2.0.0`**. From `2.0.0` on, the YAML and the OWL carry the same number, and the
  generator refuses to emit when they differ.
- **`cosaic:`, this project's contribution ontology, keeps its own line**, at `0.2.0`
  now and `1.0.0` from its first tagged release. It moves only when its own terms change.
- **What depends on a version names it.** The Risk Map catalog pins the YAML version it
  was generated from, each framework bridge pins a framework release, and the
  document-to-Risk-Map mapping names the Risk Map version it was curated against, to be
  re-reviewed at each MAJOR.

## Alternatives Considered

- **D3FEND 1.6.0 as the grounding ontology** — rejected. Not BFO-derived: no `owl:imports` at
  all, and BFO appears four times, as annotations on four of D3FEND's own properties. Its
  `Person`/`Organization` model the defended enterprise, not authorship.
- **SPDX 3.1 Core as the grounding ontology** — rejected. Zero BFO references, a single flat
  `spdx:Element` root, and no role apparatus, so it cannot distinguish Editor from Contributor
  from Workstream Lead. Kept as a SKOS bridge target.
- **OpenCRE** — rejected. Not an ontology; a Python application over `Document → CRE | Node`,
  with no agent terms.
- **A flat PROV-O or FOAF edge model** — rejected. It cannot record an affiliation whose
  bounds are unknown without inventing a start date or discarding the dates.
- **A labelled-property graph (Neo4j + n10s)** — rejected as the store. SPARQL 1.1 and native
  named graphs are lost, and the provenance partitioning depends on both. Re-testable with
  evidence in ADR-WS2-004.
- **Depending on `billbrietstout/ws2_ontology`** — rejected. v0.1.0 is neither authoritative
  nor a target. Three of its constraints are adopted independently because they are correct.
- **Fully automatic extraction without registries** — rejected. Given the observed variance,
  an automatic parser merges two people or splits one into three.

## Consequences

### Positive

Four effects follow from D2. `plan.md` §4.3 gives the model with worked Turtle.

**1. It lets the graph say what is known, and nothing more.** A flat edge — *person
`affiliatedWith` org* — asserts a present-tense fact. The corpus contains no present-tense
facts. It records that a person was credited under an employer in a document published on
a date.
Modeling affiliation as a **role borne over a temporal region**, gained and lost by events,
is what makes `boundsKnown false` and `notBefore`/`notAfter` expressible at all. In a flat
model the only ways to record *"credited under Trend Micro on 2025-07-14 and 2025-10-27,
start and end unknown"* are to invent a start date or to drop the dates. Both produce an
incorrect statement about a named individual. The same separation dates a credit carried
across a revision to the original publication, which is what prevents the unsupported
reading "Bill Stout returned to ServiceNow in August 2026".

**2. Events carry provenance, so conflicts surface instead of resolving.** Every occurrent
names its participants, the instant or interval it occupies, and the source that attested
it. Two sources asserting about one meeting produce two events, not one silently doubled
edge, which is why the store partitions by provenance and validates each partition
separately. Conflicts already present between the minutes and the graph (*Bill Stout (AI
Alliance non-voting)*, an affiliation not otherwise attested) are retained and reported. A
flat model resolves such a conflict at ingest, and an unreported resolution is an
attribution error.

**3. The event layer serves as the index.** Because every event occupies a temporal region and names its participants, the set
of events forms a join across every entry point a question can start from: a person, an
organization, a document, a section, a meeting series, a date range and a Risk Map
entity. The `PublicationEvent` reached from "what did this person work
on", from "what was published in Q3 2026", and from "who wrote about this risk" is **one
node**, not three secondary indexes requiring synchronization. The text index supplies
content; the event graph supplies the path to it and the citation for it. The layers
compose for the same reason: meetings, document sections and RM entities attach to the
same occurrents, so each layer extends the queries the others support.

**4. Roles are reified, so effort is distinguishable from credit.** One person can bear
several roles at once: Akila Srinivasan is both Reviewer and TSC Co-Chair on a single
document. Keeping `GitHubContributorRole` a separate class from the credited roles (step 6)
keeps "committed" distinct from "credited", so a typo fix is not counted as authorship.

### Negative

The model has more triples and more classes than a flat model, opaque numeric CCO IRIs,
and a learning curve for contributors familiar with SQL but not SPARQL. D1's labelling requirement
addresses the IRIs.

### Follow-up

This decision implies three others that it does not make: **ADR-WS2-003** (critical user journeys
and tool surface), **ADR-WS2-004** (graph store) and **ADR-WS2-005** (hosting, taken only if
the server is hosted). No item in `TSC-QUESTIONS.md` gates this work. The
orientation and contribution skills stay in this project, owned by this group, until a
need to move them arises.
