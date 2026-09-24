# ADR-WS2-001: A CoSAI Oracle — every answerable question about CoSAI, grounded in its own publications and data, served over MCP

**Status:** Draft — binding from Fall week 1 (2026-09-28)
**Date:** 2026-09-21
**Authors:** Josiah Hagen (Lead), Vinay Bansal (Co-Lead)

---

> **These decisions become binding in Fall week 1 — the week of 2026-09-28.** Until then
> this is a first specification that nobody has approved, and any part of it is open to
> being argued with at no cost. From week 1 the D-numbers below are the contract the
> cohort builds against and CI cites: changing one is an amendment with a dated section,
> not an edit, and a reversal needs a superseding ADR. Raise objections before then.

## Context

This project builds a GraphRAG MCP server that serves as a CoSAI Oracle. Its primary
benefit is a tool that answers every answerable question about CoSAI from ground truth,
independent of any one model. An OWL/RDF representation supports lexical, semantic and
named-entity disambiguation, expresses the relationships between entities, indexes all of
CoSAI's knowledge content, and supports reasoning over the logic it represents. MITRE
D3FEND and SPDX 3.1 both use this representation, and the Risk Map should adopt it,
because its YAML is not expressive enough
([secure-ai-tooling#388](https://github.com/cosai-oasis/secure-ai-tooling/issues/388)).
Exposing the ontology through GraphRAG gives CoSAI's users a security oracle that answers
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
ADR is canonical for the decisions below, and for who builds them and when.

Those three, and the `registry/` and `reports/` paths cited throughout, live in the
`cosai-graphrag-mcp` working repository, which is private. The findings this ADR relies on
are restated here rather than left behind a link, so reviewing the decisions does not
require reading the repository.

**Data classification.** CoSAI is an open OASIS project. Its GitHub repositories,
including the contributor email addresses published in them, and its open groups.io
mailing lists and their archives are public repositories of **TLP:CLEAR** information.
Every source this ADR ingests is one of these, so no data here is restricted by its
classification. That includes workstream and SIG minutes once a group commits them to
its public repository: the Oracle reads the committed folder, never Drive, so it holds
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
the hosted profile (§6.6) because of what it can reach, not because of the data it reads.

### D12. The tool surface is decided before the store

The critical user journeys and the MCP tool surface land as **ADR-WS2-003**, ahead of the
graph-store choice in **ADR-WS2-004**, because "which reasoning profile do we need" is a
question about which queries must work. Hosting, if it happens, is **ADR-WS2-005**.

### D13. The Oracle is maintained, not only built

The graph, its OWL/RDF (the `cosaic:` ontology, its shapes and alignments, and the
`cosai:` Risk Map catalog) and the MCP server are kept current and correct after the
Fall and Winter milestones end. Maintenance is event-driven, and each event has one
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
maintainer is a change to this decision, recorded as an amendment, so the Oracle always
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
organization, a document, a section, a meeting series, a date range and, from v3, a Risk
Map entity. The `PublicationEvent` reached from "what did this person work
on", from "what was published in Q3 2026", and from "who wrote about this risk" is **one
node**, not three secondary indexes requiring synchronization. The text index (v2) supplies
content; the event graph supplies the path to it and the citation for it. The milestones
compose for the same reason: v1's meetings, v2's sections and v3's RM entities attach to the
same occurrents, so each extends the queries the earlier ones support.

**4. Roles are reified, so effort is distinguishable from credit.** One person can bear
several roles at once: Akila Srinivasan is both Reviewer and TSC Co-Chair on a single
document. Keeping `GitHubContributorRole` a separate class from the credited roles (step 6)
keeps "committed" distinct from "credited", so a typo fix is not counted as authorship.

### Negative

The model has more triples and more classes than a flat model, opaque numeric CCO IRIs,
and a learning curve for contributors familiar with SQL but not SPARQL. D1's labelling requirement
addresses the IRIs; §8 allocates weeks 1–2 to the learning curve.

### Follow-up

This decision implies three others that it does not make: **ADR-WS2-003** (critical user journeys
and tool surface) and **ADR-WS2-004** (graph store) in week 2; **ADR-WS2-005** (hosting) only
if §6's preconditions hold. No item in `TSC-QUESTIONS.md` gates committed work. The
orientation and contribution skills stay in this project, owned by this group, until a
need to move them arises.

---

# Project plan

Eight weeks in Fall, four in Winter, delivering D1–D14 in the order below. Where this plan
and `NEXT-STEPS.md` disagree on *what* a step contains, `NEXT-STEPS.md` wins; on *when* or
*who*, this plan wins.

## 0. The team

| | Who | Commitment | Obligation |
| --- | --- | --- | --- |
| **Lead** | Josiah Hagen | Weekly | Technical direction, merge authority, the invariants D1–D14, registry countersign, integration, maintenance under D13 |
| **Co-Lead** | Vinay Bansal | Weekly | Coalition interface, contributor onboarding, TSC escalation |
| **Students** | Four, one per role in §1 | Fixed calendar | The critical path. Milestones v1, v2 and v3 are theirs |
| **CoSAI contributors** | Two | Variable, and may lapse | Issue-based. **Never on the critical path** |

The two populations are managed differently, and conflating them is the main way a project
of this shape fails. Students have a fixed calendar and a deliverable obligation. CoSAI
contributors are working professionals volunteering around a day job; their time is real but
unpredictable, and any plan that puts a milestone behind a volunteer's week is a plan that
slips. So:

> **Volunteer work is detachable.** Everything in the curation lane (§1) is chunked into
> issues that can be picked up, finished in one or two sittings, and dropped without
> stranding anyone. If a contributor disappears for three weeks, no milestone moves.

### Assumptions, and how to change them

| Assumption | Value | If it changes |
| --- | --- | --- |
| Fall week 1 | Week of **2026-09-28** | Shift the whole Fall table together; week 8 ends Fri 2026-11-20, clear of Thanksgiving (2026-11-26) |
| Winter week 1 | Week of **2027-01-04** | Winter week 3 contains MLK Day (2027-01-18) and is planned light |

If the team changes, roles and scope are adjusted then. The full scope of steps 1, 4, 5.1
and 5.2 does not fit in eight weeks, which is why §4 splits every milestone into
*committed* and *stretch*.

---

## 1. Two lanes, and a role for each student

**Build lane.** The four students, each in the role below, on the critical path
**sequentially**: v1, then v2, then v3. Every milestone draws on all four roles, so the
lane moves as one team rather than splitting into parallel tracks.

**Curation lane.** The two CoSAI contributors, plus any student overflow, on a standing
backlog of issues. Curation work depends on domain judgment rather than code, which is what
CoSAI contributors supply, and it has the highest value per hour in the project: the
registry review, the document↔RM candidate rows, framework mapping judgment, and golden
questions. The lane always works **one milestone ahead** of the build lane, so its output
arrives before it is needed rather than after.

### Roles

| Role | Responsibility |
| --- | --- |
| **Ontology** | Terms and queries |
| **Pipeline** | Use cases, workflow, tracking; registry gatekeeper and contributor wrangler |
| **Evals** | Tests per skill and per parser, end-to-end tests, and security tests at *MCP Security* Level 1 / DP1 |
| **Ingest** | Scraping data; proposes terms to Ontology and tools to Evals |

Roles say who owns what, not who may touch it.

---

## 2. Working rules

- **A weekly meeting.** Its slot is set in week 1, against the CoSAI meeting calendar.
  Students attend; contributors are invited and obligated to none of it.
- **Slack for asynchronous communication.**
- Contributors' interface is the issue tracker, and the wrangler's job is that the tracker
  always has something worth an evening.
- A demo at the weekly meeting is working software or a failing test, never slides.
- Short-lived branches, a PR to `main`, one review and CI green. Reviews rotate among the
  team as work comes up. A contributor's first PR is reviewed the same week, because
  latency is what loses volunteers.
- Test quality and coverage, not test count. Every behavior a tool promises, and every
  failure mode it reports, has a test that would fail if it broke; a PR that removes one
  says what now covers it.
- Every parser lands with its fixture in `tests/fixtures/` **before** it lands with its code.
- Unresolved anything, whether a person line, a name variant or an RM id, goes to a report
  under `reports/`, never to a guess. An absence correctly reported beats a plausible
  answer invented, as in the golden answer *"Was Bill Stout at ServiceNow in Aug 2026?"*
  → **Unknown/not asserted** (`plan.md` §11).
- Cite D1–D14 by number in review comments, commit messages and validator output, so each
  check names the decision it enforces. The ones that catch people most often are **D3**,
  **D5**, **D8** and **D10**.
- An outcome note from each weekly meeting is appended to `SESSION-NOTES.md`, including what
  the week cost in tokens.

---

## 3. Fall, week by week

| Week | Of | Build lane | Curation lane | Gate |
| --- | --- | --- | --- | --- |
| 1 | 2026-09-28 | Form, working rules, onboarding | Onboarding, backlog | Charter + first issues assigned |
| 2 | 2026-10-05 | Background evaluation, tool surface, store decision | Briefs, CUJs | **ADR-WS2-003 + ADR-WS2-004** |
| 3 | 2026-10-12 | Step 1.1–1.4 minutes | `governance-roles.yaml` seed | |
| 4 | 2026-10-19 | Step 1.5–1.9, tools | Registry review | **v1** |
| 5 | 2026-10-26 | Step 4.1 sections | Golden questions for search | |
| 6 | 2026-11-02 | Step 4 chunks, FTS5, tools | Doc↔RM candidate scouting | **v2** + hosting decision (§6.8) |
| 7 | 2026-11-09 | Step 5.1 RM generator | RM YAML gap review | |
| 8 | 2026-11-16 | Step 5.2 namespace + policy | Deprecation policy review | **v3** |

---

### Week 1 — Form, working rules, onboarding

**Goal.** A team that can make decisions, standing inside CoSAI to make them with, and a
backlog good enough to keep two volunteers productive.

1. **Roles.** Confirm each student's role under §1.
2. **Working rules.** Set the weekly meeting's slot against the CoSAI meeting calendar, so
   conflicts surface now rather than in week 5, and open the project's Slack channel.
3. **Environment.** Everyone runs the repo by the end of the week: `pip install -e ".[dev]"`,
   fetch, build and `pytest -q`, all passing. Python ≥3.11.
4. **Onboard the two CoSAI contributors.** The Co-Lead owns this, and it is a week-1
   deliverable. Issues are assigned to queue up the work, each finishable in one sitting
   and none requiring `plan.md` to be read first.
5. **Also recruit** a named TSC sponsor, and make contact with issue
   [#388](https://github.com/cosai-oasis/secure-ai-tooling/issues/388) and with the author of
   `billbrietstout/ws2_ontology`. The latter is **not a dependency** (`plan.md` §3.7), and
   the contact is to avoid duplicating it, not to adopt it.
6. **Paperwork, now, because it has latency.** Every student and contributor who will
   contribute upstream needs an OASIS Open Project iCLA on file. The repo is Apache-2.0;
   upstream contribution rules are CoSAI's. If it is not started in week 1, it blocks the
   Winter PR.
7. **Budget.** Decide who owns the model API account, and the weekly cap. The cheap lever
   `NEXT-STEPS.md` names is fewer cache invalidations: **fresh sessions with tight scope**,
   not terser work.

**Exit criteria.** A one-page charter in the repo (roles, working rules, budget cap,
escalation path). Tests passing on every machine. Each contributor has a first issue
assigned.

---

### Week 2 — Background evaluation, the tool surface, and the graph store

**Goal.** The team can defend the existing design choices, has written down what the system
is *for*, and has made one substantial architectural decision with evidence behind it.

**Evaluation.** Split the reading; every item gets a **one-page written brief**, presented
at the weekly meeting. The briefs are the deliverable, not the reading. The two
contributors are good candidates for the CoSAI-internal briefs, since they may already
know the material, which makes a brief cheap for them and valuable to the students.

*Within CoSAI:*

| Material | Question the brief answers |
| --- | --- |
| The 11 in-scope whitepapers (`plan.md` §2) | What is each about in three sentences, and what shape is its credit section? |
| `cosai-tsc` `TSC Deliverables/citation-impact/` | What is already solved here that we must not rebuild? (`plan.md` §3.5) |
| Risk Map YAML, `main` vs `develop` | What is the shape of a risk, control, component, persona — and what changed? (26 → 46 components) |
| Issue #388 | What does the Epic ask for, and where has this repo already converged with it independently? |
| TSC/PGB minutes in public git | What does a `**Present:**` block look like, and how many distinct line shapes across 104 files? |
| `secure-ai-tooling` ADR-031 / ADR-033 | What must a skill look like to be contributable upstream? |
| MCP Security §3.3 | What deployment level is this server, and what would push it to Level 2? |

*External:*

| Material | Question the brief answers |
| --- | --- |
| BFO 2020 | What is the continuant/occurrent divide, and why must affiliation be a role rather than an edge? |
| CCO v2.2 | Which five modules do we MIREOT, and why MIREOT rather than `owl:imports`? |
| SHACL | How does a shape differ from an OWL axiom, and which do we want where? |
| PROV-O, SPDX 3.1 Core | What do the SKOS bridges buy, and why not `owl:equivalentClass`? |
| D3FEND 1.6.0, ATT&CK, ATLAS | What is the real join key to a CoSAI control, given the corpus has zero framework ids? |
| NIST AI RMF 1.0 + CSF 2.0, OWASP LLM Top 10, OpenCRE | What granularity does each map at? These are Winter's targets |

**ADR-WS2-003 — the critical user journeys and the MCP tool surface.** The Pipeline and
Ingest students write it, **before** the store decision, because the store decision cannot be made without it: criterion 2 below asks
which reasoning profile we actually need, and that is a question about which queries have to
work.

What this ADR specifies:

- **The critical user journeys**, in a user's words rather than the schema's. The milestone
  demo questions in §4 and the Winter journey in §5 are the starting set — *how often does
  WS4 meet and who actually attends*, *which passage says how to contain an agent*, *what
  risks does this component carry and has its id been renamed*. Each CUJ names its actor —
  practitioner, newcomer, TSC member, workstream lead — and what they do with the answer.
- **The tool that serves each**, against the nineteen already built (`plan.md` §9) and the
  ones each milestone adds: `meeting_attendance` / `attendance_rate` / `who_leads` at v1,
  `search_documents` / `get_section` at v2, `rm_search` / `rm_entity` / `rm_change_log` at
  v3. A journey with no tool is either a gap to schedule or a journey to drop; a tool with
  no journey is scope creep with a docstring.
- **The refusals.** For each tool, what it must decline to answer and the shape of the
  decline: no current employer, no rate without a named denominator, no interpolation
  between attested spans. On this project the refusals define the surface as much as the
  returns do, and writing them here is what stops each milestone renegotiating them.
- **Retrieval only.** No tool calls a model and the server holds no key (`plan.md` §9). A
  journey needing synthesis is served by a *skill* over the tools, not by a smarter tool.
- **Which journeys are out of scope this term**, so the surface does not grow by drift.

Deliberately not in this ADR: implementations. It fixes the contract; the milestones build
against it, and §4's demo questions become its acceptance tests.

**ADR-WS2-004 — the graph store.** The Evals and Ontology students write it. This is a
real decision. The incumbent is `pyoxigraph` + sqlite FTS5
behind `src/cosai_graphrag/store.py`, chosen when the graph was ~15k triples of asserted
facts. Step 5 changes the requirement: `NEXT-STEPS.md` step 5 wants the corpus **deductively
expressed**, and pyoxigraph has no reasoner.

The criteria, in order of weight:

1. **Named-graph support** — non-negotiable; the four-way provenance partitioning, each
   partition validated alone against a class allowlist, cannot be built without it.
2. **Reasoning** — which profile do we *actually* need: OWL-RL materialization, EL
   classification, or Datalog rules? Answer with a query we want to work and that today does
   not, which ADR-WS2-003's journeys supply, before ranking any engine.
3. **SHACL** — native, or `pyshacl` alongside.
4. **Deployment posture** — this project is classified as *MCP Security* §3.3.1 Level 1 /
   DP1 (`plan.md` §12.7), and a store needing a network-listening process changes that.
   This is a security decision, not an operations one.
5. **License and cost** for a student team; **Python binding** quality; **swap cost** given
   the `store.py` seam.

The candidates, a paragraph each, are pyoxigraph (incumbent), Apache Jena + Fuseki, Ontotext GraphDB
Free, RDFox (free academic license, Datalog, incremental), Stardog (academic), QLever,
Virtuoso. Neo4j + n10s should be evaluated and most likely **rejected in writing** — it is a
labeled-property graph, and the SPARQL 1.1 and named-graph losses are the reason, not a
preference.

**The recommendation to beat:** keep pyoxigraph as the runtime store and add reasoning as an
**offline materialization step at build time** — reason with a heavier engine, load the
closure into pyoxigraph, keep the served runtime embedded, dependency-free and Level 1. This
preserves the `store.py` seam and the deployment posture at once. Confirm it with a
benchmark or overturn it with evidence; "we prefer X" is not a finding.

**Exit criteria.** Briefs in the repo. **ADR-WS2-003 and ADR-WS2-004 merged** — decision, rejected options, the
reason each was rejected, and how to override it later, in the style of `plan.md` §12. If the
decision is to swap, a spike branch proving `store.py` absorbs it without touching callers.

---

### Weeks 3–4 → **v1: CoSAI publications and meetings**

`NEXT-STEPS.md` step 1. This section schedules its sub-steps; the step gives their full
detail.

**Week 3 — build lane**

- **1.1 Re-scope `NoFabricatedAttendanceShape`** — blocking. It forbids `AttendanceRole`
  globally; it belongs to the mail graph's shape alone.
- **1.2 Split the meetings graph** into `graph/meetings-mail` and `graph/meetings-minutes`
  with explicit ownership — blocking, and the Lead's first integration job.
- **1.3 `ingest/minutes.py`** — the `**Present:** / **Regrets:** / **Guests:**` block and the
  quorum line, reusing `credits.py`'s bold-label machinery. The 2024-09-27 file predates the
  format and is a fixture, not a bug.
- **1.4 Person-line disambiguation** — the hard part. `(OpenAI)` is an organization,
  `(WS2 co-lead)` is a role, `(PGB co-chair, Google alternate \- left 35 min. in)` is both
  plus an annotation.

**Week 3 — curation lane.** Seed `registry/governance-roles.yaml` from the minutes by hand.
This is a contributor's ideal first task: it needs CoSAI knowledge, not Python, and it
unblocks 1.4.

**Week 4 — build lane**

- **1.5 Registry review gate** — the Pipeline student, countersigned by the Lead or Co-Lead. The minutes already
  contradict the graph: *Bill Stout (AI Alliance non-voting)* is an affiliation not held,
  *Dalton House (Trend Micro)* a person not known.
- **1.6 `build/minutes.py`** with its own SHACL shape.
- **1.7 Tools** — `meeting_attendance`, `attendance_rate(group, by=…)`, `who_leads(group)`.
  `Present ∪ Guests` over *what*? Each rate states its denominator in the tool output (D8).
- **1.8 Skill update** — flip the orientation skill's attendance refusals.
- **1.9 Model additions** — `MemberAttendance` / `GuestAttendance`; `DeclaredAbsence`, which
  is **not a role**; `GroupLeadershipRole`, `AlternateRole` and voting status, all
  evidence-anchored with open bounds like `AffiliationRole`.

**Week 4 — curation lane.** Contributors review the proposed registry diff line by line. This
is the highest-value use of volunteer time in the term: the reviewers were present at the
meetings whose attendance records they are checking.

---

### Weeks 5–6 → **v2: document decomposition**

`NEXT-STEPS.md` step 4.

**Week 5 — build lane**

- **`ingest/sections.py`** — heading tree, TOC stripping (`plan.md` §7 pitfall 4: the ack
  heading occurs twice in `agentic-identity-and-access-control.md`, at offset 2788 in the TOC
  and 43614 in the body — **take the last occurrence**), section-scoped chunks anchored to
  stable heading IRIs.
- Escaped and numbered headings (`## 8\. Acknowledgements `, `## 7.1. Workstream Leads`) each
  get a fixture.

**Week 6 — build lane**

- **`build/chunks.py`** over sqlite FTS5. BM25 first. Local `sentence-transformers` embeddings
  **only if** BM25 underperforms on the golden set — and "underperforms" means a number
  against a written golden set, decided before the experiment, not after.
- **Tools** — `search_documents(query, publication?)`, `get_section(publication, heading)`,
  both returning the heading path so every answer is citable to a passage.
- Stability check: heading IRIs survive a revision that does not touch the heading. If they
  don't, Winter's document↔RM mapping rots on the first upstream update.

**Curation lane, weeks 5–6.** Write the golden set — questions with the passage that should
come back — then start scouting document↔RM candidates. That scouting is Winter week 1's
input, arriving six weeks early, which is how a four-week Winter becomes feasible.

---

### Weeks 7–8 → **v3: CoSAI RM as OWL/RDF**

`NEXT-STEPS.md` steps **5.1 and 5.2 only**. Steps 5.3 to 5.6 are Winter and beyond, and saying so
in week 1 is the purpose of §4's committed/stretch split.

**Week 7 — build lane.** **5.1 The generator** over `risk-map/yaml` on `develop`, emitting
the `cosai:` namespace (reserved and unused until now). **One OWL entry per YAML id. Never
invent one** — if a concept is missing (PDP, PEP, tool registry, wallet, merchant, payment
network) the YAML changes first, upstream. The RM **tracks** upstream rather than snapshotting
it: `develop` carries 46 components against `main`'s 26 and more lands during the term, so pin
a commit per milestone, re-pin at each gate, review the diff. The catalog is **regenerated,
never curated** — the opposite of the people/org registries, and the team should be able to
say why. Rows are individuals and categories are classes. Matching is SKOS.

**Week 8 — build lane.** **5.2 Versioned namespace and deprecation policy** — a
prerequisite, not polish: emitted telemetry is an immutable historical record, so a renamed id
silently invalidates every stored event carrying it. Write the policy as a document first,
implement second, to D14's rules. Then come the RM partition's SHACL shape, the freeze,
the `2.0.0` tag, and a written handover to Winter.

**Curation lane, weeks 7–8.** Every concept the one-entry-per-id rule shows to be *missing*
from the upstream YAML becomes an issue filed against the Risk Map repository. That is a
genuine contribution to CoSAI produced as a by-product of building the generator, and it is
contributor work, not student work — it needs standing in the coalition.

---

## 4. Milestones: committed vs stretch, and definition of done

Each milestone is defined by a question the system can newly answer, in the style of
`plan.md` §11's golden answers. A gate that demos a diagram instead of an answer has not
landed.

**Committed** is what the milestone ships. **Stretch** is what it ships if time allows.
Stretch items are not failures when they don't land; they are the buffer that protects the
committed scope.

### v1 — CoSAI publications and meetings (end of week 4)

| | |
| --- | --- |
| **Demo question** | "How often does WS4 actually meet, who attends, and what was this person's affiliation in March 2026?" |
| **Correct answer shape** | An attendance rate **with its denominator named**; an affiliation with `bounds_known: false` and an inferred change window carrying `notBefore`/`notAfter`; a date between two attested spans returns **nothing**, not an interpolation |
| **Committed** | Step 1 entire: `ingest/minutes.py`, `build/minutes.py`, `governance-roles.yaml`, split meetings graphs each with its own shape, the three tools, updated orientation skill |
| **Stretch** | Step 2 (workstream and SIG minutes from GitHub), for each group that has committed its `meeting_minutes/` folder; step 3 (agendas, schedule changes and governance actions from the list archives). Neither has a TSC gate |
| **Tests** | ≥3 per parser; the 2024-09-27 pre-format file; a `(PGB co-chair, Google alternate \- left 35 min. in)` regression; both known graph contradictions resolved or reported |
| **Gate** | Registry diff reviewed and countersigned. No person or affiliation entered the graph without a human reading the line it came from |

### v2 — Document decomposition (end of week 6)

| | |
| --- | --- |
| **Demo question** | "Which passage of which CoSAI paper says how to contain a highly capable model?" |
| **Correct answer shape** | A chunk with its heading path, publication and approval status — so a draft is never presented as approved guidance |
| **Committed** | `ingest/sections.py`, `build/chunks.py`, FTS5 index, `search_documents`, `get_section`, a written golden set with measured BM25 performance |
| **Stretch** | The `cosai-doc-search` skill with portable `evals/evals.json`; embeddings, only if the golden set says BM25 is insufficient |
| **Tests** | TOC excluded (the double-heading case); heading anchor correct; cross-document query; escaped and numbered headings |
| **Gate** | Heading IRIs stable across a no-op revision. **Also the one-time hosting decision (§6.8)** — Phase A, a later phase, or no |

### v3 — CoSAI RM OWL/RDF (end of week 8)

| | |
| --- | --- |
| **Demo question** | "What is this Risk Map component, which risks does it carry, which controls address them — and has its id ever been renamed?" |
| **Correct answer shape** | Every entity traceable to exactly one upstream YAML id; a rename surfaced, never silently applied |
| **Committed** | The generator tracking `develop`; the `cosai:` catalog released as Risk Map **`2.0.0`** under D14; the versioned namespace and a **written** deprecation policy; `rm_search` and `rm_entity`; the RM SHACL shape |
| **Stretch** | `rm_change_log` implemented rather than specified; `rm_component_exposure`, `rm_persona_profile`, `rm_lifecycle_view`; step 6 (GitHub contribution activity) |
| **Tests** | Round-trip every YAML id to exactly one OWL entry and back; a fabricated-id test that **must fail the build**; regeneration against a newer upstream commit produces a reviewable diff |
| **Gate** | Deprecation policy reviewed by the CoSAI sponsor — telemetry consumers are downstream of it |

---

## 5. Winter — cross-framework mapping and constraint enrichment (4 weeks)

`NEXT-STEPS.md` steps **5.3, 5.4 and part of 5.6**, plus the constraint work the Fall
milestones make possible. Depends on v2's section index and v3's stable namespace; if either
slipped, Winter week 1 absorbs the slip and week 4's scope is cut, not week 1's quality.

Four weeks is short, so the curation lane's Fall head start on document↔RM candidates is not
a nicety — it is the reason the schedule closes.

### Winter week 1 (2027-01-04) — `registry/document-rm-mapping.yaml`

The corpus contains **zero RM ids**, confirmed by grep, and almost no external framework
ids (`plan.md` §3.6). Document↔RM linkage is therefore **curated and can never be
extracted**. Curate at *section* granularity against v2's index, starting from the Fall
candidate list.

Each row records the RM entity, the passage, the confidence and the curator. Two people
confirm every row. Entities nobody can find a passage for are the input to `rm_publication_coverage` — an
absence, recorded, is the finding.

### Winter week 2 (2027-01-11) — Framework bridges via SKOS

One alignment file per framework, **each pinned to a framework release**, all SKOS —
`skos:exactMatch` / `closeMatch` / `broadMatch`, never `owl:equivalentClass` or `owl:sameAs`.

- **Committed: one framework, done properly.** D3FEND 1.6.0 or NIST AI RMF 1.0 + CSF 2.0 —
  pick at the Fall handover based on which the contributors know best. Plus `framework_to_rm`,
  the reverse direction, which is the query #388 opens with.
- **Stretch:** OWASP LLM Top 10, MITRE ATLAS (transitively through D3FEND where direct mapping
  is weak), SPDX 3.1 + AI profile, OpenCRE.

Two traps to brief in advance. D3FEND is **not BFO-derived**, and its `Person`/`Organization`
model the defended enterprise, not authorship — a shared term is not a shared meaning. And a
mapping with no match is a result: record `noMatch` with a reason, rather than leaving a gap
that reads as "not done yet".

### Winter week 3 (2027-01-18, MLK Monday — light week) — Constraint enrichment

Turn the corpus's **normative recommendations** into machine-checkable constraints.

1. **Harvest** — over v2's index, find RFC-2119-style statements (MUST, MUST NOT, SHOULD,
   SHALL, REQUIRED) with heading anchor and publication.
2. **Curate** — harvesting is assistive only. Every candidate is human-reviewed before it
   becomes a shape, under the registry gate's rule: **never auto-emit a constraint from
   extracted text.** A wrong SHACL shape asserts that a real organization's system is
   non-conformant, which is the `plan.md` §13 attribution-error class in another form.
   This is curation-lane work, and the best use of a CoSAI contributor's judgment all term.
3. **Express** — each curated recommendation becomes a shape carrying, as annotations, the
   publication and heading it came from and its RFC-2119 strength. A violation must be able to
   cite the sentence it violates.
4. **Profile** — MCP Security §3.3's assurance levels are the worked example: Level 1 vs
   Level 2+ imply different required controls.

Committed: ~10 curated shapes, end to end, with citations. Stretch: `assurance_profile`.

### Winter week 4 (2027-01-25) — Checking, gaps, handover

- **Internal checks** over the RM + mapping graph: `rm_uncontrolled_risks`,
  `rm_orphan_controls`, `rm_framework_coverage`, `rm_publication_coverage`, `rm_persona_gap`.
  Gap analysis is named in #388 as a primary benefit — these are a deliverable, not a side
  effect. *Committed: the first three.*
- **Conformance checks** — run the week-3 shapes against a described deployment, reporting
  violations with the citing passage.
- **Stretch: `how_to_implement`** — a control → the publication sections that operationalize
  it. The payoff of every prior milestone in one tool.
- **Upstream.** One contribution PR to CoSAI, iCLA already on file from Fall week 1. Likely
  candidates: RM YAML gaps found by the one-entry-per-id rule, the citation candidates in
  `reports/discovered-candidates.json` in CoSAI's own schema.
- **A talk** to the relevant workstream, which is also the next cohort's recruiting.

**Winter demo question.** "I run NIST AI RMF and D3FEND. Which CoSAI risks does that cover,
which controls am I missing, what does CoSAI say to do about each, and which of my choices
violates a published recommendation — with the sentence that says so?"

### Not scheduled

These are the parts of `NEXT-STEPS.md` steps 4 and 5 that fall outside Fall v3 and the
four Winter weeks. None is committed or stretch in either term.

| Item | Source |
| --- | --- |
| **Adding the Telemetry RFC to scope**, once reviewed | `NEXT-STEPS.md` step 4.5, a prerequisite of step 5.5 |
| **Telemetry bridge**, from the Telemetry RFC's Appendix B and C | `NEXT-STEPS.md` step 5.5 |
| **The rest of the tools**: the gap-analysis, cross-framework, guidance, telemetry and provenance tools that Fall v3 and Winter week 4 do not build | `NEXT-STEPS.md` step 5.6 and step 5's tool families |
| **Hosting the MCP server** | §6, optional, decided once at the v2 gate |

---

## 6. Optional: hosting the MCP server

Today the server is deliberately **not** hosted, nor registered with any MCP host.
Registration is `NEXT-STEPS.md` step 7.3, held to the Level 1 / DP1 posture of `plan.md`
§12.7. Hosting is therefore not a deployment chore to slot in when there's a spare week. It is a
**change of security classification**, which is why it appears here as a conditional track
with preconditions rather than as a milestone with a date.

### 6.1 Why it might be worth doing

- **Reach.** Today's audience is people who can `pip install -e .`, fetch a corpus at pinned
  shas and build a graph. Hosting drops that to people who can paste a URL, which is most of
  the coalition.
- **Adoption.** Answering a question live in a TSC or PGB call is worth more than a repo
  link, and it is the shortest path from "interesting student project" to "thing CoSAI uses".
- **Dogfooding.** A CoSAI-facing server secured against CoSAI's own *MCP Security* guidance
  is itself an artifact worth publishing, and that guidance is in the corpus the server
  serves.

### 6.2 What it costs: the classification change

| | Local, today | Hosted |
| --- | --- | --- |
| Transport | stdio (`mcp.run()` default) | Streamable HTTP + TLS |
| Users | One, the operator | Many, some unknown |
| Level (*MCP Security* §3.3.1) | **1 — Sandbox** | **2+**, via *MCP Security* §3.3.2's data-isolation row |
| Credentials in request path | None | Still none — but session and authn state now exist, which is new attack surface |
| New obligations | — | Structured logging; per-user separation; schema validation rejecting undeclared parameters; a documented server inventory entry |
| Worst case | A local process dials itself | Network-reachable MCP-T3/T4/T10, plus abuse and availability |

`plan.md` §12.2 already records the reasoning that keeps this at Level 1: the corpus is
published, public record, so *MCP Security* §3.3.2's data-isolation row is not triggered. Hosting triggers
it on the *multi-user* axis rather than the data-sensitivity axis. The classification moves
even though the data does not change.

### 6.3 Preconditions — all of them, not most

1. **Capacity.** The *committed* scope of v1–v3 has already landed. Hosting is never traded
   against a committed milestone.
2. **Governance.** A TSC answer, as a new `TSC-QUESTIONS.md` item, covering two distinct
   questions: may a service serve aggregated CoSAI contribution data to the public, and may
   it be presented under any CoSAI-associated name or domain? Default to **no** CoSAI
   branding — an unofficial service that looks official is a worse outcome than no service.
3. **Data posture settled.** Met: the sources are TLP:CLEAR under OASIS policy (D11,
   §6.5).
4. **A named operator whose term outlasts the cohort, and a decommission date.** Students
   graduate. A hosted service that outlives the people who understand it is a liability, not
   a legacy.
5. **A budget line with an owner.**
6. **An incident contact and a written takedown path**, before anything listens on a port.

If any precondition is unmet, the fallback is Phase A below, which delivers most of the
reach at none of the cost.

### 6.4 Three phases — and stopping at any of them is a success

**Phase A — Distribution, not hosting.** *Easy. No governance gate. Recommended default, and
the only hosting-adjacent work this team should attempt in Fall.*
Attach a pre-built `graph.db` to a release tag so a consumer skips the fetch and build
entirely; a one-command install; a documented MCP-host registration snippet kept **out** of
version control while the interpreter path is machine-specific, per `NEXT-STEPS.md` step 7.3. The
audience widens substantially, the classification does not move, Level 1 holds.

**Phase B — Single-tenant hosted demo, invite-only.** *Medium. Governance gate applies.*
Streamable HTTP behind authentication; one shared, read-only graph; **no per-user data at
all**, which is what keeps the per-user-separation obligation cheap; an allowlist of invited
CoSAI members; hard request caps; the `sparql` tool absent from the profile (§6.6).

**Phase C — Multi-user public hosting.** *Hard. Winter at the earliest, realistically the
next cohort.* The full Level 2+ obligation set, operated.

### 6.5 The hosted build is the same build

The hosted artifact is the local build, because the data is TLP:CLEAR (D11). What changes
when hosting is the *multi-user* axis of §6.2 (sessions, authentication, abuse), not the
data.

### 6.6 The `sparql` escape hatch does not survive hosting unchanged

`plan.md` §12.7 establishes that read-only enforcement is **not sufficient** for this tool: a
`SELECT` carrying `SERVICE <http://host/>` makes the engine dial that host and stream matched
bindings to it. That was verified against this store — and the probe aimed at the cloud
instance-metadata address **hung for two minutes with no timeout**.

That verification was a local curiosity. On a hosted cloud VM it is the classic
instance-credential exfiltration path, and the query text is now composed by *someone else's*
model reading *your* documents. So:

- **Default: `sparql` is not in the hosted tool surface.** The eighteen purpose-built retrieval
  tools are the hosted product.
- If it is kept for an invited Phase B audience: per-session statement and wall-clock budgets,
  a result-row cap, the `SERVICE`/`LOAD` scanner tested at the boundary, and egress blocked at
  the network layer rather than trusted to the scanner alone — including the metadata address.

### 6.7 Work items, if it goes ahead

- **ADR-WS2-005** — the classification change, the profile, the rejected options, and the
  conditions under which hosting should be switched off again.
- A transport profile split in `server.py` (`stdio` | `http`), config-selected, one code path.
- A per-profile tool-surface allowlist, tested.
- Structured logging, with no full query text at info level.
- Schema validation rejecting undeclared parameters (a Level 2 obligation, not optional).
- A server inventory entry — **in** version control this time, per *MCP Security* §3.3.2's supply-chain row.
- Rate limits, a stated uptime expectation (best-effort), and the decommission runbook, dated.

### 6.8 Where it sits on the calendar

Decide at the **v2 gate, end of week 6** — and the default answer there is *Phase A
only*. Weeks 7–8 belong to v3, and anything that borrows from them borrows from the
milestone. Realistic placements: **Phase A** in Fall week 8 or Winter week 4; **Phase B** as
a Winter stretch, or handed to the next cohort with ADR-WS2-005 already written,
which is itself a good outcome. Say no at the week-6 gate rather than carrying it to week 10
as a maybe.

---

## 7. Gates, dependencies and decisions the team cannot make

| # | Gate | Blocks | Owner | Needed by |
| --- | --- | --- | --- | --- |
| — | Each workstream commits its `meeting_minutes/` folder, backfilled by one fetcher run | Step 2's coverage, group by group; nothing committed waits on it | Each workstream, proposed by the Co-Lead | From week 1 |
| Q1 | Attributing paraphrased statements to named people | Narrative extraction — **out of scope regardless** | TSC | n/a |
| Q2 | The ADR-033 D2a member-company gap | Citing a member company in a skill example; nothing scheduled | TSC | n/a |
| — | OASIS iCLA per person | Any upstream contribution | Co-Lead | Week 1 |
| — | RM `develop` churn | v3 and all of Winter | Build lane | Re-pinned each gate |
| — | **May a service serve aggregated CoSAI data publicly, and under what name?** (§6.3), raised as a `TSC-QUESTIONS.md` item only if hosting goes ahead | Hosting Phases B and C only — Phase A is ungated | TSC | Week 6, if hosting is on the table at all |

**On addresses.** `registry/people.yaml` holds 78 contributor email addresses, each
published in a CoSAI whitepaper in a public OASIS GitHub repository. Those and the open
list archives are TLP:CLEAR (D11), so tools may return addresses. The rule is provenance:
every address in the graph traces to the public document or list message it came from.

---

## 8. Skills ramp

Nobody arrives with all of this. Weeks 1–2 are where the gaps get named. Contributors need
only the last two rows of the table; their contribution is domain judgment, not Turtle.

| Capability | Who | Depth |
| --- | --- | --- |
| Python, pytest, packaging | Students | Working |
| RDF, Turtle, SPARQL 1.1 | Students | Working; **deep** for the Ontology student |
| RAG and GraphRAG | Students | Working |
| SHACL and reasoners | Ontology student; everyone by Winter week 3 | Deep |
| BFO 2020 continuant/occurrent | Ontology student | Deep |
| CCO v2.2 + MIREOT | Ontology student | Deep |
| Graph databases | Evals and Ontology students, week 2 | Working |
| Full-text search (FTS5, BM25) | Ingest and Evals students, v2 | Working |
| MCP tool design | Ingest and Evals students | Working |
| *MCP Security* levels, SPARQL egress | Evals student | Working |
| **CoSAI people, orgs and governance** | Contributors | **Deep — this is what they bring** |
| **The frameworks** (D3FEND, NIST, OWASP, ATLAS) | Contributors, Winter | Working to deep |

---

## 9. Artifacts: what each is worth, and what it costs

The unit of work here is the artifact, not the hour — which is what lets a volunteer's
evening and a student's week live in the same backlog. Difficulty is **E**asy / **M**edium /
**H**ard. ★ marks a good first contribution.

### Artifacts that make other people's work possible

| Artifact | Value | Diff. | Best done by |
| --- | --- | --- | --- |
| ★ **A well-specified issue** | The highest leverage thing in the project. It converts an evening of volunteer time into merged work, and an unspecified backlog is why volunteers drift away | E | Anyone who just finished the adjacent work |
| ★ **A fixture from an observed line variant** | Freezes a real-world variant forever. The corpus's variance is the whole difficulty; each fixture retires a class of future bug | E | Contributors, new students |
| ★ **A one-page brief** on a background material | Turns one person's reading into the team's knowledge. Cheap for someone who already knows the material, expensive for everyone else to acquire | E–M | Contributors, week 2 |
| **A golden question + expected answer** | Defines "correct" before the code exists, which is the only order in which it cannot be fitted to the result | E–M | Contributors |
| **A demo** (working software) | Forces integration weekly instead of at the gate, and gives the earliest warning of integration failure | E | Whoever has something running |

### Artifacts that carry domain judgment

| Artifact | Value | Diff. | Best done by |
| --- | --- | --- | --- |
| **A reviewed registry row** (person, org, governance role) | The highest-value volunteer hour available. Attribution correctness is the top project risk; this is the control that mitigates it, and it cannot be automated | M | **CoSAI contributors** — people who were in the room |
| **A document↔RM mapping row** | Cannot be extracted — zero RM ids in the corpus. Every row is irreplaceable human work, and Winter's schedule depends on rows existing before Winter | M | Contributors + students, Fall wks 5–8 |
| **A curated SHACL constraint** with its citing passage | Turns published prose into a check a real system can be evaluated against; the terminal deliverable of both terms | H | Contributor judgment + student implementation, paired |
| **A framework alignment file** pinned to a release | Answers "I run D3FEND — what does that cover?", the query #388 opens with. Hard because a shared term is not a shared meaning | H | Contributors with framework depth |
| **An upstream issue against the RM YAML** | A gap found by the one-entry-per-id rule, reported where it can be fixed. Contribution to CoSAI as a by-product of building | E–M | Contributors — needs standing in the coalition |

### Artifacts that are the build

| Artifact | Value | Diff. | Best done by |
| --- | --- | --- | --- |
| **A test** | Non-negotiable. Judged by what it guards, not by how many there are: a regression that is named, a fixture from real data, a failure mode that would otherwise pass silently. Three per parser, per `plan.md` §11 | M | Everyone; Evals owns the suite |
| **A parser or pipeline PR** | The milestone itself. Determinism is the bar: same inputs, same graph, every time | H | Ingest and Pipeline |
| **A new ontology term** | Permanent and expensive to change. Needs a BFO/CCO parent, a label and a comment, and review before merge | H | Ontology + Lead |
| **An MCP tool** | Where the graph becomes usable by anyone who isn't us | M | Ingest + Evals |
| **A skill + portable evals** | The unit CoSAI can actually adopt (ADR-031/033). The difference between a repo and a contribution | M–H | Students; Evals owns the evals |
| **An ADR** | The durable artifact. It outlives the cohort, and it is the only thing that stops the next team relitigating a settled question. Records the rejected options and why. ADR-WS2-003 does more than that: it fixes the tool surface and the refusals, so no milestone has to renegotiate what the system is for | M–H | Whoever made the decision |

### Artifacts that carry the work outward

| Artifact | Value | Diff. | Best done by |
| --- | --- | --- | --- |
| **An upstream PR to CoSAI** | The point of the project. Latency is in the iCLA and the review, not the code — which is why week 1 starts it | M (process, not code) | Students, Co-Lead shepherding |
| **A talk to a workstream** | Recruits the next cohort and earns the standing that makes the next gate answerable | M | Co-Lead + a student |
| ★ **A release with a pre-built `graph.db`** (§6.4 Phase A) | Most of hosting's reach for none of its governance cost — a consumer skips fetch and build entirely. The highest value per hour of any artifact in the plan | E | A student, Fall wk 8 or Winter wk 4 |
| **A hosted demo endpoint** (§6.4 Phase B) | Turns a repo link into a live answer in a TSC call. Hard because it is a classification change, not a deploy | H | Two students + a named operator, Winter stretch |
| **The Fall / Winter report** | The handover. A four-week Winter only works if the Fall handover is written, not remembered | M | Everyone, one section each |

---

## 10. Risks

| Risk | Why it bites *this* team shape | Mitigation |
| --- | --- | --- |
| **Attribution correctness** — the top risk, inherited | Fewer hands, so less cross-checking by default | The registry gate, countersigned, never by the parser's author. Contributors review because they were there |
| **Volunteer time evaporates** | Two contributors' time is *hoped-for* effort, not scheduled effort | Nothing committed sits in the curation lane. Issues are assigned to queue up the work; first PRs are reviewed the same week |
| **The two Leads are the bottleneck** | Merge authority, countersigning and the coalition interface all sit with two people | Gatekeeping and wrangling sit with the Pipeline student, and the Lead and Co-Lead can each countersign |
| **Scope of step 5** | The largest step in `NEXT-STEPS.md` gets two weeks of Fall | Fall v3 is `NEXT-STEPS.md` steps 5.1–5.2 only, with the committed/stretch split stated in week 1 |
| **False temporal precision** | The instinct is to fill in a start date | `boundsKnown` / `inferred` mandatory, surfaced in tool output, asserted by a test |
| **Upstream RM churn** | The target moves during the term | Pin per milestone, re-pin at gates, review the diff |
| **Restricted data slips into a TLP:CLEAR corpus** | Every source is public, so nobody expects to check. Minutes start in member-only Drive folders, and a chat log or attendance sheet carries members' own words and presence | The Oracle reads only what a group has committed to its public repository, never Drive. Committing chat logs and attendance sheets is each group's explicit decision, and summary pointers record `accessRestricted` rather than fetching |
| **Hosting eats a milestone** | It looks like a deploy and costs a classification change; it is the most tempting scope creep available | Preconditions in §6.3 are all-or-nothing; decided once at the week-6 gate; Phase A is the default answer |
| **A hosted service outlives its operator** | Students graduate mid-Winter; an unowned endpoint serving coalition data is a liability | A named operator with a term beyond the cohort, and a **dated** decommission runbook written before launch, not after |
| **Meetings coverage is uneven across lists** | The v1 demo question ("How often does WS4 actually meet…") is only as good as the list's window, and a short window looks like a quiet group. Every list is pulled with full history via `getmessages`, but the lists began on different dates, so their windows differ | Coverage windows are reported per list, so every rate carries its denominator (D8) |
| **Student availability** | Midterms and exam weeks | Week 8 ends 2026-11-20, clear of Thanksgiving; Winter wk 3 light around MLK Day |
| **Token budget overrun** | A shared account and enthusiastic parallel exploration | Weekly cap set in week 1; fresh tight-scope sessions over long ones |
