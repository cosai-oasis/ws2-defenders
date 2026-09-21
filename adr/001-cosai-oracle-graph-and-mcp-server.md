# ADR-WS2-001: A CoSAI Oracle — every answerable question about CoSAI, grounded in its own publications and data, served over MCP

**Status:** Draft
**Date:** 2026-09-21
**Authors:** Josiah Hagen (Lead), Vinay Bansal (Co-Lead)

---

## Context

This project builds a GraphRAG MCP server that serves as CoSAI Oracle.  The primary benefit
is a tool that answers all answerable questions about CoSAI using ground truth, in a model
independent manner.  From an OWL/RDF representation we can do lexical, semantic, and named
entity disambiguation, express relationships between entities, index all our knowledge content
and reason about the logic represented.  This is the standard for MITRE D3FEND and for SPDX 3.1,
and our Risk Map should adopt this representation; our yaml is insufficiently expressive
https://github.com/cosai-oasis/secure-ai-tooling/issues/388.  Exposing the ontology
using GraphRAG to answer meaningful questions provides CoSAI end users a security oracle,
able to answer questions about implications of the CoSAI-RM for specific user needs,
truthfully.  It's easy to build functionality that answers other user questions about CoSAI,
such as what groups are meeting and what are they doing, along the way to creating the full
structured representation and providing immediate benefit.

Concretely, two problems. Contribution credit sits in prose "Contributors and
Acknowledgements" sections at the end of eleven whitepapers across five repositories, in
three structural formats, with inconsistent role labels, inconsistent organization names,
two email addresses for one person, and no stable identifiers — so "what has this person
worked on?" means reading eleven documents by hand. And the Risk Map is YAML that cannot
express the relationships #388 asks of it. Neither surface is queryable, and neither can
state what it does not know.

**Already built:** the contribution graph, the citation layer and a v1.x meetings layer
(`plan.md` §10.0), 393 tests passing. Steps 1–7 of `NEXT-STEPS.md` are designed and not
built. Nobody starts from an empty repository.

**Boundaries.** `plan.md` is the design record; `NEXT-STEPS.md` is canonical for the content
and ordering of steps 1–7; `TSC-QUESTIONS.md` holds what is not one person's to decide. This
ADR is canonical for the decisions below and for who builds them, when.

Those three, and the `registry/` and `reports/` paths cited throughout, live in the
`cosai-graphrag-mcp` working repository. It is private pending `TSC-QUESTIONS.md` item 1 —
whether an aggregated index of 78 contributor email addresses may be published — so the
findings this ADR relies on are restated here rather than left behind a link. Reviewing the
decisions does not require reading it.

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
person can bear several at once. What this buys is set out under Consequences.

### D3. No fabricated bounds

Affiliation intervals carry `earliestEvidence`, `latestEvidence` and `boundsKnown false`.
Derived change events carry `notBefore`, `notAfter` and `inferred true`. Never a bare start
or end date, and never an interpolation between two attested spans.

### D4. A credit carried across a revision is dated to the original publication

The revision is a separate occurrent. This is what prevents the false "Bill Stout returned to
ServiceNow in August 2026" reading of the MCP Security v2.0 credit list.

### D5. Identity resolves through curated registries behind a human review gate

The parser emits a seed registry plus `reports/unresolved.md`; a human corrects it; every
build thereafter is deterministic. Upstream drift produces a reviewable diff, never a silent
overwrite. The gate is not the same person who wrote the parser.

### D6. Unresolved goes to a report, never to a guess

A person line, a name variant, an RM id that does not resolve is recorded as unresolved.
Attribution errors are the one class of defect this must not ship.

### D7. One OWL entry per Risk Map YAML id, never invented

A missing concept is fixed in the YAML upstream first. Validators and telemetry that look up
a `component_id` must not find a ghost. The catalog is regenerated, never curated — the
opposite of the people and organization registries, deliberately.

### D8. A rate without a named denominator does not ship

`Present ∪ Guests` over *what*? Attendance rates state their denominator in the tool output.

### D9. The server is retrieval-only, at MCP Security Level 1 / DP1

stdio transport, no credentials in the request path, purpose-built narrow tools, no writes,
and `stderr`-only diagnostics because stdout carries the JSON-RPC stream. No tool calls a
model; synthesis belongs to a skill over the tools.

### D10. `SERVICE` and `LOAD` are refused at the `sparql` boundary

A `SELECT` carrying `SERVICE` is an arbitrary egress primitive — verified against this store,
where a probe at the cloud metadata address hung for two minutes. The query text is composed
by a model that has just read untrusted document prose. Read-only enforcement is not
sufficient.

### D11. A hosted build carries no plaintext addresses and no `sparql` tool

If hosting happens, the boundary is the build, not a default flag.

### D12. The tool surface is decided before the store

The critical user journeys and the MCP tool surface land as **ADR-WS2-003**, ahead of the
graph-store choice in **ADR-WS2-004**, because "which reasoning profile do we need" is a
question about which queries must work. Hosting, if it happens, is **ADR-WS2-005**.

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

### Positive — what the entity-event model buys

`plan.md` §4.3 is the model itself, with worked Turtle. Four things follow from D2.

**1. It lets the graph say what is known, and nothing more.** A flat edge — *person
`affiliatedWith` org* — asserts a present-tense fact. The corpus contains no present-tense
facts. It contains a person credited under an employer in a document published on a date.
Modeling affiliation as a **role borne over a temporal region**, gained and lost by events,
is what makes `boundsKnown false` and `notBefore`/`notAfter` expressible at all. In a flat
model the only ways to record *"credited under Trend Micro on 2025-07-14 and 2025-10-27,
start and end unknown"* are to invent a start date or to drop the dates. Both are wrong
answers about a real person. The same split is what keeps a credit carried across a revision
dated to the original publication, which is the difference between silence and a fabricated
"Bill Stout returned to ServiceNow in August 2026".

**2. Events carry provenance, so conflicts surface instead of resolving.** Every occurrent
names its participants, the instant or interval it occupies, and the source that attested
it. Two sources asserting about one meeting produce two events, not one silently doubled
edge — which is why the store partitions by provenance and validates each partition alone.
The contradictions the minutes already throw at the graph (*Bill Stout (AI Alliance
non-voting)* — an affiliation not held) are findings this model can **hold and report**. A
flat model has to pick a winner at ingest, and picking silently is how an attribution error
ships.

**3. The event layer is the index.** The least obvious benefit and the most important one for
GraphRAG. Because every event occupies a temporal region and names its participants, the set
of events is a *semantically meaningful join* across every entry point a question can start
from: a person, an organization, a document, a section, a meeting series, a date range, and
from v3 a Risk Map entity. The `PublicationEvent` reached from "what did this person work
on", from "what was published in Q3 2026", and from "who wrote about this risk" is **one
node**, not three secondary indexes to keep in sync. The text index (v2) supplies content;
the event graph supplies the path to it and the citation for it. That is also why the
milestones compose rather than merely stack — v1's meetings, v2's sections and v3's RM
entities all attach to the same occurrents, so each one makes its predecessors more
answerable.

**4. Roles are reified, so effort is distinguishable from credit.** One person can bear
several roles at once: Akila Srinivasan is both Reviewer and TSC Co-Chair on a single
document. Keeping `GitHubContributorRole` a separate class from the credited roles (step 5)
is what stops "committed" from ever reading as "credited", and stops a typo fix from being
conflated with writing a section.

### Negative — the bill

More triples, more classes, opaque numeric CCO IRIs, and a real ramp for a student who has
written SQL but not SPARQL. D1's mitigations are the answer to the last two, and the ramp is
budgeted into weeks 1–2 (§8) rather than discovered in week 3.

### Follow-up

Three decisions this one implies but does not make: **ADR-WS2-003** (critical user journeys
and tool surface) and **ADR-WS2-004** (graph store) in week 2; **ADR-WS2-005** (hosting) only
if §6's preconditions hold. Three items in `TSC-QUESTIONS.md` gate parts of the work: address
aggregation (1), member-restricted Drive minutes (2), contributing the skills upstream (4).

---

# Project plan

Eight weeks in Fall, four in Winter, delivering D1–D12 in the order below. Where this plan
and `NEXT-STEPS.md` disagree on *what* a step contains, `NEXT-STEPS.md` wins; on *when* or
*who*, this plan wins.

## 0. The team

| | Count | Commitment | Obligation |
| --- | --- | --- | --- |
| **Lead** — Josiah Hagen | 1 | Weekly | Technical direction, merge authority, the invariants D1–D12, registry gate countersign |
| **Co-Lead** — Vinay Bansal | 1 | Weekly | Coalition interface, contributor recruiting and onboarding, TSC escalation, meeting slots |
| **Students** | 2–5 | 8–10 hrs/wk, fixed calendar | The critical path. Milestones v1/v2/v3 are theirs |
| **CoSAI contributors** | 2–5 | 2–4 hrs/wk, variable, may lapse | Issue-based. **Never on the critical path** |

The two populations are managed differently, and conflating them is the main way a project
this shape fails. Students have a fixed calendar and a deliverable obligation. CoSAI
contributors are working professionals volunteering around a day job; their time is real but
unpredictable, and any plan that puts a milestone behind a volunteer's week is a plan that
slips. So:

> **Volunteer work is detachable.** Everything in the curation lane (§1) is chunked into
> issues that can be picked up, finished in one or two sittings, and dropped without
> stranding anyone. If a contributor disappears for three weeks, no milestone moves.

### Assumptions, and how to change them

| Assumption | Value | If it changes |
| --- | --- | --- |
| Student effort | 8–10 hrs/wk each | Below ~6, drop to the *committed* scope in §4 and cut every stretch item |
| Contributor effort | 2–4 hrs/wk, lapsing | Already assumed lossy; no change needed |
| Fall week 1 | week of **2026-09-28** | Shift the whole Fall table together; week 8 ends Fri 2026-11-20, clear of Thanksgiving (2026-11-26) |
| Winter week 1 | week of **2027-01-04** | Winter week 3 contains MLK Day (2027-01-18) and is planned light |

**The estimates in `NEXT-STEPS.md` are not student estimates.** They are elapsed days for one
experienced maintainer working with a frontier model on a warm context. Plan on **3–4×** in
student calendar time. The arithmetic is why §4 splits every milestone into *committed* and
*stretch*:

| | Student hours, weeks 3–8 | Contributor hours | Expert-equivalent available |
| --- | ---: | ---: | --- |
| 2 students, 2 contributors | ~110 | ~35 | ≈ 1 expert week |
| 5 students, 5 contributors | ~270 | ~90 | ≈ 2.5 expert weeks |

Steps 1 + 4 + 6.6.1–2 are roughly 4–6 expert weeks at full scope. **Full scope does not fit,
at either end of the range.** The committed scope in §4 does.

---

## 1. Two lanes, not three tracks

At this size, parallel milestone tracks fragment the team. Instead:

**Build lane** — students, working in **pairs**, on the critical path **sequentially**:
v1 → v2 → v3. One pair is always on the current milestone; with 4–5 students, a second pair
runs one milestone ahead on scaffolding only (fixtures, fetchers, skeleton modules), never
on the same files.

**Curation lane** — CoSAI contributors plus any student overflow, on a standing backlog of
issues. Curation work is where domain judgment beats code, which is exactly what CoSAI
contributors bring, and it is the highest-value-per-hour work in the project: the registry
gate, the document↔RM candidate rows, framework mapping judgment, golden questions. The lane
always works **one milestone ahead** of the build lane, so its output arrives before it is
needed rather than after.

| Cohort | Shape |
| --- | --- |
| 2 students | One pair, sequential, committed scope only. Leads take the integration and release roles. |
| 3–4 students | One pair on the milestone + one floating student on fixtures, tests and the curation lane. |
| 5 students | Two pairs, second pair one milestone ahead on scaffolding. Stretch items become reachable. |

### Roles (held by people, not by tracks)

| Role | Held by | Responsibility |
| --- | --- | --- |
| Ontology owner | One student, mentored by Lead | Every new class/property, its BFO/CCO parent, its label and comment. No term enters `ontology/` without review |
| Pipeline owner | One student per milestone | Ingest/build determinism — same inputs, same graph, every time |
| Evals owner | One student, whole term | ≥3 tests per parser and per skill (`plan.md` §11); the golden sets |
| **Registry gatekeeper** | Lead, countersigned by Co-Lead | Identity decisions. **Never auto-merged, and never merged by the author of the parser that proposed them** |
| Integration steward | Lead (or a 5th student) | Merge order and named-graph ownership. The union default graph is a multiset; a triple asserted by two sources silently doubles every joined row |
| Contributor wrangler | Co-Lead | Keeps ≥10 ready issues in the backlog at all times, greets every new contributor within 48h |
| Release manager | Rotating student | Tags v1/v2/v3; keeps `README.md`'s status block true |

---

## 2. Cadence

Small team, so fewer meetings than the work suggests. Fixed in week 1, not renegotiated
after week 2.

| Meeting | When | Length | Who | Required? |
| --- | --- | --- | --- | --- |
| Working session | Wed | 60 min | Everyone | Students yes, contributors no |
| Async written update | Mon | — | Students | Yes — one paragraph, what's planned |
| Demo slot | End of Wed session | 15 min | Whoever has something running | **Working software or a failing test. No slides** |
| Leads' sync | Mon | 20 min | Lead + Co-Lead | Yes |
| Milestone gate | Weeks 4, 6, 8 | 90 min | Everyone + any CoSAI sponsor | Yes |
| CoSAI meetings | Per series | — | Co-Lead + one student, rotating | Rotating student yes |

Contributors are invited to the Wednesday session and obligated to none of it. Their
interface is the issue tracker; the wrangler's job is that the tracker always has something
worth an evening.

There is a pleasant recursion worth naming: the meetings the rotating student attends are the
same meetings v1 is modeling. Attendance is both the work and the data.

### Working rules

- Short-lived branches, PR to `main`, one review, CI green. A contributor's first PR gets
  reviewed same-week — latency is what loses volunteers.
- The 393-test baseline never goes down.
- Every parser lands with its fixture in `tests/fixtures/` **before** it lands with its code.
- Unresolved anything — a person line, a name variant, an RM id — goes to a report under
  `reports/`, never to a guess. This is the single most important habit in the project.
- A Wednesday outcome note appended to `SESSION-NOTES.md`, including what the week cost in
  tokens.

---

## 3. Fall, week by week

| Week | Of | Build lane | Curation lane | Gate |
| --- | --- | --- | --- | --- |
| 1 | 2026-09-28 | Form, cadence, recruit | Recruit, backlog | Charter + 10 ready issues |
| 2 | 2026-10-05 | Background evaluation, tool surface, store decision | Briefs, CUJs | **ADR-WS2-003 + ADR-WS2-004** |
| 3 | 2026-10-12 | Step 1.1–1.4 minutes | `governance-roles.yaml` seed | |
| 4 | 2026-10-19 | Step 1.5–1.10, tools | Registry review | **v1** |
| 5 | 2026-10-26 | Step 4.1 sections | Golden questions for search | |
| 6 | 2026-11-02 | Step 4 chunks, FTS5, tools | Doc↔RM candidate scouting | **v2** + hosting decision (§6.8) |
| 7 | 2026-11-09 | 6.6.1 RM generator | RM YAML gap review | |
| 8 | 2026-11-16 | 6.6.2 namespace + policy | Deprecation policy review | **v3** |

---

### Week 1 — Form, cadence, recruit

**Goal.** A team that can make decisions, standing inside CoSAI to make them with, and a
backlog good enough to attract volunteers.

1. **Pairs and roles.** Assign per §1. With 2 students, the Lead absorbs integration and
   release.
2. **Cadence.** Fix the §2 slots for the term against the CoSAI meeting calendar, so
   conflicts surface now rather than in week 5.
3. **Environment.** Everyone runs the repo before Friday: `pip install -e ".[dev]"`, fetch,
   build, `pytest -q`, 393 passing. Python ≥3.11. Note anaconda's `gh` shadows
   `/usr/bin/gh`, which `ingest/fetch.py` needs.
4. **Recruit 2–5 CoSAI contributors — Co-Lead owns this, and it is a week-1 deliverable, not
   an aspiration.** The pitch goes to the WS2 and WS4 lists and to the TSC and PGB calls,
   and the ask is concrete: *"a 90-minute evening, reviewing twenty name lines, and your
   judgment lands in a graph the coalition can query."* Two supporting moves:
   - **The backlog is the recruiting instrument.** Ten well-specified good-first-issues
     exist before the pitch goes out. Volunteers join projects they can contribute to in one
     sitting; they do not join projects that require reading `plan.md` first.
   - Use the `cosai-orientation` skill in this repo to find which group meets on what and how
     often. It is exactly the tool for this and it is already built.
5. **Also recruit** a named TSC sponsor, and make contact with issue
   [#388](https://github.com/cosai-oasis/secure-ai-tooling/issues/388) and with the author of
   `billbrietstout/ws2_ontology` — the latter is **not a dependency** (`plan.md` §3.7) and
   contact is to avoid duplicating it, not to adopt it.
6. **Paperwork, now, because it has latency.** Every student and contributor who will
   contribute upstream needs an OASIS Open Project iCLA on file. The repo is Apache-2.0;
   upstream contribution rules are CoSAI's. Started in week 1 or it blocks the Winter PR.
7. **Budget.** Who owns the model API account, and the weekly cap. `NEXT-STEPS.md` prices
   step 6 alone at $558–1,255 on Opus 5. The cheap lever it names is fewer cache
   invalidations — **fresh sessions with tight scope**, not terser work.

**Exit criteria.** A one-page charter in the repo (pairs, roles, cadence, budget cap,
escalation path). Tests passing on every machine. **Ten ready issues in the tracker.** At
least one recruiting pitch delivered to a live CoSAI call.

---

### Week 2 — Background evaluation, the tool surface, and the graph store

**Goal.** The team can defend the existing design choices, has written down what the system
is *for*, and has made one substantial architectural decision with evidence behind it.

**Evaluation.** Split the reading; every item gets a **one-page written brief**, presented in
5 minutes on Wednesday. The briefs are the deliverable, not the reading. Contributors are
good candidates for the CoSAI-internal briefs — several will already know the material,
which makes the brief cheap for them and valuable to the students.

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

**ADR-WS2-003 — the critical user journeys and the MCP tool surface.** Written **before** the
store decision, because the store decision cannot be made without it: criterion 2 below asks
which reasoning profile we actually need, and that is a question about which queries have to
work.

What this ADR specifies:

- **The critical user journeys**, in a user's words rather than the schema's. The milestone
  demo questions in §4 and the Winter journey in §5 are the starting set — *how often does
  WS4 meet and who actually attends*, *which passage says how to contain an agent*, *what
  risks does this component carry and has its id been renamed*. Each CUJ names its actor —
  practitioner, newcomer, TSC member, workstream lead — and what they do with the answer.
- **The tool that serves each**, against the twelve already built (`plan.md` §9) and the
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

**ADR-WS2-004 — the graph store.** A real decision. The incumbent is `pyoxigraph` + sqlite FTS5
behind `src/cosai_graphrag/store.py`, chosen when the graph was ~15k triples of asserted
facts. Step 6 changes the requirement: `NEXT-STEPS.md` §6.1 wants the corpus **deductively
expressed**, and pyoxigraph has no reasoner.

Criteria, in this weight order:

1. **Named-graph support** — non-negotiable; the four-way provenance partitioning, each
   partition validated alone against a class allowlist, cannot be built without it.
2. **Reasoning** — which profile do we *actually* need: OWL-RL materialization, EL
   classification, or Datalog rules? Answer with a query we want to work and that today does
   not — which is exactly what ADR-WS2-003's journeys supply — before ranking any engine.
3. **SHACL** — native, or `pyshacl` alongside.
4. **Deployment posture** — a store needing a network-listening process changes the MCP
   Security §3.3.1 Level 1 / DP1 classification this project is registered under
   (`plan.md` §12.7). A security decision, not an ops one.
5. **License and cost** for a student team; **Python binding** quality; **swap cost** given
   the `store.py` seam.

Candidates, a paragraph each: pyoxigraph (incumbent), Apache Jena + Fuseki, Ontotext GraphDB
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

`NEXT-STEPS.md` step 1. Read §1.1–1.11 in full; this does not repeat it.

**Week 3 — build lane**

- **1.1 Re-scope `NoFabricatedAttendanceShape`** — blocking. It forbids `AttendanceRole`
  globally; it belongs to the mail graph's shape alone.
- **1.2 Split the meetings graph** into `graph/meetings-mail` and `graph/meetings-minutes`
  with explicit ownership — blocking, and the integration steward's first real job.
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

- **1.5 Registry review gate** — Lead, countersigned by Co-Lead. The minutes already
  contradict the graph: *Bill Stout (AI Alliance non-voting)* is an affiliation not held,
  *Dalton House (Trend Micro)* a person not known.
- **1.6 `build/minutes.py`** with its own SHACL shape.
- **1.7 Tools** — `meeting_attendance`, `attendance_rate(group, by=…)`, `who_leads(group)`.
- **1.9 Model additions** — `MemberAttendance` / `GuestAttendance`; `DeclaredAbsence`, which
  is **not a role**; `GroupLeadershipRole`, `AlternateRole`, voting status, all
  evidence-anchored with open bounds like `AffiliationRole`.
- **1.10 Denominator** — `Present ∪ Guests` over *what*? State it in the tool output.
- **1.8 Skill update** — flip the orientation skill's attendance refusals.

**Week 4 — curation lane.** Contributors review the proposed registry diff line by line. This
is the highest-value volunteer hour in the whole term: people who were in those rooms
reviewing claims about who was in those rooms.

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

`NEXT-STEPS.md` §6.6 steps **1 and 2 only**. Steps 3–6 are Winter and beyond, and saying so
in week 1 rather than discovering it in November is the point of §4's committed/stretch split.

**Week 7 — build lane.** **6.6.1 The generator** over `risk-map/yaml` on `develop`, emitting
the `cosai:` namespace (reserved and unused until now). **One OWL entry per YAML id. Never
invent one** — if a concept is missing (PDP, PEP, tool registry, wallet, merchant, payment
network) the YAML changes first, upstream. The RM **tracks** upstream rather than snapshotting
it: `develop` carries 46 components against `main`'s 26 and more lands during the term, so pin
a commit per milestone, re-pin at each gate, review the diff. The catalog is **regenerated,
never curated** — the opposite of the people/org registries, and the team should be able to
say why. Rows are individuals, categories are classes. Matching is SKOS.

**Week 8 — build lane.** **6.6.2 Versioned namespace and deprecation policy** — a
prerequisite, not polish: emitted telemetry is an immutable historical record, so a renamed id
silently invalidates every stored event carrying it. Write the policy as a document first,
implement second. Then the RM partition's SHACL shape, the freeze, the tag, and a written
handover to Winter.

**Curation lane, weeks 7–8.** Every concept the one-entry-per-id rule shows to be *missing*
from the upstream YAML becomes an issue filed against the Risk Map repository. That is a
genuine contribution to CoSAI produced as a by-product of building the generator, and it is
contributor work, not student work — it needs standing in the coalition.

---

## 4. Milestones: committed vs stretch, and definition of done

Each milestone is defined by a question the system can newly answer, in the style of
`plan.md` §11's golden answers. A gate that demos a diagram instead of an answer has not
landed.

**Committed** ships with 2 students. **Stretch** is reachable with 4–5 students and an active
curation lane. Stretch items are not failures when they don't land; they are the buffer that
protects the committed scope.

### v1 — CoSAI publications and meetings (end of week 4)

| | |
| --- | --- |
| **Demo question** | "How often does WS4 actually meet, who attends, and what was this person's affiliation in March 2026?" |
| **Correct answer shape** | An attendance rate **with its denominator named**; an affiliation with `bounds_known: false` and an inferred change window carrying `notBefore`/`notAfter`; a date between two attested spans returns **nothing**, not an interpolation |
| **Committed** | Step 1 entire: `ingest/minutes.py`, `build/minutes.py`, `governance-roles.yaml`, split meetings graphs each with its own shape, the three tools, updated orientation skill |
| **Stretch** | Step 3 (groups.io re-point — lifts the mail layer's 32-day ceiling); step 2 (Drive minutes) **only if TSC question 2 is answered** |
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
| **Committed** | The generator tracking `develop`; the `cosai:` catalog; the versioned namespace and a **written** deprecation policy; `rm_search` and `rm_entity`; the RM SHACL shape |
| **Stretch** | `rm_change_log` implemented rather than specified; `rm_component_exposure`, `rm_persona_profile`, `rm_lifecycle_view`; step 5 (GitHub contribution activity) |
| **Tests** | Round-trip every YAML id to exactly one OWL entry and back; a fabricated-id test that **must fail the build**; regeneration against a newer upstream commit produces a reviewable diff |
| **Gate** | Deprecation policy reviewed by the CoSAI sponsor — telemetry consumers are downstream of it |

---

## 5. Winter — cross-framework mapping and constraint enrichment (4 weeks)

`NEXT-STEPS.md` §6.6 steps **3, 4 and part of 6**, plus the constraint work the Fall
milestones make possible. Depends on v2's section index and v3's stable namespace; if either
slipped, Winter week 1 absorbs the slip and week 4's scope is cut, not week 1's quality.

Four weeks is short, so the curation lane's Fall head start on document↔RM candidates is not
a nicety — it is the reason the schedule closes.

### Winter week 1 (2027-01-04) — `registry/document-rm-mapping.yaml`

The corpus contains **zero RM ids** — grepped, confirmed; near-zero external framework ids
either (`plan.md` §3.6). Document↔RM linkage is therefore **curated and can never be
extracted**. Curate at *section* granularity against v2's index, starting from the Fall
candidate list.

Each row: the RM entity, the passage, the confidence, the curator. Two people confirm every
row. Entities nobody can find a passage for are the input to `rm_publication_coverage` — an
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
   non-conformant, which is the `plan.md` §13 attribution-error class wearing a different hat.
   Curation lane work, and the best use of a CoSAI contributor's judgment all term.
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
  `reports/discovered-candidates.json` in CoSAI's own schema, and the fetcher divergence in
  `TSC-QUESTIONS.md` §6.
- **A talk** to the relevant workstream — which is also next cohort's recruiting.

**Winter demo question.** "I run NIST AI RMF and D3FEND. Which CoSAI risks does that cover,
which controls am I missing, what does CoSAI say to do about each, and which of my choices
violates a published recommendation — with the sentence that says so?"

---

## 6. Optional: hosting the MCP server

Today the server is deliberately **not** hosted, and `plan.md` §12.7 says so in those words:
*"Not yet done, and deliberately so: the server is not registered with any MCP host."*
Hosting is therefore not a deployment chore to slot in when there's a spare week. It is a
**change of security classification**, which is why it appears here as a conditional track
with preconditions rather than as a milestone with a date.

### 6.1 Why it might be worth doing

- **Reach.** Today's audience is people who can `pip install -e .`, fetch a corpus at pinned
  shas and build a graph. Hosting drops that to people who can paste a URL, which is most of
  the coalition.
- **Adoption.** Answering a question live in a TSC or PGB call is worth more than a repo
  link, and it is the shortest path from "interesting student project" to "thing CoSAI uses".
- **Dogfooding, with a nice recursion.** A CoSAI-facing server secured against CoSAI's own
  *MCP Security* guidance is itself an artifact worth publishing — and the paper that governs
  the deployment is in the corpus the server serves.

### 6.2 What it costs: the classification change

| | Local, today | Hosted |
| --- | --- | --- |
| Transport | stdio (`mcp.run()` default) | Streamable HTTP + TLS |
| Users | One, the operator | Many, some unknown |
| Level (*MCP Security* §3.3.1) | **1 — Sandbox** | **2+**, via §3.3.2's data-isolation row |
| Credentials in request path | None | Still none — but session and authn state now exist, which is new attack surface |
| New obligations | — | Redacted structured logging; per-user separation; schema validation rejecting undeclared parameters; a documented server inventory entry |
| Worst case | A local process dials itself | Network-reachable MCP-T3/T4/T10, plus abuse and availability |

`plan.md` §12.2 already records the reasoning that keeps this at Level 1: the corpus is
published, public record, so §3.3.2's data-isolation row is not triggered. Hosting triggers
it on the *multi-user* axis rather than the data-sensitivity axis. The classification moves
even though the data does not change.

### 6.3 Preconditions — all of them, not most

1. **Capacity.** 5 students (two pairs), with the *committed* scope of v1–v3 already landed.
   Hosting is never traded against a committed milestone.
2. **Governance.** A TSC answer, as a new `TSC-QUESTIONS.md` item, covering two distinct
   questions: may a service serve aggregated CoSAI contribution data to the public, and may
   it be presented under any CoSAI-associated name or domain? Default to **no** CoSAI
   branding — an unofficial service that looks official is a worse outcome than no service.
3. **Data posture settled** — TSC question 1 answered, *or* the redacted build of §6.5
   adopted, which makes the hosting path independent of that answer rather than blocked on it.
4. **A named operator whose term outlasts the cohort, and a decommission date.** Students
   graduate. A hosted service that outlives the people who understand it is a liability, not
   a legacy.
5. **A budget line with an owner.**
6. **An incident contact and a written takedown path**, before anything listens on a port.

If any precondition is unmet, the fallback is Phase A below, which delivers most of the
reach at none of the cost.

### 6.4 Three phases — and stopping at any of them is a success

**Phase A — Distribution, not hosting.** *Easy. No governance gate. Recommended default, and
the only hosting-adjacent work worth attempting at 2–4 students.*
Attach a pre-built `graph.db` to a release tag so a consumer skips the fetch and build
entirely; a one-command install; a documented MCP-host registration snippet kept **out** of
version control while the interpreter path is machine-specific, per `plan.md` §12.7. The
audience widens substantially, the classification does not move, Level 1 holds.

**Phase B — Single-tenant hosted demo, invite-only.** *Medium. Governance gate applies.*
Streamable HTTP behind authentication; one shared, read-only graph; **no per-user data at
all**, which is what keeps the per-user-separation obligation cheap; an allowlist of invited
CoSAI members; hard request caps; the `sparql` tool absent from the profile (§6.6).

**Phase C — Multi-user public hosting.** *Hard. Winter at the earliest, realistically the
next cohort.* The full Level 2+ obligation set, operated.

### 6.5 The hosted build is a redacted build

The hosted artifact contains **no plaintext email addresses**, whatever the TSC decides about
question 1. `emailSha256` plus domain only — already the matching key, so nothing breaks —
and `include_addresses` is not merely defaulted off but **absent from the hosted tool
surface**. `plan.md` §12.2 is explicit that the default flag is "an ergonomic default, not a
security boundary"; on a hosted server the boundary has to be the build, not the flag.

This is the same fallback `TSC-QUESTIONS.md` §1 already names as low-cost, which is the neat
part: adopting it for the hosted profile removes the governance dependency instead of waiting
it out.

### 6.6 The `sparql` escape hatch does not survive hosting unchanged

`plan.md` §12.7 establishes that read-only enforcement is **not sufficient** for this tool: a
`SELECT` carrying `SERVICE <http://host/>` makes the engine dial that host and stream matched
bindings to it. That was verified against this store — and the probe aimed at the cloud
instance-metadata address **hung for two minutes with no timeout**.

That verification was a local curiosity. On a hosted cloud VM it is the classic
instance-credential exfiltration path, and the query text is now composed by *someone else's*
model reading *your* documents. So:

- **Default: `sparql` is not in the hosted tool surface.** The twelve purpose-built retrieval
  tools are the hosted product.
- If it is kept for an invited Phase B audience: per-session statement and wall-clock budgets,
  a result-row cap, the `SERVICE`/`LOAD` scanner tested at the boundary, and egress blocked at
  the network layer rather than trusted to the scanner alone — including the metadata address.

### 6.7 Work items, if it goes ahead

- **ADR-WS2-005** — the classification change, the profile, the rejected options, and the
  conditions under which hosting should be switched off again.
- A transport profile split in `server.py` (`stdio` | `http`), config-selected, one code path.
- The redacted build profile in the build pipeline, with a test asserting no `addressValue`
  triple reaches the hosted artifact.
- A per-profile tool-surface allowlist, tested.
- Structured logging with redaction — no addresses, no full query text at info level.
- Schema validation rejecting undeclared parameters (a Level 2 obligation, not optional).
- A server inventory entry — **in** version control this time, per §3.3.2's supply-chain row.
- Rate limits, a stated uptime expectation (best-effort), and the decommission runbook, dated.

### 6.8 Where it sits on the calendar

Decide at the **v2 gate, end of week 6** — and the default answer there is *Phase A
only*. Weeks 7–8 belong to v3, and anything that borrows from them borrows from the
milestone. Realistic placements: **Phase A** in Fall week 8 or Winter week 4; **Phase B** as
a Winter stretch at 5 students, or handed to the next cohort with ADR-WS2-005 already written,
which is itself a good outcome. Say no at the week-6 gate rather than carrying it to week 10
as a maybe.

---

## 7. Gates, dependencies and decisions the team cannot make

| # | Gate | Blocks | Owner | Needed by |
| --- | --- | --- | --- | --- |
| Q1 | Publishing an aggregated index of 78 contributor addresses | Whether the repo can go public; how the team handles `people.yaml` | TSC | Week 2 |
| Q2 | Attendance from member-restricted Drive documents | Step 2 entirely — a v1 *stretch* item, so nothing committed is at risk | TSC | Week 3 |
| Q3 | Attributing paraphrased statements to named people | Narrative extraction — **out of scope regardless** | TSC | n/a |
| Q4 | Contributing the skills upstream | The Winter upstream PR | TSC | Winter wk 1 |
| — | OASIS iCLA per person | Any upstream contribution | Co-Lead | Week 1 |
| — | RM `develop` churn | v3 and all of Winter | Build lane | Re-pinned each gate |
| — | `gws` install + OAuth | Step 2, alongside Q2 | Build lane | Week 3 |
| Q8 | **May a service serve aggregated CoSAI data publicly, and under what name?** (§6.3) | Hosting Phases B and C only — Phase A is ungated | TSC | Week 6, if hosting is on the table at all |

**On Q1, because it affects everyone directly.** `registry/people.yaml` holds 78 plaintext
email addresses. Each is individually public in a whitepaper, but a machine-readable file
keyed by canonical person is a different exposure, and aggregation is what makes it
scrapeable. Until the TSC answers: the repository stays private, no tool returns an address
by default, and **nobody copies `people.yaml` outside the repo** — not into a notebook
output, not into a shared drive, not into a model context that logs. This applies to CoSAI
contributors too, who may reasonably assume the data is already theirs to handle. The fallback
if the answer is no costs little: tracked files carry `emailSha256` plus domain, already the
matching key — and §6.5 adopts that fallback for any hosted build regardless of the answer.

---

## 8. Skills ramp

Nobody arrives with all of this. Weeks 1–2 are where the gaps get named. Contributors need
only the bottom half of the table, which is the point — their contribution is judgment, not
Turtle.

| Capability | Who | Depth |
| --- | --- | --- |
| Python, pytest, packaging | Students | Working |
| RDF, Turtle, SPARQL 1.1 | Students | Working; **deep** for the ontology owner |
| SHACL | Ontology owner; everyone by Winter wk 3 | Deep |
| BFO 2020 continuant/occurrent | Ontology owner | Deep |
| CCO v2.2 + MIREOT | Ontology owner | Deep |
| sqlite FTS5, BM25 | One student, v2 | Working |
| MCP tool design | One student | Working |
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
| ★ **A well-specified issue** | The highest leverage thing in the project. It converts an evening of volunteer time into merged work, and an unspecified backlog is why volunteers drift away. Ten of these are a week-1 deliverable | E | Anyone who just finished the adjacent work |
| ★ **A fixture from an observed line variant** | Freezes a real-world variant forever. The corpus's variance is the whole difficulty; each fixture retires a class of future bug | E | Contributors, new students |
| ★ **A one-page brief** on a background material | Turns one person's reading into the team's knowledge. Cheap for someone who already knows the material, expensive for everyone else to acquire | E–M | Contributors, week 2 |
| **A golden question + expected answer** | Defines "correct" before the code exists, which is the only order in which it cannot be fitted to the result | E–M | Contributors |
| **A demo** (5 min, working software) | Forces integration weekly instead of at the gate, and is the cheapest possible early warning | E | Whoever has something running |

### Artifacts that carry domain judgment

| Artifact | Value | Diff. | Best done by |
| --- | --- | --- | --- |
| **A reviewed registry row** (person, org, governance role) | The highest-value volunteer hour available. Attribution correctness is the top project risk; this is the control that mitigates it, and it cannot be automated | M | **CoSAI contributors** — people who were in the room |
| **A document↔RM mapping row** | Cannot be extracted — zero RM ids in the corpus. Every row is irreplaceable human work, and Winter's schedule depends on rows existing before Winter | M | Contributors + students, Fall wks 5–8 |
| **A curated SHACL constraint** with its citing passage | Turns published prose into something a real system can be checked against. This is the project's end state in one artifact | H | Contributor judgment + student implementation, paired |
| **A framework alignment file** pinned to a release | Answers "I run D3FEND — what does that cover?", the query #388 opens with. Hard because a shared term is not a shared meaning | H | Contributors with framework depth |
| **An upstream issue against the RM YAML** | A gap found by the one-entry-per-id rule, reported where it can be fixed. Contribution to CoSAI as a by-product of building | E–M | Contributors — needs standing in the coalition |

### Artifacts that are the build

| Artifact | Value | Diff. | Best done by |
| --- | --- | --- | --- |
| **A test** | Non-negotiable; the 393-test baseline never drops. Three per parser, per `plan.md` §11 | M | Students |
| **A parser or pipeline PR** | The milestone itself. Determinism is the bar: same inputs, same graph, every time | H | Student pairs |
| **A new ontology term** | Permanent and expensive to change. Needs a BFO/CCO parent, a label and a comment, and review before merge | H | Ontology owner + Lead |
| **An MCP tool** | Where the graph becomes usable by anyone who isn't us | M | Students |
| **A skill + portable evals** | The unit CoSAI can actually adopt (ADR-031/033). The difference between a repo and a contribution | M–H | Students, with a contributor writing the evals |
| **An ADR** | The durable artifact. It outlives the cohort, and it is the only thing that stops the next team relitigating a settled question. Records the rejected options and why. ADR-WS2-003 does more than that: it fixes the tool surface and the refusals, so no milestone has to renegotiate what the system is for | M–H | Whoever made the decision |

### Artifacts that carry the work outward

| Artifact | Value | Diff. | Best done by |
| --- | --- | --- | --- |
| **An upstream PR to CoSAI** | The point of the project. Latency is in the iCLA and the review, not the code — which is why week 1 starts it | M (process, not code) | Students, Co-Lead shepherding |
| **A talk to a workstream** | Recruits the next cohort and earns the standing that makes the next gate answerable | M | Co-Lead + a student |
| ★ **A release with a pre-built `graph.db`** (§6.4 Phase A) | Most of hosting's reach for none of its governance cost — a consumer skips fetch and build entirely. The best value-per-hour artifact in the whole plan | E | A student, Fall wk 8 or Winter wk 4 |
| **A hosted demo endpoint** (§6.4 Phase B) | Turns a repo link into a live answer in a TSC call. Hard because it is a classification change, not a deploy | H | Two students + a named operator, Winter stretch |
| **The Fall / Winter report** | The handover. A four-week Winter only works if the Fall handover is written, not remembered | M | Everyone, one section each |

**One quality note that applies to every artifact above.** *An absence correctly reported
beats a plausible answer invented.* A tool that says "not asserted" where the data does not
support an answer is the higher-quality result. The golden set in `plan.md` §11 contains one
of these on purpose — *"Was Bill Stout at ServiceNow in Aug 2026?"* → **Unknown/not
asserted** — and a contribution that adds another is worth more than one that adds a feature.

---

## 10. Risks

| Risk | Why it bites *this* team shape | Mitigation |
| --- | --- | --- |
| **Attribution correctness** — the top risk, inherited | Fewer hands, so less cross-checking by default | The registry gate, countersigned, never by the parser's author. Contributors review because they were there |
| **Volunteer time evaporates** | 2–5 contributors at 2–4 hrs/wk is 8–20 hrs/wk of *hoped-for* effort | Nothing committed sits in the curation lane. The wrangler keeps ≥10 ready issues; first PRs reviewed same-week |
| **The two Leads are the bottleneck** | Merge authority, gate countersign, coalition interface and recruiting all sit in two people | Lead and Co-Lead can each countersign. Release manager rotates to a student from v2 |
| **Scope of step 6** | 6–10 expert weeks does not fit in two student weeks | Fall v3 is `NEXT-STEPS.md` §6.6 steps 1–2 only, committed/stretch split stated in week 1 |
| **False temporal precision** | The instinct is to fill in a start date | `boundsKnown` / `inferred` mandatory, surfaced in tool output, asserted by a test |
| **Upstream RM churn** | The target moves during the term | Pin per milestone, re-pin at gates, review the diff |
| **PII handling** | Contributors may assume CoSAI data is theirs to copy | §7 Q1 rules stated at onboarding, not discovered |
| **Hosting eats a milestone** | It looks like a deploy and costs a classification change; it is the most tempting scope creep available | Preconditions in §6.3 are all-or-nothing; decided once at the week-6 gate; Phase A is the default answer |
| **A hosted service outlives its operator** | Students graduate mid-Winter; an unowned endpoint serving coalition data is a liability | A named operator with a term beyond the cohort, and a **dated** decommission runbook written before launch, not after |
| **Bus factor** | At 2 students, one leaving is half the build lane | Pairs, not solos. Conventions written down in week 4, not week 8 |
| **Student availability** | Midterms and exam weeks | Week 8 ends 2026-11-20, clear of Thanksgiving; Winter wk 3 light around MLK Day |
| **Token budget overrun** | A shared account and enthusiastic parallel exploration | Weekly cap set in week 1; fresh tight-scope sessions over long ones |

---

## 11. Rules that do not bend

**D1–D12 above.** They are not style preferences: each exists because violating it produces a
specific wrong answer about a real person or a real system. Cite them by number in review
comments, commit messages and validator output, so a check can always name the decision it
enforces.

The four that catch people most often: **D3** no fabricated bounds, **D5** the human registry
gate, **D8** no rate without a denominator, **D10** `SERVICE`/`LOAD` refused.
