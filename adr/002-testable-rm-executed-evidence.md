# ADR-WS2-002: Testable RM — executed evidence that a CoSAI control mitigates a CoSAI risk

**Status:** Draft — binding from Fall week 1 (2026-09-28)
**Date:** 2026-09-21
**Authors:** Vinay Bansal (Lead), Josiah Hagen (Co-Lead)

---

> **These decisions become binding in Fall week 1 — the week of 2026-09-28.** Until then
> this is a first specification that nobody has approved, and any part of it is open to
> being argued with at no cost. From week 1 the D-numbers below are the contract the
> cohort builds against and CI cites: changing one is an amendment with a dated section,
> not an edit, and a reversal needs a superseding ADR. Raise objections before then.

## Context

This project builds a harness that turns the CoSAI Risk Map from a set of *asserted* relationships
into a set of *tested* ones — the ask in
[`secure-ai-tooling#491`](https://github.com/cosai-oasis/secure-ai-tooling/issues/491). The Risk
Map says that a control addresses a risk, 37 controls against 36 risks, reciprocally linked; no
executed evidence exists anywhere that any one of those edges holds. The harness runs a documented
attack against a deliberately vulnerable target, undefended and then defended, and derives its
verdict from the telemetry the Telemetry RFC already says a compliant system must emit. The output
is a run record keyed to the Risk Map's own ids, so a practitioner asking *"does this control
actually stop that risk, and how would I know?"* gets a reproducible answer carrying a date, the
versions it ran against, and a claim-strength tier that says what the answer does and does not
license. The same motion tests the RFC: a MUST field that cannot evidence the outcome it exists to
evidence is a finding about the RFC, not a gap to paper over.

**Four inputs already exist**, so the work is integration rather than new research: the Risk Map on
`develop` (36 risks, 37 controls, 42 components, 10 personas, reciprocal `risk.controls` ↔
`control.risks` edges) as the claim under test; Telemetry RFC v0.5 with 98 fields and **49
documented attacks**, serving as both attack corpus and observation contract; `secure-ai-tooling`
validator infrastructure and its ADR-025 / ADR-034 / ADR-037 rules; and a scoped first-slice
proposal already public on #491. §0 details each.

**Three things do not exist**, and are therefore the work: a harness that executes a pair and
produces an inspectable verdict; a target with enough surface to attack; and any executed
evidence, anywhere, that a CoSAI control mitigates a CoSAI risk.

**Boundaries.** [#491](https://github.com/cosai-oasis/secure-ai-tooling/issues/491) is canonical
for *what is being asked for* — where it and this ADR disagree on scope, the issue and the TSC
win. [ADR-WS2-001](001-cosai-oracle-graph-and-mcp-server.md) is canonical for the CoSAI-RM ontology and runs on
the same calendar; Winter §5.3 is the join, and the conventions the two share — committed/stretch,
gates, absence-is-a-finding — are deliberate, so two cohorts that work the same way can review each
other.

> Hosted in `cosai-graphrag-mcp` for now; moves to its own repository later, at which point the
> link above and the pointer in that repository's `README.md` both become cross-repository URLs.

## Decision

Twelve invariants. Each exists because violating it produces a specific false claim about a real
system, so cite them by number in review, commits and validator output.

### D1. A green run that never fired the attack is a false assurance claim

Every pair carries a positive control demonstrating the undefended path reaches the manifested
state. The harness **fails closed** on a pair whose positive control did not fire.

### D2. Nobody scores their own run

Red writes the attack, Blue writes the control, Harness writes the scorer — and the scorer exists
before either. No verdict is countersigned by the author of the attack or the control.

### D3. No invented attacks

Every attack traces to a documented instance in the RFC corpus with its primary source. Taxonomies
establish recognition, not occurrence — the RFC's own evidence rule, and it binds us too. A novel
attack is a proposal to the corpus, not a coverage number.

### D4. One run record per `(risk, control, attack, tier)`, keyed on upstream ids, never invented

Missing concept → file upstream and wait. This is ADR-WS2-001 D7 seen from the consuming side.

### D5. The verdict derives from emitted telemetry, not from bespoke assertions

If a field the RFC marks MUST cannot evidence the outcome, that is a finding against the RFC or
the harness — not a license to assert the outcome directly.

### D6. Claim strength is the weakest tier demonstrated, and the tier is printed

Tier A licenses nothing about any model. Tier B licenses a statement about one model on one date.
Only Tier C licenses a rate.

### D7. A rate without a named denominator does not ship

### D8. Attacks run against the range

Never a third-party system, never a production deployment, never a provider's service outside its
terms. No credentials, no live secrets, no network egress from Tier A or B.

### D9. Absence is the finding

A risk with no executable control, an attack nobody could reproduce, a control nobody could make
fail — reported in the coverage report, never omitted from it.

### D10. Every control ships with a known-bad mutant its pair must kill

And every attack ships with a benign negative control, proving the defense did not simply break
the product.

### D11. Pin everything, re-pin at every gate, review the diff

Corpus commit, model version and provider, range commit, framework release. A run record that does
not say what it ran against is not evidence.

### D12. A pair lands whole or not at all

Attack, control, mutant, benign case, fixtures, run record, countersigned verdict — one PR.

## Alternatives Considered

- **Expert assertion, as today** — rejected. It is what the Risk Map already does, and it leaves
  every risk↔control edge unfalsifiable. No way to be wrong in public is no way to be trusted.
- **Unit-test-style assertions against the control implementation** — rejected. It tests that the
  code does what its author meant, not that the attack stops. D1 and D5 exist to close exactly
  that gap.
- **Adopting Atomic Red Team directly** — rejected as the whole answer, retained as prior art.
  Its tests are not keyed to CoSAI ids and its corpus is not the RFC's 49 documented AI attacks,
  so it cannot satisfy D3 or D4. §3 week 2 evaluates it alongside AgentDojo.
- **A red-team narrative report** — rejected. Not reproducible, not re-runnable against a new
  model version, and it cannot produce a coverage denominator.
- **Waiting for the Risk Map to stabilize** — rejected. `develop` grows during the term; D11's
  pinning makes a moving target workable, and a first executed pair is worth more now than a
  complete one later.

## Consequences

### Positive

Executing attacks is more costly than asserting a risk↔control relationship. Four effects
justify the cost.

**1. It converts an editorial judgment into a measurement.** A risk↔control edge is currently an
expert assertion with no procedure that could falsify it. A harness run supplies one: a
**positive control** first, establishing that the attack reaches the manifested state against an
undefended target, and only then a defended run eligible to pass. Without the positive control, a
passing result is indistinguishable from a non-functioning test. D1 therefore fails closed on a
pair whose positive control did not fire.

**2. One experiment tests two artifacts.** Because the verdict derives from emitted telemetry rather
than bespoke assertions, every run exercises the Telemetry RFC's 98 fields as an *observation
contract* at the same time as it exercises the control. A field the RFC marks MUST that cannot
evidence its intended outcome is a finding against the RFC — a result the RFC cannot produce
about itself, obtained here as a by-product of the same run.

**3. Coverage becomes countable.** The report states which pairs have executed evidence, which do
not, and which controls are specified such that no experiment could falsify them. That third
category is unfalsifiable rather than strong, and identifying it is a primary output of the Fall
term; no other artifact in the coalition currently produces it.

**4. The run records are an index into the Risk Map.** Every record is keyed by risk id, control id,
attack id, component and telemetry field, so evidence joins back to the RM catalog and, through
the same ids, to the sibling project's ontology — which is why Winter §5.3 is a join rather than
an integration. *Which controls have been tested, against what, when, and at what strength*
becomes a query. The ids must therefore be the Risk Map's own and never invented (D4); a record
keyed to a non-existent id supports no claim.

### Negative

A target range must exist before anything can be measured, and none does; this is the top scope
risk (§9) and the reason week 2 decides its shape rather than building it. Runs are slower and
less deterministic than unit tests. Most early results will be negative or inconclusive, and
treating a negative as a failure to be tuned away invalidates the evidence being gathered.
Executed evidence also expires: it is pinned to a model, a range commit and a corpus commit, so a
Tier B claim about one model on one date does not extend six months. Re-running is recurring
maintenance, not rework (D11).

### Follow-up

The range decision and the pair contract are the two week-2 decisions everything else rests on
(§3); each warrants its own ADR in the WS2 series once taken. Upstream, D3 and D4 generate issues
against the RFC corpus and the Risk Map YAML rather than local workarounds. The SIG question in §6
G1 is the TSC's.

---

# Project plan

Eight weeks in Fall, four in Winter, delivering D1–D12 in the order below. Where this plan and
#491 disagree on scope, the issue and the TSC win; on sequencing or staffing, this plan wins.

## 0. What already exists, so nobody starts from zero

Four things are already built, and knowing this changes the week-1 posture from "design a research
program" to "wire together four existing artifacts and measure what falls out."

| Asset | State | What it gives this project |
| --- | --- | --- |
| **CoSAI Risk Map**, `develop` | **36 risks, 37 controls, 42 components, 10 personas** (plus 6 control and 4 component category nodes). Reciprocal `risk.controls` ↔ `control.risks` edges | The claim under test. Every pair the harness executes is an existing edge in this graph |
| **Telemetry RFC v0.5** (`ws2-defenders`) | **98 fields: 50 MUST / 33 SHOULD / 15 MAY**. **49 documented attacks**: `TA-01`…`TA-28`, `IR-01`…`IR-05`, `AOC-01`…`AOC-16` | The attack corpus *and* the observation contract. Appendix A maps each attack to its detecting fields, ATLAS technique and RM components; Appendix B.2 maps telemetry cluster → risk → control |
| **`secure-ai-tooling` validator infrastructure** | `scripts/hooks/`, ADR-025 (testing strategy), ADR-034 (landing sequence), ADR-037 (CI authority) | The rules any contributed harness must obey, and three named prior failures worth not repeating (D1, D2) |
| **A scoped first-slice proposal** | [@HarperZ9 on #491](https://github.com/cosai-oasis/secure-ai-tooling/issues/491#issuecomment-5449359378) — a four-part invariant and a three-file boundary; [refined](https://github.com/cosai-oasis/secure-ai-tooling/issues/491#issuecomment-5673391465) after the Co-Lead's Atomic Red Team pointer | A well-formed starting contract, already public, already reviewed by the Co-Lead |

**The red team does not invent attacks.** Forty-nine are cataloged, each with a primary source, a
detecting-field list and a component mapping. Weeks 1–3 are selection, not discovery.

### What is *not* built, and is therefore the work

1. A harness that executes a risk↔control pair and produces an inspectable verdict.
2. A target with enough surface to be attacked. There is none. §3 week 2 decides its shape and it
   is the top scope risk in the project (§9).
3. Any executed evidence, anywhere, that a CoSAI control mitigates a CoSAI risk.

---

## 1. The team

| | Count | Commitment | Obligation |
| --- | --- | --- | --- |
| **Lead** — Vinay Bansal | 1 | Weekly | Project accountability, TSC interface and the SIG question (§6 G1), scope arbitration, compute, contributor recruiting, meeting slots |
| **Co-Lead** — Josiah Hagen | 1 | Weekly | Technical direction, merge authority, the invariants D1–D12, corpus and upstream-issue routing |
| **Students** | 4–8 | 8–10 hrs/wk, fixed calendar | The critical path. Milestones v0/v1/v2/v3 are theirs |
| **CoSAI contributors** | 2–5 | 2–4 hrs/wk, variable, may lapse | Issue-based. **Never on the critical path** |

The two populations are managed differently, and conflating them is the main way a project this
shape fails. Students have a fixed calendar and a deliverable obligation; contributors are working
professionals volunteering around a day job. Any plan that puts a milestone behind a volunteer's
week is a plan that slips.

> **Volunteer work is detachable.** Contributor work here is corpus judgment: which attack in the
> RFC corpus grounds which risk, whether a control description is implementable as written, whether
> a verdict is warranted by what the run showed. Each fits a single sitting, and no committed
> scope depends on it.

`@HarperZ9` is already engaged on the issue and has proposed a bounded contribution. Treat them as a
contributor under §1's rules from week 1, with the harness-contract review (§3 week 2) as the
natural first task — it is docs, it is squarely what they offered, and it does not require the
ownership question to be settled first.

### Three teams

| Team | What it owns | What it does not own |
| --- | --- | --- |
| **Harness** | The run-record schema, the scorer, the fixture loader, CI wiring, the coverage report | Any attack. Any control. It never decides whether a pair passed |
| **Red** | Faithful reproduction of a cataloged attack against the range; the *positive control* proving the attack fires undefended | The scoring. The control |
| **Blue** | The control implementation as the RM describes it; the *known-bad mutant* of its own control; the benign-traffic negative control | The scoring. The attack |

Three failure modes this split exists to prevent, in the order they actually occur:

1. **Harness becomes a service desk.** Red and Blue queue behind a two-person team writing bespoke
   glue for each pair. Prevented by: the harness team owns a *contract*, not per-pair code. If a
   pair needs harness changes after week 4, that is a defect in the contract, and it is logged as
   one.
2. **Red and Blue race.** Prevented by: the unit of delivery is a **pair**, landed together. Red
   does not score, Blue does not score, and neither ships alone.
3. **Everyone agrees too early.** Red and Blue are the cross-check on each other. A control whose
   author also wrote the attack it survives has been tested by nobody.

### Allocation, and why Blue is never smaller than Red

Attack specifications are already written (49 of them, with detecting fields). Control
implementations are not. Blue's work per pair is strictly larger, so the odd student goes to Blue.

| Cohort | Harness | Red | Blue | Pair-units | Committed pairs (wks 3–7) | Stretch |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 2 | 1 | 1 | 1 | **5** | 7 |
| 5 | 2 | 1 | 2 | 1 | **6** | 8 |
| 6 | 2 | 2 | 2 | 2 | **8** | 11 |
| 7 | 2 | 2 | 3 | 2 | **9** | 13 |
| 8 | 2 | 3 | 3 | 3 | **11** | 15 |

Harness is fixed at 2 at every size. It is a contract, not a volume, and a third person on it is a
third opinion about the contract rather than more throughput. At 7–8 students the extra capacity
goes to pair production, where it converts directly into coverage.

Arithmetic behind the pair counts: the first pair costs ~2 student-weeks (it shapes the contract and
builds the first range surface); pairs 2–4 cost ~1; pairs 5+ cost ~0.6 once the range and fixtures
stabilize. One pair-unit is a Red/Blue couple. Weeks 3–7 is five weeks including the reference pair
in week 3. **If the first pair costs more than 3 student-weeks, cut the committed number at the
week-5 gate rather than discovering the overrun in week 7.**

### Roles, held by people rather than teams

| Role | Held by | Responsibility |
| --- | --- | --- |
| Contract owner | One harness student, mentored by Co-Lead | The run-record schema and the scorer. No verdict semantics change without review |
| Range owner | One harness student | The reference target. Determinism: same inputs, same run record, every time |
| Telemetry owner | One student, whole term | That verdicts derive from RFC fields (D5), and that the emitted field set is measured against the 50 MUST |
| **Verdict gatekeeper** | Co-Lead, countersigned by Lead | Every published mitigation claim. **Never countersigned by the author of the attack or the control** |
| Corpus liaison | Co-Lead + one contributor | Pins, re-pins, and reviews the upstream RM diff at each gate; files the gap issues Red and Blue generate |
| Contributor wrangler | Lead | ≥10 ready issues at all times; greets every new contributor within 48h |
| Release manager | Rotating student | Tags v0/v1/v2/v3; keeps the coverage report true |

---

## 2. Cadence

Fixed in week 1, not renegotiated after week 2.

| Meeting | When | Length | Who | Required? |
| --- | --- | --- | --- | --- |
| Working session | Wed | 60 min | Everyone | Students yes, contributors no |
| Async written update | Mon | — | Students | Yes — one paragraph, what's planned |
| **Pair review** | Thu | 30 min | Red + Blue of the landing pair, + gatekeeper | Yes, for any pair landing that week |
| Demo slot | End of Wed session | 15 min | Whoever has a run | **A run record or a failing test. No slides** |
| Leads' sync | Mon | 20 min | Lead + Co-Lead | Yes |
| Milestone gate | Weeks 3, 5, 7, 8 | 90 min | Everyone + TSC sponsor | Yes |
| CoSAI meetings | Per series | — | Lead + one student, rotating | Rotating student yes |

### Working rules

- Short-lived branches, PR, one review, CI green. A contributor's first PR is reviewed same-week —
  latency is what loses volunteers.
- **A pair lands as one PR**: attack, control, mutant, benign negative control, fixtures, run
  record, and the countersigned verdict note. Half a pair does not land.
- Every attack lands with its fixture **before** it lands with its code (ADR-025 D2, RED-phase).
- Unresolved anything — a pair that neither manifests nor prevents, a control too vague to
  implement, a field that cannot evidence an outcome — goes to a report under `reports/`, never to a
  guess or a skipped test.
- A Wednesday outcome note in `SESSION-NOTES.md`, including what the week cost in compute and tokens.

---

## 3. Fall, week by week

Week 1 is the week of **2026-09-28**; week 8 ends Fri **2026-11-20**, clear of Thanksgiving
(2026-11-26). Shift the whole table together if week 1 moves.

| Week | Of | Harness | Red | Blue | Gate |
| --- | --- | --- | --- | --- | --- |
| 1 | 09-28 | Form, environment, recruit, paperwork | Corpus reading | Corpus reading | Charter + 10 issues |
| 2 | 10-05 | Tool eval → **ADR-H1**, **ADR-H2** | Tool eval briefs | Tool eval briefs | **ADR-H1 + ADR-H2** |
| 3 | 10-12 | Contract + scorer + CI | Reference attack | Reference control + mutant | **v0** |
| 4 | 10-19 | Range surfaces on demand | Batch 1 attacks | Batch 1 controls | |
| 5 | 10-26 | Coverage report v1 | Batch 1 | Batch 1 | **v1** |
| 6 | 11-02 | Tier C runner | Batch 2 | Batch 2 | |
| 7 | 11-09 | Coverage + gap report | Batch 2 | Batch 2 | **v2** |
| 8 | 11-16 | Freeze, handover | Presentation | Presentation | **v3 + preso** |

---

### Week 1 — Form, ramp, recruit

**Goal.** A team that can make decisions, standing inside CoSAI to make them with, and everything
with latency started.

1. **Teams and roles** per §1. Name the verdict gatekeeper in week 1, not the first time a verdict
   is contested.
2. **Cadence.** Fix the §2 slots against the CoSAI meeting calendar so conflicts surface now rather
   than in week 5.
3. **Environment.** Everyone clones `secure-ai-tooling` (`develop`) and `ws2-defenders` and runs
   `pre-commit run --all-files` and `pytest` green before Friday. Python ≥3.11. Note that anaconda's
   `gh` shadows `/usr/bin/gh`, and that `gh issue view` currently fails on this repo with a
   Projects-classic GraphQL deprecation error — use `gh api repos/.../issues/N`.
4. **Pin the corpus.** Record the `develop` commit of `risk-map/yaml/` in the charter. Everything
   this term is stated against that pin. Re-pinned at every gate (D11).
5. **Paperwork, now, because it has latency.** OASIS Open Project iCLA on file for every student and
   contributor who will contribute upstream. Started in week 1 or it blocks the Winter PR.
6. **Compute.** Who owns the model API account and the weekly cap (§6 G3). Tier C (§3 week 2) does
   not exist without it, and "beg for compute resources" is the issue's own wording. Ask in week 1
   so a "no" arrives in time to change the plan rather than in time to end it.
7. **Recruit 2–5 CoSAI contributors — Lead owns this, and it is a week-1 deliverable.** The
   backlog is the recruiting instrument: ten well-specified good-first-issues exist before the pitch
   goes out. The concrete ask: *"ninety minutes reading one risk's control description and telling
   us whether it is implementable as written."*
8. **Open the SIG question** (§6 G1). The Co-Lead has already stated on #491 that code artifacts need a
   long-term owner before contribution is approved. That question is now on the project's critical
   path for *landing*, not for *building*, and week 1 is when it gets a date.

**Reading, split across the team, one-page brief each, presented Wednesday of week 2.** The briefs
are the deliverable, not the reading.

| Material | Question the brief answers |
| --- | --- |
| Telemetry RFC §§4–16 | What are the 50 MUST fields, and which are emittable by a small agent today? |
| Telemetry RFC Appendix A.1–A.3 | What are the 49 attacks, and which have enough detail to reproduce? |
| Telemetry RFC Appendix A.5, B.2 | What is the existing attack → ATLAS → risk → control mapping, and where is it thin? |
| RM `risks.yaml` / `controls.yaml` on `develop` | What is the shape of a risk and a control, and what does a reciprocal edge look like? |
| RM `components.yaml`, `personas.yaml` | What surfaces must a range have to host these attacks? |
| PR #507 | What lands if it merges, and what does that do to our denominator? |
| ADR-025, ADR-034, ADR-037 | What must a contributed test surface look like, and what three ways has this repo already been fooled by a green check? |
| Issue #480 | What is the vacuous-coverage failure class, in one paragraph? |
| ADR-002, ADR-004, ADR-031/033 | Where does code land, how is AI assistance attributed, what shape is contributable? |

**Exit criteria.** One-page charter in the repo (teams, roles, cadence, corpus pin, compute cap,
escalation path). Both repos green on every machine. **Ten ready issues.** iCLA process started. One
recruiting pitch delivered to a live CoSAI call.

---

### Week 2 — Tool evaluation, and the two decisions everything else rests on

**Goal.** Two architectural decisions, each with evidence, each written down so the next cohort does
not relitigate it.

#### Tool evaluation

Split across the team, one-page brief each, 5 minutes on Wednesday. Evaluate **as a substrate**, not
as a product to admire.

| Tool | Question the brief answers |
| --- | --- |
| **Atomic Red Team** | The Co-Lead's named pattern. What does a taxonomy-linked atomic test look like — inputs, prerequisites, execution requirements, cleanup — and what does the cleanup contract buy us? |
| **CALDERA** | What run-state distinctions does an execution record need (skipped / executed / failed), and which of ours are missing? |
| **PyRIT** | It separates execution from scoring, which is our §1 team split. Can its orchestrator/scorer seam be our Tier B/C substrate? (Raised at TSC 2026-09-15, incl. the 1.1.0 GUI) |
| **garak** | Probe/detector split ≈ attack/telemetry-assertion split. What does its detector library already cover? |
| **AgentDojo** | The closest prior art: agent prompt-injection benchmark with a **dual utility+security metric**. How do they prove the attack fired, and what is their benign-utility baseline? Their treatment of D1 |
| **promptfoo / DeepTeam** | Is a declarative config sufficient, or does a pair need code? |
| **Inspect (UK AISI)** | Solver/scorer model — does it fit better than pytest for Tier C? |
| **pytest + `secure-ai-tooling`'s hook framework** | If the harness lands in that repo, what does ADR-025/ADR-037 compel? |
| **OpenTelemetry GenAI semconv + collector** | Can we emit the RFC's MUST fields today? RFC Appendix D.2 already answers this — verify it rather than re-deriving it |
| **Bounded mutation (mutmut / cosmic-ray)** | Do we need a framework, or is a hand-written known-bad mutant per control enough? Default: enough |

#### ADR-H1 — What does the harness execute against, and what may a green run claim?

The central decision. Getting it wrong in either direction is fatal: a purely synthetic harness
proves nothing about models, and a purely live harness is too flaky to gate anything.

**The recommendation to beat — three tiers, with claim strength bounded by tier:**

| Tier | What runs | Determinism | Where | What a green run licenses |
| --- | --- | --- | --- | --- |
| **A — Contract** | Synthetic state machine, no model, no network | Total | CI, blocking | *"The harness discriminates this case."* Nothing about any model |
| **B — Recorded** | A real model against the range, captured once, replayed | Total in CI, real in provenance | CI, blocking | *"This model, at this version, on this date, behaved this way."* |
| **C — Live** | Live model against the range, pinned version | None | Nightly, non-blocking | *"n of N trials, with the denominator named."* Never pass/fail |

And the rule that ties them, which is the intellectual core of the project:

> **A pair's claim strength is the weakest tier it has been demonstrated at, and the harness prints
> the tier on every verdict.** A Tier A green does not license the sentence "this control mitigates
> this risk." Tier B licenses it about one model on one date. Only Tier C licenses it as a rate.

This absorbs @HarperZ9's proposed first slice exactly — it is a well-formed Tier A fixture — while
making explicit the thing that slice correctly declined to claim.

Confirm this with a worked pair or overturn it with evidence. "We prefer X" is not a finding.

#### ADR-H2 — The range

Every attack in the corpus needs a *specific* surface: persistent memory (`TA-18`, `IR-02`,
`AOC-10`), a tool registry (`TA-14`, `TA-16`), retrieval (`TA-09`, `IR-03`), MCP transport
(`TA-11`…`TA-13`), multi-agent orchestration (`AOC-04`, `AOC-09`), an egress path (`TA-01`,
`TA-03`). Candidates: adopt an existing deliberately-vulnerable agent app; adapt AgentDojo's
environment; build a minimal purpose-built range.

**The recommendation to beat: build a minimal range, and grow it one surface at a time, owned by the
pair that needs the surface.** The reason is not preference — it is that you cannot add a surface to
someone else's application, and the corpus demands surfaces no single existing app has. The
mitigation for the obvious cost objection is that **the range is not a product**: it is the smallest
thing that exposes the surface an attack needs, with no UI, no persistence beyond the run, and no
generality that a landed pair does not require.

**The range is the top scope risk in this project (§9), and the committed scope is built to survive
it slipping**: Tier A needs no range at all, so v0 lands regardless.

**Exit criteria.** Briefs in the repo. **ADR-H1 and ADR-H2 merged** — decision, rejected options, the
reason each was rejected, and how to override it later. If ADR-H2 chooses an external target, a spike
proving one corpus attack reaches it.

---

### Week 3 → **v0: the contract, and one pair end to end**

**Goal.** One risk↔control pair, executed, scored, countersigned. Everything after week 3 is
repetition of this week at volume.

**The reference pair is `riskPromptInjection` ↔ `controlInputValidationAndSanitization`**, grounded
by `TA-02` (Slack AI) or `IR-01` (Breaking the Prompt Wall). Chosen because the edge is reciprocal in
the pinned corpus today, the attack is documented with primary sources, its detecting fields
(Model Input, Input Source, Input Trust Class, Guardrail(In)) are all MUST tier, and it is the pair
@HarperZ9 already proposed — so the first thing the team builds is the first thing an outside
contributor asked to review.

**Harness — the contract.** A run record, one per `(riskId, controlId, attackId, tier)`, keyed
**only** on upstream ids. It carries: the corpus pin; the declared environment and permitted actions;
the expected terminal state; the observed telemetry; the cleanup outcome; the verdict and its tier.
Execution output is kept separate from the observation that supports the verdict — a run that
produced no evidence is **invalid**, not passing.

> **Design the run record to be RDF-projectable and keyed on RM ids in week 3.** Winter's ontology
> integration (§5.3) is cheap only if this is true, and expensive to retrofit if it is not. This is
> the single highest-leverage five minutes in the term.

**Harness — the scorer, and the four-part invariant.** For every registered pair:

1. the undefended reference path **must** reach the manifested state (the *positive control*);
2. the defended path **must** prevent it;
3. a hand-written known-bad control mutant **must** be killed by at least one fixture;
4. benign inputs **must not** be over-rejected.

Discovery derives from the fixture directory and **fails closed** on zero fixtures, unknown ids,
non-reciprocal risk/control mappings, or unreachable verdict classes. This is #480's failure class
addressed at the point where it would otherwise recur.

**Red.** The attack, plus its positive control. Faithful reproduction, cited to the RFC entry and its
primary source.

**Blue.** The control as the RM describes it, its known-bad mutant, and the benign negative control.

**Week 3 selection — the backlog, ranked.** The week's second deliverable, called out in the
brief: choose the batch by capacity, against a written rubric rather than by preference.

A candidate pair scores on:

1. Risk and control both exist in the pinned corpus and the edge is **reciprocal**.
2. An attack in the RFC corpus grounds it, with a primary source. **No invented attacks** (D3).
3. Its detecting fields are **MUST** tier, so the observation contract is already normative.
4. The range surface it needs is built, or is one increment from built.
5. **The control is a mechanism, not a policy.**

Criterion 5 disqualifies a substantial minority of the corpus and is worth stating in week 3 rather
than discovering in week 6. Controls such as `controlUserPoliciesAndEducation`,
`controlInternalPoliciesAndEducation`, `controlProductGovernance`, `controlRiskGovernance`,
`controlRedTeaming`, `controlIncidentResponseManagement` and `controlUserTransparencyAndControls` are
governance and process controls; no harness executes them. **Producing the executable /
non-executable partition of all 37 controls, with the reason for each, is a week-3 deliverable and a
genuine contribution to CoSAI** — it tells the coalition which of its controls can ever be
evidenced by testing and which are assured some other way.

**Gate v0.** One pair green at Tier A and Tier B, countersigned. The ranked batch list published,
with the committed count from §1 drawn as a line across it.

---

### Weeks 4–5 → **v1: batch 1**

Repetition at volume. Red and Blue work pairs from the ranked list in order; Harness adds range
surfaces on demand and does not write pair code.

Bias batch 1 toward **distinct telemetry clusters** rather than distinct risks — the point of batch 1
is to find out where the contract breaks, and it breaks at cluster boundaries (memory, tools,
retrieval, identity), not at the twentieth injection variant.

**Week 5 — coverage report v1.** Generated, never hand-maintained. Per D9, it reports three
populations and does not privilege the first: pairs with executed evidence; pairs selected and not
yet executed; **and risks with no executable control at all.** The third is the finding.

**Gate v1.** The committed count's first half, green and countersigned. Contract defects from batch 1
either fixed or written down with a decision. **If the first-pair cost overran §1's arithmetic, the
committed number is cut here.**

---

### Weeks 6–7 → **v2: batch 2, Tier C, and the gap report**

**Week 6 — Harness builds the Tier C runner.** Live model, pinned version, nightly, non-blocking,
reporting `n of N` with the denominator named. It is deliberately late: Tier C is worthless before
there are pairs to run through it, and building it in week 3 would have made CI flaky for four weeks.

**Weeks 6–7 — Red and Blue finish the committed count.** Pairs are now cheap; this is where the
coverage number is actually made.

**Week 7 — the gap report, which is three reports in one.** Each team generates upstream issues as a
by-product of its own work, and this is the mechanism by which an internal student project becomes a
CoSAI contribution:

| Team | Gap it is uniquely placed to find | Where it is filed |
| --- | --- | --- |
| **Red** | Risks with no documented attack instance; attacks in the corpus too thin to reproduce | RFC corpus issues, `ws2-defenders` |
| **Blue** | Control descriptions too vague to implement; controls that are policy, not mechanism | RM YAML issues, `secure-ai-tooling` |
| **Harness** | MUST fields that cannot evidence the outcome they are supposed to; fields the RFC is missing | RFC issues, and the OTel asks in Appendix D.3 |

Filing these is **contributor work where it needs standing in the coalition** and student work where
it is a technical finding. The Co-Lead routes.

**Gate v2.** Full committed count green and countersigned. Coverage report and gap report published.
Every upstream issue filed, not listed as "to file."

---

### Week 8 → **v3: freeze, presentation, handover**

**Week 8 is the presentation week**, and the presentation has three audiences at once: the Duke
faculty, the CoSAI workstream, and the next cohort. Build one artifact that serves all three.

- **A live demo, with slides as backup and not the reverse.** Take one pair from attack to
  manifested risk to control to prevented risk to the run record, on screen. The weekly demo rule
  ("a run record or a failing test, no slides") holds here too; week 8 just adds narration.
- **Include one negative result.** A pair that did not work, a control that could not be
  implemented as written, or a risk nothing could evidence. A presentation with no negatives is a
  presentation nobody in the room believes, and this project's whole quality claim rests on
  reporting absences.
- **Freeze and tag.** Corpus pin, model versions, range commit, framework releases.
- **The written handover to Winter.** A four-week Winter only works if the handover is written.
- **The talk is also the SIG pitch and next cohort's recruiting** — which is why the Lead
  co-presents and why §6 G1 wants an answer before this week, not after.

---

## 4. Milestones: committed vs stretch

Each milestone is defined by a claim the project can newly make — and, as importantly, by the claim
it still cannot. **Committed** ships at 4 students; **stretch** is reachable at 7–8 with an active
contributor lane. Stretch items are not failures when they don't land; they are the buffer that
protects the committed scope.

### v0 — Contract and reference pair (end of week 3)

| | |
| --- | --- |
| **Demo claim** | "This attack reaches the manifested state undefended, this control prevents it, this mutant of the control does not, and benign traffic still works — here is the run record, at Tier B." |
| **Committed** | Run record schema (RM-id-keyed, RDF-projectable); scorer with the four-part invariant, failing closed; `riskPromptInjection` ↔ `controlInputValidationAndSanitization` at Tier A+B; CI wiring; the ranked batch list; the executable/non-executable control partition |
| **Stretch** | A second pair in a different telemetry cluster |
| **Tests** | The scorer's own tests, including: zero fixtures fails; unknown id fails; non-reciprocal edge fails; a run with no observed telemetry returns **invalid**, not pass |
| **Gate** | Verdict countersigned by someone who wrote neither the attack nor the control |

### v1 — Batch 1 (end of week 5)

| | |
| --- | --- |
| **Demo claim** | "Here are N pairs across four telemetry clusters, and here is where the contract broke." |
| **Committed** | Half the §1 committed count, Tier A+B, countersigned; coverage report v1, generated; contract defects resolved or recorded |
| **Stretch** | Range surfaces for the MCP and multi-agent clusters |
| **Tests** | Every pair carries its positive control, mutant and benign case. Re-running the full suite twice produces identical records |
| **Gate** | Committed count re-confirmed or cut, in writing |

### v2 — Full coverage sample and gap report (end of week 7)

| | |
| --- | --- |
| **Demo claim** | "N of 36 risks have executed evidence for at least one control; M have no executable control at all; here are the rates from live runs, with denominators." |
| **Committed** | Full §1 committed count; the Tier C runner with at least three pairs run through it; coverage report; gap report; every upstream issue filed |
| **Stretch** | Tier C across the whole batch; a second model provider, which turns one date's behavior into a comparison |
| **Tests** | Regeneration against a newer corpus commit produces a **reviewable diff**, not a silent pass |
| **Gate** | Coverage report's three populations all present. A report that lists only successes does not pass this gate |

### v3 — Presentation and handover (end of week 8)

| | |
| --- | --- |
| **Committed** | Live demo delivered; frozen, tagged artifacts; written Winter handover; one negative result presented |
| **Stretch** | The upstream contribution PR opened in Fall rather than Winter — possible only if the iCLA and §6 G1/G2 all landed |
| **Gate** | TSC sponsor has seen the claim-strength rule (§3 ADR-H1) and agrees the project's published claims match their tier |

---

## 5. Winter — extend, adapt, integrate (4 weeks)

Winter week 1 is **2027-01-04**; week 3 contains MLK Day (2027-01-18) and is planned light. Four
weeks is short, and the way it closes is that §3 week 3 already made the run record RM-id-keyed and
RDF-projectable. If that did not happen, Winter week 1 absorbs the retrofit and week 4's scope is
cut — not week 1's quality.

### Winter week 1 (01-04) — Adapt: defect burn-down and re-pin

The user's brief for Winter is *extend, adapt, integrate*, and adapt comes first because the other
two are built on it.

- **Burn down the Fall defect backlog.** Every "recorded with a decision" item from gates v1 and v2.
- **Re-pin the corpus, and diff.** PR #507 may have landed, taking the corpus from 36/37 to roughly
  **55 risks and 68 controls**. That is not a minor version bump: it changes the denominator in every
  coverage claim, and it may add a control that is a better match for a pair already landed. Reviewing
  that diff pair by pair is week 1's real work, and it is a two-person job with the corpus liaison.
- **Re-run everything at the new pin.** A pair that silently stops resolving is exactly the failure
  the ontology work's deprecation policy exists to catch (§5.3).

### Winter week 2 (01-11) — Extend: coverage batch 3

Pairs are cheap now. Prioritize by what the Fall gap report found, not by what is easy:

- **Committed:** the risks the Fall coverage report showed with no executed evidence and a
  mechanism-shaped control available — these are the cheapest reduction in the measured gap.
- **Committed:** any risk↔control edge added by #507 that the MCP-mediated attacks (`TA-11`…`TA-16`)
  already ground. The attack corpus is disproportionately MCP-heavy and #507 is the MCP decomposition;
  they were written for each other.
- **Stretch:** the three proposed risks in `~/cosai-telemetry/rm-proposals/` — `riskAgentMemoryPoisoning`,
  `riskDeceptiveAgentReporting`, `riskUnsafeInterAgentPropagation`, with `controlAgentMemoryIntegrity`.
  Executing an attack against a *proposed* risk is the strongest possible argument for adopting it,
  and `TA-18` / `IR-02` / `AOC-10` already ground the memory one.

### Winter week 3 (01-18, MLK Monday — light week) — Integrate with the CoSAI-RM ontology

The join with [ADR-WS2-001](001-cosai-oracle-graph-and-mcp-server.md). That project's
Fall v3 (its week 8) emits the Risk Map as OWL/RDF in the `cosai:` namespace, one entry per YAML id,
with a versioned namespace and a written deprecation policy. **That is a hard dependency on their
milestone, and it is why this is Winter week 3 and not Fall week 8.** If their v3 slipped, this week
becomes the projection design only and the load waits.

Three deliverables, in dependency order:

1. **Project run records into RDF.** Each record becomes evidence attached to a `cosai:` risk↔control
   edge, carrying its tier, its corpus pin, its model version and its date. Cheap, if §3 week 3 held.
2. **`rm_evidence_coverage`.** The term's target query: *which risk↔control edges have executed
   evidence, at what tier, and which have none.* It extends `rm_uncontrolled_risks`, which today
   reports only edges absent from the YAML, to also report edges present in the YAML and
   unevidenced in practice. Per D9, the unevidenced set is a reportable result, and this makes it
   queryable.
3. **Meet their constraint-enrichment work from the other side.** Their Winter week 3 turns the
   corpus's RFC-2119 statements into SHACL shapes; the Telemetry RFC's 50 MUST fields *are* RFC-2119
   normative statements. A shape says a deployment must emit field X; a harness run either does or
   does not. **The harness is the executable half of their constraint work**, and the two cohorts
   should pair for this week rather than integrate at the end of it.

One trap to brief in advance, and it is the same trap in both projects: **a renamed id silently
invalidates every stored record carrying it.** Their deprecation policy is what protects our
evidence, which is why it is their Fall week 8 deliverable and not a Winter nicety.

### Winter week 4 (01-25) — Upstream, report, handover

- **The upstream contribution PR**, iCLA already on file from Fall week 1, landing per ADR-002 and
  ADR-034 — infrastructure on `main`, any corpus change on `develop`, in layer order.
- **The final coverage and gap report**, against the re-pinned corpus, with all three populations.
- **The ownership answer.** §6 G1 has to be settled by now, because the artifact exists and an
  unowned test harness in a coalition repository decays into a broken CI job within two quarters.
  Whether the answer is a SIG, a workstream, or a named maintainer, week 4 is when it is recorded.
- **A talk to the workstream** — which is also next cohort's recruiting.
- **Stretch: a conformance mode.** Point the harness at a described deployment rather than the range
  and report which controls it evidences. The payoff of every prior milestone in one tool, and the
  reason to be careful: see D6.

**Winter demo claim.** *"For these N CoSAI risks we have executed evidence that a named control
prevents a documented attack, at this tier, against this model, on this date. For these M we do not,
and here is why each one is missing — no attack, no mechanism, or nobody got to it."*

---

## 6. Gates, dependencies and decisions the team cannot make

| # | Gate | Blocks | Owner | Needed by |
| --- | --- | --- | --- | --- |
| **G1** | Does this become a SIG, and who is the long-term owner of the code? | Any upstream landing. **Not the build** | TSC, via Lead | Week 3 |
| **G2** | Which repository hosts the harness — `secure-ai-tooling` (`main`), `ws2-defenders`, or new? | Repo conventions, CI shape, ADR-025/037 applicability | TSC | Week 2, before ADR-H1 |
| **G3** | Compute and model-API budget | Tier B and Tier C entirely. Tier A is unaffected | Lead + sponsor | Week 1 |
| **G4** | **May a CoSAI repository contain executable attack implementations?** | The publication posture of the whole project | TSC | Week 3 |
| **G5** | OASIS iCLA per person | Any upstream contribution | Lead | Week 1 |
| **G6** | PR #507 landing | The denominator in every coverage claim | Corpus liaison | Re-pinned each gate |
| **G7** | AI-assistance attribution beyond ADR-004's trailer | Contributor PRs | Maintainers | Week 2 |

**On G4, because it shapes what the project may publish.** The deliverable is a repository containing
code that makes an AI system misbehave. The posture to take to the TSC, which the team should adopt
from week 1 and not wait to have ratified:

- Attacks execute **against the range only** — never a third-party system, never a production
  deployment, never a provider's service outside its terms (D8).
- No exploit code reproducing a CVE against unpatched third-party software. The corpus entry cites the
  public primary source; the harness implements the *class*, on our own target.
- No credential, no live secret, no network egress from Tier A or B.
- The value of the artifact is the **control** half. A pair without a working control does not land,
  so the repository never accumulates attacks that nothing answers.

This is a narrower posture than a red-team tool would take, and it is deliberate: the audience for
this repository is defenders evaluating a control, and the attack is there to make the control's
claim checkable.

**On G1, because the Co-Lead has already answered it once.** #491's maintainer response is that code
artifacts need ongoing maintenance and therefore a long-term owner before contribution is approved.
The students are the natural first owner and are also, by construction, temporary. The project should
treat "who owns this in 2028" as a **deliverable**, with the SIG as the likely answer and the Fall
week 8 talk as the recruiting for it.

---

## 7. Skills ramp

Nobody arrives with all of this. Weeks 1–2 are where the gaps get named. Contributors need only the
bottom rows — their contribution is judgment, not code.

| Capability | Who | Depth |
| --- | --- | --- |
| Python, pytest, fixtures and plugins | Everyone | Working; **deep** for the contract owner |
| Deterministic test design, fail-closed discovery | Harness | Deep |
| Agent frameworks, MCP client/server | Harness + Red | Working |
| OpenTelemetry instrumentation, GenAI semconv | Telemetry owner | Deep |
| Prompt injection, jailbreak and agent-attack technique | Red | Deep |
| Detection engineering, guardrail and policy-enforcement implementation | Blue | Deep |
| MITRE ATLAS; ATT&CK where the corpus crosses over | Red + Blue | Working |
| Threat modeling against the RM component graph | Everyone by week 3 | Working |
| RDF / SPARQL / SHACL | One student, Winter | Working |
| **CoSAI RM semantics — what a control actually asserts** | **Contributors** | **Deep — this is what they bring** |
| **Judging whether a control description is implementable** | **Contributors** | **Deep** |

---

## 8. Artifacts: what each is worth

The unit of work is the artifact, not the hour — which is what lets a volunteer's evening and a
student's week live in the same backlog. **E**asy / **M**edium / **H**ard. ★ marks a good first
contribution.

| Artifact | Value | Diff. | Best done by |
| --- | --- | --- | --- |
| ★ **A well-specified issue** | Converts an evening of volunteer time into merged work. Ten are a week-1 deliverable | E | Whoever just finished the adjacent work |
| ★ **A one-page tool-eval or corpus brief** | Turns one person's reading into the team's knowledge | E–M | Contributors, week 2 |
| ★ **A judgment on whether a control is implementable as written** | The gating input to §3 week 3's rubric, and unautomatable | E–M | **Contributors** |
| **A positive control** (proof the attack fires undefended) | The single artifact that separates this harness from a green test that proves nothing | M | Red |
| **A known-bad control mutant** | The specific defense against #480's vacuity class. Cheap to write, impossible to fake | M | Blue |
| **A benign negative control** | Stops the project from "mitigating" the risk by breaking the product | E–M | Blue |
| **A landed pair** | The milestone itself, and the only artifact that supports a mitigation claim | H | Red + Blue, together |
| **A range surface** | Unblocks a whole telemetry cluster. Permanent, and expensive to get wrong | H | Harness |
| **An upstream issue against the RM YAML** | A gap found by trying to implement a control. Contribution to CoSAI as a by-product | E–M | Contributors — needs standing |
| **An upstream issue against the RFC corpus** | An attack too thin to reproduce, found by trying to reproduce it | E–M | Red |
| **An entry in the non-executable control partition, with its reason** | Tells the coalition which controls can *ever* be evidenced by testing | M | Blue + contributors |
| **An ADR** | Outlives the cohort; the only thing that stops the next team relitigating a settled question | M–H | Whoever made the decision |
| **The coverage report** | Generated, never curated. Its third population — risks nothing can evidence — is the most valuable result that no other artifact in CoSAI produces | M | Harness |
| **The Fall / Winter report** | The handover. A four-week Winter only works if it is written, not remembered | M | Everyone, one section each |

**One quality note that applies to every artifact above.** *An absence correctly reported beats a
plausible claim asserted.* A coverage report that says "this risk has no executable control" is a
higher-quality result than one that quietly omits it, and a pair that lands as "control could not be
implemented as described, here is the upstream issue" is worth more than a pair that lands green
because the control was silently reinterpreted until it passed.

---

## 9. Risks

| Risk | Why it bites *this* team shape | Mitigation |
| --- | --- | --- |
| **The range eats the term** — top risk | Every attack wants a different surface, and "build a small agent platform" is a term's work on its own | ADR-H2's minimality rule. Surfaces added only by the pair that needs one. **Tier A needs no range, so v0 survives total range failure** |
| **Vacuous green** — highest-impact failure | A harness that reports mitigation when the attack never fired publishes a false assurance claim as a coalition artifact. This repository has produced three prior instances (#480, ADR-025 D10, ADR-037) | D1 and D2; the positive control; the mutant; fail-closed discovery; a run with no evidence returns **invalid**, not pass |
| **Claim overreach downstream** | Someone quotes "CoSAI proved control X mitigates risk Y" from a Tier A fixture | The tier is printed on every verdict and stated in the presentation. D6. The TSC sponsor signs off on the claim language at gate v3 |
| **Red and Blue become adversaries rather than a cross-check** | Natural dynamic of the naming | Pairs land together or not at all. Neither scores. Both are measured on landed pairs, not on wins |
| **Harness becomes a service desk** | Two people, N pairs, bespoke glue | The contract is frozen at v0. Per-pair harness work after week 4 is logged as a contract defect and fixed at the contract |
| **Compute never arrives** (G3) | Tier B and C both need model access | Ask week 1. If the answer is no, the project is Tier A only — say so at gate v0 and re-scope the claims, rather than pretending in week 7 |
| **Non-determinism leaks into CI** | Live models in a blocking gate | Tier C is nightly and non-blocking, by construction, and is built in week 6 rather than week 3 for exactly this reason |
| **Corpus churn** (#507: 36→~55 risks) | Changes the denominator mid-term and may obsolete a landed mapping | Pin at week 1, re-pin at every gate, review the diff. Winter week 1 is reserved for the big one |
| **Governance latency** (G1, G2, G4) | Three TSC-shaped questions sit between a working harness and a landed contribution | All three asked in weeks 1–3, not week 8. **None of them blocks building** — that separation is deliberate |
| **Volunteer time evaporates** | 2–5 contributors at 2–4 hrs/wk is *hoped-for* effort | Nothing committed sits in the contributor lane. ≥10 ready issues; first PRs reviewed same-week |
| **The two Leads are the bottleneck** | Merge authority, verdict countersign, TSC interface and recruiting in two people | Lead and Co-Lead can each countersign — but never the author of the attack or the control. Release manager rotates to a student from v1 |
| **Bus factor** | At 4 students, one leaving is a whole pair-unit | Red and Blue each ≥1 and never solo on a cluster. Conventions written down in week 3, not week 8 |
| **Student availability** | Midterms and exam weeks | Week 8 ends 2026-11-20, clear of Thanksgiving; Winter week 3 light around MLK Day |

---

## 10. Rules that do not bend

**D1–D12 above.** Each exists because violating it produces a specific false claim about a real
system. Cite them by number in review comments, commit messages and harness output, so a check can
always name the decision it enforces.

The three that determine whether a result is credible: **D1** the positive control, **D2**
separation of scoring from authorship, **D6** the printed tier.
