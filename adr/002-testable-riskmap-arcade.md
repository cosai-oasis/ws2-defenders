# ADR-WS2-002: ARCADE (Assessing Risks and Control through Attack Detection Evaluations): executed evidence that a CoSAI control mitigates a CoSAI risk

**Status:** Draft - Pending Review
**Date:** 2026-09-21
**Authors:** Vinay Bansal (Lead), Josiah Hagen (Co-Lead)

---

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
proposal already public on #491.

**Three things do not exist**, and are therefore the work: a harness that executes a pair and
produces an inspectable verdict; a target with enough surface to attack; and any executed
evidence, anywhere, that a CoSAI control mitigates a CoSAI risk.

**Boundaries.** [#491](https://github.com/cosai-oasis/secure-ai-tooling/issues/491) is canonical
for *what is being asked for* — where it and this ADR disagree on scope, the issue and the TSC
win. [ADR-WS2-001](001-bubo-graphrag-mcp.md) is canonical for the CoSAI-RM ontology, which
the run records join through the Risk Map's own ids (D4). The conventions the two share, such as
absence-is-a-finding, are deliberate, so two cohorts that work the same way can review each
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
  so it cannot satisfy D3 or D4.
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
category is unfalsifiable rather than strong, and identifying it is a primary output of the
harness; no other artifact in the coalition currently produces it.

**4. The run records are an index into the Risk Map.** Every record is keyed by risk id, control id,
attack id, component and telemetry field, so evidence joins back to the RM catalog and, through
the same ids, to the sibling project's ontology, as a join rather than an integration. *Which controls have been tested, against what, when, and at what strength*
becomes a query. The ids must therefore be the Risk Map's own and never invented (D4); a record
keyed to a non-existent id supports no claim.

### Negative

A target range must exist before anything can be measured, and none does; this is the top scope
risk. Runs are slower and
less deterministic than unit tests. Most early results will be negative or inconclusive, and
treating a negative as a failure to be tuned away invalidates the evidence being gathered.
Executed evidence also expires: it is pinned to a model, a range commit and a corpus commit, so a
Tier B claim about one model on one date does not extend six months. Re-running is recurring
maintenance, not rework (D11).

### Follow-up

The range decision and the pair contract are the two decisions everything else rests on;
each warrants its own ADR in the WS2 series once taken. Upstream, D3 and D4 generate issues
against the RFC corpus and the Risk Map YAML rather than local workarounds.
