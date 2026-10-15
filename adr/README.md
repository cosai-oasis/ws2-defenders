# Architecture Decision Records: WS2 Defenders

Decisions for **WS2 Defenders** tooling, infrastructure and method. Each ADR records the
context that forced a choice, the choice itself, the alternatives rejected, and what the
workstream now lives with.

The projects these ADRs govern live beside them in this repository: bubo (Backed Up By
Ontology) under `bubo/`, decided in ADR-WS2-001, and ARCADE (Assessing Risks and Control
through Attack Detection Evaluations) under `arcade/`, decided in ADR-WS2-002.

## Conventions

Adopted from [`secure-ai-tooling` `docs/adr/`](https://github.com/cosai-oasis/secure-ai-tooling/tree/main/docs/adr),
with one change.

- **Sections:** Context → Decision → Alternatives Considered → Consequences
  (Positive / Negative / Follow-up). `TEMPLATE.md` is the source.
- **Stable sub-decision IDs.** Multi-part decisions use `### D1.`, `### D2.`, and
  `#### D3a.` for internal layering. Cross-references cite `D3b`, never `§3`. This is what
  lets a validator, a CI error string or another ADR name the exact decision it enforces;
  upstream applies this throughout (`ADR-033 D2a`, `ADR-017 D4`, `ADR-037 D1`).
- **Numbering is qualified: `ADR-WS2-NNN`.** The change from upstream. `secure-ai-tooling`
  numbers bare (`ADR-001`), which collides the moment two CoSAI repositories both keep
  ADRs. The workstream infix keeps IDs unique across the coalition, so an ADR can be cited
  from anywhere without ambiguity.
- **Files are `NNN-slug.md`**: the qualified ID lives in the H1, the filename stays short.
  Claim a number by adding its row to this index **in the same commit**.
- **Lifecycle:** land as `Draft`; a maintainer flips it to `Accepted`; a replaced ADR
  becomes `Superseded by ADR-WS2-XXX` and links forward. Amendments may live inside an ADR
  as a dated section rather than forcing a new number.

## Where a decision belongs

| Surface | Scope |
| --- | --- |
| **ADRs** (here) | WS2 tooling, infrastructure, method, and the invariants that govern them |
| **Whitepapers and RFCs** (repo root, `telemetry/`, …) | Guidance published to the coalition |

## Index

| # | Title | Status | Date |
| --- | --- | --- | --- |
| [ADR-WS2-001](001-bubo-graphrag-mcp.md) | bubo-graphrag-mcp (Backed Up By Ontology): every answerable question about CoSAI, grounded in its own publications and data, served over MCP | Draft - Pending Review | 2026-09-21 |
| [ADR-WS2-002](002-testable-riskmap-arcade.md) | ARCADE (Assessing Risks and Control through Attack Detection Evaluations): executed evidence that a CoSAI control mitigates a CoSAI risk | Draft - Pending Review | 2026-09-21 |

### Reserved

Claimed by ADR-WS2-001 D12 (003 to 005) and the ADR-WS2-002 Follow-up (006 and 007);
listed here so the numbers are not reused.

| # | Expected title |
| --- | --- |
| ADR-WS2-003 | bubo: critical user journeys and the MCP tool surface |
| ADR-WS2-004 | bubo: graph store and reasoning profile |
| ADR-WS2-005 | bubo: hosting the MCP server, taken only if the server is hosted |
| ADR-WS2-006 | arcade: the target range |
| ADR-WS2-007 | arcade: the pair contract |
