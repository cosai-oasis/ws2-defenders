# Bubo Evals

The Evals workstream is responsible for validating that Bubo's parsers, MCP tools, and skills produce accurate, evidence-backed answers that can be traced to their original sources.

Evaluations should detect incorrect, incomplete, or unsupported answers, including responses that appear correct but lack sufficient evidence. When the graph does not contain enough information, tools should clearly communicate that limitation rather than invent an answer.

## Initial Priorities

### 1. Establish a Testing Baseline

- Follow the Bubo setup instructions.
- Run `python -m pytest -q` from the repository root.
- Validate the notebook workflow.
- Stop the notebook server before running tests against the same graph store to avoid database locking conflicts.
- Document baseline failures and reproducible issues.

### 2. AIMM Parser Validation

- Coordinate with Ontology and Pipeline to confirm the meaning of the AIMM release notice.
- Create fixtures covering both observed email subject lines before parser modifications.
- Validate the release notice date and agreed approval stage.
- Ensure discussions that merely mention a release are not incorrectly classified as official announcements.

### 3. Source and Evidence Verification

- Review the original AIMM paper and release email.
- Establish expected contributor credits, approval records, and announcement details.
- Compare MCP tool responses against verified source material.
- Detect identity resolution regressions, including duplicate contributor identities.
- Document test results and evidence gaps in pull requests.

### 4. Graph Store Evaluation

Support Ontology's ADR-WS2-004 decision by comparing candidate graph stores using:

- Representative queries
- Expected answers
- Validation checks
- Backend consistency tests
- Documented differences in query behavior

## Future Evaluation Coverage

### Meeting Minutes

- Support historical meeting formats.
- Test lines containing organizations, governance roles, and attendance information.
- Ensure attendance rates identify their denominators.

### Document Search

- Establish an agreed evaluation threshold for BM25 retrieval.
- Build a manually verified question-and-answer test set.
- Verify that results reference relevant document sections rather than tables of contents.
- Check cross-document retrieval accuracy.
- Ensure stable heading links when headings remain unchanged.

### Risk Map

- Verify that each upstream YAML identifier maps to exactly one OWL entry and vice versa.
- Ensure unknown identifiers fail validation.
- Verify that framework mappings contain required review evidence.
- Validate explanations for `noMatch` relationships.

### Demo and Security Validation

- Convert the Winter demo question into an end-to-end regression test.
- Verify that answers cite supporting source passages.
- Ensure insufficient evidence produces a clear refusal or uncertainty statement.
- Confirm existing local Level 1 / DP1 security checks continue to pass.

## Collaboration

Evals coordinates with:

- Ingest: Define representative fixtures and parser expectations.
- Ontology: Agree on graph rules, entity relationships, and expected meanings.
- Pipeline: Validate MCP tools, queries, and notebook behavior from the user's perspective.

Each evaluation should preserve its expected answer, supporting source material, and reproducible test results so that other contributors can independently verify the outcome.

## Maintainer

Aditya Das — Evals and Ingest