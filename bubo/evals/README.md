# Bubo Evals

Bubo evaluations validate the accuracy, consistency,
and source traceability of Bubo's outputs.

Evaluations should detect incorrect, incomplete, or unsupported answers, including responses that appear correct but lack sufficient evidence. When the graph does not contain enough information, tools should clearly communicate that limitation rather than invent an answer.

## Existing Tests

Credits and Identity

test_credits.py — Checks contributor credits.

test_frontmatter.py — Checks document metadata.

test_identity.py — Makes sure people are identified correctly.

test_temporal.py — Checks dates and timelines.

Emails and Meetings

test_groupsio.py — Tests Groups.io messages.

test_maillist.py — Checks mailing-list data.

test_meetings_graph.py — Checks meeting records.

test_approvals.py — Tests approval records.

test_calendar.py — Checks calendar events.

Documents and Sources

test_citations.py — Checks document citations.

test_website.py — Tests website data.

test_publication_candidates.py — Checks possible publications.

Graph and Queries

test_ontology.py — Checks ontology relationships.

test_shapes.py — Checks graph validation rules.

test_queries.py — Tests graph queries.

test_backend_portability.py — Checks that different graph backends return consistent results.

Tools and Skills

test_orientation.py — Tests orientation features.

test_skills.py — Checks skill functionality.

test_writing_skills.py — Tests writing skills.

Shared Test Setup

conftest.py — Contains shared test setup and fixtures.

## Running the Tests

From the bubo/ folder, run all tests:

python -m pytest -q

To run one test file:

python -m pytest tests/test_backend_portability.py -v

To run a test by name:

python -m pytest -k "test_name" -v

## What We Check

Bubo evaluations focus on:

Accuracy: Answers should match the original sources.

Identity: People should not be mixed up or duplicated.

Dates: Dates and timelines should be correct.

Approvals: Drafts and discussions should not be treated as approved decisions.

Missing information: Tools should say when there is not enough evidence.

Security: Tests should follow the project's local MCP Security Level 1 / DP1 requirements.

## Understanding Test Results

A passing test means the specific feature worked as expected for that test.

A failing test means something needs to be checked. Review the test, expected result, and source data to find the issue.

When fixing bugs or adding features, include tests to make sure the same problem does not happen again.

The goal is to keep Bubo accurate, reliable, and easy to test.

## Maintainer

Aditya Das — Evals and Ingest