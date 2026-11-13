# registry/

The curated registries: the source of truth for the bubo graph. Each file records a
judgment that cannot be derived from the sources, such as whether two people are one
person, which spellings name one organization, or which governance call approves which
work. The build reads these files and adds no judgment of its own, so a wrong entry here
becomes a wrong fact in every answer.

For what each file holds, see [Registries](../README.md#registries) in the bubo README.
This file covers how to work in the directory: which step proposes each change, what to
review it against, and how a change gets in.

```
ingest ─▶ *.seed.yaml + reports/*.md ─▶ review ─▶ *.yaml ─▶ build
```

## Seed vs. curated

- **`*.seed.yaml` is a proposal.** Ingest regenerates it on every run. Do not edit it by
  hand. After a run, restore it from git unless the regenerated seed is the change being
  made.
- **The file without `.seed` is the reviewed registry.** Ingest only reads it. Every
  change to it is a human decision, made in a commit that says why.

Compare a seed with its curated file to see what ingest is proposing now.

## Where each change comes from

| Curated file | Seed (written by) | Review against |
| --- | --- | --- |
| `people.yaml` | `people.seed.yaml` (`ingest.seed`) | `reports/unresolved.md` |
| `organizations.yaml` | `organizations.seed.yaml` (`ingest.seed`) | `reports/unresolved.md` |
| `publications.yaml` | `publications.seed.yaml` (`ingest.publication_candidates`) | `reports/approvals.md`, `reports/website.md` |
| `publication-candidates.yaml` | (none) | `publications.seed.yaml` |
| `meeting-series.yaml` | `meeting-series.seed.yaml` (`ingest.maillist`) | `reports/meetings.md`, `reports/calendar.md` |
| `approvals.yaml` | `approvals.seed.yaml` (`ingest.approvals`) | `reports/approvals.md` |
| `mail-lists.yaml` | (none) | (none) |
| `role-vocabulary.yaml` | (none) | build errors |
| `work-aliases.yaml` | (none) | build errors |
| `citation-forms.yaml` | (none) | citation discovery |

Module names are under `bubo_graphrag.`, run with `python -m`. The comment at the top
of each file holds its schema and the cases that need a person. Read it before editing.

## Reviewing a change

1. Run the ingest step for the source (see [Build](../README.md#build)).
2. Read the matching report in [`reports/`](../reports/). A section reading `none` is
   clean.
3. Diff the seed against the curated file and copy over what you accept by hand, or
   record a dismissal in `publication-candidates.yaml` with a reason.
4. Rebuild (`python -m bubo_graphrag.build.graph`) and run `python -m pytest -q`.
5. Commit the curated file. The commit message records the decision.

`python -m bubo_graphrag.ingest.seed --promote` copies the `people` and `organizations`
seeds into place **only when the curated file does not yet exist**. It is for
bootstrapping and never overwrites a reviewed registry.

## Rules

- **When unsure, do not merge.** Attribution errors are the one class of bug this
  project must not ship, and an automatic parser will merge two people or split one into
  three. That is why identity goes through these registries and a human review gate. A
  wrong merge is a wrong fact.
- **Some gaps fail the build on purpose.** An unmapped role label
  (`role-vocabulary.yaml`) or citation title (`work-aliases.yaml`) stops the build. Add
  the mapping; do not suppress the check.
- **Keys that stop matching are reported, not dropped.** A stale key in `approvals.yaml`
  or `publication-candidates.yaml` shows up in the report. Fix it or remove it.
- **Email addresses.** `people*.yaml` hold addresses taken from the public documents,
  as the only reliable cross-document identity key. Add one only with the document it
  came from (see [Security posture](../README.md#security-posture)).
