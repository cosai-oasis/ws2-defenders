# build-telemetry: the data and tools behind the telemetry documents

> **Version 0.6 — Proposal**
> Provisional tooling for CoSAI WS2's *Telemetry for AI Security* RFC and its Attack Detection and Cross-Mapping addenda, versioned with them.
>
> This is a proposal for discussion and feedback — not a final standard.

The Attack Detection Addendum (AD) and the field catalogue in RFC §6 are built from `data/`. Edit the data, not the generated regions of the documents; `tools/build.py` regenerates them and `tools/validate.py` checks the result. The documents live one level up, in `telemetry/`. Run the commands below from this directory; the tools find the data and the documents from their own location, so they also work from anywhere else.

## Files

| File | Holds |
| :--- | :--- |
| `data/fields.yaml` | Every telemetry field: tier, the basis of the tier, role, record and origin, the one-line definition RFC §6 shows, the emitting component, what to capture, and the tier rationale. |
| `data/attacks/<ID>.yaml` | One file per corpus entry: what happened, its primary source and reference number, ATLAS techniques, Risk Map risks, and its edges to fields (`fields:`), each an instance or analogical. A field's grounding attacks are derived from these edges; they are not stored on the field. |
| `data/patterns.yaml` | The correlation patterns of AD §2: stage, conditions, the fields they read and join on, and the attacks they catch. The record is documented in `tools/phase5_propose.py`. |
| `data/sections.yaml` | Layout: the RFC §6 steps and their fields in order, the AD §3 inventory tables, the pattern stage titles. |
| `data/sources.yaml` | The external versions IDs resolve against: the MITRE ATLAS release and the CoSAI Risk Map commits, and every publication the Cross-Mapping Addendum maps to. Pinned, not copied; the validator fetches them into `~/.cache/cosai-telemetry/`. |
| `data/candidates/*.yaml` | The curation registry: proposed changes and the decisions on them. |

IDs are stable and never reused: field and pattern IDs are slugs (`tool_definition_digest`, `tool_definition_changed`), attack IDs are `TA-n`, `IR-n` and `AOC-n`, and reference numbers are appended, never inserted.

## Tiers

`tools/rules.py` encodes RFC §4.7 against the recorded basis. The build refuses data that breaks it, and the validator reports every breach.

- **MUST**: at least two independent instance edges (an attack recorded `same_incident_as` another adds nothing), or `basis: {required_to_read: [...]}` naming MUST fields it is needed to read.
- **SHOULD**: a `modality:`, or `provider_gated: true`.
- **MAY**: `basis: {may: [...]}` with one or more of `qa` (dominant value Q or A), `thin` (fewer than two instances, no dependent MUST field, no modality), `research`, `redundant`.

Tiers are stored, never computed. A field that comes to meet a test is reported, not promoted.

## Changing the data

Tools propose, people decide. A change of judgement (an edge and its grounding class, a tier basis, a pattern) enters as a candidate in `data/candidates/`, is decided with `tools/curate.py`, and is applied with `tools/apply.py`. Editorial corrections the owner asks for may be made in the data directly, and are said so in the commit.

```
python3 tools/curate.py list --status proposed
python3 tools/curate.py accept ID... --by NAME
python3 tools/apply.py --dry-run          # report; write nothing
python3 tools/apply.py
python3 tools/build.py
python3 tools/validate.py
```

## Intake of a new attack

1. `python3 tools/intake.py new TA-32` writes `data/candidates/<date>-intake-TA-32.yaml` with a template record and reserves the next reference number.
2. Fill in every `TODO`: the primary source and what it documents, the instance kind (`executed`, `resisted`, `failure`), `same_incident_as` if it is another account of a corpus entry, ATLAS techniques, Risk Map risks, and the `chain`: the attack's steps in order, each with the fields that would record it and why the instance contains them (or `grounding: analogical` where it only motivates them).
3. `python3 tools/intake.py propose TA-32` adds an edge candidate per chain field, and a catch candidate for each pattern the edges support.
4. `python3 tools/intake.py report TA-32` shows what the batch would change: tier tests that change (never acted on automatically), patterns that would fire, chain steps no pattern reads, and rules the attack would break. A step no pattern reads calls for a new pattern candidate, or a recorded reason.
5. Decide the candidates, apply, build, validate, and review the generated diff.
