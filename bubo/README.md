# BUBO GraphRAG MCP

bubo (Backed Up By Ontology) is an OWL/RDF ontology of CoSAI, grounded in BFO and CCO,
and the knowledge graph built on it from the coalition's own publications and data. A
GraphRAG MCP server exposes the graph to answer questions about CoSAI: who has done what
work, affiliation over time, external citation impact, which groups meet and how often,
and how a publication was approved.

Contribution credit lives in prose "Contributors and Acknowledgements" sections at the
end of eleven markdown whitepapers across five repositories, in three structural
formats, with inconsistent role labels, inconsistent organization names, two email
addresses for one person, and no stable identifiers. Answering "what has this person
worked on?" means reading eleven documents by hand. bubo makes that a query.

The decisions behind it are recorded in
[ADR-WS2-001](../adr/001-bubo-graphrag-mcp.md).

## Time-aware, with no invented precision

Documents are works brought about by publication events at instants, revised by
revision events, and credited to people whose affiliations change over time. Nothing
that can change is modeled as a bare edge. The tools enforce two invariants rather than
leaving them to the caller:

- **Affiliation is evidence-anchored with open bounds.** The corpus records that someone
  was credited under an employer in documents published on particular dates. It does
  not record when they joined or left. Every affiliation span comes back with
  `bounds_known: false`, changes come back as inferred windows with
  `notBefore`/`notAfter`, and a date between two attested spans returns nothing rather
  than an interpolation. No tool reports a current employer, because the data does not
  support one.
- **A credit carried across a revision is dated to the original publication.** The MCP
  Security paper was revised to v2.0 on 2026-08-12 without refreshing its credit list.
  Dating those credits to the revision would manufacture two affiliation reversals that
  never happened.

Identity resolution runs through curated registries behind a human review gate rather
than a fully automatic parser. Given the observed name and organization variance, an
automatic parser merges two people or splits one into three, and attribution errors are
the one class of defect bubo must not ship.

## Installation

The server's own dependencies are separate from the `notebooks` extra (Jupyter and three
model-provider SDKs): the server makes no model call and holds no key, and its security
posture rests on that separation.

With conda, [`environment.yml`](environment.yml) builds a `cosai` env with Python 3.12
and the project installed editable with both extras. Run it from this directory:

```bash
conda env create -f environment.yml    # or: conda env update -f environment.yml --prune
conda activate cosai
```

Without conda, use a virtualenv on Python 3.11 or later (`.venv/` is gitignored):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,notebooks]"      # or ".[dev]" for the server and tests only
```

## Build

The core graph needs only `gh`:

```bash
python -m bubo_graphrag.ingest.fetch     # cache the corpus at pinned shas
python -m bubo_graphrag.build.graph      # build data/graph.db
python -m pytest -q
```

Each further layer builds its own named graph and is optional.

**Meetings and governance**, from the groups.io archives of CoSAI's eight mailing lists.
The groups.io API authenticates every call, even for a publicly visible archive, so this
needs a personal key from
[lists.oasis-open-projects.org/settings/apikeys](https://lists.oasis-open-projects.org/settings/apikeys):

```bash
export GROUPSIO_API_KEY=...
python -m bubo_graphrag.ingest.groupsio  # one mbox per list into data/mail/
python -m bubo_graphrag.ingest.maillist  # candidate series and reports/meetings.md
python -m bubo_graphrag.build.meetings   # meetings and governance calls
python -m bubo_graphrag.ingest.approvals # governance calls against the registry: reports/approvals.md
```

The fetcher pages the `getmessages` API, which any member's key can call.
`--method archive` uses `downloadarchives` instead, which allows one call per group per
24 hours, so the fetcher keeps a manifest and declines to spend that allowance twice.

**Website**, from the coalitionforsecureai.org feed, cached under `data/vendor/`. No key:

```bash
python -m bubo_graphrag.ingest.website            # build from the cache (fetches if none)
python -m bubo_graphrag.ingest.website --refresh  # fetch the feed again first
```

Each post records its site category, exact publication time and links to CoSAI works. It
credits no author, because the feed names only the account that posted it.

**Calendar**, from the `cosai-op` group's meeting calendar, with the same groups.io key:

```bash
python -m bubo_graphrag.ingest.calendar            # build from the cache (reads if none)
python -m bubo_graphrag.ingest.calendar --refresh  # read the calendar again first
```

Each event is a `cosaic:ScheduledMeeting`, a calendar entry, never a `cosaic:Meeting`;
one for a later day than the read is also a `cosaic:PlannedMeeting`. A past entry links
to the meeting the mail records for the same series and day. Organizer, location and
description are never kept.

**Publication candidates**, over the built graph:

```bash
python -m bubo_graphrag.ingest.publication_candidates  # registry/publications.seed.yaml
```

It proposes each work that governance calls approve with no node in the graph, and each
CoSAI-hosted file a website post links to that no registered work covers, with the
evidence and the fields a person still has to supply. It only proposes.

## Registries

`registry/` is the curated source of truth. A `*.seed.yaml` file is parser output for
review against its curated counterpart; restore a seed from git unless the regenerated
seed is the change being made.

| File | Holds |
| --- | --- |
| `publications.yaml` | each work, pinned to a commit. An entry reaches it only when someone pins it |
| `publication-candidates.yaml` | candidates dismissed as not publications, each with a reason |
| `people.yaml`, `organizations.yaml` | resolved identities and their name variants |
| `role-vocabulary.yaml` | credit labels as the corpus writes them, mapped to role classes. An unmapped label fails the build |
| `approvals.yaml` | each governance thread, what it decides and, for a publication, each work it approves with its role: `new`, `revision`, or `addition` (a work added `to` an approved one, such as the PQC Addendum to MCP Security) |
| `meeting-series.yaml` | curated meeting series, because names drift and a wrong merge combines two groups' histories |
| `mail-lists.yaml` | which lists are pulled, and the allowlist the parser applies before it retains anything |
| `citation-forms.yaml` | every surface form by which a work can be cited: blob, raw and PDF links, announcements, titles |
| `work-aliases.yaml` | titles in the TSC citation dataset mapped to publication ids. An unmapped title fails the build |

`reports/` holds what the build cannot resolve on its own: `unresolved.md` for
identities, `approvals.md` for each disagreement between governance evidence and a
publication's `approval_status`, and `meetings.md`, `calendar.md` and `website.md` for
their layers.

## Serve

```bash
python -m bubo_graphrag.server
```

The server speaks MCP over stdio. Registering it with an MCP host is a separate,
deliberate step, held to the posture under [Security posture](#security-posture).

## Tools

Retrieval only. The tools return facts and the client reasons over them; there is no
model call and no API key in the server.

| Tool | Answers |
| --- | --- |
| `find_person` | a name fragment or address → a canonical person id. Call this first |
| `what_did_person_do` | every credit, plus affiliation as attested ranges |
| `affiliation_timeline` | evidence instants and inferred change windows |
| `who_contributed_to` | credits on one publication, by role |
| `list_people`, `list_publications`, `list_organizations` | roster queries |
| `org_contributions` | an organization's contributions |
| `what_cited_this`, `citation_summary` | citation impact, split by category and verification |
| `cosai_overview` | workstreams, governing bodies, committees and SIGs with their rhythm, curated status and succession, and recent activity |
| `how_to_get_involved` | which group to join, its list, how often it meets |
| `find_meetings` | a topic → the series working on it, ranked by how direct the match is |
| `meeting_timeline` | what a group announced, with cancellations and date-evidence strength |
| `meeting_rhythm` | how often a group meets, per quarter or month, and when that changed |
| `meeting_records` | which meetings have a record, which do not, and records not attached |
| `upcoming_meetings` | meetings scheduled on the CoSAI calendar, soonest first |
| `governance_timeline` | review periods, ballots and approvals |
| `approval_record` | how a publication was approved: each governance call on it, by body and stage |
| `what_announced_this` | the website posts that link a publication, with each blog post's approval |
| `graph_schema`, `sparql` | the read-only escape hatch, with worked example queries |

Citation data is ingested from the CoSAI TSC's hand-verified
`citation-impact/sources.json` deliverable, and cited as the source.
[`queries/`](queries/) holds the same kind of questions as standalone `.rq` files.

## Skills

Three Agent Skills wrap the tools with the domain judgment needed to use them well:
`who-did-what`, `what-cited-this` and `cosai-orientation`. Two more carry the CoSAI
editorial conventions and need no graph: `technical-writing-style` for drafting, and
`technical-writing-review`, which bundles a standard-library prose checker
(`scripts/check_prose.py`).

All five live in [`scripts/skills/`](scripts/skills/), the vendor-neutral home that
`secure-ai-tooling` ADR-031 D5 and ADR-033 D1 prescribe: authored to the
[Agent Skills](https://agentskills.io) open standard, with frontmatter declaring only
`name` and `description`, and each shipping a portable eval at `evals/evals.json`. No
harness-specific wrapper is tracked; adapting a skill to a runtime is the consumer's step
(ADR-033 D3).

To check a change against CoSAI's neutrality gate, vendor the checker from
`secure-ai-tooling` `scripts/hooks/precommit/` into `data/vendor/cosai-neutrality/` and
run it over the skills:

```bash
PYTHONPATH=data/vendor/cosai-neutrality \
  python data/vendor/cosai-neutrality/validate_neutrality.py $(find scripts/skills -type f)
```

## Security posture

bubo is held to CoSAI's own *MCP Security* guidance. It is a **Deployment Pattern 1
(all-local)** server at **Level 1 (Sandbox)**: stdio transport, a single user, and no
credentials in the request path. `gh` and the optional groups.io key are used at build
time only, and the server holds neither.

**Read-only enforcement is not sufficient for a SPARQL escape hatch.** A `SELECT`
carrying `SERVICE <http://host/>` is a federated query, so the engine dials that host and
streams matched bindings to it. Against this store, a clause aimed at loopback returned
`ConnectionRefused`, and one aimed at the cloud instance-metadata address hung for two
minutes with no timeout. The query text is composed by a model that has just read
untrusted document prose, which makes it an arbitrary egress and exfiltration primitive
(MCP-T3, MCP-T4, MCP-T10). `SERVICE` and `LOAD` are refused at the boundary.

Every source is TLP:CLEAR: CoSAI's GitHub repositories and its open list archives are
public under OASIS policy. Email addresses appear in the graph because they are the only
reliable cross-document identity key, and each traces to the public document it came
from. They are returned only on explicit request, and the skills instruct against
volunteering them.

List mail contributes no addresses: `ingest/maillist.py` emits a `sha256` and nothing
above it sees an address. `data/mail/` is gitignored as a fetched artifact that anyone
with a key can reproduce, and each person pulls the archives with their own revocable
key rather than a shared credential. The public HTML archive is not scraped: groups.io
gates it behind a browser fingerprint probe and states that AI crawlers need a license,
so bubo uses the supported API.

## Layout

```
registry/        curated source of truth; see Registries
ontology/        cosai-contrib.ttl, CCO/BFO MIREOT subset, SKOS bridges, SHACL shapes
src/             ingest → resolve → build → serve
queries/         standalone .rq library
reports/         what the build could not resolve, per layer
scripts/skills/  vendor-neutral Agent Skills and portable evals
notebooks/       the demo below
tests/           pytest, including golden answers verified against the corpus
```

The graph is grounded in **CCO v2.2** (BSD-3-Clause), MIREOT'd rather than imported,
with SKOS bridges to SPDX 3.1 Core and PROV-O: no `owl:equivalentClass` and no
`owl:sameAs`. The `cosaic:` ontology is versioned by SemVer, as
[`secure-ai-tooling#534`](https://github.com/cosai-oasis/secure-ai-tooling/issues/534)
proposes, with each release recorded in [`ontology/CHANGELOG.md`](ontology/CHANGELOG.md).

## Demo

[`notebooks/prototype.ipynb`](notebooks/prototype.ipynb) drives the server from a
remote model (Anthropic, OpenAI or Gemini) and answers questions about CoSAI in natural
language.

The model runs at the provider and the tool loop runs locally. Anthropic's
`mcp_servers` parameter and OpenAI's `{"type": "mcp"}` tool both take a `server_url` that
the provider's infrastructure dials, so neither can reach a stdio server on localhost.
The notebook therefore spawns the server, hands the model the tool definitions, executes
each tool call locally, and feeds the results back.

```python
# Tools: find_meetings, meeting_rhythm, meeting_timeline
await ask_cosai_mcp('openai',
    "Is there a CoSAI group working on AI-assisted code development? How often does it "
    "meet, and what has it announced lately?")
```

- **One entry point across three providers.** `ask_cosai_mcp(provider, query)` takes
  `"anthropic"`, `"openai"` or `"gemini"` and labels which model produced each answer,
  so answers can be compared.
- **A trace of the tools used.** Every call prints `-> tool_name({...})`.
- **Ten golden questions that reach all twenty-two tools**, in the order a newcomer asks
  them: orientation, topics and meetings, meeting records, personal, paper and
  organization credit, citations, announcements and blogs, governance, and
  cancellations. A comment above each call names the tools a grounded answer reaches.
- **Where it should refuse.** One question asks where a person works now. The graph
  holds no current employer, only the employer each credit names on its publication
  date. A grounded answer gives the last attested employer and the window of the
  change; an ungrounded one names an employer with confidence.

The server returns `instructions` from `initialize()`, and the notebook passes them as
the system prompt with one client-side rule: *answer from the tools, or say the answer
is not held.* Without that rule, the models answer from training data, and because
CoSAI is public, what they recall is plausible enough to pass for an answer.

### Running it

Build the graph first, or the server starts and fails to open the store. Register the
environment as a kernel if Jupyter runs from elsewhere, then select it:

```bash
python -m ipykernel install --user --name cosai --display-name "cosai"
```

Keys are read from the environment:

| Variable | |
| --- | --- |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY` | required |
| `COSAI_ANTHROPIC_MODEL`, `COSAI_OPENAI_MODEL`, `COSAI_GEMINI_MODEL` | optional model overrides |
| `GROUPSIO_API_KEY` | build time only, for the meetings and calendar layers |
| `GROUPSIO_SITE` | optional, another groups.io instance |

```bash
cp set-keys.example.sh set-keys.sh     # set-keys.sh is gitignored
$EDITOR set-keys.sh                    # paste keys, or point at files holding them
source set-keys.sh && jupyter lab notebooks/prototype.ipynb
```

Source the keys before starting Jupyter. A kernel inherits the environment of the
process that launched it, so a key exported in another terminal does not reach it.

The server takes an exclusive lock on `data/graph.db`. Run the notebook's **teardown**
cell when done, or the lock is held until the kernel exits and the test suite cannot
open the store.

## License

Apache-2.0. See [LICENSE](LICENSE).

The whitepapers bubo operates on are the property of OASIS Open / CoSAI and their
contributors. They are fetched at pinned commit shas into a gitignored cache and are not
redistributed here.
