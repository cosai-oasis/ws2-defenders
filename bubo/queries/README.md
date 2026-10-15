# SPARQL query library

Standalone, copy-pasteable queries. The MCP tools use parameterised versions in
`src/bubo_graphrag/queries.py`; these are for querying the store directly:

```bash
python -c "
from bubo_graphrag.store import Store
from pathlib import Path
for r in Store().select(Path('queries/who-did-what.rq').read_text()): print(r)"
```

Prefixes are injected by `Store.select`, so the files omit them. Two conventions apply
to every result: an affiliation interval's dates are *evidence* dates with
`boundsKnown false` and are not start or end dates; and `approvalStatus` must be
carried through when reporting, because three documents are drafts.
