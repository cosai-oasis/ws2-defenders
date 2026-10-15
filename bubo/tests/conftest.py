"""Shared fixtures.

Query tests run against the real built graph rather than a synthetic one. The corpus is
the thing being modeled and its irregularities are the point -- a fixture graph would
test the queries against data that lacks the typo, the stale revision credits, and the
multi-person line that make this hard.
"""

from __future__ import annotations

import pytest

from bubo_graphrag.paths import GRAPH_DB, load_registry, raw_path, publications


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "covers(query): names the SPARQL query a test exercises")


@pytest.fixture(scope="session")
def store():
    """The built store. Skips rather than fails if the build has not been run."""
    if not GRAPH_DB.exists():
        pytest.skip(
            "data/graph.db not built. Run: python -m bubo_graphrag.ingest.fetch && "
            "python -m bubo_graphrag.ingest.seed --promote && "
            "python -m bubo_graphrag.build.graph && "
            "python -m bubo_graphrag.ingest.citations")
    from bubo_graphrag.store import get_store
    return get_store()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """No test reaches a real server. A fake that is not wired in fails here, loudly.

    The groups.io CLI tests once reached the live API because the opener was bound as
    a default argument, and passed only because the real server also rejects key "k".
    """
    import urllib.request

    def refuse(*args, **kwargs):
        raise AssertionError("a test tried to open a real URL")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)


@pytest.fixture(scope="session")
def role_registry():
    return load_registry("role-vocabulary")


@pytest.fixture(scope="session")
def corpus():
    """Raw markdown of every publication, keyed by id. Skips if not fetched."""
    out = {}
    for pub in publications():
        path = raw_path(pub)
        if not path.exists():
            pytest.skip("documents not fetched. Run: python -m bubo_graphrag.ingest.fetch")
        out[pub["id"]] = path.read_text(encoding="utf-8")
    return out


@pytest.fixture(scope="session")
def resolved():
    """The full resolve pass: (resolver, credits, findings, doc_rows)."""
    from bubo_graphrag.ingest.seed import collect
    return collect()
