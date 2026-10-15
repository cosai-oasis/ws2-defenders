"""Project paths and registry loading."""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
ONTOLOGY = ROOT / "ontology"
DATA = ROOT / "data"
RAW = DATA / "raw"
# Downloaded list archives. Gitignored: an archive holds every member address in
# plaintext, which is exactly what ingest/maillist.py refuses to carry upward.
MAIL = DATA / "mail"
REPORTS = ROOT / "reports"
QUERIES = ROOT / "queries"

GRAPH_DB = DATA / "graph.db"
CATALOG_TTL = ONTOLOGY / "catalog.ttl"


def load_registry(name: str) -> dict[str, Any]:
    """Load registry/<name>.yaml. Missing files raise, since every registry is required."""
    path = REGISTRY / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"registry file missing: {path}. Run `python -m bubo_graphrag.ingest.seed` "
            "to generate the seed registries, then review them."
        )
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


@functools.cache
def publications() -> list[dict[str, Any]]:
    return load_registry("publications")["publications"]


@functools.cache
def mail_lists() -> list[dict[str, Any]]:
    """The CoSAI mailing lists. Both the fetch set and the parser's allowlist."""
    return load_registry("mail-lists")["lists"]


@functools.cache
def _mail_groups() -> dict[str, str]:
    """Canonical list name -> the groups.io group name, which is the one in a URL.

    They differ, and the difference is a live 404. The parser's canonical name is the
    suffix-less spelling (`cosai-defenders`) because that is what a forwarded message's
    subject tag carries, but only the `-ws` form exists as a group, so a subscribe link
    built from the canonical name is broken for all four workstreams. Verified against
    the live site 2026-09-22.
    """
    table = {}
    for entry in mail_lists():
        table[entry["canonical"]] = entry["group"]
        table[entry["group"]] = entry["group"]
    return table


def mail_group(name: str) -> str:
    """The groups.io group for a list name. Unknown names pass through unchanged."""
    return _mail_groups().get(name, name)


@functools.cache
def mail_api_parent() -> str | None:
    """The groups.io parent group the lists are subgroups of, if any."""
    return load_registry("mail-lists").get("api_parent")


@functools.cache
def mail_site() -> str:
    """Base URL of the groups.io instance the lists are hosted on."""
    return load_registry("mail-lists")["site"].rstrip("/")


@functools.cache
def workstreams() -> dict[str, Any]:
    return load_registry("publications")["workstreams"]


def governing_bodies() -> dict[str, Any]:
    return load_registry("publications")["governing_bodies"]


def committees() -> dict[str, Any]:
    return load_registry("publications")["committees"]


def publication(pub_id: str) -> dict[str, Any]:
    for pub in publications():
        if pub["id"] == pub_id:
            return pub
    raise KeyError(f"unknown publication id: {pub_id}")


def raw_path(pub: dict[str, Any]) -> Path:
    """Local cache path for a publication's markdown, keyed by id so it is stable."""
    return RAW / f"{pub['id']}.md"
