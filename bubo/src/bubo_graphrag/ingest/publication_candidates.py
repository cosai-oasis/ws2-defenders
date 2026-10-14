"""Propose publications the registry does not hold, from evidence in the graph.

registry/publications.yaml stays the source of what a publication is: it pins each
document to a commit, which is what credits are read from, and a person confirms it.
This module only proposes. It reads the built graph and writes
registry/publications.seed.yaml, one candidate per piece of evidence that some CoSAI
work exists outside the registry:

  * a governance call that seeks approval of a work the graph has no node for -- a
    ``cosaic:concernsTitle`` on a publication call in the maillist graph; and
  * a CoSAI-hosted file a website post links to that matches no registered work -- a
    ``cosaic:linksToUnregistered`` in the website graph.

Each candidate carries its evidence and what the evidence suggests (a workstream, an
approval state, a repository and path), and lists the fields no evidence supplies,
because those are the ones a person has to fill: a commit to pin, above all.

A candidate reviewed and found not to be a publication -- a minutes file, an
onboarding guide -- is recorded in registry/publication-candidates.yaml under
``dismissed``, with the reason, and not proposed again.

Run:  python -m bubo_graphrag.ingest.publication_candidates
"""

from __future__ import annotations

import re
import urllib.parse
from collections import Counter, defaultdict
from typing import Callable

from ..paths import REGISTRY

Select = Callable[[str], list[dict]]

TITLE_CALLS = """
SELECT ?title ?call ?label ?stage ?body ?opened ?deadline ?closed ?restates WHERE {
  ?call a cosaic:GovernanceCall ; cosaic:subjectMatter "publication" ;
        cosaic:concernsTitle ?title ; rdfs:label ?label ; cosaic:callStage ?stage .
  OPTIONAL { ?call cosaic:decidedBy ?body }
  OPTIONAL { ?call cosaic:openedOn ?opened }
  OPTIONAL { ?call cosaic:objectionDeadline ?deadline }
  OPTIONAL { ?call cosaic:closedOn ?closed }
  OPTIONAL { ?call cosaic:restatesTscApproval ?restates }
}"""

LINKED_FILES = """
SELECT ?url ?post ?title ?at WHERE {
  ?post cosaic:linksToUnregistered ?url ; rdfs:label ?title ; cosaic:publishedAt ?at .
}"""

# Fields a registry entry needs that no graph evidence supplies on its own.
REGISTRY_FIELDS = ("id", "title", "workstream", "repo", "md_path", "commit_sha",
                   "original_date", "approval_status")


def _slug(value: str, limit: int = 60) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", value.lower())).strip("-")[:limit]


def url_key(url: str) -> str:
    parts = urllib.parse.urlsplit(url.strip())
    return f"{parts.netloc.lower().removeprefix('www.')}" \
           f"{urllib.parse.unquote(parts.path).rstrip('/')}".lower()


def _workstream_of(texts: list[str]) -> str | None:
    found = Counter(m.lower() for t in texts for m in re.findall(r"\bWS\s?(\d)\b", t, re.I))
    return f"ws{found.most_common(1)[0][0]}" if found else None


def _approval_state(calls: list[dict]) -> str:
    """What the calls show, in the registry's own words where they apply."""
    closed = {c["body"] for c in calls if c.get("closed") and c.get("body")}
    restated = any(c.get("restates") for c in calls)
    if "pgb" in closed and ("tsc" in closed or restated):
        return "approved"
    if closed:
        return f"approval in progress ({', '.join(sorted(b.upper() for b in closed))} closed)"
    return "under review"


def title_candidates(select: Select) -> dict[str, dict]:
    rows = select(TITLE_CALLS)
    by_title: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        # A full IRI or the local name the store returns: "tsc" either way.
        body = row["body"].rsplit("#", 1)[-1].removeprefix("gov-") if row.get("body") else None
        by_title[row["title"]].append({
            "call": row["label"], "stage": row["stage"], "body": body,
            "opened": row.get("opened"), "deadline": row.get("deadline"),
            "closed": row.get("closed"),
            "restates": str(row.get("restates", "")).lower() == "true"})
    out = {}
    for title, calls in by_title.items():
        # One row per call and body; a notice naming both bodies arrives twice.
        seen, unique = set(), []
        for call in sorted(calls, key=lambda c: (c["opened"] or "", c["call"], c["body"] or "")):
            key = (call["call"], call["body"], call["opened"])
            if key not in seen:
                seen.add(key)
                unique.append(call)
        suggested = {"title": title, "approval_status": _approval_state(unique)}
        if ws := _workstream_of([c["call"] for c in unique]):
            suggested["workstream"] = ws
        out[title] = {
            "proposed_id": _slug(title.split(":", 1)[0]) or _slug(title),
            "basis": "approval calls name a work with no node in the graph",
            "suggested": suggested,
            "evidence": {"approval_calls": [
                {k: v for k, v in c.items() if v not in (None, False)} for c in unique]},
        }
    return out


def _github_parts(url: str) -> dict:
    parts = urllib.parse.urlsplit(url)
    segments = [urllib.parse.unquote(s) for s in parts.path.strip("/").split("/")]
    # The host must be GitHub itself: a suffix match would admit evilgithub.com.
    if parts.hostname in ("github.com", "www.github.com") and len(segments) >= 5 \
            and segments[2] in ("blob", "raw"):
        return {"repo": f"{segments[0]}/{segments[1]}", "ref": segments[3],
                "path": "/".join(segments[4:])}
    return {}


def link_candidates(select: Select) -> dict[str, dict]:
    by_url: dict[str, dict] = {}
    for row in select(LINKED_FILES):
        key = url_key(row["url"])
        entry = by_url.setdefault(key, {"url": row["url"], "posts": []})
        entry["posts"].append({"post": row["title"], "published": row["at"][:10]})
    out = {}
    for key, entry in by_url.items():
        suggested = {}
        github = _github_parts(entry["url"])
        if github:
            suggested["repo"] = github["repo"]
            if github["ref"] != "main":
                # A branch name may contain slashes, so past blob/ the URL cannot say
                # where the ref ends and the path begins; the path is not guessed.
                suggested["note"] = ("linked on a ref other than main; its path depends "
                                     "on where the ref name ends, which the URL cannot show")
            elif github["path"].endswith(".md"):
                suggested["md_path"] = github["path"]
            elif github["path"].endswith(".pdf"):
                suggested["pdf_path"] = github["path"]
            if ws := _workstream_of([github["repo"].replace("-", " ")]):
                suggested["workstream"] = ws
        name = entry["url"].rstrip("/").rsplit("/", 1)[-1]
        out[key] = {
            "proposed_id": _slug(re.sub(r"\.(md|pdf)$", "", urllib.parse.unquote(name))),
            "basis": "website posts link a CoSAI-hosted file no registered work covers",
            "suggested": suggested,
            "evidence": {"url": entry["url"],
                         "posts": sorted(entry["posts"], key=lambda p: p["published"])},
        }
    return out


def candidates(select: Select, dismissed: dict[str, str]) -> tuple[list[dict], list[str]]:
    """Every candidate not dismissed, strongest evidence first, and the dismissals
    that matched nothing (so a stale one is visible)."""
    titles, links = title_candidates(select), link_candidates(select)
    used, out = set(), []
    for key, candidate in [*titles.items(), *links.items()]:
        match = key if key in dismissed else url_key(key) if url_key(key) in dismissed else None
        if match is not None:
            used.add(match)
            continue
        suggested = candidate["suggested"]
        candidate["missing"] = [f for f in REGISTRY_FIELDS
                                if f not in suggested and f != "id"]
        out.append(candidate)

    # Two files can share a name (cosai-tsc and oasis-open-project each have an
    # ONBOARDING.md); an ID that collides takes its repository's name.
    counts = Counter(c["proposed_id"] for c in out)
    for c in out:
        repo = c["suggested"].get("repo")
        if counts[c["proposed_id"]] > 1 and repo:
            c["proposed_id"] = _slug(f"{repo.split('/', 1)[1]}-{c['proposed_id']}")

    def strength(c: dict) -> tuple:
        approved = c["suggested"].get("approval_status") == "approved"
        calls = len(c["evidence"].get("approval_calls", []))
        posts = len(c["evidence"].get("posts", []))
        return (not approved, -calls, -posts, c["proposed_id"])

    return sorted(out, key=strength), sorted(set(dismissed) - used)


def load_dismissed() -> dict[str, str]:
    from ..paths import load_registry
    if not (REGISTRY / "publication-candidates.yaml").exists():
        return {}
    return load_registry("publication-candidates").get("dismissed") or {}


def main(argv: list[str] | None = None) -> int:
    import yaml

    from ..store import RdflibStore

    # The in-memory backend reads the built graph files, so a running server's lock on
    # the persistent store is never contended.
    store = RdflibStore()
    found, stale = candidates(store.select, load_dismissed())
    seed = REGISTRY / "publications.seed.yaml"
    seed.write_text(
        "# GENERATED by `python -m bubo_graphrag.ingest.publication_candidates` from the\n"
        "# built graph. Proposals only: review each, then add it to publications.yaml,\n"
        "# pinned to a commit, or dismiss it in publication-candidates.yaml with a reason.\n\n"
        + yaml.safe_dump({"candidates": found}, sort_keys=False, allow_unicode=True,
                         width=100), encoding="utf-8")
    print(f"{len(found)} publication candidates -> {seed}")
    for candidate in found:
        print(f"  {candidate['proposed_id']}: {candidate['basis']}")
    for key in stale:
        print(f"  dismissal matches no candidate now: {key!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
