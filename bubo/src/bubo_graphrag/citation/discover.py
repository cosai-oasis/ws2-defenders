"""Search for citations of CoSAI documents in any surface form.

The TSC citation-impact dataset is authoritative for what has already been verified.
This looks for what it has not yet recorded, and writes candidates in the dataset's own
schema so findings can be contributed upstream rather than living only here.

"Any form" is the requirement that shapes this. A citing work may reference a document
by pinned blob URL, main-branch blob URL, raw URL, PDF, repository root, an OASIS or
coalitionforsecureai.org announcement, the full title, or a short title in prose. Each
document's forms are generated from publications.yaml and registry/citation-forms.yaml.

Generic short titles ("MCP Security", "ODIS") are only counted when "CoSAI" appears
nearby, since on their own they match far more unrelated material than real citations.

Run:  python -m bubo_graphrag.citation.discover --limit 20
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import quote

from ..ingest.fetch import find_gh
from ..paths import DATA, REPORTS, load_registry, publications

VENDORED_SOURCES = DATA / "vendor" / "cosai-citation-sources.json"
CANDIDATES = REPORTS / "discovered-candidates.json"

# Repositories whose hits are self-references rather than external citations.
SELF_OWNERS = {"cosai-oasis"}


@dataclass
class SurfaceForm:
    """One string by which a publication may be cited."""

    value: str
    kind: str                  # blob-url | raw-url | pdf-url | repo-url | landing | title
    needs_context: bool = False


@dataclass
class Candidate:
    """A possible citation, in the TSC dataset's schema plus discovery provenance."""

    publisher: str
    citing_publication: str
    source_url: str
    cosai_works: list[str]
    category: str = "Unverified candidate"
    verification: str = "Search hit, not yet inspected"
    publisher_relationship: str = "Not established"
    evidence_signal: str = ""
    discovery_provider: str = "github-code-search"
    matched_form: str = ""
    matched_kind: str = ""
    notes: str = ""
    id: str = ""


def surface_forms(pub: dict, forms_registry: dict) -> list[SurfaceForm]:
    """Every form for one publication: derived URLs plus registered titles."""
    repo, md_path = pub["repo"], pub["md_path"]
    generic = {t.lower() for t in (forms_registry.get("requires_cosai_context") or [])}
    entry = (forms_registry.get("publications") or {}).get(pub["id"], {}) or {}

    out: list[SurfaceForm] = [
        SurfaceForm(f"github.com/{repo}/blob/main/{md_path}", "blob-url"),
        SurfaceForm(f"github.com/{repo}/blob/{pub['commit_sha']}/{md_path}", "blob-url"),
        SurfaceForm(f"raw.githubusercontent.com/{repo}/main/{md_path}", "raw-url"),
        SurfaceForm(f"github.com/{repo}", "repo-url", needs_context=True),
    ]
    if pdf_path := pub.get("pdf_path"):
        out.append(SurfaceForm(f"github.com/{repo}/blob/main/{pdf_path}", "pdf-url"))
    if "/" in md_path:
        directory = md_path.rsplit("/", 1)[0]
        out.append(SurfaceForm(f"github.com/{repo}/tree/main/{directory}", "repo-url",
                               needs_context=True))

    for page in entry.get("landing_pages") or []:
        out.append(SurfaceForm(page.replace("https://", ""), "landing"))
    # Copies the CoSAI website hosts, and the addresses a file had before it moved:
    # reported under the kinds they are, a PDF and a blob, not as landing pages.
    for url in entry.get("website_pdfs") or []:
        out.append(SurfaceForm(url.replace("https://", ""), "pdf-url"))
    for url in entry.get("former_urls") or []:
        out.append(SurfaceForm(url.replace("https://", ""), "blob-url"))

    titles = entry.get("titles") or [pub["title"]]
    for title in titles:
        out.append(SurfaceForm(title, "title",
                               needs_context=title.lower() in generic))
    return out


def known_urls() -> set[str]:
    """Source URLs the TSC dataset has already recorded, for deduplication."""
    if not VENDORED_SOURCES.exists():
        return set()
    rows = json.loads(VENDORED_SOURCES.read_text(encoding="utf-8"))
    return {_normalize_url(r["source_url"]) for r in rows if r.get("source_url")}


def _normalize_url(url: str) -> str:
    """Fold a URL so the same document at different shas dedupes to one key."""
    url = re.sub(r"^https?://", "", url.strip()).rstrip("/")
    url = re.sub(r"/blob/[0-9a-f]{7,40}/", "/blob/main/", url)
    return url.lower()


def search_github(gh: str, form: SurfaceForm, limit: int) -> list[dict]:
    """Run one GitHub code search. Returns raw result rows."""
    query = f'"{form.value}"'
    if form.needs_context:
        query += " CoSAI"
    result = subprocess.run(
        [gh, "search", "code", query, "--limit", str(limit),
         "--json", "repository,path,url,textMatches"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        # Code search is rate-limited far more aggressively than the REST API.
        if "rate limit" in stderr.lower() or "403" in stderr:
            raise RateLimited(stderr[:200])
        return []
    try:
        return json.loads(result.stdout) or []
    except json.JSONDecodeError:
        return []


class RateLimited(RuntimeError):
    pass


def discover(limit_per_form: int = 10, only: str | None = None,
             pause: float = 2.0) -> tuple[list[Candidate], list[str], Counter]:
    """Search every surface form. Returns (candidates, notes, hit accounting).

    The accounting matters: a bare "0 candidates" is ambiguous between a complete
    upstream dataset and a broken search. Reporting hits seen, self-references
    filtered, and already-known URLs deduped distinguishes them.
    """
    gh = find_gh()
    forms_registry = load_registry("citation-forms")
    seen = known_urls()
    candidates: list[Candidate] = []
    notes: list[str] = []
    emitted: set[tuple[str, str]] = set()
    stats: Counter = Counter()

    pubs = [p for p in publications() if only is None or p["id"] == only]
    for pub in pubs:
        for form in surface_forms(pub, forms_registry):
            stats["forms-searched"] += 1
            try:
                rows = search_github(gh, form, limit_per_form)
            except RateLimited as exc:
                notes.append(f"rate limited while searching {form.value!r}: {exc}")
                return candidates, notes, stats
            stats["hits"] += len(rows)
            for row in rows:
                repo = (row.get("repository") or {}).get("nameWithOwner", "")
                owner = repo.split("/", 1)[0] if repo else ""
                if owner in SELF_OWNERS:
                    stats["filtered-self-reference"] += 1
                    continue
                url = row.get("url", "")
                key = _normalize_url(url)
                if key in seen:
                    stats["already-in-tsc-dataset"] += 1
                    continue
                if (key, pub["id"]) in emitted:
                    stats["duplicate-within-run"] += 1
                    continue
                emitted.add((key, pub["id"]))
                stats["new-candidates"] += 1
                candidates.append(Candidate(
                    id=f"D{len(candidates) + 1:03d}",
                    publisher=owner or "unknown",
                    citing_publication=row.get("path", "") or repo,
                    source_url=url,
                    cosai_works=[pub["title"]],
                    evidence_signal=_first_snippet(row),
                    matched_form=form.value,
                    matched_kind=form.kind,
                    notes=f"matched by {form.kind}"
                          + (" with CoSAI context required" if form.needs_context else ""),
                ))
            time.sleep(pause)
    return candidates, notes, stats


def _first_snippet(row: dict) -> str:
    for match in row.get("textMatches") or []:
        if fragment := match.get("fragment"):
            return " ".join(fragment.split())[:300]
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=10,
                        help="results per surface form (default 10)")
    parser.add_argument("--only", help="restrict to one publication id")
    parser.add_argument("--pause", type=float, default=2.0,
                        help="seconds between searches; code search is rate-limited")
    parser.add_argument("--list-forms", action="store_true",
                        help="print the surface forms and exit without searching")
    args = parser.parse_args(argv)

    forms_registry = load_registry("citation-forms")
    if args.list_forms:
        total = 0
        for pub in publications():
            if args.only and pub["id"] != args.only:
                continue
            forms = surface_forms(pub, forms_registry)
            total += len(forms)
            print(f"\n{pub['id']} ({len(forms)} forms)")
            for form in forms:
                flag = "  [needs CoSAI context]" if form.needs_context else ""
                print(f"   {form.kind:11} {form.value}{flag}")
        print(f"\n{total} surface forms total")
        return 0

    candidates, notes, stats = discover(args.limit, args.only, args.pause)
    REPORTS.mkdir(parents=True, exist_ok=True)
    CANDIDATES.write_text(
        json.dumps([asdict(c) for c in candidates], indent=2, ensure_ascii=False),
        encoding="utf-8")

    print(f"{len(candidates)} candidate(s) not already in the TSC dataset "
          f"-> {CANDIDATES}")
    for key in ("forms-searched", "hits", "filtered-self-reference",
                "already-in-tsc-dataset", "duplicate-within-run", "new-candidates"):
        print(f"  {key:26} {stats[key]}")
    if not candidates and stats["hits"]:
        print("\n  Every hit was a self-reference or already recorded upstream, so the "
              "\n  TSC dataset appears complete for the searched forms.")
    elif not stats["hits"]:
        print("\n  No search hits at all. GitHub code search indexes only a subset of "
              "\n  repositories, so absence here is weak evidence.")
    for note in notes:
        print(f"  note: {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
