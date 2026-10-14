"""Fetch publication markdown at pinned commit shas.

Documents are fetched at the sha recorded in registry/publications.yaml, never at
HEAD, so a build is reproducible and an upstream edit surfaces as a deliberate
registry change rather than a silent content shift.

Uses the GitHub API via `gh` so private/rate-limited access works with the user's
existing credentials. Note anaconda ships an unrelated `gh` binary that shadows the
GitHub CLI on PATH, so the absolute path is resolved explicitly.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import urllib.parse
from pathlib import Path

from ..paths import RAW, publications, raw_path

GH_CANDIDATES = ("/usr/bin/gh", "/usr/local/bin/gh", "/opt/homebrew/bin/gh")


def find_gh() -> str:
    """Locate the real GitHub CLI, skipping anaconda's unrelated `gh`."""
    for candidate in GH_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    which = shutil.which("gh")
    if which:
        # Verify it is actually the GitHub CLI and not a namesake.
        probe = subprocess.run([which, "--version"], capture_output=True, text=True)
        if "gh version" in probe.stdout:
            return which
    raise RuntimeError(
        "GitHub CLI not found. Install it, or ensure /usr/bin/gh exists. "
        "(anaconda ships an unrelated `gh` that shadows it on PATH.)"
    )


def fetch_one(gh: str, repo: str, path: str, sha: str) -> bytes:
    """Fetch one file's raw bytes at a pinned sha via the contents API."""
    quoted = urllib.parse.quote(path)
    result = subprocess.run(
        [gh, "api", f"repos/{repo}/contents/{quoted}?ref={sha}",
         "-H", "Accept: application/vnd.github.raw"],
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"fetch failed for {repo}/{path}@{sha[:8]}: "
            f"{result.stderr.decode('utf-8', 'replace')[:300]}"
        )
    return result.stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="re-fetch cached documents")
    parser.add_argument("--only", help="fetch a single publication id")
    args = parser.parse_args(argv)

    gh = find_gh()
    RAW.mkdir(parents=True, exist_ok=True)

    pubs = publications()
    if args.only:
        pubs = [p for p in pubs if p["id"] == args.only]
        if not pubs:
            print(f"no such publication id: {args.only}", file=sys.stderr)
            return 1

    fetched = cached = 0
    for pub in pubs:
        dest = raw_path(pub)
        if dest.exists() and not args.force:
            cached += 1
            continue
        data = fetch_one(gh, pub["repo"], pub["md_path"], pub["commit_sha"])
        dest.write_bytes(data)
        fetched += 1
        print(f"  fetched {len(data):>7} B  {pub['id']}")

    print(f"\n{fetched} fetched, {cached} already cached -> {RAW}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
