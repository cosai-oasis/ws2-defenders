"""Generate seed registries and the review report.

This is the human review gate. Extraction produces a *proposal*; a person confirms it
once; thereafter builds are deterministic from the registries. Re-running against
changed upstream documents produces a diff to review rather than a silent overwrite.

Writes:
  registry/people.seed.yaml         proposed canonical people
  registry/organizations.seed.yaml  proposed organization canonicalisation
  reports/unresolved.md             every decision worth confirming

The `.seed.yaml` suffix is deliberate: `python -m bubo_graphrag.ingest.seed --promote`
copies a seed over the real registry only when the real one does not yet exist, so a
reviewed registry is never clobbered by a later extraction run.
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
from collections import Counter

import yaml

from ..paths import REGISTRY, REPORTS, load_registry, publications, raw_path
from ..resolve.identity import (
    Resolver,
    normalize_name,
    organization_variants,
)
from . import credits as C
from . import frontmatter as FM


def assertion_date(pub: dict) -> dt.date | None:
    """The date a document's credits are evidence *about*.

    For a revision that did not refresh its credit list, that is the ORIGINAL
    publication date, not the revision date. model-context-protocol-security.md was
    revised to v2.0 on 2026-08-12 carrying January's credits, which is why Bill Stout
    and Josiah Hagen appear there under employers they had already left. Dating those
    credits to the revision would read as an affiliation reversal.
    """
    original = FM.parse_date(pub.get("original_date"))
    if pub.get("credits_refreshed_at_revision") and pub.get("revised_date"):
        return FM.parse_date(pub["revised_date"])
    return original


def collect() -> tuple[Resolver, list[C.Credit], list[C.Finding], list[dict]]:
    """Parse every publication and resolve identities."""
    rv = load_registry("role-vocabulary")
    role_labels = set(rv["roles"])
    stop_headings = rv["stop_headings"]

    # Reuse a reviewed people.yaml if one exists, so its aliases steer the merge.
    aliases: dict[str, str] = {}
    try:
        existing = load_registry("people")
        for entry in existing.get("people", []):
            for alias in entry.get("name_aliases", []) or []:
                aliases[normalize_name(alias)] = entry["id"]
    except FileNotFoundError:
        pass

    # The reviewed organization registry, when it exists, supplies the judgments a
    # string comparison cannot make (confirmed variants, personal domains).
    orgs = None
    try:
        from ..resolve.organizations import OrgRegistry
        orgs = OrgRegistry()
    except FileNotFoundError:
        pass

    resolver = Resolver(aliases, orgs)
    all_credits: list[C.Credit] = []
    findings: list[C.Finding] = []
    doc_rows: list[dict] = []

    for pub in publications():
        text = raw_path(pub).read_text(encoding="utf-8")
        declared = FM.parse(text)
        parsed = C.parse(text, pub["id"], role_labels, stop_headings)
        pub_credits = list(parsed.credits)
        findings.extend(parsed.findings)

        # ODIS names its authors in front matter instead of a credit section.
        if pub.get("credits_in_frontmatter") and declared.author:
            fm_credits, fm_findings = C.parse_frontmatter_authors(
                declared.author, pub["id"])
            pub_credits.extend(fm_credits)
            findings.extend(fm_findings)

        # Record, do not reconcile: the repo sets the workstream, and a document that
        # disagrees is a finding rather than an override.
        declared_ws = declared.declared_workstream_number
        registry_ws = pub["workstream"]
        if declared_ws and f"ws{declared_ws}" != registry_ws:
            findings.append(C.Finding(
                pub["id"], "workstream-disagreement",
                f"document declares Workstream {declared_ws}; repo says {registry_ws}. "
                "Registry wins.", str(declared.author)))

        if pub.get("has_credit_section") is False and pub_credits:
            findings.append(C.Finding(
                pub["id"], "unexpected-credits",
                f"registry says no credit section but {len(pub_credits)} were parsed"))
        if pub.get("has_credit_section") is not False and not pub_credits:
            findings.append(C.Finding(
                pub["id"], "no-credits-found",
                "no credits parsed; confirm the document has none"))

        date = assertion_date(pub)
        for credit in pub_credits:
            resolver.add(credit, date)
            if credit.source_label not in role_labels:
                findings.append(C.Finding(
                    pub["id"], "unmapped-role-label",
                    f"{credit.source_label!r} is not in role-vocabulary.yaml",
                    credit.raw_line))
        all_credits.extend(pub_credits)

        doc_rows.append({
            "id": pub["id"],
            "format": parsed.format,
            "metadata_style": declared.style,
            "credits": len(pub_credits),
            "declared_title": declared.title,
            "declared_date": declared.date.isoformat() if declared.date else None,
            "assertion_date": date.isoformat() if date else None,
        })

    findings.extend(resolver.review_findings())
    return resolver, all_credits, findings, doc_rows


def write_people_seed(resolver: Resolver) -> int:
    people = []
    for person in sorted(resolver.people.values(), key=lambda p: p.display_name.lower()):
        stated = Counter(a.organization for a in person.org_evidence
                         if a.organization and a.source == "credit-line")
        independent = any(a.is_independent for a in person.org_evidence)

        # Addresses carry their own provenance: which document asserted them, when,
        # and what employer the domain implies. This is the evidence a reviewer needs
        # to confirm or reject a merge.
        addresses = []
        seen: set[str] = set()
        for e in sorted(person.emails, key=lambda e: (e.address, e.publication_id)):
            key = (e.address, e.publication_id)
            if key in seen:
                continue
            seen.add(key)
            row = {"address": e.address, "asserted_in": e.publication_id}
            if e.assertion_date:
                row["asserted_at"] = str(e.assertion_date)
            if e.implies_organization:
                row["implies_organization"] = e.implies_organization
            addresses.append(row)

        entry = {
            "id": person.id,
            "display_name": person.display_name,
            "names": [{"text": n, "kind": k} for n, k in sorted(person.names.items())],
            "email_addresses": addresses,
            "github_logins": sorted(person.github_logins),
            "credit_count": person.credit_count,
            "organizations_stated": [
                {"name": o, "credits": n} for o, n in stated.most_common()
            ],
        }
        if independent:
            entry["credited_without_employer"] = True
        people.append(entry)

    path = REGISTRY / "people.seed.yaml"
    header = (
        "# SEED -- generated by `python -m bubo_graphrag.ingest.seed`. Review, then\n"
        "# promote to people.yaml.\n"
        "#\n"
        "# Addresses are retained in full: they are published deliberately in the source\n"
        "# documents so readers can contact the person responsible for a claim, and the\n"
        "# domain is the strongest organization signal available. Each carries the\n"
        "# document and date that asserted it, so a work address that stops appearing is\n"
        "# visible as evidence rather than being silently overwritten.\n"
        "#\n"
        "# `names` records each observed form with its CCO designator kind: an\n"
        "# abbreviated name (`J.R. Rao`) and a proper name (`Josyula R. Rao`) designate\n"
        "# the same person.\n"
        "#\n"
        "# `organizations_stated` is evidence, not a current employer -- ordered by\n"
        "# credit count, and a person may legitimately appear under several over time.\n"
    )
    with path.open("w", encoding="utf-8") as fh:
        fh.write(header)
        yaml.safe_dump({"people": people}, fh, sort_keys=False, allow_unicode=True,
                       width=100)
    return len(people)


def write_organizations_seed(resolver: Resolver) -> int:
    groups = organization_variants(resolver.people)
    orgs = []
    for _, buckets in groups.items():
        stated = buckets["stated"]
        domains = buckets["domains"]
        names = list(stated)
        # Longest spelling is usually the most complete ("Dell Technologies" over
        # "Dell"); fall back to the domain label when no credit line named the org.
        canonical = max(names, key=len) if names else max(domains, key=domains.get).split(".")[0]
        entry = {"id": _slug(canonical), "canonical_name": canonical}
        if len(names) > 1:
            entry["variants"] = sorted(names)
        if domains:
            entry["email_domains"] = sorted(domains)
        orgs.append(entry)
    orgs.sort(key=lambda o: o["canonical_name"].lower())

    path = REGISTRY / "organizations.seed.yaml"
    header = (
        "# SEED -- generated. Review, then promote to organizations.yaml.\n"
        "#\n"
        "# Grouping uses stated names AND email domains as joining evidence, so\n"
        "# `Trend Micro`/`TrendMicro`/`trendmicro.com` collapse automatically.\n"
        "# What it cannot decide for you: whether `Dell` and `Dell Technologies` are one\n"
        "# organization (they are), or whether `Trend Micro` and `Trend AI` are (unclear).\n"
        "# Merge those by hand. `email_domains` is the evidence to judge by.\n"
    )
    with path.open("w", encoding="utf-8") as fh:
        fh.write(header)
        yaml.safe_dump({"organizations": orgs}, fh, sort_keys=False,
                       allow_unicode=True, width=100)
    return len(orgs)


def _slug(text: str) -> str:
    from ..resolve.identity import slugify
    return slugify(text)


def write_report(
    resolver: Resolver,
    all_credits: list[C.Credit],
    findings: list[C.Finding],
    doc_rows: list[dict],
) -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    by_kind: dict[str, list[C.Finding]] = {}
    for f in findings:
        by_kind.setdefault(f.kind, []).append(f)

    roles = Counter(c.source_label for c in all_credits)
    lines: list[str] = [
        "# Unresolved — review before trusting the graph",
        "",
        f"Generated {dt.datetime.now().astimezone().isoformat(timespec='seconds')} by "
        "`python -m bubo_graphrag.ingest.seed`.",
        "",
        "## Corpus",
        "",
        "| publication | credit format | metadata | credits | assertion date |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for row in doc_rows:
        lines.append(
            f"| `{row['id']}` | {row['format']} | {row['metadata_style']} | "
            f"{row['credits']} | {row['assertion_date'] or '—'} |")

    lines += [
        "",
        f"**{len(all_credits)} credits** across {len(doc_rows)} documents resolving to "
        f"**{len(resolver.people)} people**.",
        "",
        "Roles: " + ", ".join(f"{r} {n}" for r, n in roles.most_common()),
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("None.")
    for kind, items in sorted(by_kind.items(), key=lambda kv: -len(kv[1])):
        lines += [f"### `{kind}` — {len(items)}", ""]
        for f in items:
            where = f" (`{f.publication_id}`)" if f.publication_id else ""
            lines.append(f"- {f.detail}{where}")
            if f.raw_line:
                lines.append(f"  - source: `{f.raw_line.strip()[:160]}`")
        lines.append("")

    (REPORTS / "unresolved.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--promote", action="store_true",
                        help="copy seeds to the real registries if those do not exist")
    args = parser.parse_args(argv)

    resolver, all_credits, findings, doc_rows = collect()
    n_people = write_people_seed(resolver)
    n_orgs = write_organizations_seed(resolver)
    write_report(resolver, all_credits, findings, doc_rows)

    print(f"{len(all_credits)} credits -> {n_people} people, {n_orgs} organizations")
    print(f"{len(findings)} findings -> {REPORTS / 'unresolved.md'}")

    if args.promote:
        for name in ("people", "organizations"):
            seed, real = REGISTRY / f"{name}.seed.yaml", REGISTRY / f"{name}.yaml"
            if real.exists():
                print(f"  {real.name} already exists; not overwriting")
            else:
                shutil.copy(seed, real)
                print(f"  promoted {seed.name} -> {real.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
