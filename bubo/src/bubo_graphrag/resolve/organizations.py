"""Canonicalise organizations against the reviewed registry.

registry/organizations.yaml is the authority for three judgments a string comparison
cannot make:

  * which spellings name one organization (`Dell` / `Dell Technologies`)
  * which merges rest on knowledge outside the corpus (`Trend AI` is a rebranding and
    subcompany of the Trend Micro parent, confirmed by the maintainer)
  * which domains belong to an individual rather than an employer (`chuvakin.org`)

Once a variant pair is recorded here it stops being reported as drift, because the
registry has answered the question.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..paths import load_registry
from .identity import PERSONAL_DOMAINS, _org_key, email_domain


@dataclass
class Organization:
    id: str
    canonical_name: str
    variants: list[str] = field(default_factory=list)
    email_domains: list[str] = field(default_factory=list)
    merge_provenance: list[dict] = field(default_factory=list)


class OrgRegistry:
    """Lookup from a credit-line spelling or an address domain to a canonical org."""

    def __init__(self, data: dict | None = None) -> None:
        data = data if data is not None else load_registry("organizations")
        self.personal_domains = frozenset(
            d.lower() for d in (data.get("personal_domains") or [])
        ) | PERSONAL_DOMAINS
        self.organizations: dict[str, Organization] = {}
        self._by_key: dict[str, str] = {}
        self._by_domain: dict[str, str] = {}

        for row in data.get("organizations") or []:
            org = Organization(
                id=row["id"],
                canonical_name=row["canonical_name"],
                variants=list(row.get("variants") or []),
                email_domains=[d.lower() for d in (row.get("email_domains") or [])],
                merge_provenance=list(row.get("merge_provenance") or []),
            )
            self.organizations[org.id] = org
            for name in {org.canonical_name, *org.variants}:
                self._by_key[_org_key(name)] = org.id
            for domain in org.email_domains:
                self._by_domain[domain] = org.id

    def resolve_name(self, stated: str | None) -> Organization | None:
        if not stated:
            return None
        org_id = self._by_key.get(_org_key(stated))
        return self.organizations.get(org_id) if org_id else None

    def resolve_address(self, address: str) -> Organization | None:
        """Organization implied by an address domain, or None if it implies nothing."""
        domain = email_domain(address)
        if not domain or domain in self.personal_domains:
            return None
        if org_id := self._by_domain.get(domain):
            return self.organizations[org_id]
        # Try the registrable label, so an unlisted subdomain still resolves.
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            if org_id := self._by_domain.get(".".join(parts[i:])):
                return self.organizations[org_id]
        return None

    def is_personal_domain(self, address: str) -> bool:
        domain = email_domain(address)
        return bool(domain) and domain in self.personal_domains

    def same_organization(self, a: str | None, b: str | None) -> bool:
        """True when two stated spellings resolve to one registered organization."""
        ra, rb = self.resolve_name(a), self.resolve_name(b)
        return bool(ra and rb and ra.id == rb.id)

    def unknown_names(self, stated: set[str]) -> list[str]:
        """Stated spellings the registry does not cover, sorted for reporting."""
        return sorted(s for s in stated if s and not self.resolve_name(s))
