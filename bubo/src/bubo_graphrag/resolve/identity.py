"""Resolve credit lines to canonical people, organizations, and designators.

Email addresses and person names are modeled as first-class Information Content
Entities that *designate* a person, following CCO:

    cco:ont00002070  Email Address ⊑ cco:ont00000003 Designative Name
                                   ⊑ cco:ont00000686 Designative ICE
    cco:ont00001014  Proper Name        (e.g. "Josyula R. Rao")
    cco:ont00000605  Abbreviated Name   (e.g. "J.R. Rao")
    cco:ont00001916  designates         (designator -> bearer)

Addresses are stored in full. They are published deliberately in Apache-2.0 licensed
standards documents so that readers can contact the person responsible for a claim,
which is the norm in standards work. Hashing them would not have protected anything --
the plausible-address space is small enough to brute-force -- while discarding the
strongest organization signal in the corpus: the domain. See ADR-WS2-001 D11.

Domain-derived organization evidence is what lets `Trend Micro`/`TrendMicro` and
`Dell`/`Dell Technologies` collapse without hand-curation.
"""

from __future__ import annotations

import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from ..ingest.credits import Credit, Finding

# Organization strings that name the absence of an employer rather than an employer.
# `indepedent` is a typo present in zero-trust-for-ai-systems and is deliberately
# listed: normalizing it is what makes the Zero Trust editor list resolve to two
# independent people rather than two different organizations.
INDEPENDENT_FORMS = frozenset({
    "independent", "indepedent", "independant", "self", "unaffiliated", "none", "n/a",
})

# Domains that say nothing about an employer.
PERSONAL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com",
    "icloud.com", "me.com", "proton.me", "protonmail.com", "fastmail.com",
    "aol.com", "live.com", "msn.com", "gmx.com", "zoho.com",
})

_WS = re.compile(r"\s+")
_PUNCT_EDGE = re.compile(r"^[^\w@]+|[^\w.)]+$")
_INITIALS = re.compile(r"^(?:[A-Z]\.){2,}$")


def clean_email(email: str) -> str:
    """Normalize an address for storage and comparison.

    Unescapes markdown escaping: `Josiah\\_Hagen@trendmicro.com` and
    `josiah_hagen@trendmicro.com` are the same address.
    """
    cleaned = email.replace("\\_", "_").replace("\\.", ".").replace("\\-", "-")
    return cleaned.strip().strip("<>").lower()


def email_domain(email: str) -> str | None:
    _, _, domain = clean_email(email).partition("@")
    return domain or None


def organization_from_email(email: str) -> str | None:
    """Infer an employer from an address domain, or None if it says nothing.

    Handles subdomains (`us.ibm.com` -> `ibm`) by taking the registrable-ish label
    before the public suffix. This is evidence to be confirmed, not a fact: it seeds
    organizations.yaml and is recorded in the graph as domain-derived.
    """
    domain = email_domain(email)
    if not domain or domain in PERSONAL_DOMAINS:
        return None
    parts = domain.split(".")
    # Strip a two-part public suffix (co.uk, com.au) then take the last label.
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "ac", "gov"}:
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else None


def normalize_name(name: str) -> str:
    """Fold a display name to a matching key.

    Periods and apostrophes are dropped, so `J.R. Rao` and `JR Rao` both key to
    `jr rao`, and `O'Brien` keys to `obrien`. Hyphens become a space instead, so
    `Yu-Cheng Liang` and `Yu Cheng Liang` unify -- the corpus contains hyphenated
    names and a citing document may well write them either way.

    `Josyula R. Rao` deliberately does NOT key with `J.R. Rao`: joining a full given
    name to its initial is an alias decision for registry/people.yaml, not something
    string folding should assume.
    """
    folded = unicodedata.normalize("NFKD", name)
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    folded = re.sub(r"[.']", "", folded)
    folded = re.sub(r"[-‐-―]", " ", folded)
    folded = _WS.sub(" ", folded).strip()
    folded = _PUNCT_EDGE.sub("", folded)
    return folded.casefold()


def name_kind(name: str) -> str:
    """Classify a name string as a CCO designator kind.

    An initialised form such as `J.R. Rao` is an Abbreviated Name designating the same
    person as the Proper Name `Josyula R. Rao`; modeling both as designators is what
    lets them merge without an ad-hoc alias list.
    """
    tokens = name.split()
    if any(_INITIALS.match(t) for t in tokens):
        return "abbreviated"
    if any(len(t.rstrip(".")) == 1 and t.endswith(".") for t in tokens):
        return "abbreviated"
    return "proper"


def slugify(text: str) -> str:
    folded = unicodedata.normalize("NFKD", text)
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    slug = re.sub(r"[^a-z0-9]+", "-", folded.lower()).strip("-")
    return slug or "unknown"


def normalize_org(org: str | None) -> tuple[str | None, bool]:
    """Return (organization string, is_independent).

    Only whitespace and casing are settled here; deciding that two strings name one
    company is a judgment call recorded in registry/organizations.yaml.
    """
    if org is None:
        return None, False
    cleaned = _WS.sub(" ", org).strip().strip(",").strip()
    if not cleaned:
        return None, False
    if cleaned.casefold() in INDEPENDENT_FORMS:
        return None, True
    return cleaned, False


@dataclass
class EmailAssertion:
    """One address, as asserted by one document at one date."""

    address: str
    publication_id: str
    assertion_date: object
    implies_organization: str | None = None


@dataclass
class OrgAssertion:
    """One organization claim about a person, from one document at one date."""

    publication_id: str
    organization: str | None          # canonical, per registry/organizations.yaml
    is_independent: bool
    assertion_date: object
    source: str = "credit-line"       # or "email-domain"
    stated_as: str | None = None      # verbatim spelling, kept for audit


@dataclass
class Person:
    """A canonical person, accumulated across documents."""

    id: str
    display_name: str
    names: dict[str, str] = field(default_factory=dict)   # name -> proper|abbreviated
    emails: list[EmailAssertion] = field(default_factory=list)
    github_logins: set[str] = field(default_factory=set)
    org_evidence: list[OrgAssertion] = field(default_factory=list)
    credit_count: int = 0

    @property
    def addresses(self) -> list[str]:
        seen: dict[str, None] = {}
        for e in self.emails:
            seen.setdefault(e.address, None)
        return list(seen)


class Resolver:
    """Union-find over credits, keyed on address, then registry alias, then name."""

    def __init__(
        self,
        aliases: dict[str, str] | None = None,
        orgs: object | None = None,
    ) -> None:
        # `orgs` is a resolve.organizations.OrgRegistry when one is available. It is
        # optional so the resolver still runs on a fresh checkout, before any reviewed
        # organizations.yaml exists, during the first seed pass.
        self.aliases = aliases or {}
        self.orgs = orgs
        self._by_email: dict[str, str] = {}
        self._by_name: dict[str, str] = {}
        self.people: dict[str, Person] = {}
        self.findings: list[Finding] = []

    def _implied_org(self, address: str) -> str | None:
        """Employer implied by an address, preferring the reviewed registry."""
        if self.orgs is not None:
            if self.orgs.is_personal_domain(address):
                return None
            if (org := self.orgs.resolve_address(address)) is not None:
                return org.canonical_name
            return None
        return organization_from_email(address)

    def _canonical_org(self, stated: str | None) -> str | None:
        if stated and self.orgs is not None:
            if (org := self.orgs.resolve_name(stated)) is not None:
                return org.canonical_name
        return stated

    def add(self, credit: Credit, assertion_date: object) -> str | None:
        """Fold one credit into the person set; return the canonical person id."""
        name = credit.name
        addresses = [clean_email(e) for e in credit.emails]
        norm = normalize_name(name) if name else None

        pid = self._lookup(norm, addresses, credit.github_login)
        if pid is None:
            if name:
                pid = slugify(name)
            elif credit.github_login:
                pid = f"gh-{slugify(credit.github_login)}"
            else:
                self.findings.append(Finding(
                    credit.publication_id, "unidentifiable-credit",
                    "credit has neither a name nor a GitHub handle", credit.raw_line))
                return None
            # Slug collision with no shared key. Neither merging nor splitting is safe
            # to assume -- a person legitimately has several addresses (Jason Garman
            # uses two at Amazon), so differing addresses are not evidence of two
            # people; but two people can share a name. Keep them distinct and let the
            # reviewer decide, rather than guessing either way silently.
            base, n = pid, 2
            while pid in self.people:
                self.findings.append(Finding(
                    credit.publication_id, "name-collision",
                    f"{name!r} keys to an existing person {pid!r} with no shared "
                    f"address or alias; kept separate as {base}-{n}. Merge in "
                    "people.yaml via name_aliases if they are the same person.",
                    credit.raw_line))
                pid = f"{base}-{n}"
                n += 1

        person = self.people.get(pid)
        if person is None:
            person = Person(id=pid, display_name=name or f"@{credit.github_login}")
            self.people[pid] = person

        if name:
            person.names.setdefault(name, name_kind(name))
            if norm:
                self._by_name.setdefault(norm, pid)
            # Prefer an unabbreviated form for display.
            if name_kind(name) == "proper" and name_kind(person.display_name) == "abbreviated":
                person.display_name = name
        if credit.github_login:
            person.github_logins.add(credit.github_login)

        stated, independent = normalize_org(credit.organization)
        org = self._canonical_org(stated)
        person.org_evidence.append(OrgAssertion(
            credit.publication_id, org, independent, assertion_date, "credit-line",
            stated_as=stated))

        for address in addresses:
            self._by_email.setdefault(address, pid)
            implied = self._implied_org(address)
            person.emails.append(EmailAssertion(
                address, credit.publication_id, assertion_date, implied))
            if implied and not org:
                # Domain evidence stands in where the credit line omitted an employer.
                person.org_evidence.append(OrgAssertion(
                    credit.publication_id, implied, False, assertion_date,
                    "email-domain"))

        person.credit_count += 1
        return pid

    def _lookup(
        self, norm: str | None, addresses: list[str], github_login: str | None
    ) -> str | None:
        for address in addresses:
            if address in self._by_email:
                return self._by_email[address]
        if norm and norm in self.aliases:
            return self.aliases[norm]
        if norm and norm in self._by_name:
            return self._by_name[norm]
        if github_login:
            for pid, person in self.people.items():
                if github_login in person.github_logins:
                    return pid
        return None

    def review_findings(self) -> list[Finding]:
        """Decisions a human should confirm before the graph is trusted."""
        out = list(self.findings)
        for person in self.people.values():
            addresses = person.addresses
            # Several addresses per person is expected and is NOT reported on its own:
            # Jason Garman uses garmaja@amazon.com and jason.garman@amazon.com, and a
            # work address alongside a personal one is the ordinary shape of a job
            # change. Only addresses at two or more distinct *employer* domains are
            # worth a look, since that is the shape both a second employer and two
            # different people would take.
            employer_domains = {
                d for a in addresses
                if (d := email_domain(a)) and d not in PERSONAL_DOMAINS
            }
            if len(employer_domains) > 1:
                out.append(Finding(
                    "", "addresses-across-employers",
                    f"{person.display_name!r} has addresses at {sorted(employer_domains)}: "
                    f"{addresses}. One person who changed employer, or two people?",
                ))
            if not addresses and not person.github_logins:
                out.append(Finding(
                    "", "no-strong-key",
                    f"{person.display_name!r} matched on name alone "
                    f"({person.credit_count} credits); no address or handle",
                ))
            # Canonical names, so spellings the registry has already confirmed as one
            # organization no longer register as drift. What remains is real: a person
            # credited under two genuinely different organizations over time, which is
            # affiliation history rather than a defect -- reported so the timeline can
            # be sanity-checked, and so unregistered spellings surface.
            credit_line = [a for a in person.org_evidence if a.source == "credit-line"]
            # Independence is a state, not an absent value: "Josiah Hagen, Trend Micro"
            # followed by "Josiah Hagen, indepedent" is a change, and omitting the
            # independent case would hide exactly the transitions this model exists to
            # capture.
            states = {
                (a.organization if a.organization else "(independent)")
                for a in credit_line
                if a.organization or a.is_independent
            }
            if len(states) > 1:
                spellings = sorted({a.stated_as for a in credit_line if a.stated_as})
                out.append(Finding(
                    "", "affiliation-change",
                    f"{person.display_name!r} credited under {sorted(states)} "
                    f"(spelled {spellings}); confirm one person changing organization "
                    "rather than unregistered variants",
                ))
            if self.orgs is not None:
                unknown = self.orgs.unknown_names({a.stated_as for a in credit_line})
                for name in unknown:
                    out.append(Finding(
                        "", "unregistered-organization",
                        f"{name!r} (credited to {person.display_name!r}) is not in "
                        "organizations.yaml",
                    ))
            conflicts = self._domain_conflicts(person)
            for stated_org, implied_org in conflicts:
                out.append(Finding(
                    "", "organization-domain-mismatch",
                    f"{person.display_name!r} credited as {stated_org!r} but writes "
                    f"from a {implied_org!r} domain",
                ))
        return out

    @staticmethod
    def _domain_conflicts(person: Person) -> list[tuple[str, str]]:
        """Stated employer disagreeing with address domain, within one document.

        Both sides are reduced with the same key function. Comparing a stripped key
        against a raw lower-cased name reported every Thomson Reuters contributor as a
        mismatch against their own thomsonreuters.com address.
        """
        by_pub: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: {"stated": set(), "implied": set()})
        for a in person.org_evidence:
            if a.source == "credit-line" and a.organization:
                by_pub[a.publication_id]["stated"].add(a.organization)
        for e in person.emails:
            if e.implies_organization:
                by_pub[e.publication_id]["implied"].add(e.implies_organization)
        out: list[tuple[str, str]] = []
        for buckets in by_pub.values():
            for stated in buckets["stated"]:
                key = _org_key(stated)
                for implied in buckets["implied"]:
                    ikey = _org_key(implied)
                    if ikey and key and ikey not in key and key not in ikey:
                        pair = (stated, implied)
                        if pair not in out:
                            out.append(pair)
        return out


def _org_key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def organization_variants(people: dict[str, Person]) -> dict[str, dict]:
    """Group organization strings, using address domains as the joining evidence.

    Two passes. The first buckets stated names and domain labels that reduce to the
    same alphanumeric key, collapsing `TrendMicro`, `Trend Micro` and `trendmicro.com`.
    The second merges a bucket into another whose key is a prefix of it (or vice versa)
    when exactly one such bucket exists, which joins `Adversa AI` to `adversa.ai` and
    `Dell` to `Dell Technologies`.

    Prefix merging is deliberately limited to a unique match, so `Trend AI` and
    `Trend Micro` stay separate -- neither key prefixes the other, and whether they
    name one company is not something a string comparison should decide.
    """
    groups: dict[str, dict] = defaultdict(
        lambda: {"stated": Counter(), "domains": Counter()})
    for person in people.values():
        for a in person.org_evidence:
            if a.organization and a.source == "credit-line":
                groups[_org_key(a.organization)]["stated"][a.organization] += 1
        for e in person.emails:
            if e.implies_organization and (domain := email_domain(e.address)):
                groups[_org_key(e.implies_organization)]["domains"][domain] += 1

    merged = _merge_prefix_groups(groups)
    return dict(sorted(merged.items()))


def _merge_prefix_groups(groups: dict[str, dict]) -> dict[str, dict]:
    keys = sorted(groups, key=len)
    absorbed: dict[str, str] = {}
    for key in keys:
        if key in absorbed:
            continue
        candidates = [
            other for other in groups
            if other != key
            and other not in absorbed
            and (other.startswith(key) or key.startswith(other))
        ]
        if len(candidates) == 1:
            absorbed[key] = candidates[0]

    out: dict[str, dict] = {}
    for key, bucket in groups.items():
        target = absorbed.get(key, key)
        while target in absorbed:            # follow a short chain
            target = absorbed[target]
        if target not in out:
            out[target] = {"stated": Counter(), "domains": Counter()}
        out[target]["stated"].update(bucket["stated"])
        out[target]["domains"].update(bucket["domains"])
    return out
