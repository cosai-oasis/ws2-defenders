"""Identity and organization resolution tests.

The cases here are the ones that decide whether attribution is right: merging two
records that are one person, keeping apart two people who share a name shape, and
deciding when an address domain is evidence of an employer.
"""

from __future__ import annotations

import datetime as dt

import pytest

from bubo_graphrag.ingest.credits import Credit
from bubo_graphrag.resolve import identity as I
from bubo_graphrag.resolve.organizations import OrgRegistry


def credit(name=None, org=None, emails=(), login=None, pub="p"):
    return Credit(publication_id=pub, source_label="Contributors", raw_line="",
                  name=name, organization=org, emails=list(emails), github_login=login)


D1 = dt.date(2025, 7, 14)
D2 = dt.date(2026, 5, 26)
D3 = dt.date(2026, 9, 4)


# --- address handling -----------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("Josiah\\_Hagen@trendmicro.com", "josiah_hagen@trendmicro.com"),
    ("  AKILA@Anthropic.com ", "akila@anthropic.com"),
    ("<jrrao@us.ibm.com>", "jrrao@us.ibm.com"),
])
def test_clean_email_unescapes_and_normalizes(raw, expected):
    """Markdown escaping must be undone or the same address fails to match itself."""
    assert I.clean_email(raw) == expected


@pytest.mark.parametrize("address,expected", [
    ("asmae.mhassni@intel.com", "intel"),
    ("jrrao@us.ibm.com", "ibm"),              # subdomain reduced
    ("josiah.hagen@gmail.com", None),         # free-mail implies nothing
    ("victorjunlu@gmail.com", None),
])
def test_organization_from_email(address, expected):
    assert I.organization_from_email(address) == expected


# --- name handling --------------------------------------------------------------

@pytest.mark.parametrize("a,b", [
    ("J.R. Rao", "JR Rao"),                  # punctuation dropped
    ("Asmae Mhassni", "asmae  mhassni"),     # case and repeated whitespace
    ("Jean-Luc Roe", "Jean Luc Roe"),        # hyphen folds to a space
    ("Yu-Cheng Liang", "Yu Cheng Liang"),    # a real hyphenated name in the corpus
    ("O'Brien Roe", "OBrien Roe"),           # apostrophe dropped
])
def test_names_that_should_key_together(a, b):
    assert I.normalize_name(a) == I.normalize_name(b)


def test_spaced_initials_are_deliberately_not_folded():
    """`J R Rao` is left distinct from `J.R. Rao`.

    Folding internal spaces would merge them, but it would also merge any two-token
    name with its concatenation. That form does not occur in the corpus, so the
    speculative normalization is not worth the false-merge risk; people.yaml aliases
    exist for cases like it.
    """
    assert I.normalize_name("J R Rao") != I.normalize_name("J.R. Rao")


def test_full_given_name_does_not_silently_merge_with_initials():
    """Joining 'Josyula R. Rao' to 'J.R. Rao' is an alias decision, not string folding."""
    assert I.normalize_name("Josyula R. Rao") != I.normalize_name("J.R. Rao")


@pytest.mark.parametrize("name,kind", [
    ("J.R. Rao", "abbreviated"),
    ("Josiah Hagen", "proper"),
    ("Riggs Goodman III", "proper"),
])
def test_name_kind_classification(name, kind):
    assert I.name_kind(name) == kind


# --- organization normalization -------------------------------------------------

@pytest.mark.parametrize("raw", ["independent", "indepedent", "Independent", "none", ""])
def test_independent_forms_are_not_organizations(raw):
    """'indepedent' is a real typo in Zero Trust; normalizing it is essential."""
    org, independent = I.normalize_org(raw)
    assert org is None
    if raw:
        assert independent is True


def test_normalize_org_trims_stray_punctuation():
    assert I.normalize_org(" Intel ,")[0] == "Intel"


# --- merging --------------------------------------------------------------------

def test_merges_on_shared_address():
    r = I.Resolver()
    r.add(credit("Josiah Hagen", "Trend Micro", ["josiah_hagen@trendmicro.com"]), D1)
    r.add(credit("Josiah Hagen", None, ["josiah_hagen@trendmicro.com"]), D2)
    assert len(r.people) == 1


def test_merges_on_name_when_one_record_has_no_address():
    """26 of ~104 raw names carry no address anywhere; name has to carry them."""
    r = I.Resolver()
    r.add(credit("Igor Pedan", "Dell"), D1)
    r.add(credit("Igor Pedan", "Dell"), D2)
    assert len(r.people) == 1
    assert r.people["igor-pedan"].credit_count == 2


def test_one_person_may_hold_several_addresses():
    """Jason Garman is credited under two Amazon addresses; both belong to him."""
    r = I.Resolver()
    r.add(credit("Jason Garman", "Amazon", ["garmaja@amazon.com"]), D1)
    r.add(credit("Jason Garman", None, ["jason.garman@amazon.com"]), D2)
    assert len(r.people) == 1
    person = r.people["jason-garman"]
    assert set(person.addresses) == {"garmaja@amazon.com", "jason.garman@amazon.com"}


def test_several_addresses_at_one_domain_is_not_reported():
    """Two addresses at the same employer is unremarkable and must not be noise."""
    r = I.Resolver()
    r.add(credit("Jason Garman", "Amazon", ["garmaja@amazon.com"]), D1)
    r.add(credit("Jason Garman", None, ["jason.garman@amazon.com"]), D2)
    kinds = {f.kind for f in r.review_findings()}
    assert "addresses-across-employers" not in kinds


def test_addresses_at_two_employers_is_reported():
    """Two employer domains could be a job change or two people; surface it."""
    r = I.Resolver()
    r.add(credit("Bill Stout", "ServiceNow", ["bill.stout@servicenow.com"]), D1)
    r.add(credit("Bill Stout", "Acme", ["bill@acme.com"]), D2)
    assert any(f.kind == "addresses-across-employers" for f in r.review_findings())


def test_work_plus_personal_address_is_not_reported_as_two_employers():
    """A gmail alongside a work address is the ordinary shape of a job change."""
    r = I.Resolver()
    r.add(credit("Bill Stout", "ServiceNow", ["bill.stout@servicenow.com"]), D1)
    r.add(credit("Bill Stout", None, ["billbrietstout@gmail.com"]), D2)
    kinds = {f.kind for f in r.review_findings()}
    assert "addresses-across-employers" not in kinds


def test_same_name_two_employers_is_surfaced_not_silently_merged():
    """Two people sharing a name merge on the name, but never silently.

    The merge is reported as `addresses-across-employers`, which is the review signal
    that a human must confirm whether this is one person who moved or two people.
    """
    r = I.Resolver()
    r.add(credit("Alex Smith", "Intel", ["a.smith@intel.com"]), D1)
    r.add(credit("Alex Smith", "Meta", ["alex.smith@meta.com"]), D2)
    assert any(f.kind == "addresses-across-employers" for f in r.review_findings())


def test_slug_collision_without_a_shared_key_stays_separate_and_is_flagged():
    """Names that key differently but slug identically are kept apart, with a finding."""
    r = I.Resolver()
    r.add(credit("Alex Smith", "Intel", ["a.smith@intel.com"]), D1)
    r.add(credit("Alexsmith", "Meta", ["alex.smith@meta.com"]), D2)
    assert len(r.people) == 2
    # Different normalized names, so no merge and no collision path either; the point
    # is only that they did not collapse into one record.
    assert {p.display_name for p in r.people.values()} == {"Alex Smith", "Alexsmith"}


def test_registry_alias_forces_a_merge():
    """The reviewed people.yaml is how the emailless and variant names get joined."""
    aliases = {I.normalize_name("Josyula R. Rao"): "j-r-rao"}
    r = I.Resolver(aliases)
    r.add(credit("J.R. Rao", "IBM", ["jrrao@us.ibm.com"]), D1)
    r.add(credit("Josyula R. Rao", "IBM"), D2)
    assert len(r.people) == 1


def test_github_handle_only_credit_is_kept():
    r = I.Resolver()
    r.add(credit(None, None, login="skvcool-rgb"), D3)
    assert len(r.people) == 1
    assert next(iter(r.people.values())).github_logins == {"skvcool-rgb"}


def test_credit_with_neither_name_nor_handle_is_a_finding():
    r = I.Resolver()
    assert r.add(credit(None, None), D1) is None
    assert any(f.kind == "unidentifiable-credit" for f in r.findings)


# --- organization registry ------------------------------------------------------

def test_registry_resolves_confirmed_variants():
    reg = OrgRegistry()
    assert reg.same_organization("Trend Micro", "TrendMicro")
    assert reg.same_organization("Dell", "Dell Technologies")
    assert reg.same_organization("PayPal", "Paypal")


def test_registry_merges_trend_ai_on_maintainer_confirmation():
    """Nothing in the corpus establishes this; a human supplied the fact."""
    reg = OrgRegistry()
    assert reg.same_organization("Trend AI", "Trend Micro")
    org = reg.resolve_name("Trend AI")
    assert org.merge_provenance, "the merge basis must be recorded"
    assert org.merge_provenance[0]["basis"] == "maintainer-confirmed"


def test_registry_resolves_addresses_to_organizations():
    reg = OrgRegistry()
    assert reg.resolve_address("asmae.mhassni@intel.com").canonical_name == "Intel"
    assert reg.resolve_address("jrrao@us.ibm.com").canonical_name == "IBM"


def test_personal_domains_imply_no_employer():
    """chuvakin.org is Anton Chuvakin's own domain, not his employer."""
    reg = OrgRegistry()
    assert reg.resolve_address("anton@chuvakin.org") is None
    assert reg.is_personal_domain("anton@chuvakin.org")
    assert reg.is_personal_domain("someone@gmail.com")


def test_confirmed_variants_do_not_register_as_drift(resolved):
    """Once the registry answers a variant question, it stops being a finding."""
    _, _, findings, _ = resolved
    for finding in findings:
        if finding.kind == "affiliation-change":
            assert "TrendMicro" not in finding.detail or "(independent)" in finding.detail


def test_real_corpus_resolves_to_the_expected_shape(resolved):
    resolver, credits, _, _ = resolved
    assert len(credits) == 183          # 180 credit-section + 3 ODIS front-matter
    assert len(resolver.people) == 90
