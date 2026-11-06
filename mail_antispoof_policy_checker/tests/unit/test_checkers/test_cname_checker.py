"""Tests for the CNAME chain check on DKIM / DMARC / SPF lookup names.

All DNS answers are simulated (FakeDNS) so the tests are deterministic and
offline.  Run from the package root:

    python -m pytest tests/unit/test_checkers/test_cname_checker.py -v
"""
import types

import dns.message
import pytest

from lib.checkers.cname_checker import CNAMEChecker, is_dmarc_record, is_spf_record
from lib.checkers.dkim_checker import DKIMChecker
from lib.checkers.dmarc_checker import DMARCChecker
from lib.checkers.issue_definitions import IssueDefinitions
from lib.checkers.spf_checker import SPFChecker
from lib.checkers import unregistered_domain_checker as udc
from lib.models.dmarc_result import DMARCResult
from lib.models.spf_result import SPFResult
from lib.utils.dns_utils import DNSQueryOutcome, _extract_cname_chain

DKIM_KEY = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"


# ─────────────────────────────────────────────────────────────────────────────
# Simulated recursive resolver
# ─────────────────────────────────────────────────────────────────────────────

class FakeDNS:
    """Minimal recursive-resolver emulation over an in-memory zone.

    zone values: {'CNAME': target} | {'TXT': [...]} | {'A': [...]} | {'error': 'SERVFAIL'}
    A key '*.<parent>' acts as a wildcard for absent names directly under <parent>.
    """

    def __init__(self, zone):
        self.zone = {k.lower(): v for k, v in zone.items()}
        self.queries = []

    def _lookup(self, name):
        if name in self.zone:
            return self.zone[name]
        parent = name.split('.', 1)[1] if '.' in name else ''
        if not self._exists(name) and f"*.{parent}" in self.zone:
            return self.zone[f"*.{parent}"]
        return None

    def _exists(self, name):
        return name in self.zone or any(k.endswith('.' + name) and not k.startswith('*.') for k in self.zone)

    def query(self, name, rdtype):
        name = name.rstrip('.').lower()
        self.queries.append((name, rdtype))
        if rdtype == 'CNAME':
            node = self._lookup(name)
            if node and 'error' in node:
                return DNSQueryOutcome(name, rdtype, node['error'])
            if node and 'CNAME' in node:
                return DNSQueryOutcome(name, rdtype, 'NOERROR', [node['CNAME']])
            if node is not None or self._exists(name):
                return DNSQueryOutcome(name, rdtype, 'NODATA')
            return DNSQueryOutcome(name, rdtype, 'NXDOMAIN')

        # Recursive lookup following CNAMEs, like a real resolver
        chain, current, seen = [], name, {name}
        while True:
            node = self._lookup(current)
            if node and 'error' in node:
                return DNSQueryOutcome(name, rdtype, node['error'])
            if node and 'CNAME' in node:
                target = node['CNAME']
                chain.append((current, target))
                if target in seen:
                    return DNSQueryOutcome(name, rdtype, 'SERVFAIL')  # resolvers fail on loops
                seen.add(target)
                current = target
                continue
            if node is None and not self._exists(current):
                return DNSQueryOutcome(name, rdtype, 'NXDOMAIN', cname_chain=chain)
            records = (node or {}).get(rdtype, [])
            status = 'NOERROR' if records else 'NODATA'
            return DNSQueryOutcome(name, rdtype, status, list(records), chain)


def checker(zone, **kw):
    fake = FakeDNS(zone)
    return CNAMEChecker(query=fake.query, **kw), fake


# ─────────────────────────────────────────────────────────────────────────────
# Core classification
# ─────────────────────────────────────────────────────────────────────────────

def test_cname_to_valid_txt_without_a_aaaa_is_ok():
    c, _ = checker({
        "_dmarc.example.com": {"CNAME": "dmarc.provider.net"},
        "dmarc.provider.net": {"TXT": ["v=DMARC1; p=reject"]},   # TXT only, no A/AAAA
    })
    check = c.check_name("DMARC", "_dmarc.example.com", is_dmarc_record)
    assert check.anomaly == "ok"
    assert check.relevant_record_found is True
    assert check.dns_status == "NOERROR"   # TXT status at the target, not the CNAME query's NODATA
    assert check.chain == ["_dmarc.example.com", "dmarc.provider.net"]


def test_cname_to_nxdomain_target_is_broken_reference_and_chain_is_kept():
    c, _ = checker({"_dmarc.example.com": {"CNAME": "gone.provider.net"},
                    "provider.net": {"TXT": ["x"]}})
    check = c.check_name("DMARC", "_dmarc.example.com", is_dmarc_record)
    assert check.anomaly == "broken_reference"
    assert check.chain == ["_dmarc.example.com", "gone.provider.net"]
    assert check.failing_target == "gone.provider.net"
    assert check.dns_status == "NXDOMAIN"
    assert check.confidence == "high"


def test_source_absent_without_cname_is_not_reported():
    c, _ = checker({"example.com": {"TXT": ["v=spf1 -all"]}})
    assert c.check_name("DMARC", "_dmarc.example.com", is_dmarc_record) is None


def test_target_exists_without_relevant_txt_is_missing_record():
    c, _ = checker({
        "_dmarc.example.com": {"CNAME": "host.provider.net"},
        "host.provider.net": {"A": ["192.0.2.1"], "TXT": ["google-site-verification=abc"]},
    })
    check = c.check_name("DMARC", "_dmarc.example.com", is_dmarc_record)
    assert check.anomaly == "missing_record"
    assert check.registration["state"] == "registered"


@pytest.mark.parametrize("status", ["SERVFAIL", "TIMEOUT", "REFUSED"])
def test_temporary_errors_are_indeterminate(status):
    c, _ = checker({
        "_dmarc.example.com": {"CNAME": "flaky.provider.net"},
        "flaky.provider.net": {"error": status},
    })
    check = c.check_name("DMARC", "_dmarc.example.com", is_dmarc_record)
    assert check.anomaly == "indeterminate"
    assert check.dns_status == status
    assert check.confidence == "low"


def test_multi_hop_chain_with_absent_final_target():
    c, _ = checker({
        "_dmarc.example.com": {"CNAME": "a.hop.net"},
        "a.hop.net": {"CNAME": "b.hop.net"},
        "b.hop.net": {"CNAME": "c.gone.org"},
        "gone.org": {"TXT": ["x"]},
    })
    check = c.check_name("DMARC", "_dmarc.example.com", is_dmarc_record)
    assert check.anomaly == "broken_reference"
    assert check.chain == ["_dmarc.example.com", "a.hop.net", "b.hop.net", "c.gone.org"]
    assert [h["status"] for h in check.hops] == ["NOERROR", "NOERROR", "NOERROR", "NXDOMAIN"]
    assert check.registrable_domain == "gone.org"


def test_cname_loop_is_detected():
    c, _ = checker({
        "_dmarc.example.com": {"CNAME": "a.loop.net"},
        "a.loop.net": {"CNAME": "b.loop.net"},
        "b.loop.net": {"CNAME": "a.loop.net"},
    })
    check = c.check_name("DMARC", "_dmarc.example.com", is_dmarc_record)
    assert check.anomaly == "resolution_loop"
    assert check.chain[-1] == "a.loop.net"


def test_max_depth_exceeded():
    zone = {f"h{i}.chain.net": {"CNAME": f"h{i + 1}.chain.net"} for i in range(6)}
    zone["_dmarc.example.com"] = {"CNAME": "h0.chain.net"}
    c, _ = checker(zone, max_depth=3)
    check = c.check_name("DMARC", "_dmarc.example.com", is_dmarc_record)
    assert check.anomaly == "max_depth_exceeded"
    assert len(check.chain) == 5  # source + 4 links (one more than the limit)


def test_observed_cname_is_kept_when_hop_walk_fails():
    """CNAME seen in the TXT answer must not be lost if the CNAME query fails."""
    def query(name, rdtype):
        if rdtype == "CNAME":
            return DNSQueryOutcome(name, rdtype, "TIMEOUT")
        return DNSQueryOutcome(name, rdtype, "NXDOMAIN",
                               cname_chain=[("_dmarc.example.com", "gone.provider.net")])
    c = CNAMEChecker(query=query)
    check = c.check_name("DMARC", "_dmarc.example.com", is_dmarc_record)
    assert check.anomaly == "broken_reference"
    assert check.chain == ["_dmarc.example.com", "gone.provider.net"]
    assert check.confidence == "medium"


def test_invalid_tld_target_is_absent_but_reserved_not_registrable():
    c, _ = checker({"_dmarc.example.com": {"CNAME": "anunregistereddomain.invalid"}})
    check = c.check_name("DMARC", "_dmarc.example.com", is_dmarc_record)
    assert check.anomaly == "broken_reference"
    assert check.suffix_type == "reserved"
    assert check.registration["state"] == "reserved"
    assert check.registrable_domain is None  # never sent to the availability checker
    assert udc.collect_cname_registration_candidates([{"cname_checks": [check.to_dict()]}]) == set()


def test_registrable_domain_uses_public_suffix_list():
    assert udc.classify_registrable_domain("a.b.example.co.uk")["registrable_domain"] == "example.co.uk"
    assert udc.classify_registrable_domain("x.github.io")["suffix_type"] == "private"
    assert udc.classify_registrable_domain("foo.test")["suffix_type"] == "reserved"


# ─────────────────────────────────────────────────────────────────────────────
# Registration (reuses DomainAvailabilityChecker results — no second mechanism)
# ─────────────────────────────────────────────────────────────────────────────

def _broken_dkim_result():
    c, _ = checker({"s1._domainkey.example.com": {"CNAME": "dkim.expired-esp.com"}})
    check = c.check_name("DKIM", "s1._domainkey.example.com", lambda t: True, selector="s1")
    assert check.registration["state"] == "not_verified"
    return {"issues": [], "statistics": {"total_issues": 0}, "cname_checks": [check.to_dict()]}


def test_nxdomain_alone_never_concludes_unregistered():
    result = _broken_dkim_result()
    codes = [i["code"] for i in result["issues"]]
    assert "dkim_cname_target_unregistered" not in codes
    assert udc.collect_cname_registration_candidates([result]) == {"expired-esp.com"}


@pytest.mark.parametrize("status,state,code,severity", [
    ("available", "unregistered", "dkim_cname_target_unregistered", "critical"),
    ("unknown", "potentially_unregistered", "dkim_cname_target_potentially_unregistered", "high"),
    ("unavailable", "registered", None, None),
])
def test_registration_results_are_applied(status, state, code, severity):
    result = _broken_dkim_result()
    added = udc.apply_cname_registration_results(
        [result], {"expired-esp.com": {"status": status, "reason": "whois_available"}}
    )
    check = result["cname_checks"][0]
    assert check["registration"]["state"] == state
    assert check["registration"]["source"] == "domain_availability_checker"
    if code:
        assert [i["code"] for i in result["issues"]] == [code]
        assert result["issues"][0]["severity"] == severity
        assert "NOT confirmed" in result["issues"][0]["detail"]
        assert added[0]["registrable_domain"] == "expired-esp.com"
    else:
        assert result["issues"] == [] and added == []


# ─────────────────────────────────────────────────────────────────────────────
# DKIM wildcard handling
# ─────────────────────────────────────────────────────────────────────────────

def test_random_selectors_with_same_cname_are_wildcard_probable_and_grouped():
    fake = FakeDNS({
        "*._domainkey.example.com": {"CNAME": "dkim.gone-esp.com"},
        "example.com": {"TXT": ["v=spf1 -all"]},
    })
    c = CNAMEChecker(query=fake.query)
    candidates = [(s, f"{s}._domainkey.example.com", fake.query(f"{s}._domainkey.example.com", "TXT"))
                  for s in ("default", "google", "s1", "k1")]
    checks = c.check_dkim_selectors(candidates, lambda t: True)
    assert len(checks) == 4                                    # kept, not dropped
    assert {ch.wildcard["status"] for ch in checks} == {"wildcard_probable"}
    assert len(checks[0].wildcard["probes"]) == 3
    assert all(p["name"].startswith("random-") for p in checks[0].wildcard["probes"])
    # Once the target domain is found unregistered: ONE grouped takeover issue
    result = {"issues": [], "statistics": {}, "cname_checks": [ch.to_dict() for ch in checks]}
    udc.apply_cname_registration_results(
        [result], {"gone-esp.com": {"status": "available", "reason": "whois_available"}})
    [issue] = result["issues"]
    assert issue["code"] == "dkim_cname_target_unregistered"
    assert sorted(issue["additional_data"]["selectors"]) == ["default", "google", "k1", "s1"]
    assert "Wildcard probable" in issue["detail"]


def test_explicit_selector_with_nxdomain_probes_is_not_excluded():
    fake = FakeDNS({
        "s1._domainkey.example.com": {"CNAME": "dkim.gone-esp.com"},
        "example.com": {"TXT": ["v=spf1 -all"]},
    })
    c = CNAMEChecker(query=fake.query)
    name = "s1._domainkey.example.com"
    [check] = c.check_dkim_selectors([("s1", name, fake.query(name, "TXT"))], lambda t: True)
    assert check.wildcard["status"] == "explicit"


def test_cname_on_parent_is_not_treated_as_wildcard():
    """A CNAME at _domainkey.<domain> does not apply to its descendants."""
    fake = FakeDNS({
        "_domainkey.example.com": {"CNAME": "keys.provider.net"},
        "s1._domainkey.example.com": {"CNAME": "s1.gone.net"},
    })
    c = CNAMEChecker(query=fake.query)
    name = "s1._domainkey.example.com"
    [check] = c.check_dkim_selectors([("s1", name, fake.query(name, "TXT"))], lambda t: True)
    assert check.wildcard["status"] == "explicit"


def test_multi_label_selector_probes_its_own_parent():
    fake = FakeDNS({"a.b._domainkey.example.com": {"CNAME": "gone.esp.net"}})
    c = CNAMEChecker(query=fake.query)
    name = "a.b._domainkey.example.com"
    [check] = c.check_dkim_selectors([("a.b", name, fake.query(name, "TXT"))], lambda t: True)
    assert all(p["name"].endswith(".b._domainkey.example.com") for p in check.wildcard["probes"])


def test_dkim_checker_end_to_end_with_custom_selector_file(tmp_path):
    selector_file = tmp_path / "selectors.txt"
    selector_file.write_text("# custom list\nmail\nselector1\nselector1\n\nrsa1024\n", encoding="utf-8")
    fake = FakeDNS({
        "mail._domainkey.example.com": {"TXT": [DKIM_KEY]},
        "selector1._domainkey.example.com": {"CNAME": "anunregistereddomain.invalid"},
    })
    dkim = DKIMChecker(selector_file=str(selector_file))
    assert dkim.selectors == ["mail", "selector1", "rsa1024"]
    dkim.dns_utils = types.SimpleNamespace(query_classified=fake.query)
    dkim.cname_checker = CNAMEChecker(query=fake.query)
    result = dkim.check("example.com").to_dict()
    assert [s["selector"] for s in result["selectors_found"]] == ["mail"]
    assert [c["queried_name"] for c in result["cname_checks"]] == ["selector1._domainkey.example.com"]
    assert result["cname_checks"][0]["registration"]["state"] == "reserved"
    # .invalid is reserved: no takeover risk -> no CNAME issue at all
    assert not [i for i in result["issues"] if "cname" in i["code"]]


# ─────────────────────────────────────────────────────────────────────────────
# SPF / DMARC integration
# ─────────────────────────────────────────────────────────────────────────────

def _spf_checker(fake):
    spf = SPFChecker(data_loaders=types.SimpleNamespace(_loaded=True))
    spf.cname_checker = CNAMEChecker(query=fake.query)
    spf._check_dns = lambda domain, use_checkdmarc=True: SPFResult(domain=domain)
    return spf


def test_cname_at_spf_domain_is_checked():
    fake = FakeDNS({"test.example.com": {"CNAME": "gone.provider.net"}})
    result = _spf_checker(fake).check("test.example.com")
    assert [c.anomaly for c in result.cname_checks] == ["broken_reference"]
    assert result.cname_checks[0].registrable_domain == "provider.net"
    assert result.issues == []   # DNS anomaly alone: evidence only, issue only if unregistered


def test_spf_broken_include_without_cname_is_out_of_scope():
    fake = FakeDNS({"example.com": {"TXT": ["v=spf1 include:gone.example.net -all"]}})
    result = _spf_checker(fake).check("example.com")
    assert result.cname_checks == []
    assert not [i for i in result.issues if "cname" in i.code]
    # the SPF include target is never queried by the CNAME check
    assert not [q for q in fake.queries if q[0] == "gone.example.net"]


def test_dmarc_broken_cname_does_not_claim_absence_of_policy():
    fake = FakeDNS({"_dmarc.sub.example.com": {"CNAME": "gone.provider.net"}})
    dmarc = DMARCChecker()
    dmarc.cname_checker = CNAMEChecker(query=fake.query)
    dmarc._check_dns = lambda domain, use_checkdmarc=True: DMARCResult(domain=domain, policy="reject")
    result = dmarc.check("sub.example.com")
    assert result.issues == []                       # no "no_dmarc" / no issue from the CNAME check
    assert result.cname_checks[0].anomaly == "broken_reference"


def test_relevance_predicates():
    assert is_spf_record("v=spf1 -all") and not is_spf_record("v=spf10")
    assert is_dmarc_record("v=DMARC1; p=none") and not is_dmarc_record("v=spf1 -all")


def test_every_cname_slug_is_registered():
    defs = IssueDefinitions.get_issue_definitions()
    for protocol in ("SPF", "DMARC", "DKIM"):
        for kind in IssueDefinitions.CNAME_SLUG_SUFFIXES:
            assert IssueDefinitions.cname_slug(protocol, kind) in defs


# ─────────────────────────────────────────────────────────────────────────────
# DNSUtils: CNAME chain extraction from a real answer section
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_cname_chain_from_nxdomain_response():
    response = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NXDOMAIN\nflags QR RD RA\n"
        ";QUESTION\n_dmarc.example.com. IN TXT\n"
        ";ANSWER\n"
        "_dmarc.example.com. 300 IN CNAME a.hop.net.\n"
        "a.hop.net. 300 IN CNAME gone.provider.net.\n"
    )
    assert _extract_cname_chain(response, "_dmarc.example.com") == [
        ("_dmarc.example.com", "a.hop.net"),
        ("a.hop.net", "gone.provider.net"),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# DKIM key size classification
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("bits,code,severity", [
    (512, "dkim_rsa_weak_key", "high"),
    (1024, "dkim_rsa_perfectible_key", "low"),
    (2048, None, None),
])
def test_dkim_rsa_key_size_issue(bits, code, severity):
    issue = DKIMChecker._rsa_key_size_issue("s1", bits)
    if code is None:
        assert issue is None
    else:
        assert (issue.code, issue.severity.value) == (code, severity)
        assert issue.additional_data == {"selector": "s1", "key_size": bits}
        assert code in IssueDefinitions.get_issue_definitions()


@pytest.mark.parametrize("protocol", ["SPF", "DMARC", "DKIM"])
def test_takeover_issue_for_every_protocol(protocol):
    name = {"SPF": "example.com", "DMARC": "_dmarc.example.com", "DKIM": "s1._domainkey.example.com"}[protocol]
    c, _ = checker({name: {"CNAME": "x.expired-domain.fr"}})
    check = c.check_name(protocol, name, lambda t: True, selector="s1" if protocol == "DKIM" else None)
    result = {"issues": [], "statistics": {}, "cname_checks": [check.to_dict()]}
    udc.apply_cname_registration_results([result], {"expired-domain.fr": {"status": "available", "reason": "whois_available"}})
    assert [i["code"] for i in result["issues"]] == [f"{protocol.lower()}_cname_target_unregistered"]
    assert result["issues"][0]["severity"] == "critical"


def test_only_takeover_cname_slugs_exist():
    cname_slugs = {k for k in IssueDefinitions.get_issue_definitions() if "_cname_" in k}
    assert cname_slugs == {f"{p}_cname_target_{s}" for p in ("spf", "dmarc", "dkim")
                           for s in ("unregistered", "potentially_unregistered")}


# ─────────────────────────────────────────────────────────────────────────────
# SPF include availability (shared by the CLI and mail_audit)
# ─────────────────────────────────────────────────────────────────────────────

def test_spf_include_availability_is_deduplicated_and_applied():
    spf_a = {"issues": [], "statistics": {}, "all_includes": [{"include": "spf.gone-esp.com"}, {"include": "_spf.google.com"}]}
    spf_b = {"issues": [], "statistics": {}, "all_includes": [{"include": "mail.gone-esp.com"}]}
    sources = udc.collect_spf_include_sources([("a.fr", spf_a), ("b.fr", spf_b), ("c.fr", {"error": "x"})])
    assert set(sources) == {"gone-esp.com", "google.com"}            # one check per registered domain
    assert len(sources["gone-esp.com"]) == 2
    added = udc.apply_spf_include_availability(
        {"a.fr": spf_a, "b.fr": spf_b}, sources,
        {"gone-esp.com": {"status": "available"}, "google.com": {"status": "unavailable"}})
    assert [i["code"] for i in spf_a["issues"]] == ["spf_domain_unregistered"]
    assert [i["code"] for i in spf_b["issues"]] == ["spf_domain_unregistered"]
    assert spf_a["statistics"]["critical_issues"] == 1 and len(added) == 2


# ─────────────────────────────────────────────────────────────────────────────
# DMARC subdomain lookup: own record first, else org domain sp= (else p=)
# ─────────────────────────────────────────────────────────────────────────────

def _dmarc_with(records):
    dmarc = DMARCChecker(cname_check=False)
    dmarc.dns_utils = types.SimpleNamespace(get_dmarc_record=lambda d: records.get(d))
    return dmarc


@pytest.mark.parametrize("records,expected_policy,lax", [
    ({"_": None, "exemple.fr": "v=DMARC1; p=reject; sp=none"}, "none", True),     # sp= wins for subdomains
    ({"_": None, "exemple.fr": "v=DMARC1; p=none; sp=reject"}, "reject", False),
    ({"_": None, "exemple.fr": "v=DMARC1; p=quarantine"}, "quarantine", False),   # no sp= -> p=
    ({"news.exemple.fr": "v=DMARC1; p=none", "exemple.fr": "v=DMARC1; p=reject"}, "none", True),  # own record first
])
def test_dmarc_subdomain_policy_inheritance(records, expected_policy, lax):
    result = _dmarc_with(records).check("news.exemple.fr")
    assert result.policy == expected_policy
    assert ("dmarc_lax_policy" in [i.code for i in result.issues]) is lax
    if "news.exemple.fr" not in records:
        assert result.dmarc_domain_checked == "exemple.fr"
        assert result.policy_inherited_from.startswith("exemple.fr (")


def test_dmarc_organizational_domain_uses_public_suffix_list():
    assert DMARCChecker._organizational_domain("news.exemple.co.uk") == "exemple.co.uk"
    assert DMARCChecker._organizational_domain("a.b.example.com") == "example.com"
