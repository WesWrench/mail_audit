"""DMARC parsing with checkdmarc >= 6 (RFC 9989 / DMARCbis + RFC 9091 np).

Offline: records without rua/ruf, so checkdmarc makes no DNS query.
"""

import pytest

from lib.checkers.dmarc_checker import DMARCChecker


@pytest.fixture(scope="module")
def checker():
    return DMARCChecker(cname_check=False)


def _codes(result):
    return sorted(i.code for i in result.issues)


@pytest.mark.parametrize("record,policy,sp,np,codes", [
    ("v=DMARC1; p=reject", "reject", "reject", "reject", []),
    # Implicit sp equals p: p=none is reported once, not twice.
    ("v=DMARC1; p=none", "none", "none", "none", ["dmarc_lax_policy"]),
    ("v=DMARC1; p=reject; sp=none", "reject", "none", "none", ["dmarc_lax_subdomain_policy"]),
    # RFC 9091: np defaults to an explicit sp, else p.
    ("v=DMARC1; p=reject; sp=none; np=reject", "reject", "none", "reject", ["dmarc_lax_subdomain_policy"]),
    ("v=DMARC1; p=reject; np=none", "reject", "reject", "none", []),
    # RFC 9989: a missing p is p=none; unknown tags are ignored.
    ("v=DMARC1; adkim=s", "none", "none", "none", ["dmarc_lax_policy"]),
    ("v=DMARC1; p=reject; foo=bar", "reject", "reject", "reject", []),
])
def test_policies(checker, record, policy, sp, np, codes):
    r = checker.check_record(record, "example.com")
    assert (r.policy, r.subdomain_policy, r.np_policy, _codes(r)) == (policy, sp, np, codes)


@pytest.mark.parametrize("record,testing,codes", [
    ("v=DMARC1; p=reject; t=y", True, ["dmarc_testing_mode"]),
    ("v=DMARC1; p=quarantine; t=y", True, ["dmarc_testing_mode"]),
    ("v=DMARC1; p=reject; t=n", False, []),
    # t has no effect on p=none (already reported as lax).
    ("v=DMARC1; p=none; t=y", True, ["dmarc_lax_policy"]),
])
def test_testing_mode(checker, record, testing, codes):
    r = checker.check_record(record, "example.com")
    assert (r.testing, _codes(r)) == (testing, codes)


def test_testing_mode_severity_follows_policy(checker):
    reject = checker.check_record("v=DMARC1; p=reject; t=y", "example.com").issues[0]
    quarantine = checker.check_record("v=DMARC1; p=quarantine; t=y", "example.com").issues[0]
    assert (reject.severity.value, quarantine.severity.value) == ("medium", "high")


@pytest.mark.parametrize("record,pct", [
    ("v=DMARC1; p=reject; pct=50", 50),
    ("v=DMARC1; p=quarantine; pct=0", 0),
    ('"v=DMARC1; p=reject; pct=25"', 25),
])
def test_legacy_pct_still_reported(checker, record, pct):
    # RFC 9989 removed pct (checkdmarc drops it) but RFC 7489 receivers apply it.
    r = checker.check_record(record, "example.com")
    assert r.percentage == pct
    assert "dmarc_partial_coverage" in _codes(r)


def test_psd_flag(checker):
    assert checker.check_record("v=DMARC1; p=reject; psd=y", "example.com").psd == "y"


@pytest.mark.parametrize("record,code", [
    ("v=DMARC1; p=blah", "dmarc_invalid_tag_value"),
    ("v=DMARC1; p=reject; fo=z", "dmarc_invalid_tag_value"),
    ("v=DMARC1; p=reject; p=none", "dmarc_invalid_tag"),
])
def test_errors(checker, record, code):
    assert _codes(checker.check_record(record, "example.com")) == [code]


@pytest.mark.parametrize("record,nonexistent,policy,source", [
    ("v=DMARC1; p=reject; sp=none; np=reject", False, "none", "sp=none"),
    ("v=DMARC1; p=reject; sp=none; np=reject", True, "reject", "np=reject"),
    ("v=DMARC1; p=reject; sp=none", True, "none", "sp=none"),
    ("v=DMARC1; p=none; np=reject", True, "reject", "np=reject"),
    ("v=DMARC1; p=quarantine", True, "quarantine", "p=quarantine"),
])
def test_inherited_policy(checker, record, nonexistent, policy, source):
    r = checker.check_record(record, "example.com")
    DMARCChecker._apply_inherited_policy(r, record, "example.com", nonexistent)
    assert r.policy == policy
    assert r.policy_inherited_from == f"example.com ({source})"


@pytest.mark.parametrize("policy,pct,severity,fallback", [
    ("quarantine", 0, "high", "none"),
    ("reject", 0, "medium", "quarantine"),
    ("quarantine", 10, "high", "none"),
    ("reject", 10, "medium", "quarantine"),
    ("quarantine", 50, "medium", "none"),
    ("reject", 50, "low", "quarantine"),
    ("quarantine", 90, "low", "none"),
    ("reject", 99, "low", "quarantine"),
])
def test_pct_severity_by_range_and_policy(checker, policy, pct, severity, fallback):
    r = checker.check_record(f"v=DMARC1; p={policy}; pct={pct}", "example.com")
    [issue] = [i for i in r.issues if i.code == "dmarc_partial_coverage"]
    assert issue.severity.value == severity
    assert issue.additional_data["fallback_policy"] == fallback
    assert issue.additional_data["escape_rate"] == 100 - pct


def test_pct_on_p_none_is_low(checker):
    r = checker.check_record("v=DMARC1; p=none; pct=10", "example.com")
    [issue] = [i for i in r.issues if i.code == "dmarc_partial_coverage"]
    assert issue.severity.value == "low"
