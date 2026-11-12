"""RFC 9989 t=y (DMARC test mode): the published policy is applied one level lower."""

import json
from pathlib import Path

import pytest

from mail_audit.lib import attack_scenarios
from mail_audit.lib.attack_scenarios import AttackScenarioAnalyzer

_SERVICES = json.loads(
    (Path(attack_scenarios.__file__).parent / "data" / "email_services.json").read_text(encoding="utf-8")
)["services"]


def _analyzer(policy, testing):
    dmarc = {"policy": policy, "testing": testing, "issues": []}
    if testing and policy in ("reject", "quarantine"):
        dmarc["issues"] = [{"code": "dmarc_testing_mode"}]
    spf = {"spf_record": "v=spf1 -all", "all_includes": [], "issues": []}
    return AttackScenarioAnalyzer("example.fr", {"issues": [], "mx_results": []}, spf, dmarc, {}, _SERVICES)


@pytest.mark.parametrize("policy,testing,state", [
    ("reject", False, "reject"),
    ("reject", True, "quarantine"),
    ("quarantine", False, "quarantine"),
    ("quarantine", True, "none"),
])
def test_test_mode_lowers_the_effective_policy(policy, testing, state):
    assert _analyzer(policy, testing)._dmarc_state()[0] == state


def test_quarantine_in_test_mode_is_spoofable_from_any_server():
    # t=y on p=quarantine behaves like p=none: the generic direct-spoof scenario fires.
    enforced = [s.scenario_name for s in _analyzer("quarantine", False).analyze()]
    testing = [s.scenario_name for s in _analyzer("quarantine", True).analyze()]
    assert len(testing) > len(enforced)


# --- p=quarantine with t=y / pct=0 behaves like p=none everywhere -------------------

def _dm(policy, testing=False, pct=100):
    return {"policy": policy, "testing": testing, "percentage": pct, "issues": [],
            "dmarc_record": f"v=DMARC1; p={policy}"}


def _names(dmarc, spf):
    a = AttackScenarioAnalyzer("example.fr", {"issues": [], "mx_results": []}, spf, dmarc, {}, _SERVICES)
    return a, a.analyze()


_SOFTFAIL = {"spf_record": "v=spf1 ~all", "all_includes": [], "issues": [{"code": "spf_softfail"}]}


@pytest.mark.parametrize("dmarc", [_dm("quarantine", testing=True), _dm("quarantine", pct=0)])
def test_softfail_monitoring_rule_fires_when_quarantine_is_lowered(dmarc):
    _, scs = _names(dmarc, _SOFTFAIL)
    assert any("DMARC Monitoring Only" in s.scenario_name for s in scs)


def test_softfail_monitoring_rule_not_fired_on_real_quarantine():
    _, scs = _names(_dm("quarantine"), _SOFTFAIL)
    assert not any("DMARC Monitoring Only" in s.scenario_name for s in scs)


@pytest.mark.parametrize("dmarc,fix", [
    (_dm("quarantine", testing=True), "remove t=y"),
    (_dm("quarantine", pct=0), "set pct=100"),
    (_dm("reject", testing=True), "remove t=y"),
])
def test_remediation_says_what_to_remove(dmarc, fix):
    _, scs = _names(dmarc, _SOFTFAIL)
    generic = [s for s in scs if s.attack_type.name in ("SPOOFING_NO_DMARC_ENFORCEMENT", "SPOOFING_AUTH_MISCONFIG")]
    if dmarc["policy"] == "quarantine":
        assert generic
    assert all(fix in s.remediation and "already publishes" in s.remediation for s in generic)


@pytest.mark.parametrize("org_dmarc,enforcing", [
    (_dm("quarantine"), True),
    (_dm("quarantine", testing=True), False),   # applied as p=none
    (_dm("reject", pct=0), True),               # applied as p=quarantine: still enforcing
])
def test_relaxed_alignment_uses_the_parent_effective_policy(org_dmarc, enforcing):
    spf = {"spf_record": "v=spf1 include:_spf.alwaysdata.com -all", "issues": [],
           "all_includes": [{"include": "_spf.alwaysdata.com", "dangerous": True,
                             "service_name": "AlwaysData", "service_type": "Shared Hosting"}]}
    a = AttackScenarioAnalyzer("sub.example.fr", {"issues": [], "mx_results": []}, spf, _dm("reject"), {},
                               _SERVICES, org_domain="example.fr", org_dmarc_result=org_dmarc)
    [sc] = [s for s in a.analyze() if s.attack_type.name == "SPOOFING_RELAXED_ALIGNMENT"]
    assert sc.probability == ("high" if enforcing else "medium")
    if org_dmarc["testing"] or org_dmarc["percentage"] == 0:
        assert "applied as p=" in " ".join(sc.conditions_met)


# --- Affected Domains of the relaxed-alignment scenario -----------------------------

def _xalign(family):
    spf = {"spf_record": "v=spf1 include:_spf.alwaysdata.com -all", "issues": [],
           "all_includes": [{"include": "_spf.alwaysdata.com", "dangerous": True,
                             "service_name": "AlwaysData", "service_type": "Shared Hosting"}]}
    org = {"policy": "reject", "dmarc_record": "v=DMARC1; p=reject"}
    a = AttackScenarioAnalyzer("alwaysdata.spoofin.fr", {"issues": [], "mx_results": []}, spf,
                               {"policy": "reject"}, {}, _SERVICES, org_domain="spoofin.fr",
                               org_dmarc_result=org, org_family=family)
    [sc] = [s for s in a.analyze() if s.attack_type.name == "SPOOFING_RELAXED_ALIGNMENT"]
    return sc


def test_affected_domains_cover_the_whole_namespace():
    sc = _xalign([("ovh.spoofin.fr", {}), ("rejectdmarc.spoofin.fr", {"alignment_spf": "r"})])
    assert sc.affected_domains == ["spoofin.fr", "*.spoofin.fr"]
    text = " ".join(sc.conditions_met)
    assert "Including the 2 audited subdomains: ovh.spoofin.fr, rejectdmarc.spoofin.fr" in text
    assert "Caveat" in text


def test_strict_alignment_subdomain_is_listed_as_an_exception():
    sc = _xalign([("ovh.spoofin.fr", {}),
                  ("strict.spoofin.fr", {"alignment_spf": "s", "alignment_dkim": "s"})])
    assert sc.affected_domains == ["spoofin.fr", "*.spoofin.fr (except strict.spoofin.fr)"]
    assert any(c.startswith("Not spoofable this way") and "strict.spoofin.fr" in c for c in sc.conditions_met)
