"""SendGrid web UI spoofing: probability, impact and risk level per DMARC policy (test 2026-10-30)."""

import json
from pathlib import Path

import pytest

from mail_audit.lib import attack_scenarios
from mail_audit.lib.attack_scenarios import AttackScenarioAnalyzer

_SERVICES = json.loads(
    (Path(attack_scenarios.__file__).parent / "data" / "email_services.json").read_text(encoding="utf-8")
)["services"]


def _scenario(policy):
    dmarc = {"policy": policy, "issues": []}
    if policy == "none":
        dmarc["issues"] = [{"code": "dmarc_lax_policy"}]
    elif policy is None:
        dmarc["issues"] = [{"code": "no_dmarc"}]
    spf = {"all_includes": [{"dangerous": True, "service_name": "SendGrid"}], "issues": []}
    a = AttackScenarioAnalyzer("example.fr", {"issues": [], "mx_results": []}, spf, dmarc, {}, _SERVICES)
    [sc] = [s for s in a.analyze() if s.service_name == "SendGrid"]
    return sc


@pytest.mark.parametrize("policy,probability,impact,risk", [
    ("none", "medium", "medium", "moderate"),
    (None, "medium", "medium", "moderate"),
    ("quarantine", "medium", "low", "low"),
    ("reject", "low", "medium", "low"),
])
def test_levels_follow_the_dmarc_policy(policy, probability, impact, risk):
    sc = _scenario(policy)
    web_ui = next(v for v in sc.attack_vectors if v.vector_type == "web_ui")
    assert (web_ui.likelihood, web_ui.impact, web_ui.risk) == (probability, impact, risk)
    assert (sc.probability, sc.risk) == (probability, risk)


def test_conditions_show_the_measure_of_the_policy_only():
    conditions = " ".join(_scenario("quarantine").conditions_met)
    assert "7.30/11" in conditions
    assert "9.80/11" not in conditions and "1.70/11" not in conditions


def test_remediation_does_not_ask_a_reject_domain_to_enforce_reject():
    assert "Enforce DMARC" not in _scenario("reject").remediation
    assert "Move DMARC to p=reject" in _scenario("quarantine").remediation
    assert "Enforce DMARC" in _scenario("none").remediation
