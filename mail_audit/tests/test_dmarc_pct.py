"""DMARC pct (RFC 7489 §6.6.4): partial enforcement scenario and pct=0."""

import json
from pathlib import Path

import pytest

from mail_audit.lib import attack_scenarios
from mail_audit.lib.attack_scenarios import AttackScenarioAnalyzer
from mail_audit.lib.models import AttackType

_SERVICES = json.loads(
    (Path(attack_scenarios.__file__).parent / "data" / "email_services.json").read_text(encoding="utf-8")
)["services"]


def _analyzer(policy, pct, testing=False):
    dmarc = {"policy": policy, "percentage": pct, "testing": testing, "issues": []}
    if policy == "none":
        dmarc["issues"] = [{"code": "dmarc_lax_policy"}]
    spf = {"spf_record": "v=spf1 -all", "all_includes": [], "issues": []}
    return AttackScenarioAnalyzer("example.fr", {"issues": [], "mx_results": []}, spf, dmarc, {}, _SERVICES)


def _pct_scenarios(policy, pct, testing=False):
    return [s for s in _analyzer(policy, pct, testing).analyze()
            if s.attack_type == AttackType.SPOOFING_PARTIAL_DMARC]


@pytest.mark.parametrize("pct,likelihood", [
    (1, "very_high"), (10, "very_high"), (11, "high"), (35, "high"), (36, "medium"),
    (50, "medium"), (65, "medium"), (66, "low"), (90, "low"), (91, "very_low"), (99, "very_low"),
])
def test_likelihood_follows_the_pct_range(pct, likelihood):
    [sc] = _pct_scenarios("quarantine", pct)
    assert sc.probability == likelihood


@pytest.mark.parametrize("policy,pct,risk", [
    ("quarantine", 10, "critical"),   # escaped spoofs get p=none: delivered
    ("quarantine", 50, "high"),
    ("quarantine", 90, "moderate"),
    ("reject", 10, "high"),           # escaped spoofs are only quarantined
    ("reject", 50, "moderate"),
    ("reject", 90, "low"),
])
def test_impact_depends_on_what_escaped_spoofs_get(policy, pct, risk):
    [sc] = _pct_scenarios(policy, pct)
    assert sc.risk == risk


def test_texts_are_rendered():
    [sc] = _pct_scenarios("reject", 25)
    text = " ".join([sc.scenario_name, sc.description, *sc.conditions_met, *sc.bypass_notes])
    assert "pct=25" in text and "75%" in text and "p=quarantine" in text
    assert "{" not in text
    assert "98%" in text   # 1 - 0.25^3: at least one of 3 copies escapes


@pytest.mark.parametrize("policy,pct,testing", [
    ("reject", 100, False),    # full enforcement
    ("reject", 0, False),      # pct=0: whole policy lowered instead
    ("none", 10, False),       # nothing enforced: pct changes nothing
    ("reject", 50, True),      # t=y: whole policy lowered instead
])
def test_no_pct_scenario(policy, pct, testing):
    assert _pct_scenarios(policy, pct, testing) == []


@pytest.mark.parametrize("policy,state", [("reject", "quarantine"), ("quarantine", "none")])
def test_pct_zero_lowers_the_whole_policy(policy, state):
    assert _analyzer(policy, 0)._dmarc_state()[0] == state
