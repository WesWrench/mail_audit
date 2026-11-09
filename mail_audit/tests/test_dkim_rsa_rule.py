"""The DKIM key scenario only follows the RSA issue code."""

from mail_audit.lib.attack_scenarios import AttackScenarioAnalyzer


def _names(code):
    dkim = {"issues": [{"code": code}], "selectors_found": []}
    a = AttackScenarioAnalyzer("example.fr", {"issues": [], "mx_results": []}, {}, {"policy": "reject"}, dkim, {})
    return [s.scenario_name for s in a.analyze()]


def test_weak_rsa_key_triggers_the_factoring_scenario():
    assert any(n.startswith("Weak DKIM RSA key") for n in _names("dkim_rsa_weak_key"))


def test_syntax_error_does_not_trigger_the_factoring_scenario():
    assert not any(n.startswith("Weak DKIM RSA key") for n in _names("dkim_syntax_error"))
