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


def _scenario(code):
    dkim = {"issues": [{"code": code}], "selectors_found": []}
    a = AttackScenarioAnalyzer("example.fr", {"issues": [], "mx_results": []}, {}, {"policy": "reject"}, dkim, {})
    return [s for s in a.analyze() if s.attack_type.name == "SPOOFING_DKIM_MISCONFIG"]


def test_known_factorization_is_critical_even_at_p_reject():
    [sc] = _scenario("dkim_rsa_known_factorization")
    assert sc.scenario_name.startswith("DKIM RSA key with a known factorization")
    assert (sc.risk, sc.probability) == ("critical", "very_high")
    assert set(sc.bypasses) == {"DKIM", "DMARC"}


def test_dangerous_exponent_is_a_low_risk_scenario():
    [sc] = _scenario("dkim_rsa_dangerous_exponent")
    assert (sc.risk, sc.probability) == ("low", "very_low")
    assert set(sc.conditional_bypasses) == {"DKIM", "DMARC"}


def test_nonstandard_exponent_has_no_scenario():
    assert _scenario("dkim_rsa_nonstandard_exponent") == []
