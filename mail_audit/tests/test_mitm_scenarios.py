"""MITM scenarios: which certificate attack applies, and when DANE lowers the downgrade."""

from mail_audit.lib.attack_scenarios import AttackScenarioAnalyzer


def _analyzer(mta_sts_issue=None, mx_issues=(), dane_valid=False, dane_usable=False):
    smtp = {
        "issues": [{"code": mta_sts_issue}] if mta_sts_issue else [],
        "mta_sts": {"policy": {"mode": "testing"}} if mta_sts_issue == "mta_sts_non_enforce" else {},
        "mx_results": [{
            "hostname": "mail.example.fr",
            "issues": [{"code": c} for c in mx_issues],
            "smtp": {"tests": {}},
            "dane": {"dane_valid": dane_valid, "dane_usable": dane_usable},
        }],
    }
    return AttackScenarioAnalyzer("example.fr", smtp, {}, {}, {}, {})


def test_no_mta_sts_no_dane_any_attacker_certificate_works():
    a = _analyzer("mta_sts_missing", ["dane_no_tlsa"])
    [cert] = a._check_dane_fake_cert()
    assert "no certificate validation required" in cert.scenario_name
    assert cert.attack_vectors[0].likelihood == "medium"
    assert cert.service_name == "SMTP (TCP 25)"
    assert any(c.startswith("Assumed (not tested)") for c in cert.conditions_met)


def test_mta_sts_enforce_needs_a_fraudulent_ca_certificate():
    a = _analyzer(None, ["dane_no_tlsa"])
    assert a._check_ssl_stripping() == []
    [cert] = a._check_dane_fake_cert()
    assert "Fraudulent CA-Issued Certificate" in cert.scenario_name
    assert cert.attack_vectors[0].likelihood == "low"


def test_usable_dane_removes_certificate_attack_and_lowers_downgrade():
    a = _analyzer("mta_sts_missing", dane_valid=True, dane_usable=True)
    assert a._check_dane_fake_cert() == []
    [strip] = a._check_ssl_stripping()
    assert strip.attack_vectors[0].likelihood == "low"
    assert any("DANE usable" in c for c in strip.conditions_met)


def test_tlsa_without_dnssec_is_not_usable_dane():
    a = _analyzer("mta_sts_missing", ["tlsa_no_dnssec"], dane_valid=True, dane_usable=False)
    [cert] = a._check_dane_fake_cert()
    assert "not DNSSEC-validated" in cert.conditions_met[1]
    [tlsa] = a._check_tlsa_without_dnssec()
    assert "DANE ignored" in tlsa.scenario_name


# README "MITM Attacks" matrix: (MTA-STS, DANE) -> {scenario name prefix: (probability, risk level)}
_STRIP, _CERT, _CA, _TLSA = ("STARTTLS Downgrade", "TLS Interception with an Attacker Certificate",
                             "Fraudulent CA-Issued Certificate", "TLSA Records Without DNSSEC")
_MATRIX = {
    ("absent", "no_tlsa"):    {_STRIP: ("medium", "high"), _CERT: ("medium", "high")},
    ("absent", "no_dnssec"):  {_STRIP: ("medium", "high"), _CERT: ("medium", "high"), _TLSA: ("medium", "high")},
    ("absent", "usable"):     {_STRIP: ("low", "moderate")},
    ("testing", "no_tlsa"):   {_STRIP: ("medium", "high"), _CERT: ("medium", "high")},
    ("testing", "no_dnssec"): {_STRIP: ("medium", "high"), _CERT: ("medium", "high"), _TLSA: ("medium", "high")},
    ("testing", "usable"):    {_STRIP: ("low", "moderate")},
    ("enforce", "no_tlsa"):   {_CA: ("low", "moderate")},
    ("enforce", "no_dnssec"): {_CA: ("low", "moderate"), _TLSA: ("low", "moderate")},
    ("enforce", "usable"):    {},
}
_STS = {"absent": "mta_sts_missing", "testing": "mta_sts_non_enforce", "enforce": None}
_DANE = {"no_tlsa": (["dane_no_tlsa"], False, False), "no_dnssec": (["tlsa_no_dnssec"], True, False),
         "usable": ([], True, True)}


def test_probability_matrix():
    for (sts, dane), expected in _MATRIX.items():
        issues, valid, usable = _DANE[dane]
        a = _analyzer(_STS[sts], issues, dane_valid=valid, dane_usable=usable)
        got = {}
        for sc in a.analyze():
            if sc.attack_category.value == "MITM":
                prefix = next(p for p in (_STRIP, _CERT, _CA, _TLSA) if sc.scenario_name.startswith(p))
                got[prefix] = (sc.probability, sc.risk)
        assert got == expected, (sts, dane, got)
