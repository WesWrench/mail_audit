"""Open relay bypass profile: SPF authorization of the relay IP x DMARC state."""

import pytest

from mail_audit.lib.attack_scenarios import AttackScenarioAnalyzer, group_mx_scenarios

RELAY_IP = "51.75.24.36"


def _mx(ptr="mail.example.fr"):
    return {
        "hostname": "mail.example.fr",
        "issues": [{"code": "smtp_open_relay"}],
        "smtp": {"target": "mail.example.fr", "tests": {"smtp_reverse_lookup": {
            "server_ip": RELAY_IP, "reverse_dns_host": ptr, "forward_ips_from_ptr": [RELAY_IP]}}},
    }


def _spf(record, ips=(), ranges=(), includes=(), mechanisms=(), issues=()):
    return {
        "spf_record": record,
        "all_ip_addresses": [{"ip": ip} for ip in ips],
        "all_ip_ranges": [{"ip_range": r} for r in ranges],
        "all_includes": [{"include": i} for i in includes],
        "parsed_spf": {"parsed": {"mechanisms": list(mechanisms)}},
        "issues": [{"code": c} for c in issues],
    }


def _relay(spf, dmarc_issues=(), policy="reject", ptr="mail.example.fr", domain="example.fr"):
    analyzer = AttackScenarioAnalyzer(
        domain,
        {"mx_results": [_mx(ptr)]},
        spf,
        {"policy": policy, "issues": [{"code": c} for c in dmarc_issues]},
        {},
        {},
    )
    scenarios = analyzer._analyze_open_relay()
    assert len(scenarios) == 1
    return scenarios[0]


@pytest.mark.parametrize("spf, expected", [
    (_spf("v=spf1 ip4:51.75.24.36 -all", ips=[RELAY_IP]), "pass"),
    (_spf("v=spf1 ip4:51.75.24.0/24 -all", ranges=["51.75.24.0/24"]), "pass"),
    (_spf("v=spf1 mx -all", mechanisms=[{"mechanism": "mx", "value": "", "action": "pass"}]), "pass"),
    (_spf("v=spf1 +all", issues=["spf_pass"]), "pass"),
    (_spf("v=spf1 include:x.net -all", includes=["x.net", "ptr:example.fr"]), "pass"),   # validated PTR
    (_spf("v=spf1 include:mx.ovh.com -all", ranges=["8.33.137.105/32"],
          includes=["mx.ovh.com", "ptr:mail-out.ovh.net"]), "fail"),
    (_spf("v=spf1 include:x.net -all", includes=["x.net", "a:other.net"]), "unknown"),
    ({}, "none"),
])
def test_spf_authorizes_relay_ip(spf, expected):
    analyzer = AttackScenarioAnalyzer("example.fr", {}, spf, {}, {}, {})
    assert analyzer._spf_authorizes(RELAY_IP, "mail.example.fr") == expected


def test_relay_in_spf_is_a_direct_bypass():
    sc = _relay(_spf("v=spf1 ip4:51.75.24.36 -all", ips=[RELAY_IP]))
    assert sc.bypasses == ["SPF", "DMARC"]
    assert sc.conditional_bypasses == ["DKIM"]
    assert sc.attack_vectors[0].likelihood == "very_high"
    assert "direct SPF/DMARC bypass" in sc.scenario_name
    assert any("OpenDKIM" in n for n in sc.bypass_notes)


def test_relay_not_in_spf_dmarc_enforced_needs_dkim_signing():
    sc = _relay(_spf("v=spf1 ip4:1.2.3.4 -all", ips=["1.2.3.4"]), policy="reject")
    assert sc.bypasses == []
    assert sc.conditional_bypasses == ["DKIM", "DMARC"]
    assert sc.attack_vectors[0].likelihood == "low"


def test_relay_not_in_spf_dmarc_none():
    sc = _relay(_spf("v=spf1 ip4:1.2.3.4 -all", ips=["1.2.3.4"]), dmarc_issues=["dmarc_lax_policy"])
    assert sc.bypasses == []
    assert sc.conditional_bypasses == ["DKIM", "DMARC"]
    assert (sc.attack_vectors[0].impact, sc.attack_vectors[0].likelihood) == ("high", "high")


def test_relay_in_spf_without_dmarc_lists_no_dmarc_bypass():
    sc = _relay(_spf("v=spf1 ip4:51.75.24.36 -all", ips=[RELAY_IP]), dmarc_issues=["no_dmarc"])
    assert sc.bypasses == ["SPF"]
    assert any(n.startswith("DMARC: absent") for n in sc.bypass_notes)



def test_relay_cases_stay_separate_rows_per_mx():
    direct = _relay(_spf("v=spf1 ip4:51.75.24.36 -all", ips=[RELAY_IP]), domain="a.example.fr")
    other = _relay(_spf("v=spf1 ip4:1.2.3.4 -all", ips=["1.2.3.4"]), domain="b.example.fr")
    same = _relay(_spf("v=spf1 ip4:51.75.24.36 -all", ips=[RELAY_IP]), domain="c.example.fr")
    for sc in (direct, other, same):     # risk / probability are set by analyze(); mimic it
        sc.probability = sc.attack_vectors[0].likelihood
        sc.risk = {"very_high": "critical", "low": "moderate"}[sc.probability]

    rows = group_mx_scenarios([direct, other, same])

    assert sorted(r.affected_domains for r in rows) == [["a.example.fr", "c.example.fr"], ["b.example.fr"]]


def test_grouped_open_relay_vector_keeps_port_25_server_to_server():
    # The group rebuild must preserve the vector's transport fields (regression:
    # the Attack Modes column dropped the port after grouping).
    direct = _relay(_spf("v=spf1 ip4:51.75.24.36 -all", ips=[RELAY_IP]), domain="a.example.fr")
    assert (direct.attack_vectors[0].port, direct.attack_vectors[0].transport) == ("25", "server_to_server")
    direct.probability = direct.attack_vectors[0].likelihood
    direct.risk = "critical"
    [row] = group_mx_scenarios([direct])
    vec = row.attack_vectors[0]
    assert (vec.vector_type, vec.auth_mode, vec.port, vec.transport) == (
        "smtp_server", "none", "25", "server_to_server")
