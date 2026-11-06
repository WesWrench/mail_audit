"""AlwaysData shared hosting (test 2026-10-30): two modes, Critical, DKIM note mentions R_DKIM_NA. OVH stays Low."""

import json
from pathlib import Path

from mail_audit.lib import attack_scenarios
from mail_audit.lib.attack_scenarios import AttackScenarioAnalyzer

_SERVICES = json.loads(
    (Path(attack_scenarios.__file__).parent / "data" / "email_services.json").read_text(encoding="utf-8")
)["services"]


def _scenario(service):
    spf = {"all_includes": [{"dangerous": True, "service_name": service}], "issues": []}
    dmarc = {"policy": "reject", "issues": []}
    a = AttackScenarioAnalyzer("example.fr", {"issues": [], "mx_results": []}, spf, dmarc, {}, _SERVICES)
    return next(s for s in a.analyze() if s.service_name == service)


def test_alwaysdata_is_critical_with_both_modes_confirmed():
    sc = _scenario("AlwaysData")
    assert sc.risk == "critical"
    vectors = {v.vector_type: v for v in sc.attack_vectors}
    assert {"local_script", "smtp_server"} <= set(vectors)
    assert all((v.status.value or "").lower() == "confirmed" for v in vectors.values())


def test_confirmed_smtp_server_scores_high_critical_like_local_mta():
    vectors = {v.vector_type: v for v in _scenario("AlwaysData").attack_vectors}
    # A confirmed vector is rated High / Critical, not its generic Medium default.
    assert (vectors["smtp_server"].likelihood, vectors["smtp_server"].risk) == ("high", "critical")
    assert (vectors["local_script"].likelihood, vectors["local_script"].risk) == ("high", "critical")


def test_smtp_transport_is_submission_587_465():
    vectors = {v.vector_type: v for v in _scenario("AlwaysData").attack_vectors}
    assert (vectors["smtp_server"].port, vectors["smtp_server"].transport) == ("587/465", "client_to_server")
    assert vectors["local_script"].transport == "local_submission"


def test_alwaysdata_dkim_note_explains_the_r_dkim_na_point():
    notes = " ".join(_scenario("AlwaysData").bypass_notes)
    assert "DKIM" in " ".join(_scenario("AlwaysData").conditional_bypasses)
    assert "R_DKIM_NA" in notes
    assert "alwaysdata.net:s=default" in notes


def test_ovh_shared_hosting_stays_low():
    assert _scenario("OVH").risk == "low"


def test_shared_smtp_server_is_marked_on_the_vector():
    for service in ("AlwaysData", "OVH"):
        vectors = {v["vector_type"]: v for v in _SERVICES[service]["attack_vectors"]}
        assert vectors["smtp_server"].get("shared") is True, service
        assert "shared" not in vectors["local_script"]
