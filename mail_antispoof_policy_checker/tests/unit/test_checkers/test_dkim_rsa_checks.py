"""DKIM RSA key checks: public exponent, small factor, prime modulus, factordb lookup."""
import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from lib.checkers.dkim_checker import DKIMChecker
from lib.utils.factordb import FactorDBResult
from tests.unit.rsa_der import dkim_record

M521 = 2**521 - 1
M607 = 2**607 - 1
M1279 = 2**1279 - 1   # Mersenne prime, 1279 bits
RSA100 = 1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139


class FakeFactorDB:
    """Stands in for FactorDBClient: returns a fixed result and records lookups."""

    def __init__(self, result):
        self.result, self.calls = result, []

    def lookup(self, n):
        self.calls.append(n)
        return self.result


def _real_record(e=65537, bits=2048):
    key = rsa.generate_private_key(public_exponent=e, key_size=bits).public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}", key.public_numbers().n


def _check(record, factordb=None):
    checker = DKIMChecker(selector_file="", cname_check=False, factordb=factordb)
    return checker.check_record(record, selector="s1", record_id="example.com")


def _codes(result):
    return sorted(i.code for i in result.issues)


@pytest.fixture(scope="module")
def good_key():
    return _real_record()


def test_standard_key_has_no_finding(good_key):
    r = _check(good_key[0])
    assert _codes(r) == []
    assert r.selectors_found[0].rsa_exponent == 65537


@pytest.mark.parametrize("e,code,severity", [
    (3, "dkim_rsa_dangerous_exponent", "high"),
    (17, "dkim_rsa_nonstandard_exponent", "low"),
])
def test_exponent_rating(good_key, e, code, severity):
    # cryptography only generates e=3 / e=65537 keys: publish the real modulus with e.
    r = _check(dkim_record(good_key[1], e))
    issues = [i for i in r.issues if i.code == code]
    assert len(issues) == 1 and issues[0].severity.value == severity
    assert issues[0].additional_data["exponent"] == str(e)


def test_exponent_one_is_read_although_cryptography_refuses_it(good_key):
    # cryptography will not load e=1; the DER is read directly and rated critical.
    r = _check(dkim_record(good_key[1], 1))
    [issue] = [i for i in r.issues if i.code == "dkim_rsa_dangerous_exponent"]
    assert issue.severity.value == "critical"
    assert "dkim_syntax_error" not in _codes(r)


def test_small_factor():
    r = _check(dkim_record(3 * M1279, 65537))
    [issue] = [i for i in r.issues if i.code == "dkim_rsa_known_factorization"]
    assert issue.severity.value == "critical"
    assert issue.additional_data["source"] == "small_factor"


def test_prime_modulus():
    r = _check(dkim_record(M1279, 65537))
    [issue] = [i for i in r.issues if i.code == "dkim_rsa_known_factorization"]
    assert issue.additional_data["source"] == "prime_modulus"


def test_offline_finding_still_queries_factordb_for_its_note():
    # A prime modulus is caught offline; factordb is still read for the context box.
    note = "Interesting number. The second most common 512-bit export DH prime (Logjam)."
    fdb = FakeFactorDB(FactorDBResult(status="P", url="u", notes=[note]))
    r = _check(dkim_record(M1279, 65537), factordb=fdb)
    assert fdb.calls == [M1279]
    [issue] = [i for i in r.issues if i.code == "dkim_rsa_known_factorization"]
    assert issue.additional_data["source"] == "prime_modulus"   # the offline source wins
    assert issue.additional_data["factordb"]["notes"] == [note]
    assert note in issue.detail
    assert r.selectors_found[0].to_dict()["factordb"]["notes"] == [note]


def test_factordb_known_factor():
    n = M521 * M607
    fdb = FakeFactorDB(FactorDBResult(status="FF", url="https://factordb.com/index.php?query=x",
                                      factors=[M521, M607]))
    r = _check(dkim_record(n, 65537), factordb=fdb)
    assert fdb.calls == [n]
    [issue] = [i for i in r.issues if i.code == "dkim_rsa_known_factorization"]
    assert issue.additional_data["source"] == "factordb"
    assert issue.additional_data["factordb"]["status"] == "FF"
    assert r.selectors_found[0].factordb["url"].startswith("https://factordb.com/")


@pytest.mark.parametrize("status", ["C", "U", "error", "skipped"])
def test_factordb_without_known_factor(good_key, status):
    fdb = FakeFactorDB(FactorDBResult(status=status, url="u"))
    r = _check(good_key[0], factordb=fdb)
    assert _codes(r) == []
    assert r.selectors_found[0].factordb["status"] == status


def test_no_factordb_client_means_no_lookup(good_key):
    r = _check(good_key[0])
    assert r.selectors_found[0].factordb is None
    assert "factordb" not in r.selectors_found[0].to_dict()


def test_weak_key_size_and_known_factorization_both_reported():
    fdb = FakeFactorDB(FactorDBResult(status="FF", url="u",
                                      factors=[37975227936943673922808872755445627854565536638199]))
    r = _check(dkim_record(RSA100, 65537), factordb=fdb)
    assert {"dkim_rsa_weak_key", "dkim_rsa_known_factorization"} <= set(_codes(r))


def test_to_dict_exposes_exponent(good_key):
    d = _check(good_key[0]).selectors_found[0].to_dict()
    assert d["rsa_exponent"] == "65537"
