"""DKIM key type handling: k= is read first, RSA size thresholds apply to RSA keys only."""

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from lib.checkers.dkim_checker import DKIMChecker
from lib.utils.dns_utils import DNSQueryOutcome, STATUS_NOERROR


def _spki(key):
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


_ED = ed25519.Ed25519PrivateKey.generate().public_key()
_ED_RAW = base64.b64encode(_ED.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
_RSA_512 = rsa.RSAPublicNumbers(65537, (1 << 511) | 1).public_key()
_RSA_1024 = rsa.generate_private_key(65537, 1024).public_key()
_RSA_2048 = rsa.generate_private_key(65537, 2048).public_key()
_P256 = ec.generate_private_key(ec.SECP256R1()).public_key()

# record, expected key_type, expected key_size, expected issue code
CASES = {
    "rsa_512": (f"v=DKIM1; k=rsa; p={_spki(_RSA_512)}", "rsa", 512, "dkim_rsa_weak_key"),
    "rsa_1024": (f"v=DKIM1; k=rsa; p={_spki(_RSA_1024)}", "rsa", 1024, "dkim_rsa_perfectible_key"),
    "rsa_1024_default_k": (f"v=DKIM1; p={_spki(_RSA_1024)}", "rsa", 1024, "dkim_rsa_perfectible_key"),
    "rsa_1024_uppercase_k": (f"v=DKIM1; k=RSA; p={_spki(_RSA_1024)}", "rsa", 1024, "dkim_rsa_perfectible_key"),
    "rsa_2048": (f"v=DKIM1; k=rsa; p={_spki(_RSA_2048)}", "rsa", 2048, None),
    "ed25519_raw": (f"v=DKIM1; k=ed25519; p={_ED_RAW}", "ed25519", 256, None),
    "ed25519_der_wrapped": (f"v=DKIM1; k=ed25519; p={_spki(_ED)}", "ed25519", None, "dkim_syntax_error"),
    "ed25519_wrong_length": (f"v=DKIM1; k=ed25519; p={base64.b64encode(bytes(16)).decode()}", "ed25519", None, "dkim_syntax_error"),
    "rsa_under_k_ed25519": (f"v=DKIM1; k=ed25519; p={_spki(_RSA_1024)}", "ed25519", None, "dkim_syntax_error"),
    "raw_ed25519_without_k": (f"v=DKIM1; p={_ED_RAW}", "rsa", None, "dkim_syntax_error"),
    "der_ed25519_under_k_rsa": (f"v=DKIM1; k=rsa; p={_spki(_ED)}", "rsa", None, "dkim_syntax_error"),
    "ec_key": (f"v=DKIM1; k=rsa; p={_spki(_P256)}", "rsa", None, "dkim_syntax_error"),
    "ec_key_default_k": (f"v=DKIM1; p={_spki(_P256)}", "rsa", None, "dkim_syntax_error"),
    "unknown_k": (f"v=DKIM1; k=foo; p={_spki(_RSA_2048)}", "foo", None, "dkim_syntax_error"),
    "invalid_base64": ("v=DKIM1; k=rsa; p=not*base64", "rsa", None, "dkim_syntax_error"),
    "unreadable_rsa": (f"v=DKIM1; k=rsa; p={base64.b64encode(bytes(64)).decode()}", "rsa", None, "dkim_syntax_error"),
    "revoked": ("v=DKIM1; k=ed25519; p=", "ed25519", None, None),
}


def _scan(record):
    checker = DKIMChecker.__new__(DKIMChecker)
    outcome = DNSQueryOutcome("s1._domainkey.example.com", "TXT", STATUS_NOERROR, [record])
    return checker._check_selector("s1", "example.com", outcome)


def _check_record(record):
    return DKIMChecker.__new__(DKIMChecker)._parse_dkim_record_string(record, "s1")


@pytest.mark.parametrize("read", [_scan, _check_record], ids=["scan", "check_record"])
@pytest.mark.parametrize("case", CASES)
def test_key_type_handling(read, case):
    record, key_type, key_size, code = CASES[case]
    info = read(record)
    assert (info.key_type, info.key_size) == (key_type, key_size)
    assert [i.code for i in info.issues] == ([code] if code else [])


def test_non_key_txt_at_selector_stays_silent_in_scan():
    # A wildcard TXT at a tested selector name is not a key record
    info = _scan("v=spf1 -all")
    assert info.issues == []
    assert info.key_size is None


def test_check_record_still_requires_v_and_p():
    assert [i.code for i in _check_record("k=rsa; p=abc").issues] == ["dkim_syntax_error"]
    assert [i.code for i in _check_record("v=DKIM1; k=rsa").issues] == ["dkim_syntax_error"]
