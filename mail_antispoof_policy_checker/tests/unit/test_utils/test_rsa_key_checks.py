"""Offline RSA public key checks: DER parsing, exponent rating, small factor, primality."""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from lib.utils.rsa_key_checks import (
    EXPONENT_DANGEROUS, EXPONENT_INVALID, EXPONENT_LEGACY, EXPONENT_NON_STANDARD,
    EXPONENT_STANDARD, is_probable_prime, parse_rsa_spki, rate_exponent, small_prime_factor,
)
from tests.unit.rsa_der import spki

RSA100 = 1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139
M127 = 2**127 - 1   # Mersenne prime
M521 = 2**521 - 1   # Mersenne prime


@pytest.mark.parametrize("e,rating", [
    (65537, EXPONENT_STANDARD),
    (2**255 + 1, EXPONENT_STANDARD),
    (1, EXPONENT_DANGEROUS),
    (3, EXPONENT_DANGEROUS),
    (17, EXPONENT_LEGACY),
    (257, EXPONENT_LEGACY),
    (0, EXPONENT_INVALID),
    (2, EXPONENT_INVALID),
    (65536, EXPONENT_INVALID),
    (2**256 + 1, EXPONENT_NON_STANDARD),
])
def test_rate_exponent(e, rating):
    assert rate_exponent(e)[0] == rating


def test_parse_real_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert parse_rsa_spki(der) == (key.public_numbers().n, 65537)


def test_parse_exponent_that_cryptography_refuses():
    assert parse_rsa_spki(spki(RSA100, 1)) == (RSA100, 1)


@pytest.mark.parametrize("der", [b"", b"\x30\x00", b"\x30\x82\xff\xff", b"garbage"])
def test_parse_rejects_garbage(der):
    assert parse_rsa_spki(der) is None


def test_parse_rejects_non_rsa_key():
    from cryptography.hazmat.primitives.asymmetric import ec
    der = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert parse_rsa_spki(der) is None


def test_small_prime_factor():
    assert small_prime_factor(3 * M521) == 3
    assert small_prime_factor(65521 * M521) == 65521   # largest prime < 2^16
    assert small_prime_factor(RSA100) is None
    assert small_prime_factor(M127 * M521) is None


@pytest.mark.parametrize("n,prime", [
    (M127, True), (M521, True), (RSA100, False), (M127 * M521, False),
    (561, False),   # Carmichael number
    (2, True), (1, False), (0, False),
])
def test_is_probable_prime(n, prime):
    assert is_probable_prime(n) is prime
