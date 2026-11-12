"""Offline checks of an RSA public key (DKIM p= tag): exponent, small factors, primality.

* :func:`parse_rsa_spki` reads ``(n, e)`` from a DER SubjectPublicKeyInfo
  (rsaEncryption). It does not validate ``e``, unlike ``cryptography`` which refuses to
  load a key with ``e < 3``: that is how an ``e=1`` key can still be rated.
* :func:`rate_exponent` rates the public exponent ``e``.
* :func:`small_prime_factor` / :func:`is_probable_prime` detect a modulus whose private
  key anyone can compute (a small factor, or a prime modulus).
"""
from __future__ import annotations

import random
from typing import List, Optional, Tuple

RSA_ENCRYPTION_OID = bytes.fromhex("2a864886f70d010101")   # 1.2.840.113549.1.1.1

STANDARD_EXPONENT = 65537

# Exponent ratings
EXPONENT_STANDARD = "standard"          # 65537 <= e < 2^256 (NIST SP 800-56B)
EXPONENT_DANGEROUS = "dangerous"        # e = 1 or e = 3
EXPONENT_LEGACY = "legacy"              # 3 < e < 65537, e.g. 17
EXPONENT_INVALID = "invalid"            # e < 3 other than 1, or even
EXPONENT_NON_STANDARD = "non_standard"  # e >= 2^256


# --------------------------------------------------------------------------- DER

def _read_tlv(data: bytes, pos: int) -> Tuple[int, int, int]:
    """Return ``(tag, value_start, value_end)`` of the DER element at *pos*."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise ValueError("truncated DER")
    return tag, pos, end


def parse_rsa_spki(der: bytes) -> Optional[Tuple[int, int]]:
    """``(n, e)`` of an RSA SubjectPublicKeyInfo, or None if *der* is not one."""
    try:
        tag, start, end = _read_tlv(der, 0)                  # SubjectPublicKeyInfo
        if tag != 0x30:
            return None
        tag, a_start, a_end = _read_tlv(der, start)          # AlgorithmIdentifier
        if tag != 0x30:
            return None
        tag, o_start, o_end = _read_tlv(der, a_start)        # algorithm OID
        if tag != 0x06 or der[o_start:o_end] != RSA_ENCRYPTION_OID:
            return None
        tag, b_start, b_end = _read_tlv(der, a_end)          # BIT STRING
        if tag != 0x03 or der[b_start] != 0:
            return None
        tag, k_start, _ = _read_tlv(der, b_start + 1)        # RSAPublicKey
        if tag != 0x30:
            return None
        tag, n_start, n_end = _read_tlv(der, k_start)        # modulus
        if tag != 0x02:
            return None
        tag, e_start, e_end = _read_tlv(der, n_end)          # publicExponent
        if tag != 0x02:
            return None
        n = int.from_bytes(der[n_start:n_end], "big")
        e = int.from_bytes(der[e_start:e_end], "big")
        return (n, e) if n > 0 else None
    except (IndexError, ValueError):
        return None


# ---------------------------------------------------------------------- exponent

def rate_exponent(e: int) -> Tuple[str, str]:
    """Rate an RSA public exponent: ``(rating, reason)``.

    ======================  ============  =====================================================
    e                       rating        why
    ======================  ============  =====================================================
    65537 <= e < 2^256 odd  standard      RFC 8017 / NIST SP 800-56B range; 65537 is the norm
    1                       dangerous     s^1 = s: the padded hash itself is a valid signature
    3                       dangerous     cube-root forgery (Bleichenbacher 2006) on verifiers
                                          that check PKCS#1 v1.5 padding loosely
    3 < e < 65537 odd       legacy        e.g. 17: no practical attack with correct padding,
                                          but outdated and below the NIST minimum
    e < 3, or e even        invalid       no private exponent exists: nothing verifies
    e >= 2^256 odd          non_standard  above the NIST maximum; some verifiers refuse it
    ======================  ============  =====================================================
    """
    if e == 1:
        return EXPONENT_DANGEROUS, (
            "e=1: RSA verification computes s^1 = s, so a 'signature' equal to the padded hash "
            "of any message verifies — no private key is needed")
    if e < 3 or e % 2 == 0:
        return EXPONENT_INVALID, (
            f"e={e} is not a valid RSA public exponent (must be odd and >= 3): no private key "
            "can produce a signature that verifies, so mail signed with this selector fails DKIM")
    if e == 3:
        return EXPONENT_DANGEROUS, (
            "e=3: vulnerable to cube-root signature forgery (Bleichenbacher 2006) on verifiers "
            "that check the PKCS#1 v1.5 padding loosely; modern verifiers are fixed, but e=3 "
            "leaves no margin")
    if e < STANDARD_EXPONENT:
        return EXPONENT_LEGACY, (
            f"e={e}: small non-standard exponent (legacy). No practical attack with correct "
            "padding, but below the NIST SP 800-56B minimum (65537); 65537 is the norm")
    if e >= 2**256:
        return EXPONENT_NON_STANDARD, (
            f"e is {e.bit_length()} bits: above the NIST SP 800-56B maximum (2^256); some "
            "verifiers refuse such keys")
    return EXPONENT_STANDARD, "standard exponent"


# ------------------------------------------------------------------- factoring

def _small_primes(limit: int) -> List[int]:
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i in range(limit) if sieve[i]]


SMALL_PRIME_LIMIT = 1 << 16
_SMALL_PRIMES = _small_primes(SMALL_PRIME_LIMIT)


def small_prime_factor(n: int) -> Optional[int]:
    """Smallest prime factor of *n* below 2^16 (trial division), or None."""
    for p in _SMALL_PRIMES:
        if p >= n:
            return None
        if n % p == 0:
            return p
    return None


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    """Miller-Rabin probable-prime test (error probability <= 4^-rounds)."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES[:50]:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    rng = random.Random(n)   # deterministic per n: reproducible results
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
