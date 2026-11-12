"""Build RSA SubjectPublicKeyInfo DER for tests, with any (n, e) — including values
that ``cryptography`` refuses to serialise (e=1, prime modulus...)."""
import base64


def _len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _int(v: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
    return b"\x02" + _len(len(b)) + b


def _seq(body: bytes) -> bytes:
    return b"\x30" + _len(len(body)) + body


def spki(n: int, e: int) -> bytes:
    """DER SubjectPublicKeyInfo (rsaEncryption) for (n, e)."""
    algorithm = _seq(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00")
    key = _seq(_int(n) + _int(e))
    return _seq(algorithm + b"\x03" + _len(len(key) + 1) + b"\x00" + key)


def dkim_record(n: int, e: int) -> str:
    """DKIM TXT record publishing (n, e)."""
    return f"v=DKIM1; k=rsa; p={base64.b64encode(spki(n, e)).decode()}"
