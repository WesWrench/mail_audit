"""
DNSSEC chain validation, DANE SMTP, and MTA-STS verification.

Functions in this module are independent of SMTPChecker and can be used
standalone or via DomainChecker.
"""
import hashlib
import smtplib
import ssl
import threading
from typing import Any, Optional

import checkdmarc.dnssec
import checkdmarc.mta_sts
import checkdmarc.smtp
import dns.dnssec
import dns.exception
import dns.flags
import dns.name
import dns.rdatatype
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# DNSSEC trust anchors
# ---------------------------------------------------------------------------

# Key tags of the ICANN root zone KSK trust anchors (RFC 7958).
# 19036 = KSK-2010 (retired 2018, kept for legacy resolvers)
# 20326 = KSK-2017 (current)
_ROOT_TRUST_ANCHOR_TAGS: frozenset[int] = frozenset({19036, 20326})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_resolver(
    nameservers: Optional[list[str]] = None,
    timeout: float = 5.0,
) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


def _normalize(name: str) -> str:
    return str(name).rstrip(".")


def _dns_resolve(
    resolver: "dns.resolver.Resolver",
    name: str,
    rdtype: str,
    sem: Optional[threading.Semaphore] = None,
) -> Any:
    """Wrapper around resolver.resolve() that acquires *sem* before querying."""
    if sem is not None:
        with sem:
            return resolver.resolve(name, rdtype)
    return resolver.resolve(name, rdtype)


def _extract_rrsig_covering(response: Any, rdtype: int) -> Optional[Any]:
    """
    Extract the RRSIG RRset that covers *rdtype* from a DNS response's answer
    section.  Returns the first matching RRset, or None if absent.

    When a resolver is queried with DO=1 it includes the RRSIG(s) for the
    requested RRset in the answer section alongside the records themselves.
    """
    for rrset in getattr(response, "answer", []):
        if rrset.rdtype == dns.rdatatype.RRSIG:
            for rdata in rrset:
                if getattr(rdata, "type_covered", None) == rdtype:
                    return rrset
    return None


def _as_plain(obj: Any) -> Any:
    """Recursively convert checkdmarc pydantic/dataclass objects to plain dicts."""
    if obj is None:
        return None
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    if isinstance(obj, list):
        return [_as_plain(x) for x in obj]
    if isinstance(obj, tuple):
        return [_as_plain(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _as_plain(v) for k, v in obj.items()}
    return obj


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def resolve_records(
    name: str,
    rdtype: str,
    *,
    nameservers: Optional[list[str]] = None,
    timeout: float = 5.0,
    _dns_sem: Optional[threading.Semaphore] = None,
) -> dict[str, Any]:
    """
    Resolve DNS records of a given type.
    Returns a dict with keys: name, type, records, resolvable, error.

    :param _dns_sem: Optional threading.Semaphore to limit concurrent DNS queries.
    """
    resolver = _make_resolver(nameservers=nameservers, timeout=timeout)
    result: dict[str, Any] = {
        "name": _normalize(name),
        "type": rdtype,
        "records": [],
        "resolvable": False,
        "error": None,
    }
    try:
        answers = _dns_resolve(resolver, name, rdtype, _dns_sem)
        result["records"] = [r.to_text().strip('"') for r in answers]
        result["resolvable"] = len(result["records"]) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
        result["error"] = e.__class__.__name__
    except dns.exception.DNSException as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# DNSSEC chain validation
# ---------------------------------------------------------------------------

def _build_zone_chain(zone: str) -> list[str]:
    """
    Return the list of DNS zones from root to *zone*, each with a trailing dot.

    Examples::
        "flex-led.com"  → [".", "com.", "flex-led.com."]
        "com"           → [".", "com."]
        "."             → ["."]
    """
    normalized = zone.rstrip(".")
    if not normalized:
        return ["."]
    parts = normalized.split(".")
    chain: list[str] = ["."]
    for i in range(len(parts) - 1, -1, -1):
        chain.append(".".join(parts[i:]) + ".")
    return chain


def check_dnssec_chain(
    name: str,
    *,
    nameservers: Optional[list[str]] = None,
    timeout: float = 5.0,
    _dns_sem: Optional[threading.Semaphore] = None,
) -> dict[str, Any]:
    """
    Validate the DNSSEC chain for a DNS name.

    Two-stage strategy:

    1. **AD bit** (primary) — query the zone's DNSKEY with the DNSSEC-OK
       (DO) flag set.  A validating recursive resolver (e.g. 1.1.1.1, 8.8.8.8)
       sets the AD (Authenticated Data) bit in the response when it has already
       verified the full cryptographic chain all the way to the ICANN root
       trust anchor.  If AD is set, ``dnssec_valid`` is immediately True.

    2. **Chain walk** (fallback) — full cryptographic validation without
       trusting the resolver.  Walk every zone level from the root (".") down
       to the target zone.  At each hop two checks are performed:

       * **DS ↔ DNSKEY hash** — recompute ``dns.dnssec.make_ds()`` for every
         (DS record, DNSKEY) pair and verify that key_tag, algorithm,
         digest_type, and digest all match the DS record published in the
         parent zone.  This validates the key delegation chain.

       * **RRSIG over the DNSKEY RRSet** — call ``dns.dnssec.validate()`` to
         cryptographically verify the RRSIG signature covering the DNSKEY
         RRSet at that zone level.  The KSK self-signs the DNSKEY RRSet; this
         confirms the RRSet has not been tampered with.  At the root, the
         signing key is bootstrapped by matching key-tags 19036 / 20326
         (RFC 7958 trust anchors) before verifying the self-signature.

    Returns a dict with keys:
        name, zone, dnskey_present, ds_present, ds_dnskey_match,
        dnssec_valid, matched_ds, validation_method, error
    """
    result: dict[str, Any] = {
        "name": _normalize(name),
        "zone": None,
        "dnskey_present": False,
        "ds_present": False,
        "ds_dnskey_match": False,
        "dnssec_valid": False,
        "matched_ds": None,
        "validation_method": None,  # "ad_bit" | "chain_walk"
        "error": None,
    }

    resolver = _make_resolver(nameservers=nameservers, timeout=timeout)
    # DO flag: ask the resolver to include DNSSEC records and set AD when valid.
    resolver.use_edns(ednsflags=dns.flags.DO)

    # ── Determine authoritative zone via SOA walk ─────────────────────────
    try:
        zone_obj = dns.resolver.zone_for_name(name, resolver=resolver)
        zone_str = _normalize(str(zone_obj))
    except Exception as e:
        result["error"] = f"Cannot determine authoritative zone: {e}"
        return result

    result["zone"] = zone_str

    # ── Query DNSKEY (presence check + capture response for AD bit) ───────
    try:
        dnskey_answer = _dns_resolve(resolver, zone_str, "DNSKEY", _dns_sem)
        dnskeys = list(dnskey_answer)
    except Exception:
        dnskeys = []

    result["dnskey_present"] = len(dnskeys) > 0
    if not dnskeys:
        return result

    # ── Primary: AD bit ───────────────────────────────────────────────────
    try:
        ad_set = bool(dnskey_answer.response.flags & dns.flags.AD)
    except Exception:
        ad_set = False

    if ad_set:
        # The validating resolver confirmed the full chain to the root anchor.
        result["dnssec_valid"] = True
        result["ds_present"] = True
        result["ds_dnskey_match"] = True
        result["validation_method"] = "ad_bit"
        return result

    # ── Fallback: full cryptographic chain walk ───────────────────────────
    chain = _build_zone_chain(zone_str)

    for zone_level in chain:
        # Use bare name for resolver ("com." → "com", "." stays ".")
        query_name = zone_level if zone_level == "." else zone_level.rstrip(".")
        is_target = (zone_level.rstrip(".") == zone_str)
        zone_name_obj = (
            dns.name.root if zone_level == "." else dns.name.from_text(zone_level)
        )

        # Fetch DNSKEY RRSet — keep the full answer to extract RRSIG from response
        try:
            level_answer = _dns_resolve(resolver, query_name, "DNSKEY", _dns_sem)
            level_dnskeys = list(level_answer)
            level_dnskey_rrset = level_answer.rrset
        except Exception as e:
            result["error"] = f"Cannot get DNSKEY for {zone_level}: {e}"
            return result

        if not level_dnskeys:
            result["error"] = f"No DNSKEY records for {zone_level}"
            return result

        # Extract RRSIG covering the DNSKEY RRSet from the response.
        # With DO=1 the authoritative server includes it in the answer section.
        rrsig_rrset = _extract_rrsig_covering(level_answer.response, dns.rdatatype.DNSKEY)
        if rrsig_rrset is None:
            result["error"] = (
                f"No RRSIG for DNSKEY RRSet at {zone_level} — "
                "zone is not fully signed or resolver stripped DNSSEC records"
            )
            return result

        if zone_level == ".":
            # Root zone: bootstrap trust via hardcoded key-tag anchors.
            # Use make_ds() to reliably extract the key_tag.
            key_tags: set[int] = set()
            for k in level_dnskeys:
                try:
                    key_tags.add(dns.dnssec.make_ds(dns.name.root, k, 2).key_tag)
                except Exception:
                    pass
            if not (key_tags & _ROOT_TRUST_ANCHOR_TAGS):
                result["error"] = (
                    f"Root DNSKEY key tags {sorted(key_tags)} do not match "
                    f"known trust anchors {sorted(_ROOT_TRUST_ANCHOR_TAGS)}"
                )
                return result

            # Verify RRSIG over root DNSKEY RRSet.
            # The root KSK self-signs the DNSKEY RRSet — we use the full RRSet
            # as the keys dict; dns.dnssec.validate() will pick the right key.
            try:
                dns.dnssec.validate(
                    level_dnskey_rrset,
                    rrsig_rrset,
                    {dns.name.root: level_dnskey_rrset},
                )
            except Exception as e:
                result["error"] = f"Root DNSKEY RRSIG validation failed: {e}"
                return result

            continue  # root has no parent DS — proceed to next level

        # Non-root: DS (stored in parent zone) must match a child DNSKEY.
        try:
            ds_records = list(_dns_resolve(resolver, query_name, "DS", _dns_sem))
        except Exception:
            ds_records = []

        if is_target:
            result["ds_present"] = len(ds_records) > 0

        if not ds_records:
            result["error"] = f"No DS records found for {zone_level}"
            return result

        # ── Check 1: DS ↔ DNSKEY hash ────────────────────────────────────
        matched = False
        matched_info: Optional[dict] = None
        for ds in ds_records:
            for dnskey in level_dnskeys:
                try:
                    computed = dns.dnssec.make_ds(zone_name_obj, dnskey, ds.digest_type)
                    if (
                        computed.key_tag == ds.key_tag
                        and computed.algorithm == ds.algorithm
                        and computed.digest_type == ds.digest_type
                        and computed.digest == ds.digest
                    ):
                        matched = True
                        matched_info = {
                            "key_tag": ds.key_tag,
                            "algorithm": int(ds.algorithm),
                            "digest_type": int(ds.digest_type),
                            "digest": (
                                ds.digest.hex()
                                if isinstance(ds.digest, bytes)
                                else str(ds.digest)
                            ),
                        }
                        break
                except Exception:
                    continue
            if matched:
                break

        if not matched:
            result["error"] = f"DS↔DNSKEY mismatch at zone {zone_level}"
            return result

        # ── Check 2: RRSIG over DNSKEY RRSet ─────────────────────────────
        # The KSK self-signs the DNSKEY RRSet.  dns.dnssec.validate() verifies
        # the cryptographic signature — this is what was missing before.
        try:
            dns.dnssec.validate(
                level_dnskey_rrset,
                rrsig_rrset,
                {zone_name_obj: level_dnskey_rrset},
            )
        except Exception as e:
            result["error"] = f"DNSKEY RRSIG validation failed at {zone_level}: {e}"
            return result

        if is_target:
            result["ds_dnskey_match"] = True
            result["dnssec_valid"] = True
            result["matched_ds"] = matched_info
            result["validation_method"] = "chain_walk"
            return result

    # Edge case: zone_str is the root itself
    if not zone_str or zone_str == ".":
        result["dnssec_valid"] = True
        result["validation_method"] = "chain_walk"

    return result


# ---------------------------------------------------------------------------
# TLS certificate retrieval
# ---------------------------------------------------------------------------

def fetch_smtp_cert_der(
    hostname: str,
    port: int = 25,
    timeout: float = 10.0,
    verify: bool = False,
) -> bytes:
    """
    Retrieve the TLS certificate presented by an SMTP server after STARTTLS.

    :param hostname: MX hostname.
    :param port: SMTP port (default 25).
    :param timeout: Connection timeout.
    :param verify: If False (default), accept any certificate (CERT_NONE).
                   Set True only for strict validation contexts.
    :raises RuntimeError: If STARTTLS fails or no certificate is returned.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        try:
            import certifi
            ctx.load_verify_locations(certifi.where())
        except ImportError:
            pass  # fall back to the system CA bundle

    with smtplib.SMTP(hostname, port, timeout=timeout) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ctx)
        smtp.ehlo()
        if smtp.sock is None:
            raise RuntimeError("TLS socket unavailable after STARTTLS")
        cert_der = smtp.sock.getpeercert(binary_form=True)
        if not cert_der:
            raise RuntimeError("No certificate returned by server")
        return cert_der


# ---------------------------------------------------------------------------
# TLSA hash computation
# ---------------------------------------------------------------------------

def compute_tlsa_hash(
    cert_der: bytes,
    selector: int,
    matching_type: int,
) -> str:
    """
    Apply TLSA selector + matching_type to compute the expected hash.

    selector:       0 = full DER certificate, 1 = SubjectPublicKeyInfo
    matching_type:  0 = raw hex, 1 = SHA-256, 2 = SHA-512
    """
    cert = x509.load_der_x509_certificate(cert_der)

    if selector == 0:
        data = cert.public_bytes(serialization.Encoding.DER)
    elif selector == 1:
        data = cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        raise ValueError(f"Unsupported TLSA selector: {selector}")

    if matching_type == 0:
        return data.hex()
    if matching_type == 1:
        return hashlib.sha256(data).hexdigest()
    if matching_type == 2:
        return hashlib.sha512(data).hexdigest()
    raise ValueError(f"Unsupported TLSA matching type: {matching_type}")


# ---------------------------------------------------------------------------
# DANE SMTP verification
# ---------------------------------------------------------------------------

def verify_mx_dane(
    hostname: str,
    *,
    domain_dnssec: dict[str, Any],
    nameservers: Optional[list[str]] = None,
    timeout: float = 5.0,
    cert_der: Optional[bytes] = None,
    _dns_sem: Optional[threading.Semaphore] = None,
) -> dict[str, Any]:
    """
    Verify DANE SMTP for an MX hostname.

    Checks:
    - DNSSEC chain on MX hostname zone and TLSA owner zone
    - TLSA records (retrieved via checkdmarc for validation)
    - TLS certificate hash against TLSA records
    - dane_usable: full DNSSEC chain + hash match

    :param hostname: MX hostname (e.g. "bobmail.de-sono.com").
    :param domain_dnssec: DNSSEC result for the parent domain zone
                          (used for dane_usable check on MX record protection).
    :param nameservers: Nameservers to use.
    :param timeout: DNS/SMTP timeout.
    :param cert_der: Pre-fetched certificate DER bytes (from SMTPChecker).
                     If None, a fresh SMTP connection is made.
    """
    if nameservers is None:
        nameservers = ["1.1.1.1", "8.8.8.8"]

    tlsa_owner = f"_25._tcp.{hostname}"

    # Compute DNSSEC chains once — reused in both mx_dnssec and address_lookup.
    _mx_dnssec = check_dnssec_chain(hostname, nameservers=nameservers, timeout=timeout, _dns_sem=_dns_sem)
    _tlsa_dnssec = check_dnssec_chain(tlsa_owner, nameservers=nameservers, timeout=timeout, _dns_sem=_dns_sem)

    result: dict[str, Any] = {
        "hostname": hostname,
        "mx_dnssec": _mx_dnssec,
        "address_lookup": {
            "hostname": hostname,
            "dnssec": _mx_dnssec,   # same chain — no redundant query
            "A": resolve_records(hostname, "A", nameservers=nameservers, timeout=timeout, _dns_sem=_dns_sem),
            "AAAA": resolve_records(hostname, "AAAA", nameservers=nameservers, timeout=timeout, _dns_sem=_dns_sem),
        },
        "tlsa_lookup": {
            "owner": tlsa_owner,
            "dnssec": _tlsa_dnssec,
            "raw_lookup": resolve_records(tlsa_owner, "TLSA", nameservers=nameservers, timeout=timeout, _dns_sem=_dns_sem),
        },
        "tlsa_records_validated": [],
        "certificate_retrieved": cert_der is not None,
        "dane_matches": [],
        "dane_valid": False,
        "dane_usable": False,
        "dane_usable_reason": None,  # populated below when dane_usable is False
        "error": None,
    }

    try:
        # Retrieve TLSA records (validated by checkdmarc)
        try:
            tlsa_records = checkdmarc.dnssec.get_tlsa_records(
                hostname,
                port=25,
                protocol="tcp",
                nameservers=nameservers,
                timeout=timeout,
            )
        except Exception:
            tlsa_records = []

        result["tlsa_records_validated"] = tlsa_records
        if not tlsa_records:
            return result

        # Fetch cert if not already provided
        if cert_der is None:
            cert_der = fetch_smtp_cert_der(hostname, port=25, timeout=max(timeout, 10.0))
            result["certificate_retrieved"] = True

        # Match each TLSA record against the cert
        matches = []
        for raw in tlsa_records:
            parts = raw.strip().split()
            if len(parts) != 4:
                matches.append({"record": raw, "match": False, "error": "Unexpected TLSA format"})
                continue

            usage, selector, matching_type, tlsa_hex = int(parts[0]), int(parts[1]), int(parts[2]), parts[3]
            try:
                computed = compute_tlsa_hash(cert_der, selector, matching_type)
                match = computed.lower() == tlsa_hex.lower()
                matches.append({
                    "record": raw,
                    "usage": usage,
                    "selector": selector,
                    "matching_type": matching_type,
                    "expected": tlsa_hex.lower(),
                    "computed": computed.lower(),
                    "match": match,
                })
            except ValueError as e:
                matches.append({"record": raw, "match": False, "error": str(e)})

        result["dane_matches"] = matches
        result["dane_valid"] = any(m.get("match") for m in matches)

        # dane_usable requires the full DNSSEC chain to be valid:
        # 1. Parent domain zone DNSSEC (MX record is protected)
        # 2. MX hostname zone DNSSEC (A/AAAA records are protected)
        # 3. TLSA owner zone DNSSEC (TLSA record is protected)
        # 4. At least one TLSA record retrieved
        # 5. At least one hash match
        result["dane_usable"] = bool(
            domain_dnssec.get("dnssec_valid")
            and result["mx_dnssec"].get("dnssec_valid")
            and result["tlsa_lookup"]["dnssec"].get("dnssec_valid")
            and result["tlsa_records_validated"]
            and result["dane_valid"]
        )

        if not result["dane_usable"]:
            # Identify the first failing condition for a clear diagnosis.
            if "dnssec_valid" not in domain_dnssec:
                # domain_dnssec={} → called from mx_hostname mode; parent unknown.
                result["dane_usable_reason"] = "parent_domain_unknown"
            elif not domain_dnssec.get("dnssec_valid"):
                result["dane_usable_reason"] = "parent_domain_dnssec_invalid"
            elif not result["mx_dnssec"].get("dnssec_valid"):
                result["dane_usable_reason"] = "mx_host_dnssec_invalid"
            elif not result["tlsa_lookup"]["dnssec"].get("dnssec_valid"):
                result["dane_usable_reason"] = "tlsa_dnssec_invalid"
            elif not result["tlsa_records_validated"]:
                result["dane_usable_reason"] = "no_tlsa_records"
            elif not result["dane_valid"]:
                result["dane_usable_reason"] = "cert_hash_mismatch"

    except Exception as e:
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# MX hostname resolution
# ---------------------------------------------------------------------------

def get_mx_hostnames(
    domain: str,
    *,
    nameservers: Optional[list[str]] = None,
    timeout: float = 5.0,
    timeout_retries: int = 2,
) -> list[str]:
    """
    Return the list of MX hostnames for a domain, ordered by preference.
    Uses checkdmarc.smtp.get_mx_hosts with skip_tls=True.
    """
    mx_result = checkdmarc.smtp.get_mx_hosts(
        domain,
        nameservers=nameservers,
        timeout=timeout,
        timeout_retries=timeout_retries,
        skip_tls=True,
    )
    data = _as_plain(mx_result)

    hosts: list = (
        data.get("hosts", []) if isinstance(data, dict)
        else data if isinstance(data, list)
        else []
    )

    hostnames = []
    for item in hosts:
        if isinstance(item, dict):
            hostname = item.get("hostname") or item.get("host") or item.get("exchange")
            if hostname:
                hostnames.append(_normalize(str(hostname)))
        elif isinstance(item, str):
            hostnames.append(_normalize(item))

    return hostnames


# ---------------------------------------------------------------------------
# MTA-STS
# ---------------------------------------------------------------------------

def check_mta_sts(
    domain: str,
    *,
    nameservers: Optional[list[str]] = None,
    timeout: float = 5.0,
    timeout_retries: int = 2,
) -> Optional[dict[str, Any]]:
    """
    Check the MTA-STS policy for a domain via checkdmarc.
    Returns None if the check fails entirely.
    """
    try:
        result = checkdmarc.mta_sts.check_mta_sts(
            domain,
            nameservers=nameservers,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )
        return _as_plain(result)
    except Exception:
        return None
