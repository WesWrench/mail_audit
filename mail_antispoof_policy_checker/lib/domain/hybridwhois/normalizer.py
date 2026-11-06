"""
Format converters and result merger for HybridWhois.

Provides:
  - rdap_domain_to_normalized()  — RDAP parsed domain dict → whoisitlegacy format
  - whois_domain_to_normalized() — whoisitlegacy domain result → normalized format
  - merge_normalized()           — fill gaps in primary result from secondary
  - is_incomplete()              — decide whether a fallback is warranted
  - check_required_fields()     — check if required field groups are satisfied
  - needs_fallback()            — combined completeness + required-field check
"""

from __future__ import annotations
from typing import Any
import json as _json
import os as _os
import re as _re
from urllib.parse import urlsplit as _urlsplit


# ---------------------------------------------------------------------------
# Per-endpoint RDAP availability signals
# ---------------------------------------------------------------------------

_SIGNALS_PATH = _os.path.join(
    _os.path.dirname(__file__), "..", "whoisit", "data", "rdap_available_signals.json"
)
_signals_cache: dict | None = None


def _get_rdap_signals() -> dict:
    global _signals_cache
    if _signals_cache is None:
        try:
            with open(_SIGNALS_PATH, encoding="utf-8") as _f:
                _signals_cache = _json.load(_f).get("endpoints", {})
        except Exception:
            _signals_cache = {}
    return _signals_cache


def _resolve_signal_path(path: list[str], r: dict):
    """
    Walk a JSON-path list into the RDAP response dict.

    If any intermediate value is a list, the remaining path is applied to
    every element and results are collected into a flat list.
    Returns a scalar, a list of scalars, or None.
    """
    current = r
    for key in path:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, list):
            # Descend into each element and flatten results
            results = []
            for item in current:
                if isinstance(item, dict):
                    v = item.get(key)
                    if v is not None:
                        if isinstance(v, list):
                            results.extend(v)
                        else:
                            results.append(v)
            current = results if results else None
        else:
            return None
    return current


def _eval_signal_condition(cond: dict, r: dict, http_status: int | None) -> bool:
    field = cond.get("field")
    op    = cond.get("op", "eq")
    value = cond.get("value")

    # Special computed/meta fields (string, not a path list)
    if field == "http_status":
        actual = http_status
    elif field == "body_empty":
        has_content = any(
            r.get(k)
            for k in ("errorCode", "error_code", "title", "errors",
                      "objectClassName", "status", "notices")
        )
        actual = not has_content
    elif isinstance(field, list):
        actual = _resolve_signal_path(field, r)
    else:
        actual = None

    if op == "eq":
        if isinstance(actual, list):
            return value in actual
        return actual == value
    if op == "regex":
        if isinstance(actual, list):
            return any(bool(_re.search(value, str(v))) for v in actual)
        return bool(_re.search(value, str(actual or ""))) if actual is not None else False
    if op == "contains":
        if isinstance(actual, list):
            return value in actual
        if isinstance(actual, str):
            return value in actual
        return False
    return False


def _check_rdap_endpoint_available(r: dict, http_status: int | None) -> bool | None:
    """
    Check per-endpoint RDAP signals to determine if the domain is available.

    Returns True  if the endpoint's availability conditions all match.
    Returns None  if no signal entry exists for this endpoint or signal is unreliable.
    """
    source = r.get("_rdap_source") or {}
    url = source.get("url") or ""
    if not url:
        return None
    host = _urlsplit(url).netloc
    if not host:
        return None
    signals = _get_rdap_signals()
    ep_data = signals.get(host)
    if not ep_data:
        return None
    conditions = ep_data.get("available_when") or []
    if not conditions:
        return None
    if all(_eval_signal_condition(c, r, http_status) for c in conditions):
        return True
    return None


# ---------------------------------------------------------------------------
# RDAP blocking / reservation detection
# ---------------------------------------------------------------------------

# Notice titles that definitively indicate the domain cannot be registered
_BLOCKING_NOTICE_TITLES: frozenset[str] = frozenset({
    "blocked domain",
    "prohibited string - domain cannot be registered",
    "restricted registration",
    "reserved",
})

# Substrings (in notice title, lower-cased) that also indicate blocking
_BLOCKING_TITLE_SUBSTRINGS: tuple[str, ...] = (
    "globalblock",
    "adultblock",
    "has been blocked",
)

# Substrings in notice *description* (lower-cased) that indicate blocking
_BLOCKING_DESC_PHRASES: tuple[str, ...] = (
    "has been blocked",
    "blocked by a globalblock",
    "blocked by an globalblock",
    "blocked by a adultblock",
    "blocked by an adultblock",
    "blocked by a adult block",
    "blocked by an adult block",
    "not available for registration",
    "under the reserved name list",
    "reserved name",
    "reserved domain",
    "prohibited string",
    "restricted_registration",
    "dropzone",
    "platinum reserved",
    "reserved for registry",
    "reserved by registry",
    "reserved by iana",
    "reserved by icann",
)

# RDAP link rel values that signal the domain cannot be registered
_BLOCKING_LINK_RELS: frozenset[str] = frozenset({
    "restricted_registration",
})


def _check_rdap_blocking(raw: dict) -> str | None:
    """
    Inspect the raw RDAP response dict (which may be an error response) for
    notices, links, or status values that indicate the domain is blocked or
    reserved.

    Returns a human-readable reason string if blocking is detected, or None.
    """
    # Check notices array
    for notice in raw.get("notices", []):
        title = (notice.get("title") or "").strip().lower()
        descs = notice.get("description") or []
        desc_text = " ".join(descs).lower()

        # Exact title match
        if title in _BLOCKING_NOTICE_TITLES:
            return f"Domain blocked: {notice.get('title', title)}"

        # Substring match in title
        for sub in _BLOCKING_TITLE_SUBSTRINGS:
            if sub in title:
                return f"Domain blocked: {notice.get('title', title)}"

        # Phrase match in description
        for phrase in _BLOCKING_DESC_PHRASES:
            if phrase in desc_text:
                return f"Domain blocked/reserved: {notice.get('title') or 'notice'}"

    # Check remarks (some registries use remarks instead of notices)
    for remark in raw.get("remarks", []):
        title = (remark.get("title") or "").strip().lower()
        descs = remark.get("description") or []
        desc_text = " ".join(descs).lower()
        if title in _BLOCKING_NOTICE_TITLES:
            return f"Domain reserved: {remark.get('title', title)}"
        for phrase in _BLOCKING_DESC_PHRASES:
            if phrase in desc_text:
                return f"Domain reserved: {remark.get('title') or 'remark'}"

    # Check links for restricted_registration
    for link in raw.get("links", []):
        if (link.get("rel") or "").lower() in _BLOCKING_LINK_RELS:
            return "Domain restricted: restricted_registration link"

    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_date(dt: Any) -> str | None:
    """Format a datetime object or ISO string to YYYY-MM-DD."""
    if dt is None:
        return None
    if hasattr(dt, "strftime"):
        return dt.strftime("%Y-%m-%d")
    if isinstance(dt, str) and len(dt) >= 10:
        return dt[:10]
    return None


def _entity_to_contact(entity: dict) -> dict:
    """
    Convert a whoisit RDAP entity dict (with VCard data) to the whoisitlegacy
    contact format.
    """
    contact: dict = {}
    if entity.get("name"):
        contact["full_name"] = entity["name"]
    if entity.get("email"):
        contact["email_address"] = entity["email"]
    if entity.get("tel"):
        contact["phone_number"] = entity["tel"]
    addr = entity.get("address")
    if isinstance(addr, dict):
        parts = [
            addr.get("street_address", ""),
            addr.get("locality", ""),
            addr.get("region", ""),
            addr.get("postal_code", ""),
        ]
        addr_str = ", ".join(p for p in parts if p)
        if addr_str:
            contact["mailing_address"] = addr_str
        if addr.get("country"):
            contact["country_code"] = addr["country"]
    return contact


def _first_entity(entities: dict, role: str) -> dict:
    ents = entities.get(role, [])
    return _entity_to_contact(ents[0]) if ents else {}


# ---------------------------------------------------------------------------
# RDAP → normalized
# ---------------------------------------------------------------------------

def rdap_domain_to_normalized(rdap_result: dict | None) -> dict:
    """
    Convert a parsed RDAP domain result (as returned by ``whoisit.domain_async``)
    to the whoisitlegacy normalized format.

    Handles:
    - Flat result (``follow_rdap_registrar=False``)
    - Nested result (``follow_rdap_registrar=True``) → ``{"registry": ..., "registrar": ...}``
    - Error responses (``_rdap_error`` key present)
    """
    if not rdap_result:
        return _empty_normalized("No RDAP result")

    # Nested registry/registrar form
    if "registry" in rdap_result and "registrar" in rdap_result:
        reg = rdap_result["registry"] or {}
        rar = rdap_result["registrar"] or {}
        reg_norm = _rdap_single_to_normalized(reg)
        rar_norm = _rdap_single_to_normalized(rar) if rar and not rar.get("_rdap_error") else {}
        return _merge_rdap_registry_registrar(reg_norm, rar_norm)

    # Flat form
    return _rdap_single_to_normalized(rdap_result)


def _rdap_single_to_normalized(r: dict) -> dict:
    """Convert a single (flat) RDAP parsed domain dict to normalized format."""
    rdap_error = r.get("_rdap_error")
    if rdap_error:
        status_code = rdap_error.get("status_code")
        is_rate_limited  = status_code == 429
        is_service_error = status_code not in (None, 200, 404, 429)

        # Even on error responses, check for explicit blocking/reservation notices
        blocking_reason = _check_rdap_blocking(r)
        if blocking_reason:
            result = _empty_normalized(
                reason=blocking_reason,
                is_rate_limited=is_rate_limited,
                is_service_error=is_service_error,
            )
            result["available"] = False
            result["availability_reason"] = blocking_reason
            return result

        # Per-endpoint signal check: handles SIDN status=["free"], AFNIC errors[], Verisign empty body, etc.
        # Must run BEFORE the generic `if status:` block to avoid misclassifying status=["free"] as unavailable.
        available_by_signal = _check_rdap_endpoint_available(r, status_code)
        if available_by_signal is True:
            result = _empty_normalized(
                reason="RDAP: domain not found (endpoint signal)",
                is_rate_limited=False,
                is_service_error=False,
            )
            result["available"] = True
            result["availability_reason"] = "RDAP: domain not found (endpoint signal)"
            return result

        # Also check status field embedded in the error body (e.g. 404 with status: ["inactive"])
        status = r.get("status", [])
        if status:
            result = _empty_normalized(
                reason=f"Domain has blocking status in RDAP error response: {', '.join(status)}",
                is_rate_limited=is_rate_limited,
                is_service_error=is_service_error,
            )
            result["available"] = False
            result["availability_reason"] = result["availability_reason"]
            result["domain_status"] = status
            return result

        # 404 with no blocking notices = domain not found = available for registration
        if status_code == 404:
            result = _empty_normalized(
                reason="RDAP 404: domain not found",
                is_rate_limited=False,
                is_service_error=False,
            )
            result["available"] = True
            result["availability_reason"] = "RDAP 404: domain not found"
            return result

        return _empty_normalized(
            reason=f"RDAP error {status_code}: {rdap_error.get('message', 'unknown')}",
            is_rate_limited=is_rate_limited,
            is_service_error=is_service_error,
        )

    entities = r.get("entities", {})
    status = r.get("status", [])

    # Check notices/remarks/links for explicit blocking or reservation
    blocking_reason = _check_rdap_blocking(r)

    # Determine availability from RDAP status
    status_lower = [s.lower() for s in status]
    if any(s in ("active", "ok") for s in status_lower):
        available = False
        avail_reason = f"Domain is registered - RDAP status: {', '.join(status)}"
    elif status:
        available = False
        avail_reason = f"Domain has RDAP record - status: {', '.join(status)}"
    elif blocking_reason:
        available = False
        avail_reason = blocking_reason
    else:
        available = None
        avail_reason = "Unknown - no status in RDAP response"

    # Registrar from entities
    registrar: dict = {}
    reg_ents = entities.get("registrar", [])
    if reg_ents:
        e = reg_ents[0]
        if e.get("name"):
            registrar["registrar_name"] = e["name"]
        if e.get("whois_server"):
            registrar["whois_server"] = e["whois_server"]
        if e.get("handle"):
            try:
                registrar["iana_id"] = int(e["handle"])
            except (ValueError, TypeError):
                pass
        if e.get("url"):
            registrar["website_url"] = e["url"]

    return {
        "name_servers":            r.get("nameservers", []),
        "create_date":             _fmt_date(r.get("registration_date")),
        "expiry_date":             _fmt_date(r.get("expiration_date")),
        "update_date":             _fmt_date(r.get("last_changed_date")),
        "domain_status":           status,
        "registrar":               registrar,
        "registrant":              _first_entity(entities, "registrant"),
        "administrative_contact":  _first_entity(entities, "administrative"),
        "technical_contact":       _first_entity(entities, "technical"),
        "billing_contact":         _first_entity(entities, "billing"),
        "available":               available,
        "availability_reason":     avail_reason,
        "is_rate_limited":         False,
        "is_service_error":        False,
        "dnssec":                  r.get("dnssec", False),
    }


def _merge_rdap_registry_registrar(registry: dict, registrar: dict) -> dict:
    """
    Merge RDAP registry + registrar normalized dicts.
    Registry is authoritative for domain-level fields; registrar fills contact gaps.
    """
    result = dict(registry)
    if not registrar:
        return result
    # Fill contact gaps from registrar data
    for key in ("registrant", "administrative_contact", "technical_contact", "billing_contact"):
        if not result.get(key) and registrar.get(key):
            result[key] = registrar[key]
        elif result.get(key) and registrar.get(key):
            merged = dict(registrar[key])
            merged.update({k: v for k, v in result[key].items() if v})
            result[key] = merged
    # Fill registrar info gaps
    if not result.get("registrar") and registrar.get("registrar"):
        result["registrar"] = registrar["registrar"]
    # Fill date gaps
    for key in ("create_date", "expiry_date", "update_date"):
        if not result.get(key) and registrar.get(key):
            result[key] = registrar[key]
    return result


# ---------------------------------------------------------------------------
# WHOIS → normalized
# ---------------------------------------------------------------------------

def whois_domain_to_normalized(whois_result: dict | None) -> dict:
    """
    Extract normalized format from a whoisitlegacy domain result.

    whoisitlegacy returns::

        {
            "source": "registry"|"registrar",
            "whois_server": ...,
            "whois_registry": {"whois_endpoint": ..., "raw_data": ..., "parsed": {...}},
            "whois_registrar": {"whois_endpoint": ..., "raw_data": ..., "parsed": {...}},
        }
    """
    if not whois_result:
        return _empty_normalized("No WHOIS result")

    if "error" in whois_result:
        return _empty_normalized(f"WHOIS error: {whois_result['error']}")

    reg_parsed  = (whois_result.get("whois_registry")  or {}).get("parsed") or {}
    rar_parsed  = (whois_result.get("whois_registrar") or {}).get("parsed") or {}

    def pick(key: str, *sources: dict) -> Any:
        for src in sources:
            v = src.get(key)
            if v is not None and v != "" and v != [] and v != {}:
                return v
        return None

    def pick_list(key: str, *sources: dict) -> list:
        for src in sources:
            v = src.get(key)
            if v and isinstance(v, list):
                return v
        return []

    def pick_dict(key: str, *sources: dict) -> dict:
        for src in sources:
            v = src.get(key)
            if v and isinstance(v, dict) and any(v.values()):
                return v
        return {}

    # Domain-level: registry is authoritative
    name_servers   = pick_list("name_servers",  reg_parsed, rar_parsed)
    create_date    = pick("create_date",        reg_parsed, rar_parsed)
    expiry_date    = pick("expiry_date",        reg_parsed, rar_parsed)
    update_date    = pick("update_date",        reg_parsed, rar_parsed)
    domain_status  = pick_list("domain_status", reg_parsed, rar_parsed)
    available      = pick("available",          reg_parsed, rar_parsed)
    avail_reason   = pick("availability_reason", reg_parsed, rar_parsed) or "Unknown"

    # Error flags: OR of both sources
    is_rl = bool(reg_parsed.get("is_rate_limited") or rar_parsed.get("is_rate_limited"))
    is_se = bool(reg_parsed.get("is_service_error") or rar_parsed.get("is_service_error"))

    # Contact: registrar data usually richer
    registrar = pick_dict("registrar",               rar_parsed, reg_parsed)
    registrant = pick_dict("registrant",             rar_parsed, reg_parsed)
    admin      = pick_dict("administrative_contact", rar_parsed, reg_parsed)
    tech       = pick_dict("technical_contact",      rar_parsed, reg_parsed)
    billing    = pick_dict("billing_contact",        rar_parsed, reg_parsed)

    return {
        "name_servers":           name_servers,
        "create_date":            create_date,
        "expiry_date":            expiry_date,
        "update_date":            update_date,
        "domain_status":          domain_status,
        "registrar":              registrar,
        "registrant":             registrant,
        "administrative_contact": admin,
        "technical_contact":      tech,
        "billing_contact":        billing,
        "available":              available,
        "availability_reason":    avail_reason,
        "is_rate_limited":        is_rl,
        "is_service_error":       is_se,
    }


# ---------------------------------------------------------------------------
# Merger
# ---------------------------------------------------------------------------

def merge_normalized(primary: dict, secondary: dict) -> dict:
    """
    Fill missing / empty fields in *primary* from *secondary*.
    Primary values are never overwritten (only gaps are filled).
    """
    result = dict(primary)

    for key in ("create_date", "expiry_date", "update_date"):
        if not result.get(key) and secondary.get(key) is not None:
            result[key] = secondary[key]

    # For availability: prefer the source that has a definitive False answer
    if result.get("available") is None and secondary.get("available") is not None:
        result["available"] = secondary["available"]
        result["availability_reason"] = secondary.get("availability_reason") or result.get("availability_reason")
    elif result.get("available") is not False and secondary.get("available") is False:
        # Secondary is definitive (False) while primary is not — prefer secondary
        result["available"] = False
        result["availability_reason"] = secondary.get("availability_reason") or result.get("availability_reason")
    elif not result.get("availability_reason") and secondary.get("availability_reason"):
        result["availability_reason"] = secondary["availability_reason"]

    for key in ("name_servers", "domain_status"):
        if not result.get(key) and secondary.get(key):
            result[key] = secondary[key]

    for key in ("registrar", "registrant", "administrative_contact",
                "technical_contact", "billing_contact"):
        prim = result.get(key) or {}
        sec  = secondary.get(key) or {}
        if not prim and sec:
            result[key] = sec
        elif prim and sec:
            # Merge: keep all primary values, add secondary keys that are missing
            merged = dict(sec)
            merged.update({k: v for k, v in prim.items() if v})
            result[key] = merged

    result["is_rate_limited"] = bool(
        primary.get("is_rate_limited") or secondary.get("is_rate_limited")
    )
    result["is_service_error"] = bool(
        primary.get("is_service_error") or secondary.get("is_service_error")
    )

    # Preserve dnssec if present in either
    if not result.get("dnssec") and secondary.get("dnssec"):
        result["dnssec"] = secondary["dnssec"]

    return result


# ---------------------------------------------------------------------------
# Completeness check
# ---------------------------------------------------------------------------

def is_incomplete(normalized: dict) -> bool:
    """
    Return True if the normalized result is missing key information and a
    fallback to the secondary source is warranted.

    Triggers fallback when:
    - The server was rate-limited or returned a service error, OR
    - No dates AND no name-servers (essentially empty result), OR
    - Has dates but no registrar info (common with registry-only WHOIS).
    """
    if normalized.get("is_rate_limited") or normalized.get("is_service_error"):
        return True
    has_dates    = bool(normalized.get("create_date") or normalized.get("expiry_date"))
    has_ns       = bool(normalized.get("name_servers"))
    has_registrar = bool((normalized.get("registrar") or {}).get("registrar_name"))

    if not has_dates and not has_ns:
        return True  # effectively empty
    if has_dates and not has_registrar:
        return True  # registry only — missing registrar
    return False


def _get_field(normalized: dict, dotted: str) -> Any:
    """Resolve a dotted field path (e.g. ``"registrar.registrar_name"``) from *normalized*."""
    value: Any = normalized
    for part in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _group_satisfied(normalized: dict, group: list[str]) -> bool:
    """Return True if every field in *group* is non-empty in *normalized*."""
    for field in group:
        v = _get_field(normalized, field)
        if not v and v != 0:
            return False
    return True


def _normalize_required(
    required_fields: "list[str] | list[list[str]]",
) -> "list[list[str]]":
    """
    Normalise *required_fields* to a list of groups (list of lists).

    A flat ``list[str]`` is treated as a single AND group.
    A ``list[list[str]]`` is used as-is (OR between groups, AND within each).
    """
    if not required_fields:
        return []
    if isinstance(required_fields[0], str):
        return [required_fields]   # type: ignore[list-item]
    return required_fields         # type: ignore[return-value]


def check_required_fields(
    normalized: dict,
    required_fields: "list[str] | list[list[str]] | None",
) -> bool:
    """
    Return True (fallback needed) if none of the *required_fields* groups are
    fully satisfied.

    *required_fields* can be:

    - ``None`` — no extra requirement, always returns False.
    - ``["field1", "field2"]`` — single AND group: fallback if *any* field is
      missing.
    - ``[["field1", "field2"], ["field1", "field3"]]`` — OR between groups:
      fallback only if *all* groups have at least one missing field.  No
      fallback as soon as one group is fully satisfied.

    Supports dotted paths for nested fields (e.g. ``"registrar.registrar_name"``).
    """
    if not required_fields:
        return False
    groups = _normalize_required(required_fields)
    # No fallback if at least one group is fully satisfied
    return not any(_group_satisfied(normalized, g) for g in groups)


def needs_fallback(
    normalized: dict,
    required_fields: "list[str] | list[list[str]] | None" = None,
) -> bool:
    """
    Combined completeness check.

    Returns True if :func:`is_incomplete` returns True OR if none of the
    *required_fields* groups are fully satisfied.
    """
    if is_incomplete(normalized):
        return True
    return check_required_fields(normalized, required_fields)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_normalized(
    reason: str = "Unknown",
    is_rate_limited: bool = False,
    is_service_error: bool = False,
) -> dict:
    return {
        "name_servers":           [],
        "create_date":            None,
        "expiry_date":            None,
        "update_date":            None,
        "domain_status":          [],
        "registrar":              {},
        "registrant":             {},
        "administrative_contact": {},
        "technical_contact":      {},
        "billing_contact":        {},
        "available":              None,
        "availability_reason":    reason,
        "is_rate_limited":        is_rate_limited,
        "is_service_error":       is_service_error,
    }
