"""
HybridWhois — unified WHOIS + RDAP client.

Wraps both ``whoisitlegacy`` (TCP/43 WHOIS) and ``whoisit`` (RDAP/HTTPS) to
maximise the information retrieved for any asset.

Quick start
-----------

::

    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

    import hybridwhois

    # Bootstrap both underlying clients once
    hybridwhois.bootstrap()

    # --- Synchronous ---
    result = hybridwhois.domain("google.com")
    print(result["create_date"])          # normalised (whoisitlegacy format)
    print(result["sources_used"])         # ["whois"] or ["whois", "rdap"]
    print(result["whois"]["registry"])    # raw whoisitlegacy registry entry
    print(result["rdap"]["registry"])     # raw whoisit RDAP entry (if used)

    # --- Async ---
    import asyncio
    result = asyncio.run(hybridwhois.domain_async("github.com"))

    # --- Force both sources ---
    result = hybridwhois.domain("example.com", both=True)

    # --- Always start with RDAP ---
    result = hybridwhois.domain("example.com", first_method="rdap")

    # --- IP / ASN (RDAP only) ---
    result = hybridwhois.ip("8.8.8.8")
    result = asyncio.run(hybridwhois.asn_async(15169))

Result structure
----------------

::

    {
        # Normalised fields (whoisitlegacy format)
        "name_servers":           [...],
        "create_date":            "YYYY-MM-DD" | None,
        "expiry_date":            "YYYY-MM-DD" | None,
        "update_date":            "YYYY-MM-DD" | None,
        "domain_status":          [...],
        "registrar":              {"registrar_name": ..., "iana_id": ..., ...},
        "registrant":             {...},
        "administrative_contact": {...},
        "technical_contact":      {...},
        "billing_contact":        {...},
        "available":              True | False | None,
        "availability_reason":    "...",
        "is_rate_limited":        bool,
        "is_service_error":       bool,
        "dnssec":                 bool | None,      # present for domain queries
        "sources_used":           ["whois"] | ["rdap"] | ["whois", "rdap"],

        # Raw source data
        "whois": {
            "registry":  {...} | None,
            "registrar": {...} | None,
            "error":     "..." | None,
        },
        "rdap": {
            "registry":  {...} | None,
            "registrar": {...} | None,
            "error":     "..." | None,
        },
    }
"""

from __future__ import annotations

import sys
import os

# Allow sibling packages (whoisit, whoisitlegacy) to be imported by name
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import whoisit
import whoisitlegacy

from .client import HybridWhoisClient
from .normalizer import (
    rdap_domain_to_normalized,
    whois_domain_to_normalized,
    merge_normalized,
    is_incomplete,
    check_required_fields,
    needs_fallback,
)

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Global default client (module-level convenience API)
# ---------------------------------------------------------------------------

_default_client: HybridWhoisClient | None = None


def _get_client(**overrides) -> HybridWhoisClient:
    """Return (or lazily create) the module-level default client."""
    global _default_client
    if _default_client is None or overrides:
        if overrides:
            return HybridWhoisClient(**overrides)
        _default_client = HybridWhoisClient()
    return _default_client


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def bootstrap(
    whois_server_cache: bool = True,
    rdap_overrides:     bool = True,
) -> None:
    """
    Bootstrap both underlying clients.

    Must be called once before making any queries.

    Parameters
    ----------
    whois_server_cache:
        Passed to ``whoisitlegacy.bootstrap()``.  Enables WHOIS server
        address caching.
    rdap_overrides:
        Passed to ``whoisit.bootstrap()``.  Loads RDAP endpoint overrides.
    """
    whoisitlegacy.bootstrap(whois_server_cache=whois_server_cache)
    whoisit.bootstrap(overrides=rdap_overrides)


async def bootstrap_async(
    whois_server_cache: bool = True,
    rdap_overrides:     bool = True,
) -> None:
    """Async version of :func:`bootstrap`."""
    await whoisitlegacy.bootstrap_async(whois_server_cache=whois_server_cache)
    whoisit.bootstrap(overrides=rdap_overrides)


# ---------------------------------------------------------------------------
# create_client
# ---------------------------------------------------------------------------

def create_client(
    first_method:    str  = "whois",
    both:            bool = False,
    fallback:        bool = True,
    rdap_options:    dict | None = None,
    whois_options:   dict | None = None,
    rdap_pool=None,
    whois_pool=None,
    required_fields: list | None = None,
) -> HybridWhoisClient:
    """
    Create a :class:`HybridWhoisClient` instance.

    Parameters
    ----------
    first_method:
        ``"whois"`` (default) or ``"rdap"``.  Determines which source is tried
        first for domain queries.
    both:
        If ``True``, always query both sources (in parallel for async) and
        merge the results.
    fallback:
        If ``True`` (default), automatically try the secondary source when
        the primary result is incomplete (missing dates, registrar info, etc.).
    rdap_options:
        Extra keyword arguments forwarded to ``whoisit.domain_async()`` /
        ``whoisit.domain()``.
        E.g. ``{"follow_rdap_registrar": True, "follow_related": True}``.
    whois_options:
        Extra keyword arguments forwarded to ``whoisitlegacy.domain_async()`` /
        ``whoisitlegacy.domain()``.
        E.g. ``{"follow_whois_registrar": True}``.
    rdap_pool:
        Optional pre-created :class:`whoisit.RDAPPool`.  A default pool is
        created automatically when needed.
    whois_pool:
        Optional pre-created :class:`whoisitlegacy.WhoisPool` for limiting
        concurrent TCP/43 queries.
    required_fields:
        Optional list of field names that must be non-empty; if any are absent
        after the primary query the secondary source is tried.  Supports dotted
        paths, e.g. ``["registrar.registrar_name", "expiry_date"]``.
    """
    return HybridWhoisClient(
        first_method=first_method,
        both=both,
        fallback=fallback,
        rdap_options=rdap_options,
        whois_options=whois_options,
        rdap_pool=rdap_pool,
        whois_pool=whois_pool,
        required_fields=required_fields,
    )


# ---------------------------------------------------------------------------
# Module-level convenience functions (use the default client)
# ---------------------------------------------------------------------------

def domain(
    domain_name:     str,
    first_method:    str  = "whois",
    both:            bool = False,
    fallback:        bool = True,
    rdap_options:    dict | None = None,
    whois_options:   dict | None = None,
    required_fields: list | None = None,
) -> dict:
    """
    Query a domain via WHOIS and/or RDAP and return the normalised result.

    Parameters
    ----------
    domain_name:
        The fully qualified domain name (e.g. ``"google.com"``).
    first_method:
        ``"whois"`` (default) or ``"rdap"``.
    both:
        Query both sources and merge.
    fallback:
        Fall back to the secondary source if the primary result is incomplete.
    rdap_options / whois_options:
        Per-call option overrides (see :func:`create_client`).
    required_fields:
        Optional list of fields that must be non-empty; triggers fallback if any
        are absent (see :func:`create_client`).
    """
    has_overrides = (
        rdap_options or whois_options or required_fields
        or first_method != "whois" or both or not fallback
    )
    client = _get_client(
        first_method=first_method, both=both, fallback=fallback,
        rdap_options=rdap_options, whois_options=whois_options,
        required_fields=required_fields,
    ) if has_overrides else _get_client()
    return client.domain(domain_name)


async def domain_async(
    domain_name:     str,
    first_method:    str  = "whois",
    both:            bool = False,
    fallback:        bool = True,
    rdap_options:    dict | None = None,
    whois_options:   dict | None = None,
    rdap_pool=None,
    whois_pool=None,
    required_fields: list | None = None,
) -> dict:
    """Async version of :func:`domain`."""
    has_overrides = (
        rdap_options or whois_options or required_fields
        or first_method != "whois" or both or not fallback
        or rdap_pool or whois_pool
    )
    client = _get_client(
        first_method=first_method, both=both, fallback=fallback,
        rdap_options=rdap_options, whois_options=whois_options,
        rdap_pool=rdap_pool, whois_pool=whois_pool,
        required_fields=required_fields,
    ) if has_overrides else _get_client()
    return await client.domain_async(domain_name)


def ip(ip_address: str, rir: str | None = None, rdap_options: dict | None = None) -> dict:
    """Query an IP address via RDAP (whoisit)."""
    return _get_client(rdap_options=rdap_options).ip(ip_address, rir=rir)


async def ip_async(
    ip_address: str, rir: str | None = None, rdap_options: dict | None = None
) -> dict:
    """Async version of :func:`ip`."""
    return await _get_client(rdap_options=rdap_options).ip_async(ip_address, rir=rir)


def asn(as_number: int, rir: str | None = None, rdap_options: dict | None = None) -> dict:
    """Query an AS number via RDAP (whoisit)."""
    return _get_client(rdap_options=rdap_options).asn(as_number, rir=rir)


async def asn_async(
    as_number: int, rir: str | None = None, rdap_options: dict | None = None
) -> dict:
    """Async version of :func:`asn`."""
    return await _get_client(rdap_options=rdap_options).asn_async(as_number, rir=rir)


def entity(
    entity_handle: str, rir: str | None = None, rdap_options: dict | None = None
) -> dict:
    """Query an entity via RDAP (whoisit)."""
    return _get_client(rdap_options=rdap_options).entity(entity_handle, rir=rir)


async def entity_async(
    entity_handle: str, rir: str | None = None, rdap_options: dict | None = None
) -> dict:
    """Async version of :func:`entity`."""
    return await _get_client(rdap_options=rdap_options).entity_async(entity_handle, rir=rir)


def flush_rdap_status() -> None:
    """Flush the default client's RDAP pool status.json."""
    if _default_client is not None:
        _default_client.flush_rdap_status()


# ---------------------------------------------------------------------------
# Re-export useful helpers from underlying libraries
# ---------------------------------------------------------------------------

# whoisit utilities
get_registrar_rdap_url = whoisit.get_registrar_rdap_url
get_registrar_info     = whoisit.get_registrar_info
get_rdap_host_delays   = whoisit.get_rdap_host_delays
create_rdap_pool       = whoisit.create_rdap_pool

# whoisitlegacy utilities
get_registrar_by_iana_id      = whoisitlegacy.get_registrar_by_iana_id
get_registrar_whois_endpoint  = whoisitlegacy.get_registrar_whois_endpoint
create_whois_pool             = whoisitlegacy.create_whois_pool


__all__ = [
    # Core
    "HybridWhoisClient",
    "bootstrap",
    "bootstrap_async",
    "create_client",
    # Domain
    "domain",
    "domain_async",
    # IP / ASN / Entity (RDAP only)
    "ip",
    "ip_async",
    "asn",
    "asn_async",
    "entity",
    "entity_async",
    # Utilities
    "flush_rdap_status",
    "get_registrar_rdap_url",
    "get_registrar_info",
    "get_rdap_host_delays",
    "create_rdap_pool",
    "create_whois_pool",
    "get_registrar_by_iana_id",
    "get_registrar_whois_endpoint",
    # Normalizer helpers (for advanced use)
    "rdap_domain_to_normalized",
    "whois_domain_to_normalized",
    "merge_normalized",
    "is_incomplete",
    "check_required_fields",
    "needs_fallback",
]
