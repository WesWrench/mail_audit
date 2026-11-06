"""
WhoisItLegacy - A comprehensive WHOIS (TCP/43) client library for all RIRs.

This library provides a complete WHOIS client that:
- Supports all RIRs (ARIN, RIPE, AfriNIC, APNIC, LACNIC)
- Handles all object types (IPs, networks, ASNs, organizations, POCs, etc.)
- Returns structured JSON output compatible with RIPE Stat API format
- Preserves all information without data loss
- Adds metadata like object_type for easier normalization

Usage:
    from whoisitlegacy import WhoisClient

    # Bootstrap once at application startup (recommended)
    WhoisClient.bootstrap()

    # Create client
    client = WhoisClient()

    # Lookup IP
    result = client.lookup("8.8.8.8")

    # Lookup ASN
    result = client.lookup("AS15169")

    # Lookup domain (with normalization)
    result = client.domain("google.com", normalize=True)

    # Lookup ARIN organization
    result = client.entity("GOGL", rir="arin")

    # Lookup RIPE person
    result = client.entity("DR5299-RIPE", rir="ripe")
"""

from .client import WhoisClient
from .exceptions import (
    WhoisError,
    WhoisConnectionError,
    WhoisParseError,
    WhoisNotFoundError
)
from .bootstrap import bootstrap, bootstrap_async, is_bootstrapped, get_bootstrap_stats, clear_cache
from .parsers import parse_whois, WhoisParser
from .whois_pool import WhoisPool

__version__ = "1.0.0"


def create_whois_pool(max_concurrent: "int | None" = None) -> WhoisPool:
    """
    Create a :class:`WhoisPool` that limits concurrent async WHOIS queries.

    Parameters
    ----------
    max_concurrent:
        Maximum number of simultaneous TCP/43 queries.  ``None`` = no limit.

    Example::

        pool = whoisitlegacy.create_whois_pool(max_concurrent=20)
        results = await asyncio.gather(*[
            whoisitlegacy.domain_async(d, whois_pool=pool)
            for d in domains
        ])
    """
    return WhoisPool(max_concurrent=max_concurrent)


# Global client instance for module-level functions
_global_client = None


def _get_client():
    """Get or create the global WhoisClient instance."""
    global _global_client
    if _global_client is None:
        _global_client = WhoisClient()
    return _global_client


# Module-level convenience functions
def domain(
    domain_name: str,
    raw_parsed: bool = False,
    follow_whois_registrar: bool = True,
    include_whois_registry: bool = True,
    include_raw_parsed: bool = False,
    timeout: float = None,
):
    """
    Query WHOIS for a domain name.

    Args:
        domain_name: Domain to query (e.g., 'google.com')
        raw_parsed: If True, return raw line-by-line parsed data (key: value).
                    If False (default), return normalized structured format.
        follow_whois_registrar: If True (default), follow up with the registrar
                                WHOIS server for richer contact data.
        include_whois_registry: If True (default), include ``whois_registry`` in the result.
        include_raw_parsed: If True, add ``raw_parsed`` dict to ``whois_registry`` and
                            ``whois_registrar`` with flat key:value pairs from each server.
        timeout: Optional timeout override in seconds.

    Returns:
        WHOIS data for the domain.

    Example:
        >>> import whoisitlegacy
        >>> whoisitlegacy.bootstrap()
        >>> result = whoisitlegacy.domain('google.com')
        >>> print(result['source'])                             # "registrar"
        >>> print(result['whois_registry']['whois_endpoint'])  # registry server
        >>> print(result['whois_registrar']['raw_data'])        # registrar raw WHOIS
    """
    client = _get_client()
    if timeout is not None:
        client.timeout = timeout
    return client.domain(
        domain_name,
        raw_parsed=raw_parsed,
        follow_whois_registrar=follow_whois_registrar,
        include_whois_registry=include_whois_registry,
        include_raw_parsed=include_raw_parsed,
    )


async def domain_async(
    domain_name: str,
    raw_parsed: bool = False,
    follow_whois_registrar: bool = True,
    include_whois_registry: bool = True,
    include_raw_parsed: bool = False,
    timeout: float = None,
    whois_pool: "WhoisPool | None" = None,
):
    """
    Async version of :func:`domain`. Non-blocking TCP/43 queries using ``asyncio``.

    Args:
        domain_name: Domain to query (e.g., 'google.com')
        raw_parsed: If True, return raw line-by-line parsed data (key: value).
        follow_whois_registrar: If True (default), follow up with the registrar WHOIS server.
        include_whois_registry: If True (default), include ``whois_registry`` in the result.
        include_raw_parsed: If True, add ``raw_parsed`` to each source entry.
        timeout: Optional timeout override in seconds.
        whois_pool: Optional :class:`WhoisPool` for concurrency limiting.

    Returns:
        WHOIS data for the domain.

    Example:
        >>> import asyncio, whoisitlegacy
        >>> whoisitlegacy.bootstrap(whois_server_cache=True)
        >>> result = asyncio.run(whoisitlegacy.domain_async('google.com'))
        >>> print(result['whois_registry']['whois_endpoint'])
    """
    client = _get_client()
    if timeout is not None:
        client.timeout = timeout
    coro = client.domain_async(
        domain_name,
        raw_parsed=raw_parsed,
        follow_whois_registrar=follow_whois_registrar,
        include_whois_registry=include_whois_registry,
        include_raw_parsed=include_raw_parsed,
    )
    if whois_pool is not None:
        return await whois_pool.execute(coro)
    return await coro


def ip(ip_address: str, timeout: float = None):
    """
    Query WHOIS for an IP address or network.

    Args:
        ip_address: IP address or network (e.g., '8.8.8.8' or '8.8.8.0/24')
        timeout: Optional timeout override

    Returns:
        WHOIS data for the IP

    Example:
        >>> import whoisitlegacy
        >>> result = whoisitlegacy.ip('8.8.8.8')
        >>> print(result)
    """
    client = _get_client()
    if timeout is not None:
        client.timeout = timeout
    return client.lookup(ip_address)


async def ip_async(ip_address: str, timeout: float = None):
    """
    Async version of :func:`ip`. Non-blocking IP address lookup.

    Args:
        ip_address: IP address or network (e.g., '8.8.8.8' or '8.8.8.0/24')
        timeout: Optional timeout override

    Returns:
        WHOIS data for the IP

    Example:
        >>> import asyncio, whoisitlegacy
        >>> result = asyncio.run(whoisitlegacy.ip_async('8.8.8.8'))
        >>> print(result)
    """
    client = _get_client()
    if timeout is not None:
        client.timeout = timeout
    return await client.ip_async(ip_address)


def asn(asn_number: int, timeout: float = None):
    """
    Query WHOIS for an ASN.

    Args:
        asn_number: ASN number (e.g., 15169 for Google)
        timeout: Optional timeout override

    Returns:
        WHOIS data for the ASN

    Example:
        >>> import whoisitlegacy
        >>> result = whoisitlegacy.asn(15169)
        >>> print(result)
    """
    client = _get_client()
    if timeout is not None:
        client.timeout = timeout
    return client.lookup(f"AS{asn_number}")


async def asn_async(asn_number: int, timeout: float = None):
    """
    Async version of :func:`asn`. Non-blocking ASN lookup.

    Args:
        asn_number: ASN number (e.g., 15169 for Google)
        timeout: Optional timeout override

    Returns:
        WHOIS data for the ASN

    Example:
        >>> import asyncio, whoisitlegacy
        >>> result = asyncio.run(whoisitlegacy.asn_async(15169))
        >>> print(result)
    """
    client = _get_client()
    if timeout is not None:
        client.timeout = timeout
    return await client.asn_async(asn_number)


def entity(entity_id: str, rir: str = None, timeout: float = None):
    """
    Query WHOIS for an entity (organization, person, role, etc.).

    Args:
        entity_id: Entity identifier (e.g., 'GOGL' for ARIN, 'DR5299-RIPE' for RIPE)
        rir: Optional RIR to query (arin, ripe, apnic, afrinic, lacnic)
        timeout: Optional timeout override

    Returns:
        WHOIS data for the entity

    Example:
        >>> import whoisitlegacy
        >>> result = whoisitlegacy.entity('GOGL', rir='arin')
        >>> print(result)
    """
    client = _get_client()
    if timeout is not None:
        client.timeout = timeout
    return client.entity(entity_id, rir=rir)


async def entity_async(entity_id: str, rir: str = None, timeout: float = None):
    """
    Async version of :func:`entity`. Non-blocking entity lookup.

    Args:
        entity_id: Entity identifier (e.g., 'GOGL' for ARIN, 'DR5299-RIPE' for RIPE)
        rir: Optional RIR to query (arin, ripe, apnic, afrinic, lacnic)
        timeout: Optional timeout override

    Returns:
        WHOIS data for the entity

    Example:
        >>> import asyncio, whoisitlegacy
        >>> result = asyncio.run(whoisitlegacy.entity_async('GOGL', rir='arin'))
        >>> print(result)
    """
    client = _get_client()
    if timeout is not None:
        client.timeout = timeout
    return await client.entity_async(entity_id, rir=rir)


def lookup(query: str, timeout: float = None):
    """
    Generic WHOIS lookup for any query type.

    Args:
        query: Query string (IP, ASN, domain, etc.)
        timeout: Optional timeout override

    Returns:
        WHOIS data for the query

    Example:
        >>> import whoisitlegacy
        >>> result = whoisitlegacy.lookup('8.8.8.8')
        >>> print(result)
    """
    client = _get_client()
    if timeout is not None:
        client.timeout = timeout
    return client.lookup(query)


async def lookup_async(query: str, timeout: float = None):
    """
    Async version of :func:`lookup`. Non-blocking generic WHOIS lookup.

    Args:
        query: Query string (IP, ASN, domain, etc.)
        timeout: Optional timeout override

    Returns:
        WHOIS data for the query

    Example:
        >>> import asyncio, whoisitlegacy
        >>> result = asyncio.run(whoisitlegacy.lookup_async('8.8.8.8'))
        >>> print(result)
    """
    client = _get_client()
    if timeout is not None:
        client.timeout = timeout
    return await client.lookup_async(query)


def get_registrar_by_iana_id(iana_id: int) -> "dict | None":
    """
    Return the full registrar entry from ``registrar_whois_map.json`` for the
    given IANA registrar ID, or ``None`` if not found.

    The returned dict contains:
        ``whois_endpoint``, ``iana_registrar_id``, ``iana_registrar_name``,
        ``iana_registrar_website``, ``nominet_registrar_name`` (may be null),
        ``nominet_registrar_tag`` (may be null), ``nominet_registrar_website`` (may be null).

    Example::

        import whoisitlegacy
        entry = whoisitlegacy.get_registrar_by_iana_id(146)
        print(entry["whois_endpoint"])   # "whois.godaddy.com"
    """
    import json
    from pathlib import Path
    map_path = Path(__file__).parent / "data" / "registrar_whois_map.json"
    try:
        with open(map_path, encoding="utf-8") as f:
            entries = json.load(f)
    except Exception:
        return None
    for entry in entries:
        if entry.get("iana_registrar_id") == iana_id:
            return entry
    return None


def get_registrar_whois_endpoint(iana_id: int) -> "str | None":
    """
    Return the WHOIS server hostname for a registrar by its IANA ID,
    or ``None`` if not found.

    This is a fast shortcut for ``get_registrar_by_iana_id(iana_id)["whois_endpoint"]``.

    Example::

        import whoisitlegacy
        endpoint = whoisitlegacy.get_registrar_whois_endpoint(146)
        print(endpoint)  # "whois.godaddy.com"
    """
    from .domain import _get_registrar_map_indexes
    idx = _get_registrar_map_indexes()
    return idx.get("by_iana_id", {}).get(int(iana_id))


__all__ = [
    "WhoisClient",
    "WhoisParser",
    "parse_whois",
    "WhoisError",
    "WhoisConnectionError",
    "WhoisParseError",
    "WhoisNotFoundError",
    "bootstrap",
    "bootstrap_async",
    "is_bootstrapped",
    "get_bootstrap_stats",
    "clear_cache",
    # Module-level sync functions
    "domain",
    "ip",
    "asn",
    "entity",
    "lookup",
    # Module-level async functions
    "domain_async",
    "ip_async",
    "asn_async",
    "entity_async",
    "lookup_async",
    # Utility / cross-client helpers
    "get_registrar_by_iana_id",
    "get_registrar_whois_endpoint",
    # Concurrency pool
    "WhoisPool",
    "create_whois_pool",
]
