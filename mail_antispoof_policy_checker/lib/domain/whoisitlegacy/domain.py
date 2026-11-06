"""
Domain WHOIS lookup functionality.

Handles domain name lookups by:
1. Extracting TLD from domain
2. Querying IANA for TLD's WHOIS server
3. Querying the TLD WHOIS server for domain details
"""

import json
import re
from pathlib import Path
from typing import Optional, Dict, Any
from .connection import query_rir
from .exceptions import WhoisError


# Module-level cache — built once on first use
_REGISTRAR_MAP_INDEXES: Optional[Dict[str, Dict]] = None


# TLDs managed by Nominet — Nominet tag/name strategies only apply to these
_NOMINET_TLDS = {'uk', 'wales', 'cymru', 'gb'}


def _get_registrar_map_indexes() -> Dict[str, Dict]:
    """
    Load registrar_whois_map.json and build multiple lookup indexes.

    Indexes built (all keys lowercased):
      by_iana_id           : {iana_registrar_id (int): endpoint}
      by_iana_name         : {iana_registrar_name: endpoint}
      by_nominet_name_tag  : {"nominet_name [tag = nominet_tag]": endpoint}
      by_nominet_name      : {nominet_registrar_name: endpoint}
      by_iana_name_nom_tag : {"iana_name [tag = nominet_tag]": endpoint}
      by_nominet_tag       : {nominet_registrar_tag: endpoint}
    """
    global _REGISTRAR_MAP_INDEXES
    if _REGISTRAR_MAP_INDEXES is not None:
        return _REGISTRAR_MAP_INDEXES

    map_path = Path(__file__).parent / "data" / "registrar_whois_map.json"
    try:
        with open(map_path, encoding="utf-8") as f:
            entries = json.load(f)
    except Exception:
        _REGISTRAR_MAP_INDEXES = {}
        return _REGISTRAR_MAP_INDEXES

    by_iana_id: Dict[int, str] = {}
    by_iana_name: Dict[str, str] = {}
    by_nominet_name_tag: Dict[str, str] = {}
    by_nominet_name: Dict[str, str] = {}
    by_iana_name_nom_tag: Dict[str, str] = {}
    by_nominet_tag: Dict[str, str] = {}

    for entry in entries:
        endpoint = (entry.get("whois_endpoint") or "").strip()
        if not endpoint:
            continue

        iana_id = entry.get("iana_registrar_id")
        iana_name = (entry.get("iana_registrar_name") or "").strip()
        nom_name = (entry.get("nominet_registrar_name") or "").strip()
        nom_tag = (entry.get("nominet_registrar_tag") or "").strip()

        if iana_id and int(iana_id) not in by_iana_id:
            by_iana_id[int(iana_id)] = endpoint
        if iana_name:
            by_iana_name.setdefault(iana_name.lower(), endpoint)
        if nom_name and nom_tag:
            key = f"{nom_name.lower()} [tag = {nom_tag.lower()}]"
            by_nominet_name_tag.setdefault(key, endpoint)
        if nom_name:
            by_nominet_name.setdefault(nom_name.lower(), endpoint)
        if iana_name and nom_tag:
            key = f"{iana_name.lower()} [tag = {nom_tag.lower()}]"
            by_iana_name_nom_tag.setdefault(key, endpoint)
        if nom_tag:
            by_nominet_tag.setdefault(nom_tag.lower(), endpoint)

    _REGISTRAR_MAP_INDEXES = {
        "by_iana_id": by_iana_id,
        "by_iana_name": by_iana_name,
        "by_nominet_name_tag": by_nominet_name_tag,
        "by_nominet_name": by_nominet_name,
        "by_iana_name_nom_tag": by_iana_name_nom_tag,
        "by_nominet_tag": by_nominet_tag,
    }
    return _REGISTRAR_MAP_INDEXES


def _get_whois_server_for_registrar(
    iana_id=None,
    registrar_name: Optional[str] = None,
    tld: Optional[str] = None,
) -> Optional[str]:
    """
    Return the known WHOIS endpoint for a registrar using multiple fallback strategies
    (tried in this priority order):

      1. iana_registrar_id       — direct numeric ID match
      2. iana_registrar_name     — name matched against IANA names in the map
      3. nominet_name [tag]      — name matched against "nominet_name [tag = tag]"
                                   (Nominet TLDs only: .uk, .wales, .cymru, .gb)
      4. nominet_registrar_name  — name matched against Nominet registrar names
                                   (Nominet TLDs only)
      5. iana_name [tag]         — name matched against "iana_name [tag = nominet_tag]"
                                   (Nominet TLDs only)
      6. nominet_registrar_tag   — name matched as a bare Nominet tag
                                   (Nominet TLDs only)

    ``registrar_name`` is the raw value of the ``Registrar:`` field from the WHOIS
    response.  ``tld`` is the top-level domain of the queried domain (e.g. ``"uk"``,
    ``"com"``); Nominet strategies 3–6 are skipped for non-Nominet TLDs.
    """
    idx = _get_registrar_map_indexes()
    if not idx:
        return None

    # 1. IANA ID
    if iana_id is not None:
        result = idx["by_iana_id"].get(int(iana_id))
        if result:
            return result

    if not registrar_name:
        return None

    name_lower = registrar_name.lower().strip()

    # 2. Match against iana_registrar_name
    result = idx["by_iana_name"].get(name_lower)
    if result:
        return result

    # Strategies 3–6 are Nominet-specific — only apply for Nominet TLDs
    is_nominet = tld is not None and tld.lower() in _NOMINET_TLDS

    if is_nominet:
        # 3. Match against "nominet_name [tag = tag]"
        result = idx["by_nominet_name_tag"].get(name_lower)
        if result:
            return result

        # 4. Match against nominet_registrar_name
        result = idx["by_nominet_name"].get(name_lower)
        if result:
            return result

        # 5. Match against "iana_name [tag = nominet_tag]"
        result = idx["by_iana_name_nom_tag"].get(name_lower)
        if result:
            return result

        # 6. Match as bare nominet_registrar_tag
        result = idx["by_nominet_tag"].get(name_lower)
        if result:
            return result

    return None


def is_valid_domain(domain: str) -> bool:
    """
    Validate if string is a valid domain name (not an IP or invalid format).

    Args:
        domain: String to validate

    Returns:
        True if valid domain, False otherwise
    """
    # Check for IP address patterns
    # IPv4: x.x.x.x
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ipv4_pattern, domain):
        return False

    # IPv6: contains colons
    if ':' in domain and not domain.startswith('http'):
        return False

    # Basic domain validation
    # Must have at least one dot
    if '.' not in domain:
        return False

    # Remove protocol if present
    clean_domain = re.sub(r'^https?://', '', domain)
    clean_domain = clean_domain.split('/')[0]
    clean_domain = clean_domain.split(':')[0]

    # Check domain format: alphanumeric + dots + hyphens
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'
    return bool(re.match(domain_pattern, clean_domain))


def extract_tld(domain: str) -> Optional[str]:
    """
    Extract TLD from domain name.

    Args:
        domain: Domain name (e.g., "google.com", "bbc.co.uk")

    Returns:
        TLD without dot (e.g., "com", "uk") or None if invalid
    """
    # Remove protocol if present
    domain = re.sub(r'^https?://', '', domain)

    # Remove path if present
    domain = domain.split('/')[0]

    # Remove port if present
    domain = domain.split(':')[0]

    # Extract TLD
    parts = domain.split('.')
    if len(parts) >= 2:
        return parts[-1].lower()

    return None


def get_tld_whois_server(tld: str, timeout: float = 10.0, use_cache: bool = True) -> Optional[str]:
    """
    Get WHOIS server for a TLD.

    First checks the bootstrap cache, then queries IANA if not cached.

    Args:
        tld: TLD without dot (e.g., "com", "org", "fr")
        timeout: Query timeout
        use_cache: If True, use cached value from bootstrap (default: True)

    Returns:
        WHOIS server hostname or None if not found
    """
    # Check cache first if enabled
    if use_cache:
        from .bootstrap import get_cached_whois_server
        cached = get_cached_whois_server(tld)
        if cached:
            return cached

    # Fallback to IANA query
    try:
        # Query IANA for TLD information
        response = query_rir("iana", tld, timeout=timeout)

        # Look for whois: field in response
        for line in response.split('\n'):
            line = line.strip()
            if line.startswith('whois:'):
                # Extract whois server
                whois_server = line.split('whois:')[1].strip()
                if whois_server:
                    return whois_server

        return None

    except Exception:
        return None


def _merge_whois_data(registry_parsed: Dict[str, Any], registrar_parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge registrar WHOIS data over registry WHOIS data.

    Registrar WHOIS servers typically return richer contact data (registrant,
    admin, tech contacts) that the registry suppresses for privacy.  Registry
    data is kept as the authoritative source for dates and name servers.

    Args:
        registry_parsed: Parsed data from the registry WHOIS server.
        registrar_parsed: Parsed data from the registrar WHOIS server.

    Returns:
        Merged parsed data dictionary.
    """
    merged = dict(registry_parsed)

    # Contacts: prefer registrar (richer data, unredacted fields)
    for key in ('registrant', 'administrative_contact', 'technical_contact', 'billing_contact'):
        reg_contact = registrar_parsed.get(key) or {}
        if reg_contact:
            merged[key] = reg_contact

    # Registrar info: overlay registrar's own self-description
    reg_info = registrar_parsed.get('registrar') or {}
    if reg_info:
        base = dict(merged.get('registrar') or {})
        for k, v in reg_info.items():
            if v:
                base[k] = v
        merged['registrar'] = base

    # Status: union of both sets (registrar may add pendingDelete, etc.)
    merged['domain_status'] = sorted(
        set(merged.get('domain_status') or []) | set(registrar_parsed.get('domain_status') or [])
    )

    # Dates: prefer registry (authoritative source), fall back to registrar
    for date_key in ('create_date', 'expiry_date', 'update_date'):
        if not merged.get(date_key) and registrar_parsed.get(date_key):
            merged[date_key] = registrar_parsed[date_key]

    # Name servers: prefer registry, fall back to registrar
    if not merged.get('name_servers') and registrar_parsed.get('name_servers'):
        merged['name_servers'] = registrar_parsed['name_servers']

    # Availability: prefer a definitive result (False/True) over None
    if merged.get('available') is None and registrar_parsed.get('available') is not None:
        merged['available'] = registrar_parsed['available']
        merged['availability_reason'] = registrar_parsed.get('availability_reason', '')

    return merged


def query_domain(
    domain: str,
    timeout: float = 10.0,
    max_retries: int = 5,
    raw_parsed: bool = False,
    follow_whois_registrar: bool = True,
    include_whois_registry: bool = True,
    include_raw_parsed: bool = False,
) -> Dict[str, Any]:
    """
    Query domain WHOIS information.

    Args:
        domain: Domain name (e.g., "google.com")
        timeout: Query timeout in seconds
        max_retries: Maximum retry attempts for each WHOIS server
        raw_parsed: If True, return raw line-by-line parsed format (simple key: value).
                    If False (default), return normalized Whoxy-compatible format.
        follow_whois_registrar: If True (default), perform a second WHOIS query on the
                                registrar's own WHOIS server to obtain richer contact data.
                                Set to False to only query the registry WHOIS server.
        include_whois_registry: If True (default), include the registry WHOIS raw response
                                in the ``raw_whois`` list even when a registrar follow-up
                                was performed.  If False, only the registrar raw response
                                is included when both were queried.

    Returns:
        Dictionary with domain WHOIS data. Key fields:

        - ``source`` (str): ``"registry"`` or ``"registrar"`` — indicates which server
          provided the primary parsed data.
        - ``whois_server`` (str): Hostname of the server that provided the primary data.
        - ``registry_whois_server`` (str, optional): Hostname of the registry WHOIS server,
          only present when ``source`` is ``"registrar"``.
        - ``whois_registry`` / ``whois_registrar`` (dict): Per-source entry with
          ``whois_endpoint``, ``raw_data``, parsed fields, and optionally ``raw_parsed``.

    Raises:
        WhoisError: If domain is invalid or all WHOIS servers fail.
    """
    # Validate domain format
    if not is_valid_domain(domain):
        raise WhoisError(
            f"Invalid domain format: {domain}. "
            "Domain queries require a valid domain name, not an IP address."
        )

    # Extract TLD
    tld = extract_tld(domain)
    if not tld:
        raise WhoisError(f"Invalid domain: {domain}")

    # Get all available WHOIS servers for TLD (with fallback support)
    from .bootstrap import get_all_whois_servers, mark_working_server
    whois_servers = get_all_whois_servers(tld)

    if not whois_servers:
        raise WhoisError(f"No WHOIS server found for TLD: .{tld}")

    # Try each registry server in order until one works
    from .connection import whois_query
    last_error = None

    for whois_server in whois_servers:
        try:
            response = whois_query(
                whois_server,
                43,
                domain,
                timeout=timeout,
                max_retries=max_retries,
            )

            from .parsers import parse_whois
            from .formatter import format_whois

            registry_parsed = parse_whois(response)

            registry_entry = {
                "whois_endpoint": whois_server,
                "raw_data": response,
                "parsed": registry_parsed,
            }

            source = "registry"
            registry_whois_server = None  # only set when source becomes "registrar"
            registrar_entry = None

            # Follow registrar WHOIS server for richer contact data
            if follow_whois_registrar:
                registrar_info = registry_parsed.get('registrar') or {}
                registrar_server = registrar_info.get('whois_server', '').strip()
                # Fallback: look up WHOIS server via registrar map (IANA ID then name)
                if not registrar_server:
                    registrar_server = _get_whois_server_for_registrar(
                        iana_id=registrar_info.get('iana_id'),
                        registrar_name=registrar_info.get('registrar_name'),
                        tld=tld,
                    ) or ''
                if registrar_server and registrar_server != whois_server:
                    try:
                        reg_response = whois_query(
                            registrar_server,
                            43,
                            domain,
                            timeout=timeout,
                            max_retries=min(max_retries, 3),
                        )
                        reg_parsed = parse_whois(reg_response)
                        registrar_entry = {
                            "whois_endpoint": registrar_server,
                            "raw_data": reg_response,
                            "parsed": reg_parsed,
                        }
                        # Only promote to source="registrar" when the registrar adds
                        # contacts — otherwise registry remains the primary data source.
                        has_new_contacts = any(
                            reg_parsed.get(k)
                            for k in ('registrant', 'administrative_contact',
                                      'technical_contact', 'billing_contact')
                        )
                        if has_new_contacts:
                            source = "registrar"
                            registry_whois_server = whois_server
                    except Exception:
                        pass  # Registrar WHOIS failure is non-fatal — registry data is returned

            # Merged parsed data for top-level fields
            if registrar_entry:
                parsed_data = _merge_whois_data(registry_parsed, registrar_entry["parsed"])
            else:
                parsed_data = registry_parsed

            final_server = registrar_entry["whois_endpoint"] if source == "registrar" else whois_server

            # Format based on raw_parsed parameter
            formatted_data = format_whois(
                domain_name=domain,
                parsed_data=parsed_data,
                registry_entry=registry_entry,
                registrar_entry=registrar_entry,
                raw_parsed=raw_parsed,
                whois_server=final_server,
                source=source,
                registry_whois_server=registry_whois_server,
                include_whois_registry=include_whois_registry,
                include_raw_parsed=include_raw_parsed,
            )

            # Mark this server as working for this TLD
            mark_working_server(tld, whois_server)

            return formatted_data

        except Exception as e:
            last_error = e
            # Try next server in the list
            continue

    # If all servers failed, raise the last error
    if last_error:
        raise WhoisError(f"Failed to query {tld} using {len(whois_servers)} server(s): {last_error}")
    else:
        raise WhoisError(f"No WHOIS servers available for TLD: .{tld}")


async def query_domain_async(
    domain: str,
    timeout: float = 10.0,
    max_retries: int = 3,
    raw_parsed: bool = False,
    follow_whois_registrar: bool = True,
    include_whois_registry: bool = True,
    include_raw_parsed: bool = False,
) -> Dict[str, Any]:
    """
    Async version of :func:`query_domain`. Queries domain WHOIS over TCP/43
    using ``asyncio`` (non-blocking).

    All parameters are identical to :func:`query_domain`.

    Returns:
        Dictionary with domain WHOIS data (same structure as :func:`query_domain`).

    Raises:
        WhoisError: If domain is invalid or all WHOIS servers fail.
    """
    if not is_valid_domain(domain):
        raise WhoisError(
            f"Invalid domain format: {domain}. "
            "Domain queries require a valid domain name, not an IP address."
        )

    tld = extract_tld(domain)
    if not tld:
        raise WhoisError(f"Invalid domain: {domain}")

    from .bootstrap import get_all_whois_servers, mark_working_server
    whois_servers = get_all_whois_servers(tld)

    if not whois_servers:
        raise WhoisError(f"No WHOIS server found for TLD: .{tld}")

    from .connection import async_whois_query
    from .parsers import parse_whois
    from .formatter import format_whois

    last_error = None

    for whois_server in whois_servers:
        try:
            response = await async_whois_query(
                whois_server, 43, domain, timeout=timeout, max_retries=max_retries,
            )

            registry_parsed = parse_whois(response)
            registry_entry = {
                "whois_endpoint": whois_server,
                "raw_data": response,
                "parsed": registry_parsed,
            }

            source = "registry"
            registry_whois_server = None
            registrar_entry = None

            if follow_whois_registrar:
                registrar_info = registry_parsed.get('registrar') or {}
                registrar_server = registrar_info.get('whois_server', '').strip()
                if not registrar_server:
                    registrar_server = _get_whois_server_for_registrar(
                        iana_id=registrar_info.get('iana_id'),
                        registrar_name=registrar_info.get('registrar_name'),
                        tld=tld,
                    ) or ''
                if registrar_server and registrar_server != whois_server:
                    try:
                        reg_response = await async_whois_query(
                            registrar_server, 43, domain,
                            timeout=timeout, max_retries=min(max_retries, 2),
                        )
                        reg_parsed = parse_whois(reg_response)
                        registrar_entry = {
                            "whois_endpoint": registrar_server,
                            "raw_data": reg_response,
                            "parsed": reg_parsed,
                        }
                        has_new_contacts = any(
                            reg_parsed.get(k)
                            for k in ('registrant', 'administrative_contact',
                                      'technical_contact', 'billing_contact')
                        )
                        if has_new_contacts:
                            source = "registrar"
                            registry_whois_server = whois_server
                    except Exception:
                        pass  # Non-fatal — registry data is returned

            if registrar_entry:
                parsed_data = _merge_whois_data(registry_parsed, registrar_entry["parsed"])
            else:
                parsed_data = registry_parsed

            final_server = registrar_entry["whois_endpoint"] if source == "registrar" else whois_server

            formatted_data = format_whois(
                domain_name=domain,
                parsed_data=parsed_data,
                registry_entry=registry_entry,
                registrar_entry=registrar_entry,
                raw_parsed=raw_parsed,
                whois_server=final_server,
                source=source,
                registry_whois_server=registry_whois_server,
                include_whois_registry=include_whois_registry,
                include_raw_parsed=include_raw_parsed,
            )

            mark_working_server(tld, whois_server)
            return formatted_data

        except Exception as e:
            last_error = e
            continue

    if last_error:
        raise WhoisError(f"Failed to query {tld} using {len(whois_servers)} server(s): {last_error}")
    else:
        raise WhoisError(f"No WHOIS servers available for TLD: .{tld}")
