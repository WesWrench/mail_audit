"""
Main WhoisClient class for querying RIR WHOIS servers.

This module provides the high-level interface for WHOIS lookups.
"""

import re
import ipaddress
from typing import Dict, Any, Optional, List

from .connection import query_rir, async_query_rir, RIR_SERVERS
from .parsers import RPSLParser, ARINParser
from .parsers.arin_summary_parser import ARINSummaryParser
from .parsers.arin_detailed_parser import ARINDetailedParser
from .parsers.rpsl_detailed_parser import RPSLDetailedParser
from .exceptions import WhoisError, WhoisNotFoundError
from .domain import query_domain, extract_tld


class WhoisClient:
    """
    Comprehensive WHOIS client for all RIRs.

    Supports:
    - IP addresses (IPv4 and IPv6)
    - IP networks/ranges
    - AS numbers
    - Organizations
    - Points of Contact (POCs)
    - All RPSL object types

    Example:
        client = WhoisClient()

        # Lookup IP
        result = client.lookup("8.8.8.8")

        # Lookup ASN
        result = client.lookup("AS15169")

        # Lookup ARIN entity
        result = client.entity("GOGL", rir="arin")

        # Lookup RIPE person
        result = client.entity("DR5299-RIPE", rir="ripe")
    """

    # RIR detection patterns
    RIR_DETECTION = {
        "arin": [
            re.compile(r'-ARIN$', re.I),  # Handles like ZG39-ARIN
            re.compile(r'^C\d{8}$', re.I),  # Customer handles
            re.compile(r'^AS\d+-ARIN$', re.I),  # ASN handles
        ],
        "ripe": [
            re.compile(r'-RIPE$', re.I),  # Handles like DR5299-RIPE
            re.compile(r'-MNT$', re.I),  # Maintainers
        ],
        "afrinic": [
            re.compile(r'-AFRINIC$', re.I),
        ],
        "apnic": [
            re.compile(r'-AP$', re.I),
            re.compile(r'-APNIC$', re.I),
        ],
        "lacnic": [
            re.compile(r'-LACNIC$', re.I),
            re.compile(r'-LAC$', re.I),
        ]
    }

    # ARIN typed query prefixes
    ARIN_QUERY_TYPES = {
        "organization": "o",
        "poc": "p",
        "network": "n",
        "asn": "a",
        "customer": "c"
    }

    # Negative response patterns
    NO_MATCH_PATTERNS = [
        re.compile(r"\bno match\b", re.I),
        re.compile(r"\bnot found\b", re.I),
        re.compile(r"\bno entries found\b", re.I),
        re.compile(r"\bno object found\b", re.I),
        re.compile(r"^%.*no entries found", re.I | re.M),
        re.compile(r"^%.*error:", re.I | re.M),
    ]

    def __init__(self, timeout: float = 10.0):
        """
        Initialize WhoisClient.

        Args:
            timeout: Socket timeout in seconds (default: 10.0)
        """
        self.timeout = timeout

    @staticmethod
    def bootstrap(
        force: bool = False,
        timeout: float = 5.0,
        max_tlds: Optional[int] = None,
        verbose: bool = False,
        tlds_iana_cache: bool = False,
        whois_server_cache: bool = False,
        use_ruby_whois: bool = True
    ) -> Dict[str, str]:
        """
        Bootstrap the TLD WHOIS server cache using multiple sources.

        This static method scrapes the IANA website for the list of TLDs and queries
        IANA's WHOIS server to find the authoritative WHOIS server for each TLD.
        It also uses the Ruby WHOIS library data as a fallback source.
        The results are cached in memory for fast domain lookups.

        This method should be called ONCE at application startup for optimal
        performance when doing multiple domain lookups.

        Args:
            force: If True, re-bootstrap even if already done (default: False)
            timeout: Timeout for each IANA query in seconds (default: 5.0)
            max_tlds: Maximum number of TLDs to process, for testing (default: None = all)
            verbose: If True, print progress information (default: False)
            tlds_iana_cache: If True, use cached TLD list instead of scraping IANA (default: False)
            whois_server_cache: If True, save/load WHOIS server cache from disk (default: False)
            use_ruby_whois: If True, use Ruby WHOIS library data as fallback (default: True)

        Returns:
            None.  Use :func:`get_bootstrap_stats` or :func:`is_bootstrapped`
            to inspect state.  Pass ``verbose=True`` to print progress.

        Raises:
            WhoisError: If bootstrap fails

        Example:
            >>> from whoisitlegacy import WhoisClient
            >>> # Scrape IANA each time, use Ruby WHOIS as fallback
            >>> WhoisClient.bootstrap(verbose=True)
            >>> # Use cached TLDs and WHOIS servers for faster loading
            >>> WhoisClient.bootstrap(tlds_iana_cache=True, whois_server_cache=True)

        Note:
            This method is thread-safe and will only bootstrap once unless
            force=True is specified. The cache is shared across all WhoisClient
            instances.
        """
        from .bootstrap import bootstrap as _bootstrap
        return _bootstrap(
            force=force,
            timeout=timeout,
            max_tlds=max_tlds,
            verbose=verbose,
            tlds_iana_cache=tlds_iana_cache,
            whois_server_cache=whois_server_cache,
            use_ruby_whois=use_ruby_whois
        )

    def _is_no_match(self, response: str) -> bool:
        """Check if response indicates no match/not found."""
        for pattern in self.NO_MATCH_PATTERNS:
            if pattern.search(response):
                return True
        return False

    def _detect_rir_from_handle(self, handle: str) -> Optional[str]:
        """
        Detect RIR from handle pattern.

        Args:
            handle: Entity handle/identifier

        Returns:
            RIR name or None if cannot be determined
        """
        for rir, patterns in self.RIR_DETECTION.items():
            for pattern in patterns:
                if pattern.search(handle):
                    return rir
        return None

    def _detect_rir_from_ip(self, ip: str) -> str:
        """
        Detect RIR from IP address by querying IANA.

        IANA (whois.iana.org) provides authoritative information about
        which RIR is responsible for a given IP address.

        Args:
            ip: IP address

        Returns:
            RIR name (defaults to "arin" if detection fails)
        """
        try:
            # Query IANA to find the authoritative RIR
            response = query_rir("iana", ip, timeout=self.timeout)

            # Parse IANA response to find the whois server reference
            # IANA response contains lines like:
            # whois:        whois.ripe.net
            # or
            # refer:        whois.apnic.net

            response_lower = response.lower()

            # Check for explicit whois server references
            if "whois.ripe.net" in response_lower or "ripencc" in response_lower:
                return "ripe"
            elif "whois.apnic.net" in response_lower:
                return "apnic"
            elif "whois.lacnic.net" in response_lower:
                return "lacnic"
            elif "whois.afrinic.net" in response_lower:
                return "afrinic"
            elif "whois.arin.net" in response_lower:
                return "arin"

            # If no explicit server found, check for RIR mentions
            if "ripe ncc" in response_lower or "ripe" in response_lower:
                return "ripe"
            elif "apnic" in response_lower:
                return "apnic"
            elif "lacnic" in response_lower:
                return "lacnic"
            elif "afrinic" in response_lower:
                return "afrinic"
            elif "arin" in response_lower:
                return "arin"

            # Default to ARIN if nothing matches
            return "arin"

        except Exception:
            # Default to ARIN on error
            return "arin"

    def _build_arin_queries(self, query: str) -> List[str]:
        """
        Build list of ARIN queries to try (with type prefixes).

        Args:
            query: Query string

        Returns:
            List of query strings to try (up to 5 different variations)
        """
        queries = []

        # Detect type and add typed queries
        if re.match(r'^C\d{8}$', query, re.I):
            # Customer handle
            queries.append(f"c {query}")
            queries.append(query)
            queries.append(f"n {query}")
        elif re.match(r'.+-ARIN$', query, re.I):
            # POC handle
            queries.append(f"p {query}")
            queries.append(query)
            queries.append(f"o {query}")
        elif re.match(r'^AS\d+$', query, re.I):
            # ASN
            queries.append(f"a {query}")
            queries.append(query)
            queries.append(f"n {query}")
        elif re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', query) or ':' in query:
            # IP or network
            queries.append(f"n {query}")
            queries.append(query)
        else:
            # Unknown type - try all possibilities
            queries.append(f"o {query}")  # Organization
            queries.append(f"p {query}")  # POC
            queries.append(f"n {query}")  # Network
            queries.append(f"a {query}")  # ASN
            queries.append(query)         # Raw

        return queries

    def lookup(self, query: str, rir: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform WHOIS lookup for any type of object.

        Automatically detects RIR, domain, and object type.

        Args:
            query: Query string (IP, ASN, handle, domain, etc.)
            rir: Optional RIR name to query directly (arin, ripe, afrinic, apnic, lacnic)

        Returns:
            Parsed WHOIS data as dictionary

        Raises:
            WhoisError: If query fails
            WhoisNotFoundError: If object not found

        Example:
            result = client.lookup("8.8.8.8")
            result = client.lookup("AS15169")
            result = client.lookup("GOGL", rir="arin")
            result = client.lookup("google.com")
        """
        # Check if it's a domain name (contains dot and TLD exists)
        if '.' in query and not rir:
            tld = extract_tld(query)
            if tld and len(tld) >= 2:
                # Looks like a domain, try domain lookup
                try:
                    return query_domain(query, timeout=self.timeout)
                except Exception:
                    # If domain lookup fails, continue with IP/RIR lookup
                    pass

        # Auto-detect RIR if not specified
        if not rir:
            # Try to detect from handle pattern
            rir = self._detect_rir_from_handle(query)

            # If still unknown, check if it's an IP
            if not rir:
                try:
                    ipaddress.ip_address(query)
                    rir = self._detect_rir_from_ip(query)
                except ValueError:
                    # Not an IP, default to ARIN for now
                    rir = "arin"

        rir = rir.lower()

        # Query the RIR
        if rir == "arin":
            # ARIN needs special handling with typed queries
            return self._lookup_arin(query)
        else:
            # RPSL-based RIRs
            return self._lookup_rpsl(query, rir)

    def _lookup_arin(self, query: str) -> Dict[str, Any]:
        """
        Lookup on ARIN with typed query attempts.

        Args:
            query: Query string

        Returns:
            Parsed WHOIS data

        Raises:
            WhoisNotFoundError: If not found
        """
        queries = self._build_arin_queries(query)

        last_response = None
        for q in queries:
            try:
                response = query_rir("arin", q, timeout=self.timeout)
                last_response = response

                # Check if valid response
                if not self._is_no_match(response):
                    # Check if this is summary format (IP queries often return this)
                    if ARINSummaryParser.is_summary_format(response):
                        # Get the most specific network handle
                        handle = ARINSummaryParser.get_most_specific_handle(response)
                        if handle:
                            # Query again with the handle for detailed info
                            detail_response = query_rir("arin", handle, timeout=self.timeout)
                            if not self._is_no_match(detail_response):
                                # Use detailed parser to segment into multiple objects
                                return ARINDetailedParser.parse(detail_response)

                    # Parse detailed response with segmentation
                    return ARINDetailedParser.parse(response)

            except Exception:
                continue

        # No valid response found
        raise WhoisNotFoundError(f"Object not found: {query} (tried {len(queries)} queries)")

    def _lookup_rpsl(self, query: str, rir: str) -> Dict[str, Any]:
        """
        Lookup on RPSL-based RIR (RIPE, AfriNIC, APNIC, LACNIC).

        Args:
            query: Query string
            rir: RIR name

        Returns:
            Parsed WHOIS data in RIPE Stat API format

        Raises:
            WhoisNotFoundError: If not found
        """
        response = query_rir(rir, query, timeout=self.timeout)

        # Check if valid response
        if self._is_no_match(response):
            raise WhoisNotFoundError(f"Object not found: {query}")

        # Parse and return using detailed parser (RIPE Stat API format)
        return RPSLDetailedParser.parse(response)

    def entity(
        self,
        handle: str,
        rir: Optional[str] = None,
        entity_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Lookup entity (person, role, organization, POC).

        This is a specialized method for entity lookups, particularly useful for ARIN
        where you need to specify the entity type.

        Args:
            handle: Entity handle (e.g., "GOGL", "ZG39-ARIN", "DR5299-RIPE")
            rir: Optional RIR name
            entity_type: Optional entity type for ARIN ("organization", "poc", "person", "role")

        Returns:
            Parsed entity data

        Raises:
            WhoisError: If query fails
            WhoisNotFoundError: If entity not found

        Example:
            # ARIN organization
            result = client.entity("GOGL", rir="arin", entity_type="organization")

            # ARIN POC
            result = client.entity("ZG39-ARIN", rir="arin")

            # RIPE person
            result = client.entity("DR5299-RIPE")
        """
        # Auto-detect RIR from handle if not specified
        if not rir:
            rir = self._detect_rir_from_handle(handle)
            if not rir:
                raise WhoisError(f"Cannot determine RIR from handle: {handle}")

        rir = rir.lower()

        # For ARIN, build typed query if entity_type is specified
        if rir == "arin" and entity_type:
            prefix = self.ARIN_QUERY_TYPES.get(entity_type.lower())
            if prefix:
                query = f"{prefix} {handle}"
            else:
                query = handle
        else:
            query = handle

        # Use regular lookup
        return self.lookup(query, rir=rir)

    def ip(self, ip_address: str, rir: Optional[str] = None) -> Dict[str, Any]:
        """
        Lookup IP address (convenience method).

        Args:
            ip_address: IPv4 or IPv6 address
            rir: Optional RIR name to query directly

        Returns:
            Parsed WHOIS data for the IP

        Raises:
            WhoisError: If query fails
            WhoisNotFoundError: If IP not found
        """
        return self.lookup(ip_address, rir=rir)

    def asn(self, as_number: int, rir: Optional[str] = None) -> Dict[str, Any]:
        """
        Lookup AS number (convenience method).

        Args:
            as_number: AS number (e.g., 15169)
            rir: Optional RIR name to query directly

        Returns:
            Parsed WHOIS data for the ASN

        Raises:
            WhoisError: If query fails
            WhoisNotFoundError: If ASN not found
        """
        query = f"AS{as_number}"
        return self.lookup(query, rir=rir)

    def domain(
        self,
        domain_name: str,
        raw_parsed: bool = False,
        follow_whois_registrar: bool = True,
        include_whois_registry: bool = True,
        include_raw_parsed: bool = False,
    ) -> Dict[str, Any]:
        """
        Lookup domain name (convenience method).

        Args:
            domain_name: Domain name (e.g., "google.com", "bbc.co.uk")
            raw_parsed: If True, return raw line-by-line parsed format (simple key: value).
                        If False (default), return normalized Whoxy-compatible format.
            follow_whois_registrar: If True (default), follow up with the registrar WHOIS
                                    server to obtain richer contact data.
            include_whois_registry: If True (default), include ``whois_registry`` in the result.
            include_raw_parsed: If True, add a ``raw_parsed`` dict to ``whois_registry`` and
                                ``whois_registrar`` with flat key:value pairs parsed from each
                                server's raw response.

        Returns:
            Parsed WHOIS data for the domain.

        Raises:
            WhoisError: If query fails or domain is invalid
        """
        return query_domain(
            domain_name,
            timeout=self.timeout,
            raw_parsed=raw_parsed,
            follow_whois_registrar=follow_whois_registrar,
            include_whois_registry=include_whois_registry,
            include_raw_parsed=include_raw_parsed,
        )

    async def domain_async(
        self,
        domain_name: str,
        raw_parsed: bool = False,
        follow_whois_registrar: bool = True,
        include_whois_registry: bool = True,
        include_raw_parsed: bool = False,
    ) -> Dict[str, Any]:
        """
        Async version of :meth:`domain`. Non-blocking TCP/43 queries using ``asyncio``.

        Args:
            domain_name: Domain name (e.g., "google.com", "bbc.co.uk")
            raw_parsed: If True, return raw line-by-line parsed format.
            follow_whois_registrar: If True (default), follow up with the registrar WHOIS server.
            include_whois_registry: If True (default), include ``whois_registry`` in the result.
            include_raw_parsed: If True, add ``raw_parsed`` to each source entry.

        Returns:
            Parsed WHOIS data for the domain.

        Raises:
            WhoisError: If query fails or domain is invalid
        """
        from .domain import query_domain_async
        return await query_domain_async(
            domain_name,
            timeout=self.timeout,
            raw_parsed=raw_parsed,
            follow_whois_registrar=follow_whois_registrar,
            include_whois_registry=include_whois_registry,
            include_raw_parsed=include_raw_parsed,
        )

    async def _lookup_arin_async(self, query: str) -> Dict[str, Any]:
        """Async version of :meth:`_lookup_arin`."""
        queries = self._build_arin_queries(query)

        last_response = None
        for q in queries:
            try:
                response = await async_query_rir("arin", q, timeout=self.timeout)
                last_response = response

                if not self._is_no_match(response):
                    if ARINSummaryParser.is_summary_format(response):
                        handle = ARINSummaryParser.get_most_specific_handle(response)
                        if handle:
                            detail_response = await async_query_rir("arin", handle, timeout=self.timeout)
                            if not self._is_no_match(detail_response):
                                return ARINDetailedParser.parse(detail_response)
                    return ARINDetailedParser.parse(response)

            except Exception:
                continue

        raise WhoisNotFoundError(f"Object not found: {query} (tried {len(queries)} queries)")

    async def _lookup_rpsl_async(self, query: str, rir: str) -> Dict[str, Any]:
        """Async version of :meth:`_lookup_rpsl`."""
        response = await async_query_rir(rir, query, timeout=self.timeout)

        if self._is_no_match(response):
            raise WhoisNotFoundError(f"Object not found: {query}")

        return RPSLDetailedParser.parse(response)

    async def _detect_rir_from_ip_async(self, ip: str) -> str:
        """Async version of :meth:`_detect_rir_from_ip`."""
        try:
            response = await async_query_rir("iana", ip, timeout=self.timeout)
            response_lower = response.lower()

            if "whois.ripe.net" in response_lower or "ripencc" in response_lower:
                return "ripe"
            elif "whois.apnic.net" in response_lower:
                return "apnic"
            elif "whois.lacnic.net" in response_lower:
                return "lacnic"
            elif "whois.afrinic.net" in response_lower:
                return "afrinic"
            elif "whois.arin.net" in response_lower:
                return "arin"

            if "ripe ncc" in response_lower or "ripe" in response_lower:
                return "ripe"
            elif "apnic" in response_lower:
                return "apnic"
            elif "lacnic" in response_lower:
                return "lacnic"
            elif "afrinic" in response_lower:
                return "afrinic"

            return "arin"
        except Exception:
            return "arin"

    async def lookup_async(self, query: str, rir: Optional[str] = None) -> Dict[str, Any]:
        """
        Async version of :meth:`lookup`. Non-blocking WHOIS lookup for any object type.

        Args:
            query: Query string (IP, ASN, handle, domain, etc.)
            rir: Optional RIR name to query directly

        Returns:
            Parsed WHOIS data as dictionary

        Raises:
            WhoisError: If query fails
            WhoisNotFoundError: If object not found

        Example:
            result = await client.lookup_async("8.8.8.8")
            result = await client.lookup_async("AS15169")
        """
        import ipaddress as _ipaddress

        # Domain check
        if '.' in query and not rir:
            tld = extract_tld(query)
            if tld and len(tld) >= 2:
                try:
                    return await self.domain_async(query)
                except Exception:
                    pass

        if not rir:
            rir = self._detect_rir_from_handle(query)
            if not rir:
                try:
                    _ipaddress.ip_address(query)
                    rir = await self._detect_rir_from_ip_async(query)
                except ValueError:
                    rir = "arin"

        rir = rir.lower()

        if rir == "arin":
            return await self._lookup_arin_async(query)
        else:
            return await self._lookup_rpsl_async(query, rir)

    async def ip_async(self, ip_address: str, rir: Optional[str] = None) -> Dict[str, Any]:
        """
        Async version of :meth:`ip`. Non-blocking IP address lookup.

        Args:
            ip_address: IPv4 or IPv6 address
            rir: Optional RIR name to query directly

        Returns:
            Parsed WHOIS data for the IP

        Example:
            result = await client.ip_async("8.8.8.8")
        """
        return await self.lookup_async(ip_address, rir=rir)

    async def asn_async(self, as_number: int, rir: Optional[str] = None) -> Dict[str, Any]:
        """
        Async version of :meth:`asn`. Non-blocking ASN lookup.

        Args:
            as_number: AS number (e.g., 15169)
            rir: Optional RIR name to query directly

        Returns:
            Parsed WHOIS data for the ASN

        Example:
            result = await client.asn_async(15169)
        """
        return await self.lookup_async(f"AS{as_number}", rir=rir)

    async def entity_async(
        self,
        handle: str,
        rir: Optional[str] = None,
        entity_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Async version of :meth:`entity`. Non-blocking entity lookup.

        Args:
            handle: Entity handle (e.g., "GOGL", "ZG39-ARIN", "DR5299-RIPE")
            rir: Optional RIR name
            entity_type: Optional entity type for ARIN

        Returns:
            Parsed entity data

        Example:
            result = await client.entity_async("GOGL", rir="arin")
            result = await client.entity_async("DR5299-RIPE")
        """
        if not rir:
            rir = self._detect_rir_from_handle(handle)
            if not rir:
                raise WhoisError(f"Cannot determine RIR from handle: {handle}")

        rir = rir.lower()

        if rir == "arin" and entity_type:
            prefix = self.ARIN_QUERY_TYPES.get(entity_type.lower())
            query = f"{prefix} {handle}" if prefix else handle
        else:
            query = handle

        return await self.lookup_async(query, rir=rir)

    @staticmethod
    async def bootstrap_async(
        force: bool = False,
        timeout: float = 5.0,
        max_tlds: Optional[int] = None,
        verbose: bool = False,
        max_workers: int = 40,
        tlds_iana_cache: bool = False,
        whois_server_cache: bool = False,
        use_ruby_whois: bool = True,
    ) -> None:
        """
        Async version of :meth:`bootstrap`. Uses ``asyncio.gather`` with a semaphore
        for non-blocking concurrent IANA queries.

        Args:
            force: Re-bootstrap even if already complete.
            timeout: Per-TLD query timeout in seconds.
            max_tlds: Limit the number of TLDs processed (testing).
            verbose: Print progress information.
            max_workers: Maximum concurrent IANA queries (default: 40).
            tlds_iana_cache: If True, use cached TLD list.
            whois_server_cache: If True, load from on-disk cache.
            use_ruby_whois: If True, use Ruby WHOIS library data as base layer.

        Example:
            >>> import asyncio
            >>> from whoisitlegacy import WhoisClient
            >>> asyncio.run(WhoisClient.bootstrap_async())
            >>> asyncio.run(WhoisClient.bootstrap_async(whois_server_cache=True))
        """
        from .bootstrap import bootstrap_async as _bootstrap_async
        await _bootstrap_async(
            force=force,
            timeout=timeout,
            max_tlds=max_tlds,
            verbose=verbose,
            max_workers=max_workers,
            tlds_iana_cache=tlds_iana_cache,
            whois_server_cache=whois_server_cache,
            use_ruby_whois=use_ruby_whois,
        )
