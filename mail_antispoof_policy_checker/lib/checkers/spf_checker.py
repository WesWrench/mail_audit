"""SPF policy checker with advanced dangerous configuration detection"""

import asyncio
import contextlib
import re
import dns.resolver
import dns.exception
import checkdmarc
from typing import List, Dict, Any, Optional, Set, Tuple
from ..models.spf_result import SPFResult, SPFResolutionPath
from ..models.issue import Issue, IssueCategory, IssueSeverity
from ..utils.dns_utils import DNSUtils
from ..utils.ip_utils import IPUtils
from ..utils.maxmind_client import MaxMindClient
from ..utils.async_dns_resolver import AsyncPooledDNSResolver
from ..data.loaders import DataLoaders
from .issue_definitions import IssueDefinitions
from .cname_checker import CNAMEChecker, is_spf_record, DEFAULT_MAX_DEPTH


class SPFChecker:
    """
    Advanced SPF policy checker that extends mailspoof functionality with:
    - Detection of dangerous includes (shared hosting, email delivery services)
    - Detection of dangerous IP ranges
    - MaxMind AS organization checking
    - Full resolution path tracking
    """

    def __init__(
        self,
        maxmind_client: Optional[MaxMindClient] = None,
        data_loaders: Optional[DataLoaders] = None,
        data_dir: str = "./data",
        dns_timeout: int = 5,
        nameservers: Optional[List[str]] = None,
        use_ns_record: bool = False,
        max_dns_retries: int = 3,
        build_ptr_blacklist: bool = False,
        ptr_pool_size: int = 20,
        resolver: Optional[AsyncPooledDNSResolver] = None,
        cname_check: bool = True,
        cname_max_depth: int = DEFAULT_MAX_DEPTH,
    ):
        """
        Initialize SPF checker.

        Args:
            maxmind_client: MaxMind client for AS organization lookups
            data_loaders: Data loaders for dangerous SPF records
            data_dir: Directory containing CSV data files (used if data_loaders not provided)
            dns_timeout: DNS query timeout in seconds
            nameservers: Custom DNS resolver(s) as a list of IPs (e.g., ['1.1.1.1', '8.8.8.8']). If None, uses system default
            use_ns_record: If True, use domain's NS servers for DNS queries
            max_dns_retries: Maximum retries per DNS server before trying fallback servers (default: 3)
            build_ptr_blacklist: If True, build PTR blacklist from dangerous IPs (EXPENSIVE!)
            ptr_pool_size: Number of parallel PTR lookups when building blacklist
            cname_check: If True, check(domain) also inspects a CNAME alias at the
                         domain name itself (where the SPF TXT is looked up)
            cname_max_depth: Maximum number of CNAME links followed by that check
        """
        self.dns_utils = DNSUtils(timeout=dns_timeout, nameservers=nameservers, max_retries=max_dns_retries)
        # Pooled resolver passed to checkdmarc (parse_spf_record).
        # When set, checkdmarc uses it for all include/redirect DNS resolution;
        # its own nameservers/timeout kwargs are ignored.
        # None = checkdmarc creates its own plain resolver (legacy behaviour).
        self._checkdmarc_resolver: Optional[AsyncPooledDNSResolver] = resolver
        # _base_dns_utils always points to the original public resolver.
        # check() may temporarily swap self.dns_utils with an NS-based resolver;
        # _basic_recurse_includes must still use public DNS to resolve external includes
        # (e.g. spf.protection.outlook.com) that an authoritative NS won't answer.
        self._base_dns_utils = self.dns_utils
        # _ns_lock serialises concurrent check() calls when use_ns_record=True.
        # check() temporarily mutates self.dns_utils (not thread-safe); the lock
        # prevents races when check_async() runs multiple domains in parallel.
        # Created lazily inside check_async() so it belongs to the running loop.
        self._ns_lock: Optional[asyncio.Lock] = None
        self.maxmind_client = maxmind_client
        self.data_loaders = data_loaders or DataLoaders(
            data_dir=data_dir,
            disable_ptr_blacklist=not build_ptr_blacklist,
            ptr_pool_size=ptr_pool_size
        )
        self.ip_utils = IPUtils()
        self.use_ns_record = use_ns_record
        # CNAME alias at the SPF lookup name — always resolved through the public
        # resolver (an authoritative NS would not follow an external alias).
        self.cname_checker: Optional[CNAMEChecker] = (
            CNAMEChecker(self._base_dns_utils, max_depth=cname_max_depth) if cname_check else None
        )

        # Load data
        if not self.data_loaders._loaded:
            self.data_loaders.load_all()

    def check(self, domain: str, use_checkdmarc: bool = True) -> SPFResult:
        """
        Check SPF policy for a domain.

        This method does: DNS query → check_record() → check_spf_tree(), then
        (unless disabled) the CNAME chain check at the domain name itself.
        SPF include:/redirect= targets are not part of the CNAME check.

        Args:
            domain: Domain to check
            use_checkdmarc: Whether to use checkdmarc library for parsing (recommended)

        Returns:
            SPFResult object with all findings
        """
        result = self._check_dns(domain, use_checkdmarc)
        if self.cname_checker is not None:
            self.cname_checker.check_and_attach(result, 'SPF', domain, is_spf_record)
        return result

    def _check_dns(self, domain: str, use_checkdmarc: bool = True) -> SPFResult:
        """DNS query → check_record() → check_spf_tree() (see :meth:`check`)."""
        # If use_ns_record enabled, resolve the domain's NS hostnames to IPs and
        # use the first reachable one for both the TXT fetch and checkdmarc's
        # include resolution.  NS records are returned as hostnames (e.g.
        # 'ns2.esa.int') which dnspython rejects as nameserver values — resolve
        # them to IP addresses first.
        original_dns_utils = None
        ns_ips: List[str] = []
        if self.use_ns_record:
            ns_ips = self.dns_utils.get_ns_ips(domain)
            if ns_ips:
                original_dns_utils = self.dns_utils
                self.dns_utils = DNSUtils(
                    timeout=original_dns_utils.timeout,
                    nameservers=ns_ips,
                    max_retries=original_dns_utils.max_retries
                )

        try:
            # Try to get SPF record via DNS
            try:
                spf_record = self.dns_utils.get_spf_record(domain)
            except dns.exception.Timeout:
                result = SPFResult(domain=domain)
                # Create DNS timeout issue (we only scan email domains, so this is always relevant)
                result.add_issue(IssueDefinitions.create_spf_dns_timeout(domain, IssueSeverity.HIGH))
                return result

            if not spf_record:
                result = SPFResult(domain=domain)
                # Check if domain exists
                try:
                    if not self.dns_utils.domain_exists(domain):
                        result.add_issue(IssueDefinitions.create_spf_nx_domain(domain))
                    else:
                        result.add_issue(IssueDefinitions.create_spf_no_spf())
                except dns.exception.Timeout:
                    # Create DNS timeout issue (we only scan email domains, so this is always relevant)
                    result.add_issue(IssueDefinitions.create_spf_dns_timeout(domain, IssueSeverity.HIGH))
                return result

            # Delegate to check_record().
            # NOTE: NS IPs are intentionally NOT forwarded here.
            # parse_spf_record must use public DNS to resolve includes
            # (sendgrid.net, mailjet.com, etc.) — the domain's authoritative NS
            # only knows about its own records, so passing it would cause all
            # external includes to silently return empty results.
            return self.check_record(spf_record, record_id=domain, resolve_includes=use_checkdmarc)
        finally:
            # Restore original DNS utils if we switched to NS-based resolver
            if original_dns_utils is not None:
                self.dns_utils = original_dns_utils

    async def check_async(
        self,
        domains: List[str],
        max_concurrent: int = 50,
        use_checkdmarc: bool = True,
    ) -> List[SPFResult]:
        """Check SPF policy for multiple domains concurrently.

        Uses :func:`asyncio.to_thread` to run blocking DNS calls in a thread
        pool, allowing parallel processing of multiple domains.

        When ``use_ns_record=True`` the per-domain NS lookup temporarily
        mutates ``self.dns_utils`` (not thread-safe).  An
        :class:`asyncio.Lock` serialises those calls automatically.

        Args:
            domains: List of domains to check.
            max_concurrent: Maximum concurrent checks (0 = unlimited).
                            Default: 50.
            use_checkdmarc: Whether to use checkdmarc for parsing.

        Returns:
            List of :class:`SPFResult` in the same order as *domains*.
            Items that raised an unexpected exception are returned as the
            :class:`Exception` instance — callers should check with
            ``isinstance(item, Exception)``.
        """
        # Lazily create the lock inside the running event loop.
        if self.use_ns_record and self._ns_lock is None:
            self._ns_lock = asyncio.Lock()

        sem = asyncio.Semaphore(max_concurrent) if max_concurrent > 0 else None

        async def _check_one(domain: str):
            ctx_sem = sem if sem is not None else contextlib.nullcontext()
            async with ctx_sem:
                if self._ns_lock is not None:
                    async with self._ns_lock:
                        return await asyncio.to_thread(self.check, domain, use_checkdmarc)
                return await asyncio.to_thread(self.check, domain, use_checkdmarc)

        return list(await asyncio.gather(
            *[_check_one(d) for d in domains],
            return_exceptions=True,
        ))

    def check_record(self, spf_record: str, record_id: str = "SPF-Record", resolve_includes: bool = True) -> SPFResult:
        """
        Check an SPF record directly without initial DNS query.

        This method does: Parse with checkdmarc → check_spf_tree()

        Args:
            spf_record: SPF record string (e.g., "v=spf1 include:example.com -all")
            record_id: Identifier for this record (used as domain in result)
            resolve_includes: Whether to resolve includes recursively via DNS (default: True)

        Returns:
            SPFResult object with all findings
        """
        # Use checkdmarc's parse_spf_record for parsing
        try:
            from checkdmarc.spf import parse_spf_record, SPFSyntaxError, SPFTooManyDNSLookups

            # parse_spf_record will make DNS queries to resolve includes if they exist.
            # ignore_too_many_lookups=True: skip unresolvable/NXDOMAIN includes instead of
            # aborting — important for domains with internal DNS names (e.g. _iplist.state.gov).
            parsed_spf = parse_spf_record(
                spf_record,
                record_id,
                parked=False,
                ignore_too_many_lookups=True,
                resolver=self._checkdmarc_resolver,  # None → checkdmarc creates its own
                # timeout/timeout_retries are ignored when resolver= is supplied;
                # kept here as fallback for when resolver=None (legacy path).
                timeout=self.dns_utils.resolver.timeout,
                timeout_retries=self.dns_utils.max_retries,
            )

            # Delegate to check_spf_tree()
            result = self.check_spf_tree(parsed_spf, record_id)

            # Ensure we have the original SPF record
            if not result.spf_record:
                result.spf_record = spf_record

            return result

        except SPFSyntaxError as e:
            # SPF record is not parsable (e.g. commas instead of spaces, unknown mechanisms)
            result = SPFResult(domain=record_id)
            result.spf_record = spf_record
            result.add_issue(IssueDefinitions.create_spf_syntax_error(str(e)))
            return result

        except SPFTooManyDNSLookups as e:
            # RFC 7208 §4.6.4 hard limit (>10 lookups) — real policy issue, partial analysis
            result = SPFResult(domain=record_id)
            result.spf_record = spf_record
            result.add_issue(IssueDefinitions.create_spf_lookup_error())
            self._process_basic_spf(result, spf_record, record_id)
            return result

        except Exception:
            # Unexpected error — fall back to basic parsing, no finding surfaced
            # (not a policy issue visible to email receivers)
            result = SPFResult(domain=record_id)
            result.spf_record = spf_record
            self._process_basic_spf(result, spf_record, record_id)
            return result

    def check_spf_tree(self, parsed_spf: Dict[str, Any], record_id: str = "SPF-Record", store_parsed: bool = True) -> SPFResult:
        """
        Check an already parsed SPF record tree from checkdmarc.

        Args:
            parsed_spf: Parsed SPF structure from checkdmarc (with 'parsed', 'dns_lookups', etc.)
            record_id: Identifier for this record (used as domain in result)
            store_parsed: If True, store the complete parsed structure in result.parsed_spf

        Returns:
            SPFResult object with all findings

        Example:
            >>> from checkdmarc.spf import parse_spf_record
            >>> parsed = parse_spf_record("v=spf1 include:example.com -all", "example.com")
            >>> result = spf_checker.check_spf_tree(parsed, "example.com")
        """
        result = SPFResult(domain=record_id)

        # Extract the SPF record if available
        if 'record' in parsed_spf:
            result.spf_record = parsed_spf['record']

        # Store the complete parsed structure if requested
        if store_parsed:
            result.parsed_spf = parsed_spf

        # Process the parsed structure
        self._process_parsed_spf_record(result, parsed_spf, [record_id])

        return result

    def _process_parsed_spf_record(self, result: SPFResult, parsed_spf: Dict[str, Any], path: List[str]):
        """
        Process results from checkdmarc.spf.parse_spf_record.
        This has a different structure than query_spf_record.

        Args:
            result: SPFResult object to populate
            parsed_spf: Parsed SPF data from parse_spf_record
            path: Current resolution path
        """
        # Get DNS lookup count
        if 'dns_lookups' in parsed_spf:
            result.lookup_count = parsed_spf['dns_lookups']
            if result.lookup_count > 10:
                result.add_issue(IssueDefinitions.create_spf_lookup_error())

        # Check 'all' mechanism
        if 'parsed' in parsed_spf and 'all' in parsed_spf['parsed']:
            all_value = parsed_spf['parsed']['all']
            result.has_all_mechanism = True
            result.all_qualifier = all_value

            if all_value == 'pass' or all_value == '+':
                result.add_issue(IssueDefinitions.create_spf_pass_all())
            elif all_value == 'neutral' or all_value == '?':
                result.add_issue(IssueDefinitions.create_spf_neutral_all())
            elif all_value == 'softfail' or all_value == '~':
                result.add_issue(IssueDefinitions.create_spf_soft_fail_all())
        else:
            result.has_all_mechanism = False
            result.add_issue(IssueDefinitions.create_spf_no_all())

        # Process mechanisms recursively
        if 'parsed' in parsed_spf and 'mechanisms' in parsed_spf['parsed']:
            self._process_mechanisms_list(result, parsed_spf['parsed']['mechanisms'], path)

    def _process_mechanisms_list(self, result: SPFResult, mechanisms: List[Dict[str, Any]], path: List[str]):
        """
        Process a list of mechanisms from parse_spf_record.

        Args:
            result: SPFResult object to populate
            mechanisms: List of mechanism dictionaries
            path: Current resolution path
        """
        for mechanism in mechanisms:
            mech_type = mechanism.get('mechanism', '')
            value = mechanism.get('value', '')

            if mech_type == 'include':
                include_path = path + [f"include:{value}"]

                # Check if this include is dangerous
                dangerous_matches = self.data_loaders.find_dangerous_include(value)
                if dangerous_matches:
                    for match in dangerous_matches:
                        # Get severity using cascade: Service Name > Service Type > Base Severity
                        base_severity = IssueSeverity.CRITICAL if match.service_type == "Shared Hosting" else IssueSeverity.HIGH
                        severity = self.data_loaders.get_severity_for_service(
                            match.service_type,
                            match.service_name,
                            base_severity
                        )

                        issue = IssueDefinitions.create_spf_dangerous_include(
                            value,
                            match.service_type,
                            match.service_name,
                            severity=severity
                        )
                        issue.resolution_path = include_path
                        result.add_issue(issue)

                    # Track for output
                    result.all_includes.append({
                        'include': value,
                        'path': ' -> '.join(include_path),
                        'dangerous': True,
                        'service_type': dangerous_matches[0].service_type,
                        'service_name': dangerous_matches[0].service_name
                    })
                else:
                    # Safe include, add to tracking
                    result.all_includes.append({
                        'include': value,
                        'path': ' -> '.join(include_path),
                        'dangerous': False
                    })

                # Recurse into the included record
                if 'parsed' in mechanism and 'mechanisms' in mechanism['parsed']:
                    self._process_mechanisms_list(result, mechanism['parsed']['mechanisms'], include_path)

            elif mech_type in ['ip4', 'ip6']:
                ip_path = path + [f"{mech_type}:{value}"]
                # Check if it's a range or single IP
                if '/' in value:
                    self._check_dangerous_ip_range(result, value, ip_path)
                else:
                    self._check_dangerous_ip(result, value, ip_path)

            elif mech_type == 'a':
                # Process 'a' mechanism - resolves to A/AAAA records
                # value contains the domain (or current domain if empty)
                # addresses contains the resolved IPs (may be None if DNS lookup failed)
                a_path = path + [f"a:{value}" if value else "a"]
                addresses = mechanism.get('addresses') or []

                # Track explicit domain for unregistered-domain availability check
                if value:
                    result.all_includes.append({
                        'include': f"a:{value}",
                        'path': ' -> '.join(a_path),
                        'dangerous': False
                    })

                # Check if this 'a' issue would be redundant with an existing include/redirect issue
                # Priority: Include/Redirect > IP Range > PTR/MX/A
                if not self._is_ptr_issue_redundant(result, a_path, value if value else result.domain):
                    for ip in addresses:
                        self._check_dangerous_ip(result, ip, a_path)

            elif mech_type == 'mx':
                # Process 'mx' mechanism - resolves MX then A/AAAA
                # value contains the domain (or current domain if empty)
                # hosts is a dict: {mx_host: [ip1, ip2, ...]}
                mx_path = path + [f"mx:{value}" if value else "mx"]
                hosts = mechanism.get('hosts') or {}

                # Track explicit domain for unregistered-domain availability check
                if value:
                    result.all_includes.append({
                        'include': f"mx:{value}",
                        'path': ' -> '.join(mx_path),
                        'dangerous': False
                    })

                # Check if this 'mx' issue would be redundant with an existing include/redirect issue
                # Priority: Include/Redirect > IP Range > PTR/MX/A
                if not self._is_ptr_issue_redundant(result, mx_path, value if value else result.domain):
                    for mx_host, addresses in hosts.items():
                        mx_host_path = mx_path + [mx_host]
                        for ip in addresses:
                            self._check_dangerous_ip(result, ip, mx_host_path)

            elif mech_type == 'ptr':
                # Process 'ptr' mechanism - check if PTR domain is dangerous
                # value contains the domain (or current domain if empty)
                # RFC 7208 § 5.5: ptr mechanism allows any IP with PTR ending in domain
                ptr_path = path + [f"ptr:{value}" if value else "ptr"]
                ptr_domain = value if value else result.domain

                # Track explicit domain for unregistered-domain availability check
                if value:
                    result.all_includes.append({
                        'include': f"ptr:{value}",
                        'path': ' -> '.join(ptr_path),
                        'dangerous': False
                    })

                # Check if this PTR domain is dangerous
                dangerous_matches = self.data_loaders.find_dangerous_ptr_domain(ptr_domain)
                if dangerous_matches:
                    for match in dangerous_matches:
                        # Check if this PTR issue is redundant with an existing include/redirect issue
                        # Priority: Include/Redirect > IP Range > PTR/MX/A
                        # Don't report PTR if the source include is already flagged
                        if self._is_ptr_issue_redundant(result, ptr_path, ptr_domain):
                            continue

                        # Get severity using cascade
                        base_severity = IssueSeverity.CRITICAL if match.service_type == "Shared Hosting" else IssueSeverity.HIGH
                        severity = self.data_loaders.get_severity_for_service(
                            match.service_type,
                            match.service_name,
                            base_severity
                        )

                        issue = IssueDefinitions.create_spf_dangerous_ptr(
                            ptr_domain,
                            match.service_type,
                            match.service_name,
                            severity=severity
                        )
                        issue.resolution_path = ptr_path
                        result.add_issue(issue)

            elif mech_type == 'exists':
                # exists:<domain> — domain checked for existence (often uses macros).
                # Track for unregistered-domain availability check when an explicit domain is given.
                if value:
                    exists_path = path + [f"exists:{value}"]
                    result.all_includes.append({
                        'include': f"exists:{value}",
                        'path': ' -> '.join(exists_path),
                        'dangerous': False
                    })

    def _process_checkdmarc_result(self, result: SPFResult, parsed_spf: Dict[str, Any], domain: str):
        """
        Process results from checkdmarc library.

        Args:
            result: SPFResult object to populate
            parsed_spf: Parsed SPF data from checkdmarc
            domain: Domain being checked
        """
        # Check for warnings (these are mailspoof-like issues)
        if 'warnings' in parsed_spf and parsed_spf['warnings']:
            for warning in parsed_spf['warnings']:
                # Convert checkdmarc warnings to issues
                if 'all' in warning.lower() and 'not' in warning.lower():
                    result.add_issue(IssueDefinitions.create_spf_no_all())
                elif 'lookup' in warning.lower():
                    result.add_issue(IssueDefinitions.create_spf_lookup_error())

        # Get DNS lookup count
        if 'dns_lookups' in parsed_spf:
            result.lookup_count = parsed_spf['dns_lookups']
            if result.lookup_count > 10:
                result.add_issue(IssueDefinitions.create_spf_lookup_error())

        # Check 'all' mechanism
        if 'parsed' in parsed_spf and 'all' in parsed_spf['parsed']:
            all_value = parsed_spf['parsed']['all']
            result.has_all_mechanism = True
            result.all_qualifier = all_value

            if all_value == 'pass' or all_value == '+':
                result.add_issue(IssueDefinitions.create_spf_pass_all())
            elif all_value == 'neutral' or all_value == '?':
                result.add_issue(IssueDefinitions.create_spf_neutral_all())
            elif all_value == 'softfail' or all_value == '~':
                result.add_issue(IssueDefinitions.create_spf_soft_fail_all())
        else:
            result.has_all_mechanism = False
            # Check if redirect is present
            if 'parsed' not in parsed_spf or 'redirect' not in parsed_spf.get('parsed', {}):
                result.add_issue(IssueDefinitions.create_spf_no_all())

        # Process includes, IP ranges, and IP addresses
        self._analyze_spf_mechanisms(result, parsed_spf, [domain])

    def _analyze_spf_mechanisms(self, result: SPFResult, parsed_spf: Dict[str, Any], path: List[str]):
        """
        Recursively analyze SPF mechanisms for dangerous configurations.

        Args:
            result: SPFResult object to populate
            parsed_spf: Parsed SPF data from checkdmarc
            path: Current resolution path
        """
        if 'parsed' not in parsed_spf:
            return

        parsed = parsed_spf['parsed']

        # Helper function to extract clean domain from path element
        def extract_domain(path_element: str) -> str:
            """Extract domain from path elements like 'include:domain' or 'redirect=domain'"""
            if 'include:' in path_element:
                return path_element.split('include:', 1)[1]
            elif 'redirect=' in path_element:
                return path_element.split('redirect=', 1)[1]
            return path_element

        # Process redirect (acts like include but replaces the entire policy)
        # IMPORTANT: redirect= means "abandon my rules and use EXCLUSIVELY those of this domain"
        if 'redirect' in parsed:
            redirect_data = parsed['redirect']
            redirect_domain = redirect_data.get('domain', '') if isinstance(redirect_data, dict) else redirect_data
            redirect_path = path + [f"redirect={redirect_domain}"]

            # Check for trivial recursion (redirect to self or domain already in path)
            domains_in_path = [extract_domain(p) for p in path]
            if redirect_domain in domains_in_path:
                result.add_issue(IssueDefinitions.create_spf_recurse(redirect_domain, path[0]))
                return  # Stop recursion to avoid infinite loop

            # Check if this redirect is dangerous
            dangerous_matches = self.data_loaders.find_dangerous_include(redirect_domain)
            if dangerous_matches:
                for match in dangerous_matches:
                    # Get severity using cascade: Service Name > Service Type > Base Severity
                    base_severity = IssueSeverity.CRITICAL if match.service_type == "Shared Hosting" else IssueSeverity.HIGH
                    severity = self.data_loaders.get_severity_for_service(
                        match.service_type,
                        match.service_name,
                        base_severity
                    )

                    issue = IssueDefinitions.create_spf_dangerous_include(
                        redirect_domain,
                        match.service_type,
                        match.service_name,
                        severity=severity
                    )
                    issue.resolution_path = redirect_path
                    result.add_issue(issue)

                # Add to resolution paths but don't recurse into dangerous redirects
                result.resolution_paths.append(SPFResolutionPath(
                    path=redirect_path,
                    mechanism_type='redirect',
                    value=redirect_domain,
                    issue=dangerous_matches[0] if dangerous_matches else None
                ))

                # Track for output
                result.all_includes.append({
                    'include': f"redirect={redirect_domain}",
                    'path': ' -> '.join(redirect_path),
                    'dangerous': True,
                    'service_type': dangerous_matches[0].service_type,
                    'service_name': dangerous_matches[0].service_name
                })
            else:
                # Safe redirect, add to tracking
                result.all_includes.append({
                    'include': f"redirect={redirect_domain}",
                    'path': ' -> '.join(redirect_path),
                    'dangerous': False
                })

                # Recurse into safe redirects
                if isinstance(redirect_data, dict) and 'dns_lookups' in redirect_data:
                    self._analyze_spf_mechanisms(result, redirect_data, redirect_path)

        # Process includes
        if 'include' in parsed:
            for include_data in parsed['include']:
                include_domain = include_data.get('domain', '')
                include_path = path + [f"include:{include_domain}"]

                # Check for trivial recursion (include to self or domain already in path)
                domains_in_path = [extract_domain(p) for p in path]
                if include_domain in domains_in_path:
                    result.add_issue(IssueDefinitions.create_spf_recurse(include_domain, path[0]))
                    continue  # Skip this include to avoid infinite loop

                # Check if this include is dangerous
                dangerous_matches = self.data_loaders.find_dangerous_include(include_domain)
                if dangerous_matches:
                    for match in dangerous_matches:
                        # Get severity using cascade: Service Name > Service Type > Base Severity
                        base_severity = IssueSeverity.CRITICAL if match.service_type == "Shared Hosting" else IssueSeverity.HIGH
                        severity = self.data_loaders.get_severity_for_service(
                            match.service_type,
                            match.service_name,
                            base_severity
                        )

                        issue = IssueDefinitions.create_spf_dangerous_include(
                            include_domain,
                            match.service_type,
                            match.service_name,
                            severity=severity
                        )
                        issue.resolution_path = include_path
                        result.add_issue(issue)

                    # Add to resolution paths but don't recurse into dangerous includes
                    result.resolution_paths.append(SPFResolutionPath(
                        path=include_path,
                        mechanism_type='include',
                        value=include_domain,
                        issue=dangerous_matches[0] if dangerous_matches else None
                    ))

                    # Track for output
                    result.all_includes.append({
                        'include': include_domain,
                        'path': ' -> '.join(include_path),
                        'dangerous': True,
                        'service_type': dangerous_matches[0].service_type,
                        'service_name': dangerous_matches[0].service_name
                    })
                else:
                    # Safe include, add to tracking
                    result.all_includes.append({
                        'include': include_domain,
                        'path': ' -> '.join(include_path),
                        'dangerous': False
                    })

                    # Recurse into safe includes
                    if 'dns_lookups' in include_data:
                        self._analyze_spf_mechanisms(result, include_data, include_path)

        # Process IP4 and IP6
        for ip_type in ['ip4', 'ip6']:
            if ip_type in parsed:
                for ip_item in parsed[ip_type]:
                    ip_value = ip_item.get('value', '')
                    ip_path = path + [f"{ip_type}:{ip_value}"]

                    # Check if it's a range or single IP
                    if '/' in ip_value:
                        # It's a range
                        self._check_dangerous_ip_range(result, ip_value, ip_path)
                    else:
                        # It's a single IP
                        self._check_dangerous_ip(result, ip_value, ip_path)

        # Process A and MX (these expand to IPs)
        for mechanism in ['a', 'mx']:
            if mechanism in parsed:
                for item in parsed[mechanism]:
                    domain_value = item.get('domain', path[0])
                    item_path = path + [f"{mechanism}:{domain_value}"]
                    # Note: We can't resolve these to IPs without additional DNS queries
                    # Just track them
                    result.all_includes.append({
                        'include': f"{mechanism}:{domain_value}",
                        'path': ' -> '.join(item_path),
                        'dangerous': False
                    })

    def _check_dangerous_ip_range(self, result: SPFResult, ip_range: str, path: List[str]):
        """
        Check if an IP range is dangerous.
        Detects exact matches, subnet matches, and partial overlaps.

        Args:
            result: SPFResult object to populate
            ip_range: IP range in CIDR notation
            path: Resolution path
        """
        # Whitelisted platform space (resolved from Whitelisted_SPF_Include.csv):
        # skip both the dangerous-range tier and the AS-organization tier below.
        # Safe to skip wholesale because precedence is already settled at load time —
        # a whitelist range overlapping declared dangerous data was dropped there, so
        # anything still whitelisted here carries no declared dangerous classification.
        # Requires full containment, so an over-broad range clipping the platform
        # (e.g. 54.0.0.0/8) is still checked.
        whitelisted = self.data_loaders.find_whitelisted_ip_range(ip_range)
        if whitelisted:
            result.all_ip_ranges.append({
                'ip_range': ip_range,
                'path': ' -> '.join(path),
                'dangerous': False,
                'match_type': 'whitelisted',
                'whitelisted_range': whitelisted.ip_range,
                'service_type': whitelisted.service_type,
                'service_name': whitelisted.service_name,
                'source_include': whitelisted.source_include
            })
            return

        # Check against known dangerous ranges
        for dangerous_range in self.data_loaders.dangerous_ip_ranges:
            # SKIP creating issue if this IP was extracted from a dangerous include
            # The include itself already has an issue, so we don't want duplicates.
            # Use exact path-element matching to avoid false positives where source_include
            # is a substring of another domain (e.g. "outlook.com" ⊂ "spf.protection.outlook.com").
            skip_issue = False
            if dangerous_range.source_include:
                exact_forms = {
                    f"include:{dangerous_range.source_include}",
                    f"redirect={dangerous_range.source_include}",
                }
                if any(pe in exact_forms for pe in path):
                    skip_issue = True

            # Case 1: ip_range is a subnet of dangerous_range
            if self.ip_utils.is_range_in_range(ip_range, dangerous_range.ip_range):
                # Only create issue if not from a dangerous include in the path
                if not skip_issue:
                    # Get severity using cascade: Service Name > Service Type > Base Severity
                    base_severity = IssueSeverity.CRITICAL if dangerous_range.service_type == "Shared Hosting" else IssueSeverity.HIGH
                    severity = self.data_loaders.get_severity_for_service(
                        dangerous_range.service_type,
                        dangerous_range.service_name,
                        base_severity
                    )

                    issue = IssueDefinitions.create_spf_dangerous_ip_range(
                        ip_range,
                        dangerous_range.service_type,
                        dangerous_range.service_name,
                        match_type='subnet',
                        dangerous_range=dangerous_range.ip_range,
                        severity=severity
                    )
                    issue.resolution_path = path
                    result.add_issue(issue)

                result.all_ip_ranges.append({
                    'ip_range': ip_range,
                    'path': ' -> '.join(path),
                    'dangerous': True,
                    'match_type': 'subnet',
                    'service_type': dangerous_range.service_type,
                    'service_name': dangerous_range.service_name,
                    'from_dangerous_include': skip_issue  # Mark if this came from a dangerous include
                })
                return

            # Case 2: dangerous_range is a subnet of ip_range
            elif self.ip_utils.is_range_in_range(dangerous_range.ip_range, ip_range):
                # Calculate overlap (which is the entire dangerous_subnet in this case)
                overlap = self.ip_utils.get_range_overlap(ip_range, dangerous_range.ip_range)

                # Only create issue if not from a dangerous include in the path
                if not skip_issue:
                    # Get severity using cascade: Service Name > Service Type > Base Severity
                    base_severity = IssueSeverity.CRITICAL if dangerous_range.service_type == "Shared Hosting" else IssueSeverity.HIGH
                    severity = self.data_loaders.get_severity_for_service(
                        dangerous_range.service_type,
                        dangerous_range.service_name,
                        base_severity
                    )

                    overlap_details = {
                        'overlap_start': overlap['ip_start'] if overlap else None,
                        'overlap_end': overlap['ip_end'] if overlap else None,
                        'overlap_count': overlap['count'] if overlap else None
                    }
                    issue = IssueDefinitions.create_spf_dangerous_ip_range(
                        ip_range,
                        dangerous_range.service_type,
                        dangerous_range.service_name,
                        match_type='contains_dangerous_subnet',
                        dangerous_range=dangerous_range.ip_range,
                        overlap_details=overlap_details,
                        severity=severity
                    )
                    issue.resolution_path = path
                    result.add_issue(issue)

                result.all_ip_ranges.append({
                    'ip_range': ip_range,
                    'path': ' -> '.join(path),
                    'dangerous': True,
                    'match_type': 'contains_dangerous_subnet',
                    'dangerous_subnet': dangerous_range.ip_range,
                    'overlap_start': overlap['ip_start'] if overlap else None,
                    'overlap_end': overlap['ip_end'] if overlap else None,
                    'overlap_count': overlap['count'] if overlap else None,
                    'service_type': dangerous_range.service_type,
                    'service_name': dangerous_range.service_name,
                    'from_dangerous_include': skip_issue  # Mark if this came from a dangerous include
                })
                return

            # Case 3: Partial overlap (neither is a subnet of the other)
            else:
                overlap = self.ip_utils.get_range_overlap(ip_range, dangerous_range.ip_range)
                if overlap:
                    # Only create issue if not from a dangerous include in the path
                    if not skip_issue:
                        # Get severity using cascade: Service Name > Service Type > Base Severity
                        base_severity = IssueSeverity.CRITICAL if dangerous_range.service_type == "Shared Hosting" else IssueSeverity.HIGH
                        severity = self.data_loaders.get_severity_for_service(
                            dangerous_range.service_type,
                            dangerous_range.service_name,
                            base_severity
                        )

                        overlap_details = {
                            'overlap_start': overlap['ip_start'],
                            'overlap_end': overlap['ip_end'],
                            'overlap_count': overlap['count']
                        }
                        issue = IssueDefinitions.create_spf_dangerous_ip_range(
                            ip_range,
                            dangerous_range.service_type,
                            dangerous_range.service_name,
                            match_type='partial_overlap',
                            dangerous_range=dangerous_range.ip_range,
                            overlap_details=overlap_details,
                            severity=severity
                        )
                        issue.resolution_path = path
                        result.add_issue(issue)

                    result.all_ip_ranges.append({
                        'ip_range': ip_range,
                        'path': ' -> '.join(path),
                        'dangerous': True,
                        'match_type': 'partial_overlap',
                        'overlap_start': overlap['ip_start'],
                        'overlap_end': overlap['ip_end'],
                        'overlap_count': overlap['count'],
                        'dangerous_range': dangerous_range.ip_range,
                        'service_type': dangerous_range.service_type,
                        'service_name': dangerous_range.service_name,
                        'from_dangerous_include': skip_issue  # Mark if this came from a dangerous include
                    })
                    return

        # Check using MaxMind if available
        if self.maxmind_client:
            first_ip = self.ip_utils.get_first_ip_in_range(ip_range)
            if first_ip:
                ip_info = self.maxmind_client.get_ip_information(first_ip)
                as_org = ip_info.get('as_organization')

                if as_org:
                    service_matches = self.data_loaders.find_third_party_service(as_org)
                    if service_matches:
                        # Use only the first match to avoid duplicate issues
                        # (CSV may contain multiple entries for same AS org with different casing)
                        match = service_matches[0]

                        # Get severity using cascade: Service Name > Service Type > Base Severity
                        base_severity = IssueSeverity.CRITICAL if match.service_type == "Shared Hosting" else IssueSeverity.HIGH
                        severity = self.data_loaders.get_severity_for_service(
                            match.service_type,
                            match.service_name,
                            base_severity
                        )

                        issue = IssueDefinitions.create_spf_dangerous_as_organization(
                            ip_range,
                            as_org,
                            match.service_type,
                            match.service_name,
                            severity=severity
                        )
                        issue.resolution_path = path
                        result.add_issue(issue)

                        result.all_ip_ranges.append({
                            'ip_range': ip_range,
                            'path': ' -> '.join(path),
                            'dangerous': True,
                            'as_organization': as_org,
                            'service_type': match.service_type,
                            'service_name': match.service_name
                        })
                        return

        # Not dangerous, but track for output
        result.all_ip_ranges.append({
            'ip_range': ip_range,
            'path': ' -> '.join(path),
            'dangerous': False
        })

    def _check_dangerous_ip(self, result: SPFResult, ip: str, path: List[str]):
        """
        Check if an IP address is dangerous.

        Args:
            result: SPFResult object to populate
            ip: IP address
            path: Resolution path
        """
        # Whitelisted platform space — see _check_dangerous_ip_range() for why
        # skipping wholesale is safe here.
        if self.data_loaders.is_whitelisted_ip(ip):
            return

        # Check if IP is in any dangerous range
        for dangerous_range in self.data_loaders.dangerous_ip_ranges:
            if self.ip_utils.is_ip_in_range(ip, dangerous_range.ip_range):
                # SKIP creating issue if this IP was extracted from a dangerous include
                # The include itself already has an issue, so we don't want duplicates.
                # Use exact path-element matching to avoid false positives where source_include
                # is a substring of another domain (e.g. "outlook.com" ⊂ "spf.protection.outlook.com").
                skip_issue = False
                if dangerous_range.source_include:
                    exact_forms = {
                        f"include:{dangerous_range.source_include}",
                        f"redirect={dangerous_range.source_include}",
                    }
                    if any(pe in exact_forms for pe in path):
                        skip_issue = True

                # Only create issue if not from a dangerous include in the path
                if not skip_issue:
                    # Get severity using cascade: Service Name > Service Type > Base Severity
                    base_severity = IssueSeverity.CRITICAL if dangerous_range.service_type == "Shared Hosting" else IssueSeverity.HIGH
                    severity = self.data_loaders.get_severity_for_service(
                        dangerous_range.service_type,
                        dangerous_range.service_name,
                        base_severity
                    )

                    issue = IssueDefinitions.create_spf_dangerous_ip_range(
                        ip,
                        dangerous_range.service_type,
                        dangerous_range.service_name,
                        severity=severity
                    )
                    issue.resolution_path = path
                    result.add_issue(issue)

                result.all_ip_addresses.append({
                    'ip': ip,
                    'path': ' -> '.join(path),
                    'dangerous': True,
                    'dangerous_range': dangerous_range.ip_range,
                    'service_type': dangerous_range.service_type,
                    'service_name': dangerous_range.service_name,
                    'from_dangerous_include': skip_issue  # Mark if this came from a dangerous include
                })
                return

        # Check using MaxMind if available
        if self.maxmind_client:
            ip_info = self.maxmind_client.get_ip_information(ip)
            as_org = ip_info.get('as_organization')

            if as_org:
                service_matches = self.data_loaders.find_third_party_service(as_org)
                if service_matches:
                    # Use only the first match to avoid duplicate issues
                    # (CSV may contain multiple entries for same AS org with different casing)
                    match = service_matches[0]

                    # Get severity using cascade: Service Name > Service Type > Base Severity
                    base_severity = IssueSeverity.CRITICAL if match.service_type == "Shared Hosting" else IssueSeverity.HIGH
                    severity = self.data_loaders.get_severity_for_service(
                        match.service_type,
                        match.service_name,
                        base_severity
                    )

                    issue = IssueDefinitions.create_spf_dangerous_as_organization(
                        ip,
                        as_org,
                        match.service_type,
                        match.service_name,
                        severity=severity
                    )
                    issue.resolution_path = path
                    result.add_issue(issue)

                    result.all_ip_addresses.append({
                        'ip': ip,
                        'path': ' -> '.join(path),
                        'dangerous': True,
                        'as_organization': as_org,
                        'service_type': match.service_type,
                        'service_name': match.service_name
                    })
                    return

        # Not dangerous, but track for output
        result.all_ip_addresses.append({
            'ip': ip,
            'path': ' -> '.join(path),
            'dangerous': False
        })

    def _is_ptr_issue_redundant(self, result: SPFResult, ptr_path: List[str], ptr_domain: str) -> bool:
        """
        Check if a PTR issue is redundant with an existing include/redirect issue.

        Priority hierarchy: Include/Redirect > IP Range > PTR/MX/A
        Don't report PTR if the source include/redirect is already flagged as dangerous.

        Args:
            result: SPFResult object containing existing issues
            ptr_path: Resolution path for this PTR mechanism
            ptr_domain: PTR domain being checked

        Returns:
            True if this PTR issue is redundant and should be skipped
        """
        # Check if any dangerous include/redirect in the path
        for path_element in ptr_path:
            # Extract domain from path element (e.g., "include:mx.ovh.com" → "mx.ovh.com")
            if path_element.startswith('include:'):
                include_domain = path_element.replace('include:', '')
                # Check if this include is dangerous
                if self.data_loaders.find_dangerous_include(include_domain):
                    # This PTR comes from a dangerous include already flagged
                    return True

            elif path_element.startswith('redirect:'):
                redirect_domain = path_element.replace('redirect:', '')
                # Check if this redirect is dangerous (treated like includes)
                if self.data_loaders.find_dangerous_include(redirect_domain):
                    # This PTR comes from a dangerous redirect already flagged
                    return True

        return False

    def _process_basic_spf(self, result: SPFResult, spf_record: str, domain: str):
        """
        Basic SPF processing without checkdmarc (fallback).

        Args:
            result: SPFResult object to populate
            spf_record: Raw SPF record
            domain: Domain being checked
        """
        # Check for 'all' mechanism
        terms = spf_record.split(' ')
        all_qualifier = None
        all_match = re.match(r'^([-?~+])all$', terms[-1])

        if all_match:
            all_qualifier = all_match.group(1)
            result.has_all_mechanism = True
            result.all_qualifier = all_qualifier

            if all_qualifier == '+':
                result.add_issue(IssueDefinitions.create_spf_pass_all())
            elif all_qualifier == '?':
                result.add_issue(IssueDefinitions.create_spf_neutral_all())
            elif all_qualifier == '~':
                result.add_issue(IssueDefinitions.create_spf_soft_fail_all())
        else:
            # Check if redirect is present
            if 'redirect' not in spf_record:
                result.has_all_mechanism = False
                result.add_issue(IssueDefinitions.create_spf_no_all())

        # Basic recursion for includes
        self._basic_recurse_includes(result, domain, [domain])

    def _basic_recurse_includes(self, result: SPFResult, domain: str, path: List[str]):
        """
        Basic recursive include processing.

        Args:
            result: SPFResult object to populate
            domain: Current domain
            path: Resolution path
        """
        try:
            # Always use the base (public) DNS resolver here, not the potentially
            # NS-swapped self.dns_utils.  When use_ns_record=True, self.dns_utils
            # may point to the domain's authoritative NS which cannot resolve
            # external includes like spf.protection.outlook.com.
            spf_record = self._base_dns_utils.get_spf_record(domain)
        except Exception:
            return

        if not spf_record:
            return

        terms = spf_record.split(' ')
        result.lookup_count += 1

        for term in terms:
            # Handle both ':' (include:, redirect:) and '=' (redirect=)
            if ':' in term:
                mechanism, value = term.split(':', 1)
            elif '=' in term:
                mechanism, value = term.split('=', 1)
            else:
                continue

            # Handle ip4 / ip6
            if mechanism in ('ip4', 'ip6'):
                ip_path = path + [f"{mechanism}:{value}"]
                if '/' in value:
                    self._check_dangerous_ip_range(result, value, ip_path)
                else:
                    self._check_dangerous_ip(result, value, ip_path)
                continue

            # Handle include
            if mechanism == 'include':
                include_path = path + [f"include:{value}"]

                # Check for dangerous include
                dangerous_matches = self.data_loaders.find_dangerous_include(value)
                if dangerous_matches:
                    for match in dangerous_matches:
                        # Get severity using cascade: Service Name > Service Type > Base Severity
                        base_severity = IssueSeverity.CRITICAL if match.service_type == "Shared Hosting" else IssueSeverity.HIGH
                        severity = self.data_loaders.get_severity_for_service(
                            match.service_type,
                            match.service_name,
                            base_severity
                        )

                        issue = IssueDefinitions.create_spf_dangerous_include(
                            value,
                            match.service_type,
                            match.service_name,
                            severity=severity
                        )
                        issue.resolution_path = include_path
                        result.add_issue(issue)

                    result.all_includes.append({
                        'include': value,
                        'path': ' -> '.join(include_path),
                        'dangerous': True,
                        'service_type': dangerous_matches[0].service_type,
                        'service_name': dangerous_matches[0].service_name
                    })
                else:
                    result.all_includes.append({
                        'include': value,
                        'path': ' -> '.join(include_path),
                        'dangerous': False
                    })
                    # Recurse into safe includes
                    if result.lookup_count <= 10:
                        self._basic_recurse_includes(result, value, include_path)

            # Handle redirect (same as include but replaces entire policy)
            elif mechanism == 'redirect':
                redirect_path = path + [f"redirect={value}"]

                # Check for dangerous redirect
                dangerous_matches = self.data_loaders.find_dangerous_include(value)
                if dangerous_matches:
                    for match in dangerous_matches:
                        # Get severity using cascade: Service Name > Service Type > Base Severity
                        base_severity = IssueSeverity.CRITICAL if match.service_type == "Shared Hosting" else IssueSeverity.HIGH
                        severity = self.data_loaders.get_severity_for_service(
                            match.service_type,
                            match.service_name,
                            base_severity
                        )

                        issue = IssueDefinitions.create_spf_dangerous_include(
                            value,
                            match.service_type,
                            match.service_name,
                            severity=severity
                        )
                        issue.resolution_path = redirect_path
                        result.add_issue(issue)

                    result.all_includes.append({
                        'include': f"redirect={value}",
                        'path': ' -> '.join(redirect_path),
                        'dangerous': True,
                        'service_type': dangerous_matches[0].service_type,
                        'service_name': dangerous_matches[0].service_name
                    })
                else:
                    result.all_includes.append({
                        'include': f"redirect={value}",
                        'path': ' -> '.join(redirect_path),
                        'dangerous': False
                    })
                    # Recurse into safe redirects
                    if result.lookup_count <= 10:
                        self._basic_recurse_includes(result, value, redirect_path)

            # Track a:/mx:/ptr:/exists: domains for unregistered-domain availability check
            elif mechanism in ('a', 'mx', 'ptr', 'exists') and value:
                mech_path = path + [f"{mechanism}:{value}"]
                result.all_includes.append({
                    'include': f"{mechanism}:{value}",
                    'path': ' -> '.join(mech_path),
                    'dangerous': False
                })

        if result.lookup_count > 10:
            result.add_issue(IssueDefinitions.create_spf_lookup_error())
