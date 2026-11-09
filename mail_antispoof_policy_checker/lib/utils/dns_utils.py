"""DNS utilities for checking records"""

import dns.exception
import dns.rdatatype
import dns.resolver
from dataclasses import dataclass, field
from typing import Optional, List, Tuple


# ── Classified DNS outcome (used by the CNAME chain checks) ───────────────────
# NXDOMAIN / NODATA are definitive answers; SERVFAIL, REFUSED, TIMEOUT and
# ERROR are *indeterminate* and must never be read as "name does not exist".

STATUS_NOERROR  = "NOERROR"    # answer with records of the requested type
STATUS_NODATA   = "NODATA"     # name exists, no record of the requested type
STATUS_NXDOMAIN = "NXDOMAIN"   # name does not exist
STATUS_SERVFAIL = "SERVFAIL"
STATUS_REFUSED  = "REFUSED"
STATUS_TIMEOUT  = "TIMEOUT"
STATUS_ERROR    = "ERROR"

INDETERMINATE_STATUSES = frozenset({STATUS_SERVFAIL, STATUS_REFUSED, STATUS_TIMEOUT, STATUS_ERROR})


def _normalize_name(name: str) -> str:
    return str(name).rstrip('.').lower()


@dataclass
class DNSQueryOutcome:
    """Result of :meth:`DNSUtils.query_classified` — never raises, always classified."""

    name: str
    rdtype: str
    status: str
    records: List[str] = field(default_factory=list)
    # CNAME links observed in the answer section, in chain order: [(owner, target), ...].
    # Kept even when the final rcode is NXDOMAIN (alias present, target absent).
    cname_chain: List[Tuple[str, str]] = field(default_factory=list)
    server: Optional[str] = None
    error: Optional[str] = None

    @property
    def indeterminate(self) -> bool:
        return self.status in INDETERMINATE_STATUSES

    def to_dict(self) -> dict:
        result = {'name': self.name, 'rdtype': self.rdtype, 'status': self.status}
        if self.records:
            result['records'] = self.records
        if self.cname_chain:
            result['cname_chain'] = [list(link) for link in self.cname_chain]
        if self.server:
            result['server'] = self.server
        if self.error:
            result['error'] = self.error
        return result


def _extract_cname_chain(response, qname: str) -> List[Tuple[str, str]]:
    """Return the CNAME links of *response*'s answer section, ordered from *qname*."""
    if response is None:
        return []
    links = {}
    for rrset in response.answer:
        if rrset.rdtype != dns.rdatatype.CNAME:
            continue
        owner = _normalize_name(rrset.name.to_text())
        for rdata in rrset:
            links[owner] = _normalize_name(rdata.target.to_text())
    chain: List[Tuple[str, str]] = []
    current = _normalize_name(qname)
    seen = set()
    while current in links and current not in seen:
        seen.add(current)
        chain.append((current, links[current]))
        current = links[current]
    return chain


def _rdata_to_text(rdata, rdtype: str) -> str:
    if rdtype == 'TXT':
        chunks = getattr(rdata, "strings", None)
        if chunks is not None:
            return b"".join(chunks).decode("utf-8", errors="replace")
        return str(rdata).strip('"')
    if rdtype == 'CNAME':
        return _normalize_name(rdata.target.to_text())
    return rdata.to_text()


class DNSUtils:
    """Utilities for DNS operations"""

    def __init__(
        self,
        timeout: int = 5,
        nameservers: Optional[List[str]] = None,
        max_retries: int = 3,
        fallback_dns_servers: Optional[List[str]] = None
    ):
        """
        Initialize DNS utilities.

        Args:
            timeout: DNS query timeout in seconds
            nameservers: Custom DNS resolver(s) to use, as a list of IPs
                        (e.g., ['1.1.1.1', '8.8.8.8']). A bare string is also
                        accepted for convenience. If None, uses system default.
            max_retries: Maximum number of retries per DNS server (default: 3)
            fallback_dns_servers: List of fallback DNS servers to try if primary times out
                                 If None, defaults to ['8.8.8.8', '1.1.1.1']
        """
        # Accept a list of resolvers; tolerate a bare string.
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.timeout = timeout
        self.max_retries = max_retries
        self.nameservers = list(nameservers) if nameservers else None
        self.primary_dns_server = self.nameservers[0] if self.nameservers else None

        # Set fallback DNS servers
        if fallback_dns_servers is None:
            self.fallback_dns_servers = ['8.8.8.8', '1.1.1.1']
        else:
            self.fallback_dns_servers = fallback_dns_servers

        if self.nameservers:
            self.resolver.nameservers = list(self.nameservers)

    def _query_with_retry(self, domain: str, record_type: str):
        """
        Query DNS with retry mechanism across multiple DNS servers.

        Strategy:
        1. Try primary/configured DNS server up to max_retries times
        2. If all fail with timeout, try fallback DNS servers (e.g., 8.8.8.8, 1.1.1.1)
        3. If still timeout, try the domain's NS servers
        4. If all attempts timeout, raise dns.exception.Timeout

        Args:
            domain: Domain to query
            record_type: DNS record type (e.g., 'TXT', 'MX', 'NS', 'A')

        Returns:
            DNS answer object

        Raises:
            dns.exception.Timeout: If all retry attempts timeout
            Other dns exceptions: NXDOMAIN, NoAnswer, etc.
        """
        import dns.exception

        # List of DNS server configurations to try
        dns_configs_to_try = []

        # 1. Primary/configured DNS server (try max_retries times)
        current_nameservers = self.resolver.nameservers.copy()
        for _ in range(self.max_retries):
            dns_configs_to_try.append(current_nameservers)

        # 2. Fallback DNS servers (Google, Cloudflare)
        for fallback_server in self.fallback_dns_servers:
            dns_configs_to_try.append([fallback_server])

        # 3. Try to get NS servers for the domain (only if not querying NS itself)
        if record_type != 'NS':
            try:
                # Use a temporary resolver with fallback DNS to get NS records
                temp_resolver = dns.resolver.Resolver()
                temp_resolver.nameservers = self.fallback_dns_servers
                temp_resolver.timeout = self.timeout
                temp_resolver.lifetime = self.timeout
                ns_answers = temp_resolver.resolve(domain, 'NS')
                ns_servers = [str(rdata.target).rstrip('.') for rdata in ns_answers]
                if ns_servers:
                    # Resolve NS server hostnames to IPs
                    for ns_server in ns_servers[:2]:  # Limit to first 2 NS servers
                        try:
                            ns_ips_answers = temp_resolver.resolve(ns_server, 'A')
                            ns_ips = [str(rdata) for rdata in ns_ips_answers]
                            if ns_ips:
                                dns_configs_to_try.append(ns_ips[:1])  # Use first IP
                        except Exception:
                            continue
            except Exception:
                # Could not get NS servers, skip this step
                pass

        # Try each DNS configuration
        last_exception = None
        for i, nameservers in enumerate(dns_configs_to_try):
            try:
                # Create a new resolver for this attempt
                resolver = dns.resolver.Resolver()
                resolver.nameservers = nameservers
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout

                # Attempt query
                return resolver.resolve(domain, record_type)

            except dns.exception.Timeout as e:
                last_exception = e
                # Continue to next DNS server
                continue
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
                # These are NOT timeout errors - they are definitive answers
                # Re-raise immediately without retry
                raise
            except Exception as e:
                # Other exceptions, save and continue
                last_exception = e
                continue

        # All attempts failed with timeout
        if isinstance(last_exception, dns.exception.Timeout):
            raise last_exception
        elif last_exception:
            raise last_exception
        else:
            raise dns.exception.Timeout()

    def query_classified(self, name: str, record_type: str) -> DNSQueryOutcome:
        """
        Query *name* / *record_type* and classify the outcome instead of raising.

        Unlike :meth:`_query_with_retry`, the CNAME links present in the answer
        section are preserved for every rcode — including NXDOMAIN, where a
        recursive resolver returns the alias chain followed by the missing target.

        Retry strategy: the configured servers ``max_retries`` times, then each
        fallback server.  Only indeterminate outcomes (timeout, SERVFAIL,
        REFUSED, other errors) are retried; NXDOMAIN / NODATA / NOERROR are
        definitive and returned immediately.

        Args:
            name: Fully-qualified name to query
            record_type: DNS record type (e.g. 'TXT', 'CNAME')

        Returns:
            DNSQueryOutcome (never raises)
        """
        attempts: List[List[str]] = [list(self.resolver.nameservers)] * max(1, self.max_retries)
        attempts += [[server] for server in self.fallback_dns_servers]

        last: Optional[DNSQueryOutcome] = None
        for nameservers in attempts:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = nameservers
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            server = ','.join(str(ns) for ns in nameservers)
            try:
                answer = resolver.resolve(name, record_type, raise_on_no_answer=False)
                chain = _extract_cname_chain(answer.response, name)
                if answer.rrset is None:
                    return DNSQueryOutcome(name, record_type, STATUS_NODATA, cname_chain=chain, server=server)
                records = [_rdata_to_text(rdata, record_type) for rdata in answer.rrset]
                return DNSQueryOutcome(name, record_type, STATUS_NOERROR, records, chain, server)
            except dns.resolver.NXDOMAIN as e:
                chain: List[Tuple[str, str]] = []
                for response in e.responses().values():
                    chain = _extract_cname_chain(response, name) or chain
                return DNSQueryOutcome(name, record_type, STATUS_NXDOMAIN, cname_chain=chain, server=server)
            except dns.resolver.NoNameservers as e:
                status = STATUS_REFUSED if 'REFUSED' in str(e) else STATUS_SERVFAIL
                last = DNSQueryOutcome(name, record_type, status, server=server, error=str(e))
            except dns.exception.Timeout as e:
                last = DNSQueryOutcome(name, record_type, STATUS_TIMEOUT, server=server, error=str(e))
            except Exception as e:
                last = DNSQueryOutcome(name, record_type, STATUS_ERROR, server=server,
                                       error=f"{type(e).__name__}: {e}")
        return last or DNSQueryOutcome(name, record_type, STATUS_ERROR, error="no nameserver configured")

    def get_txt_record(self, domain: str, prefix: Optional[str] = None) -> Optional[str]:
        """
        Get a TXT record for a domain, optionally filtered by prefix.
        Uses retry mechanism with multiple DNS servers.

        Args:
            domain: Domain to query
            prefix: Optional prefix to filter records (e.g., 'v=spf1 ')

        Returns:
            TXT record as string, or None if not found

        Raises:
            dns.exception.Timeout: If all DNS servers timeout
        """
        try:
            txt_records = self._query_with_retry(domain, 'TXT')
            for txt_record in txt_records:
                # rdata.strings is the authoritative list of <=255-byte chunks
                chunks = getattr(txt_record, "strings", None)

                if chunks is None:
                    # Fallback: old/odd behavior; keep previous logic as a last resort
                    value = str(txt_record).strip('"')
                else:
                    # Join chunks exactly; decode safely
                    value = b"".join(chunks).decode("utf-8", errors="replace")

                # Normalize prefix matching (some callers pass "v=spf1 " with a trailing space)
                if prefix is None:
                    return value
                if value.startswith(prefix) or value.lstrip().startswith(prefix):
                    return value
            return None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, ValueError):
            return None
        except dns.exception.Timeout:
            raise

    def get_spf_record(self, domain: str) -> Optional[str]:
        """
        Get the SPF record for a domain.

        Args:
            domain: Domain to query

        Returns:
            SPF record as string (with double quotes removed), or None if not found
        """
        record = self.get_txt_record(domain, prefix='v=spf1 ')
        # Remove double quotes that might split long SPF records
        return record.replace('"', '') if record else None

    def get_dmarc_record(self, domain: str) -> Optional[str]:
        """
        Get the DMARC record for a domain.

        Args:
            domain: Domain to query (will be prefixed with _dmarc.)

        Returns:
            DMARC record as string, or None if not found
        """
        dmarc_domain = f'_dmarc.{domain}'
        return self.get_txt_record(dmarc_domain, prefix='v=DMARC1')

    def get_dkim_record(self, selector: str, domain: str) -> Optional[str]:
        """
        Get the DKIM record for a domain and selector.

        Args:
            selector: DKIM selector
            domain: Domain to query

        Returns:
            DKIM record as string, or None if not found
        """
        dkim_domain = f'{selector}._domainkey.{domain}'
        return self.get_txt_record(dkim_domain)

    def domain_exists(self, domain: str) -> bool:
        """
        Check if a domain exists (has DNS records).
        Uses retry mechanism with multiple DNS servers.

        Args:
            domain: Domain to check

        Returns:
            True if domain exists, False otherwise
        """
        try:
            self._query_with_retry(domain, 'A')
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            # Domain might exist but no A record, or timeout
            return True

    def get_ns_servers(self, domain: str) -> List[str]:
        """
        Get NS (nameserver) records for a domain.
        Uses retry mechanism with multiple DNS servers.

        Args:
            domain: Domain to query

        Returns:
            List of nameserver hostnames, or empty list if not found
        """
        try:
            answers = self._query_with_retry(domain, 'NS')
            return [str(rdata.target).rstrip('.') for rdata in answers]
        except Exception:
            return []

    def resolve_hostname_to_ip(self, hostname: str) -> Optional[str]:
        """
        Resolve a hostname to its first A record IP address.

        Uses fallback resolvers (e.g. 8.8.8.8, 1.1.1.1) to avoid circular
        dependency when the hostname belongs to the domain being queried.

        Args:
            hostname: Hostname to resolve (e.g. 'ns2.esa.int')

        Returns:
            IP address string, or None if resolution failed
        """
        for server in self.fallback_dns_servers:
            try:
                r = dns.resolver.Resolver()
                r.nameservers = [server]
                r.timeout = self.timeout
                r.lifetime = self.timeout
                answers = r.resolve(hostname, 'A')
                return str(answers[0])
            except Exception:
                continue
        return None

    def get_ns_ips(self, domain: str) -> List[str]:
        """
        Get IP addresses of the authoritative NS servers for a domain.

        Resolves each NS hostname returned by get_ns_servers() to its
        first A record, skipping any that cannot be resolved.

        Args:
            domain: Domain to query

        Returns:
            List of IP address strings (may be empty)
        """
        ns_ips: List[str] = []
        for ns_hostname in self.get_ns_servers(domain):
            ip = self.resolve_hostname_to_ip(ns_hostname)
            if ip:
                ns_ips.append(ip)
        return ns_ips

    def has_mx_records(self, domain: str) -> bool:
        """
        Check if a domain has MX (mail exchange) records.
        Uses retry mechanism with multiple DNS servers.

        Args:
            domain: Domain to query

        Returns:
            True if domain has MX records, False otherwise

        Raises:
            dns.exception.Timeout: If all DNS servers timeout
        """
        try:
            answers = self._query_with_retry(domain, 'MX')
            return len(answers) > 0
        except dns.exception.Timeout:
            # Re-raise timeout so calling code can distinguish from "no MX"
            raise
        except Exception:
            return False

    def has_smtp_server(self, domain: str, timeout: int = 5) -> bool:
        """
        Check if a domain has a responding SMTP server.
        Attempts to connect to port 25 (SMTP) on the domain's A record.
        Uses retry mechanism with multiple DNS servers.

        Args:
            domain: Domain to check
            timeout: Connection timeout in seconds

        Returns:
            True if SMTP server responds, False otherwise
        """
        import smtplib
        import socket

        try:
            # Get the A record (IP address) for the domain
            answers = self._query_with_retry(domain, 'A')
            if not answers:
                return False

            # Try first IP address
            ip = str(answers[0])

            # Attempt SMTP connection
            smtp = smtplib.SMTP(timeout=timeout)
            smtp.connect(ip, 25)
            smtp.quit()
            return True

        except (socket.timeout, socket.error, smtplib.SMTPException, Exception):
            return False
