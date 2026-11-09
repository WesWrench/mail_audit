"""PTR (reverse DNS) utilities for SPF checking"""

import dns.resolver
import dns.reversename
import tldextract
from typing import List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed


class PTRUtils:
    """Utilities for PTR (reverse DNS) operations"""

    @staticmethod
    def reverse_lookup(ip: str, timeout: int = 5) -> Optional[str]:
        """
        Perform reverse PTR lookup for an IP address.

        Args:
            ip: IP address to lookup
            timeout: DNS query timeout in seconds

        Returns:
            PTR record (hostname) or None if not found

        Example:
            >>> PTRUtils.reverse_lookup("8.8.8.8")
            'dns.google'
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout

            # Convert IP to reverse DNS name (e.g., 8.8.8.8 → 8.8.8.8.in-addr.arpa)
            rev_name = dns.reversename.from_address(ip)

            # Query PTR record
            answers = resolver.resolve(rev_name, "PTR")
            if answers:
                # Return first PTR record, strip trailing dot
                return str(answers[0]).rstrip('.')
            return None

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return None
        except dns.exception.Timeout:
            return None
        except Exception:
            return None

    @staticmethod
    def extract_domain_hierarchy(ptr_record: str) -> List[str]:
        """
        Extract domain hierarchy from a PTR record.

        Uses tldextract to properly handle TLDs and extract meaningful domain levels.

        Args:
            ptr_record: PTR record hostname (e.g., "mail.server.example.com")

        Returns:
            List of domains from most specific to least specific

        Example:
            >>> PTRUtils.extract_domain_hierarchy("mail.server.ovh.com")
            ['mail.server.ovh.com', 'server.ovh.com', 'ovh.com']

            >>> PTRUtils.extract_domain_hierarchy("test.mail.google.com")
            ['test.mail.google.com', 'mail.google.com', 'google.com']
        """
        if not ptr_record:
            return []

        # Use tldextract to get the registered domain
        ext = tldextract.extract(ptr_record)

        # Get the full registered domain (domain + suffix)
        registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else None

        if not registered_domain:
            return []

        hierarchy = []

        # Split into parts
        parts = ptr_record.lower().split('.')

        # Build hierarchy from full hostname down to registered domain
        for i in range(len(parts)):
            subdomain = '.'.join(parts[i:])

            # Add to hierarchy
            hierarchy.append(subdomain)

            # Stop at registered domain level
            if subdomain == registered_domain:
                break

        return hierarchy

    @staticmethod
    def batch_reverse_lookup(
        ips: List[str],
        pool_size: int = 20,
        timeout: int = 5
    ) -> List[dict]:
        """
        Perform reverse PTR lookups for multiple IPs in parallel.

        Args:
            ips: List of IP addresses
            pool_size: Number of parallel lookups
            timeout: DNS query timeout per IP

        Returns:
            List of dictionaries: [{"ip": "1.2.3.4", "ptr": "mail.example.com"}, ...]

        Example:
            >>> ips = ["8.8.8.8", "1.1.1.1"]
            >>> results = PTRUtils.batch_reverse_lookup(ips)
            >>> print(results)
            [{'ip': '8.8.8.8', 'ptr': 'dns.google'}, {'ip': '1.1.1.1', 'ptr': 'one.one.one.one'}]
        """
        results = []

        with ThreadPoolExecutor(max_workers=pool_size) as executor:
            # Submit all lookup tasks
            future_to_ip = {
                executor.submit(PTRUtils.reverse_lookup, ip, timeout): ip
                for ip in ips
            }

            # Collect results as they complete
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    ptr = future.result()
                    results.append({
                        'ip': ip,
                        'ptr': ptr
                    })
                except Exception:
                    results.append({
                        'ip': ip,
                        'ptr': None
                    })

        return results

    @staticmethod
    def build_ptr_blacklist_from_ips(
        ips: List[str],
        pool_size: int = 20,
        timeout: int = 5
    ) -> Set[str]:
        """
        Build a PTR domain blacklist from a list of IPs.

        For each IP:
        1. Perform reverse PTR lookup
        2. Extract domain hierarchy
        3. Add all levels to blacklist

        Args:
            ips: List of dangerous IPs
            pool_size: Number of parallel PTR lookups
            timeout: DNS query timeout per IP

        Returns:
            Set of PTR domains to blacklist

        Example:
            >>> ips = ["1.2.3.4"]  # Suppose PTR is mail.server.ovh.com
            >>> blacklist = PTRUtils.build_ptr_blacklist_from_ips(ips)
            >>> print(blacklist)
            {'mail.server.ovh.com', 'server.ovh.com', 'ovh.com'}
        """
        blacklist = set()

        # Perform batch PTR lookups
        ptr_results = PTRUtils.batch_reverse_lookup(ips, pool_size, timeout)

        # Extract domain hierarchies
        for result in ptr_results:
            ptr = result.get('ptr')
            if ptr:
                hierarchy = PTRUtils.extract_domain_hierarchy(ptr)
                blacklist.update(hierarchy)

        return blacklist

    @staticmethod
    def ptr_matches_domain(ptr_record: str, domain: str) -> bool:
        """
        Check if a PTR record ends with a specific domain (RFC 7208 § 5.5).

        This implements the SPF ptr mechanism matching logic.

        Args:
            ptr_record: PTR record hostname
            domain: Domain to check against

        Returns:
            True if PTR ends with domain, False otherwise

        Example:
            >>> PTRUtils.ptr_matches_domain("mail.server.example.com", "example.com")
            True
            >>> PTRUtils.ptr_matches_domain("mail.server.example.com", "other.com")
            False
        """
        if not ptr_record or not domain:
            return False

        ptr_lower = ptr_record.lower()
        domain_lower = domain.lower()

        # Exact match
        if ptr_lower == domain_lower:
            return True

        # Check if ends with ".domain"
        if ptr_lower.endswith('.' + domain_lower):
            return True

        return False
