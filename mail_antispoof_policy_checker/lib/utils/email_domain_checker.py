"""Email domain checker for detecting if a domain is used for email"""

import dns.exception
from typing import List, Dict, Optional
from .dns_utils import DNSUtils


class EmailDomainChecker:
    """
    Checker for determining if a domain is used for email.

    Detects email usage through four indicators:
    - HAS_MX: Domain has MX (mail exchange) records
    - HAS_SPF: Domain has SPF record
    - HAS_DMARC: Domain has DMARC record on current domain (NOT inherited)
    - HAS_SMTP: Domain has responding SMTP server on port 25

    Usage:
        # Create checker
        checker = EmailDomainChecker(dns_timeout=5)

        # Check a domain
        indicators = checker.check("gmail.com")
        # Returns: ['HAS_MX', 'HAS_SPF', 'HAS_DMARC']

        # Check if domain is used for email
        if checker.is_email_domain("gmail.com"):
            print("This is an email domain")

        # Get cached results
        indicators = checker.get_indicators("gmail.com")
    """

    def __init__(
        self,
        dns_timeout: int = 5,
        nameservers: Optional[List[str]] = None,
        max_retries: int = 3,
        required_indicators: Optional[List[str]] = None,
        available_checks: Optional[List[str]] = None
    ):
        """
        Initialize email domain checker.

        Args:
            dns_timeout: DNS query timeout in seconds
            nameservers: Custom DNS resolver(s) as a list of IPs (e.g., ['1.1.1.1', '8.8.8.8']). If None, uses system default
            max_retries: Maximum retries per DNS server before trying fallback servers (default: 3)
            required_indicators: Minimum indicators to consider domain as "email domain"
                                Default: ['HAS_MX'] (only MX required)
                                Empty list [] means any indicator is sufficient
            available_checks: Which checks to perform
                             Default: ['HAS_MX', 'HAS_SPF', 'HAS_DMARC', 'HAS_SMTP']
                             Use to skip expensive checks like HAS_SMTP
        """
        self.dns_utils = DNSUtils(timeout=dns_timeout, nameservers=nameservers, max_retries=max_retries)
        self._cache: Dict[str, List[str]] = {}

        # Default: Only MX required to consider as email domain
        if required_indicators is None:
            self.required_indicators = ['HAS_MX']
        else:
            self.required_indicators = required_indicators

        # Default: Check all indicators
        if available_checks is None:
            self.available_checks = ['HAS_MX', 'HAS_SPF', 'HAS_DMARC', 'HAS_SMTP']
        else:
            self.available_checks = available_checks

    def check(self, domain: str) -> List[str]:
        """
        Check if a domain is used for email and return the indicators.

        Results are cached for performance.

        Args:
            domain: Domain to check

        Returns:
            List of indicators (e.g., ['HAS_MX', 'HAS_SPF']) or empty list if not an email domain
        """
        # Return cached result if available
        if domain in self._cache:
            return self._cache[domain]

        indicators = []

        # Check for MX records (if enabled)
        if 'HAS_MX' in self.available_checks:
            try:
                if self.dns_utils.has_mx_records(domain):
                    indicators.append('HAS_MX')
            except dns.exception.Timeout:
                # DNS timeout - do not add HAS_MX indicator
                pass
            except Exception:
                # Other exceptions - no MX found
                pass

        # Check if there's SPF on the domain (if enabled)
        if 'HAS_SPF' in self.available_checks:
            try:
                spf_record = self.dns_utils.get_spf_record(domain)
                if spf_record:
                    indicators.append('HAS_SPF')
            except dns.exception.Timeout:
                # DNS timeout - do not add HAS_SPF indicator
                pass
            except Exception:
                # Other exceptions - no SPF found
                pass

        # Check if there's DMARC on the current domain (not inherited from parent) (if enabled)
        if 'HAS_DMARC' in self.available_checks:
            try:
                dmarc_domain = f'_dmarc.{domain}'
                dmarc_record = self.dns_utils.get_txt_record(dmarc_domain, prefix='v=DMARC1')
                if dmarc_record:
                    indicators.append('HAS_DMARC')
            except dns.exception.Timeout:
                # DNS timeout - do not add HAS_DMARC indicator
                # This is different from "no record" - we simply couldn't query
                pass
            except Exception:
                # Other exceptions (NXDOMAIN, NoAnswer, etc.) - no DMARC found
                pass

        # Check if there's an SMTP server responding (if enabled)
        if 'HAS_SMTP' in self.available_checks:
            try:
                if self.dns_utils.has_smtp_server(domain):
                    indicators.append('HAS_SMTP')
            except Exception:
                pass

        # Cache the result
        self._cache[domain] = indicators

        return indicators

    def is_email_domain(self, domain: str) -> bool:
        """
        Check if a domain is used for email based on required indicators.

        Args:
            domain: Domain to check

        Returns:
            True if domain meets required indicator criteria, False otherwise
        """
        indicators = self.check(domain)

        # If no required indicators specified, any indicator is sufficient
        if not self.required_indicators:
            return len(indicators) > 0

        # Check if all required indicators are present
        for required in self.required_indicators:
            if required not in indicators:
                return False

        return True

    def get_indicators(self, domain: str) -> List[str]:
        """
        Get cached email domain indicators for a domain.

        If domain hasn't been checked yet, performs the check.

        Args:
            domain: Domain to get indicators for

        Returns:
            List of indicators or empty list
        """
        return self.check(domain)

    def clear_cache(self):
        """Clear the indicator cache."""
        self._cache.clear()

    def get_cache_size(self) -> int:
        """
        Get the number of cached domain results.

        Returns:
            Number of domains in cache
        """
        return len(self._cache)
