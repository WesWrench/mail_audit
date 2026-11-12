"""DKIM policy checker with selector discovery and key validation"""

import asyncio
import base64
import contextlib
import dns.exception
from typing import List, Optional, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.backends import default_backend
from ..models.dkim_result import DKIMResult, DKIMSelectorInfo
from ..models.issue import IssueSeverity
from ..utils.dns_utils import DNSUtils, DNSQueryOutcome, STATUS_NOERROR, STATUS_TIMEOUT
from ..utils.factordb import FactorDBClient
from ..utils.rsa_key_checks import (
    EXPONENT_STANDARD, is_probable_prime, parse_rsa_spki, rate_exponent, small_prime_factor,
)
from .issue_definitions import IssueDefinitions
from .cname_checker import CNAMEChecker, DEFAULT_MAX_DEPTH, DEFAULT_WILDCARD_PROBES

SUPPORTED_KEY_TYPES = ('rsa', 'ed25519')
ED25519_KEY_BYTES = 32  # RFC 8463: p= holds the raw public key, not a DER structure


class DKIMChecker:
    """
    DKIM policy checker that:
    - Discovers DKIM selectors from a known list
    - Reads the key type (k=, default rsa) and checks p= against it
    - Reports weak / perfectible RSA keys (size thresholds apply to RSA only)
    - Rates the RSA public exponent (e=1 / e=3 dangerous, e != 65537 non-standard)
    - Detects RSA keys whose private key anyone can compute: small factor, prime
      modulus (offline), or factorization published on factordb.com (optional)
    - Detects broken / suspicious CNAME chains at selector names, with
      wildcard probing to avoid enumeration false positives
    """

    factordb: Optional[FactorDBClient] = None   # factordb.com client (None = no lookup)

    def __init__(
        self,
        selector_file: str = "./data/DKIM_Selectors.txt",
        dns_timeout: int = 5,
        nameservers: Optional[List[str]] = None,
        max_dns_retries: int = 3,
        cname_check: bool = True,
        cname_max_depth: int = DEFAULT_MAX_DEPTH,
        wildcard_probes: int = DEFAULT_WILDCARD_PROBES,
        factordb: Optional[FactorDBClient] = None,
    ):
        """
        Initialize DKIM checker.

        Args:
            selector_file: Path to file containing DKIM selectors (one per line,
                           blank lines and lines starting with '#' ignored).
                           Use it to replace the bundled list with a custom one.
            dns_timeout: DNS query timeout in seconds
            nameservers: Custom DNS resolver(s) as a list of IPs (e.g., ['1.1.1.1', '8.8.8.8']). If None, uses system default
            max_dns_retries: Maximum retries per DNS server before trying fallback servers (default: 3)
            cname_check: If True, CNAME chains found at selector names are checked
            cname_max_depth: Maximum number of CNAME links followed
            wildcard_probes: Random sibling names probed per selector parent (min 3)
            factordb: Client used to look each RSA modulus up on factordb.com
                      (None = no network lookup; the offline checks always run)
        """
        self.dns_utils = DNSUtils(timeout=dns_timeout, nameservers=nameservers, max_retries=max_dns_retries)
        self.selector_file = selector_file
        self.selectors = self._load_selectors(selector_file)
        self.factordb = factordb
        self.cname_checker: Optional[CNAMEChecker] = (
            CNAMEChecker(self.dns_utils, max_depth=cname_max_depth, wildcard_probes=wildcard_probes)
            if cname_check else None
        )

    @staticmethod
    def load_selector_file(selector_file: str) -> List[str]:
        """
        Read a DKIM selector list (one per line, '#' comments, duplicates removed).

        Raises:
            FileNotFoundError: If *selector_file* does not exist
        """
        selectors: List[str] = []
        seen = set()
        with open(selector_file, 'r', encoding='utf-8-sig') as f:
            for line in f:
                selector = line.strip()
                if not selector or selector.startswith('#') or selector in seen:
                    continue
                seen.add(selector)
                selectors.append(selector)
        return selectors

    def _load_selectors(self, selector_file: str) -> List[str]:
        """
        Load DKIM selectors from file.

        Args:
            selector_file: Path to selector file

        Returns:
            List of selector strings (empty if the file does not exist)
        """
        try:
            return self.load_selector_file(selector_file)
        except FileNotFoundError:
            return []

    def check_selector(self, domain: str, selector: str) -> DKIMResult:
        """
        Check a specific DKIM selector for a domain.

        Args:
            domain: Domain to check
            selector: DKIM selector (e.g., "default", "google", "s1")

        Returns:
            DKIMResult object with findings for this selector
        """
        result = DKIMResult(domain=domain)
        result.selectors_tested = [selector]

        try:
            selector_info = self._check_selector(selector, domain)
            if selector_info.found:
                result.add_selector(selector_info)
            else:
                result.add_issue(IssueDefinitions.create_dkim_no_selectors_found())
        except dns.exception.Timeout:
            # DKIM is brute force - timeouts are expected, don't create issues
            pass

        if self.cname_checker is not None:
            name, outcome = self._query_selector(selector, domain)
            if self.cname_checker.needs_chain_check(outcome):
                self._check_cnames(result, [(selector, name, outcome)])

        return result

    def check(self, domain: str, custom_selectors: Optional[List[str]] = None) -> DKIMResult:
        """
        Check DKIM configuration for a domain by trying multiple selectors.

        Args:
            domain: Domain to check
            custom_selectors: Optional list of custom selectors to check in addition to the default list

        Returns:
            DKIMResult object with all findings
        """
        result = DKIMResult(domain=domain)

        # Combine default and custom selectors
        selectors_to_test = self.selectors.copy()
        if custom_selectors:
            selectors_to_test.extend(custom_selectors)

        result.selectors_tested = selectors_to_test

        # Test each selector (one TXT query each; the outcome also carries any
        # CNAME seen in the answer section, so aliases cost no extra query)
        cname_candidates: List[Tuple[str, str, DNSQueryOutcome]] = []
        for selector in selectors_to_test:
            name, outcome = self._query_selector(selector, domain)
            if self.cname_checker is not None and self.cname_checker.needs_chain_check(outcome):
                cname_candidates.append((selector, name, outcome))
            if outcome.status == STATUS_TIMEOUT:
                # DKIM is brute force - timeouts are expected, don't create issues
                continue
            selector_info = self._check_selector(selector, domain, outcome)
            if selector_info.found:
                result.add_selector(selector_info)

        # If no selectors found, report it
        if not result.selectors_found:
            result.add_issue(IssueDefinitions.create_dkim_no_selectors_found())

        self._check_cnames(result, cname_candidates)

        return result

    def _check_cnames(self, result: DKIMResult, candidates: List[Tuple[str, str, DNSQueryOutcome]]) -> None:
        """Run the CNAME chain + wildcard checks on selectors that need it."""
        if self.cname_checker is None or not candidates:
            return
        # Recorded as evidence only; issues come from the registration check
        result.cname_checks.extend(self.cname_checker.check_dkim_selectors(candidates, self._is_dkim_record))

    def _is_dkim_record(self, txt: str) -> bool:
        """True if *txt* is a DKIM key record (has a p= tag, even empty/revoked)."""
        return 'public_key' in (self._parse_dkim_record(txt) or {})

    def _query_selector(self, selector: str, domain: str) -> Tuple[str, DNSQueryOutcome]:
        """TXT lookup of ``<selector>._domainkey.<domain>`` (classified, never raises)."""
        name = f'{selector}._domainkey.{domain}'
        return name, self.dns_utils.query_classified(name, 'TXT')

    async def check_async(
        self,
        domains: List[str],
        max_concurrent: int = 50,
        custom_selectors: Optional[List[str]] = None,
    ) -> List[DKIMResult]:
        """Check DKIM configuration for multiple domains concurrently.

        Uses :func:`asyncio.to_thread` to run blocking DNS calls in a thread
        pool.

        Args:
            domains: List of domains to check.
            max_concurrent: Maximum concurrent checks (0 = unlimited).
                            Default: 50.
            custom_selectors: Optional list of extra DKIM selectors to probe.

        Returns:
            List of :class:`DKIMResult` in the same order as *domains*.
            Unexpected exceptions are returned as :class:`Exception` instances.
        """
        sem = asyncio.Semaphore(max_concurrent) if max_concurrent > 0 else None

        async def _check_one(domain: str):
            ctx_sem = sem if sem is not None else contextlib.nullcontext()
            async with ctx_sem:
                return await asyncio.to_thread(self.check, domain, custom_selectors)

        return list(await asyncio.gather(
            *[_check_one(d) for d in domains],
            return_exceptions=True,
        ))

    def check_record(self, dkim_record: str, selector: str = "default", record_id: str = "DKIM-Record") -> DKIMResult:
        """
        Check a DKIM record directly without DNS queries.

        Args:
            dkim_record: DKIM record string (e.g., "v=DKIM1; k=rsa; p=MIGfMA0G...")
            selector: Selector name (for tracking purposes)
            record_id: Identifier for this record (used as domain in result)

        Returns:
            DKIMResult object with all findings
        """
        result = DKIMResult(domain=record_id)
        result.selectors_tested = [selector]

        # Parse and validate the DKIM record
        selector_info = self._parse_dkim_record_string(dkim_record, selector)

        if selector_info.found:
            result.add_selector(selector_info)
        else:
            result.add_issue(IssueDefinitions.create_dkim_no_selectors_found())

        return result

    def _parse_dkim_record_string(self, dkim_record: str, selector: str) -> DKIMSelectorInfo:
        """
        Parse a DKIM record string and extract key information.

        Args:
            dkim_record: DKIM record string
            selector: Selector name

        Returns:
            DKIMSelectorInfo object
        """
        selector_info = DKIMSelectorInfo(selector=selector, found=False)

        if not dkim_record:
            return selector_info

        selector_info.found = True
        selector_info.record = dkim_record

        # Validate DKIM record format
        if not dkim_record.startswith('v=DKIM1'):
            error_message = f"DKIM record must start with 'v=DKIM1', found: '{dkim_record[:20]}...'"
            selector_info.issues.append(IssueDefinitions.create_dkim_syntax_error(selector, error_message))
            return selector_info

        # Report malformed tags
        for part in dkim_record.split(';'):
            part = part.strip()
            if part and '=' not in part:
                error_message = f"Invalid DKIM tag format (missing '='): '{part}'"
                selector_info.issues.append(IssueDefinitions.create_dkim_syntax_error(selector, error_message))

        # Validate required 'p' tag (public key)
        key_data = self._parse_dkim_record(dkim_record) or {}
        if 'public_key' not in key_data:
            error_message = "DKIM record missing required 'p' (public key) tag"
            selector_info.issues.append(IssueDefinitions.create_dkim_syntax_error(selector, error_message))
            return selector_info

        self._check_key(selector_info, key_data, selector)
        return selector_info

    def _check_selector(
        self, selector: str, domain: str, outcome: Optional[DNSQueryOutcome] = None
    ) -> DKIMSelectorInfo:
        """
        Check a specific DKIM selector.

        Args:
            selector: DKIM selector
            domain: Domain to check
            outcome: TXT lookup outcome already fetched by :meth:`_query_selector`.
                     When omitted, the record is queried via ``get_dkim_record``.

        Returns:
            DKIMSelectorInfo object
        """
        selector_info = DKIMSelectorInfo(selector=selector, found=False)

        # Query DKIM record (first TXT string, as get_dkim_record returns)
        if outcome is not None:
            dkim_record = outcome.records[0] if outcome.status == STATUS_NOERROR and outcome.records else None
        else:
            dkim_record = self.dns_utils.get_dkim_record(selector, domain)

        if not dkim_record:
            return selector_info

        selector_info.found = True
        selector_info.record = dkim_record

        # Parse DKIM record
        key_data = self._parse_dkim_record(dkim_record)

        if not key_data:
            return selector_info

        self._check_key(selector_info, key_data, selector)
        return selector_info

    def _check_key(self, selector_info: DKIMSelectorInfo, key_data: dict, selector: str) -> None:
        """Check the p= value against the k= value and record the findings on *selector_info*."""
        selector_info.public_key = key_data.get('public_key')
        selector_info.key_type = key_data.get('key_type', 'rsa')

        # No p= (not a key record) or empty p= (revoked key): nothing to inspect
        if not selector_info.public_key:
            return

        key_size, error_message = self._inspect_key(selector_info.key_type, selector_info.public_key)
        if error_message:
            selector_info.issues.append(IssueDefinitions.create_dkim_syntax_error(selector, error_message))
            return

        selector_info.key_size = key_size
        if selector_info.key_type == 'rsa':
            issue = self._rsa_key_size_issue(selector, key_size)
            if issue:
                selector_info.issues.append(issue)
            numbers = parse_rsa_spki(base64.b64decode(selector_info.public_key))
            if numbers:
                self._check_rsa_numbers(selector_info, selector, *numbers)

    def _check_rsa_numbers(self, selector_info: DKIMSelectorInfo, selector: str, n: int, e: int) -> None:
        """Exponent rating, then "can anyone compute the private key?" checks on (n, e).

        Offline (trial division below 2^16, Miller-Rabin primality) and factordb.com
        when a client is configured. factordb is queried even after an offline finding:
        its information box ("Interesting number. ...") tells where the key comes from
        (e.g. a Logjam DH prime). One finding at most; an offline source wins.
        """
        selector_info.rsa_exponent = e
        rating, reason = rate_exponent(e)
        if rating != EXPONENT_STANDARD:
            selector_info.issues.append(
                IssueDefinitions.create_dkim_rsa_exponent_issue(selector, e, rating, reason))

        key_size = n.bit_length()
        lookup = self.factordb.lookup(n) if self.factordb is not None else None
        factordb = lookup.to_dict() if lookup is not None else None
        selector_info.factordb = factordb

        factor = small_prime_factor(n)
        if factor:
            source, digits = 'small_factor', [len(str(factor))]
        elif is_probable_prime(n):
            source, digits = 'prime_modulus', None
        elif lookup is not None and lookup.factor_known:
            source, digits = 'factordb', [len(str(f)) for f in lookup.factors]
        else:
            return
        selector_info.issues.append(IssueDefinitions.create_dkim_rsa_known_factorization(
            selector, key_size, source, factor_digits=digits, factordb=factordb))

    @staticmethod
    def _inspect_key(key_type: str, public_key_b64: str) -> Tuple[Optional[int], Optional[str]]:
        """
        Read a p= value as a key of type *key_type*.

        Args:
            key_type: Lowercase value of the k= tag ('rsa' when absent, RFC 6376)
            public_key_b64: Base64-encoded value of the p= tag, without whitespace

        Returns:
            (key size in bits, None) if the key is usable, (None, error message) otherwise
        """
        if key_type not in SUPPORTED_KEY_TYPES:
            return None, f"Unsupported key type 'k={key_type}'. Supported types: rsa, ed25519"

        try:
            raw_key = base64.b64decode(public_key_b64, validate=True)
        except ValueError as e:
            return None, f"Invalid base64 encoding in public key: {e}"

        try:
            der_key = serialization.load_der_public_key(raw_key, backend=default_backend())
        except Exception:
            der_key = None

        if isinstance(der_key, rsa.RSAPublicKey):
            algorithm = 'RSA'
        elif isinstance(der_key, ed25519.Ed25519PublicKey):
            algorithm = 'Ed25519'
        elif isinstance(der_key, ec.EllipticCurvePublicKey):
            algorithm = 'EC'
        else:
            algorithm = 'unsupported' if der_key is not None else None

        if key_type == 'ed25519':
            if algorithm == 'Ed25519':
                return None, "k=ed25519 requires the raw 32-byte public key (RFC 8463), found a DER-wrapped key"
            if algorithm:
                return None, f"k=ed25519 is declared but p= holds a {algorithm} key"
            if len(raw_key) != ED25519_KEY_BYTES:
                return None, f"k=ed25519 requires a raw 32-byte public key (RFC 8463), found {len(raw_key)} bytes"
            return ED25519_KEY_BYTES * 8, None

        if algorithm == 'RSA':
            return der_key.key_size, None
        # An RSA SubjectPublicKeyInfo that cryptography refuses to load because of its
        # exponent (e < 3): still an RSA key, rated by the exponent check.
        numbers = parse_rsa_spki(raw_key) if der_key is None else None
        if numbers:
            return numbers[0].bit_length(), None
        if algorithm:
            return None, f"k=rsa (declared or default) but p= holds a {algorithm} key"
        if len(raw_key) == ED25519_KEY_BYTES:
            return None, "k=rsa (declared or default) but p= looks like a raw Ed25519 key: is k=ed25519 missing?"
        return None, "Invalid RSA public key format in p="

    @staticmethod
    def _rsa_key_size_issue(selector: str, key_size: int):
        """Weak RSA key (< 1024 bits, high) or perfectible RSA key (= 1024 bits, low); None otherwise."""
        if key_size < 1024:
            return IssueDefinitions.create_dkim_rsa_weak_key(selector, key_size)
        if key_size == 1024:
            return IssueDefinitions.create_dkim_rsa_perfectible_key(selector, key_size)
        return None

    def _parse_dkim_record(self, dkim_record: str) -> Optional[dict]:
        """
        Parse DKIM TXT record to extract key information.

        Args:
            dkim_record: Raw DKIM TXT record

        Returns:
            Dictionary with parsed data or None
        """
        result = {}

        # Remove quotes and newlines
        dkim_record = dkim_record.replace('"', '').replace('\n', '').replace('\r', '')

        # Split into tags
        tags = [tag.strip() for tag in dkim_record.split(';') if tag.strip()]

        for tag in tags:
            if '=' not in tag:
                continue

            key, value = tag.split('=', 1)
            key = key.strip()
            value = value.strip()

            if key == 'p':
                result['public_key'] = ''.join(value.split())
            elif key == 'k':
                result['key_type'] = value.lower()

        return result if result else None
