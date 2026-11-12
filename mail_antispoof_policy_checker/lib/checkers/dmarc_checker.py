"""DMARC policy checker"""

import asyncio
import contextlib
import re
import dns.exception
from typing import Optional, Dict, Any, List
from ..models.dmarc_result import DMARCResult
from ..models.issue import IssueSeverity
from ..utils.dns_utils import DNSUtils, STATUS_NXDOMAIN
from ..utils.async_dns_resolver import AsyncPooledDNSResolver
from .issue_definitions import IssueDefinitions
from .cname_checker import CNAMEChecker, is_dmarc_record, DEFAULT_MAX_DEPTH


# Parsing and validation are delegated to checkdmarc >= 6 (RFC 9989 / DMARCbis):
# it understands np / psd / t, ignores unknown tags (with a warning), and returns
# every tag with an ``explicit`` flag (sp / np / adkim / aspf are always present,
# filled with their defaults when not published).
#
# One RFC 7489 tag is read here: ``pct``. RFC 9989 removed it, so checkdmarc drops
# it from ``tags``, but receivers that still implement RFC 7489 apply it.
_PCT_RE = re.compile(r"(?:^|;)\s*pct\s*=\s*(\d{1,3})\s*(?:;|$)", re.IGNORECASE)


def _legacy_pct(dmarc_record: Optional[str]) -> Optional[int]:
    """``pct=`` value of *dmarc_record* (RFC 7489), or None when absent/invalid."""
    match = _PCT_RE.search((dmarc_record or "").strip('"'))
    if not match:
        return None
    pct = int(match.group(1))
    return pct if 0 <= pct <= 100 else None


def _parse_dmarc_tags(dmarc_record: str) -> Dict[str, str]:
    """Minimal ``tag=value`` tokeniser, only for the last-resort fallback
    (:meth:`DMARCChecker._process_basic_dmarc`) when checkdmarc fails unexpectedly.
    Tag names are lower-cased; the first occurrence of a tag wins."""
    tags: Dict[str, str] = {}
    for term in (dmarc_record or "").strip('"').split(";"):
        key, sep, value = term.partition("=")
        key = key.strip().lower()
        if sep and key and key not in tags:
            tags[key] = value.strip()
    return tags


class DMARCChecker:
    """
    DMARC policy checker that validates DMARC configurations.
    """

    def __init__(
        self,
        dns_timeout: int = 5,
        nameservers: Optional[List[str]] = None,
        use_ns_record: bool = False,
        max_dns_retries: int = 3,
        resolver: Optional[AsyncPooledDNSResolver] = None,
        cname_check: bool = True,
        cname_max_depth: int = DEFAULT_MAX_DEPTH,
    ):
        """
        Initialize DMARC checker.

        Args:
            dns_timeout: DNS query timeout in seconds
            nameservers: Custom DNS resolver(s) as a list of IPs (e.g., ['1.1.1.1', '8.8.8.8']). If None, uses system default
            use_ns_record: If True, use domain's NS servers for DNS queries
            max_dns_retries: Maximum retries per DNS server before trying fallback servers (default: 3)
            resolver: Optional AsyncPooledDNSResolver passed to checkdmarc's parse_dmarc_record.
                      When set, checkdmarc uses it for all DNS resolution; its own
                      nameservers/timeout kwargs are ignored.  None = legacy behaviour.
            cname_check: If True, check(domain) also inspects a CNAME alias at
                         _dmarc.<domain>
            cname_max_depth: Maximum number of CNAME links followed by that check
        """
        self.dns_utils = DNSUtils(timeout=dns_timeout, nameservers=nameservers, max_retries=max_dns_retries)
        self.use_ns_record = use_ns_record
        self._checkdmarc_resolver: Optional[AsyncPooledDNSResolver] = resolver
        self.cname_checker: Optional[CNAMEChecker] = (
            CNAMEChecker(self.dns_utils, max_depth=cname_max_depth) if cname_check else None
        )

    def check(self, domain: str, use_checkdmarc: bool = True) -> DMARCResult:
        """
        Check DMARC policy for a domain.
        This method does: DNS query → check_record() → check_parsed_dmarc()

        Implements RFC 7489 subdomain DMARC lookup:
        - For subdomains: First check _dmarc.subdomain.domain.tld
        - If not found: Check _dmarc.domain.tld (organizational domain)

        Args:
            domain: Domain to check
            use_checkdmarc: Whether to use checkdmarc library for parsing (recommended)

        A CNAME alias at ``_dmarc.<domain>`` is then checked (unless disabled).
        A broken alias is reported as a broken reference only: the
        organizational-domain fallback may still provide a policy.

        Returns:
            DMARCResult object with all findings
        """
        result = self._check_dns(domain, use_checkdmarc)
        if self.cname_checker is not None:
            self.cname_checker.check_and_attach(result, 'DMARC', f'_dmarc.{domain}', is_dmarc_record)
        return result

    def _check_dns(self, domain: str, use_checkdmarc: bool = True) -> DMARCResult:
        """DNS query → check_record() → check_parsed_dmarc() (see :meth:`check`)."""
        # Organizational domain from the Public Suffix List (news.exemple.co.uk ->
        # exemple.co.uk), not the last two labels.
        organizational_domain = self._organizational_domain(domain)
        is_subdomain = organizational_domain != domain.rstrip('.').lower()

        dmarc_record = None
        dmarc_domain_checked = domain

        # Try to get DMARC record via DNS
        try:
            # First, try the exact domain (including subdomain if present)
            dmarc_record = self.dns_utils.get_dmarc_record(domain)

            # If subdomain and no record found, try organizational domain (RFC 7489)
            # RFC 7489: Jump directly to organizational domain (no hierarchical walk)
            if not dmarc_record and is_subdomain:
                dmarc_record = self.dns_utils.get_dmarc_record(organizational_domain)
                if dmarc_record:
                    dmarc_domain_checked = organizational_domain

        except dns.exception.Timeout:
            result = DMARCResult(domain=domain)
            # Create DNS timeout issue (we only scan email domains, so this is always relevant)
            result.add_issue(IssueDefinitions.create_dmarc_dns_timeout(domain, IssueSeverity.HIGH))
            return result

        if not dmarc_record:
            result = DMARCResult(domain=domain)
            result.add_issue(IssueDefinitions.create_dmarc_no_dmarc())
            return result

        # Delegate to check_record() with the actual domain that had the DMARC record
        result = self.check_record(dmarc_record, record_id=domain)

        # Store which domain was actually checked for DMARC
        result.dmarc_domain_checked = dmarc_domain_checked

        if dmarc_domain_checked != domain:
            # RFC 9091: a NON-EXISTENT subdomain (NXDOMAIN) inherits the org record's
            # np= (if present); an existing one inherits sp=. Only resolve existence
            # here, in the inherited branch, to pick the right tag.
            is_nonexistent = self._is_nonexistent_domain(domain)
            self._apply_inherited_policy(result, dmarc_record, organizational_domain, is_nonexistent)

        return result

    def _is_nonexistent_domain(self, domain: str) -> bool:
        """RFC 9091 'non-existent domain': the name returns NXDOMAIN (no DNS records
        of any type). Only a definitive NXDOMAIN counts — NODATA (name exists with no
        A record), an answer, or any indeterminate result (timeout / SERVFAIL) is NOT
        treated as non-existent, so a policy is never wrongly relaxed on uncertainty."""
        try:
            return self.dns_utils.query_classified(domain, 'A').status == STATUS_NXDOMAIN
        except Exception:
            return False

    @staticmethod
    def _organizational_domain(domain: str) -> str:
        """Organizational domain (RFC 7489 §3.2) via the Public Suffix List.

        Delegates to :func:`lib.utils.org_domains.organizational_domain` so the
        PSL logic lives in one place (shared with the org-parent derivation).
        """
        from ..utils.org_domains import organizational_domain
        return organizational_domain(domain)

    @staticmethod
    def _apply_inherited_policy(result: DMARCResult, org_record: str, org_domain: str,
                               is_nonexistent: bool = False) -> None:
        """Subdomain without its own _dmarc record: apply the org record's policy.

        RFC 7489 §6.6.3 / RFC 9091 §3.3: when the record comes from the organizational
        domain, the policy applied depends on whether the queried subdomain exists:

        * **existing** subdomain -> ``sp=`` if present, else ``p=``;
        * **non-existent** subdomain (NXDOMAIN) -> ``np=`` if present, else ``sp=``,
          else ``p=`` (so a domain with ``sp=none`` but ``np=reject`` is correctly
          enforcing for a spoof of one of its non-existent subdomains — no false
          "spoofable" scenario).

        ``policy`` / ``subdomain_policy`` are set to that effective value and the
        lax-policy issues are recomputed from it (the org's own ``p=`` is kept in
        ``organizational_policy``; the org's ``np=`` in ``np_policy``).

        *result* comes from :meth:`check_record` on *org_record*: its ``subdomain_policy``
        and ``np_policy`` already hold checkdmarc's resolved values (sp defaults to p;
        np defaults to an explicit sp, else p). Only the name of the tag that supplied
        the value is derived here, from checkdmarc's ``explicit`` flags.
        """
        explicit = DMARCChecker._explicit_tags(result, org_record)
        org_p = result.policy
        if is_nonexistent:
            effective = result.np_policy or result.subdomain_policy or org_p
            source_tag = next((t for t in ('np', 'sp') if t in explicit), 'p')
        else:
            effective = result.subdomain_policy or org_p
            source_tag = 'sp' if 'sp' in explicit else 'p'

        result.organizational_policy = org_p
        result.policy_inherited_from = f"{org_domain} ({source_tag}={effective})"
        result.policy = effective
        result.subdomain_policy = effective

        lax_codes = (IssueDefinitions.DMARC_LAX_POLICY, IssueDefinitions.DMARC_LAX_SUBDOMAIN_POLICY)
        result.issues = [i for i in result.issues if i.code not in lax_codes]
        if effective and effective not in ('reject', 'quarantine'):
            result.add_issue(IssueDefinitions.create_dmarc_lax_policy(
                effective, inherited_from=result.policy_inherited_from))

    @staticmethod
    def _explicit_tags(result: DMARCResult, record: Optional[str] = None) -> set:
        """Tags actually published in the record (checkdmarc ``explicit`` flag).
        Falls back to a plain tokenisation when no checkdmarc parse is available."""
        tags = (result.parsed_dmarc or {}).get('tags')
        if isinstance(tags, dict):
            return {t for t, v in tags.items() if isinstance(v, dict) and v.get('explicit')}
        return set(_parse_dmarc_tags(record or result.dmarc_record or ''))

    async def check_async(
        self,
        domains: List[str],
        max_concurrent: int = 50,
        use_checkdmarc: bool = True,
    ) -> List[DMARCResult]:
        """Check DMARC policy for multiple domains concurrently.

        Uses :func:`asyncio.to_thread` to run blocking DNS calls in a thread
        pool.

        Args:
            domains: List of domains to check.
            max_concurrent: Maximum concurrent checks (0 = unlimited).
                            Default: 50.
            use_checkdmarc: Passed through to :meth:`check`.

        Returns:
            List of :class:`DMARCResult` in the same order as *domains*.
            Unexpected exceptions are returned as :class:`Exception` instances.
        """
        sem = asyncio.Semaphore(max_concurrent) if max_concurrent > 0 else None

        async def _check_one(domain: str):
            ctx_sem = sem if sem is not None else contextlib.nullcontext()
            async with ctx_sem:
                return await asyncio.to_thread(self.check, domain, use_checkdmarc)

        return list(await asyncio.gather(
            *[_check_one(d) for d in domains],
            return_exceptions=True,
        ))

    def check_record(self, dmarc_record: str, record_id: str = "DMARC-Record") -> DMARCResult:
        """
        Check a DMARC record directly without initial DNS query.
        This method does: Parse with checkdmarc → check_parsed_dmarc()

        Args:
            dmarc_record: DMARC record string (e.g., "v=DMARC1; p=reject; rua=mailto:...")
            record_id: Identifier for this record (used as domain in result)

        Returns:
            DMARCResult object with all findings
        """
        from checkdmarc.dmarc import (
            parse_dmarc_record,
            DMARCSyntaxError,
            InvalidDMARCTag,
            InvalidDMARCTagValue,
            InvalidDMARCReportURI,
            MultipleDMARCRecords,
        )

        def _error_result() -> DMARCResult:
            result = DMARCResult(domain=record_id)
            result.dmarc_record = dmarc_record
            return result

        try:
            # May make DNS queries (external report URI authorization). Uses the
            # pooled resolver when set; checkdmarc then ignores timeout/retries.
            parsed_dmarc = parse_dmarc_record(
                dmarc_record,
                record_id,
                include_tag_descriptions=False,
                resolver=self._checkdmarc_resolver,
            )
        except MultipleDMARCRecords as e:
            result = _error_result()
            result.add_issue(IssueDefinitions.create_dmarc_multiple_records(str(e)))
            return result
        except InvalidDMARCReportURI as e:
            # Subclass of InvalidDMARCTagValue: must be caught first.
            result = _error_result()
            match = re.search(r"mailto:[^\s'\"]+", str(e))
            result.add_issue(IssueDefinitions.create_dmarc_invalid_report_uri(
                match.group(0) if match else "unknown", str(e)))
            return result
        except InvalidDMARCTagValue as e:
            # checkdmarc 6 messages:
            #   "Tag p must have one of the following values: none,quarantine,reject - not blah"
            #   "x is not a valid option for the DMARC fo tag."
            result = _error_result()
            msg = str(e)
            tag_name, value = "unknown", "unknown"
            match = re.search(r"Tag (\w+) must .* - not (.*)$", msg)
            if match:
                tag_name, value = match.group(1), match.group(2)
            else:
                match = re.search(r"^(.*?) is not a valid option for the DMARC (\w+) tag", msg)
                if match:
                    value, tag_name = match.group(1), match.group(2)
            result.add_issue(IssueDefinitions.create_dmarc_invalid_tag_value(tag_name, value, msg))
            return result
        except InvalidDMARCTag as e:
            # checkdmarc 6 ignores unknown tags; this is raised for duplicate tags.
            result = _error_result()
            match = re.search(r"Duplicate ([\w,]+) tags", str(e))
            result.add_issue(IssueDefinitions.create_dmarc_invalid_tag(
                match.group(1) if match else "unknown", str(e)))
            return result
        except DMARCSyntaxError as e:
            result = _error_result()
            result.add_issue(IssueDefinitions.create_dmarc_syntax_error(str(e)))
            return result
        except Exception:
            # Unexpected checkdmarc failure: keep p= / sp= / aspf= with a minimal parse.
            result = _error_result()
            self._process_basic_dmarc(result, dmarc_record)
            return result

        result = self.check_parsed_dmarc(parsed_dmarc, record_id, record=dmarc_record)
        if not result.dmarc_record:
            result.dmarc_record = dmarc_record
        return result

    def check_parsed_dmarc(self, parsed_dmarc: Dict[str, Any], record_id: str = "DMARC-Record",
                           store_parsed: bool = True, record: Optional[str] = None) -> DMARCResult:
        """
        Check an already parsed DMARC record from checkdmarc.

        Args:
            parsed_dmarc: Parsed DMARC structure from checkdmarc (with 'tags', etc.)
            record_id: Identifier for this record (used as domain in result)
            store_parsed: If True, store the complete parsed structure in result.parsed_dmarc
            record: Raw record, used for the RFC 7489 ``pct`` tag that checkdmarc >= 6
                    no longer returns. Defaults to ``parsed_dmarc['record']`` if present.

        Returns:
            DMARCResult object with all findings

        Example:
            >>> from checkdmarc.dmarc import parse_dmarc_record
            >>> parsed = parse_dmarc_record("v=DMARC1; p=reject", "example.com")
            >>> result = dmarc_checker.check_parsed_dmarc(parsed, "example.com")
        """
        result = DMARCResult(domain=record_id)
        result.dmarc_record = record or parsed_dmarc.get('record')

        if store_parsed:
            result.parsed_dmarc = parsed_dmarc

        self._process_checkdmarc_result(result, parsed_dmarc)
        return result

    def _process_checkdmarc_result(self, result: DMARCResult, parsed_dmarc: Dict[str, Any]):
        """
        Populate *result* from a checkdmarc >= 6 parse.

        checkdmarc fills implicit tags with their defaults (``explicit: False``):
        sp = p, np = explicit sp else p, adkim = aspf = r, t = n, psd = u.
        """
        tags = parsed_dmarc.get('tags')
        if not tags:
            return

        def value(tag: str) -> Any:
            item = tags.get(tag)
            return item.get('value') if isinstance(item, dict) else item

        def explicit(tag: str) -> bool:
            item = tags.get(tag)
            return bool(item.get('explicit', True)) if isinstance(item, dict) else item is not None

        result.policy = value('p')
        if result.policy and result.policy not in ('reject', 'quarantine'):
            result.add_issue(IssueDefinitions.create_dmarc_lax_policy(result.policy))

        result.subdomain_policy = value('sp') or result.policy
        # Only report sp= when it is published: an implicit sp equals p, already reported.
        if explicit('sp') and result.subdomain_policy not in ('reject', 'quarantine'):
            result.add_issue(IssueDefinitions.create_dmarc_lax_subdomain_policy(result.subdomain_policy))

        result.np_policy = value('np') or result.subdomain_policy
        result.psd = value('psd')

        # RFC 9989 test mode: the policy must not be applied as published.
        result.testing = value('t') == 'y'
        if result.testing and result.policy in ('reject', 'quarantine'):
            result.add_issue(IssueDefinitions.create_dmarc_testing_mode(result.policy))

        # RFC 7489 pct (absent from checkdmarc >= 6 tags, still honoured by older receivers)
        pct = value('pct')
        pct = int(pct) if isinstance(pct, str) and pct.isdigit() else _legacy_pct(result.dmarc_record)
        if pct is not None:
            result.percentage = pct
            if pct < 100:
                result.add_issue(IssueDefinitions.create_dmarc_not_100_pct(pct, result.policy))

        if 'rua' in tags:
            result.aggregate_reports = [uri['address'] for uri in value('rua') or []]
        if 'ruf' in tags:
            result.forensic_reports = [uri['address'] for uri in value('ruf') or []]

        result.alignment_spf = value('aspf')
        result.alignment_dkim = value('adkim')

    def _process_basic_dmarc(self, result: DMARCResult, dmarc_record: str):
        """
        Last-resort parsing when checkdmarc fails unexpectedly (not on a syntax
        error, which is reported as such): keeps the main tags so a valid ``p=``
        is not lost. Applies the same defaults as checkdmarc.
        """
        raw = _parse_dmarc_tags(dmarc_record)
        tags = {k: v.lower() for k, v in raw.items() if k not in ('rua', 'ruf')}

        result.policy = tags.get('p', 'none')
        if result.policy not in ('quarantine', 'reject'):
            result.add_issue(IssueDefinitions.create_dmarc_lax_policy(result.policy))

        result.subdomain_policy = tags.get('sp', result.policy)
        if 'sp' in tags and result.subdomain_policy not in ('quarantine', 'reject'):
            result.add_issue(IssueDefinitions.create_dmarc_lax_subdomain_policy(result.subdomain_policy))

        result.np_policy = tags.get('np', result.subdomain_policy)
        result.psd = tags.get('psd')
        result.testing = tags.get('t') == 'y'
        if result.testing and result.policy in ('reject', 'quarantine'):
            result.add_issue(IssueDefinitions.create_dmarc_testing_mode(result.policy))

        pct = _legacy_pct(dmarc_record)
        if pct is not None:
            result.percentage = pct
            if pct < 100:
                result.add_issue(IssueDefinitions.create_dmarc_not_100_pct(pct, result.policy))

        for tag, attr in (('rua', 'aggregate_reports'), ('ruf', 'forensic_reports')):
            if tag in raw:
                setattr(result, attr, [a.strip() for a in raw[tag].split(',') if a.strip()])

        result.alignment_spf = tags.get('aspf', 'r')
        result.alignment_dkim = tags.get('adkim', 'r')
