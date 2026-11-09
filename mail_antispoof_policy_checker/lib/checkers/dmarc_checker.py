"""DMARC policy checker"""

import asyncio
import contextlib
import dns.exception
import checkdmarc
from typing import Optional, Dict, Any, List
from ..models.dmarc_result import DMARCResult
from ..models.issue import IssueSeverity
from ..utils.dns_utils import DNSUtils, STATUS_NXDOMAIN
from ..utils.async_dns_resolver import AsyncPooledDNSResolver
from .issue_definitions import IssueDefinitions
from .cname_checker import CNAMEChecker, is_dmarc_record, DEFAULT_MAX_DEPTH


# Standard DMARC tags recognised by this checker. Per RFC 7489 §6.3 a receiver MUST
# ignore unknown tags, and a legitimate but newer tag (e.g. RFC 9091 ``np``) must not
# invalidate the whole record. ``checkdmarc`` (through 5.12.x) still rejects ``np`` with
# InvalidDMARCTag; we tolerate any recognised tag it refuses (see ``check_record``).
#   v     RFC 7489  version (DMARC1)
#   p     RFC 7489  requested policy (none/quarantine/reject)
#   sp    RFC 7489  subdomain policy (defaults to p)
#   np    RFC 9091  non-existent-subdomain policy (defaults to sp, else p)
#   adkim RFC 7489  DKIM alignment (r/s, default r)
#   aspf  RFC 7489  SPF alignment  (r/s, default r)
#   pct   RFC 7489  percentage 0-100 (default 100)
#   fo    RFC 7489  failure-reporting options (0/1/d/s, default 0)
#   rf    RFC 7489  failure report format (default afrf)
#   ri    RFC 7489  aggregate report interval (default 86400)
#   rua   RFC 7489  aggregate report URIs
#   ruf   RFC 7489  failure report URIs
_RECOGNIZED_DMARC_TAGS = {
    "v", "p", "sp", "np", "adkim", "aspf", "pct", "fo", "rf", "ri", "rua", "ruf",
}
_DMARC_POLICY_VALUES = {"none", "quarantine", "reject"}
_DMARC_ALIGNMENT_VALUES = {"r", "s"}


def _parse_dmarc_tags(dmarc_record: str) -> Dict[str, str]:
    """RFC 7489 §6.3 tokeniser: ``tag=value`` pairs separated by ``;``.

    Tag names are case-insensitive (lower-cased here); surrounding whitespace is
    stripped. The first ``v=`` wins. Returns a plain ``{tag: value}`` mapping with
    every tag present in the record (unknown tags included so callers can decide);
    no validation is performed here.
    """
    tags: Dict[str, str] = {}
    for term in (dmarc_record or "").split(";"):
        term = term.strip()
        if not term or "=" not in term:
            continue
        key, value = term.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if key and key not in tags:
            tags[key] = value
    return tags


def _strip_dmarc_tags(dmarc_record: str, drop: set) -> str:
    """Return *dmarc_record* without the ``tag=value`` terms whose (lower-cased)
    tag is in *drop*, preserving the order and ``;`` separators of the rest."""
    kept = []
    for term in (dmarc_record or "").split(";"):
        stripped = term.strip()
        if "=" in stripped:
            key = stripped.split("=", 1)[0].strip().lower()
            if key in drop:
                continue
        if stripped:
            kept.append(stripped)
    return "; ".join(kept)


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
        """
        tags = {}
        for part in org_record.replace('"', '').split(';'):
            if '=' in part:
                key, value = part.split('=', 1)
                tags[key.strip().lower()] = value.strip().lower()
        org_p = tags.get('p') or result.policy
        sp = tags.get('sp')
        np = tags.get('np')
        if is_nonexistent:
            effective = np or sp or org_p
            source_tag = 'np' if np else ('sp' if sp else 'p')
        else:
            effective = sp or org_p
            source_tag = 'sp' if sp else 'p'

        result.organizational_policy = org_p
        result.np_policy = np
        result.policy_inherited_from = f"{org_domain} ({source_tag}={effective})"
        result.policy = effective
        result.subdomain_policy = effective

        lax_codes = (IssueDefinitions.DMARC_LAX_POLICY, IssueDefinitions.DMARC_LAX_SUBDOMAIN_POLICY)
        result.issues = [i for i in result.issues if i.code not in lax_codes]
        if effective and effective not in ('reject', 'quarantine'):
            result.add_issue(IssueDefinitions.create_dmarc_lax_policy(
                effective, inherited_from=result.policy_inherited_from))

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
        # Use checkdmarc's parse_dmarc_record for parsing
        try:
            from checkdmarc.dmarc import (
                parse_dmarc_record,
                DMARCSyntaxError,
                InvalidDMARCTag,
                InvalidDMARCTagValue,
                InvalidDMARCReportURI,
                MultipleDMARCRecords
            )
            # parse_dmarc_record parses the DMARC record (may make DNS queries
            # for external URI validation).  Pass the pooled resolver when set;
            # timeout/timeout_retries are ignored by checkdmarc when resolver= is supplied.
            parsed_dmarc = parse_dmarc_record(
                dmarc_record,
                record_id,
                include_tag_descriptions=False,
                resolver=self._checkdmarc_resolver,
            )

            # Delegate to check_parsed_dmarc()
            result = self.check_parsed_dmarc(parsed_dmarc, record_id)

            # Ensure we have the original DMARC record
            if not result.dmarc_record:
                result.dmarc_record = dmarc_record

            return result

        except MultipleDMARCRecords as e:
            # Multiple DMARC records found
            result = DMARCResult(domain=record_id)
            result.dmarc_record = dmarc_record
            error_message = str(e)
            result.add_issue(IssueDefinitions.create_dmarc_multiple_records(error_message))
            return result

        except InvalidDMARCTag as e:
            error_message = str(e)
            # checkdmarc message: "<tag> is not a valid DMARC tag."
            tag_name = (error_message.split() or ["unknown"])[0].strip().lower()
            # RFC 7489 §6.3: unknown tags MUST be ignored, and a legitimate newer tag
            # (RFC 9091 'np', which checkdmarc 5.12.x still rejects) must NOT void the
            # whole record. If checkdmarc refused a tag we recognise, strip it, re-parse
            # the remainder with checkdmarc (keeping its full validation), then re-apply
            # the stripped tag's value natively.
            if tag_name in _RECOGNIZED_DMARC_TAGS and tag_name != "v":
                recovered = self._reparse_tolerating_tags(dmarc_record, record_id)
                if recovered is not None:
                    return recovered
            # Genuinely unknown/garbage tag (or recovery failed): still populate the
            # core fields natively so a valid p= / aspf= is not lost, and only report
            # the bad tag when it is truly not a recognised DMARC tag.
            result = DMARCResult(domain=record_id)
            result.dmarc_record = dmarc_record
            self._process_basic_dmarc(result, dmarc_record)
            if tag_name not in _RECOGNIZED_DMARC_TAGS:
                result.add_issue(IssueDefinitions.create_dmarc_invalid_tag(tag_name, error_message))
            return result

        except InvalidDMARCTagValue as e:
            # Invalid DMARC tag value
            result = DMARCResult(domain=record_id)
            result.dmarc_record = dmarc_record
            error_message = str(e)
            # Try to extract tag and value from error message
            tag_name = "unknown"
            value = "unknown"
            # checkdmarc format: "tag_name: Invalid value 'value'"
            if ":" in error_message:
                parts = error_message.split(":", 1)
                tag_name = parts[0].strip()
                if "'" in parts[1]:
                    value = parts[1].split("'")[1]
            result.add_issue(IssueDefinitions.create_dmarc_invalid_tag_value(tag_name, value, error_message))
            return result

        except InvalidDMARCReportURI as e:
            # Invalid DMARC report URI
            result = DMARCResult(domain=record_id)
            result.dmarc_record = dmarc_record
            error_message = str(e)
            # Try to extract URI from error message
            uri = "unknown"
            if "mailto:" in error_message:
                # Extract mailto URI
                start = error_message.find("mailto:")
                end = error_message.find(" ", start)
                if end == -1:
                    uri = error_message[start:]
                else:
                    uri = error_message[start:end]
            result.add_issue(IssueDefinitions.create_dmarc_invalid_report_uri(uri, error_message))
            return result

        except DMARCSyntaxError as e:
            # DMARC syntax error
            result = DMARCResult(domain=record_id)
            result.dmarc_record = dmarc_record
            error_message = str(e)
            result.add_issue(IssueDefinitions.create_dmarc_syntax_error(error_message))
            return result

        except Exception as e:
            # Fallback to basic parsing if checkdmarc fails
            result = DMARCResult(domain=record_id)
            result.dmarc_record = dmarc_record
            self._process_basic_dmarc(result, dmarc_record)
            return result

    def _reparse_tolerating_tags(self, dmarc_record: str, record_id: str) -> Optional[DMARCResult]:
        """Re-parse with checkdmarc, stripping any RECOGNISED tag it rejects.

        ``checkdmarc`` aborts a whole record on the first tag it does not know
        (e.g. RFC 9091 ``np``). To keep its full validation of the standard tags
        while tolerating legitimate ones it lacks, drop each recognised tag it
        complains about and retry; the dropped tags' values are then re-applied
        natively. Returns a populated :class:`DMARCResult`, or ``None`` if the
        remainder still cannot be parsed (the caller then falls back to the native
        parser).
        """
        from checkdmarc.dmarc import parse_dmarc_record, InvalidDMARCTag
        dropped: set = set()
        record = dmarc_record
        for _ in range(len(_RECOGNIZED_DMARC_TAGS) + 2):
            try:
                parsed = parse_dmarc_record(
                    record, record_id,
                    include_tag_descriptions=False,
                    resolver=self._checkdmarc_resolver,
                )
            except InvalidDMARCTag as e:
                tag = (str(e).split() or ["unknown"])[0].strip().lower()
                if tag in _RECOGNIZED_DMARC_TAGS and tag != "v" and tag not in dropped:
                    dropped.add(tag)
                    record = _strip_dmarc_tags(record, {tag})
                    continue
                return None
            except Exception:
                return None
            # Parsed the remainder: build the result, keep the ORIGINAL record string,
            # and re-apply the tags checkdmarc could not read.
            result = self.check_parsed_dmarc(parsed, record_id)
            result.dmarc_record = dmarc_record
            self._apply_native_tags(result, dmarc_record, only=dropped)
            return result
        return None

    def _apply_native_tags(self, result: DMARCResult, dmarc_record: str, only: set) -> None:
        """Populate fields for tags *only* (dropped before a checkdmarc re-parse)
        from a native RFC 7489/9091 tokenisation of the original record."""
        if not only:
            return
        tags = _parse_dmarc_tags(dmarc_record)
        if "p" in only and tags.get("p"):
            result.policy = tags["p"].lower()
        if "sp" in only and tags.get("sp"):
            result.subdomain_policy = tags["sp"].lower()
        if "np" in only and tags.get("np"):
            result.np_policy = tags["np"].lower()
        if "aspf" in only and tags.get("aspf"):
            result.alignment_spf = tags["aspf"].lower()
        if "adkim" in only and tags.get("adkim"):
            result.alignment_dkim = tags["adkim"].lower()
        if "pct" in only and tags.get("pct", "").isdigit():
            result.percentage = int(tags["pct"])

    def check_parsed_dmarc(self, parsed_dmarc: Dict[str, Any], record_id: str = "DMARC-Record", store_parsed: bool = True) -> DMARCResult:
        """
        Check an already parsed DMARC record from checkdmarc.

        Args:
            parsed_dmarc: Parsed DMARC structure from checkdmarc (with 'tags', etc.)
            record_id: Identifier for this record (used as domain in result)
            store_parsed: If True, store the complete parsed structure in result.parsed_dmarc

        Returns:
            DMARCResult object with all findings

        Example:
            >>> from checkdmarc.dmarc import parse_dmarc_record
            >>> parsed = parse_dmarc_record("v=DMARC1; p=reject", "example.com")
            >>> result = dmarc_checker.check_dmarc_tree(parsed, "example.com")
        """
        result = DMARCResult(domain=record_id)

        # Extract the DMARC record if available
        if 'record' in parsed_dmarc:
            result.dmarc_record = parsed_dmarc['record']

        # Store the complete parsed structure if requested
        if store_parsed:
            result.parsed_dmarc = parsed_dmarc

        # Process the parsed structure
        self._process_checkdmarc_result(result, parsed_dmarc)

        return result

    def _process_checkdmarc_result(self, result: DMARCResult, parsed_dmarc: Dict[str, Any]):
        """
        Process results from checkdmarc library.

        Args:
            result: DMARCResult object to populate
            parsed_dmarc: Parsed DMARC data from checkdmarc
        """
        if 'tags' not in parsed_dmarc:
            return

        tags = parsed_dmarc['tags']

        # Extract policy
        if 'p' in tags:
            policy = tags['p']['value']
            result.policy = policy

            if policy not in ['reject', 'quarantine']:
                result.add_issue(IssueDefinitions.create_dmarc_lax_policy(policy))

        # Extract subdomain policy
        if 'sp' in tags:
            sp_policy = tags['sp']['value']
            result.subdomain_policy = sp_policy

            if sp_policy not in ['reject', 'quarantine']:
                result.add_issue(IssueDefinitions.create_dmarc_lax_subdomain_policy(sp_policy))
        else:
            # If sp is not defined, it defaults to p
            if result.policy and result.policy not in ['reject', 'quarantine']:
                result.subdomain_policy = result.policy
                # Don't double-report the issue

        # Extract np (RFC 9091 non-existent-subdomain policy) when present. Current
        # checkdmarc rejects 'np' before reaching here (recovered via
        # _reparse_tolerating_tags -> _apply_native_tags); kept for forward support.
        if 'np' in tags:
            np_val = tags['np']
            result.np_policy = np_val['value'] if isinstance(np_val, dict) else np_val

        # Extract percentage
        if 'pct' in tags:
            pct = int(tags['pct']['value'])
            result.percentage = pct

            if pct < 100:
                result.add_issue(IssueDefinitions.create_dmarc_not_100_pct(pct))

        # Extract reporting addresses
        if 'rua' in tags:
            result.aggregate_reports = [uri['address'] for uri in tags['rua']['value']]

        if 'ruf' in tags:
            result.forensic_reports = [uri['address'] for uri in tags['ruf']['value']]

        # Extract alignment modes
        if 'aspf' in tags:
            result.alignment_spf = tags['aspf']['value']

        if 'adkim' in tags:
            result.alignment_dkim = tags['adkim']['value']

    def _process_basic_dmarc(self, result: DMARCResult, dmarc_record: str):
        """
        Native RFC 7489 / RFC 9091 DMARC parsing (no checkdmarc).

        Used as the robust fallback whenever checkdmarc cannot parse a record, so a
        valid ``p=`` / ``aspf=`` / ``sp=`` is never lost. Tag names are
        case-insensitive and enum values are lower-cased; unknown tags are ignored
        (RFC 7489 §6.3). ``sp`` defaults to ``p``; ``np`` (RFC 9091) defaults to the
        effective ``sp``.

        Args:
            result: DMARCResult object to populate
            dmarc_record: Raw DMARC record
        """
        tags = _parse_dmarc_tags(dmarc_record)

        if 'p' in tags:
            value = tags['p'].lower()
            result.policy = value
            if value not in ['quarantine', 'reject']:
                result.add_issue(IssueDefinitions.create_dmarc_lax_policy(value))

        if 'sp' in tags:
            value = tags['sp'].lower()
            result.subdomain_policy = value
            if value not in ['quarantine', 'reject']:
                result.add_issue(IssueDefinitions.create_dmarc_lax_subdomain_policy(value))

        if 'np' in tags:
            result.np_policy = tags['np'].lower()

        if 'pct' in tags:
            try:
                pct = int(tags['pct'])
                result.percentage = pct
                if pct < 100:
                    result.add_issue(IssueDefinitions.create_dmarc_not_100_pct(pct))
            except ValueError:
                pass

        if 'rua' in tags:
            result.aggregate_reports = [addr.strip() for addr in tags['rua'].split(',') if addr.strip()]

        if 'ruf' in tags:
            result.forensic_reports = [addr.strip() for addr in tags['ruf'].split(',') if addr.strip()]

        if 'aspf' in tags:
            result.alignment_spf = tags['aspf'].lower()

        if 'adkim' in tags:
            result.alignment_dkim = tags['adkim'].lower()

        # RFC 7489: sp defaults to p. RFC 9091: np defaults to the effective sp.
        if not result.subdomain_policy and result.policy:
            result.subdomain_policy = result.policy
        if not result.np_policy and result.subdomain_policy:
            result.np_policy = result.subdomain_policy
