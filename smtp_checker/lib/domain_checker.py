"""
DomainChecker — combined mail-security audit for a domain or MX hostname.

Auto-detects the input type:
  - Has MX records → domain mode: resolves MX hosts, runs SMTP + DANE + MTA-STS.
  - No MX records  → mx_hostname mode: treats the input as the SMTP server itself.

Async support via run_all_tests_async() (uses asyncio.to_thread internally,
so the underlying synchronous DNS/SMTP code runs in a thread pool).
"""
import asyncio
import csv
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

import dns.exception
import dns.resolver

from .checker import SMTPChecker
from .config import DEFAULT_OPTIONS
from .dane import (
    check_dnssec_chain,
    check_mta_sts,
    get_mx_hostnames,
    resolve_records,
    verify_mx_dane,
)
from .exceptions import SMTPConnectionError

# ---------------------------------------------------------------------------
# Issue definitions — loaded once from lib/data/issue_definitions.csv
# ---------------------------------------------------------------------------

_ISSUE_DEFS_PATH = Path(__file__).parent / "data" / "issue_definitions.csv"
_ISSUE_DEFS: dict[str, dict[str, Any]] = {}


def _load_issue_definitions() -> None:
    global _ISSUE_DEFS
    if not _ISSUE_DEFS_PATH.exists():
        return
    with open(_ISSUE_DEFS_PATH, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter=";"):
            code = row["issue_code"]
            _ISSUE_DEFS[code] = {
                "code":     code,
                "title":    row["issue_title"],
                "category": row["category"],
                "severity": row["default_severity"],
            }


_load_issue_definitions()


def get_issue_definitions() -> dict[str, dict[str, Any]]:
    """Return a copy of all smtp_checker issue definitions keyed by slug.

    Each entry: ``{"code": str, "title": str, "category": str, "severity": str}``
    Intended for external consumers (e.g. mail_audit) that need to enumerate
    all known smtp_checker issue codes without hard-coding them.
    """
    return dict(_ISSUE_DEFS)


def _make_issue(code: str, **extra: Any) -> dict[str, Any]:
    """Return an issue dict from the registry, optionally overriding fields."""
    base = dict(_ISSUE_DEFS.get(code, {"code": code, "title": code.replace("_", " ").title(), "severity": "medium", "category": "SMTP"}))
    base.update(extra)
    return base


def _collect_domain_issues(mta_sts: dict[str, Any]) -> list[dict[str, Any]]:
    """Map MTA-STS result to domain-level issue codes."""
    issues: list[dict[str, Any]] = []
    valid: bool = bool(mta_sts.get("valid", False))
    policy: dict[str, Any] = mta_sts.get("policy") or {}
    mode: Optional[str] = policy.get("mode") if policy else None

    if not valid or not policy:
        issues.append(_make_issue("mta_sts_missing"))
    elif mode != "enforce":
        issues.append(_make_issue("mta_sts_non_enforce", details=f"MTA-STS mode is '{mode}'"))
    return issues


def _collect_mx_issues(
    smtp_tests: dict[str, Any],
    dane: dict[str, Any],
) -> list[dict[str, Any]]:
    """Map per-MX SMTP test results and DANE data to issue codes."""
    issues: list[dict[str, Any]] = []

    # SMTP connectivity
    if not smtp_tests.get("smtp_connect", {}).get("ok", True):
        issues.append(_make_issue("smtp_connection_failure"))

    # Banner check
    if not smtp_tests.get("smtp_banner_check", {}).get("ok", True):
        issues.append(_make_issue("smtp_banner_mismatch"))

    # Open relay (FAIL = relay accepted = vulnerability)
    # The relay test reports an accepted external RCPT TO as WARNING (FAIL kept for safety)
    if smtp_tests.get("smtp_open_relay", {}).get("status") in ("WARNING", "FAIL"):
        issues.append(_make_issue("smtp_open_relay"))

    # STARTTLS
    if not smtp_tests.get("smtp_tls", {}).get("ok", True):
        issues.append(_make_issue("smtp_no_starttls"))

    # TLS certificate
    if not smtp_tests.get("smtp_tls_cert_check", {}).get("ok", True):
        issues.append(_make_issue("tls_cert_invalid"))

    # Reverse DNS
    if not smtp_tests.get("smtp_reverse_dns_mismatch", {}).get("ok", True):
        issues.append(_make_issue("smtp_rdns_mismatch"))

    # DANE
    tlsa_records: list[Any] = dane.get("tlsa_lookup", {}).get("records", [])
    dane_valid: bool = bool(dane.get("dane_valid", False))
    mx_dnssec_valid: bool = bool(dane.get("mx_dnssec", {}).get("dnssec_valid", False))

    if not dane_valid and not tlsa_records:
        issues.append(_make_issue("dane_no_tlsa"))
    if tlsa_records and not mx_dnssec_valid:
        issues.append(_make_issue("tlsa_no_dnssec"))

    return issues


class DomainChecker:
    """
    Comprehensive mail-security checker for a domain or MX hostname.

    Combines:
    - SMTP diagnostic tests (SMTPChecker)
    - DANE / DNSSEC chain validation
    - MTA-STS policy check (domain mode only)
    - TLS-RPT DNS record check (domain mode only)

    Certificate reuse: when SMTPChecker performs STARTTLS and captures the
    server certificate, that DER blob is passed directly to DANE verification
    to avoid a second SMTP connection.

    Usage::

        # Synchronous
        checker = DomainChecker("flex-led.com")
        report = checker.run_all_tests()

        # Asynchronous (single domain)
        report = await DomainChecker("flex-led.com").run_all_tests_async()

        # Bulk async
        results = await scan_domains_async(["flex-led.com", "granier.be"])
    """

    def __init__(
        self,
        target: Union[str, list[str]],
        port: int = 25,
        timeout: float = 10.0,
        dns_timeout: float = 5.0,
        nameservers: Optional[list[str]] = None,
        open_relay_sender: Optional[str] = None,
        open_relay_recipient: Optional[str] = None,
        open_relay_mode: str = "rcpt",
        smtp_options: Optional[dict[str, bool]] = None,
        target_type: str = "auto",
    ) -> None:
        """
        :param target: Domain name (e.g. ``"example.com"``), MX hostname
                       (e.g. ``"mail.example.com"``), **or a list** of either
                       for batch scanning.

                       - Single string → ``run_all_tests()`` returns a dict.
                       - List of strings → ``run_all_tests()`` returns a list
                         of dicts (sequential); ``run_all_tests_async()``
                         scans them concurrently.
        :param port: SMTP port (default 25).
        :param timeout: SMTP connection / transaction timeout in seconds.
        :param dns_timeout: DNS query timeout in seconds.
        :param nameservers: Custom nameservers.  Defaults to Cloudflare +
                            Google (["1.1.1.1", "8.8.8.8"]).
        :param open_relay_sender: Sender address for the open-relay test.
        :param open_relay_recipient: Recipient address for the open-relay test.
        :param open_relay_mode: ``"rcpt"`` (stop after RCPT TO, default) or ``"data"``
            (also send DATA, expect 354, then drop the connection without content).
        :param smtp_options: Override individual SMTPChecker test flags.
                             smtp_starttls_cert is always forced True internally.
        :param target_type: ``"auto"`` (default: a target with MX records is a
            domain, otherwise it is tested as an MX hostname), ``"domain"`` (always
            an email domain: a domain without MX is reported as such, never tested
            as its own mail server unless it has an A/AAAA record = RFC 5321
            implicit MX) or ``"mx_hostname"`` (always a mail server).
        """
        if target_type not in ("auto", "domain", "mx_hostname"):
            raise ValueError(f"target_type must be auto, domain or mx_hostname, not {target_type!r}")
        self.target_type = target_type
        if isinstance(target, list):
            self._target_list: Optional[list[str]] = target
            self.target = target[0] if target else ""
        else:
            self._target_list = None
            self.target = target
        self.port = port
        # Injected by batch infrastructure — do not set manually
        self._dns_semaphore: Optional[threading.Semaphore] = None
        self.timeout = timeout
        self.dns_timeout = dns_timeout
        self.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
        self.open_relay_sender = open_relay_sender
        self.open_relay_recipient = open_relay_recipient
        self.open_relay_mode = open_relay_mode
        self.smtp_options = smtp_options or {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _has_mx_records(self, name: str, attempts: int = 3) -> Optional[bool]:
        """Return True if *name* publishes MX records (→ it is a domain).

        False only on a definitive answer (NXDOMAIN, or no MX record).  A timeout /
        SERVFAIL is retried; if it persists, None (undetermined) is returned — it
        must not turn a domain into an "MX hostname" target.
        """
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.nameservers
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout
        for _ in range(attempts):
            try:
                return len(list(resolver.resolve(name, "MX"))) > 0
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return False
            except (dns.exception.Timeout, dns.resolver.NoNameservers):
                continue
            except Exception:
                return False
        return None

    def _has_address(self, name: str) -> bool:
        """True if *name* has an A or AAAA record (usable as an implicit MX)."""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.nameservers
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout
        for rdtype in ("A", "AAAA"):
            try:
                if len(list(resolver.resolve(name, rdtype))) > 0:
                    return True
            except Exception:
                continue
        return False

    def _build_smtp_options(self) -> dict[str, bool]:
        """
        Merge user-supplied smtp_options with defaults and force
        smtp_starttls_cert=True so the certificate is always captured
        for DANE reuse.
        """
        options = DEFAULT_OPTIONS.copy()
        options.update(self.smtp_options)
        options["smtp_starttls_cert"] = True   # internal cert capture for DANE reuse
        options["smtp_tls_cert_check"] = True  # user-facing cert validation
        return options

    def _run_smtp_for_mx(self, mx_hostname: str) -> tuple[dict[str, Any], Optional[bytes]]:
        """
        Run SMTPChecker on *mx_hostname*.
        Returns (smtp_result_dict, tls_cert_der_or_None).
        Never raises — connection errors are captured inside smtp_result.
        """
        try:
            checker = SMTPChecker(
                target=mx_hostname,
                port=self.port,
                timeout=self.timeout,
                open_relay_sender=self.open_relay_sender,
                open_relay_recipient=self.open_relay_recipient,
                open_relay_mode=self.open_relay_mode,
                options=self._build_smtp_options(),
            )
            result = checker.run_all_tests()
            cert_der = checker.tls_cert_der
            # smtp_starttls_cert is an internal cert-capture mechanism for DANE
            # reuse — not a user-facing test.  Remove it from the visible report.
            result.get("tests", {}).pop("smtp_starttls_cert", None)
            return result, cert_der
        except SMTPConnectionError as exc:
            return {
                "target": mx_hostname,
                "port": self.port,
                "error": str(exc),
                "tests": {},
                "session_transcript": "",
            }, None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def _clone(self, target: str) -> "DomainChecker":
        """Return a fresh DomainChecker for *target* with the same configuration."""
        return DomainChecker(
            target,
            port=self.port,
            timeout=self.timeout,
            dns_timeout=self.dns_timeout,
            nameservers=list(self.nameservers),
            open_relay_sender=self.open_relay_sender,
            open_relay_recipient=self.open_relay_recipient,
            open_relay_mode=self.open_relay_mode,
            smtp_options=dict(self.smtp_options),
            target_type=self.target_type,
        )

    def run_all_tests(self) -> Union[dict[str, Any], list[dict[str, Any]]]:
        """
        Run all security checks.

        - **Single target** (default): returns a combined report dict.
        - **List of targets**: returns a list of report dicts, one per target,
          scanned sequentially.  Use ``run_all_tests_async()`` for concurrent
          execution.

        Report structure (single target)::

            {
              "target": str,
              "target_type": "domain" | "mx_hostname",
              "domain": str | None,
              "nameservers": [...],
              "scan_timestamp": "2025-...",
              "dnssec": {...},          # domain or MX-host zone
              "mta_sts": {...} | None,  # domain mode only
              "mta_sts_dns": {...} | None,
              "smtp_tls_rpt_dns": {...} | None,
              "mx_hosts": [...],
              "mx_results": [
                {
                  "hostname": str,
                  "smtp": {...},   # SMTPChecker.run_all_tests() output
                  "dane": {...},   # verify_mx_dane() output
                },
                ...
              ],
              "errors": [...]
            }
        """
        if self._target_list is not None:
            return [self._clone(t).run_all_tests() for t in self._target_list]

        if self.target_type == "auto":
            has_mx = self._has_mx_records(self.target)
            # Undetermined (DNS timeout / SERVFAIL): audit it as a domain — the MX
            # lookup below retries and reports its own error — not as its own MX host.
            is_domain = has_mx is not False
        else:
            has_mx = True               # forced: no auto-detection
            is_domain = self.target_type == "domain"
        target_type = "domain" if is_domain else "mx_hostname"
        domain: Optional[str] = self.target if is_domain else None

        report: dict[str, Any] = {
            "target": self.target,
            "target_type": target_type,
            "domain": domain,
            "nameservers": self.nameservers,
            "scan_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "dnssec": None,
            "mta_sts": None,
            "mta_sts_dns": None,
            "smtp_tls_rpt_dns": None,
            "mx_hosts": [],
            # "mx" | "implicit_mx" (no MX, A/AAAA used, RFC 5321 §5.1) |
            # "no_mx" (no MX nor A/AAAA: cannot receive mail) | "nxdomain" |
            # "error" | "mx_hostname" (the target is the mail server itself)
            "mx_status": None,
            "mx_results": [],
            "errors": [],
        }
        if has_mx is None:
            report["errors"].append({
                "stage": "target_type",
                "error": "MX lookup undetermined (DNS timeout / SERVFAIL): target audited as a domain",
            })

        sem = self._dns_semaphore  # shorthand; may be None

        if is_domain:
            # ---- Domain mode: full audit ----
            report["dnssec"] = check_dnssec_chain(
                domain,
                nameservers=self.nameservers,
                timeout=self.dns_timeout,
                _dns_sem=sem,
            )

            report["mta_sts"] = check_mta_sts(
                domain,
                nameservers=self.nameservers,
                timeout=self.dns_timeout,
            )

            report["mta_sts_dns"] = {
                "owner": f"_mta-sts.{domain}",
                "dnssec": check_dnssec_chain(
                    f"_mta-sts.{domain}",
                    nameservers=self.nameservers,
                    timeout=self.dns_timeout,
                    _dns_sem=sem,
                ),
                "txt_lookup": resolve_records(
                    f"_mta-sts.{domain}",
                    "TXT",
                    nameservers=self.nameservers,
                    timeout=self.dns_timeout,
                    _dns_sem=sem,
                ),
            }

            report["smtp_tls_rpt_dns"] = {
                "owner": f"_smtp._tls.{domain}",
                "dnssec": check_dnssec_chain(
                    f"_smtp._tls.{domain}",
                    nameservers=self.nameservers,
                    timeout=self.dns_timeout,
                    _dns_sem=sem,
                ),
                "txt_lookup": resolve_records(
                    f"_smtp._tls.{domain}",
                    "TXT",
                    nameservers=self.nameservers,
                    timeout=self.dns_timeout,
                    _dns_sem=sem,
                ),
            }

            try:
                mx_hostnames = get_mx_hostnames(
                    domain,
                    nameservers=self.nameservers,
                    timeout=self.dns_timeout,
                )
            except Exception as exc:
                if "NXDOMAIN" in type(exc).__name__:
                    report["mx_status"] = "nxdomain"    # the name does not exist
                    return report
                report["mx_status"] = "error"
                report["errors"].append({"stage": "mx_lookup", "error": str(exc)})
                return report

            if mx_hostnames:
                report["mx_status"] = "mx"
            elif self._has_address(domain):
                mx_hostnames = [domain]                 # RFC 5321 §5.1 implicit MX
                report["mx_status"] = "implicit_mx"
            else:
                report["mx_status"] = "no_mx"           # no mail server at all
            report["mx_hosts"] = mx_hostnames
            domain_dnssec = report["dnssec"] or {}

        else:
            # ---- MX hostname mode: target IS the mail server ----
            # MTA-STS, TLS-RPT, and domain-level DNSSEC are not applicable:
            # they require an email domain (e.g. "example.com"), not an MX
            # hostname (e.g. "mail.example.com").  Checking the MX hostname's
            # own DNS zone would give a meaningless result here.
            mx_hostnames = [self.target]
            report["mx_hosts"] = mx_hostnames
            report["mx_status"] = "mx_hostname"
            report["dnssec"] = None   # not applicable — no email domain known
            # Empty dict → verify_mx_dane will set dane_usable_reason =
            # "parent_domain_unknown" to explain why dane_usable is False.
            domain_dnssec = {}

        # ---- Per-MX: SMTP tests + DANE ----
        for mx_hostname in mx_hostnames:
            smtp_result, cert_der = self._run_smtp_for_mx(mx_hostname)

            dane_result = verify_mx_dane(
                mx_hostname,
                domain_dnssec=domain_dnssec,
                nameservers=self.nameservers,
                timeout=self.dns_timeout,
                cert_der=cert_der,
                _dns_sem=sem,
            )

            mx_entry: dict[str, Any] = {
                "hostname": mx_hostname,
                "smtp": smtp_result,
                "dane": dane_result,
                "issues": _collect_mx_issues(
                    smtp_result.get("tests", {}), dane_result
                ),
            }
            report["mx_results"].append(mx_entry)

        # Domain-level issues (MTA-STS) — only in domain mode
        report["issues"] = (
            _collect_domain_issues(report["mta_sts"])
            if is_domain and report.get("mta_sts")
            else []
        )

        return report

    async def run_all_tests_async(
        self,
        *,
        max_smtp: int = 10,
        max_dns: int = 50,
    ) -> Union[dict[str, Any], list[dict[str, Any]]]:
        """
        Async version of ``run_all_tests()``.

        - **Single target**: dispatches blocking work to a thread pool via
          ``asyncio.to_thread`` and returns a dict.
        - **List of targets**: scans all targets concurrently via
          ``asyncio.gather`` and returns a list of dicts in input order.
          Concurrency is capped by *max_smtp* (simultaneous domain scans)
          and *max_dns* (simultaneous DNS resolver calls).

        :param max_smtp: Maximum number of concurrent domain scans (= SMTP
                         connections).  ``0`` means no limit.
        :param max_dns:  Maximum number of concurrent ``dns.resolver`` calls.
                         ``0`` means no limit.  Note: DNS queries made
                         internally by checkdmarc are not subject to this
                         limit.

        Example::

            import asyncio

            # Single target
            report = asyncio.run(DomainChecker("flex-led.com").run_all_tests_async())

            # Multiple targets (concurrent) with concurrency limits
            reports = asyncio.run(
                DomainChecker(["flex-led.com", "granier.be"]).run_all_tests_async(
                    max_smtp=5, max_dns=20
                )
            )
        """
        if self._target_list is not None:
            smtp_sem = asyncio.Semaphore(max_smtp) if max_smtp > 0 else None
            dns_sem  = threading.Semaphore(max_dns)  if max_dns  > 0 else None

            async def _guarded(target: str) -> dict[str, Any]:
                checker = self._clone(target)
                checker._dns_semaphore = dns_sem
                if smtp_sem:
                    async with smtp_sem:
                        return await asyncio.to_thread(checker.run_all_tests)
                return await asyncio.to_thread(checker.run_all_tests)

            return list(await asyncio.gather(*[_guarded(t) for t in self._target_list]))

        return await asyncio.to_thread(self.run_all_tests)


# ---------------------------------------------------------------------------
# Module-level bulk async helper
# ---------------------------------------------------------------------------

async def scan_domains_async(
    targets: list[str],
    *,
    port: int = 25,
    timeout: float = 10.0,
    dns_timeout: float = 5.0,
    nameservers: Optional[list[str]] = None,
    open_relay_sender: Optional[str] = None,
    open_relay_recipient: Optional[str] = None,
    open_relay_mode: str = "rcpt",
    smtp_options: Optional[dict[str, bool]] = None,
    target_type: str = "auto",
    max_smtp: int = 10,
    max_dns: int = 50,
) -> list[dict[str, Any]]:
    """
    Scan multiple targets concurrently with configurable concurrency limits.

    Each target runs in its own thread via ``asyncio.to_thread``.
    *max_smtp* caps how many domain scans (= SMTP connections) run at once.
    *max_dns* caps how many ``dns.resolver`` calls run simultaneously across
    all threads.  DNS queries made internally by checkdmarc are not subject
    to this limit.

    :param targets:   List of domain names or MX hostnames.
    :param max_smtp:  Maximum concurrent domain scans.  ``0`` = no limit.
    :param max_dns:   Maximum concurrent ``dns.resolver`` calls.  ``0`` = no limit.
    :returns: List of report dicts in the same order as *targets*.

    Example::

        import asyncio
        from lib import scan_domains_async

        results = asyncio.run(scan_domains_async(
            ["flex-led.com", "granier.be", "example.com"],
            nameservers=["1.1.1.1", "8.8.8.8"],
            max_smtp=5,
            max_dns=20,
        ))
        for r in results:
            print(r["target"], r["dnssec"]["dnssec_valid"])
    """
    smtp_sem = asyncio.Semaphore(max_smtp) if max_smtp > 0 else None
    dns_sem  = threading.Semaphore(max_dns)  if max_dns  > 0 else None

    async def _guarded(target: str) -> dict[str, Any]:
        checker = DomainChecker(
            target=target,
            port=port,
            timeout=timeout,
            dns_timeout=dns_timeout,
            nameservers=nameservers,
            open_relay_sender=open_relay_sender,
            open_relay_recipient=open_relay_recipient,
            open_relay_mode=open_relay_mode,
            smtp_options=smtp_options,
            target_type=target_type,
        )
        checker._dns_semaphore = dns_sem
        if smtp_sem:
            async with smtp_sem:
                return await asyncio.to_thread(checker.run_all_tests)
        return await asyncio.to_thread(checker.run_all_tests)

    return list(await asyncio.gather(*[_guarded(t) for t in targets]))
