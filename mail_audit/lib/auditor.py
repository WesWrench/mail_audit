"""
MailAuditor - Main orchestration class for the mail_audit module.

Runs smtp_checker (DomainChecker) and mail_antispoof_policy_checker
(SPF/DMARC/DKIM) concurrently then synthesises the results into
AttackScenario objects and exports to JSON + Excel.

Install the sibling packages first:
    pip install -e ../smtp_checker
    pip install -e ../mail_antispoof_policy_checker
    pip install -e .
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from smtp_checker.lib import DomainChecker, export_domain_results_to_excel
from mail_antispoof_policy_checker.lib import (
    SPFChecker,
    DMARCChecker,
    DKIMChecker,
    DataLoaders,
    MaxMindClient,
    AsyncPooledDNSResolver,
    organizational_domain,
    derive_org_parents,
)
from mail_antispoof_policy_checker.lib.checkers.unregistered_domain_checker import (
    check_domains_availability,
    collect_spf_include_sources,
    apply_spf_include_availability,
    collect_cname_registration_candidates,
    apply_cname_registration_results,
    _CHECKER_AVAILABLE as _DOMAIN_CHECKER_AVAILABLE,
    _CHECKER_IMPORT_ERROR as _DOMAIN_CHECKER_IMPORT_ERROR,
)

from .attack_scenarios import AttackScenarioAnalyzer, group_mx_scenarios
from .excel_exporter import ExcelExporter
from .models import AuditResult, DomainAudit, RiskLevel


def _antispoof_pkg_root() -> Path:
    """
    Return the root directory of the mail_antispoof_policy_checker package.

    Uses the top-level package __init__.py so the path is always relative to
    wherever the package is installed — works for both editable and normal installs.
    """
    import mail_antispoof_policy_checker as _pkg
    return Path(_pkg.__file__).parent


def _antispoof_data_dir() -> str:
    """Return the absolute path to the antispoof CSV data directory."""
    return str(_antispoof_pkg_root() / "data")


def _antispoof_dkim_selector_file() -> str:
    """Return the absolute path to the bundled DKIM selectors list."""
    return str(_antispoof_pkg_root() / "data" / "DKIM_Selectors.txt")


def _antispoof_maxmind_db_path() -> str:
    """Return the absolute path to the MaxMind databases directory."""
    return str(_antispoof_pkg_root() / "utils" / "maxmind")


class MailAuditor:
    """
    Orchestrates smtp_checker and mail_antispoof_policy_checker for one or
    more domains and produces a structured AuditResult with attack scenarios.

    Parameters
    ----------
    domains : str | List[str]
        Domain(s) to audit.  A single string is treated as one domain.
    smtp_port : int
        SMTP port for DomainChecker (default 25).
    smtp_timeout : float
        SMTP connection timeout in seconds (default 10.0).
    smtp_dns_timeout : float
        DNS query timeout for smtp_checker (default 5.0).
    smtp_nameservers : List[str] | None
        Custom DNS resolvers for smtp_checker.
    open_relay_sender : str
        MAIL FROM address used for the open relay test.
    open_relay_recipient : str
        RCPT TO address used for the open relay test (must be external).
    smtp_options : Dict[str, bool] | None
        Override individual smtp_checker test flags.
    check_types : List[str] | None
        Which antispoof checks to run: any subset of ["spf","dmarc","dkim"].
        Defaults to all three.
    nameservers : List[str] | None
        Custom DNS resolver(s) for the antispoof checkers, as a list of IPs
        (the same list also drives the SMTP checker via ``smtp_nameservers``).
    dns_timeout : int
        DNS timeout for antispoof checkers (default 5).
    use_ns_record : bool
        Use domain's authoritative NS for antispoof DNS queries.
    max_dns_retries : int
        DNS retry count for antispoof checkers (default 3).
    data_dir : str | None
        Path to the CSV data directory used by DataLoaders.
        Defaults to the bundled ``mail_antispoof_policy_checker/lib/data/``.
    maxmind_license_key : str | None
        MaxMind GeoIP licence key for AS-number lookups.
    dkim_selector_file : str | None
        Path to a text file containing DKIM selectors (one per line).
        Replaces the bundled ``DKIM_Selectors.txt`` (used when omitted).
    cname_check : bool
        Check CNAME chains at DKIM selector, ``_dmarc`` and SPF domain names
        (default ``True``).
    skip_domain_availability_check : bool
        Do not run the end-of-run registration check (SPF include domains and
        broken CNAME targets, which then stay ``not_verified``).  Default ``False``.
    skip_smtp : bool
        When ``True``, skip smtp_checker entirely.  No SMTP connections are
        made; MITM and open-relay scenarios are not generated.  Useful for
        fast policy-only audits or when port 25 is blocked.
    output_dir : str
        Directory for exported files (default ``./output``).
    max_concurrent : int
        Max concurrent domain checks for antispoof (default 50).
    max_smtp : int
        Max concurrent SMTP connections for smtp_checker (default 10).
    max_dns : int
        Max concurrent DNS queries for smtp_checker (default 50).
    email_services_file : str | None
        Path to a custom ``email_services.json``.
        Defaults to the bundled ``mail_audit/lib/data/email_services.json``.
    """

    # No built-in defaults: open relay test is disabled if either is None.
    DEFAULT_OPEN_RELAY_SENDER: Optional[str] = None
    DEFAULT_OPEN_RELAY_RECIPIENT: Optional[str] = None

    def __init__(
        self,
        domains: Union[str, List[str]],
        # Pre-computed JSON inputs (offline / hybrid mode)
        smtp_json_path: Optional[str] = None,
        antispoof_json_path: Optional[str] = None,
        # SMTP / Domain options
        smtp_port: int = 25,
        smtp_timeout: float = 10.0,
        smtp_dns_timeout: float = 5.0,
        smtp_nameservers: Optional[List[str]] = None,
        open_relay_sender: Optional[str] = None,
        open_relay_recipient: Optional[str] = None,
        open_relay_mode: str = "rcpt",
        smtp_options: Optional[Dict[str, bool]] = None,
        # AntiSpoof options
        check_types: Optional[List[str]] = None,
        nameservers: Optional[List[str]] = None,
        dns_timeout: int = 5,
        use_ns_record: bool = False,
        max_dns_retries: int = 3,
        data_dir: Optional[str] = None,
        maxmind_license_key: Optional[str] = None,
        dkim_selector_file: Optional[str] = None,
        cname_check: bool = True,
        skip_domain_availability_check: bool = False,
        # DNS concurrency limiting (AsyncPooledDNSResolver)
        max_dns_global_concurrent: int = 50,
        max_dns_per_nameserver: int = 20,
        # General
        skip_smtp: bool = False,
        output_dir: str = "./output",
        max_concurrent: int = 50,
        max_smtp: int = 10,
        max_dns: int = 50,
        email_services_file: Optional[str] = None,
    ) -> None:
        self.domains: List[str] = [domains] if isinstance(domains, str) else list(domains)

        # Offline / hybrid mode
        self.smtp_json_path: Optional[str] = str(Path(smtp_json_path).resolve()) if smtp_json_path else None
        self.antispoof_json_path: Optional[str] = str(Path(antispoof_json_path).resolve()) if antispoof_json_path else None

        # SMTP options
        self.smtp_port = smtp_port
        self.smtp_timeout = smtp_timeout
        self.smtp_dns_timeout = smtp_dns_timeout
        self.smtp_nameservers = smtp_nameservers
        self.open_relay_sender = open_relay_sender
        self.open_relay_recipient = open_relay_recipient
        self.open_relay_mode = open_relay_mode
        self.smtp_options = dict(smtp_options or {})

        # Auto-disable open relay if sender or recipient are not configured.
        # smtp_checker would return SKIPPED anyway, but being explicit here
        # avoids pointless SMTP round-trips and makes the intent clear.
        if not self.open_relay_sender or not self.open_relay_recipient:
            if not self.smtp_options.get("smtp_open_relay", True):
                pass  # already explicitly disabled by the caller — no message needed
            else:
                missing = [
                    name for name, val in (
                        ("open_relay_sender",    self.open_relay_sender),
                        ("open_relay_recipient", self.open_relay_recipient),
                    ) if not val
                ]
                print(
                    f"[mail_audit] INFO: open relay test disabled "
                    f"(not configured: {', '.join(missing)})",
                    file=sys.stderr, flush=True,
                )
            self.smtp_options["smtp_open_relay"] = False

        # AntiSpoof options
        self.check_types: List[str] = check_types or ["spf", "dmarc", "dkim"]
        self.nameservers = nameservers
        self.dns_timeout = dns_timeout
        self.use_ns_record = use_ns_record
        self.max_dns_retries = max_dns_retries
        self.data_dir = str(Path(data_dir).resolve()) if data_dir else _antispoof_data_dir()
        self.maxmind_license_key = maxmind_license_key
        self.max_dns_global_concurrent = max_dns_global_concurrent
        self.max_dns_per_nameserver = max_dns_per_nameserver
        self.dkim_selector_file = (
            str(Path(dkim_selector_file).resolve())
            if dkim_selector_file
            else _antispoof_dkim_selector_file()
        )
        self.dkim_selector_file_is_custom = bool(dkim_selector_file)
        self.cname_check = cname_check
        self.skip_domain_availability_check = skip_domain_availability_check

        # Execution options
        self.skip_smtp = skip_smtp
        self.output_dir = output_dir
        self.max_concurrent = max_concurrent
        self.max_smtp = max_smtp
        self.max_dns = max_dns

        # Email services configuration
        services_path = (
            Path(email_services_file)
            if email_services_file
            else Path(__file__).parent / "data" / "email_services.json"
        )
        with open(services_path, "r", encoding="utf-8") as fh:
            services_data = json.load(fh)
        self.email_services: Dict[str, Any] = services_data.get("services", {})

    # ------------------------------------------------------------------
    # Public run API
    # ------------------------------------------------------------------

    def run(self) -> AuditResult:
        """Synchronous run - wraps ``run_async`` in a new event loop."""
        return asyncio.run(self.run_async())

    async def run_async(self) -> AuditResult:
        """
        Async run.  Executes smtp_checker and antispoof checks concurrently
        for all domains, then synthesises attack scenarios.

        Supports four operating modes depending on which inputs are pre-loaded:

        - **Full online** (default): both checkers run live.
        - **SMTP offline**: ``smtp_json_path`` set → load SMTP results from file,
          run antispoof online.
        - **Antispoof offline**: ``antispoof_json_path`` set → load antispoof
          results from file, run SMTP online.
        - **Fully offline**: both paths set → load both from files, no network
          calls are made.

        ``skip_smtp=True`` is still honoured when ``smtp_json_path`` is not set.
        """
        # ── Resolve SMTP results ─────────────────────────────────────────────
        smtp_coroutine = None
        smtp_results: List[Dict[str, Any]] = []

        if self.smtp_json_path:
            smtp_results = self._load_smtp_json(self.smtp_json_path)
            n = len(smtp_results)
            print(
                f"[mail-audit] [SMTP ] Loaded {n} result(s) from {self.smtp_json_path}",
                file=sys.stderr, flush=True,
            )
        elif self.skip_smtp:
            print("[mail-audit] [SMTP ] Skipped (--no-smtp)", file=sys.stderr, flush=True)
        else:
            smtp_coroutine = self._run_smtp_async()

        # ── Resolve antispoof results ────────────────────────────────────────
        antispoof_coroutine = None
        antispoof_results: Dict[str, Dict[str, Any]] = {}

        if self.antispoof_json_path:
            antispoof_results = self._load_antispoof_json(self.antispoof_json_path)
            n = len(antispoof_results)
            print(
                f"[mail-audit] [ANTISPOOF] Loaded {n} domain(s) from {self.antispoof_json_path}",
                file=sys.stderr, flush=True,
            )
        else:
            antispoof_coroutine = self._run_antispoof_async()

        # ── Run whatever needs to run online ─────────────────────────────────
        if smtp_coroutine and antispoof_coroutine:
            smtp_results, antispoof_results = await asyncio.gather(
                asyncio.create_task(smtp_coroutine),
                asyncio.create_task(antispoof_coroutine),
            )
        elif smtp_coroutine:
            smtp_results = await smtp_coroutine
        elif antispoof_coroutine:
            antispoof_results = await antispoof_coroutine

        return self._build_audit_result(smtp_results, antispoof_results)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export(
        self, result: AuditResult, base_filename: str = "mail_audit"
    ) -> Dict[str, str]:
        """
        Export *result* to 6 files in ``self.output_dir``:

        - ``{base}.json`` / ``{base}.xlsx``          — mail_audit scenarios
        - ``{base}_smtp.json`` / ``{base}_smtp.xlsx`` — smtp_checker raw results
        - ``{base}_antispoof.json`` / ``{base}_antispoof.xlsx`` — antispoof raw results

        Returns
        -------
        dict
            Mapping with keys ``json``, ``excel``, ``smtp_json``, ``smtp_excel``,
            ``antispoof_json``, ``antispoof_excel``.
        """
        output_path = Path(self.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # ── mail_audit ──────────────────────────────────────────────────────
        json_path = output_path / f"{base_filename}.json"
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False, default=str)

        excel_path = output_path / f"{base_filename}.xlsx"
        ExcelExporter(result).export(str(excel_path))

        paths: Dict[str, str] = {
            "json":  str(json_path.resolve()),
            "excel": str(excel_path.resolve()),
        }

        # ── smtp_checker ────────────────────────────────────────────────────
        if not self.skip_smtp:
            smtp_json_path  = output_path / f"{base_filename}_smtp.json"
            smtp_excel_path = output_path / f"{base_filename}_smtp.xlsx"
            try:
                with open(smtp_json_path, "w", encoding="utf-8") as fh:
                    json.dump(result.smtp_raw, fh, indent=2, ensure_ascii=False, default=str)
                self._export_smtp_excel(result.smtp_raw, str(smtp_excel_path))
                paths["smtp_json"]  = str(smtp_json_path.resolve())
                paths["smtp_excel"] = str(smtp_excel_path.resolve())
            except Exception as exc:
                print(f"[mail_audit] WARNING: smtp export failed: {exc}", file=sys.stderr, flush=True)

        # ── antispoof ───────────────────────────────────────────────────────
        antispoof_json_path  = output_path / f"{base_filename}_antispoof.json"
        antispoof_excel_path = output_path / f"{base_filename}_antispoof.xlsx"
        try:
            # Build list in the same format as the native CLI JSON output:
            # each entry has record_id + domain + email_domain_indicators + spf/dmarc/dkim
            antispoof_list = [
                {"record_id": d, "domain": d, "email_domain_indicators": [], **v}
                for d, v in (result.antispoof_raw or {}).items()
            ]
            with open(antispoof_json_path, "w", encoding="utf-8") as fh:
                json.dump(antispoof_list, fh, indent=2, ensure_ascii=False, default=str)
            self._export_antispoof_excel(antispoof_list, str(antispoof_excel_path))
            paths["antispoof_json"]  = str(antispoof_json_path.resolve())
            paths["antispoof_excel"] = str(antispoof_excel_path.resolve())
        except Exception as exc:
            print(f"[mail_audit] WARNING: antispoof export failed: {exc}", file=sys.stderr, flush=True)

        return paths

    # ------------------------------------------------------------------
    # Private export helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _export_smtp_excel(results: List[Dict[str, Any]], output_file: str) -> None:
        """Export DomainChecker smtp_raw results to Excel (smtp_checker's exporter)."""
        try:
            import pandas  # noqa: F401
        except ImportError:
            print("[mail_audit] WARNING: pandas not installed — smtp Excel export skipped.", file=sys.stderr, flush=True)
            return
        export_domain_results_to_excel([r for r in results if r is not None], output_file)

    @staticmethod
    def _export_antispoof_excel(
        all_results: List[Dict[str, Any]], output_file: str
    ) -> None:
        """
        Export antispoof results to Excel using the same format as the native
        mail_antispoof_policy_checker CLI (convert_json_report_to_excel).

        Sheets: Summary, SPF Records, DMARC Records, DKIM Records,
                SPF Issues, DMARC Issues, DKIM Issues.
        """
        try:
            import pandas as pd
        except ImportError:
            print("[mail_audit] WARNING: pandas not installed — antispoof Excel export skipped.", file=sys.stderr, flush=True)
            return

        has_spf   = any("spf"   in r for r in all_results)
        has_dmarc = any("dmarc" in r for r in all_results)
        has_dkim  = any("dkim"  in r for r in all_results)

        with pd.ExcelWriter(output_file, engine="openpyxl") as writer:

            # ── Summary ─────────────────────────────────────────────────────
            summary_data = []
            for result in all_results:
                row: Dict[str, Any] = {
                    "Record ID": result.get("record_id", result.get("domain", "")),
                    "Domain":    result.get("domain", ""),
                    "Email Domain Indicators": ", ".join(result.get("email_domain_indicators", [])),
                }
                spf = result.get("spf") or {}
                if spf:
                    if "error" in spf:
                        row["SPF Status"] = "Error"
                        row["SPF Issues"] = spf["error"]
                    else:
                        row["SPF Status"] = "OK" if not spf.get("issues") else "Issues"
                        row["SPF Issues"] = len(spf.get("issues") or [])
                        row["SPF Includes"] = len(spf.get("all_includes") or [])
                        row["SPF IP Addresses Count"] = len(spf.get("all_ip_addresses") or [])

                dmarc = result.get("dmarc") or {}
                if dmarc:
                    if "error" in dmarc:
                        row["DMARC Status"] = "Error"
                        row["DMARC Policy"] = dmarc["error"]
                    else:
                        row["DMARC Status"] = "OK" if not dmarc.get("issues") else "Issues"
                        row["DMARC Policy"] = dmarc.get("policy", "N/A")
                        row["DMARC Issues"] = len(dmarc.get("issues") or [])

                dkim = result.get("dkim") or {}
                if dkim:
                    if "error" in dkim:
                        row["DKIM Status"] = "Error"
                    else:
                        row["DKIM Status"] = "OK" if not dkim.get("issues") else "Issues"
                        row["DKIM Issues"] = len(dkim.get("issues") or [])

                summary_data.append(row)

            pd.DataFrame(summary_data).to_excel(writer, sheet_name="Summary", index=False)

            # ── SPF Records ──────────────────────────────────────────────────
            if has_spf:
                spf_records_data = []
                for result in all_results:
                    spf = result.get("spf") or {}
                    if spf and "error" not in spf:
                        spf_records_data.append({
                            "Record ID":          result.get("record_id", result.get("domain", "")),
                            "Domain":             result.get("domain", ""),
                            "SPF Record":         spf.get("spf_record", ""),
                            "ALL Qualifier":      spf.get("all_qualifier") or spf.get("has_all_mechanism", "N/A"),
                            "Includes Count":     len(spf.get("all_includes") or []),
                            "IP Addresses Count": len(spf.get("all_ip_addresses") or []),
                            "Issues Count":       len(spf.get("issues") or []),
                        })
                if spf_records_data:
                    pd.DataFrame(spf_records_data).to_excel(writer, sheet_name="SPF Records", index=False)

            # ── DMARC Records ────────────────────────────────────────────────
            if has_dmarc:
                dmarc_records_data = []
                for result in all_results:
                    dmarc = result.get("dmarc") or {}
                    if dmarc and "error" not in dmarc and dmarc.get("dmarc_record"):
                        dmarc_records_data.append({
                            "Record ID":          result.get("record_id", result.get("domain", "")),
                            "Domain":             result.get("domain", ""),
                            "DMARC Domain Checked": dmarc.get("dmarc_domain_checked", ""),
                            "DMARC Record":       dmarc.get("dmarc_record", ""),
                            "Policy":             dmarc.get("policy", "N/A"),
                            "Subdomain Policy":   dmarc.get("subdomain_policy", "N/A"),
                            "Percentage":         dmarc.get("percentage", "N/A"),
                            "Issues Count":       len(dmarc.get("issues") or []),
                        })
                if dmarc_records_data:
                    pd.DataFrame(dmarc_records_data).to_excel(writer, sheet_name="DMARC Records", index=False)

            # ── DKIM Records ─────────────────────────────────────────────────
            if has_dkim:
                dkim_records_data = []
                for result in all_results:
                    dkim = result.get("dkim") or {}
                    if dkim and "error" not in dkim:
                        for selector_info in (dkim.get("selectors_found") or []):
                            if isinstance(selector_info, dict):
                                dkim_records_data.append({
                                    "Record ID": result.get("record_id", result.get("domain", "")),
                                    "Domain":    result.get("domain", ""),
                                    "Selector":  selector_info.get("selector", "N/A"),
                                    "DKIM Record": selector_info.get("dkim_record", ""),
                                    "Key Type":  selector_info.get("key_type", "N/A"),
                                    "Key Size":  selector_info.get("key_size", "N/A"),
                                })
                if dkim_records_data:
                    pd.DataFrame(dkim_records_data).to_excel(writer, sheet_name="DKIM Records", index=False)

            # ── SPF Issues ───────────────────────────────────────────────────
            if has_spf:
                spf_details = []
                for result in all_results:
                    spf = result.get("spf") or {}
                    if spf and "error" not in spf:
                        for issue in (spf.get("issues") or []):
                            additional_data = issue.get("additional_data") or {}
                            resolution_path = issue.get("resolution_path") or []
                            row = {
                                "Record ID":       result.get("record_id", result.get("domain", "")),
                                "Domain":          result.get("domain", ""),
                                "Resolution Path": " > ".join(resolution_path),
                                "Severity":        issue.get("severity", "N/A"),
                                "Category":        issue.get("category", "N/A"),
                                "Title":           issue.get("title", "N/A"),
                            }
                            svc = additional_data.get("service_name", "")
                            if svc:
                                row["Service Name"] = svc
                            indicators = result.get("email_domain_indicators") or []
                            if indicators:
                                row["Email Domain Indicators"] = ", ".join(indicators)
                            if "include" in additional_data:
                                row["Include"] = additional_data["include"]
                                if "registered_domain" in additional_data:
                                    row["Domain To Buy"] = additional_data["registered_domain"]
                            elif "chain" in additional_data:
                                row["CNAME Chain"] = " -> ".join(additional_data["chain"])
                                row["Domain To Buy"] = additional_data.get("registrable_domain", "")
                            elif "ip_range" in additional_data:
                                row["IP Range"] = additional_data["ip_range"]
                                if "match_type" in additional_data:
                                    row["Match Type"] = additional_data["match_type"]
                            elif "ip" in additional_data:
                                row["IP Address"] = additional_data["ip"]
                                if "as_organization" in additional_data:
                                    row["AS Organization"] = additional_data["as_organization"]
                            spf_details.append(row)
                if spf_details:
                    pd.DataFrame(spf_details).to_excel(writer, sheet_name="SPF Issues", index=False)

            # ── DMARC Issues ─────────────────────────────────────────────────
            if has_dmarc:
                dmarc_details = []
                for result in all_results:
                    dmarc = result.get("dmarc") or {}
                    if dmarc and "error" not in dmarc:
                        for issue in (dmarc.get("issues") or []):
                            additional_data = issue.get("additional_data") or {}
                            row = {
                                "Record ID": result.get("record_id", result.get("domain", "")),
                                "Domain":    result.get("domain", ""),
                                "Severity":  issue.get("severity", "N/A"),
                                "Category":  issue.get("category", "N/A"),
                                "Title":     issue.get("title", "N/A"),
                            }
                            if dmarc.get("dmarc_domain_checked"):
                                row["DMARC Domain"] = dmarc["dmarc_domain_checked"]
                            indicators = result.get("email_domain_indicators") or []
                            if indicators:
                                row["Email Domain Indicators"] = ", ".join(indicators)
                            for k in ("policy", "subdomain_policy", "percentage"):
                                if k in additional_data:
                                    row[k.replace("_", " ").title()] = additional_data[k]
                            if "chain" in additional_data:
                                row["CNAME Chain"] = " -> ".join(additional_data["chain"])
                                row["Domain To Buy"] = additional_data.get("registrable_domain", "")
                            dmarc_details.append(row)
                if dmarc_details:
                    pd.DataFrame(dmarc_details).to_excel(writer, sheet_name="DMARC Issues", index=False)

            # ── DKIM Issues ──────────────────────────────────────────────────
            if has_dkim:
                dkim_details = []
                for result in all_results:
                    dkim = result.get("dkim") or {}
                    if dkim and "error" not in dkim:
                        for issue in (dkim.get("issues") or []):
                            additional_data = issue.get("additional_data") or {}
                            row = {
                                "Record ID": result.get("record_id", result.get("domain", "")),
                                "Domain":    result.get("domain", ""),
                                "Severity":  issue.get("severity", "N/A"),
                                "Category":  issue.get("category", "N/A"),
                                "Title":     issue.get("title", "N/A"),
                                "Selector":  additional_data.get("selector")
                                             or ", ".join(additional_data.get("selectors") or []),
                                "Key Size":  additional_data.get("key_size", ""),
                                "CNAME Chain": " -> ".join(additional_data.get("chain") or []),
                                "Domain To Buy": additional_data.get("registrable_domain", ""),
                                "Detail":    issue.get("detail", ""),
                            }
                            indicators = result.get("email_domain_indicators") or []
                            if indicators:
                                row["Email Domain Indicators"] = ", ".join(indicators)
                            dkim_details.append(row)
                if dkim_details:
                    pd.DataFrame(dkim_details).to_excel(writer, sheet_name="DKIM Issues", index=False)


    def run_and_export(self, base_filename: str = "mail_audit") -> Dict[str, str]:
        """Convenience: run audit and immediately export results."""
        result = self.run()
        return self.export(result, base_filename)

    async def run_and_export_async(self, base_filename: str = "mail_audit") -> Dict[str, str]:
        """Async version of ``run_and_export``."""
        result = await self.run_async()
        return self.export(result, base_filename)

    # ------------------------------------------------------------------
    # Internal: SMTP checker runner
    # ------------------------------------------------------------------

    async def _run_smtp_async(self) -> List[Dict[str, Any]]:
        """Run smtp_checker for all domains asynchronously."""
        n = len(self.domains)
        relay = (
            f"open relay ({self.open_relay_mode}): {self.open_relay_sender} → {self.open_relay_recipient}"
            if not self.smtp_options.get("smtp_open_relay") is False
            and self.open_relay_sender and self.open_relay_recipient
            else "open relay: disabled"
        )
        domains_label = self.domains[0] if n == 1 else f"{n} domain(s)"
        print(
            f"[mail-audit] [SMTP ] {domains_label} | starting"
            f" (MTA-STS, DANE, STARTTLS, {relay})...",
            file=sys.stderr, flush=True,
        )

        checker_kwargs: Dict[str, Any] = {
            "port": self.smtp_port,
            "timeout": self.smtp_timeout,
            "dns_timeout": self.smtp_dns_timeout,
            "open_relay_sender": self.open_relay_sender,
            "open_relay_recipient": self.open_relay_recipient,
            "open_relay_mode": self.open_relay_mode,
            # Inputs are email domains: never test a domain without MX as a mail server.
            "target_type": "domain",
        }
        if self.smtp_nameservers:
            checker_kwargs["nameservers"] = self.smtp_nameservers
        if self.smtp_options:
            checker_kwargs["smtp_options"] = self.smtp_options

        try:
            checker = DomainChecker(target=self.domains, **checker_kwargs)
            results = await checker.run_all_tests_async(
                max_smtp=self.max_smtp, max_dns=self.max_dns
            )
            if isinstance(results, dict):
                results = [results]
            # Count total MX hosts found
            total_mx = sum(len((r or {}).get("mx_results") or []) for r in results)
            print(
                f"[mail-audit] [SMTP ] {domains_label} | done"
                f" ({total_mx} MX host(s) checked)",
                file=sys.stderr, flush=True,
            )
            return results
        except Exception as exc:
            print(f"[mail-audit] [SMTP ] ERROR: {exc}", file=sys.stderr, flush=True)
            return [{"target": d, "mx_results": [], "errors": [str(exc)]} for d in self.domains]

    # ------------------------------------------------------------------
    # Internal: AntiSpoof checker runner
    # ------------------------------------------------------------------

    async def _run_antispoof_async(self) -> Dict[str, Dict[str, Any]]:
        """
        Run SPF/DMARC/DKIM checks for all domains asynchronously.

        Returns
        -------
        dict
            Mapping of ``{domain: {"spf": ..., "dmarc": ..., "dkim": ...}}``.
        """
        results: Dict[str, Dict[str, Any]] = {
            d: {"spf": None, "dmarc": None, "dkim": None} for d in self.domains
        }
        n = len(self.domains)
        domains_label = self.domains[0] if n == 1 else f"{n} domain(s)"

        # Build shared AsyncPooledDNSResolver for all checkdmarc calls.
        # checkdmarc ignores nameservers/timeout kwargs when a resolver= object is
        # supplied — values must be pre-configured here.
        _resolver_ns = self.nameservers or None
        checkdmarc_resolver = AsyncPooledDNSResolver(
            nameservers=_resolver_ns,
            timeout=float(self.dns_timeout),
            max_global_concurrent=self.max_dns_global_concurrent,
            max_per_nameserver=self.max_dns_per_nameserver,
        )

        common_kwargs: Dict[str, Any] = {
            "dns_timeout": self.dns_timeout,
            "nameservers": self.nameservers,
            "use_ns_record": self.use_ns_record,
            "max_dns_retries": self.max_dns_retries,
            "resolver": checkdmarc_resolver,
            "cname_check": self.cname_check,
        }

        maxmind_client = None
        _mm_key = self.maxmind_license_key or os.environ.get("MAXMIND_LICENSE_KEY")
        if _mm_key:
            try:
                maxmind_client = MaxMindClient(
                    license_key=_mm_key,
                    db_path=_antispoof_maxmind_db_path(),
                )
                print("[mail_audit] MaxMind client: initialized (license key validated)", file=sys.stderr, flush=True)
            except Exception as exc:
                print(f"[mail_audit] WARNING: MaxMind init failed: {exc}", file=sys.stderr, flush=True)

        print(
            f"[mail-audit] [DATA ] {domains_label} | loading SPF data (includes, IP ranges, PTR)...",
            file=sys.stderr, flush=True,
        )
        data_loaders = None
        try:
            data_loaders = DataLoaders(data_dir=self.data_dir)
            print(f"[mail-audit] [DATA ] {domains_label} | done", file=sys.stderr, flush=True)
        except Exception as exc:
            print(f"[mail-audit] [DATA ] WARNING: DataLoaders init failed: {exc}", file=sys.stderr, flush=True)

        # --- SPF ---
        if "spf" in self.check_types:
            print(
                f"[mail-audit] [SPF  ] {domains_label} | checking...",
                file=sys.stderr, flush=True,
            )
            try:
                spf_checker = SPFChecker(
                    maxmind_client=maxmind_client,
                    data_loaders=data_loaders,
                    data_dir=self.data_dir,
                    **common_kwargs,
                )
                spf_coro = spf_checker.check_async(self.domains, max_concurrent=self.max_concurrent)
                if asyncio.iscoroutine(spf_coro):
                    spf_result_list = await spf_coro
                else:
                    spf_result_list = await asyncio.get_event_loop().run_in_executor(None, lambda: spf_coro)
                for dom, res in zip(self.domains, spf_result_list):
                    if isinstance(res, Exception):
                        print(
                            f"[mail-audit] [SPF  ] WARNING: check failed for {dom}: "
                            f"{type(res).__name__}: {res}",
                            file=sys.stderr, flush=True,
                        )
                        continue
                    d = res.domain if hasattr(res, "domain") else res.get("domain", "")
                    if d in results:
                        results[d]["spf"] = res.to_dict() if hasattr(res, "to_dict") else res
                print(
                    f"[mail-audit] [SPF  ] {domains_label} | done",
                    file=sys.stderr, flush=True,
                )
            except Exception as exc:
                print(f"[mail-audit] [SPF  ] ERROR: {exc}", file=sys.stderr, flush=True)

        # --- DMARC ---
        if "dmarc" in self.check_types:
            print(
                f"[mail-audit] [DMARC] {domains_label} | checking...",
                file=sys.stderr, flush=True,
            )
            try:
                dmarc_checker = DMARCChecker(**common_kwargs)
                dmarc_coro = dmarc_checker.check_async(self.domains, max_concurrent=self.max_concurrent)
                if asyncio.iscoroutine(dmarc_coro):
                    dmarc_result_list = await dmarc_coro
                else:
                    dmarc_result_list = await asyncio.get_event_loop().run_in_executor(None, lambda: dmarc_coro)
                for dom, res in zip(self.domains, dmarc_result_list):
                    if isinstance(res, Exception):
                        print(
                            f"[mail-audit] [DMARC] WARNING: check failed for {dom}: "
                            f"{type(res).__name__}: {res}",
                            file=sys.stderr, flush=True,
                        )
                        continue
                    d = res.domain if hasattr(res, "domain") else res.get("domain", "")
                    if d in results:
                        results[d]["dmarc"] = res.to_dict() if hasattr(res, "to_dict") else res
                print(
                    f"[mail-audit] [DMARC] {domains_label} | done",
                    file=sys.stderr, flush=True,
                )
            except Exception as exc:
                print(f"[mail-audit] [DMARC] ERROR: {exc}", file=sys.stderr, flush=True)

        # --- DKIM ---
        if "dkim" in self.check_types:
            print(
                f"[mail-audit] [DKIM ] {domains_label} | checking...",
                file=sys.stderr, flush=True,
            )
            try:
                dkim_kwargs: Dict[str, Any] = {
                    "dns_timeout": self.dns_timeout,
                    "nameservers": self.nameservers,
                    "max_dns_retries": self.max_dns_retries,
                    "cname_check": self.cname_check,
                }
                if Path(self.dkim_selector_file).exists():
                    dkim_kwargs["selector_file"] = self.dkim_selector_file
                    n_sel = len(DKIMChecker.load_selector_file(self.dkim_selector_file))
                    print(
                        f"[mail-audit] [DKIM ] selectors: {n_sel} from {self.dkim_selector_file}"
                        f"{'' if self.dkim_selector_file_is_custom else ' (default)'}",
                        file=sys.stderr, flush=True,
                    )
                elif self.dkim_selector_file_is_custom:
                    raise FileNotFoundError(f"DKIM selector file not found: {self.dkim_selector_file}")
                dkim_checker = DKIMChecker(**dkim_kwargs)
                dkim_coro = dkim_checker.check_async(self.domains, max_concurrent=self.max_concurrent)
                if asyncio.iscoroutine(dkim_coro):
                    dkim_result_list = await dkim_coro
                else:
                    dkim_result_list = await asyncio.get_event_loop().run_in_executor(None, lambda: dkim_coro)
                for dom, res in zip(self.domains, dkim_result_list):
                    if isinstance(res, Exception):
                        print(
                            f"[mail-audit] [DKIM ] WARNING: check failed for {dom}: "
                            f"{type(res).__name__}: {res}",
                            file=sys.stderr, flush=True,
                        )
                        continue
                    d = res.domain if hasattr(res, "domain") else res.get("domain", "")
                    if d in results:
                        results[d]["dkim"] = res.to_dict() if hasattr(res, "to_dict") else res
                print(
                    f"[mail-audit] [DKIM ] {domains_label} | done",
                    file=sys.stderr, flush=True,
                )
            except Exception as exc:
                print(f"[mail-audit] [DKIM ] ERROR: {exc}", file=sys.stderr, flush=True)

        # --- Organizational-parent DMARC (relaxed-alignment cross-domain spoofing) ---
        # DMARC is evaluated against the From-header domain. To spoof From:@<parent>
        # from a weak subdomain (relaxed alignment, the default), it is the PARENT's
        # own DMARC that governs — not the subdomain's. For each audited subdomain,
        # fetch the organizational (registrable) parent's DMARC when that parent is
        # not already audited. DMARC only: the parent's SPF/DKIM are NOT fetched here
        # (the leverage is the subdomain's SPF/DKIM, not the parent's).
        if "dmarc" in self.check_types:
            org_parents = [p for p in derive_org_parents(self.domains) if p not in results]
            if org_parents:
                print(
                    f"[mail-audit] [DMARC] org-parent(s) for relaxed-alignment check: "
                    f"{', '.join(org_parents)}",
                    file=sys.stderr, flush=True,
                )
                try:
                    parent_checker = DMARCChecker(**common_kwargs)
                    parent_coro = parent_checker.check_async(org_parents, max_concurrent=self.max_concurrent)
                    if asyncio.iscoroutine(parent_coro):
                        parent_list = await parent_coro
                    else:
                        parent_list = await asyncio.get_event_loop().run_in_executor(None, lambda: parent_coro)
                    for dom, res in zip(org_parents, parent_list):
                        if isinstance(res, Exception):
                            print(
                                f"[mail-audit] [DMARC] WARNING: org-parent check failed for {dom}: "
                                f"{type(res).__name__}: {res}",
                                file=sys.stderr, flush=True,
                            )
                            continue
                        d = res.domain if hasattr(res, "domain") else res.get("domain", "")
                        if not d:
                            continue
                        results[d] = {
                            "spf": None,
                            "dmarc": res.to_dict() if hasattr(res, "to_dict") else res,
                            "dkim": None,
                            "_org_parent_dmarc_only": True,
                        }
                except Exception as exc:
                    print(f"[mail-audit] [DMARC] org-parent ERROR: {exc}", file=sys.stderr, flush=True)

        await self._check_domain_registration(results)

        return results

    async def _check_domain_registration(self, results: Dict[str, Dict[str, Any]]) -> None:
        """
        End-of-run registration check (one bulk call for the whole batch).

        Covers, with the antispoof checker's DomainAvailabilityChecker pipeline
        (``check_domains_availability``), the same way as the antispoof CLI:

        - registered domains of **SPF includes** -> ``spf_domain_unregistered``
          (critical) / ``spf_domain_potentially_unregistered`` (high);
        - registrable domains of **broken CNAME targets** at DKIM/DMARC/SPF names
          -> ``*_cname_target_unregistered`` / ``*_cname_target_potentially_unregistered``.

        Run once after all domains are analysed so every registered domain is
        checked a single time (deduplicated across domains and both sources).
        """
        if "spf" in self.check_types:
            include_sources = collect_spf_include_sources(
                (domain, per_domain.get("spf")) for domain, per_domain in results.items()
            )
        else:
            include_sources = {}
        protocol_results = [
            r for per_domain in results.values() for r in per_domain.values() if isinstance(r, dict)
        ]
        cname_candidates = collect_cname_registration_candidates(protocol_results)
        to_check = sorted(set(include_sources) | cname_candidates)
        if not to_check:
            return
        label = (f"{len(include_sources)} SPF include domain(s) + "
                 f"{len(cname_candidates)} CNAME target domain(s)")
        if self.skip_domain_availability_check:
            print(f"[mail-audit] [AVAIL] skipped ({label} not checked)", file=sys.stderr, flush=True)
            return
        if not _DOMAIN_CHECKER_AVAILABLE:
            print(
                f"[mail-audit] [AVAIL] WARNING: domain availability checker unavailable "
                f"({_DOMAIN_CHECKER_IMPORT_ERROR}) - {label} not checked",
                file=sys.stderr, flush=True,
            )
            return
        print(f"[mail-audit] [AVAIL] checking registration of {len(to_check)} unique domain(s) "
              f"({label})...", file=sys.stderr, flush=True)
        try:
            # check_domains_availability() calls asyncio.run(): run it in a thread
            availability = await asyncio.to_thread(check_domains_availability, to_check)
        except Exception as exc:
            print(f"[mail-audit] [AVAIL] ERROR: {exc}", file=sys.stderr, flush=True)
            return

        if include_sources:
            spf_by_domain = {d: per_domain.get("spf") for d, per_domain in results.items()}
            for event in apply_spf_include_availability(spf_by_domain, include_sources, availability):
                print(
                    f"[mail-audit] [AVAIL] SPF {event['record_id']} include:{event['include']} -> "
                    f"{event['registered_domain']} {event['status']} ({event['severity']})",
                    file=sys.stderr, flush=True,
                )
        for event in apply_cname_registration_results(protocol_results, availability):
            print(
                f"[mail-audit] [AVAIL] CNAME {event['protocol']} {', '.join(event['names'][:3])} -> "
                f"{event['registrable_domain']} {event['state'].replace('_', ' ')} ({event['severity']})",
                file=sys.stderr, flush=True,
            )

    # ------------------------------------------------------------------
    # Internal: JSON loaders (offline / hybrid mode)
    # ------------------------------------------------------------------

    @staticmethod
    def _load_smtp_json(path: str) -> List[Dict[str, Any]]:
        """
        Load smtp_checker results from a JSON file.

        Accepts two formats:

        - **mail_audit** ``_smtp.json``: a JSON array where each element is a
          DomainChecker result dict (key ``"target"``).
        - **smtp_checker native** output: same array format produced by
          ``smtp_checker`` CLI (``-o json``).

        Any ``None`` entries are silently dropped.
        """
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data = [data]
        return [r for r in data if r is not None]

    @staticmethod
    def _load_antispoof_json(path: str) -> Dict[str, Dict[str, Any]]:
        """
        Load mail_antispoof_policy_checker results from a JSON file.

        Accepts two formats:

        - **mail_audit** ``_antispoof.json``: a JSON array where each element
          has a ``"domain"`` key plus ``"spf"``, ``"dmarc"``, ``"dkim"`` keys.
        - **mail_antispoof_policy_checker native** ``policy_check_*.json``:
          same list format with ``"domain"`` and checker result keys.

        Returns a dict keyed by domain name.
        """
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        results: Dict[str, Dict[str, Any]] = {}
        for entry in data:
            if not entry:
                continue
            domain = entry.get("domain", "")
            if not domain:
                continue
            results[domain] = {
                "spf":   entry.get("spf"),
                "dmarc": entry.get("dmarc"),
                "dkim":  entry.get("dkim"),
            }
        return results

    # ------------------------------------------------------------------
    # Internal: build final AuditResult
    # ------------------------------------------------------------------

    def _build_audit_result(
        self,
        smtp_results: List[Dict[str, Any]],
        antispoof_results: Dict[str, Dict[str, Any]],
    ) -> AuditResult:
        smtp_by_domain: Dict[str, Dict[str, Any]] = {
            r.get("target", ""): r for r in smtp_results
        }

        # DMARC of every domain we hold a result for (incl. auto-added org parents),
        # keyed by domain — used to resolve the From-domain (organizational) policy
        # that governs a relaxed-alignment cross-domain spoof.
        dmarc_by_domain: Dict[str, Any] = {
            d: r.get("dmarc") for d, r in antispoof_results.items() if isinstance(r, dict)
        }

        # Group the audited domains by organizational domain, so each cross-domain
        # (relaxed-alignment) scenario can list every sibling From identity it also
        # lets an attacker forge (relaxed alignment is symmetric at the org level).
        family_by_org: Dict[str, List[str]] = {}
        for d in self.domains:
            family_by_org.setdefault(organizational_domain(d), []).append(d)

        domain_audits: List[DomainAudit] = []
        for domain in self.domains:
            smtp_r = smtp_by_domain.get(domain, {})
            antispoof_r = antispoof_results.get(domain, {})

            spf_r = antispoof_r.get("spf")
            dmarc_r = antispoof_r.get("dmarc")
            dkim_r = antispoof_r.get("dkim")

            # Organizational (registrable) parent of this domain and its DMARC, for
            # the relaxed-alignment cross-domain spoofing analysis (None when this
            # domain IS its organizational domain, or the parent DMARC is unknown).
            org_domain = organizational_domain(domain)
            org_dmarc_r = dmarc_by_domain.get(org_domain) if org_domain != domain else None
            # Sibling From identities sharing this org domain (audited domains other
            # than this one and other than the org domain itself), with their DMARC.
            org_family = [
                (s, dmarc_by_domain.get(s))
                for s in family_by_org.get(org_domain, [])
                if s != domain and s != org_domain
            ]

            analyzer = AttackScenarioAnalyzer(
                domain=domain,
                smtp_result=smtp_r,
                spf_result=spf_r,
                dmarc_result=dmarc_r,
                dkim_result=dkim_r,
                email_services=self.email_services,
                org_domain=org_domain if org_domain != domain else None,
                org_dmarc_result=org_dmarc_r,
                org_family=org_family,
            )
            scenarios = analyzer.analyze()

            domain_audits.append(
                DomainAudit(
                    domain=domain,
                    smtp_result=smtp_r or None,
                    spf_result=spf_r,
                    dmarc_result=dmarc_r,
                    dkim_result=dkim_r,
                    attack_scenarios=scenarios,
                )
            )

        # MITM / open relay target the MX host: one scenario per (scenario, MX)
        # listing every audited domain that uses that MX.
        all_scenarios = [sc for da in domain_audits for sc in da.attack_scenarios]
        return AuditResult(
            domains=domain_audits,
            mx_scenarios=group_mx_scenarios(all_scenarios),
            smtp_raw=[r for r in smtp_results if r is not None],
            antispoof_raw=antispoof_results,
        )

    # ------------------------------------------------------------------
    # Convenience: print summary to stdout
    # ------------------------------------------------------------------

    def print_summary(self, result: AuditResult) -> None:
        """Print a concise audit summary to stdout."""
        print("\n" + "=" * 70)
        print("MAIL AUDIT SUMMARY")
        print("=" * 70)
        print(f"Domains audited: {len(result.domains)}")

        total_counts = result.total_scenario_count_by_risk()
        print("\nAttack Scenarios by Risk Level:")
        for risk in RiskLevel:
            count = total_counts.get(risk.value, 0)
            if count > 0:
                print(f"  {risk.value.upper():15s}: {count}")

        print("\nPer-Domain Summary:")
        for domain_audit in result.domains:
            counts = domain_audit.scenario_count_by_risk()
            total = sum(counts.values())
            scenario_summary = ", ".join(
                f"{r}: {c}" for r, c in counts.items() if c > 0
            )
            print(f"  {domain_audit.domain:40s} | {total:2d} scenarios | {scenario_summary}")

        print("=" * 70 + "\n")
