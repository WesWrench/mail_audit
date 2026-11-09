"""
Excel exporter for mail_audit results.

Generates a rich, colour-coded Excel workbook containing:
  - Summary sheet (one row per domain)
  - All Attack Scenarios sheet
  - MITM Attacks sheet (filtered)
  - External Attacks sheet (filtered)
  - SMTP Results sheet (raw smtp_checker output)
  - AntiSpoof Results sheet (raw SPF/DMARC/DKIM output)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from .attack_scenarios import is_mx_level
from .models import AttackCategory, AuditResult, DomainAudit, LIKELIHOOD_LABELS, RISK_LABELS

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

# Risk level (low / moderate / high / critical)
RISK_COLOURS = {
    "critical": "FFFF0000",   # Red
    "high":     "FFFF6600",   # Orange
    "moderate": "FFFFCC00",   # Yellow
    "low":      "FF00CCFF",   # Light blue
}

# Probability (very_low .. very_high)
LIKELIHOOD_COLOURS = {
    "very_high": "FFFF0000",  # Red
    "high":      "FFFF6600",  # Orange
    "medium":    "FFFFCC00",  # Yellow
    "low":       "FF00CCFF",  # Light blue
    "very_low":  "FFCCCCCC",  # Light grey
}

HEADER_FILL = PatternFill(
    start_color="FF2F4F7F", end_color="FF2F4F7F", fill_type="solid"
)
HEADER_FONT = Font(bold=True, color="FFFFFFFF", size=11)
HEADER_ALIGNMENT = Alignment(horizontal="center", vertical="center", wrap_text=True)

THIN_BORDER = Border(
    left=Side(style="thin"),
    right=Side(style="thin"),
    top=Side(style="thin"),
    bottom=Side(style="thin"),
)

CATEGORY_COLOURS = {
    AttackCategory.MITM:     "FFFFF0E0",   # Pale orange tint
    AttackCategory.EXTERNAL: "FFE0F0FF",   # Pale blue tint
}


def _fill(hex_color: str) -> PatternFill:
    return PatternFill(start_color=hex_color, end_color=hex_color, fill_type="solid")


def _risk_fill(risk: str) -> PatternFill:
    return _fill(RISK_COLOURS.get((risk or "").lower(), "FFFFFFFF"))


def _likelihood_fill(likelihood: str) -> PatternFill:
    return _fill(LIKELIHOOD_COLOURS.get((likelihood or "").lower(), "FFFFFFFF"))


def _risk_label(risk: str) -> str:
    return RISK_LABELS.get((risk or "").lower(), (risk or "").capitalize())


def _likelihood_label(likelihood: str) -> str:
    return LIKELIHOOD_LABELS.get((likelihood or "").lower(), (likelihood or "").capitalize())


_VECTOR_MODE_LABELS = {
    "web_ui": "Web UI",
    "http_api": "HTTP API",
    "smtp_server": "SMTP Server",
    "local_script": "Local MTA",
    "email_forwarding": "Email Forwarding",
    "network": "Network (MITM)",
}


def _vector_mode_label(vec: Dict[str, Any]) -> str:
    """Human-readable delivery mode of an attack vector (for the scenario sheets)."""
    vector_type = vec.get("vector_type", "")
    if vector_type == "smtp_server":
        base = "Shared SMTP Server" if vec.get("shared") else "SMTP Server"
        port = vec.get("port", "")
        return f"{base} ({port})" if port else base
    return _VECTOR_MODE_LABELS.get(vector_type, vector_type.replace("_", " ").title())


def _scenario_vectors(scenario_dict: Dict[str, Any]) -> str:
    """Distinct ACTIVE attack vectors of a scenario, in order (e.g. 'Local MTA, Shared SMTP Server').

    Vectors tested and blocked (``status == "blocked"``) are excluded: they are not
    a way the spoof actually gets through (e.g. SendGrid's authenticated SMTP server,
    blocked by its sender-ownership control, leaves only the Web UI). If every vector
    is blocked, they are shown rather than printing nothing.
    """
    vectors = scenario_dict.get("attack_vectors", [])
    active = [v for v in vectors if v.get("status") != "blocked"]
    modes: List[str] = []
    for vec in (active or vectors):
        label = _vector_mode_label(vec)
        if label and label not in modes:
            modes.append(label)
    return ", ".join(modes)


def _write_header(ws: Worksheet, headers: List[str], row: int = 1) -> None:
    for col_idx, header in enumerate(headers, start=1):
        cell = ws.cell(row=row, column=col_idx, value=header)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = HEADER_ALIGNMENT
        cell.border = THIN_BORDER


def _auto_width(ws: Worksheet, min_w: int = 12, max_w: int = 60) -> None:
    for col in ws.columns:
        max_len = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            try:
                cell_len = len(str(cell.value or ""))
                if cell_len > max_len:
                    max_len = cell_len
            except Exception:
                pass
        adjusted = min(max(max_len + 2, min_w), max_w)
        ws.column_dimensions[col_letter].width = adjusted


def _cell_value(value: Any) -> str:
    """Convert complex types to a readable string for cell values."""
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


class ExcelExporter:
    """Export an AuditResult to a formatted Excel workbook."""

    def __init__(self, result: AuditResult) -> None:
        self.result = result

    def export(self, output_path: str) -> str:
        """
        Write the workbook to *output_path* and return the absolute path.
        """
        wb = openpyxl.Workbook()
        # Remove default sheet
        default_sheet = wb.active
        if default_sheet is not None:
            wb.remove(default_sheet)

        self._write_summary(wb)
        self._write_all_scenarios(wb)
        self._write_scenarios_filtered(wb, "MITM Attacks", AttackCategory.MITM)
        self._write_scenarios_filtered(wb, "External Attacks", AttackCategory.EXTERNAL)
        self._write_smtp_results(wb)
        self._write_antispoof_results(wb)
        self._write_legend(wb)

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        wb.save(str(path))
        return str(path.resolve())

    # ------------------------------------------------------------------
    # Sheet: Legend
    # ------------------------------------------------------------------

    _LEGEND = [
        ("Columns", None),
        ("Target", "Domain for spoofing scenarios; MX hostname for MITM and open relay "
                   "scenarios (one row per MX host, the domains it serves in Affected Domains)."),
        ("Probability", "How likely the technique works today: Very Low / Low / Medium / High / "
                        "Very High (from the attack vectors, service defaults and dated tests)."),
        ("Risk Level", "Impact x Probability (risk matrix): Low / Moderate / High / Critical. A "
                 "scenario's risk is the worst risk of its vectors."),
        ("Bypassed (certain)", "Authentication controls (SPF / DKIM / DMARC) the technique defeats "
                               "by itself, whatever the configuration of the servers involved."),
        ("Possibly Bypassed", "Controls defeated only under a condition the audit cannot observe "
                              "(e.g. an open relay that DKIM-signs relayed mail with the domain "
                              "key). The condition is given in Bypass Conditions."),
        ("Bypass Conditions", "Per control: why it is bypassed, or under which condition."),
        ("Attack Vector(s)", "The scenario's ACTIVE attack vectors, human-readable: Web UI, "
                         "SMTP Server, Shared SMTP Server (a mutualised mail server, e.g. "
                         "smtp-<user>.alwaysdata.net), Local MTA, Email Forwarding, Network "
                         "(MITM). Vectors tested and blocked are not listed (e.g. a service whose "
                         "authenticated SMTP server enforces sender ownership leaves only Web UI). "
                         "SMTP Server shows its port: submission 587/465 (client->server, "
                         "authenticated account) vs. port 25 (server->server, direct MX / open "
                         "relay — the sender acts as an MTA, so the receiver expects a valid "
                         "reverse DNS / PTR and HELO)."),
        ("Bypass semantics", None),
        ("Not bypassed vs absent", "A control that is absent or not enforced (no DMARC record, "
                                   "p=none) is not 'bypassed': there is nothing to bypass. The "
                                   "notes say so."),
        ("DMARC", "Passes when SPF OR DKIM passes ALIGNED with the From domain. One aligned pass "
                  "is enough: an aligned SPF pass bypasses DMARC even at p=reject."),
        ("Open relay", "Evaluated per domain, one row per (relay, case), the case in the "
                       "name: SPF passes only if the domain's SPF authorizes the relay IP "
                       "(being the domain's MX is not enough). SPF-authorized relay: direct "
                       "SPF/DMARC bypass (Very High / Critical); relay not in the SPF: High / "
                       "High if DMARC is not enforced, Low / Moderate if it is. DKIM is always "
                       "'possible': it depends on the relay's DKIM signer (OpenDKIM "
                       "InternalHosts, localhost re-injection after a content filter...) and "
                       "the test never sends content."),
        ("Shared hosting", "SPF + DMARC certain (SPF-authorized host IP, aligned MAIL FROM). DKIM "
                           "possible if the host signs with the sender domain's key without "
                           "checking account ownership."),
        ("Service in SPF", "SPF only (From-domain SPF matches the service IP); DKIM is the "
                           "service's own signature, not aligned; DMARC not bypassed."),
        ("No DMARC / p=none", "SPF and DKIM trivially defeated (own server, own key); DMARC absent "
                              "or monitoring-only."),
        ("Domain takeover", "The control whose DNS name points to a buyable domain (SPF / DKIM / "
                            "DMARC), plus DMARC when SPF or DKIM can then pass aligned."),
        ("MITM", "Transport attacks on the SMTP connection to the MX (Service: SMTP (TCP 25)): "
                 "bypass columns are N/A. Conditions Met separate what is Measured (DNS / SMTP "
                 "results) from what is Assumed (on-path position, sender behaviour), which the "
                 "audit cannot test. Without MTA-STS enforce or usable DANE, opportunistic "
                 "senders accept any certificate (no CA compromise needed); a fraudulent "
                 "CA-issued certificate is only needed against MTA-STS enforce."),
    ]

    def _write_legend(self, wb: openpyxl.Workbook) -> None:
        ws = wb.create_sheet("Legend")
        _write_header(ws, ["Item", "Meaning"])
        ws.freeze_panes = "A2"
        for row_idx, (item, meaning) in enumerate(self._LEGEND, start=2):
            a = ws.cell(row=row_idx, column=1, value=item)
            b = ws.cell(row=row_idx, column=2, value=meaning)
            for cell in (a, b):
                cell.alignment = Alignment(vertical="top", wrap_text=True)
            if meaning is None:
                a.font = Font(bold=True, size=12)
            else:
                a.font = Font(bold=True)
                a.border = b.border = THIN_BORDER
        ws.column_dimensions["A"].width = 28
        ws.column_dimensions["B"].width = 110

    # ------------------------------------------------------------------
    # Sheet: Summary
    # ------------------------------------------------------------------

    def _write_summary(self, wb: openpyxl.Workbook) -> None:
        ws = wb.create_sheet("Summary")
        headers = [
            "Domain",
            "Total Scenarios",
            "Critical Risk Level",
            "High Risk Level",
            "Moderate Risk Level",
            "Low Risk Level",
            "DMARC Status",
            "MTA-STS Status",
            "Open Relay",
            "DANE Status",
        ]
        _write_header(ws, headers)
        ws.row_dimensions[1].height = 30
        ws.freeze_panes = "A2"

        for row_idx, domain_audit in enumerate(self.result.domains, start=2):
            counts = domain_audit.scenario_count_by_risk()
            total = sum(counts.values())

            dmarc = domain_audit.dmarc_result or {}
            dmarc_policy = dmarc.get("policy") or ("absent" if not dmarc.get("dmarc_record") else "present")
            if not dmarc.get("dmarc_record"):
                dmarc_status = "Absent"
            else:
                dmarc_status = str(dmarc_policy).capitalize()

            smtp_r = domain_audit.smtp_result or {}
            mta_sts = smtp_r.get("mta_sts") or {}
            mta_sts_valid = mta_sts.get("valid", False)
            mta_sts_policy = mta_sts.get("policy") or {}
            mta_sts_mode = mta_sts_policy.get("mode", "N/A") if mta_sts_valid else "Absent"
            mta_sts_status = f"{'Valid' if mta_sts_valid else 'Invalid'} ({mta_sts_mode})"

            # Open relay: any MX with FAIL
            mx_results: List[Dict[str, Any]] = smtp_r.get("mx_results") or []
            open_relay_hosts = [
                mx.get("hostname", "?")
                for mx in mx_results
                if mx and (mx.get("smtp") or {}).get("tests", {}).get("smtp_open_relay", {}).get("status") in ("WARNING", "FAIL")
            ]
            open_relay_status = "YES: " + ", ".join(open_relay_hosts) if open_relay_hosts else "No"

            # DANE status summary
            dane_stati = []
            for mx in mx_results:
                if not mx:
                    continue
                dane = mx.get("dane") or {}
                dane_valid = dane.get("dane_valid", False)
                dane_usable = dane.get("dane_usable", False)
                host = mx.get("hostname", "?")
                dane_stati.append(f"{host}: {'Valid' if dane_valid else 'Invalid'}")
            dane_status = "; ".join(dane_stati) if dane_stati else "N/A"

            row_data = [
                domain_audit.domain,
                total,
                counts.get("critical", 0),
                counts.get("high", 0),
                counts.get("moderate", 0),
                counts.get("low", 0),
                dmarc_status,
                mta_sts_status,
                open_relay_status,
                dane_status,
            ]

            for col_idx, value in enumerate(row_data, start=1):
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                cell.border = THIN_BORDER
                cell.alignment = Alignment(vertical="center", wrap_text=True)

            # Colour the critical/high/moderate/low risk count cells
            risk_col_offset = 3  # "Critical Risk" starts at column 3
            for col_offset, risk in enumerate(["critical", "high", "moderate", "low"]):
                cell = ws.cell(row=row_idx, column=risk_col_offset + col_offset)
                if counts.get(risk, 0) > 0:
                    cell.fill = _risk_fill(risk)

            # Highlight open relay
            relay_cell = ws.cell(row=row_idx, column=9)
            if open_relay_hosts:
                relay_cell.fill = _fill("FFFF0000")
                relay_cell.font = Font(bold=True, color="FFFFFFFF")

        ws.column_dimensions["A"].width = 30
        for col in ["B", "C", "D", "E", "F", "G"]:
            ws.column_dimensions[col].width = 12
        for col in ["H", "I", "J"]:
            ws.column_dimensions[col].width = 22
        ws.column_dimensions["K"].width = 45

    # ------------------------------------------------------------------
    # Sheet: All Attack Scenarios (and filtered variants)
    # ------------------------------------------------------------------

    def _report_scenarios(self) -> List[tuple]:
        """``(target, scenario)`` rows for the scenario sheets.

        Domain-level scenarios are listed per domain (target = domain).
        MX-level scenarios (MITM, open relay) are listed once per MX host
        (target = MX host, ``affected_domains`` = domains using it) instead of
        being repeated for every domain.
        """
        rows = [
            (domain_audit.domain, sc)
            for domain_audit in self.result.domains
            for sc in domain_audit.sorted_scenarios
            if not is_mx_level(sc)
        ]
        rows += [(sc.mx_host, sc) for sc in self.result.mx_scenarios]
        return sorted(rows, key=lambda r: r[1].risk_order)

    def _scenario_headers(self) -> List[str]:
        return [
            "Target",
            "Category",
            "Attack Type",
            "Scenario Name",
            "Probability",
            "Risk Level",
            "Bypassed (certain)",
            "Possibly Bypassed",
            "Bypass Conditions",
            "Service",
            "Attack Vector(s)",
            "Affected Domains",
            "Conditions Met",
            "Description",
            "Remediation",
        ]

    def _write_scenario_row(
        self,
        ws: Worksheet,
        row_idx: int,
        domain: str,
        scenario_dict: Dict[str, Any],
    ) -> None:
        prob_str: str = scenario_dict.get("probability", "")
        risk_str: str = scenario_dict.get("risk_level", "")

        conditions = scenario_dict.get("conditions_met", [])
        conditions_str = "\n".join(f"• {c}" for c in conditions)

        bypasses_str = ", ".join(scenario_dict.get("bypasses", []))
        conditional_str = ", ".join(scenario_dict.get("conditional_bypasses", []))
        if scenario_dict.get("attack_category") == AttackCategory.MITM.value:
            bypasses_str = conditional_str = "N/A (transport attack)"
        notes_str = "\n".join(f"• {n}" for n in scenario_dict.get("bypass_notes", []))

        row_data = [
            domain,
            scenario_dict.get("attack_category", ""),
            scenario_dict.get("attack_type", ""),
            scenario_dict.get("scenario_name", ""),
            _likelihood_label(prob_str),
            _risk_label(risk_str),
            bypasses_str,
            conditional_str,
            notes_str,
            scenario_dict.get("service_name") or "",
            _scenario_vectors(scenario_dict),
            ", ".join(scenario_dict.get("affected_domains") or []) or domain,
            conditions_str,
            scenario_dict.get("description", ""),
            scenario_dict.get("remediation", ""),
        ]

        for col_idx, value in enumerate(row_data, start=1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.border = THIN_BORDER
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            # Probability colour (col 5) and Risk colour (col 6)
            if col_idx == 5:
                cell.fill = _likelihood_fill(prob_str)
                cell.font = Font(bold=True)
            if col_idx == 6:
                cell.fill = _risk_fill(risk_str)
                cell.font = Font(bold=True)

        ws.row_dimensions[row_idx].height = 60

    def _write_all_scenarios(self, wb: openpyxl.Workbook) -> None:
        ws = wb.create_sheet("All Attack Scenarios")
        headers = self._scenario_headers()
        _write_header(ws, headers)
        ws.row_dimensions[1].height = 30
        ws.freeze_panes = "A2"

        row_idx = 2
        for target, scenario in self._report_scenarios():
            self._write_scenario_row(ws, row_idx, target, scenario.to_dict())
            row_idx += 1

        self._apply_scenario_column_widths(ws)

    def _write_scenarios_filtered(
        self,
        wb: openpyxl.Workbook,
        sheet_name: str,
        category: AttackCategory,
    ) -> None:
        ws = wb.create_sheet(sheet_name)
        headers = self._scenario_headers()
        _write_header(ws, headers)
        ws.row_dimensions[1].height = 30
        ws.freeze_panes = "A2"

        row_idx = 2
        for target, scenario in self._report_scenarios():
            if scenario.attack_category == category:
                self._write_scenario_row(ws, row_idx, target, scenario.to_dict())
                row_idx += 1

        self._apply_scenario_column_widths(ws)

    def _apply_scenario_column_widths(self, ws: Worksheet) -> None:
        widths = {
            "A": 28,   # Target (domain, or MX host for MITM / open relay)
            "B": 14,   # Category
            "C": 30,   # Attack Type
            "D": 40,   # Scenario Name
            "E": 14,   # Probability
            "F": 14,   # Risk Level
            "G": 16,   # Bypassed (certain)
            "H": 16,   # Possibly Bypassed
            "I": 70,   # Bypass Conditions
            "J": 22,   # Service
            "K": 24,   # Attack Vector(s)
            "L": 40,   # Affected Domains
            "M": 40,   # Conditions Met
            "N": 70,   # Description
            "O": 55,   # Remediation
        }
        for col_letter, width in widths.items():
            ws.column_dimensions[col_letter].width = width

    # ------------------------------------------------------------------
    # Sheet: SMTP Results
    # ------------------------------------------------------------------

    def _write_smtp_results(self, wb: openpyxl.Workbook) -> None:
        ws = wb.create_sheet("SMTP Results")
        headers = [
            "Domain",
            "MX Hostname",
            "MTA-STS Valid",
            "MTA-STS Mode",
            "DNSSEC Valid",
            "DANE Valid",
            "DANE Usable",
            "TLSA Records",
            "Open Relay",
            "STARTTLS",
            "STARTTLS Downgrade",
            "Cert Valid",
            "Errors",
        ]
        _write_header(ws, headers)
        ws.row_dimensions[1].height = 30
        ws.freeze_panes = "A2"

        row_idx = 2
        for smtp_entry in self.result.smtp_raw:
            if smtp_entry is None:
                continue
            domain = smtp_entry.get("target", "")
            mta_sts = smtp_entry.get("mta_sts") or {}
            mta_sts_valid = mta_sts.get("valid", False)
            mta_sts_policy = mta_sts.get("policy") or {}
            mta_sts_mode = mta_sts_policy.get("mode", "N/A")
            dnssec = smtp_entry.get("dnssec") or {}
            dnssec_valid = dnssec.get("dnssec_valid", False)
            errors = smtp_entry.get("errors") or []
            errors_str = "; ".join(str(e) for e in errors)

            mx_results: List[Dict[str, Any]] = smtp_entry.get("mx_results") or []
            if not mx_results:
                row_data = [
                    domain,
                    "N/A",
                    str(mta_sts_valid),
                    mta_sts_mode,
                    str(dnssec_valid),
                    "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A",
                    errors_str,
                ]
                for col_idx, value in enumerate(row_data, start=1):
                    cell = ws.cell(row=row_idx, column=col_idx, value=value)
                    cell.border = THIN_BORDER
                    cell.alignment = Alignment(vertical="top", wrap_text=True)
                row_idx += 1
                continue

            for mx in mx_results:
                if not mx:
                    continue
                hostname = mx.get("hostname", "")
                dane = mx.get("dane") or {}
                smtp_tests = (mx.get("smtp") or {}).get("tests") or {}

                dane_valid = dane.get("dane_valid", False)
                dane_usable = dane.get("dane_usable", False)
                tlsa_records = (dane.get("tlsa_lookup") or {}).get("records") or []
                tlsa_count = len(tlsa_records)

                open_relay = (smtp_tests.get("smtp_open_relay") or {}).get("status", "N/A")
                # smtp_checker test keys: STARTTLS support is `smtp_tls`, the certificate
                # check is `smtp_tls_cert_check` (there is no separate downgrade probe —
                # STARTTLS stripping is inferred in the MITM scenarios, not measured here).
                starttls = (smtp_tests.get("smtp_tls") or {}).get("status", "N/A")
                starttls_dg = (smtp_tests.get("smtp_tls_downgrade") or {}).get("status", "N/A")
                cert_valid = (smtp_tests.get("smtp_tls_cert_check") or {}).get("status", "N/A")

                row_data = [
                    domain,
                    hostname,
                    "Yes" if mta_sts_valid else "No",
                    mta_sts_mode,
                    "Yes" if dnssec_valid else "No",
                    "Yes" if dane_valid else "No",
                    "Yes" if dane_usable else "No",
                    str(tlsa_count),
                    open_relay,
                    starttls,
                    starttls_dg,
                    cert_valid,
                    errors_str,
                ]

                for col_idx, value in enumerate(row_data, start=1):
                    cell = ws.cell(row=row_idx, column=col_idx, value=value)
                    cell.border = THIN_BORDER
                    cell.alignment = Alignment(vertical="top", wrap_text=True)
                    # Highlight open relay FAIL
                    if col_idx == 9 and open_relay in ("WARNING", "FAIL"):
                        cell.fill = _fill("FFFF0000")
                        cell.font = Font(bold=True, color="FFFFFFFF")
                    # Highlight MTA-STS
                    if col_idx == 3:
                        if not mta_sts_valid:
                            cell.fill = _fill("FFFFCC00")

                ws.row_dimensions[row_idx].height = 22
                row_idx += 1

        col_widths = {
            "A": 28, "B": 35, "C": 14, "D": 14, "E": 14,
            "F": 12, "G": 12, "H": 12, "I": 14,
            "J": 14, "K": 18, "L": 14, "M": 45,
        }
        for col_letter, width in col_widths.items():
            ws.column_dimensions[col_letter].width = width

    # ------------------------------------------------------------------
    # Sheet: AntiSpoof Results
    # ------------------------------------------------------------------

    def _write_antispoof_results(self, wb: openpyxl.Workbook) -> None:
        ws = wb.create_sheet("AntiSpoof Results")
        headers = [
            "Domain",
            "SPF Record",
            "SPF Issues (Count)",
            "SPF Critical Issues",
            "SPF All Qualifier",
            "SPF Lookup Count",
            "SPF Services Found",
            "DMARC Record",
            "DMARC Policy",
            "DMARC Subdomain Policy",
            "DMARC Percentage",
            "DMARC DKIM Alignment",
            "DMARC SPF Alignment",
            "DMARC Issues (Count)",
            "DKIM Selectors Tested",
            "DKIM Selectors Found",
        ]
        _write_header(ws, headers)
        ws.row_dimensions[1].height = 30
        ws.freeze_panes = "A2"

        row_idx = 2
        antispoof = self.result.antispoof_raw

        for domain_audit in self.result.domains:
            domain = domain_audit.domain
            spf = domain_audit.spf_result or {}
            dmarc = domain_audit.dmarc_result or {}
            dkim = domain_audit.dkim_result or {}

            spf_issues = spf.get("issues", [])
            spf_critical = [
                i.get("title", "") for i in spf_issues
                if i.get("severity") in ("critical", "high")
            ]
            spf_services = [
                inc.get("service_name") or inc.get("include", "")
                for inc in spf.get("all_includes", [])
                if inc.get("service_name")
            ]

            dmarc_issues = dmarc.get("issues", [])
            dkim_found = dkim.get("selectors_found", [])

            row_data = [
                domain,
                spf.get("spf_record") or "Absent",
                str(len(spf_issues)),
                "; ".join(spf_critical[:5]) or "None",
                spf.get("all_qualifier") or "N/A",
                str(spf.get("lookup_count", 0)),
                ", ".join(spf_services) or "None",
                dmarc.get("dmarc_record") or "Absent",
                dmarc.get("policy") or "Absent",
                dmarc.get("subdomain_policy") or "N/A",
                str(dmarc.get("percentage", 100)),
                dmarc.get("alignment_dkim") or "N/A",
                dmarc.get("alignment_spf") or "N/A",
                str(len(dmarc_issues)),
                str(dkim.get("selectors_tested", 0)),
                ", ".join(str(s) for s in dkim_found) if dkim_found else "None found",
            ]

            for col_idx, value in enumerate(row_data, start=1):
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                cell.border = THIN_BORDER
                cell.alignment = Alignment(vertical="top", wrap_text=True)
                # Highlight absent SPF
                if col_idx == 2 and (not spf.get("spf_record")):
                    cell.fill = _fill("FFFF6600")
                    cell.font = Font(bold=True)
                # Highlight absent/none DMARC
                if col_idx == 9:
                    if not dmarc.get("dmarc_record"):
                        cell.fill = _fill("FFFF0000")
                        cell.font = Font(bold=True, color="FFFFFFFF")
                    elif dmarc.get("policy") == "none":
                        cell.fill = _fill("FFFFCC00")
                        cell.font = Font(bold=True)

            ws.row_dimensions[row_idx].height = 30
            row_idx += 1

        col_widths = {
            "A": 28, "B": 55, "C": 18, "D": 45,
            "E": 16, "F": 16, "G": 30,
            "H": 55, "I": 16, "J": 22, "K": 16,
            "L": 18, "M": 18, "N": 18,
            "O": 20, "P": 35,
        }
        for col_letter, width in col_widths.items():
            ws.column_dimensions[col_letter].width = width
