"""
Excel export of DomainChecker results (domain mode).

Shared by the smtp_checker CLI and mail_audit.  Sheets:

  - Summary    : one row per audited domain (DNSSEC, MX hosts, MTA-STS / TLS-RPT state,
                 roll-up of the MX-level results).
  - MTA-STS    : one row per domain — DNS record, policy, MX coverage, TLS-RPT.
  - SMTP Tests : one row per (MX host, test).  SMTP tests target the MX server, not the
                 domain: an MX shared by several domains is listed once, with the domains
                 whose MX points to it in "Email Domains".
  - DANE       : one row per MX host (TLSA lives at _25._tcp.<mx>), same grouping.

Rows are only merged when the results are identical; an MX that answered differently
for two domains (e.g. temporary error) keeps one row per distinct result.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

SHEETS = ("Summary", "MTA-STS", "SMTP Tests", "DANE")

_MX_STATUS_LABELS = {
    "mx":          "MX records",
    "implicit_mx": "No MX: implicit MX (A/AAAA of the domain)",
    "no_mx":       "No MX, no A/AAAA: cannot receive mail",
    "nxdomain":    "Domain does not exist (NXDOMAIN)",
    "error":       "MX lookup error",
    "mx_hostname": "Target is a mail server",
}

_STATUS_ORDER = {"PROBLEM": 0, "FAIL": 0, "WARNING": 1, "UNKNOWN": 2, "SKIPPED": 3, "OK": 4}


def _domain(report: Dict[str, Any]) -> str:
    return report.get("domain") or report.get("target", "N/A")


def _mx_matches(host: str, patterns: List[str]) -> bool:
    """RFC 8461 §4.1: '*.' matches exactly one leftmost label."""
    host = host.rstrip(".").lower()
    for pattern in patterns:
        pattern = pattern.rstrip(".").lower()
        if pattern.startswith("*."):
            if host.count(".") >= 1 and host.split(".", 1)[1] == pattern[2:]:
                return True
        elif host == pattern:
            return True
    return False


def _group(entries: List[Tuple[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Merge identical rows; collect their domains into 'Email Domains'."""
    grouped: Dict[Tuple, Dict[str, Any]] = {}
    for domain, row in entries:
        key = tuple((k, str(v)) for k, v in row.items())
        if key not in grouped:
            grouped[key] = {"row": row, "domains": []}
        if domain not in grouped[key]["domains"]:
            grouped[key]["domains"].append(domain)
    rows = []
    for item in grouped.values():
        domains = sorted(item["domains"])
        row = dict(item["row"])
        mx = row.pop("MX Hostname")
        rows.append({"MX Hostname": mx, "Email Domain Count": len(domains),
                     "Email Domains": ", ".join(domains), **row})
    return rows


def _smtp_rows(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for mx_entry in report.get("mx_results") or []:
        hostname = mx_entry.get("hostname", "N/A")
        smtp = mx_entry.get("smtp") or {}
        tests = smtp.get("tests") or {}
        if smtp.get("error"):
            rows.append({"MX Hostname": hostname, "Check": "SMTP Connection",
                         "Status": "PROBLEM", "Details": smtp["error"]})
            continue
        cert = tests.get("smtp_tls_cert_check") or {}
        cert_cols = {
            "Cert Subject":        cert.get("cert_subject"),
            "Cert Issuer":         cert.get("cert_issuer"),
            "Cert Expiry":         cert.get("cert_not_after"),
            "Cert Days Left":      cert.get("cert_days_remaining"),
            "Cert Self-Signed":    cert.get("cert_self_signed"),
            "Cert Hostname Match": cert.get("cert_hostname_match"),
            "Cert CA Valid":       cert.get("cert_ca_valid"),
            "Cert CA Error":       cert.get("cert_ca_error"),
        }
        for test_name, test_result in tests.items():
            if test_name == "smtp_tls_cert_check":
                continue  # cert details added as extra columns
            rows.append({
                "MX Hostname": hostname,
                "Check":       test_result.get("title", test_name),
                "Status":      test_result.get("status", "UNKNOWN"),
                "Details":     test_result.get("details", ""),
                **cert_cols,
            })
    return rows


def _dane_rows(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for mx_entry in report.get("mx_results") or []:
        dane = mx_entry.get("dane") or {}
        tlsa = dane.get("tlsa_lookup") or {}
        rows.append({
            "MX Hostname":       mx_entry.get("hostname", "N/A"),
            "MX DNSSEC Valid":   (dane.get("mx_dnssec") or {}).get("dnssec_valid"),
            "TLSA DNSSEC Valid": (tlsa.get("dnssec") or {}).get("dnssec_valid"),
            "TLSA Records":      ", ".join((tlsa.get("raw_lookup") or {}).get("records", [])),
            "Cert Retrieved":    dane.get("certificate_retrieved"),
            "DANE Valid":        dane.get("dane_valid"),
            "DANE Usable":       dane.get("dane_usable"),
        })
    return rows


def _mta_sts_row(report: Dict[str, Any]) -> Dict[str, Any]:
    mta_sts = report.get("mta_sts") or {}
    policy = mta_sts.get("policy") or {}
    sts_dns = report.get("mta_sts_dns") or {}
    tls_rpt = report.get("smtp_tls_rpt_dns") or {}
    patterns = policy.get("mx") or []
    mx_hosts = report.get("mx_hosts") or []
    uncovered = [h for h in mx_hosts if not _mx_matches(h, patterns)] if policy else []
    return {
        "Domain":                 _domain(report),
        "MTA-STS Valid":          mta_sts.get("valid"),
        "DNS Record (_mta-sts)":  ", ".join((sts_dns.get("txt_lookup") or {}).get("records", [])),
        "Policy ID":              mta_sts.get("id"),
        "Mode":                   policy.get("mode"),
        "Max Age (s)":            policy.get("max_age"),
        "Policy MX Patterns":     ", ".join(patterns),
        "MX Hosts":               ", ".join(mx_hosts),
        "MX Not Covered":         ", ".join(uncovered),
        "_mta-sts DNSSEC":        (sts_dns.get("dnssec") or {}).get("dnssec_valid"),
        "Warnings / Error":       "; ".join(mta_sts.get("warnings") or []) or mta_sts.get("error"),
        "TLS-RPT Record":         ", ".join((tls_rpt.get("txt_lookup") or {}).get("records", [])),
        "TLS-RPT DNSSEC":         (tls_rpt.get("dnssec") or {}).get("dnssec_valid"),
    }


def _worst(statuses: List[str]) -> str:
    return min(statuses, key=lambda s: _STATUS_ORDER.get(s, 2)) if statuses else None


def _summary_row(report: Dict[str, Any]) -> Dict[str, Any]:
    dnssec = report.get("dnssec") or {}
    mta_sts = report.get("mta_sts") or {}
    tls_rpt = report.get("smtp_tls_rpt_dns") or {}
    sts_record = ((report.get("mta_sts_dns") or {}).get("txt_lookup") or {}).get("records")
    mx_results = report.get("mx_results") or []
    smtp_statuses, relays, dane_valid = [], [], []
    for mx in mx_results:
        smtp = mx.get("smtp") or {}
        if smtp.get("error"):
            smtp_statuses.append("PROBLEM")
        for name, test in (smtp.get("tests") or {}).items():
            smtp_statuses.append(test.get("status", "UNKNOWN"))
            if name == "smtp_open_relay" and test.get("status") in ("WARNING", "FAIL"):
                relays.append(mx.get("hostname"))
        dane_valid.append(bool((mx.get("dane") or {}).get("dane_valid")))
    return {
        "Domain":             _domain(report),
        "Type":               report.get("target_type", "N/A"),
        "MX Hosts":           ", ".join(report.get("mx_hosts") or []),
        "MX Status":          _MX_STATUS_LABELS.get(report.get("mx_status"), report.get("mx_status")),
        "DNSSEC Valid":       dnssec.get("dnssec_valid"),
        "DNSKEY Present":     dnssec.get("dnskey_present"),
        "DS Present":         dnssec.get("ds_present"),
        "DS/DNSKEY Match":    dnssec.get("ds_dnskey_match"),
        "MTA-STS Mode":       (mta_sts.get("policy") or {}).get("mode") or ("invalid" if sts_record else "none"),
        "TLS-RPT":            bool((tls_rpt.get("txt_lookup") or {}).get("records")),
        "DANE (all MX)":      all(dane_valid) if dane_valid else None,
        "Open Relay MX":      ", ".join(relays),
        "Worst SMTP Status":  _worst(smtp_statuses),
        "Errors":             "; ".join(f"[{e.get('stage')}] {e.get('error')}" for e in report.get("errors") or []),
    }


def build_domain_sheets(results: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Return {sheet name: rows} for DomainChecker results."""
    smtp_entries, dane_entries = [], []
    for report in results:
        domain = _domain(report)
        smtp_entries += [(domain, row) for row in _smtp_rows(report)]
        dane_entries += [(domain, row) for row in _dane_rows(report)]

    smtp_rows = sorted(_group(smtp_entries), key=lambda r: (
        r["MX Hostname"], _STATUS_ORDER.get(r["Status"], 2), r["Check"]))
    dane_rows = sorted(_group(dane_entries), key=lambda r: r["MX Hostname"])
    return {
        "Summary":    [_summary_row(r) for r in results],
        "MTA-STS":    [_mta_sts_row(r) for r in results],
        "SMTP Tests": smtp_rows,
        "DANE":       dane_rows,
    }


def export_domain_results_to_excel(results: List[Dict[str, Any]], output_file: str) -> None:
    """Write DomainChecker results to an Excel workbook (see module docstring)."""
    import pandas as pd

    sheets = build_domain_sheets(results)
    with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
        for name in SHEETS:
            pd.DataFrame(sheets[name]).to_excel(writer, sheet_name=name, index=False)
        for ws in writer.sheets.values():
            ws.freeze_panes = "A2"
            for column in ws.columns:
                width = max(len(str(c.value)) if c.value is not None else 0 for c in column)
                ws.column_dimensions[column[0].column_letter].width = min(max(width + 2, 10), 60)
