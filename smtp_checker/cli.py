#!/usr/bin/env python3
"""
SMTP Checker CLI - Bulk SMTP server and domain security testing tool.

Supports two modes:
  smtp    — Direct SMTP tests against one or more mail server hostnames/IPs
            using SMTPChecker. Fast, no DNS overhead beyond what SMTP needs.
  domain  — Full domain audit (DNSSEC, DANE, MTA-STS, TLS-RPT, TLS cert) using
            DomainChecker. Accepts domain names OR MX hostnames as input.

Both modes support synchronous (default) and asynchronous scanning.
"""

import argparse
import asyncio
import json
import sys
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import socket

from lib import SMTPChecker, DomainChecker, SMTPConnectionError, export_domain_results_to_excel


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def load_targets(input_value: str) -> List[str]:
    """Load targets from a file (one per line) or return a single target."""
    if os.path.isfile(input_value):
        targets = []
        try:
            with open(input_value, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except Exception as e:
            print(f"Error reading file '{input_value}': {e}", file=sys.stderr)
            sys.exit(1)
        return targets
    return [input_value]


def resolve_hostname(target: str) -> str:
    """Resolve a hostname to its IP address, or return it as-is if already an IP."""
    try:
        import ipaddress
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return "N/A"


def parse_options_file(options_file: str) -> Dict[str, bool]:
    """Load SMTPChecker test-option overrides from a JSON file."""
    try:
        with open(options_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Options file '{options_file}' not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing options file: {e}", file=sys.stderr)
        sys.exit(1)


def validate_sender_mx(sender: str) -> None:
    """Verify that the sender domain has MX records (required for open relay test)."""
    if not sender or "@" not in sender:
        return
    domain = sender.split("@", 1)[1]
    print(f"Checking MX record for sender domain '{domain}'...", end=" ", flush=True)
    try:
        import dns.resolver
        try:
            if not list(dns.resolver.resolve(domain, "MX")):
                raise dns.resolver.NoAnswer
            print("OK")
        except dns.resolver.NXDOMAIN:
            print("FAILED")
            print(f"Error: Sender domain '{domain}' does not exist (NXDOMAIN).", file=sys.stderr)
            sys.exit(1)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            print("FAILED")
            print(f"Error: Sender domain '{domain}' has no MX records.", file=sys.stderr)
            sys.exit(1)
    except ImportError:
        print("SKIPPED (dnspython not installed)")


def export_to_json(results: List[Dict[str, Any]], output_file: str) -> None:
    """Write results to a JSON file."""
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\nJSON report saved to: {output_file}")
    except Exception as e:
        print(f"Error writing JSON file: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# smtp mode — SMTPChecker
# ---------------------------------------------------------------------------

def scan_smtp_server(
    target: str,
    port: int = 25,
    timeout: float = 10.0,
    open_relay_sender: Optional[str] = None,
    open_relay_recipient: Optional[str] = None,
    options: Optional[Dict[str, bool]] = None,
    open_relay_mode: str = "rcpt",
) -> Dict[str, Any]:
    """Run SMTPChecker on a single target and return its result dict."""
    print(f"Scanning {target}...", end=" ", flush=True)
    try:
        checker = SMTPChecker(
            target=target,
            port=port,
            timeout=timeout,
            open_relay_sender=open_relay_sender,
            open_relay_recipient=open_relay_recipient,
            open_relay_mode=open_relay_mode,
            options=options,
        )
        result = checker.run_all_tests()
        result["ip_address"] = resolve_hostname(target)
        result["scan_timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        print("Done")
        return result
    except SMTPConnectionError as e:
        print(f"Connection Failed - {e}")
        return {
            "target": target,
            "ip_address": resolve_hostname(target),
            "port": port,
            "scan_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "error": str(e),
            "tests": {},
        }
    except Exception as e:
        print(f"Error - {e}")
        return {
            "target": target,
            "ip_address": resolve_hostname(target),
            "port": port,
            "scan_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "error": str(e),
            "tests": {},
        }


async def _run_smtp_batch_async(
    targets: List[str],
    port: int,
    timeout: float,
    open_relay_sender: Optional[str],
    open_relay_recipient: Optional[str],
    options: Optional[Dict[str, bool]],
    max_smtp: int = 10,
    open_relay_mode: str = "rcpt",
) -> List[Dict[str, Any]]:
    """Scan all SMTP targets concurrently, each in its own thread.

    *max_smtp* caps concurrent connections (0 = no limit).
    """
    smtp_sem = asyncio.Semaphore(max_smtp) if max_smtp > 0 else None

    async def _guarded(t: str) -> Dict[str, Any]:
        if smtp_sem:
            async with smtp_sem:
                return await asyncio.to_thread(scan_smtp_server, t, port, timeout,
                                               open_relay_sender, open_relay_recipient, options,
                                               open_relay_mode)
        return await asyncio.to_thread(scan_smtp_server, t, port, timeout,
                                       open_relay_sender, open_relay_recipient, options,
                                       open_relay_mode)

    return list(await asyncio.gather(*[_guarded(t) for t in targets]))


async def _run_domain_batch_async(
    targets: List[str],
    domain_kwargs: Dict[str, Any],
    max_smtp: int = 10,
    max_dns: int = 50,
) -> List[Dict[str, Any]]:
    """Scan all domains concurrently with per-domain progress output.

    Each domain runs in its own thread (DomainChecker is blocking).
    *max_smtp* caps the concurrency.
    """
    n = len(targets)
    smtp_sem = asyncio.Semaphore(max_smtp) if max_smtp > 0 else None
    completed = 0

    async def _scan_one(target: str) -> Dict[str, Any]:
        nonlocal completed

        async def _run() -> Dict[str, Any]:
            result = await asyncio.to_thread(
                lambda: DomainChecker(target, **domain_kwargs).run_all_tests()
            )
            if isinstance(result, list):
                result = result[0]
            return result or {}

        if smtp_sem:
            async with smtp_sem:
                result = await _run()
        else:
            result = await _run()

        completed += 1
        mx_count = len((result or {}).get("mx_results") or [])
        print(f"[{completed}/{n}] {target} done ({mx_count} MX)", flush=True)
        return result

    return list(await asyncio.gather(*[_scan_one(t) for t in targets]))


def export_smtp_to_excel(results: List[Dict[str, Any]], output_file: str) -> None:
    """
    Export SMTPChecker results to Excel.
    One row per test per target.
    """
    try:
        import pandas as pd
    except ImportError:
        print("Error: pandas is required for Excel export. pip install pandas openpyxl", file=sys.stderr)
        sys.exit(1)

    rows = []
    for result in results:
        target = result.get("target", "N/A")
        ip = result.get("ip_address", "N/A")
        if "error" in result:
            rows.append({
                "Hostname": target, "IP Address": ip,
                "Check": "Connection", "Status": "PROBLEM",
                "Details": result["error"],
            })
            continue
        for test_name, test_result in result.get("tests", {}).items():
            rows.append({
                "Hostname": target,
                "IP Address": ip,
                "Check": test_result.get("title", test_name),
                "Status": test_result.get("status", "UNKNOWN"),
                "Details": test_result.get("details", "N/A"),
            })

    if not rows:
        print("Warning: No data to export", file=sys.stderr)
        return

    try:
        import pandas as pd
        pd.DataFrame(rows).to_excel(output_file, index=False, engine="openpyxl")
        print(f"\nExcel report saved to: {output_file}")
    except Exception as e:
        print(f"Error writing Excel file: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# domain mode — DomainChecker (batch helpers)
# ---------------------------------------------------------------------------

def _domain_checker(
    targets: List[str],
    port: int,
    timeout: float,
    dns_timeout: float,
    nameservers: Optional[List[str]],
    open_relay_sender: Optional[str],
    open_relay_recipient: Optional[str],
    open_relay_mode: str = "rcpt",
) -> DomainChecker:
    """Build a DomainChecker configured for a list of targets."""
    return DomainChecker(
        targets,
        port=port,
        timeout=timeout,
        dns_timeout=dns_timeout,
        nameservers=nameservers,
        open_relay_sender=open_relay_sender,
        open_relay_recipient=open_relay_recipient,
        open_relay_mode=open_relay_mode,
    )


def export_domain_to_excel(results: List[Dict[str, Any]], output_file: str) -> None:
    """
    Export DomainChecker results to Excel (sheets: Summary, MTA-STS, SMTP Tests, DANE).

    SMTP Tests and DANE are MX-level: one row per MX host, with the domains whose MX points
    to it in "Email Domains".  See lib/excel_export.py.
    """
    try:
        import pandas  # noqa: F401
    except ImportError:
        print("Error: pandas is required for Excel export. pip install pandas openpyxl", file=sys.stderr)
        sys.exit(1)

    try:
        export_domain_results_to_excel(results, output_file)
        print(f"\nExcel report saved to: {output_file}  (sheets: Summary, MTA-STS, SMTP Tests, DANE)")
    except Exception as e:
        print(f"Error writing Excel file: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    # Windows consoles/pipes default to cp1252: never crash on non-ASCII help/output text.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    parser = argparse.ArgumentParser(
        description="SMTP Checker CLI - Bulk SMTP server and domain security testing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  smtp    Direct SMTP checks against mail server hostnames/IPs (SMTPChecker).
  domain  Full domain audit: DNSSEC, DANE, MTA-STS, TLS-RPT, TLS cert (DomainChecker).

Examples:
  # SMTP mode — single host, JSON output
  python cli.py -i mail.example.com -o results.json

  # SMTP mode — batch from file, Excel output, custom port
  python cli.py -i servers.txt -o results.xlsx -p 587 -t 15

  # Domain mode — single domain, JSON output
  python cli.py --mode domain -i example.com -o report.json

  # Domain mode — batch, Excel output, async scanning
  python cli.py --mode domain --async-mode -i domains.txt -o report.xlsx

  # Open relay test (both modes)
  python cli.py -i servers.txt -o results.json \\
      --sender probe@yourdomain.com --recipient external@otherdomain.com

  # Domain mode with custom DNS resolvers
  python cli.py --mode domain -i domains.txt -o report.json \\
      --nameservers 1.1.1.1,8.8.8.8

  # Convert an existing JSON result to Excel (no re-scan)
  python cli.py --convert-json report.json -o report.xlsx
        """,
    )

    # ── Input / Output ──────────────────────────────────────────────────────
    parser.add_argument(
        "-i", "--input", required=False, default=None,
        help="Target hostname/IP/domain, or a file with one target per line. "
             "Not required when --convert-json is used.",
    )
    parser.add_argument(
        "-o", "--output", required=True,
        help="Output file path. Extension determines format: "
             ".json → JSON, .xlsx → Excel.",
    )
    parser.add_argument(
        "--convert-json",
        metavar="FILE.json",
        dest="convert_json",
        default=None,
        help="Convert an existing JSON result file to Excel (.xlsx) without "
             "re-running any scan. Use -o to set the output .xlsx path. "
             "Example: --convert-json report.json -o report.xlsx",
    )

    # ── Mode ────────────────────────────────────────────────────────────────
    parser.add_argument(
        "--mode", choices=["smtp", "domain"], default="smtp",
        help="Scan mode: 'smtp' uses SMTPChecker (default), 'domain' uses DomainChecker",
    )
    parser.add_argument(
        "--target-type", choices=["auto", "domain", "mx_hostname"], default="auto",
        help="Domain mode: how targets are read. 'auto' (default) = a target with MX records "
             "is a domain, otherwise an MX hostname; 'domain' = always an email domain (a "
             "domain without MX is reported as 'no_mx' / 'nxdomain', not tested as a mail "
             "server); 'mx_hostname' = always a mail server.",
    )

    # ── Sync / Async ────────────────────────────────────────────────────────
    async_group = parser.add_mutually_exclusive_group()
    async_group.add_argument(
        "--async-mode", dest="use_async", action="store_true", default=False,
        help="Scan all targets concurrently (async)",
    )
    async_group.add_argument(
        "--sync-mode", dest="use_async", action="store_false",
        help="Scan targets sequentially (default)",
    )

    # ── Connection ──────────────────────────────────────────────────────────
    parser.add_argument("-p", "--port",    type=int,   default=25,   help="SMTP port (default: 25)")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, help="SMTP connection timeout in seconds (default: 10.0)")
    parser.add_argument(
        "--dns-timeout", type=float, default=5.0,
        help="DNS query timeout in seconds, domain mode only (default: 5.0)",
    )
    parser.add_argument(
        "--nameservers",
        help="Comma-separated DNS resolver IPs, domain mode only (default: 1.1.1.1,8.8.8.8)",
    )

    # ── Open relay ──────────────────────────────────────────────────────────
    parser.add_argument(
        "--sender", default=None,
        help="Sender address for open relay test (must use a domain with MX records)",
    )
    parser.add_argument(
        "--recipient", default=None,
        help="Recipient address for open relay test (must be a foreign address)",
    )
    parser.add_argument(
        "--open-relay-mode", choices=["rcpt", "data"], default="rcpt",
        help="How far the open relay test goes: 'rcpt' = stop after RCPT TO (default, like "
             "MXToolbox); 'data' = also send DATA and expect 354, then drop the connection "
             "without sending any content (like Nessus). Nothing is relayed in either mode.",
    )

    # ── Concurrency limits ──────────────────────────────────────────────────
    parser.add_argument(
        "--max-smtp", type=int, default=10,
        help="Maximum concurrent SMTP connections / domain scans in async mode "
             "(default: 10, 0 = no limit)",
    )
    parser.add_argument(
        "--max-dns", type=int, default=50,
        help="Maximum concurrent DNS resolver calls in async mode, domain mode only "
             "(default: 50, 0 = no limit). DNS queries made by checkdmarc are not subject to this limit.",
    )

    # ── smtp mode extras ────────────────────────────────────────────────────
    parser.add_argument(
        "--options",
        help="smtp mode only: JSON file with SMTPChecker test-flag overrides",
    )

    args = parser.parse_args()

    # ── Validate output format ──────────────────────────────────────────────
    output_path = Path(args.output)
    if output_path.suffix.lower() not in (".json", ".xlsx", ".xls"):
        print(f"Error: Unsupported output format '{output_path.suffix}'. Use .json or .xlsx", file=sys.stderr)
        sys.exit(1)

    # ── Convert-only mode (--convert-json) ─────────────────────────────────
    if args.convert_json:
        src = Path(args.convert_json)
        if not src.exists():
            print(f"Error: JSON file not found: {src}", file=sys.stderr)
            sys.exit(1)
        if output_path.suffix.lower() not in (".xlsx", ".xls"):
            print("Error: --convert-json requires an .xlsx output file (-o report.xlsx)", file=sys.stderr)
            sys.exit(1)
        print(f"Converting {src} → {args.output}...")
        with open(src, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data = [data]
        # Auto-detect mode from data structure
        first = next((r for r in data if r), {})
        if "mx_results" in first or "dnssec" in first:
            export_domain_to_excel(data, args.output)
        else:
            export_smtp_to_excel(data, args.output)
        print(f"Done: {args.output}")
        return

    # ── Validate -i required for scan ──────────────────────────────────────
    if not args.input:
        print("Error: -i/--input is required unless --convert-json is used.", file=sys.stderr)
        sys.exit(1)

    # ── Validate sender MX ──────────────────────────────────────────────────
    if args.sender:
        validate_sender_mx(args.sender)

    # ── Parse nameservers ───────────────────────────────────────────────────
    nameservers: Optional[List[str]] = None
    if args.nameservers:
        nameservers = [ns.strip() for ns in args.nameservers.split(",") if ns.strip()]

    # ── Load test options (smtp mode only) ──────────────────────────────────
    options: Optional[Dict[str, bool]] = None
    if args.options:
        if args.mode != "smtp":
            print("Warning: --options is only used in smtp mode and will be ignored.", file=sys.stderr)
        else:
            options = parse_options_file(args.options)

    # ── Load targets ────────────────────────────────────────────────────────
    targets = load_targets(args.input)
    if not targets:
        print("Error: No targets found in input.", file=sys.stderr)
        sys.exit(1)

    print(f"Mode: {args.mode}  |  Targets: {len(targets)}  |  "
          f"Port: {args.port}  |  Timeout: {args.timeout}s  |  "
          f"Scan: {'async' if args.use_async else 'sync'}")
    if args.mode == "domain":
        print(f"DNS timeout: {args.dns_timeout}s  |  "
              f"Nameservers: {nameservers or ['1.1.1.1', '8.8.8.8'] }")
    print("-" * 60)

    # ── Run scans ───────────────────────────────────────────────────────────
    all_results: List[Dict[str, Any]] = []

    if args.mode == "smtp":
        if args.use_async:
            all_results = asyncio.run(
                _run_smtp_batch_async(targets, args.port, args.timeout,
                                      args.sender, args.recipient, options,
                                      args.max_smtp, args.open_relay_mode)
            )
        else:
            all_results = [
                scan_smtp_server(t, args.port, args.timeout,
                                 args.sender, args.recipient, options,
                                 args.open_relay_mode)
                for t in targets
            ]

    else:  # domain mode
        domain_kwargs = dict(
            port=args.port,
            timeout=args.timeout,
            dns_timeout=args.dns_timeout,
            nameservers=nameservers,
            open_relay_sender=args.sender,
            open_relay_recipient=args.recipient,
            open_relay_mode=args.open_relay_mode,
            target_type=args.target_type,
        )
        n = len(targets)

        if args.use_async:
            all_results = asyncio.run(
                _run_domain_batch_async(targets, domain_kwargs,
                                        args.max_smtp, args.max_dns)
            )
        else:
            for i, target in enumerate(targets, 1):
                print(f"[{i}/{n}] {target}...", end=" ", flush=True)
                try:
                    result = DomainChecker(target, **domain_kwargs).run_all_tests()
                    if isinstance(result, list):
                        result = result[0]
                    mx_count = len((result or {}).get("mx_results") or [])
                    print(f"done ({mx_count} MX)", flush=True)
                    all_results.append(result)
                except Exception as exc:
                    print(f"error: {exc}", flush=True)
                    all_results.append({"target": target, "mx_results": [], "errors": [str(exc)]})

    print("-" * 60)
    print(f"Scan completed: {len(all_results)} target(s) scanned")

    # ── Export ──────────────────────────────────────────────────────────────
    if output_path.suffix.lower() == ".json":
        export_to_json(all_results, args.output)
    else:
        if args.mode == "domain":
            export_domain_to_excel(all_results, args.output)
        else:
            export_smtp_to_excel(all_results, args.output)


if __name__ == "__main__":
    main()
