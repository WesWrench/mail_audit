"""
mail_audit CLI - Command-line interface for the mail audit tool.

Usage examples
--------------
Single domain (sync, default):
    python cli.py -i example.com

Multiple domains from a file (async):
    python cli.py -i domains.txt --async-mode

Comma-separated domains:
    python cli.py -i "example.com,target.org"

Custom output directory:
    python cli.py -i example.com --output-dir ./results

Custom SMTP options:
    python cli.py -i example.com --sender test@example.net \\
                  --recipient osef@domain.com --port 25

All options:
    python cli.py -i example.com \\
        --port 25 --timeout 10 --dns-timeout 5 \\
        --check-types spf,dmarc \\
        --async-mode \\
        --output-dir ./output \\
        --output mail_audit_report
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from mail_audit.lib import MailAuditor
from mail_audit.lib.models import AttackProbability


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mail-audit",
        description=(
            "Mail security auditing tool. Runs SMTP checks (MTA-STS, DANE, "
            "STARTTLS, Open Relay) and anti-spoofing policy checks (SPF, DMARC, "
            "DKIM), then generates an Excel report with detailed attack scenarios."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ------------------------------------------------------------------ Input
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-i", "--input",
        required=False,
        default=None,
        metavar="DOMAINS",
        help=(
            "Domain(s) to audit. Accepts: a single domain (e.g. example.com), "
            "a comma-separated list (e.g. 'example.com,target.org'), or a path "
            "to a file containing one domain per line. "
            "Optional when --smtp-json or --antispoof-json is provided "
            "(domains are derived from the JSON file)."
        ),
    )
    input_group.add_argument(
        "--smtp-json",
        metavar="FILE.json",
        dest="smtp_json",
        default=None,
        help=(
            "Path to a pre-computed smtp_checker result file (JSON). "
            "When provided, SMTP checks are skipped and results are loaded "
            "from this file instead. Accepts mail_audit _smtp.json output or "
            "smtp_checker native JSON output."
        ),
    )
    input_group.add_argument(
        "--antispoof-json",
        metavar="FILE.json",
        dest="antispoof_json",
        default=None,
        help=(
            "Path to a pre-computed antispoof result file (JSON). "
            "When provided, SPF/DMARC/DKIM checks are skipped and results are "
            "loaded from this file instead. Accepts mail_audit _antispoof.json "
            "output or mail_antispoof_policy_checker native policy_check_*.json output."
        ),
    )

    # ------------------------------------------------------------------ SMTP
    smtp_group = parser.add_argument_group("SMTP / Domain options")
    smtp_group.add_argument(
        "-p", "--port",
        type=int,
        default=25,
        metavar="PORT",
        help="SMTP port (default: 25)",
    )
    smtp_group.add_argument(
        "-t", "--timeout",
        type=float,
        default=10.0,
        metavar="SEC",
        help="SMTP connection timeout in seconds (default: 10.0)",
    )
    smtp_group.add_argument(
        "--dns-timeout",
        type=float,
        default=5.0,
        metavar="SEC",
        dest="dns_timeout_smtp",
        help="DNS query timeout for SMTP checker in seconds (default: 5.0)",
    )
    smtp_group.add_argument(
        "--nameservers",
        metavar="IP[,IP...]",
        help="Comma-separated custom DNS resolvers (e.g. '1.1.1.1,8.8.8.8') used by BOTH the SMTP checker and the antispoof (SPF/DKIM/DMARC) checkers",
    )
    smtp_group.add_argument(
        "--sender",
        default=None,
        metavar="EMAIL",
        help=(
            "MAIL FROM address for the open relay test (e.g. test@example.com). "
            "If not set, the open relay test is automatically disabled."
        ),
    )
    smtp_group.add_argument(
        "--open-relay-mode",
        choices=["rcpt", "data"],
        default="rcpt",
        help=(
            "How far the open relay test goes: 'rcpt' = stop after RCPT TO (default, like "
            "MXToolbox); 'data' = also send DATA and expect 354, then drop the connection "
            "without sending any content (like Nessus). Nothing is relayed in either mode."
        ),
    )
    smtp_group.add_argument(
        "--recipient",
        default=None,
        metavar="EMAIL",
        help=(
            "RCPT TO address for the open relay test — must be an external address "
            "unrelated to the audited domain (e.g. check@external.com). "
            "If not set, the open relay test is automatically disabled."
        ),
    )
    smtp_group.add_argument(
        "--no-open-relay",
        action="store_true",
        default=False,
        dest="no_open_relay",
        help=(
            "Disable the SMTP open relay test. Useful when you have not configured "
            "a valid external RCPT TO address or when the test is too intrusive. "
            "Equivalent to --smtp-options with {\"smtp_open_relay\": false}."
        ),
    )
    smtp_group.add_argument(
        "--smtp-options",
        metavar="FILE.json",
        dest="smtp_options_file",
        help=(
            "Path to a JSON file with SMTPChecker test flag overrides. "
            "Valid keys: smtp_open_relay, smtp_tls, smtp_banner_check, "
            "smtp_reverse_dns_mismatch, smtp_tls_cert_check, etc."
        ),
    )

    # --------------------------------------------------------------- AntiSpoof
    antispoof_group = parser.add_argument_group("AntiSpoof options")
    antispoof_group.add_argument(
        "--check-types",
        default="spf,dmarc,dkim",
        metavar="TYPES",
        help="Comma-separated checks to run: spf,dmarc,dkim (default: all three)",
    )
    antispoof_group.add_argument(
        "--antispoof-dns-timeout",
        type=int,
        default=5,
        metavar="SEC",
        dest="antispoof_dns_timeout",
        help="DNS query timeout for antispoof checkers in seconds (default: 5)",
    )
    antispoof_group.add_argument(
        "--use-ns-record",
        action="store_true",
        help="Use domain's authoritative NS for antispoof DNS queries",
    )
    antispoof_group.add_argument(
        "--max-dns-retries",
        type=int,
        default=3,
        metavar="N",
        help="DNS retry count before fallback for antispoof checkers (default: 3)",
    )
    antispoof_group.add_argument(
        "--data-dir",
        metavar="DIR",
        help=(
            "Directory containing CSV data files for the antispoof checker. "
            "Defaults to mail_antispoof_policy_checker/data/ inside the repo."
        ),
    )
    antispoof_group.add_argument(
        "--maxmind-key",
        metavar="KEY",
        help="MaxMind GeoIP licence key for AS-number lookups in SPF analysis",
    )
    antispoof_group.add_argument(
        "--dkim-selector-file",
        metavar="FILE",
        help=(
            "Custom DKIM selector list (one per line, '#' comments allowed). "
            "Replaces the bundled DKIM_Selectors.txt"
        ),
    )
    antispoof_group.add_argument(
        "--skip-cname-check",
        action="store_true",
        help="Skip the CNAME chain check on DKIM selector, _dmarc and SPF domain names",
    )
    antispoof_group.add_argument(
        "--skip-factordb-check",
        action="store_true",
        help=(
            "Do not look DKIM RSA moduli up on factordb.com (known factorizations). "
            "The offline key checks (exponent, small factor, prime modulus) still run"
        ),
    )
    antispoof_group.add_argument(
        "--skip-domain-availability-check",
        action="store_true",
        help="Do not check whether broken CNAME targets point to unregistered domains",
    )

    # --------------------------------------------------------------- Execution
    exec_group = parser.add_argument_group("Execution")
    exec_group.add_argument(
        "--no-smtp",
        action="store_true",
        default=False,
        dest="no_smtp",
        help=(
            "Skip smtp_checker entirely — no SMTP connections are made. "
            "MITM and open-relay scenarios will not be generated. "
            "Useful for fast policy-only audits or when port 25 is blocked."
        ),
    )
    mode_group = exec_group.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--sync-mode",
        action="store_true",
        default=False,
        help="Run checks sequentially with asyncio.run() (default behaviour)",
    )
    mode_group.add_argument(
        "--async-mode",
        action="store_true",
        default=False,
        help="Run checks concurrently (faster for many domains)",
    )
    exec_group.add_argument(
        "--max-concurrent",
        type=int,
        default=50,
        metavar="N",
        help="Max concurrent domain checks for antispoof (default: 50)",
    )
    exec_group.add_argument(
        "--max-smtp",
        type=int,
        default=10,
        metavar="N",
        help="Max concurrent SMTP connections (default: 10)",
    )
    exec_group.add_argument(
        "--max-dns",
        type=int,
        default=50,
        metavar="N",
        help="Max concurrent DNS queries for SMTP checker (default: 50)",
    )

    # ----------------------------------------------------------------- Output
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output",
        default="mail_audit",
        metavar="BASENAME",
        help="Output filename base (without extension, default: mail_audit)",
    )
    output_group.add_argument(
        "--output-dir",
        default="./output",
        metavar="DIR",
        help="Directory for output files (default: ./output)",
    )
    output_group.add_argument(
        "--email-services",
        metavar="FILE.json",
        dest="email_services_file",
        help="Path to a custom email_services.json configuration file",
    )

    return parser


# ---------------------------------------------------------------------------
# Domain resolution from -i argument
# ---------------------------------------------------------------------------


def resolve_domains(input_str: str) -> List[str]:
    """
    Parse the -i / --input argument into a list of domain strings.

    Accepts:
    - A single domain: "example.com"
    - A comma-separated list: "example.com,target.org"
    - A file path (one domain per line)
    """
    # A file if it exists, has a path separator or a list-file extension.
    # A bare suffix is not enough: every domain has one (".fr", ".com").
    path = Path(input_str)
    looks_like_file = (
        path.is_file()
        or "/" in input_str
        or "\\" in input_str
        or path.suffix.lower() in (".txt", ".csv", ".lst", ".list")
    )

    if looks_like_file:
        if not path.exists():
            raise ValueError(f"File not found: {path.resolve()}")
        if not path.is_file():
            raise ValueError(f"Not a file: {path.resolve()}")
        raw = path.read_text(encoding="utf-8").splitlines()
        domains = [
            line.strip()
            for line in raw
            if line.strip() and not line.strip().startswith("#")
        ]
        if not domains:
            raise ValueError(f"No domains found in file: {path}")
        return domains

    # Comma-separated or single domain
    domains = [d.strip() for d in input_str.split(",") if d.strip()]
    if not domains:
        raise ValueError(f"No valid domains found in input: '{input_str}'")
    return domains


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------


def _domains_from_json(
    smtp_path: Optional[str] = None,
    antispoof_path: Optional[str] = None,
) -> List[str]:
    """
    Derive a domain list from pre-computed JSON files when -i is not provided.

    Preference order: antispoof JSON first (``"domain"`` key), then smtp JSON
    (``"target"`` key).  Duplicates are removed; original order is preserved.
    """
    seen: "dict[str, None]" = {}

    if antispoof_path:
        with open(antispoof_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for entry in data or []:
            d = (entry or {}).get("domain", "").strip()
            if d:
                seen[d] = None

    if smtp_path and not seen:
        with open(smtp_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data = [data]
        for entry in data or []:
            d = (entry or {}).get("target", "").strip()
            if d:
                seen[d] = None

    return list(seen.keys())


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    # Windows consoles/pipes default to cp1252: never crash on non-ASCII output text.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    parser = build_parser()
    args = parser.parse_args(argv)

    # ---- Validate inputs ----
    if not args.input and not args.smtp_json and not args.antispoof_json:
        print(
            "ERROR: At least one of -i/--input, --smtp-json, or --antispoof-json is required.",
            file=sys.stderr,
        )
        return 1

    # ---- Resolve domains ----
    domains: List[str] = []
    if args.input:
        try:
            domains = resolve_domains(args.input)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    # Derive domains from JSON files when -i is not provided
    if not domains and (args.smtp_json or args.antispoof_json):
        try:
            domains = _domains_from_json(
                smtp_path=args.smtp_json,
                antispoof_path=args.antispoof_json,
            )
        except Exception as exc:
            print(f"ERROR: Could not derive domains from JSON file(s): {exc}", file=sys.stderr)
            return 1

    if not domains:
        print("ERROR: No domains could be resolved from the provided inputs.", file=sys.stderr)
        return 1

    # ---- Load SMTP options from file if provided ----
    smtp_options: Optional[dict] = None
    if args.smtp_options_file:
        try:
            with open(args.smtp_options_file, "r", encoding="utf-8") as fh:
                smtp_options = json.load(fh)
        except Exception as exc:
            print(f"WARNING: Could not load smtp-options file: {exc}", file=sys.stderr)

    # ---- Apply individual SMTP flag overrides ----
    if args.no_open_relay:
        smtp_options = smtp_options or {}
        smtp_options["smtp_open_relay"] = False

    # ---- Parse nameservers ----
    nameservers = None
    if args.nameservers:
        nameservers = [ns.strip() for ns in args.nameservers.split(",") if ns.strip()]

    # ---- Parse check types ----
    check_types = [ct.strip().lower() for ct in args.check_types.split(",") if ct.strip()]

    if args.dkim_selector_file and not os.path.isfile(args.dkim_selector_file):
        print(f"ERROR: DKIM selector file not found: {args.dkim_selector_file}", file=sys.stderr)
        return 1

    # ---- Build labels ----
    if args.smtp_json:
        smtp_label = f"offline (loaded from {args.smtp_json})"
    elif args.no_smtp:
        smtp_label = "skipped (--no-smtp)"
    elif args.no_open_relay or not args.sender or not args.recipient:
        reason = "--no-open-relay" if args.no_open_relay else "sender/recipient not configured"
        smtp_label = f"port {args.port} (open relay disabled: {reason})"
    else:
        smtp_label = f"port {args.port} (open relay [{args.open_relay_mode}]: {args.sender} → {args.recipient})"

    if args.antispoof_json:
        antispoof_label = f"offline (loaded from {args.antispoof_json})"
    else:
        antispoof_label = ", ".join(check_types)

    maxmind_key = args.maxmind_key or os.environ.get("MAXMIND_LICENSE_KEY")
    if maxmind_key:
        maxmind_label = "initialized" + ("" if args.maxmind_key else " (from env MAXMIND_LICENSE_KEY)")
    else:
        maxmind_label = "disabled (no license key — AS organization lookups unavailable)"

    # ---- Print startup info ----
    if len(domains) <= 5:
        domains_inline = ", ".join(domains)
    else:
        domains_inline = ", ".join(domains[:5]) + f", … (+{len(domains) - 5} more)"
    print(f"\n[mail-audit] Starting audit for {len(domains)} domain(s): {domains_inline}")
    print(f"[mail-audit] Output:   {args.output_dir}/{args.output}.{{json,xlsx}}")
    print(f"[mail-audit] Checks:   antispoof={antispoof_label} | smtp={smtp_label}")
    print(f"[mail-audit] MaxMind:  {maxmind_label}")
    print(f"[mail-audit] Mode:     {'async' if args.async_mode else 'sync (default)'}")
    print()

    # ---- Build auditor ----
    try:
        auditor = MailAuditor(
            domains=domains,
            # Offline / hybrid inputs
            smtp_json_path=args.smtp_json,
            antispoof_json_path=args.antispoof_json,
            # SMTP
            smtp_port=args.port,
            smtp_timeout=args.timeout,
            smtp_dns_timeout=args.dns_timeout_smtp,
            smtp_nameservers=nameservers,
            open_relay_sender=args.sender,
            open_relay_recipient=args.recipient,
            open_relay_mode=args.open_relay_mode,
            smtp_options=smtp_options,
            # AntiSpoof
            check_types=check_types,
            nameservers=nameservers,
            dns_timeout=args.antispoof_dns_timeout,
            use_ns_record=args.use_ns_record,
            max_dns_retries=args.max_dns_retries,
            data_dir=args.data_dir,
            maxmind_license_key=args.maxmind_key,
            dkim_selector_file=args.dkim_selector_file,
            cname_check=not args.skip_cname_check,
            skip_domain_availability_check=args.skip_domain_availability_check,
            factordb_check=not args.skip_factordb_check,
            # Execution
            skip_smtp=args.no_smtp,
            output_dir=args.output_dir,
            max_concurrent=args.max_concurrent,
            max_smtp=args.max_smtp,
            max_dns=args.max_dns,
            email_services_file=args.email_services_file,
        )
    except Exception as exc:
        print(f"ERROR: Failed to initialise MailAuditor: {exc}", file=sys.stderr)
        return 1

    # ---- Run ----
    try:
        if args.async_mode:
            result = asyncio.run(auditor.run_async())
        else:
            result = auditor.run()
    except KeyboardInterrupt:
        print("\n[mail-audit] Interrupted by user.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: Audit failed: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    # ---- Export ----
    try:
        paths = auditor.export(result, base_filename=args.output)
    except Exception as exc:
        import traceback
        print(f"ERROR: Export failed: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

    # ---- Print summary ----
    auditor.print_summary(result)

    print("[mail-audit] Output files generated:")
    for fmt, path in paths.items():
        print(f"  {fmt.upper():8s}: {path}")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
