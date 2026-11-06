"""
Test DomainAvailabilityChecker.

Usage
-----
    # top-1000-websites.txt (first 50)
    python test_availability_checker.py

    # specific domains
    python test_availability_checker.py --domains google.com amazon.fr

    # random domain + amazon.<tld> for each TLD in the sample file
    python test_availability_checker.py --tld-coverage

    # full top-1000 list
    python test_availability_checker.py --all

    # tune concurrency and sources
    python test_availability_checker.py --concurrency 20 --sources namecheap gandi

    # include detailed WHOIS/DNS/service output
    python test_availability_checker.py --domains example.com --details

    # disable individual stages
    python test_availability_checker.py --domains example.com --no-whois
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import os
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

import hybridwhois
from domain_availability_checker import DomainAvailabilityChecker

DOMAINS_FILE  = Path(__file__).parent / "top-1000-websites.txt"
RESULTS_FILE  = Path(__file__).parent / "availability_results.json"
DEFAULT_LIMIT = 50


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_domains(limit: int | None, specific: list[str] | None) -> list[str]:
    if specific:
        return specific
    if not DOMAINS_FILE.exists():
        print(f"ERROR: {DOMAINS_FILE} not found.", file=sys.stderr)
        sys.exit(1)
    lines = [l.strip() for l in DOMAINS_FILE.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.startswith("#")]
    return lines[:limit] if limit else lines


def _tld_coverage_domains() -> list[str]:
    """
    Build a test list covering ALL root TLDs from tldextract:
    - top-1000-websites.txt (first 50) as a warm-up
    - kfdsjfdklkjfdsdsqjlkjsqiqdhjqkdjdskkjq.<tld> for every root TLD  (should be available)
    - amazon.<tld> for every root TLD                                    (often blocked/registered)
    """
    try:
        import tldextract as _tldextract
        _ext = _tldextract.TLDExtract()
        _suffixes = _ext._get_tld_extractor().tlds()
        all_tlds = sorted({s.lower() for s in _suffixes if "." not in s})
    except Exception:
        # Fallback: extract TLDs from the top-50 list
        base_domains = _load_domains(50, None)
        all_tlds = sorted({d.rsplit(".", 1)[-1] for d in base_domains if "." in d})

    base = _load_domains(50, None)
    extra: list[str] = []
    for tld in all_tlds:
        extra.append(f"kfdsjfdklkjfdsdsqjlkjsqiqdhjqkdjdskkjq.{tld}")
        extra.append(f"amazon.{tld}")
    return base + extra


def _fmt_status(result: dict) -> str:
    status = result.get("status", "?")
    reason = result.get("reason", "")
    icon   = {"available": "[+]", "unavailable": "[-]", "unknown": "[?]"}.get(status, "[?]")
    return f"{icon} {status:<12} ({reason})"


def _stats(results: dict[str, dict]) -> dict:
    total       = len(results)
    available   = sum(1 for r in results.values() if r.get("status") == "available")
    unavailable = sum(1 for r in results.values() if r.get("status") == "unavailable")
    unknown     = sum(1 for r in results.values() if r.get("status") == "unknown")
    by_reason: dict[str, int] = {}
    for r in results.values():
        k = r.get("reason", "?")
        by_reason[k] = by_reason.get(k, 0) + 1
    return {
        "total": total, "available": available,
        "unavailable": unavailable, "unknown": unknown,
        "by_reason": by_reason,
    }


# ---------------------------------------------------------------------------
# Async runner
# ---------------------------------------------------------------------------

async def run_async(
    domains:      list[str],
    checker:      DomainAvailabilityChecker,
    concurrency:  int,
) -> dict[str, dict]:
    total = len(domains)
    done  = 0
    t0    = time.monotonic()
    results: dict[str, dict] = {}

    def callback(result: dict) -> None:
        nonlocal done
        done += 1
        elapsed = time.monotonic() - t0
        rate    = done / elapsed if elapsed > 0 else 0
        domain  = result["domain"]
        fmt     = _fmt_status(result)
        print(f"[{done:>4}/{total}  {rate:.1f}/s]  {domain:<45}  {fmt}")

    results = await checker.check_domains_async(
        domains,
        callback=callback,
        concurrency=concurrency,
    )
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domains", nargs="*",
                    help="Specific domains to test")
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                    help=f"Max domains from file (default {DEFAULT_LIMIT})")
    ap.add_argument("--all", action="store_true",
                    help="Test all domains in the file")
    ap.add_argument("--tld-coverage", action="store_true",
                    help="Run TLD coverage test (top-50 + junk + amazon for every root TLD from tldextract)")
    ap.add_argument("--concurrency", type=int, default=10,
                    help="Max parallel domain checks (default 10)")
    ap.add_argument("--max-concurrent", type=int, default=None,
                    help="Max total concurrent WHOIS/RDAP sub-requests (default: no limit)")
    ap.add_argument("--sources", nargs="+",
                    default=["namecheap"],
                    choices=["namecheap", "gandi", "wix", "ovh"],
                    help="Service checker sources (default: namecheap)")
    ap.add_argument("--mode", default="lax", choices=["lax", "strict"],
                    help="Service checker aggregation mode (default: lax)")
    ap.add_argument("--sleep", nargs="+", type=float, default=None,
                    metavar="SEC",
                    help="Sleep between service-checker requests: 5 | 5 10 (random 5-10 s). "
                         "Default: 5 10")
    ap.add_argument("--details", action="store_true",
                    help="Include DNS / WHOIS / service details in output")
    ap.add_argument("--output", default=str(RESULTS_FILE),
                    help="Output JSON file path")
    args = ap.parse_args()

    # Parse sleep spec
    if args.sleep is not None:
        sleep_spec = args.sleep[0] if len(args.sleep) == 1 else args.sleep
    else:
        sleep_spec = None  # use DomainAvailabilityServiceChecker default [5, 10]

    # Build domain list
    if args.tld_coverage:
        domains = _tld_coverage_domains()
    elif args.domains:
        domains = args.domains
    else:
        limit   = None if args.all else args.limit
        domains = _load_domains(limit, None)

    hybridwhois.bootstrap()

    checker = DomainAvailabilityChecker(
        max_total_concurrent=args.max_concurrent,
        service_checker_sources=args.sources,
        service_checker_mode=args.mode,
        include_details=args.details,
        sleep_between_request=sleep_spec,
    )

    print(f"DomainAvailabilityChecker test")
    print(f"  Domains        : {len(domains)}")
    print(f"  concurrency    : {args.concurrency}")
    print(f"  sleep          : {sleep_spec if sleep_spec is not None else '[5, 10] (default)'}")
    print(f"  max_concurrent : {args.max_concurrent}")
    print(f"  sources        : {args.sources}")
    print(f"  mode           : {args.mode}")
    print(f"  include_details: {args.details}")
    print(f"  output         : {args.output}")
    print()

    t0      = time.monotonic()
    results = asyncio.run(run_async(domains, checker, args.concurrency))
    elapsed = time.monotonic() - t0

    # Write JSON
    out_path = Path(args.output)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False, default=str)

    # Summary
    s = _stats(results)
    print(f"\n{'-' * 70}")
    print(f"Done in {elapsed:.1f}s  ({len(domains)/elapsed:.1f} domains/s)")
    print(f"  Total       : {s['total']}")
    print(f"  Available   : {s['available']}")
    print(f"  Unavailable : {s['unavailable']}")
    print(f"  Unknown     : {s['unknown']}")
    print(f"\n  Breakdown by reason:")
    for reason, count in sorted(s["by_reason"].items(), key=lambda x: -x[1]):
        print(f"    {reason:<30} {count}")
    print(f"\nResults -> {out_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
