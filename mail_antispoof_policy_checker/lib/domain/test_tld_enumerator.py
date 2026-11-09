"""
Enumerate TLD availability for sonofrance.fr, google.com and amazon.com.

Downloads TLD stats on first run (cached in ./data/tld_stats.json).
Prints results live as each domain is resolved.
"""

import asyncio
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from tld_enumerator import TLDEnumerator

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DOMAINS        = ["sonofrance.fr", "google.com", "amazon.com"]
MIN_DOMAINS    = 10_000   # only scan TLDs with >= 10k registered domains
CONCURRENCY    = 20       # simultaneous WHOIS/RDAP checks
SLEEP          = [2, 5]   # sleep between service-checker requests (seconds)

# ---------------------------------------------------------------------------
# Callback
# ---------------------------------------------------------------------------

_counters: dict[str, dict] = {}


def _print_result(keyword: str, result: dict) -> None:
    domain = result["domain"]
    status = result.get("status", "unknown")
    reason = result.get("reason", "")

    _counters[keyword]["total"] += 1
    if status == "available":
        _counters[keyword]["available"] += 1
        tag = "\033[32mAVAIL\033[0m"   # green
    elif status == "unavailable":
        _counters[keyword]["unavailable"] += 1
        tag = "\033[31mTAKEN\033[0m"   # red
    else:
        _counters[keyword]["unknown"] += 1
        tag = "\033[33m  ???\033[0m"   # yellow

    print(f"  [{tag}] {domain:<40}  ({reason})")


def make_callback(keyword: str):
    def cb(result: dict) -> None:
        _print_result(keyword, result)
    return cb


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    enum = TLDEnumerator(
        min_domain_count=MIN_DOMAINS,
        sleep_between_request=SLEEP,
        include_details=False,
    )

    # Show how many TLDs will be scanned
    tlds = enum.get_tlds()
    print(f"TLDs in scope (>= {MIN_DOMAINS:,} domains): {len(tlds)}")
    print(f"Domains to enumerate: {DOMAINS}\n")

    for domain in DOMAINS:
        keyword = domain.split(".")[0]   # quick extract for display
        _counters[keyword] = {"total": 0, "available": 0, "unavailable": 0, "unknown": 0}

        print(f"{'='*60}")
        print(f"  Scanning keyword: \"{keyword}\"  (from {domain})")
        print(f"  Started: {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*60}")

        await enum.scan_by_domain_async(
            domain,
            callback=make_callback(keyword),
            concurrency=CONCURRENCY,
        )

        c = _counters[keyword]
        print(f"\n  Summary for \"{keyword}\":")
        print(f"    Scanned    : {c['total']}")
        print(f"    Available  : {c['available']}")
        print(f"    Taken      : {c['unavailable']}")
        print(f"    Unknown    : {c['unknown']}")
        print()


if __name__ == "__main__":
    asyncio.run(main())
