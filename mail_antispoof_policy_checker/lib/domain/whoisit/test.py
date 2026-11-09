"""
RDAP bulk lookup for top-1000-websites.txt

Reads domain names from top-1000-websites.txt, runs async RDAP queries (registry
+ registrar) through an RDAPPool, and writes each result to ./results/<domain>.json
as it arrives.

Usage:
    python test.py

Results are streamed — each file is written as soon as the domain finishes, so you
can inspect partial output while the script is still running.

The script respects configured rate limits (from rdap_host_delay.json /
rdap_registrar_host_delay.json), skips blacklisted endpoints, and handles 429
responses automatically.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

# Add the parent directory to the path so we can import whoisit directly
sys.path.insert(0, str(Path(__file__).parent.parent))
import whoisit

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DOMAINS_FILE = Path(__file__).parent / "top-1000-websites.txt"
RESULTS_DIR = Path(__file__).parent / "results"

# Pool settings
MAX_CONCURRENT_PER_HOST = 1
MAX_SLEEP_BY_ENDPOINT = 90      # skip endpoints requiring > 90 s sleep
MAX_TOTAL_TIME = None           # no global time limit (set e.g. 3600 for 1 hour)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_counter = {"done": 0, "errors": 0}
_start_time = 0.0


def _safe_filename(domain: str) -> str:
    """Convert a domain name to a safe filename."""
    return domain.replace("/", "_").replace(":", "_").replace("*", "_")


def on_result(domain: str, result: dict) -> None:
    """
    Callback invoked as each domain result becomes available.
    Writes the result to results/<domain>.json and prints a status line.
    """
    _counter["done"] += 1
    elapsed = time.monotonic() - _start_time

    # Determine status
    registry = result.get("registry") if isinstance(result, dict) else result
    has_error = (
        isinstance(result, dict)
        and (
            "_rdap_error" in result
            or (isinstance(registry, dict) and "_rdap_error" in registry)
        )
    )
    if has_error:
        _counter["errors"] += 1
        status = "ERR"
    else:
        status = "OK "

    # Write to file
    out_path = RESULTS_DIR / f"{_safe_filename(domain)}.json"
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False, default=str)
    except Exception as exc:
        print(f"  [WRITE ERROR] {domain}: {exc}", file=sys.stderr)
        return

    n = _counter["done"]
    rate = n / elapsed if elapsed > 0 else 0
    print(
        f"[{status}] #{n:>4}  {elapsed:>7.1f}s  {rate:.2f}/s  {domain}",
        flush=True,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    global _start_time

    # Read domain list
    if not DOMAINS_FILE.exists():
        print(f"ERROR: {DOMAINS_FILE} not found", file=sys.stderr)
        sys.exit(1)

    with open(DOMAINS_FILE, encoding="utf-8") as fh:
        domains = [
            line.strip()
            for line in fh
            if line.strip() and not line.startswith("#")
        ]

    print(f"Loaded {len(domains)} domains from {DOMAINS_FILE.name}")

    # Bootstrap
    print("Bootstrapping RDAP data...")
    await whoisit.bootstrap_async(overrides=True)
    print("Bootstrap complete.")

    # Create results directory
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Create pool
    pool = whoisit.create_rdap_pool(
        max_requests_per_hostname=MAX_CONCURRENT_PER_HOST,
        max_sleep_by_endpoint=MAX_SLEEP_BY_ENDPOINT,
        use_status=True,
    )

    print(f"\nStarting RDAP lookups (raw=True, follow_rdap_registrar=True)...\n")
    _start_time = time.monotonic()

    results = await whoisit.check_domains_async(
        domains,
        callback=on_result,
        max_total_time=MAX_TOTAL_TIME,
        max_sleep_by_endpoint=MAX_SLEEP_BY_ENDPOINT,
        follow_rdap_registrar=True,
        raw=True,
        allow_invalid_certificate=True,
        rdap_pool=pool,
    )

    elapsed = time.monotonic() - _start_time
    total = len(results)
    errors = _counter["errors"]
    ok = total - errors

    print(f"\n{'─' * 60}")
    print(f"Done in {elapsed:.1f}s")
    print(f"  Total  : {total}")
    print(f"  OK     : {ok}")
    print(f"  Errors : {errors}")
    print(f"  Results: {RESULTS_DIR}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        whoisit.flush_status()
        elapsed = time.monotonic() - _start_time if _start_time else 0
        print(
            f"\nInterrupted after {elapsed:.1f}s  "
            f"({_counter['done']} done, {_counter['errors']} errors)",
            file=sys.stderr,
        )
        sys.exit(130)
