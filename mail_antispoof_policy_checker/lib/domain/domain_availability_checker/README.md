# DomainAvailabilityChecker

Fast three-stage domain availability checker that combines DNS lookups, WHOIS/RDAP data, and commercial availability APIs to give a reliable, low-latency answer for any domain.

---

## How it works

Every domain goes through up to three stages, stopping as soon as a definitive answer is found:

```
Domain
  │
  ▼
Stage 1 — DNS NS lookup
  NS records found?
  ├── YES → UNAVAILABLE  (domain is in use)
  └── NO / timeout → continue
         │
         ▼
       Stage 2 — WHOIS / RDAP (hybridwhois)
         available=False or reserved/hold status?
         ├── YES → UNAVAILABLE
         └── NO / unknown → continue
                │
                ▼
              Stage 3 — Service checker (DomainAvailabilityServiceChecker)
                available=True  → AVAILABLE
                available=False → UNAVAILABLE
                available=None  → UNKNOWN
```

### Stage 1 — DNS NS lookup

Uses `dns.asyncresolver` (dnspython) to query NS records.  Three DNS resolvers are tried in order:

1. **System default** nameserver
2. **1.1.1.1** (Cloudflare)
3. **8.8.8.8** (Google)

Each resolver is tried up to **3 times** before falling back to the next (max 9 queries total).  A confirmed NS record proves the domain is in use — no further stages are needed.

### Stage 2 — WHOIS / RDAP

Uses [`hybridwhois`](../hybridwhois/) to query both TCP/43 WHOIS and RDAP.  The result is considered "unavailable" when:
- `available=False` is returned by whoisitlegacy parser, OR
- `domain_status` contains a blocking value (`reserved`, `hold`, `serverHold`, `pendingDelete`, `redemptionPeriod`, `blocked`, `quarantined`, …)

### Stage 3 — Service checker

Uses [`DomainAvailabilityServiceChecker`](../DomainAvailabilityServiceChecker/) to query commercial registrar APIs (NameCheap, Gandi, Wix, OVH).  Default: **NameCheap only** in **lax** mode (available = at least one source agrees).

**Optional:** if the `domain_availability_service_checker` package is missing or fails to
import, stages 1–2 still run (NS, WHOIS/RDAP) and the domains they cannot decide end as
`unknown` (reason `service_unknown`); the import error is kept in
`DomainAvailabilityChecker.service_checker_error`.

---

## Quick start

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import hybridwhois
from domain_availability_checker import DomainAvailabilityChecker

hybridwhois.bootstrap()

checker = DomainAvailabilityChecker()

# Single domain (sync)
result = checker.check_domain("example.com")
print(result["status"])   # "available" | "unavailable" | "unknown"
print(result["reason"])   # why the status was determined

# Multiple domains (sync)
results = checker.check_domains(["example.com", "google.com", "zzz-not-real.io"])
for domain, r in results.items():
    print(f"{domain}: {r['status']} ({r['reason']})")
```

### Async

```python
import asyncio

async def main():
    hybridwhois.bootstrap()
    checker = DomainAvailabilityChecker()

    # Single domain
    result = await checker.check_domain_async("example.com")

    # Multiple domains with progress callback
    def on_result(r):
        print(f"{r['domain']}: {r['status']}")

    results = await checker.check_domains_async(
        ["example.com", "google.com", "zzz-not-real.io"],
        callback=on_result,
        concurrency=20,
    )

asyncio.run(main())
```

---

## `DomainAvailabilityChecker` — constructor parameters

```python
checker = DomainAvailabilityChecker(
    max_total_concurrent    = None,          # global WHOIS/RDAP concurrency cap
    service_checker_sources = ["namecheap"], # which service APIs to query
    service_checker_mode    = "lax",         # "lax" | "strict"
    include_details         = False,         # add raw DNS/WHOIS/service data
    whois_options           = {},            # forwarded to whoisitlegacy
    rdap_options            = {},            # forwarded to whoisit
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_total_concurrent` | `int\|None` | `None` | Maximum simultaneous WHOIS TCP/43 and RDAP HTTPS requests combined.  Maps to `max_total_concurrent` in the RDAP pool and `max_concurrent` in the WHOIS pool.  `None` = no limit. |
| `service_checker_sources` | `list[str]` | `["namecheap"]` | Which commercial APIs to query in stage 3.  Options: `"namecheap"`, `"gandi"`, `"wix"`, `"ovh"`. |
| `service_checker_mode` | `str` | `"lax"` | How to aggregate multiple sources: `"lax"` = available if any source says so; `"strict"` = available only if all non-error sources agree. |
| `include_details` | `bool` | `False` | When `True`, each result includes a `"details"` key with raw DNS, WHOIS, and service-checker output.  Useful for debugging. |
| `whois_options` | `dict` | `{}` | Extra kwargs forwarded to `whoisitlegacy.domain_async()`.  See [hybridwhois README](../hybridwhois/README.md). |
| `rdap_options` | `dict` | `{}` | Extra kwargs forwarded to `whoisit.domain_async()`.  See [hybridwhois README](../hybridwhois/README.md). |

---

## Methods

### `check_domain(domain)` — sync, single domain

```python
result = checker.check_domain("example.com")
```

### `check_domains(domains)` — sync, batch

```python
results = checker.check_domains(["example.com", "google.com"])
# returns {domain: result, ...}
```

### `check_domain_async(domain)` — async, single domain

```python
result = await checker.check_domain_async("example.com")
```

### `check_domains_async(domains, callback, concurrency)` — async, batch

```python
results = await checker.check_domains_async(
    domains,
    callback    = on_result,   # called for each domain as it completes (sync or async)
    concurrency = 20,          # max simultaneous domain checks
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domains` | `list[str]` | — | Domains to check |
| `callback` | `callable\|None` | `None` | Invoked with each result dict as it completes.  Can be sync or `async`. |
| `concurrency` | `int` | `10` | Max domain checks running in parallel.  Independent of `max_total_concurrent` (which limits sub-requests). |

> **Batching note:** When calling `check_domains` / `check_domains_async`, the service checker (stage 3) is invoked with a single batch call for all remaining domains, which is much more efficient than per-domain calls (NameCheap supports 64 domains per batch).  The single-domain methods (`check_domain`, `check_domain_async`) skip this optimisation.

---

## Result structure

```python
{
    "domain":    "example.com",
    "status":    "available" | "unavailable" | "unknown",
    "available": True | False,      # True only when status == "available"
    "reason":    str,               # see table below

    # Only when include_details=True:
    "details": {
        "dns": {
            "has_ns":      bool,        # True if NS records were found
            "ns_records":  list[str],   # e.g. ["ns1.example.com", ...]
            "server_used": str | None,  # "system" | "1.1.1.1" | "8.8.8.8" | None
            "nxdomain":    bool,        # True if domain doesn't exist in DNS
            "error":       str | None,
        },
        "whois": { ... } | None,    # full hybridwhois result (stage 2)
        "service": { ... } | None,  # DomainAvailabilityServiceChecker result (stage 3)
    },
}
```

### Reason codes

| Reason | Stage | Meaning |
|--------|-------|---------|
| `has_ns` | 1 | NS records found in DNS — domain is actively used |
| `whois_unavailable` | 2 | WHOIS/RDAP reports domain as registered or blocked |
| `service_available` | 3 | Service checker confirms domain is available |
| `service_unavailable` | 3 | Service checker confirms domain is taken |
| `service_unknown` | 3 | Service checker could not determine availability |

---

## Status constants

```python
from domain_availability_checker import STATUS_AVAILABLE, STATUS_UNAVAILABLE, STATUS_UNKNOWN
# "available", "unavailable", "unknown"
```

---

## `include_details` — verbose mode

```python
checker = DomainAvailabilityChecker(include_details=True)
result  = checker.check_domain("example.co.uk")

print(result["details"]["dns"]["server_used"])         # "system"
print(result["details"]["whois"]["registrar"])         # hybridwhois registrar dict
print(result["details"]["service"]["details"])         # per-source breakdown
```

---

## Concurrency tuning

```python
checker = DomainAvailabilityChecker(
    max_total_concurrent = 30,   # cap WHOIS + RDAP sub-requests
)

results = await checker.check_domains_async(
    domains,
    concurrency = 50,    # 50 domains in flight simultaneously
)
```

Two independent knobs:

| Parameter | Controls |
|-----------|---------|
| `max_total_concurrent` | Internal WHOIS TCP/43 + RDAP HTTPS concurrency across both libraries |
| `concurrency` (in `check_domains_async`) | How many domains are checked simultaneously at the top level |

---

## Test script

```bash
# First 50 domains from top-1000-websites.txt
python test_availability_checker.py

# Specific domains
python test_availability_checker.py --domains google.com amazon.fr zzz-not-real-at-all.io

# TLD coverage: top-50 + random + amazon.<tld> per unique TLD
python test_availability_checker.py --tld-coverage

# Full list
python test_availability_checker.py --all

# Tune concurrency
python test_availability_checker.py --concurrency 20 --max-concurrent 50

# Multiple sources in strict mode
python test_availability_checker.py --sources namecheap gandi --mode strict

# Include full details
python test_availability_checker.py --domains example.com --details

# Custom output file
python test_availability_checker.py --output my_results.json
```

Results are saved to `availability_results.json`.

---

## Dependencies

- `dnspython` — async DNS queries (`pip install dnspython`)
- `hybridwhois` — WHOIS/RDAP lookups (sibling package)
- `DomainAvailabilityServiceChecker` — commercial availability APIs (sibling package)
