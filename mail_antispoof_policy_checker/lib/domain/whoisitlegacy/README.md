# WhoisItLegacy

A comprehensive Python WHOIS (TCP/43) client library for all internet resources — IPs, ASNs, and domain names. `whoisitlegacy` queries the classic port-43 WHOIS protocol, which is still the only way to reach registrar-level contact data for most TLDs.

---

## Features

- **Complete RIR Support**: ARIN, RIPE, AfriNIC, APNIC, LACNIC
- **Domain WHOIS with Registrar Follow-up**: Queries both the registry and the registrar's WHOIS server automatically for the richest possible contact data
- **Dual Raw WHOIS**: `raw_whois` is a structured list containing registry and/or registrar responses, each labelled with its source and endpoint
- **`source` Field**: Every domain result identifies whether the primary data came from the `"registry"` or `"registrar"`
- **Intelligent Parser**: Adaptive parser handles EPP, RPSL, NIC-HDL block formats and dozens of TLD-specific quirks
- **Normalized Output**: Whoxy-compatible flat structure (registrant, admin, tech contacts, dates, statuses…)
- **Availability Detection**: Multi-signal heuristics including redemption-period and pending-delete awareness
- **Full Async API**: Every function has an `_async` variant — `bootstrap_async`, `domain_async`, `ip_async`, `asn_async`, `entity_async`, `lookup_async` — powered by `asyncio`
- **Parallel Bootstrap**: ~1,300+ TLDs bootstrapped in 1–2 minutes using 40 parallel TCP workers (sync) or an `asyncio.Semaphore` (async)
- **Automatic Fallback**: Multiple WHOIS servers per TLD — the first responsive one is used

---

## Installation

```bash
pip install whoisitlegacy
```

---

## Quick Start

```python
import whoisitlegacy

# Bootstrap once at startup (loads TLD → WHOIS server mapping)
whoisitlegacy.bootstrap()

# Domain lookup (registry + registrar by default)
result = whoisitlegacy.domain("google.com")
print(result["source"])            # "registrar"
print(result["whois_server"])      # "whois.markmonitor.com"
print(result["domain_registered"]) # "yes"
print(result["registrant_contact"]["full_name"])

# IP lookup
result = whoisitlegacy.ip("8.8.8.8")

# ASN lookup
result = whoisitlegacy.asn(15169)
```

Every function has a fully non-blocking `_async` variant:

```python
import asyncio, whoisitlegacy

async def main():
    await whoisitlegacy.bootstrap_async()
    result = await whoisitlegacy.domain_async("google.com")
    result = await whoisitlegacy.ip_async("8.8.8.8")
    result = await whoisitlegacy.asn_async(15169)

asyncio.run(main())
```

---

## Bootstrap

```python
whoisitlegacy.bootstrap()         # silent, returns None
whoisitlegacy.bootstrap(verbose=True)  # prints progress
```

`bootstrap()` must be called **once** before any domain lookup. It returns `None` and is silent by default. To inspect the loaded state, use `get_bootstrap_stats()` or `is_bootstrapped()`.

### Why parallel?

The IANA WHOIS server (`whois.iana.org:43`) must be queried individually for each of the ~1,300+ TLDs to discover their authoritative WHOIS server. Each query is a TCP/43 connection taking 1–3 seconds. Doing this sequentially would take **~45 minutes**. With 40 parallel workers the full live bootstrap completes in **~1–2 minutes**.

The sync version uses a `ThreadPoolExecutor`; the async version (`bootstrap_async`) uses an `asyncio.Semaphore` for fully non-blocking bootstrap.

### Bootstrap Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `force` | `False` | Re-bootstrap even if already done in this process |
| `timeout` | `3.0` | Per-TLD TCP query timeout (seconds) |
| `max_workers` | `40` | Number of parallel IANA query threads |
| `verbose` | `False` | Print progress to stdout |
| `tlds_iana_cache` | `False` | Use cached TLD list instead of re-scraping IANA |
| `whois_server_cache` | `False` | Load WHOIS server map from disk cache (fastest) |
| `use_ruby_whois` | `True` | Seed with the Ruby WHOIS library data (1,317+ TLDs) |
| `max_tlds` | `None` | Limit TLDs processed (for testing) |

### Bootstrap Strategies

```python
# Full live bootstrap — scrapes IANA, queries all TLDs, saves to disk
whoisitlegacy.bootstrap(verbose=True)

# Fast startup — load from disk cache written by a previous live run
whoisitlegacy.bootstrap(whois_server_cache=True)

# Fast startup + cached TLD list
whoisitlegacy.bootstrap(tlds_iana_cache=True, whois_server_cache=True)

# Check bootstrap state
if whoisitlegacy.is_bootstrapped():
    stats = whoisitlegacy.get_bootstrap_stats()
    # {"tlds_cached": 1315, "is_complete": True}
```

---

## Domain Lookup

### Basic Usage

```python
result = whoisitlegacy.domain("example.com")
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `domain_name` | required | Domain to query (e.g. `"google.com"`) |
| `follow_whois_registrar` | `True` | Follow up with the registrar's WHOIS server for richer contacts |
| `include_whois_registry` | `True` | Include `whois_registry` in the result |
| `include_raw_parsed` | `False` | Add `raw_parsed` flat dict inside `whois_registry` / `whois_registrar` |
| `raw_parsed` | `False` | Return raw key:value pairs instead of normalized format |
| `timeout` | `10.0` | TCP query timeout in seconds |

### Registry vs Registrar WHOIS

Most domain registries (e.g. Verisign for `.com`) only return minimal data:
- Basic dates, name servers, domain status
- Registrar name and IANA ID
- **No registrant/admin/tech contacts** (redacted for GDPR)

The registrar's own WHOIS server (e.g. `whois.namecheap.com`) often returns:
- Full registrant, admin, technical, billing contacts
- Additional EPP statuses (`pendingDelete`, `redemptionPeriod`…)
- More precise registrar information

`whoisitlegacy` queries **both** by default and merges the results:
- **Contacts** → from registrar (richer)
- **Dates** → from registry (authoritative)
- **Name servers** → from registry (authoritative)
- **Statuses** → union of both sets
- **Registrar info** → registrar's self-description wins

### Response Structure

```python
result = whoisitlegacy.domain("ein-buch-lesen24.com")
```

```json
{
    "domain_name": "ein-buch-lesen24.com",
    "query_time": "2026-03-06 19:23:21",
    "source": "registrar",
    "domain_registered": "yes",
    "whois_server": "whois.namecheap.com",
    "registry_whois_server": "whois.verisign-grs.com",
    "create_date": "2025-01-20",
    "update_date": "2026-03-03",
    "expiry_date": "2026-01-20",
    "domain_registrar": {
        "iana_id": 1068,
        "registrar_name": "NAMECHEAP INC",
        "whois_server": "whois.namecheap.com",
        "website_url": "http://www.namecheap.com",
        "email_address": "abuse@namecheap.com",
        "phone_number": "+1.9854014545"
    },
    "registrant_contact": {
        "full_name": "REACTIVATION PERIOD",
        "company_name": "Withheld for Privacy Purposes",
        "mailing_address": "Kalkofnsvegur 2",
        "city_name": "Reykjavik",
        "state_name": "Capital Region",
        "zip_code": "101",
        "country_name": "Iceland",
        "country_code": "IS",
        "email_address": "reactivation-pending@mail.withheldforprivacy.com",
        "phone_number": "+354.4212434"
    },
    "administrative_contact": { "...": "..." },
    "technical_contact": { "...": "..." },
    "name_servers": ["dns101.registrar-servers.com", "dns102.registrar-servers.com"],
    "domain_status": ["clientTransferProhibited", "pendingDelete", "redemptionPeriod"],
    "whois_registry": {
        "whois_endpoint": "whois.verisign-grs.com",
        "raw_data": "Domain Name: EIN-BUCH-LESEN24.COM\r\n...",
        "create_date": "2025-01-20",
        "expiry_date": "2026-01-20",
        "name_servers": ["dns101.registrar-servers.com", "dns102.registrar-servers.com"],
        "domain_status": ["clientTransferProhibited"],
        "registrar": { "registrar_name": "NAMECHEAP INC", "whois_server": "whois.namecheap.com" },
        "available": false
    },
    "whois_registrar": {
        "whois_endpoint": "whois.namecheap.com",
        "raw_data": "Domain name: ein-buch-lesen24.com\r\n...",
        "create_date": "2025-01-20",
        "expiry_date": "2026-01-20",
        "domain_status": ["clientTransferProhibited", "pendingDelete", "redemptionPeriod"],
        "registrant_contact": { "full_name": "REACTIVATION PERIOD", "...": "..." },
        "administrative_contact": { "...": "..." },
        "technical_contact": { "...": "..." },
        "available": false
    }
}
```

### Key Fields

| Field | Type | Description |
|-------|------|-------------|
| `source` | `str` | `"registry"` or `"registrar"` — which server provided the primary data |
| `whois_server` | `str` | Hostname of the primary WHOIS server used |
| `registry_whois_server` | `str` | Registry server hostname (only present when `source` is `"registrar"`) |
| `domain_registered` | `str` | `"yes"`, `"no"`, or `"unknown"` |
| `whois_registry` | `dict` | Registry WHOIS data: parsed fields + `raw_data` + `whois_endpoint` |
| `whois_registrar` | `dict` | Registrar WHOIS data (if queried): same structure. Absent when `follow_whois_registrar=False` |

### `whois_registry` / `whois_registrar` Structure

Each per-source dict contains:

| Key | Description |
|-----|-------------|
| `whois_endpoint` | Hostname of the queried WHOIS server |
| `raw_data` | Raw WHOIS response text from that server |
| `create_date` | Creation date parsed from that server (if present) |
| `update_date` | Last update date parsed from that server (if present) |
| `expiry_date` | Expiry date parsed from that server (if present) |
| `name_servers` | Name servers parsed from that server (if present) |
| `domain_status` | EPP statuses parsed from that server (if present) |
| `registrar` | Registrar info parsed from that server (if present) |
| `registrant_contact` | Registrant contact (if present) |
| `administrative_contact` | Admin contact (if present) |
| `technical_contact` | Tech contact (if present) |
| `billing_contact` | Billing contact (if present) |
| `available` | Availability as detected from that server's response alone |
| `availability_reason` | Human-readable reason for the availability decision |

### Control What Is Included

```python
# Registry only — skip registrar follow-up (faster, less data)
result = whoisitlegacy.domain("google.com", follow_whois_registrar=False)
# result["source"] == "registry"
# result has "whois_registry" but no "whois_registrar"

# Both queried, but omit whois_registry from the result
result = whoisitlegacy.domain("google.com", include_whois_registry=False)
# result["source"] == "registrar"
# result has "whois_registrar" but no "whois_registry"

# Both queried, both included (default)
result = whoisitlegacy.domain("google.com")
# result has both "whois_registry" and "whois_registrar"
```

### Availability Detection

The parser uses multi-signal heuristics:

- **Registered** (`domain_registered: "yes"`): creation date, expiry date, name servers, registrar info, domain status — at least 2 strong signals needed
- **Available** (`domain_registered: "no"`): "no match", "not found", "domain not found", "no matching record", `未注册`, etc.
- **Hold** (`client hold`, `server hold`): domain registered but delegations suspended → `"yes"`
- **Auto-renew grace period**: domain recently expired, registrar can still auto-renew → `"yes"`
- **Redemption period** (`redemptionPeriod`): domain expired, registrant can still renew → `"yes"`
- **Pending delete** (`pendingDelete`, `待删除`): about to be released, not yet registrable → `"yes"`
- **Unknown** (`domain_registered: "unknown"`): expired domain with no grace/redemption status, or conflicting signals

### Raw Parsed Format

```python
result = whoisitlegacy.domain("google.com", raw_parsed=True)
# Returns a flat dict of raw key:value pairs (both registry and registrar
# responses concatenated and parsed line by line)
print(result["Creation Date"])  # "1997-09-15T04:00:00Z"
```

---

## Direct Parser Access

You can call the WHOIS parser directly on any raw WHOIS text, without performing a network query:

```python
from whoisitlegacy import parse_whois, WhoisParser

raw = """
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 2000-01-01T00:00:00Z
Registry Expiry Date: 2030-01-01T00:00:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
Domain Status: clientTransferProhibited
"""

result = parse_whois(raw)

print(result["available"])           # False
print(result["availability_reason"]) # "Domain is registered - ..."
print(result["create_date"])         # "2000-01-01"
print(result["expiry_date"])         # "2030-01-01"
print(result["name_servers"])        # ["ns1.example.com", "ns2.example.com"]
print(result["domain_status"])       # ["clientTransferProhibited"]
```

`parse_whois(raw_text)` returns a dict with:

| Key | Type | Description |
|-----|------|-------------|
| `available` | `bool \| None` | `False` = registered, `True` = available, `None` = unknown |
| `availability_reason` | `str` | Human-readable explanation of the decision |
| `create_date` | `str` | Creation date (`YYYY-MM-DD`) |
| `update_date` | `str` | Last update date |
| `expiry_date` | `str` | Expiry date |
| `name_servers` | `list[str]` | List of name servers (lowercased) |
| `domain_status` | `list[str]` | EPP status codes |
| `registrar` | `dict` | Registrar info (`registrar_name`, `whois_server`, `iana_id`, …) |
| `registrant` | `dict` | Registrant contact fields |
| `administrative_contact` | `dict` | Admin contact fields |
| `technical_contact` | `dict` | Tech contact fields |
| `billing_contact` | `dict` | Billing contact fields |

For lower-level access, use `WhoisParser` directly:

```python
parser = WhoisParser()
result = parser.parse(raw_text)
```

---

## Async API

Every function in `whoisitlegacy` has a fully non-blocking `_async` counterpart powered by `asyncio.open_connection()`. All parameters are identical to the synchronous versions.

### Async Bootstrap

```python
import asyncio, whoisitlegacy

# Fully async bootstrap — uses asyncio.Semaphore instead of ThreadPoolExecutor
asyncio.run(whoisitlegacy.bootstrap_async())

# Fast startup from disk cache
asyncio.run(whoisitlegacy.bootstrap_async(whois_server_cache=True))
```

### Async Domain Lookup

```python
import asyncio, whoisitlegacy

async def main():
    await whoisitlegacy.bootstrap_async(whois_server_cache=True)

    # Single async domain lookup
    result = await whoisitlegacy.domain_async("google.com")
    print(result["source"])            # "registrar"
    print(result["domain_registered"]) # "yes"

    # Concurrent domain lookups
    results = await asyncio.gather(
        whoisitlegacy.domain_async("google.com"),
        whoisitlegacy.domain_async("github.com"),
        whoisitlegacy.domain_async("example.org"),
    )
    for r in results:
        print(r["domain_name"], r["domain_registered"])

asyncio.run(main())
```

### Async IP, ASN, Entity, and Lookup

```python
import asyncio, whoisitlegacy

async def main():
    # IP address
    result = await whoisitlegacy.ip_async("8.8.8.8")

    # ASN
    result = await whoisitlegacy.asn_async(15169)

    # Entity
    result = await whoisitlegacy.entity_async("GOGL", rir="arin")
    result = await whoisitlegacy.entity_async("DR5299-RIPE")

    # Generic lookup (auto-detects type)
    result = await whoisitlegacy.lookup_async("8.8.8.8")
    result = await whoisitlegacy.lookup_async("AS15169")

    # Concurrent mixed queries
    results = await asyncio.gather(
        whoisitlegacy.ip_async("8.8.8.8"),
        whoisitlegacy.asn_async(15169),
        whoisitlegacy.domain_async("google.com"),
    )

asyncio.run(main())
```

### Via `WhoisClient`

```python
from whoisitlegacy import WhoisClient
import asyncio

async def main():
    await WhoisClient.bootstrap_async(whois_server_cache=True)

    client = WhoisClient(timeout=15.0)

    result = await client.domain_async(
        "example.com",
        follow_whois_registrar=True,
        include_raw_parsed=True,
    )
    print(result["whois_registry"]["raw_parsed"])   # flat key:value dict
    print(result["whois_registrar"]["raw_parsed"])  # flat key:value dict

    result = await client.ip_async("8.8.8.8")
    result = await client.asn_async(15169)
    result = await client.entity_async("GOGL", rir="arin")
    result = await client.lookup_async("AS3333")

asyncio.run(main())
```

---

## `include_raw_parsed` Option

When `include_raw_parsed=True`, each source entry (`whois_registry` / `whois_registrar`) gains a `raw_parsed` key — a flat `dict` of the raw key:value pairs extracted line by line from that server's response, before any normalization:

```python
result = whoisitlegacy.domain("google.com", include_raw_parsed=True)

reg = result["whois_registry"]
print(reg["raw_parsed"]["Creation Date"])   # "1997-09-15T04:00:00Z"
print(reg["raw_parsed"]["Name Server"])     # ["NS1.GOOGLE.COM", "NS2.GOOGLE.COM"]

rar = result["whois_registrar"]
print(rar["raw_parsed"]["Registrant Name"]) # "Google LLC"
```

This is useful for debugging, auditing the raw source data, or extracting fields that the parser does not yet normalize.

---

## IP Lookup

```python
result = whoisitlegacy.ip("8.8.8.8")
result = whoisitlegacy.ip("2001:4860:4860::8888")
result = whoisitlegacy.ip("8.8.8.0/24")

# Async
result = await whoisitlegacy.ip_async("8.8.8.8")
```

Uses IANA delegation lookup to route to the correct RIR (ARIN, RIPE, APNIC, AFRINIC, LACNIC) automatically.

---

## ASN Lookup

```python
result = whoisitlegacy.asn(15169)   # Google
result = whoisitlegacy.asn(3333)    # RIPE NCC

# Async
result = await whoisitlegacy.asn_async(15169)
```

---

## Entity Lookup

```python
# ARIN organization
result = whoisitlegacy.entity("GOGL", rir="arin")

# RIPE person
result = whoisitlegacy.entity("DR5299-RIPE")

# APNIC object
result = whoisitlegacy.entity("IRT-APNIC-AP", rir="apnic")

# Async
result = await whoisitlegacy.entity_async("GOGL", rir="arin")
result = await whoisitlegacy.entity_async("DR5299-RIPE")
```

---

## WhoisClient Class

For more control, use `WhoisClient` directly:

```python
from whoisitlegacy import WhoisClient

WhoisClient.bootstrap(whois_server_cache=True)

client = WhoisClient(timeout=15.0)

# Domain with full control
result = client.domain(
    "example.com",
    follow_whois_registrar=True,
    include_whois_registry=True,
)

# IP
result = client.ip("1.1.1.1")

# ASN
result = client.asn(13335)

# Entity
result = client.entity("APNIC-HM", rir="apnic")

# Generic lookup
result = client.lookup("8.8.8.8")
result = client.lookup("AS15169")
result = client.lookup("google.com")
```

---

## Exceptions

```python
from whoisitlegacy import WhoisError, WhoisConnectionError, WhoisNotFoundError

try:
    result = whoisitlegacy.domain("invalid-domain")
except WhoisNotFoundError:
    print("Domain not found")
except WhoisConnectionError:
    print("Connection failed")
except WhoisError as e:
    print(f"WHOIS error: {e}")
```

---

---

## Cross-Client Utility Functions

These functions help bridge `whoisitlegacy` with `whoisit` (RDAP) in hybrid
clients.

### `get_registrar_by_iana_id(iana_id)` — full registrar entry

Returns the full entry from `registrar_whois_map.json` for the given IANA
registrar ID, or `None` if not found.

```python
import whoisitlegacy

entry = whoisitlegacy.get_registrar_by_iana_id(146)
print(entry["whois_endpoint"])         # "whois.godaddy.com"
print(entry["iana_registrar_name"])    # "GoDaddy.com, LLC"
print(entry["iana_registrar_website"]) # "https://www.godaddy.com"
```

Fields in the returned dict: `whois_endpoint`, `iana_registrar_id`,
`iana_registrar_name`, `iana_registrar_website`, `nominet_registrar_name` (may
be `null`), `nominet_registrar_tag` (may be `null`), `nominet_registrar_website`
(may be `null`).

### `get_registrar_whois_endpoint(iana_id)` — fast endpoint lookup

Returns only the WHOIS server hostname for the registrar, or `None`.
Uses the in-memory index (built once on first call) so it is fast.

```python
endpoint = whoisitlegacy.get_registrar_whois_endpoint(146)
# -> "whois.godaddy.com"
```

---

## WHOIS Pool — Per-Endpoint Rate Limiting

`WHOISPool` is a per-endpoint concurrency and rate-limit controller for bulk domain
lookups, modelled directly after the `RDAPPool` in `whoisit`.

### Create a pool

```python
import whoisitlegacy

await whoisitlegacy.bootstrap_async(whois_server_cache=True)

pool = whoisitlegacy.create_whois_pool(
    max_requests_per_endpoint=1,   # concurrent TCP/43 connections per server (None = unlimited)
    host_delays={                  # optional per-endpoint inter-request delay (seconds)
        "whois.verisign-grs.com": 0.5,
        "whois.nic.fr": 1.0,
    },
    use_status=True,               # persist last-request timestamps across restarts
)
```

### Single domain with pool

```python
result = await whoisitlegacy.domain_async("example.com", whois_pool=pool)
```

All requests (registry **and** registrar follow-up) are routed through the pool, so
both hops are rate-limited independently.

### Bulk lookup — `check_domains_async`

```python
results = await whoisitlegacy.check_domains_async(
    ["google.com", "github.com", "example.org"],
    callback=lambda domain, result: print(domain, result["domain_registered"]),
    max_total_time=300,           # stop after 5 minutes
    follow_whois_registrar=True,
    whois_pool=pool,
)

for domain, result in results.items():
    if "_whois_error" in result:
        print(f"{domain}: {result['_whois_error']}")
    else:
        print(f"{domain}: {result['domain_registered']}")
```

The synchronous wrapper `check_domains()` is also available:

```python
results = whoisitlegacy.check_domains(
    ["google.com", "github.com"],
    follow_whois_registrar=True,
)
```

### Pool parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_requests_per_endpoint` | `1` | Max concurrent TCP/43 connections per WHOIS server. `None` = no limit |
| `host_delays` | `{}` | Dict `{hostname: delay_seconds}` — minimum inter-request gap per server |
| `use_status` | `True` | Persist last-request timestamps in `data/whois_status.json` so delays survive restarts |
| `blacklist` | `set()` | WHOIS server hostnames to never query |

### `check_domains_async` parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `callback` | `None` | `callable(domain, result)` invoked as each result arrives |
| `max_total_time` | `86400` | Stop and mark pending domains with `_whois_error` after this many seconds. `None` = unlimited |
| `follow_whois_registrar` | `True` | Also query the registrar's WHOIS server |
| `whois_pool` | `None` | Provide an existing pool; one is created automatically if `None` |
| `timeout` | `10.0` | TCP query timeout per request |

### Status persistence (`data/whois_status.json`)

The last-request wall-clock timestamp for each server is written to
`whoisitlegacy/data/whois_status.json` via a background writer thread.  On restart,
only the remaining inter-request delay is enforced — the pool never waits the full
configured delay unnecessarily.

Flush explicitly on shutdown:

```python
whoisitlegacy.flush_whois_status()
```

---

## Architecture

```
whoisitlegacy/
├── __init__.py          # Module-level API: sync + async variants of domain, ip, asn, entity,
│                        #   lookup, bootstrap; parse_whois, WhoisParser
├── client.py            # WhoisClient class (sync + async methods)
├── bootstrap.py         # TLD WHOIS server discovery + caching
│                        #   sync: ThreadPoolExecutor | async: asyncio.Semaphore
├── domain.py            # Domain WHOIS logic (registry + registrar follow-up, merging)
├── connection.py        # TCP/43 socket layer — sync (whois_query, query_rir)
│                        #   + async (async_whois_query, async_query_rir)
├── formatter.py         # WhoxyFormatter + RawFormatter
├── parsers/
│   └── whois_parser.py  # Intelligent multi-format WHOIS parser (WhoisParser, parse_whois)
├── iana.py              # IANA TLD list scraping + Ruby WHOIS data loading
├── exceptions.py
└── data/
    ├── bootstrap_cache.json     # Disk cache: TLD → [WHOIS servers]
    ├── iana_tlds_cache.json     # Disk cache: IANA TLD list
    ├── tld_whois_ruby.json      # Ruby WHOIS library data (base layer)
    └── other_whois_servers.json # Additional curated WHOIS servers
```

### Data Flow for Domain Queries

```
domain("example.com")
    │
    ├─ bootstrap lookup → registry WHOIS server (e.g. whois.verisign-grs.com)
    │
    ├─ TCP/43 query → registry WHOIS
    │   └─ parse → extract registrar.whois_server
    │
    ├─ [follow_whois_registrar=True]
    │   └─ TCP/43 query → registrar WHOIS (e.g. whois.namecheap.com)
    │       └─ parse → richer contacts, additional statuses
    │
    ├─ _merge_whois_data(registry_parsed, registrar_parsed)
    │   ├─ contacts     ← registrar (richer)
    │   ├─ dates        ← registry  (authoritative)
    │   ├─ name servers ← registry  (authoritative)
    │   ├─ statuses     ← union of both
    │   └─ registrar    ← registrar self-description
    │
    └─ WhoxyFormatter.format()
        └─ {source, whois_server, registry_whois_server,
            whois_registry: {whois_endpoint, raw_data, parsed fields…},
            whois_registrar: {whois_endpoint, raw_data, parsed fields…}}
```
