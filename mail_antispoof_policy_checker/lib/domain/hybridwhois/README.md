# HybridWhois

Unified WHOIS + RDAP client that combines [`whoisitlegacy`](../whoisitlegacy/) (TCP/43 WHOIS) and [`whoisit`](../whoisit/) (RDAP/HTTPS) to maximise the information retrieved for any asset.

---

## Quick start

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import hybridwhois

# Bootstrap both underlying clients once
hybridwhois.bootstrap()

# Synchronous
result = hybridwhois.domain("google.com")
print(result["create_date"])        # "1997-09-15"
print(result["sources_used"])       # ["whois"] or ["whois", "rdap"]
print(result["whois"]["registry"])  # raw whoisitlegacy registry entry
print(result["rdap"]["registry"])   # raw whoisit RDAP entry (if used)

# Async
import asyncio
result = asyncio.run(hybridwhois.domain_async("github.com"))
```

---

## `bootstrap()`

Must be called once before any queries.

```python
hybridwhois.bootstrap(
    whois_server_cache = True,   # enable WHOIS server address caching (whoisitlegacy)
    rdap_overrides     = True,   # load RDAP endpoint overrides (whoisit)
)

# Async variant
await hybridwhois.bootstrap_async(
    whois_server_cache = True,
    rdap_overrides     = True,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `whois_server_cache` | `bool` | `True` | Passed to `whoisitlegacy.bootstrap()` — enables WHOIS server address caching |
| `rdap_overrides` | `bool` | `True` | Passed to `whoisit.bootstrap(overrides=...)` — loads RDAP endpoint override table |

---

## Result structure

Every domain query returns:

```python
{
    # Normalised fields (whoisitlegacy format)
    "name_servers":           ["ns1.example.com", ...],
    "create_date":            "YYYY-MM-DD" | None,
    "expiry_date":            "YYYY-MM-DD" | None,
    "update_date":            "YYYY-MM-DD" | None,
    "domain_status":          ["clientTransferProhibited", ...],
    "registrar": {
        "registrar_name": "...",
        "iana_id":        146,
        "whois_server":   "whois.godaddy.com",
        "website_url":    "https://...",
    },
    "registrant":             {"full_name": ..., "email_address": ..., ...},
    "administrative_contact": {...},
    "technical_contact":      {...},
    "billing_contact":        {...},
    "available":              True | False | None,
    "availability_reason":    "Domain is registered - ...",
    "is_rate_limited":        False,
    "is_service_error":       False,
    "dnssec":                 True | False | None,
    "sources_used":           ["whois"] | ["rdap"] | ["whois", "rdap"],

    # Raw source data (kept for inspection / downstream use)
    "whois": {
        "registry":  {...} | None,   # whoisitlegacy whois_registry entry
        "registrar": {...} | None,   # whoisitlegacy whois_registrar entry
        "error":     "..." | None,
    },
    "rdap": {
        "registry":  {...} | None,   # whoisit parsed domain (registry)
        "registrar": {...} | None,   # whoisit parsed domain (registrar)
        "error":     "..." | None,
    },
}
```

---

## `domain()` / `domain_async()`

```python
result = hybridwhois.domain(
    domain_name,
    first_method    = "whois",   # "whois" (default) | "rdap"
    both            = False,     # True = always query both sources
    fallback        = True,      # True = auto-fallback if primary is incomplete
    whois_options   = {...},     # forwarded to whoisitlegacy.domain()
    rdap_options    = {...},     # forwarded to whoisit.domain()
    required_fields = [...],     # optional — see section below
)

# Async version adds rdap_pool
result = await hybridwhois.domain_async(
    domain_name,
    first_method    = "whois",
    both            = False,
    fallback        = True,
    whois_options   = {...},
    rdap_options    = {...},
    required_fields = [...],
    rdap_pool       = pool,      # optional pre-created RDAPPool
)
```

### Top-level parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain_name` | `str` | — | Fully qualified domain name |
| `first_method` | `str` | `"whois"` | Which source to try first: `"whois"` or `"rdap"` |
| `both` | `bool` | `False` | Always query both sources and merge results (async: in parallel) |
| `fallback` | `bool` | `True` | Automatically try secondary source when primary result is incomplete |
| `whois_options` | `dict` | `None` | Extra kwargs forwarded to `whoisitlegacy.domain()` — see below |
| `rdap_options` | `dict` | `None` | Extra kwargs forwarded to `whoisit.domain()` — see below |
| `required_fields` | `list` | `None` | Field-level fallback control — see below |
| `rdap_pool` | `RDAPPool` | `None` | Pre-created pool for rate limiting (async only) |

### `whois_options` — whoisitlegacy options

All keys are forwarded directly to `whoisitlegacy.domain()` / `domain_async()`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `follow_whois_registrar` | `bool` | `True` | Follow up with registrar WHOIS server after registry query |
| `include_whois_registry` | `bool` | `True` | Include `whois_registry` section in raw result |
| `raw_parsed` | `bool` | `False` | Return raw line-by-line parsed data instead of normalised structure |
| `include_raw_parsed` | `bool` | `False` | Add a `raw_parsed` flat key:value dict to `whois_registry` and `whois_registrar` |
| `timeout` | `float` | `None` | TCP connection timeout override in seconds |

```python
result = hybridwhois.domain(
    "example.com",
    whois_options={
        "follow_whois_registrar": True,
        "include_whois_registry": True,
        "include_raw_parsed":     True,   # adds raw_parsed to whois.registry / whois.registrar
        "timeout":                10.0,
    },
)
```

### `rdap_options` — whoisit options

All keys are forwarded directly to `whoisit.domain()` / `domain_async()`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `follow_rdap_registrar` | `bool` | `True` | Query the registrar RDAP endpoint in addition to the registry |
| `follow_related` | `bool` | `True` | Follow `"related"` / `"registration"` RDAP links |
| `return_on_error` | `bool` | `True`* | Return an error dict instead of raising on RDAP errors |
| `raw` | `bool` | `False` | Return the raw RDAP JSON response instead of the parsed result |
| `include_raw` | `bool` | `False` | Include the raw RDAP JSON alongside the parsed result |
| `allow_insecure_ssl` | `bool` | `False` | Disable SSL certificate verification |
| `allow_invalid_certificate` | `bool` | `False` | Accept invalid/expired SSL certificates |

> \* hybridwhois always passes `return_on_error=True` by default so errors are captured in the result dict rather than raised as exceptions.

```python
result = hybridwhois.domain(
    "example.com",
    rdap_options={
        "follow_rdap_registrar":    True,
        "follow_related":           True,
        "include_raw":              True,   # adds raw RDAP JSON to rdap.registry / rdap.registrar
        "allow_insecure_ssl":       True,   # for local/test RDAP servers
    },
)
```

---

## `create_client()` — reusable client instance

For bulk queries, create a client once and reuse it:

```python
client = hybridwhois.create_client(
    first_method    = "whois",
    both            = False,
    fallback        = True,
    whois_options   = {"follow_whois_registrar": True, "timeout": 10.0},
    rdap_options    = {"follow_rdap_registrar": True, "follow_related": True},
    rdap_pool       = hybridwhois.create_rdap_pool(max_total_concurrent=50),
    required_fields = ["expiry_date", "registrar.registrar_name"],
)

result = client.domain("example.com")
result = await client.domain_async("example.com")
```

All parameters are identical to those of `domain()` / `domain_async()`.

---

## Query modes

### Default: WHOIS first, RDAP as fallback

```python
# Typical path for a well-supported TLD — sources_used = ["whois"]
result = hybridwhois.domain("google.com")

# ccTLD registry-only WHOIS (dates + NS, no registrar) — sources_used = ["whois", "rdap"]
result = hybridwhois.domain("example.co.uk")
```

### Force RDAP first

```python
result = hybridwhois.domain("example.com", first_method="rdap")
```

### Always use both sources

Queries both WHOIS and RDAP; async version runs them in parallel:

```python
result = await hybridwhois.domain_async("example.com", both=True)
# sources_used = ["whois", "rdap"] always
```

### Disable fallback

```python
result = hybridwhois.domain("example.com", fallback=False)
# Only WHOIS is used — no automatic RDAP fallback
```

---

## `required_fields` — field-level fallback control

Trigger the secondary source when specific fields are missing, beyond the
standard completeness check.

**Single AND group** — fallback if *any* listed field is absent:

```python
result = hybridwhois.domain(
    "example.com",
    required_fields=["expiry_date", "registrar.registrar_name"],
)
# fallback if expiry_date OR registrar.registrar_name is missing
```

**OR between groups** — fallback only if *all* groups have at least one missing
field; no fallback as soon as one group is fully satisfied:

```python
result = hybridwhois.domain(
    "example.com",
    required_fields=[
        ["expiry_date", "registrant.email_address"],              # group A
        ["expiry_date", "administrative_contact.email_address"],  # group B
    ],
    # fallback only if neither group A nor group B is complete
)
```

Supports dotted paths for nested fields (`"registrar.registrar_name"`,
`"registrant.email_address"`, etc.).  The standard completeness check
(rate-limit, empty result, missing registrar) always runs first.

---

## Fallback / incompleteness logic

A result is considered **incomplete** (triggering fallback) when:
- `is_rate_limited` or `is_service_error` is `True`, OR
- Both `create_date` and `expiry_date` are absent AND no `name_servers`, OR
- Dates are present but `registrar.registrar_name` is missing (registry-only WHOIS).

The last case is the most common: many ccTLD registry WHOIS servers return
domain dates and name servers but no registrar contact.  In that case, RDAP
fills in the registrar name, IANA ID, and contact details.

---

## IP / ASN / Entity (RDAP only)

TCP/43 WHOIS only supports domain queries.  IP, ASN, and entity lookups
always use RDAP (`whoisit`):

```python
result = hybridwhois.ip("8.8.8.8")
result = asyncio.run(hybridwhois.ip_async("2001:4860:4860::8888"))

result = hybridwhois.asn(15169)
result = asyncio.run(hybridwhois.asn_async(15169))

result = hybridwhois.entity("GOGL", rir="arin")
result = asyncio.run(hybridwhois.entity_async("DR5299-RIPE", rir="ripe"))
```

### IP options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ip_address` | `str` | — | IPv4/IPv6 address or network (e.g. `"8.8.8.8"`, `"8.8.8.0/24"`) |
| `rir` | `str` | `None` | Force a specific RIR: `"arin"`, `"ripe"`, `"apnic"`, `"afrinic"`, `"lacnic"` |
| `rdap_options` | `dict` | `None` | Forwarded to `whoisit.ip()` — supports `raw`, `include_raw`, `allow_insecure_ssl` |

### ASN options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `as_number` | `int` | — | AS number (e.g. `15169`) |
| `rir` | `str` | `None` | Force a specific RIR |
| `rdap_options` | `dict` | `None` | Forwarded to `whoisit.asn()` — supports `raw`, `include_raw`, `allow_insecure_ssl` |

### Entity options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `entity_handle` | `str` | — | Entity identifier (e.g. `"GOGL"`, `"DR5299-RIPE"`) |
| `rir` | `str` | `None` | Force a specific RIR |
| `rdap_options` | `dict` | `None` | Forwarded to `whoisit.entity()` — supports `raw`, `include_raw`, `allow_insecure_ssl` |

> For IP, ASN, and entity queries, only `raw`, `include_raw`, and
> `allow_insecure_ssl` are forwarded from `rdap_options` (other keys are
> domain-specific and ignored).

---

## RDAP pool

Pass a pre-created pool to share rate-limiting state across many concurrent calls:

```python
pool = hybridwhois.create_rdap_pool(
    max_requests_per_hostname = 1,      # max simultaneous requests per hostname
    max_sleep_by_endpoint     = 90.0,   # skip endpoints whose 429 recovery > N seconds
    use_status                = True,   # persist delays across restarts (status.json)
    max_total_concurrent      = 50,     # global cap across all endpoints (None = unlimited)
)

results = await asyncio.gather(*[
    hybridwhois.domain_async(d, rdap_pool=pool)
    for d in many_domains
])

pool.flush_status()   # persist status.json before exit
```

### `create_rdap_pool()` parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_requests_per_hostname` | `int` | `1` | Max simultaneous RDAP requests to any single hostname |
| `max_sleep_by_endpoint` | `float\|None` | `90.0` | Disable endpoint if its 429-recovery sleep exceeds this value (seconds); `None` = no limit |
| `use_status` | `bool` | `True` | Load/save `data/status.json` to preserve per-endpoint delays across restarts |
| `max_total_concurrent` | `int\|None` | `None` | Global semaphore cap on total in-flight requests across all endpoints |

---

## Cross-client utility functions

Re-exported from the underlying libraries for convenience:

| Function | Source | Description |
|----------|--------|-------------|
| `get_registrar_rdap_url(iana_id)` | whoisit | RDAP base URL for a registrar (by IANA ID) |
| `get_registrar_info(iana_id)` | whoisit | `{"iana_id": ..., "rdap_url": ...}` dict |
| `get_rdap_host_delays()` | whoisit | Per-hostname RDAP delay map (from `rdap_host_delay.json`) |
| `create_rdap_pool(...)` | whoisit | Create a pre-configured `RDAPPool` |
| `get_registrar_by_iana_id(iana_id)` | whoisitlegacy | Full registrar entry from `registrar_whois_map.json` |
| `get_registrar_whois_endpoint(iana_id)` | whoisitlegacy | WHOIS server hostname for a registrar (by IANA ID) |

```python
# IANA ID → RDAP URL
rdap_url = hybridwhois.get_registrar_rdap_url("146")

# IANA ID → WHOIS server hostname
whois_ep = hybridwhois.get_registrar_whois_endpoint(146)

# Full registrar entry
entry = hybridwhois.get_registrar_by_iana_id(146)
# {"iana_registrar_id": 146, "registrar_name": "GoDaddy.com, LLC", "whois_server": "whois.godaddy.com", ...}
```

---

## Normalizer helpers (advanced)

Low-level functions exposed for downstream use:

| Function | Description |
|----------|-------------|
| `whois_domain_to_normalized(whois_result)` | Convert a `whoisitlegacy.domain()` result to the normalised dict |
| `rdap_domain_to_normalized(rdap_result)` | Convert a `whoisit.domain()` result to the normalised dict |
| `merge_normalized(primary, secondary)` | Fill gaps in `primary` from `secondary` (primary values are never overwritten) |
| `is_incomplete(normalized)` | Standard completeness check — returns `True` if fallback is warranted |
| `check_required_fields(normalized, required_fields)` | Check whether any required-fields group is satisfied |
| `needs_fallback(normalized, required_fields)` | Combined check: `is_incomplete` OR `check_required_fields` |

---

## Test script

```bash
python test_hybridwhois.py                                      # first 50 domains, default mode
python test_hybridwhois.py --limit 200                          # first 200
python test_hybridwhois.py --all                                # all domains in file
python test_hybridwhois.py --both                               # force both WHOIS + RDAP
python test_hybridwhois.py --first rdap                         # start with RDAP
python test_hybridwhois.py --no-fallback                        # disable fallback
python test_hybridwhois.py --concurrency 20                     # 20 parallel queries
python test_hybridwhois.py --domains google.com github.com      # specific domains
python test_hybridwhois.py --required-fields expiry_date registrar.registrar_name
python test_hybridwhois.py --output my_results.json
```

Results are saved to `hybrid_results.json` (or `--output` path).
