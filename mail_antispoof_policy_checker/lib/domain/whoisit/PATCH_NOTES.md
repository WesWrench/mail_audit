# Whoisit Patches for RDAP Collection

This document describes the patches applied to the whoisit library for improved RDAP data collection.

## Patch 1: `return_on_error` Parameter

### Problem
When querying blocked/reserved domains, RDAP servers return HTTP 404 with a JSON body containing useful information (e.g., "Blocked Domain" notices). The original whoisit library raises `ResourceDoesNotExist` exception on 404, preventing access to this valuable data.

### Solution
Added `return_on_error` parameter to all query functions:
- `whoisit.domain(domain_name, ..., return_on_error=False)`
- `whoisit.domain_async(domain_name, ..., return_on_error=False)`
- `whoisit.ip(ip_address, ..., return_on_error=False)`
- `whoisit.asn(as_number, ..., return_on_error=False)`

### Behavior

**Default (`return_on_error=False`)**: Original behavior - raises exceptions on HTTP errors

**With `return_on_error=True`**: Returns JSON response with `_rdap_error` field:
```python
result = whoisit.domain('youtube.cash', raw=True, return_on_error=True)
# Returns:
{
  "notices": [...],
  "_rdap_error": {
    "status_code": 404,
    "error_type": "ResourceDoesNotExist",
    "message": "RDAP GET request to ... returned a 404 error..."
  }
}
```

### Modified Files
- `whoisit/query.py`: Added `return_on_error` parameter to `BaseQuery`, `Query`, `QueryAsync`
- `whoisit/__init__.py`: Added `return_on_error` parameter to `domain()`, `domain_async()`, etc.

---

## Patch 2: `allow_invalid_certificate` Parameter

### Problem
Some RDAP servers have invalid or self-signed SSL certificates. The existing `allow_insecure_ssl=True` only permits weaker SSL ciphers but still validates certificates. This causes SSL errors for servers with certificate issues.

Example: `whoisit.domain("instagram.gs")` fails with SSL certificate verification error even with `allow_insecure_ssl=True`.

### Solution
Added `allow_invalid_certificate` parameter that completely disables SSL certificate verification:
- `whoisit.domain(domain_name, ..., allow_invalid_certificate=False)`
- `whoisit.domain_async(domain_name, ..., allow_invalid_certificate=False)`

### Behavior

**Default (`allow_invalid_certificate=False`)**: Validates SSL certificates (secure)

**With `allow_invalid_certificate=True`**: Disables SSL certificate verification entirely
```python
result = whoisit.domain('instagram.gs', allow_invalid_certificate=True)
# Works even with invalid certificates
```

### Implementation Details
- For `requests.Session`: Sets `session.verify = False`
- For `httpx.AsyncClient`: Sets `verify=False` in client constructor
- Automatically suppresses `InsecureRequestWarning` to reduce noise

### Modified Files
- `whoisit/utils.py`:
  - `get_session_or_async_client()`: Added `allow_invalid_certificate` parameter
  - `get_session()`: Added `allow_invalid_certificate` parameter
  - `get_async_client()`: Added `allow_invalid_certificate` parameter
  - `create_session()`: Implements certificate verification bypass
  - `create_async_client()`: Implements certificate verification bypass
  - `_default_session`: Added `"no_verify"` key for caching

- `whoisit/__init__.py`:
  - `domain()`: Added `allow_invalid_certificate` parameter
  - `domain_async()`: Added `allow_invalid_certificate` parameter

---

## Patch 3: Rate Limit and Timeout Optimization

### Problem
RDAP servers implement rate limiting (HTTP 429). The original whoisit retries 429 errors 3 times with exponential backoff, which can cause long delays during bulk collection.

### Solution
Modified retry and timeout behavior for bulk collection:

**Changes in `whoisit/utils.py`:**
```python
# Before
http_timeout = 10  # 10 second timeout
http_retry_statuses = [429]  # Retry on 429
http_max_retries = 3

# After
http_timeout = 5  # 5 second timeout (faster failure)
http_retry_statuses = []  # No retries (fail fast)
http_max_retries = 3  # Still configured but not used
```

### Benefits
- Faster collection: No waiting for retries
- With `return_on_error=True`, 429 responses are captured with full RDAP data
- Timeout reduced from 10s to 5s for faster failure on unresponsive servers

---

## Usage Examples

### Example 1: Blocked Domain Detection
```python
import whoisit
whoisit.bootstrap(overrides=True)

result = whoisit.domain('youtube.cash', raw=True, return_on_error=True)

if '_rdap_error' in result and result['_rdap_error']['status_code'] == 404:
    for notice in result.get('notices', []):
        if 'block' in notice.get('title', '').lower():
            print("Domain is BLOCKED")
            break
```

### Example 2: Invalid Certificate Handling
```python
import whoisit
whoisit.bootstrap(overrides=True)

# Fails with SSL error
# result = whoisit.domain('instagram.gs')

# Works with certificate validation disabled
result = whoisit.domain('instagram.gs', allow_invalid_certificate=True)
print(f"Domain: {result.get('name')}")
```

### Example 3: Rate Limited Server
```python
import whoisit
whoisit.bootstrap(overrides=True)

result = whoisit.domain('example.nec', raw=True, return_on_error=True)

if '_rdap_error' in result and result['_rdap_error']['status_code'] == 429:
    print("Rate limited - skip and continue")
    # No retries, fails fast
```

### Example 4: Maximum Permissiveness for Bulk Collection
```python
import whoisit
whoisit.bootstrap(overrides=True)

# Most permissive settings for bulk collection
result = whoisit.domain(
    'example.com',
    raw=True,
    return_on_error=True,
    allow_invalid_certificate=True
)

# Always returns data, even on errors
if '_rdap_error' in result:
    print(f"Error {result['_rdap_error']['status_code']}: {result['_rdap_error']['error_type']}")
else:
    print(f"Success: {result.get('name')}")
```

---

## Comparison: Before vs After

### Before Patches
```python
# PROBLEM: Cannot differentiate blocked vs available domains
try:
    result = whoisit.domain('youtube.cash')
except ResourceDoesNotExist:
    # Is it available? Blocked? Reserved? Can't tell!
    pass

# PROBLEM: SSL errors on invalid certificates
try:
    result = whoisit.domain('instagram.gs', allow_insecure_ssl=True)
except SSLError:
    # Still fails even with allow_insecure_ssl
    pass

# PROBLEM: Slow retries on rate limits
result = whoisit.domain('example.nec')  # Retries 3 times, takes 30+ seconds
```

### After Patches
```python
# SOLUTION: Get full RDAP data on errors
result = whoisit.domain('youtube.cash', raw=True, return_on_error=True)
if '_rdap_error' in result:
    print(f"Status: {result['_rdap_error']['status_code']}")
    # Check notices to determine if blocked/reserved
    for notice in result.get('notices', []):
        print(f"Notice: {notice.get('title')}")

# SOLUTION: Bypass invalid certificates
result = whoisit.domain('instagram.gs', allow_invalid_certificate=True)
print(f"Success: {result.get('name')}")

# SOLUTION: Fast failure on rate limits
result = whoisit.domain('example.nec', raw=True, return_on_error=True)
# Fails immediately (5s timeout), no retries
if result['_rdap_error']['status_code'] == 429:
    print("Rate limited - moving on")
```

---

## Backward Compatibility

All patches maintain backward compatibility:
- `return_on_error=False` (default): Original behavior
- `allow_invalid_certificate=False` (default): Validates certificates
- `http_retry_statuses = []`: Can be modified if retries are needed

Existing code using whoisit continues to work unchanged.

---

## Testing

Test the patches with:
```bash
python test_whoisit_patch2.py
```

Test scenarios:
- ✅ Blocked domain (404 + JSON): `youtube.cash`
- ✅ Invalid certificate: `instagram.gs`
- ✅ Rate limited: `instagram.nec`
- ✅ Normal registered domain: `google.com`
- ✅ Available domain: `thisdomainshouldnotexist12345.com`

---

## Files Modified

### Core Patches
1. `whoisit/query.py` - Lines 210, 240-323, 334, 355
2. `whoisit/__init__.py` - Lines 141-185
3. `whoisit/utils.py` - Lines 19-20, 30-176

### Documentation
4. `PATCH_NOTES.md` - This file

### Test Scripts
5. `test_whoisit_patch.py`
6. `test_whoisit_patch2.py`

### Collection Script
7. `collect_rdap_all.py` - Uses all patches for bulk collection

---

## Performance Impact

- **Minimal overhead**: Only affects error paths
- **Faster failure**: Reduced timeout (10s → 5s)
- **No retries**: Saves time on rate-limited servers
- **Certificate bypass**: Only when explicitly enabled

For bulk RDAP collection of 20,000+ domains, these patches significantly improve speed and reliability.

---

## Patch 4: Registrar RDAP Endpoint Support + Per-Hostname RDAP Pool

### Problem
`whoisit` only bootstraps **Registry RDAP** endpoints from IANA (`dns.json`), e.g., `.wales` resolves to `rdap.nominet.uk`. These return basic data. **Registrars** (e.g., Netistrar for `c.wales`) also run RDAP endpoints with richer data (full contacts, detailed registrar info). IANA publishes registrar IANA ID to RDAP URL mappings at `https://www.iana.org/assignments/registrar-ids/registrar-ids.xml`.

Additionally, RDAP per-hostname rate limiting was previously handled in `whois_client`, but sub-requests issued by `whoisit` (like `follow_related` or the new `follow_rdap_registrar`) bypassed the pool entirely.

### Solution

#### 4a: Registrar RDAP Bootstrap

During bootstrap, `whoisit` now also downloads and parses the IANA registrar-ids XML to build a mapping of IANA registrar ID to RDAP base URL.

**Changes in `whoisit/bootstrap.py`:**
- Added `REGISTRAR_IDS_URL` constant pointing to the IANA XML
- Added `_registrar_rdap_urls: dict[str, str]` to `BaseBootstrap`
- Added `_parse_registrar_ids_xml(xml_text)` method that parses `<record>` elements for `<value>` (IANA ID) and `<rdapurl><server>` (RDAP URL)
- Both `Bootstrap.bootstrap()` and `BootstrapAsync.bootstrap_async()` download the XML after the standard IANA bootstrap
- Added `get_registrar_rdap_url(iana_id) -> str | None` public method

#### 4b: `follow_rdap_registrar` Parameter

New parameter on `_domain()`, `domain()`, and `domain_async()`:

```python
result = whoisit.domain_async(
    "c.wales",
    raw=True,
    follow_rdap_registrar=True,  # NEW
    rdap_pool=pool,              # NEW
)
```

When `follow_rdap_registrar=True`:
1. After the primary registry RDAP query, extract the registrar IANA ID from the response entities (`publicIds` with type "IANA Registrar ID", or numeric `handle`)
2. Look up the registrar's RDAP base URL via `get_registrar_rdap_url(iana_id)`
3. Query `{registrar_base_url}/domain/{domain_name}` with `return_on_error=True`
4. Deep-merge the registrar response over the registry response using `recursive_merge()`

**New helper in `whoisit/__init__.py`:**
- `_extract_registrar_iana_id(response) -> str | None`: Searches entities for role "registrar", checks `publicIds` for "IANA Registrar ID", falls back to numeric `handle`

#### 4c: Per-Hostname RDAP Pool (`RDAPPool`)

**New file `whoisit/rdap_pool.py`:**
- `RDAPHostQueue`: Per-hostname async semaphore + inter-request delay
- `RDAPPool`: Registry of per-hostname queues, created via `whoisit.create_rdap_pool()`

The pool ensures at most `max_requests_per_hostname` (default 1) concurrent requests per RDAP host, with configurable delays from `rdap_host_delay.json`.

When `rdap_pool` is passed to `domain_async()`, **all** HTTP requests (primary registry query + registrar follow-up) are routed through it:

```python
# In domain_async(), each query goes through the pool:
if rdap_pool and hasattr(q, "url"):
    req_resp = await rdap_pool.execute(q.url, q.request())
else:
    req_resp = await q.request()
```

#### 4d: RDAP Host Delays Moved to `whoisit`

**Moved `rdap_host_delay.json`** from `whois_client/data/` to `whoisit/data/`.

The delays are loaded automatically in `BaseBootstrap.__init__()` and exposed via:
- `get_rdap_host_delays() -> dict[str, float]`
- `create_rdap_pool(max_requests_per_hostname=1) -> RDAPPool` (pre-loaded with delays)

### New Public API

```python
import whoisit

# Create a per-hostname RDAP pool (event-loop bound)
pool = whoisit.create_rdap_pool(max_requests_per_hostname=1)

# Query with registrar follow-up, routed through the pool
result = await whoisit.domain_async(
    "c.wales",
    raw=True,
    return_on_error=True,
    allow_invalid_certificate=True,
    follow_related=False,
    follow_rdap_registrar=True,
    rdap_pool=pool,
)

# Get loaded host delays
delays = whoisit.get_rdap_host_delays()

# Look up a registrar RDAP URL by IANA ID
url = whoisit.get_registrar_rdap_url("1448")
# -> "https://rdap.netistrar.com/"
```

### Modified Files
- `whoisit/rdap_pool.py` -- **NEW**: `RDAPPool` + `RDAPHostQueue`
- `whoisit/data/rdap_host_delay.json` -- **MOVED** from `whois_client/data/`
- `whoisit/bootstrap.py` -- Registrar XML loading, `rdap_host_delay.json` loading, new public methods
- `whoisit/__init__.py` -- `follow_rdap_registrar`, `rdap_pool` params, `create_rdap_pool()`, `_extract_registrar_iana_id()`

### Backward Compatibility
- `follow_rdap_registrar=False` (default in `whoisit`): Original behavior, no registrar follow-up
- `rdap_pool=None` (default): No per-hostname rate limiting, requests go through directly
- All existing `whoisit` function signatures are unchanged (new params are optional with defaults)
