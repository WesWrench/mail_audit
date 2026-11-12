# Mail AntiSpoof Policy Checker

A comprehensive Python library and CLI tool for checking and analyzing email authentication policies (SPF, DMARC, DKIM) with advanced detection of dangerous third-party email services.

## Versioning

| Version | Date       | Status  | Highlights                                                                                                           |
|---------|------------|---------|----------------------------------------------------------------------------------------------------------------------|
| 2.2.0   | 2026-10-29 | Stable  | CNAME chain check on DKIM selector / `_dmarc` / SPF domain names (broken, missing record, loop, indeterminate, unregistered target, DKIM wildcard probes); `--dkim-selector-file` |
| 2.1.0   | 2026-04-01 | Stable  | `AsyncPooledDNSResolver` — pooled DNS resolver with global + per-NS concurrency limits passed to checkdmarc          |
| 2.0.1   | 2026-03-23 | Stable  | Fix: `--async-mode` empty `email_domain_indicators`; `timeout_retries` forwarded to `parse_spf_record`              |
| 2.0.0   | 2026-03-22 | Stable  | Async mode — `check_async()` on all checkers, `--async-mode` / `--max-concurrent` CLI flags (Python 3.9+)           |
| 1.2.0   | 2026-03-22 | Stable  | Unregistered/Potentially-Unregistered domain check via DomainAvailabilityChecker (bulk, codes 17 & 18)               |
| 1.1.0   | 2026-03-22 | Stable  | 4 bug fixes — severity cascade, Excel service name, skip_issue substring, recursive include resolution; Free Mail Provider detection |
| 1.0.0   | 2026-03-22 | Stable  | Initial release — SPF/DMARC/DKIM checks, MaxMind AS org detection, CSV severity cascade, CLI                        |

> See [CHANGELOG.md](CHANGELOG.md) for the full history of changes.

---

## Features

### Core Features
- **SPF Record Checking**: Validate SPF records with full include/redirect tree resolution
  - ✅ Parse `include`, `ip4`, `ip6` mechanisms
  - ✅ Parse `a` and `mx` mechanisms with IP resolution
  - ✅ Parse `ptr` mechanisms with dangerous domain detection
- **DMARC Policy Checking**: Analyze DMARC configurations and policies
- **DKIM Selector Checking**: Verify DKIM selector configurations (bundled list or your own with `--dkim-selector-file`)
- **CNAME Chain Checking**: Detect obsolete / broken CNAME aliases at the names where SPF, DMARC and DKIM records are looked up (broken reference, missing record, loop, unregistered target), with DKIM wildcard probing to limit false positives — see [CNAME Chain Checks](#cname-chain-checks)
- **Dangerous Service Detection**: Identify risky third-party email services via:
  - CSV-based dangerous includes/redirects database
  - CSV-based dangerous IP range database
  - CSV-based dangerous PTR domain database
  - AS Organization lookup via MaxMind GeoIP2
  - Optional PTR blacklist building from dangerous IPs (reverse DNS)
- **Unknown Data Analysis**: Find SPF data not in your databases with PTR lookups
- **Flexible Input**: DNS queries, raw records, or pre-parsed trees
- **Multiple Output Formats**: JSON and Excel with detailed sheets
- **CLI Tool**: Full-featured command-line interface

### Advanced Features
- **DNS Retry Mechanism**: Automatic retry with fallback DNS servers (Google, Cloudflare, NS servers)
- **Configurable Email Domain Detection**: Customize required indicators (MX, SPF, DMARC, SMTP)
- **PTR Blacklist Building**: Build PTR domain blacklist from dangerous IPs via reverse DNS (optional, expensive)

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Library Usage](#library-usage)
   - [EmailDomainChecker](#emaildomainchecker)
   - [SPFChecker](#spfchecker)
   - [DMARCChecker](#dmarcchecker)
   - [DKIMChecker](#dkimchecker)
   - [UnknownDataAnalyzer](#unknowndataanalyzer)
4. [Detected Issues Reference](#detected-issues-reference)
   - [CNAME Chain Checks](#cname-chain-checks)
5. [CLI Tool (cli.py)](#cli-tool-clipy)
6. [Configuration](#configuration)
7. [CSV Databases](#csv-databases)
8. [Output Format](#output-format)
9. [Examples](#examples)
10. [Architecture](#architecture)

---

## Installation

### Requirements

- Python 3.8+ (Python 3.9+ required for `--async-mode`)
- Dependencies:
  ```bash
  pip install checkdmarc dnspython geoip2 pandas openpyxl requests
  ```

### Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd "Mail AntiSpoof Policy Checker"
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) Download the domain availability libraries for the **Unregistered Domain Check** feature. These internal packages are hosted on the Deloitte Azure DevOps OSINT repository and must be placed manually under `./lib/domain/`:

   | Package | Azure DevOps path |
   |---|---|
   | `hybridwhois`, `whoisit`, `whoisitlegacy` | `Scripts/Utils/Whois` |
   | `domain_availability_checker`, `domain_availability_service_checker` | `Scripts/Domains, Subdomains, DNS/Domain Availability Checker` |

   Repository: `https://dev.azure.com/deloittefranceosc/Cyber OSC - GIT/_git/OSINT`

   Also install the public dependency used by the domain checker:
   ```bash
   pip install tldextract
   ```

   Expected directory structure after download:

   ```
   lib/domain/
   ├── __init__.py
   ├── domain_availability_checker/
   │   ├── __init__.py
   │   ├── checker.py
   │   └── dns_check.py
   ├── domain_availability_service_checker/
   │   ├── __init__.py
   │   ├── GandiShop/
   │   ├── NameCheap/
   │   ├── Ovh/
   │   └── Wix/
   ├── hybridwhois/
   │   └── __init__.py
   ├── whoisit/
   │   └── __init__.py
   └── whoisitlegacy/
       ├── __init__.py
       └── parsers/
   ```

   If this step is skipped the tool runs normally — the unregistered domain check is silently disabled and all other SPF/DMARC/DKIM checks continue to work.

4. (Optional) Set MaxMind license key for AS organization detection. The CLI reads it from
   the `MAXMIND_LICENSE_KEY` environment variable (current terminal session only). Never
   write the key in the code or in a committed file:
   ```powershell
   # Windows PowerShell
   $env:MAXMIND_LICENSE_KEY = "your_license_key_here"
   ```
   ```bat
   :: Windows cmd (no quotes, no spaces around =)
   set MAXMIND_LICENSE_KEY=your_license_key_here
   ```
   ```bash
   # Linux / macOS / WSL / Git Bash
   export MAXMIND_LICENSE_KEY="your_license_key_here"
   ```
   Permanent: `setx MAXMIND_LICENSE_KEY "your_license_key_here"` (Windows, new terminals)
   or the `export` line in `~/.bashrc`. When used through `mail_audit`, the key can also be
   passed with `--maxmind-key`.

---

## Quick Start

### Library Usage

```python
from lib import (
    EmailDomainChecker,
    SPFChecker,
    DMARCChecker,
    DKIMChecker,
    DataLoaders,
    MaxMindClient
)

# 1. Check if domain is used for email
email_checker = EmailDomainChecker(dns_timeout=5)
indicators = email_checker.check("example.com")
print(f"Email indicators: {indicators}")  # ['HAS_MX', 'HAS_SPF', ...]

# Only scan if domain is used for email
if email_checker.is_email_domain("example.com"):
    # 2. Initialize data loaders
    data_loaders = DataLoaders(data_dir="./data")
    data_loaders.load_all()

    # 3. (Optional) Initialize MaxMind for AS organization detection
    maxmind_client = MaxMindClient.from_environment()

    # 4. Create SPF checker
    spf_checker = SPFChecker(
        maxmind_client=maxmind_client,
        data_loaders=data_loaders
    )

    # 5. Check the domain
    result = spf_checker.check("example.com")

    # Access results
    print(f"Issues: {len(result.issues)}")
    print(f"ALL qualifier: {result.all_qualifier}")
```

### Async Library Usage (v2.0.0+)

```python
import asyncio
from lib import SPFChecker, DMARCChecker, DKIMChecker

domains = ["example.com", "gmail.com", "outlook.com"]

spf_checker = SPFChecker()
dmarc_checker = DMARCChecker()
dkim_checker = DKIMChecker()

# Run all three checks concurrently — max 10 domains at a time
spf_results   = asyncio.run(spf_checker.check_async(domains, max_concurrent=10))
dmarc_results = asyncio.run(dmarc_checker.check_async(domains, max_concurrent=10))
dkim_results  = asyncio.run(dkim_checker.check_async(domains, max_concurrent=10))

for domain, spf, dmarc, dkim in zip(domains, spf_results, dmarc_results, dkim_results):
    print(f"{domain}: SPF issues={len(spf.issues)}, DMARC policy={dmarc.policy}")
```

> `max_concurrent=0` removes the concurrency cap entirely.

### CLI Usage

```bash
# Check SPF/DMARC/DKIM for domains in a file (sync, default)
python cli.py --hostnames domains.txt

# Same but process up to 20 domains in parallel (async mode)
python cli.py --hostnames domains.txt --async-mode --max-concurrent 20

# Unlimited concurrency (use with caution on large lists)
python cli.py --hostnames domains.txt --async-mode --max-concurrent 0

# Check SPF records from CSV (SPF ONLY)
python cli.py --check-spf-records spf_records.csv

# Check SPF trees from JSON directory (SPF ONLY)
python cli.py --spf-tree-json output/spf_trees/

# Analyze unknown SPF data
python cli.py --spf-tree-json output/spf_analysis.json --mode check_unknown_data --include-ptr
```

---

## Library Usage

### EmailDomainChecker

The **EmailDomainChecker** determines if a domain is used for email by checking multiple indicators. This is useful to avoid scanning non-email domains and polluting Excel exports with false positives.

#### Email Domain Indicators

The checker verifies four indicators:

| Indicator | Description | Check Method |
|-----------|-------------|--------------|
| `HAS_MX` | Domain has MX records | DNS MX query |
| `HAS_SPF` | Domain has SPF record | DNS TXT record for SPF |
| `HAS_DMARC` | Domain has DMARC on current domain (NOT inherited) | DNS TXT at `_dmarc.{domain}` |
| `HAS_SMTP` | SMTP server responds | TCP connection to port 25 |

**Important**: For subdomains, `HAS_DMARC` only checks the current domain (`_dmarc.sub.domain.com`), NOT the parent (`_dmarc.domain.com`), to avoid false positives.

#### Initialization

```python
from lib import EmailDomainChecker

# Basic initialization
email_checker = EmailDomainChecker(dns_timeout=5)

# With custom DNS server
email_checker = EmailDomainChecker(
    dns_timeout=10,
    nameservers=['8.8.8.8']
)
```

#### Usage

```python
# Check if domain is used for email
indicators = email_checker.check("gmail.com")
# Returns: ['HAS_MX', 'HAS_SPF', 'HAS_DMARC']

# Simple boolean check
if email_checker.is_email_domain("gmail.com"):
    print("This is an email domain")

# Get cached results (no additional DNS queries)
indicators = email_checker.get_indicators("gmail.com")

# Clear cache
email_checker.clear_cache()
```

#### Integration with SPF/DMARC Checkers

```python
from lib import EmailDomainChecker, SPFChecker, DMARCChecker, DataLoaders

# Create email domain checker
email_checker = EmailDomainChecker()

# Initialize other components
data_loaders = DataLoaders()
data_loaders.load_all()

domains = ["gmail.com", "cdn.example.com", "harmonieambulance.com"]

for domain in domains:
    # Check email indicators FIRST
    indicators = email_checker.check(domain)

    if not indicators:
        print(f"{domain}: Non-email domain, skipping...")
        continue

    print(f"{domain}: Email domain ({', '.join(indicators)})")

    # Only scan email domains
    spf_checker = SPFChecker(data_loaders=data_loaders)
    spf_result = spf_checker.check(domain)

    dmarc_checker = DMARCChecker()
    dmarc_result = dmarc_checker.check(domain)
```

#### Performance - Caching

Results are automatically cached to avoid redundant DNS queries:

```python
email_checker = EmailDomainChecker()

# First call: performs DNS queries
indicators1 = email_checker.check("gmail.com")  # ~4 DNS queries

# Subsequent calls: uses cached result
indicators2 = email_checker.check("gmail.com")  # 0 DNS queries

# Check cache size
print(f"Cached domains: {email_checker.get_cache_size()}")
```

---

### SPFChecker

The **SPFChecker** validates SPF records and detects dangerous third-party services.

#### Three-Tier Cascade Architecture

```
check(domain)               → DNS query, returns SPFResult
    ↓
check_record(spf_string)    → Parse SPF record, returns SPFResult
    ↓
check_spf_tree(parsed_spf)  → Analyze parsed SPF tree, returns SPFResult
```

#### Initialization

```python
from lib.checkers.spf_checker import SPFChecker
from lib.data.loaders import DataLoaders
from lib.utils.maxmind_client import MaxMindClient

# Basic initialization (uses defaults)
spf_checker = SPFChecker()

# Full configuration
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

maxmind_client = MaxMindClient.from_environment()

spf_checker = SPFChecker(
    maxmind_client=maxmind_client,      # Optional: For AS organization detection
    data_loaders=data_loaders,          # Optional: Custom data loaders
    data_dir="./data",                  # Directory with CSV databases
    dns_timeout=5,                      # DNS query timeout in seconds
    nameservers=["8.8.8.8"],               # Custom DNS resolver(s), list of IPs (None = system default)
    use_ns_record=False                 # Use domain's NS servers for queries
)
```

#### Method 1: check(domain) - Full DNS Query

Performs DNS query to get SPF record, then analyzes it.

```python
# Check via DNS
result = spf_checker.check("example.com")

print(f"Domain: {result.domain}")
print(f"SPF Record: {result.spf_record}")
print(f"Issues: {len(result.issues)}")

# Access includes
for include in result.all_includes:
    print(f"  Include: {include['include']}")
    if include.get('dangerous'):
        print(f"    DANGEROUS: {include.get('service_name')} ({include.get('service_type')})")

# Access IP addresses
for ip in result.all_ip_addresses:
    print(f"  IP: {ip['ip']}")
    if ip.get('dangerous'):
        print(f"    DANGEROUS: AS Org = {ip.get('as_organization')}")

# Check issues
for issue in result.issues:
    print(f"  [{issue.severity.upper()}] {issue.title}")
    print(f"    {issue.description}")
```

#### Method 2: check_record(spf_string) - Direct Record Analysis

Analyze a SPF record string directly (no DNS query).

```python
spf_record = "v=spf1 include:spf.mailjet.com ip4:192.168.1.0/24 -all"

result = spf_checker.check_record(
    spf_record,
    record_id="my-domain.com"
)

print(f"Parsed {len(result.all_includes)} includes")
print(f"Parsed {len(result.all_ip_ranges)} IP ranges")
print(f"Parsed {len(result.all_ip_addresses)} IP addresses")
```

#### Method 3: check_spf_tree(parsed_spf) - Pre-Parsed Tree

Analyze an already-parsed SPF tree from checkdmarc.

```python
from checkdmarc.spf import parse_spf_record

# Parse SPF record
parsed_spf = parse_spf_record("v=spf1 include:spf.mailjet.com -all", "example.com")

# Analyze the parsed tree
result = spf_checker.check_spf_tree(
    parsed_spf,
    record_id="example.com",
    store_parsed=True  # Store parsed_spf in result
)

# Access the stored parsed tree
print(result.parsed_spf)
```

#### SPFResult Object

```python
class SPFResult:
    domain: str                      # Domain checked
    spf_record: str                  # Raw SPF record
    all_qualifier: str               # ALL mechanism qualifier (pass/fail/softfail/neutral)
    all_includes: List[Dict]         # All includes with dangerous flags
    all_redirects: List[Dict]        # All redirects with dangerous flags
    all_ip_ranges: List[Dict]        # All IP ranges with dangerous flags
    all_ip_addresses: List[Dict]     # All IP addresses with dangerous flags
    issues: List[Issue]              # List of detected issues
    parsed_spf: Dict                 # Parsed SPF tree (if store_parsed=True)
```

#### Dangerous Detection - 3-Tier System

The SPFChecker uses a **3-tier priority system** to detect dangerous entries:

**Tier 1: Dangerous Includes/Redirects (CSV)**
- File: `data/Dangerous_SPF_Include.csv`
- Checks if include/redirect domain is in the dangerous list
- If found → flagged as dangerous, skip next tiers
- Whitelist guard: sub-includes listed in `data/Whitelisted_SPF_Include.csv` are not walked, so a shared platform reached through a dangerous include (e.g. `amazonses.com` via `spf.infomaniak.ch`) does not inherit that service's IP ranges

**Whitelist (applies across all 3 tiers)**
- File: `data/Whitelisted_SPF_Include.csv`, resolved recursively into IP ranges
- An IP fully contained in whitelisted space skips tiers 2 and 3
- Explicitly declared dangerous data always wins — see [Whitelisted_SPF_Include.csv](#4-whitelisted_spf_includecsv-whitelist)

**Tier 2: Dangerous IP Ranges (CSV)**
- File: `data/Dangerous_SPF_Records_IP_Range.csv`
- Checks if IP/range overlaps with dangerous ranges
- If found → flagged as dangerous, skip next tier

**Tier 3: Dangerous AS Organization (MaxMind + CSV)**
- File: `data/Dangerous_AS_Organization.csv`
- Uses MaxMind to lookup AS organization for IP
- Checks if AS org is in the dangerous list
- If found → flagged as dangerous

**Example:**

```python
# SPF: v=spf1 include:spf.mailjet.com ip4:223.165.113.0 -all

result = spf_checker.check_record("v=spf1 include:spf.mailjet.com ip4:223.165.113.0 -all", "test.com")

# Include detected via Tier 1 (CSV)
print(result.all_includes[0])
# {
#   'include': 'spf.mailjet.com',
#   'dangerous': True,
#   'service_type': 'Email Delivery Service',
#   'service_name': 'Mailjet',
#   'path': 'test.com'
# }

# IP detected via Tier 3 (MaxMind AS org)
print(result.all_ip_addresses[0])
# {
#   'ip': '223.165.113.0',
#   'dangerous': True,
#   'as_organization': 'SENDGRID',
#   'service_type': 'Email Marketing',
#   'service_name': 'SendGrid',
#   'path': 'test.com'
# }
```

#### Advanced Configuration: NS Record Resolution

Use the domain's authoritative nameservers for DNS queries:

```python
spf_checker = SPFChecker(use_ns_record=True)

# This will:
# 1. Query NS records for example.com
# 2. Use the first NS server for all subsequent queries
# 3. Restore original DNS resolver after check
result = spf_checker.check("example.com")
```

---

### DMARCChecker

The **DMARCChecker** validates DMARC policies and configurations.

#### Three-Tier Cascade Architecture

```
check(domain)                      → DNS query, returns DMARCResult
    ↓
check_record(dmarc_string)         → Parse DMARC record, returns DMARCResult
    ↓
check_parsed_dmarc(parsed_dmarc)   → Analyze parsed DMARC tags, returns DMARCResult
```

#### Initialization

```python
from lib.checkers.dmarc_checker import DMARCChecker

# Basic initialization
dmarc_checker = DMARCChecker()

# Full configuration
dmarc_checker = DMARCChecker(
    dns_timeout=5,              # DNS query timeout in seconds
    nameservers=["8.8.8.8"],       # Custom DNS resolver(s), list of IPs (None = system default)
    use_ns_record=False         # Use domain's NS servers for queries
)
```

#### Method 1: check(domain) - Full DNS Query

```python
result = dmarc_checker.check("example.com")

print(f"Domain: {result.domain}")
print(f"DMARC Record: {result.dmarc_record}")
print(f"Policy: {result.policy}")
print(f"Subdomain Policy: {result.subdomain_policy}")
print(f"Percentage: {result.percentage}")
print(f"Aggregate URIs: {result.aggregate_report_uris}")
print(f"Forensic URIs: {result.forensic_report_uris}")
print(f"Issues: {len(result.issues)}")
```

#### Method 2: check_record(dmarc_string) - Direct Record Analysis

```python
dmarc_record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"

result = dmarc_checker.check_record(
    dmarc_record,
    record_id="example.com"
)

print(f"Policy: {result.policy}")
```

#### Method 3: check_parsed_dmarc(parsed_dmarc) - Pre-Parsed Tags

```python
from checkdmarc.dmarc import parse_dmarc_record

# Parse DMARC record
parsed_dmarc = parse_dmarc_record(
    "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "example.com"
)

# Analyze the parsed tags
result = dmarc_checker.check_parsed_dmarc(
    parsed_dmarc,
    record_id="example.com",
    store_parsed=True  # Store parsed_dmarc in result
)

# Access the stored parsed data
print(result.parsed_dmarc)
```

#### DMARCResult Object

```python
class DMARCResult:
    domain: str                          # Domain checked
    dmarc_record: str                    # Raw DMARC record
    policy: str                          # Policy p= (none/quarantine/reject)
    subdomain_policy: str                # Subdomain policy sp= (defaults to p)
    np_policy: str                       # RFC 9091 np= non-existent-subdomain policy
    testing: bool                        # RFC 9989 t=y (policy in test mode)
    psd: str                             # RFC 9989 psd= flag (y/n/u)
    percentage: int                      # RFC 7489 pct= (removed in RFC 9989)
    aggregate_report_uris: List[str]     # RUA addresses
    forensic_report_uris: List[str]      # RUF addresses
    issues: List[Issue]                  # List of detected issues
    parsed_dmarc: Dict                   # Parsed DMARC (if store_parsed=True)
```

#### DMARCbis (RFC 9989) and `np=` (RFC 9091)

Parsing and validation come from `checkdmarc>=6`, which implements RFC 9989: `np`, `psd` and
`t` are understood, unknown tags are ignored (with a warning), and implicit tags are filled
with their defaults (`sp` = `p`, `np` = an explicit `sp` else `p`, `adkim` = `aspf` = `r`).
So `v=DMARC1; p=reject; sp=quarantine; np=none; aspf=r` yields `policy=reject`,
`subdomain_policy=quarantine`, `np_policy=none`, `alignment_spf=r`.

- **`t=y` (test mode)**: `testing=True` and a `dmarc_testing_mode` issue (medium on
  `p=reject`, high on `p=quarantine`). `mail_audit` applies the policy one level lower.
- **`pct`**: removed by RFC 9989 (checkdmarc drops it), but still applied by RFC 7489
  receivers, so it is read from the raw record and `pct` < 100 raises
  `dmarc_partial_coverage`.
- **`sp`**: `dmarc_lax_subdomain_policy` is only raised for a published `sp=` (an implicit
  `sp` equals `p`, already reported).

**Subdomain inheritance (RFC 9091).** When a subdomain has no own `_dmarc`, the policy it
inherits from the organizational domain depends on whether the subdomain **exists**: an
**existing** subdomain inherits `sp=` (then `p=`); a **non-existent** subdomain (NXDOMAIN)
inherits **`np=`** (then `sp=`, then `p=`). `check()` resolves existence only in the inherited
branch, with a single classified `A` query, and treats **only a definitive NXDOMAIN** as
non-existent (NODATA / answer / timeout are not). So `example.com` with `sp=none; np=reject` is
reported as **enforcing** for a spoof of a non-existent subdomain such as
`invoices.example.com` — avoiding a false "spoofable" finding.

#### Organizational-domain helpers & relaxed-alignment awareness

DMARC is evaluated against the **From-header** domain. For a subdomain with no own
`_dmarc` record, the lookup jumps **directly to the organizational (registrable) domain**
(RFC 7489 §6.6.3) — it does **not** walk the tree label by label:
`a.b.sub.example.co.uk` → `example.co.uk`, never the intermediate labels. And alignment
defaults to **relaxed** (`aspf`/`adkim` absent = `r`), which compares only the
organizational domain — so an SPF pass or a DKIM signature on *any* name sharing the
organizational domain satisfies DMARC for a `From:` on that organizational domain.

`lib/utils/org_domains.py` (re-exported from `lib`) exposes the PSL-backed helpers used to
reason about this:

```python
from lib import organizational_domain, is_subdomain, derive_org_parents

organizational_domain("a.b.spoofin.fr")      # -> "spoofin.fr"
is_subdomain("alwaysdata.spoofin.fr")         # -> True
derive_org_parents(["alwaysdata.cef.fr",      # -> ["cef.fr"]  (spoofin.fr dropped:
                    "spoofin.fr"])            #     already in the input)
```

`DMARCChecker._organizational_domain` delegates to `organizational_domain` (single source).

**CLI**: when `dmarc` is among the check types, the CLI adds each input subdomain's
organizational parent as a **DMARC-only** target (deduplicated — a parent already listed is
not re-added). Only the parent's DMARC is fetched (its SPF/DKIM are not): the parent's DMARC
is the policy that governs a `From:@<parent>` spoof mounted from a weak subdomain. Such an
entry is marked `org_parent_dmarc_only: true` in the output. `mail_audit` performs the same
derivation and uses the parent DMARC to raise its *relaxed-alignment cross-domain spoofing*
scenario.

---

### DKIMChecker

The **DKIMChecker** validates DKIM selector configurations.

#### Initialization

```python
from lib.checkers.dkim_checker import DKIMChecker

# Basic initialization (bundled data/DKIM_Selectors.txt, ~840 selectors)
dkim_checker = DKIMChecker()

# Full configuration
dkim_checker = DKIMChecker(
    selector_file="./selector.txt",  # Custom selector list — REPLACES the bundled one
    dns_timeout=5,                   # DNS query timeout in seconds
    nameservers=["8.8.8.8"],            # Custom DNS resolver(s), list of IPs (None = system default)
    max_dns_retries=3,
    cname_check=True,                # CNAME chain check at selector names (default: True)
    cname_max_depth=10,              # Max CNAME links followed
    wildcard_probes=3,               # Random sibling probes per selector parent (min 3)
    factordb=FactorDBClient(),       # factordb.com lookup of RSA moduli (default None: no lookup)
)
```

`FactorDBClient` comes from `lib.utils.factordb`. See *RSA key checks* below.

**Selector file format** — one selector per line; blank lines and lines starting
with `#` are ignored; duplicates are removed (order kept). Multi-label selectors
(`s1.mail`) are allowed.

```text
# selector.txt
mail
ovhmo-selector-1
selector1
```

`DKIMChecker.load_selector_file(path)` returns the parsed list (raises
`FileNotFoundError`); the constructor silently falls back to an empty list when the
file is missing, so the CLIs validate the path first.

#### Method: check(domain, custom_selectors=None) - Selector Enumeration

```python
result = dkim_checker.check("example.com")                  # all selectors of the list
result = dkim_checker.check("example.com", ["s2025", "k3"])  # + extra selectors
result = dkim_checker.check_selector("example.com", "default")  # a single selector

for sel in result.selectors_found:
    print(sel.selector, sel.key_type, sel.key_size)
for chk in result.cname_checks:           # aliases found at <selector>._domainkey.<domain>
    print(chk.queried_name, chk.anomaly, chk.chain, chk.wildcard["status"])
```

Each selector costs a single TXT query: CNAMEs present in the answer section are
captured at the same time, so the CNAME check only issues extra queries for
selectors that actually are aliases (or whose lookup was indeterminate).

#### DKIMResult Object

```python
class DKIMResult:
    domain: str                            # Domain checked
    selectors_tested: List[str]            # Selectors tried (count in to_dict())
    selectors_found: List[DKIMSelectorInfo]  # selector, key_type, key_size, issues
    issues: List[Issue]                    # All DKIM issues (incl. CNAME issues)
    cname_checks: List[CNAMECheck]         # CNAME chains seen at selector names
```

`SPFResult.cname_checks` (alias at `<domain>`) and `DMARCResult.cname_checks`
(alias at `_dmarc.<domain>`) follow the same model. The CNAME check is enabled by
default on all three checkers; disable it at construction with `cname_check=False`
(`SPFChecker`, `DMARCChecker` and `DKIMChecker` also accept `cname_max_depth`).

---

### UnknownDataAnalyzer

The **UnknownDataAnalyzer** finds SPF data not in your CSV databases and performs PTR lookups.

#### Initialization

```python
from lib.analyzers.unknown_data_analyzer import UnknownDataAnalyzer
from lib.data.loaders import DataLoaders
from lib.utils.maxmind_client import MaxMindClient

# Initialize components
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

maxmind_client = MaxMindClient.from_environment()

# Create analyzer
analyzer = UnknownDataAnalyzer(
    data_loaders=data_loaders,
    maxmind_client=maxmind_client,  # Optional: For AS org lookup
    ptr_pool_size=20                # Number of parallel PTR lookups
)
```

#### Analyze JSON Output

```python
import json

# Load JSON from SPF scanner
with open("output/spf_analysis_20251212.json", "r") as f:
    json_data = json.load(f)

# Analyze to find unknown data
analysis_result = analyzer.analyze_json_output(json_data)

print(f"Unknown includes: {len(analysis_result['unknown_includes'])}")
print(f"Unknown IP ranges: {len(analysis_result['unknown_ip_ranges'])}")
print(f"Unknown IP addresses: {len(analysis_result['unknown_ip_addresses'])}")
```

#### PTR Lookups for IP Ranges

```python
import asyncio

async def analyze_with_ptr():
    # Perform async PTR lookups for IP range
    ptr_results = await analyzer.lookup_ptr_for_range("192.168.1.0/24")

    for ptr_entry in ptr_results:
        print(f"IP: {ptr_entry['ip']} → PTR: {ptr_entry['ptr']}")

asyncio.run(analyze_with_ptr())
```

#### Export Results

```python
# Export to JSON
analyzer.export_to_json(
    analysis_result,
    "output/unknown_data.json"
)

# Export to Excel (without PTR)
analyzer.export_to_excel(
    analysis_result,
    "output/unknown_data.xlsx"
)

# Export to Excel (with PTR)
ptr_results = {
    "192.168.1.0/24": [
        {"ip": "192.168.1.1", "ptr": "router.example.com"},
        {"ip": "192.168.1.2", "ptr": "server.example.com"}
    ]
}

analyzer.export_to_excel(
    analysis_result,
    "output/unknown_data_with_ptr.xlsx",
    include_ptr=True,
    ptr_results=ptr_results
)
```

#### Standalone Function

```python
from lib.analyzers.unknown_data_analyzer import check_unknown_spf_data

# One-line analysis with PTR lookups
check_unknown_spf_data(
    input_json_path="output/spf_analysis_20251212.json",
    output_dir="./output",
    data_dir="./data",
    ptr_pool_size=20,
    include_ptr_lookups=True,
    maxmind_license_key="your_key_here"
)

# Outputs:
# - output/unknown_spf_data_TIMESTAMP.json
# - output/unknown_spf_data_TIMESTAMP.xlsx
```

---

## Detected Issues Reference

This section lists all security issues that can be detected by the Mail AntiSpoof Policy Checker.

> **Note:** Issue codes are internal identifiers used in JSON exports. They correspond to numeric values (0-15) but are not required for normal usage.

### SPF Issues (17 types)

| Title | Severity | Description | When Detected |
|-------|----------|-------------|---------------|
| Domain Does Not Exist | High | The domain does not exist (NXDOMAIN) | DNS query returns NXDOMAIN |
| No SPF Record | High | No SPF record found for this domain | Domain exists but has no TXT record starting with `v=spf1` |
| Missing ALL Mechanism | Medium | SPF record does not contain an ALL mechanism | SPF record doesn't end with `all`, `+all`, `-all`, `~all`, or `?all` |
| Pass ALL Mechanism | Critical | SPF record allows all senders with `+all` | SPF record ends with `+all` (allows anyone to send — equivalent to no SPF) |
| Neutral ALL | High | SPF record is neutral for all senders with `?all` | SPF record ends with `?all` (no opinion — treated like no SPF assertion, **more permissive than softfail**) |
| Soft Fail ALL | Medium | SPF record uses soft fail `~all` instead of hard fail `-all` | SPF record ends with `~all` (weak enforcement — at least emits a negative signal) |
| SPF Lookup Error | Medium | Error occurred while looking up SPF record | Generic DNS lookup failure |
| Unregistered domain in SPF (`spf_domain_unregistered`) | Critical | An `include:` / `redirect=` (or `a:`/`mx:`/`exists:`) points to a domain that appears unregistered | End-of-run bulk check (DomainAvailabilityChecker) says *available* — whoever registers it can authorize their servers in the SPF |
| Potentially unregistered domain in SPF (`spf_domain_potentially_unregistered`) | High | Same, registration not confirmed | No NS and WHOIS/RDAP inconclusive |
| DNS Timeout | Medium | DNS query timed out | DNS server didn't respond within timeout period |
| Too Many DNS Lookups | Medium | SPF record exceeds the 10 DNS lookup limit (RFC 7208) | SPF resolution requires >10 DNS queries |
| Dangerous Include Detected | High/Critical | SPF record includes a dangerous third-party service | Include matches CSV dangerous list (Critical if Shared Hosting) |
| Dangerous IP Range Detected | High/Critical | SPF record contains IP ranges from dangerous services | IP range matches CSV or overlaps with dangerous range (Critical if Shared Hosting) |
| Dangerous AS Organization Detected | High/Critical | IP belongs to a dangerous AS organization | MaxMind AS lookup matches CSV dangerous list (Critical if Shared Hosting) |
| SPF Syntax Error | High | SPF record has invalid syntax | checkdmarc parser raises SPFSyntaxError (e.g., missing `ip4:` prefix, invalid mechanism format) |
| SPF domain CNAME points to an unregistered domain (`spf_cname_target_unregistered`) | Critical | The registrable domain of the broken target appears unregistered | Domain availability pipeline (NS → RDAP/WHOIS → registrar) says *available* |
| SPF domain CNAME points to a potentially unregistered domain (`spf_cname_target_potentially_unregistered`) | High | No NS and registration status could not be confirmed | Availability pipeline returns *unknown* |

> The CNAME rows above only concern an alias **at the audited domain name itself**
> whose target falls in a domain **anyone can buy** — the spoofing risk. A CNAME that is
> merely broken (NXDOMAIN under a registered or reserved domain), loops or times out is
> recorded as evidence in the JSON (`cname_checks`), without an issue.
> (where the SPF TXT is looked up). Targets of `include:` / `redirect=` are covered by
> **Unregistered Domains in SPF** (`spf_domain_unregistered`,
> `spf_domain_potentially_unregistered`) — unchanged and not duplicated.

### DMARC Issues (13 types)

| Title | Severity | Description | When Detected |
|-------|----------|-------------|---------------|
| No DMARC Record | High | No DMARC record found for this domain | DNS query for `_dmarc.domain` returns no TXT record starting with `v=DMARC1` |
| Lax DMARC Policy | Medium | DMARC policy is set to 'none' (not enforced) | `p=none` (emails failing DMARC are delivered anyway) |
| Lax DMARC Subdomain Policy | Medium | DMARC subdomain policy is set to 'none' (allows subdomain spoofing) | `sp=none` or `sp=` absent with `p=none` (subdomains inherit weak policy) |
| Partial DMARC coverage (`dmarc_partial_coverage`) | Low → High (by `pct` range, see below) | DMARC is not applied to 100% of messages | `pct=` value is less than 100 (partial enforcement) |
| DMARC policy in test mode (`dmarc_testing_mode`) | Medium (`p=reject`) / High (`p=quarantine`) | `t=y` (RFC 9989): the policy is applied one level lower | `t=y` with `p=quarantine` or `p=reject` |
| DNS Timeout | Medium | DNS query timed out | DNS server didn't respond within timeout period |
| DMARC Syntax Error | High | DMARC record has invalid syntax | checkdmarc parser raises DMARCSyntaxError (e.g., malformed tags, invalid format) |
| Invalid DMARC Tag | Medium | DMARC record contains an unrecognized tag | checkdmarc raises InvalidDMARCTag (tag not in DMARC specification) |
| Invalid DMARC Tag Value | Medium | DMARC tag has an invalid value | checkdmarc raises InvalidDMARCTagValue (e.g., `p=invalid`, `pct=150`) |
| Invalid DMARC Report URI | Low | DMARC report URI is malformed | checkdmarc raises InvalidDMARCReportURI (e.g., invalid mailto format) |
| Multiple DMARC Records | High | Multiple DMARC records found for domain | checkdmarc raises MultipleDMARCRecords (only one DMARC record allowed per domain) |
| _dmarc CNAME points to an unregistered domain (`dmarc_cname_target_unregistered`) | Critical | Registrable domain of the broken target appears unregistered | Whoever registers it controls the DMARC policy (e.g. `p=none`) |
| _dmarc CNAME points to a potentially unregistered domain (`dmarc_cname_target_potentially_unregistered`) | High | No NS, registration not confirmed | Availability pipeline returns *unknown* |

**`pct` (RFC 7489 §6.6.4) — severity by range.** A receiver implementing RFC 7489 applies
the policy to `pct`% of the messages failing DMARC and the **next less strict policy** to the
other `(100 - pct)`%: `p=quarantine` → `none` (delivered), `p=reject` → `quarantine` (spam).
The severity of `dmarc_partial_coverage` therefore depends on the range **and** on the policy
(`IssueDefinitions.DMARC_PCT_SEVERITY`, same ranges as the `likelihood_by_pct` table of
`mail_audit`):

| `pct` | Share of spoofs escaping `p=` | `p=quarantine` (escapes get `none`) | `p=reject` (escapes get `quarantine`) |
|---|---|---|---|
| 0 | 100 % (whole policy one level lower, like `t=y`) | High | Medium |
| 1 – 10 | 90 – 99 % | High | Medium |
| 11 – 35 | 65 – 89 % | High | Medium |
| 36 – 65 | 35 – 64 % | Medium | Low |
| 66 – 90 | 10 – 34 % | Low | Low |
| 91 – 99 | 1 – 9 % | Low | Low |
| any, with `p=none` | — | Low (nothing is enforced anyway) | — |

`additional_data` carries `percentage`, `escape_rate`, `pct_range`, `policy` and
`fallback_policy`. RFC 9989 (DMARCbis) removed `pct`: receivers implementing it ignore the
tag and apply the full policy; `pct` is still read because RFC 7489 receivers apply it.

### DKIM Issues (10 types)

| Title | Severity | Description | When Detected |
|-------|----------|-------------|---------------|
| No DKIM selectors found (`dkim_no_selectors`) | Medium | None of the tested selectors has a TXT record | Enumeration of the selector list finds nothing |
| Weak DKIM RSA Key Size (`dkim_rsa_weak_key`) | High | RSA key of less than 1024 bits (weak cryptography) | `k=rsa` or no `k=` tag, and RSA key size < 1024 bits (factorable, e.g. 512-bit) |
| Perfectible DKIM RSA Key Size (`dkim_rsa_perfectible_key`) | Low | RSA key of exactly 1024 bits | `k=rsa` or no `k=` tag. RFC 8301 minimum, not practically factorable today, but 2048 bits is recommended — plan a rotation |
| DKIM RSA private key is recoverable (`dkim_rsa_known_factorization`) | Critical | Anyone can compute the private key | A factor of the modulus is known: published on factordb.com (verified locally), small prime factor (< 2^16), or prime modulus. See *RSA key checks* below |
| Dangerous DKIM RSA public exponent (`dkim_rsa_dangerous_exponent`) | Critical (`e=1`) / High (`e=3`) | Signature forgery without the private key on lenient verifiers | `e=1` or `e=3` |
| Non-standard / invalid DKIM RSA public exponent (`dkim_rsa_nonstandard_exponent`) | Low (legacy, too large) / Medium (invalid) | Exponent other than 65537 | `3 < e < 65537` (e.g. 17), `e >= 2^256`, or an invalid `e` (even, `< 3`) |
| DKIM Syntax Error (`dkim_syntax_error`) | Medium | DKIM record or key is invalid | Unknown `k=` value, invalid base64, `p=` not matching `k=` (see below); in `check_record` mode also missing `v=DKIM1` or missing `p=` tag |
| DNS Timeout (`dkim_dns_timeout`) | High | DNS timeout on an email domain | Timeout while querying the domain |
| DKIM selector CNAME points to an unregistered domain (`dkim_cname_target_unregistered`) | Critical | Registrable domain of the broken target appears unregistered | Whoever registers it can publish a key and sign mail **as the audited domain** (DKIM-aligned → DMARC pass) |
| DKIM selector CNAME points to a potentially unregistered domain (`dkim_cname_target_potentially_unregistered`) | High | No NS, registration not confirmed | Availability pipeline returns *unknown* |

**Key type handling.** The checker reads `k=` (default `rsa`, RFC 6376), then checks `p=`
against it. The 1024-bit thresholds apply to RSA keys only:

| `k=` | `p=` | Result |
|---|---|---|
| `rsa` or absent | RSA key < 1024 bits | `dkim_rsa_weak_key` (High) |
| `rsa` or absent | RSA key of 1024 bits | `dkim_rsa_perfectible_key` (Low) |
| `rsa` or absent | RSA key > 1024 bits | no issue |
| `ed25519` | raw 32-byte key (RFC 8463) | no issue, key size 256 |
| `ed25519` | DER-wrapped Ed25519 key, RSA key, other length | `dkim_syntax_error` |
| `rsa` or absent | Ed25519 or EC key, invalid key | `dkim_syntax_error` |
| any other value | any | `dkim_syntax_error` (unsupported key type) |
| any | empty (revoked key) | no issue |

#### RSA key checks: public exponent and recoverable private key

For every RSA key (`k=rsa` or no `k=`), `n` and `e` are read from the DER
SubjectPublicKeyInfo (`lib/utils/rsa_key_checks.py`, which also reads keys that
`cryptography` refuses to load, e.g. `e=1`), then:

**1. Public exponent `e`** (`rate_exponent`):

| `e` | Rating | Issue | Why |
|---|---|---|---|
| 65537 (up to 2^256) | standard | — | RFC 8017 / NIST SP 800-56B range; 65537 is the norm |
| 1 | dangerous | `dkim_rsa_dangerous_exponent` (Critical) | `s^1 = s`: the padded hash is its own signature, no private key needed |
| 3 | dangerous | `dkim_rsa_dangerous_exponent` (High) | Cube-root forgery (Bleichenbacher 2006) on verifiers that check the PKCS#1 v1.5 padding loosely |
| 5 … 65535 (e.g. 17) | legacy | `dkim_rsa_nonstandard_exponent` (Low) | No practical attack with correct padding, but outdated, below the NIST minimum |
| even, or < 3 (other than 1) | invalid | `dkim_rsa_nonstandard_exponent` (Medium) | No private exponent exists: nothing verifies, mail signed with the selector fails DKIM |
| ≥ 2^256 | non_standard | `dkim_rsa_nonstandard_exponent` (Low) | Above the NIST maximum; some verifiers refuse it |

**2. Can anyone compute the private key?** One `dkim_rsa_known_factorization` (Critical)
at most, with `additional_data.source`:

| Check | Where | `source` |
|---|---|---|
| Trial division by every prime < 2^16 | offline | `small_factor` |
| Miller-Rabin primality test (a prime modulus makes `φ(n) = n - 1` public) | offline | `prime_modulus` |
| Lookup on [factordb.com](https://factordb.com) | network | `factordb` |

**factordb lookup** (`lib/utils/factordb.py`, `FactorDBClient`):

- Reads the search page `https://factordb.com/index.php?query=<n in decimal>`, not the
  throttled JSON API. Reading a number does not store it on factordb ("Reading never stores
  anything"), so an audit does not add the audited keys to the database.
- factordb status (badge on the page): `FF` fully factored, `CF` a factor known, `C` no
  factor known, `P`/`PRP` prime, `U` unknown. With `FF`/`CF` each listed factor is read
  (abbreviated long factors are fetched from their own page, `?id=<id>&full=1`) and
  **verified locally** (`1 < p < n` and `n mod p = 0`) before an issue is raised: a change of
  the site's HTML can cause a miss, never a false finding.
- Follows https://factordb.com/limits.php: its own User-Agent, one request at a time, 0.5 s
  between requests, in-memory cache per modulus (a key shared by many domains is queried once),
  and no further request in the run after an HTTP 429. Network errors are reported in the
  selector's `factordb` field (`status: "error"`), never as an issue.
- **Information box.** factordb annotates well-known numbers ("*Interesting number.* 768-bit
  Oakley Group 1 (RFC 2409, 1998)…", "*…the second most common 512-bit export DH prime…
  Logjam…*", RSA challenge numbers…). The text is kept in `notes`: it tells where a key
  comes from (a copied example, a published prime). It is added to the issue detail and to
  the *factordb Note* column of the `mail_audit` Excel export.
- factordb is queried for every RSA key when enabled, **even after an offline finding**
  (small factor, prime modulus), so that the note is available; the offline source is kept
  as the issue `source`.
- Each RSA selector gets a `factordb` field in the JSON output: `status`, `url` (link to
  the factordb page), `notes` when factordb has some, and `factor_digits` when a factor is
  known. The factors themselves are not written to the report.
- Disable it with `--skip-factordb-check` (CLI) or `DKIMChecker(factordb=None)` (the
  default for the library). The offline checks always run.

### CNAME Chain Checks

Complementary control: **detect broken or hijackable CNAME aliases at the DNS names
where receivers look up authentication records**.

| Protocol | Name checked | Source of the names |
|----------|--------------|---------------------|
| SPF   | `<domain>` | the audited domain (alias at the name holding the SPF TXT) |
| DMARC | `_dmarc.<domain>` | the audited domain |
| DKIM  | `<selector>._domainkey.<domain>` | every selector tested by the enumeration (bundled list or `--dkim-selector-file`) |

Out of scope: `include:` / `redirect=` targets of an SPF record (already handled by
the **Unregistered Domains in SPF** control, which is left untouched).

```dns
; configuration detected (example)
test                     IN CNAME target.example.
_dmarc.test              IN CNAME target.example.
selector1._domainkey.test IN CNAME target.example.
```

**Resolution**

1. The TXT lookup keeps the CNAME links of the answer section even when the final
   rcode is NXDOMAIN — "source name absent" and "alias present, target absent" are
   never confused. A source name without CNAME is **not** reported.
2. When an alias is observed (or the lookup is SERVFAIL/TIMEOUT/REFUSED, which is how
   resolvers answer CNAME loops), the chain is walked **hop by hop** (`qtype=CNAME`),
   with loop detection and a maximum depth (`--cname-max-depth`, default 10). The
   status of each hop is stored.
3. The TXT RRset is fetched at the final target. **The absence of A/AAAA is never a
   failure** — a DKIM/DMARC/SPF target can legitimately serve only TXT.
4. If the hop-by-hop walk cannot confirm an alias that the TXT answer showed, the
   observed chain is kept (confidence `medium`).

**Anomaly categories** (`cname_checks[].anomaly`)

These anomalies are **evidence only — none of them raises an issue by itself**. The
only CNAME issues are the takeover risks below (`*_cname_target_unregistered`,
`*_cname_target_potentially_unregistered`).

| Anomaly | Meaning | Registration check? |
|---------|---------|---------------------|
| `ok` | Chain resolves to a relevant TXT (`v=spf1`, `v=DMARC1`, DKIM `p=`) | no (target exists) |
| `broken_reference` | Final target is NXDOMAIN | **yes** — the target domain may be buyable |
| `missing_record` | Target exists (NOERROR/NODATA) but has no relevant TXT | no (domain is registered) |
| `resolution_loop` / `max_depth_exceeded` | Loop / chain too long | no |
| `indeterminate` | SERVFAIL / TIMEOUT / REFUSED — **never** read as absent | **yes** (a lame/expired delegation often answers SERVFAIL) |
| `check_error` | Unexpected exception in the check (main result kept) | no |

**Issues raised (takeover risk only)**

| Issue | Severity | When |
|-------|----------|------|
| `<spf\|dmarc\|dkim>_cname_target_unregistered` | Critical | Availability pipeline says the target's registrable domain is **available** |
| `<spf\|dmarc\|dkim>_cname_target_potentially_unregistered` | High | No NS and registration **not confirmed** (same rule as the SPF include control) |

A TXT present but **invalid** (bad DKIM key, DMARC syntax error…) is a content
problem, reported by the existing validators — not evidence of an abandoned domain.

**DKIM wildcard control** (separate from target validation)

- For each DNS parent of a selector that is an alias (`_domainkey.<domain>`, or
  `<label>._domainkey.<domain>` for multi-label selectors), at least **3 random names**
  `random-<uuid>.<parent>` are resolved (`--cname-wildcard-probes`).
- If all probes return the **same CNAME chain** as the selector → `wildcard_probable`
  (an explicit record is not excluded). Other outcomes: `explicit` (probes not aliased),
  `wildcard_other_target`, `inconclusive`, `indeterminate`.
- Wildcard results are **grouped, not dropped**: if the wildcard target is unregistered,
  one takeover issue lists every selector.
- A CNAME on the parent (`_domainkey.<domain>`) is never treated as a wildcard — it
  does not apply to descendants. Closest-encloser rules are applied by the
  authoritative server; nothing is simulated by string substitution.

**Registrable domain & registration state** (`registrable_domain`, `suffix_type`, `registration`)

`NXDOMAIN` is **never** treated as "available for registration": a sub-domain can be
absent while its parent is registered. For broken / indeterminate targets:

| `registration.state` | Meaning |
|----------------------|---------|
| `not_verified` | Not checked (`--skip-domain-availability-check`, checker unavailable) |
| `registered` | Registrable domain is registered — only the target name is missing |
| `unregistered` | Availability pipeline says *available* → `*_cname_target_unregistered` (critical) |
| `potentially_unregistered` | No NS, status unconfirmed → `*_cname_target_potentially_unregistered` (high) |
| `reserved` | Special-use / reserved name (`.invalid`, `.test`, `.example`, `.localhost`, `.local`, `.onion`, `.alt`, `.internal`, `example.com/net/org`, `home.arpa`): absent **and** not registrable |
| `private_suffix` | Under a PSL *private* suffix (hosted platform, e.g. `*.github.io`): claimability depends on the provider, verify manually |
| `unknown` | No public suffix match |

- The registrable domain comes from the **Public Suffix List** (tldextract), never from
  the last two labels.
- Registration checks reuse the **same** `DomainAvailabilityChecker` pipeline as the SPF
  include control (`check_domains_availability`), in the **same bulk call**; the source
  stage (`has_ns`, `whois_available`, `service_unknown`…) is kept as evidence.
- Network errors, rate limits and ambiguous answers stay `potentially_unregistered` /
  `unknown`; an expired date alone is not "re-registrable". Takeover is **never**
  reported as confirmed, and nothing is ever registered.

Each `cname_checks` entry contains: `protocol`, `queried_name`, `selector`, `chain`,
`hops` (name/status/target), `failing_target`, `dns_status`, `txt_status`,
`relevant_record_found`, `wildcard`, `registrable_domain`, `suffix_type`,
`registration`, `anomaly`, `confidence` (`high`/`medium`/`low`) and `evidence`.

### Severity Levels

| Severity | Impact | Recommended Action |
|----------|--------|-------------------|
| **Critical** | Directly exploitable spoofing / takeover vector | Fix immediately |
| **High** | Critical security vulnerability | Fix immediately |
| **Medium** | Moderate security risk | Fix soon |
| **Low** | Minor configuration issue | Fix when possible |

### Issue Detection Flow

**SPF:**
1. DNS query for TXT record
2. Parse SPF syntax
3. Check for dangerous includes (CSV Tier 1)
4. Check for dangerous IP ranges (CSV Tier 2)
5. Lookup AS organization via MaxMind (Tier 3)
6. Validate ALL mechanism
7. Count DNS lookups (max 10)
8. CNAME chain check at `<domain>` (alias only, not includes) — evidence only
9. (CLI / mail_audit) bulk registration check of include domains + broken CNAME targets

**DMARC:**
1. DNS query for `_dmarc.domain` TXT record. For a subdomain (e.g. `news.exemple.fr`):
   - a valid record at `_dmarc.news.exemple.fr` takes priority;
   - otherwise the record of the **organizational domain** (Public Suffix List:
     `news.exemple.co.uk` → `exemple.co.uk`) applies, with its **`sp=`** policy, or **`p=`**
     when `sp=` is absent (RFC 7489 §6.6.3). `policy` is then this effective value,
     `policy_inherited_from` says where it comes from (e.g. `exemple.fr (sp=none)`) and
     `organizational_policy` keeps the org's own `p=`; `dmarc_lax_policy` is computed on the
     effective value
2. Parse DMARC tags (p=, sp=, pct=, etc.)
3. Validate policy strictness
4. Check subdomain policy
5. Verify percentage coverage
6. CNAME chain check at `_dmarc.<domain>` — evidence only

**DKIM:**
1. Try common selectors from list
2. DNS query for `selector._domainkey.domain` TXT record
3. Parse the `k=` and `p=` tags (`k=` defaults to `rsa`)
4. Check that `p=` matches `k=` (otherwise `dkim_syntax_error`), then, for RSA keys only,
   validate the size (< 1024 bits → weak, high; = 1024 bits → perfectible, low)
5. CNAME chain check on aliased selectors + wildcard probes (3 random siblings per parent)

### Related Files

- **Issue Definitions:** [lib/checkers/issue_definitions.py](lib/checkers/issue_definitions.py)
- **Issue Model:** [lib/models/issue.py](lib/models/issue.py)
- **SPF Checker:** [lib/checkers/spf_checker.py](lib/checkers/spf_checker.py)
- **DMARC Checker:** [lib/checkers/dmarc_checker.py](lib/checkers/dmarc_checker.py)
- **DKIM Checker:** [lib/checkers/dkim_checker.py](lib/checkers/dkim_checker.py)
- **CNAME Checker:** [lib/checkers/cname_checker.py](lib/checkers/cname_checker.py), [lib/utils/cname_chain.py](lib/utils/cname_chain.py), [lib/models/cname_result.py](lib/models/cname_result.py)
- **Registration checks:** [lib/checkers/unregistered_domain_checker.py](lib/checkers/unregistered_domain_checker.py)

---

## CLI Tool (cli.py)

Full-featured command-line interface for batch processing and analysis.

### Modes

#### 1. check_record (Default)

Check SPF/DKIM/DMARC records from various input sources.

#### 2. check_unknown_data

Analyze JSON output to find unknown SPF data not in CSV databases.

---

### Input Sources

**Mutually exclusive** - choose one:

#### --hostnames FILE

File with hostnames (one per line). Scans SPF/DMARC/DKIM via DNS.

**Example file (domains.txt):**
```
example.com
google.com
github.com
```

**Usage:**
```bash
python cli.py --hostnames domains.txt
```

**Respects `--check-types`**: Yes

---

#### --check-spf-records FILE

CSV file with `domain;SPF` columns (semicolon-separated). **SPF ONLY mode** - checks only SPF records, ignores `--check-types`.

**Example file (spf_records.csv):**
```csv
domain;SPF
example.com;v=spf1 include:_spf.google.com -all
github.com;v=spf1 ip4:192.30.252.0/22 -all
```

**Usage:**
```bash
python cli.py --check-spf-records spf_records.csv
```

**Output**: JSON and Excel will contain ONLY SPF records and issues (no DMARC/DKIM).

**Respects `--check-types`**: No (forced to SPF only)

---

#### --spf-tree-json PATH

JSON file or directory containing JSON files with parsed SPF trees (output from previous scan). **SPF ONLY mode** - checks only SPF records, ignores `--check-types`.

**Single file:**
```bash
python cli.py --spf-tree-json output/spf_analysis_20251212.json
```

**Directory (loads all .json files):**
```bash
python cli.py --spf-tree-json output/spf_trees/
```

**Output**: JSON and Excel will contain ONLY SPF records and issues (no DMARC/DKIM).

**Respects `--check-types`**: No (forced to SPF only)

---

#### --convert-json-report-to-excel JSON_FILE

Convert a JSON report file (from a previous scan) to Excel format. Useful for regenerating Excel files with updated formatting or after code changes.

**Usage:**
```bash
python cli.py --convert-json-report-to-excel ./results/policy_check_20260120_114335.json
```

**Output**: Creates an Excel file with the same name as the JSON file but with `.xlsx` extension.

**Example:**
```bash
# Input:  ./results/policy_check_20260120_114335.json
# Output: ./results/policy_check_20260120_114335.xlsx
```

**Sheets generated** (based on data present in JSON):
- **Summary** - Overview of all domains
- **SPF Records** - Full SPF records
- **DMARC Records** - Full DMARC records
- **DKIM Records** - DKIM selector records, with Key Type and Key Size
- **SPF Issues** - Detailed SPF issues with Resolution Path
- **DMARC Issues** - Detailed DMARC issues

**Note**: This option is standalone and ignores all other arguments (--mode, --check-types, etc.).

---

### Configuration Options

#### --mode {check_record,check_unknown_data}

Mode of operation (default: `check_record`).

```bash
# Check records (default)
python cli.py --hostnames domains.txt --mode check_record

# Analyze unknown data
python cli.py --spf-tree-json output/scan.json --mode check_unknown_data
```

#### --check-types {spf,dkim,dmarc} [{spf,dkim,dmarc} ...]

Record types to check (default: `spf dkim dmarc`).

```bash
# Check only SPF
python cli.py --hostnames domains.txt --check-types spf

# Check SPF and DMARC
python cli.py --hostnames domains.txt --check-types spf dmarc
```

#### --data-dir DIR

Directory containing CSV databases (default: `./data`).

```bash
python cli.py --hostnames domains.txt --data-dir /custom/data/path
```

#### --nameservers IP[,IP...]

Custom DNS resolver(s), as a comma-separated list of IPs, e.g. `1.1.1.1,8.8.8.8` (default: system default).

```bash
# Use Google DNS
python cli.py --hostnames domains.txt --nameservers 8.8.8.8

# Use Cloudflare DNS
python cli.py --hostnames domains.txt --nameservers 1.1.1.1
```

#### --use-ns-record

Use domain's NS record for DNS queries (default: False).

```bash
python cli.py --hostnames domains.txt --use-ns-record
```

**What it does:**
1. Query NS records for each domain
2. Use the first authoritative nameserver for all subsequent queries
3. More accurate results, bypasses caching

#### --dns-timeout SECONDS

DNS query timeout in seconds (default: 5).

```bash
python cli.py --hostnames domains.txt --dns-timeout 10
```

#### --skip-email-domain-indicators-check

Skip email domain indicator checks and scan all domains (default: False).

**By default**, the tool checks if a domain is used for email (via MX, SPF, DMARC, SMTP indicators) before scanning SPF/DMARC. This prevents pollution of Excel exports with false positives for non-email domains.

Use this flag to **disable** the check and scan all domains regardless of email indicators.

```bash
# Default behavior: Only scan email domains
python cli.py --hostnames domains.txt

# Skip check: Scan ALL domains (including CDN, static sites, etc.)
python cli.py --hostnames domains.txt --skip-email-domain-indicators-check
```

**Recommended**: Leave this flag OFF to avoid false positives in Excel reports.

#### --output-dir DIR

Output directory (default: `./output`).

```bash
python cli.py --hostnames domains.txt --output-dir ./results
```

#### --output FILENAME

Output filename (without extension, will create .json and .xlsx).

**If file exists, will prompt for new name in a loop.**

```bash
python cli.py --hostnames domains.txt --output my_scan_results
# Creates:
# - output/my_scan_results.json
# - output/my_scan_results.xlsx

# If files exist:
# Prompts: "File 'my_scan_results.json' already exists in output/"
# Prompts: "Enter a different filename (without path):"
# Loops until unique name provided
```

#### --ptr-pool-size N

Number of parallel PTR lookups for `check_unknown_data` mode (default: 20).

```bash
python cli.py --spf-tree-json scan.json --mode check_unknown_data --ptr-pool-size 50
```

#### --include-ptr

Include PTR lookups in `check_unknown_data` mode (default: False).

```bash
python cli.py --spf-tree-json scan.json --mode check_unknown_data --include-ptr
```

#### --dkim-selector-file FILE

Custom DKIM selector list (one selector per line, `#` comments allowed). It
**replaces** the bundled `<data-dir>/DKIM_Selectors.txt` (default). The file is
validated at start-up (missing or empty file → error).

```bash
python cli.py --hostnames domains.txt --dkim-selector-file ./selector.txt
```

#### --skip-cname-check

Disable the [CNAME chain check](#cname-chain-checks) on DKIM selector, `_dmarc` and
SPF domain names (default: enabled).

#### --cname-max-depth N

Maximum number of CNAME links followed before reporting `max_depth_exceeded`
(default: 10).

#### --cname-wildcard-probes N

Random sibling names (`random-<uuid>.<parent>`) resolved per DKIM selector parent to
detect wildcards (default and minimum: 3).

#### --skip-domain-availability-check

Skip the registration check (DomainAvailabilityChecker: NS → RDAP/WHOIS → registrar)
on SPF include domains **and** on the registrable domains of broken CNAME targets.
Those CNAME targets then stay `registration.state = not_verified`.

#### --skip-factordb-check

Do not look DKIM RSA moduli up on factordb.com (known factorizations). The offline key
checks (exponent, small factor, prime modulus) still run. See *RSA key checks*.

---

### CLI Examples

#### Example 1: Basic SPF/DMARC/DKIM Check

```bash
python cli.py --hostnames domains.txt
```

**Output:**
- `output/policy_check_TIMESTAMP.json`
- `output/policy_check_TIMESTAMP.xlsx`

#### Example 2: SPF Only with Custom DNS

```bash
python cli.py --hostnames domains.txt \
  --check-types spf \
  --nameservers 8.8.8.8 \
  --output spf_scan_google_dns
```

#### Example 3: Use Authoritative Nameservers

```bash
python cli.py --hostnames domains.txt \
  --use-ns-record \
  --dns-timeout 10
```

#### Example 4: Check SPF Records from CSV (SPF ONLY)

```bash
python cli.py --check-spf-records spf_records.csv \
  --output corporate_spf_analysis
```

**Note**: Ignores `--check-types`, only checks SPF. Output contains only SPF records and issues.

#### Example 5: Check SPF Trees from JSON (SPF ONLY)

**Single file:**
```bash
python cli.py --spf-tree-json output/spf_analysis_20251212.json \
  --output spf_tree_check
```

**Directory (all .json files):**
```bash
python cli.py --spf-tree-json output/spf_trees/ \
  --output batch_spf_check
```

**Note**: Ignores `--check-types`, only checks SPF. Output contains only SPF records and issues.

#### Example 6: Analyze Unknown SPF Data

```bash
python cli.py --spf-tree-json output/spf_analysis_20251212.json \
  --mode check_unknown_data \
  --include-ptr \
  --ptr-pool-size 30 \
  --output unknown_analysis
```

**Output:**
- `output/unknown_spf_data_TIMESTAMP.json`
- `output/unknown_spf_data_TIMESTAMP.xlsx` with sheets:
  - Unknown Includes
  - IP AS Organization
  - IP Address AS Org
  - IP PTR Records

#### Example 7: Custom Everything

```bash
python cli.py --hostnames domains.txt \
  --check-types spf dmarc \
  --data-dir /custom/data \
  --nameservers 1.1.1.1 \
  --use-ns-record \
  --dns-timeout 15 \
  --output-dir ./results \
  --output my_detailed_scan
```

#### Example 8: Convert JSON Report to Excel

```bash
# Convert existing JSON report to Excel format
python cli.py --convert-json-report-to-excel ./results/policy_check_20260120_114335.json

# Output: ./results/policy_check_20260120_114335.xlsx
```

**Use case**: Regenerate Excel file after code updates (e.g., new columns added to SPF Issues sheet).

---

### CLI Help

```bash
python cli.py --help
```

**Output:**
```
usage: cli.py [-h]
               (--hostnames HOSTNAMES | --check-spf-records CHECK_SPF_RECORDS | --spf-tree-json SPF_TREE_JSON)
               [--mode {check_record,check_unknown_data}]
               [--check-types {spf,dkim,dmarc} [{spf,dkim,dmarc} ...]]
               [--data-dir DATA_DIR] [--nameservers IP[,IP...]]
               [--use-ns-record] [--dns-timeout DNS_TIMEOUT]
               [--max-dns-retries MAX_DNS_RETRIES]
               [--output-dir OUTPUT_DIR] [--output OUTPUT]
               [--require-indicators REQUIRE_INDICATORS [REQUIRE_INDICATORS ...]]
               [--email-checks EMAIL_CHECKS [EMAIL_CHECKS ...]]
               [--disable-ptr-blacklist] [--disable-update-ptr-blacklist]
               [--ptr-blacklist-pool-size PTR_BLACKLIST_POOL_SIZE]
               [--skip-domain-availability-check] [--dkim-selector-file FILE]
               [--skip-cname-check] [--cname-max-depth N]
               [--cname-wildcard-probes N]

Mail AntiSpoof Policy Checker - Check SPF/DKIM/DMARC records and analyze unknown SPF data

options:
  -h, --help            show this help message and exit
  --hostnames HOSTNAMES
                        File with hostnames (one per line)
  --check-spf-records CHECK_SPF_RECORDS
                        CSV file with domain;SPF columns
  --spf-tree-json SPF_TREE_JSON
                        JSON file with parsed SPF trees
  --mode {check_record,check_unknown_data}
                        Mode of operation (default: check_record)
  --check-types {spf,dkim,dmarc} [{spf,dkim,dmarc} ...]
                        Record types to check (default: spf dkim dmarc)
  --data-dir DATA_DIR   Directory containing CSV databases (default: ./data)
  --nameservers IP[,IP...]
                        Comma-separated custom DNS resolvers (e.g.
                        '1.1.1.1,8.8.8.8'). Default: system default
  --use-ns-record       Use domain's NS record for DNS queries
  --dns-timeout DNS_TIMEOUT
                        DNS query timeout in seconds (default: 5)
  --max-dns-retries MAX_DNS_RETRIES
                        Maximum DNS retries per server (default: 3)
  --output-dir OUTPUT_DIR
                        Output directory (default: ./output)
  --output OUTPUT       Output filename (without extension, will create .json
                        and .xlsx). If file exists, will prompt for new name.
  --require-indicators REQUIRE_INDICATORS [REQUIRE_INDICATORS ...]
                        Email indicators required (default: HAS_MX)
  --email-checks EMAIL_CHECKS [EMAIL_CHECKS ...]
                        Email indicators to check (default: all)
  --disable-ptr-blacklist
                        Disable PTR blacklist from IPs via reverse DNS (enabled by default)
  --disable-update-ptr-blacklist
                        Disable automatic update of PTR blacklist CSV on first run
  --ptr-blacklist-pool-size PTR_BLACKLIST_POOL_SIZE
                        Parallel PTR lookups pool size (default: 20)
  --skip-domain-availability-check
                        Skip the unregistered/potentially-unregistered domain check on SPF
                        includes and on broken CNAME targets (default: False)
  --dkim-selector-file FILE
                        Custom DKIM selector list (one selector per line, "#" comments
                        allowed). Replaces the bundled list. Default:
                        <data-dir>/DKIM_Selectors.txt
  --skip-cname-check    Skip the CNAME chain check on DKIM selector, _dmarc and SPF domain
                        names (default: False)
  --cname-max-depth N   Maximum number of CNAME links followed before reporting excessive
                        depth (default: 10)
  --cname-wildcard-probes N
                        Random sibling names probed per DKIM selector parent to detect
                        wildcards (minimum and default: 3)

Examples:
  # Check SPF/DMARC/DKIM for domains in a file
  python cli.py --hostnames domains.txt

  # Check only SPF from a CSV file
  python cli.py --check-spf-records domains.csv --check-types spf

  # Analyze unknown SPF data from JSON output
  python cli.py --spf-tree-json output/spf_analysis.json --mode check_unknown_data

  # Use custom DNS server and output filename
  python cli.py --hostnames domains.txt --nameservers 1.1.1.1 --output my_results
```

---

## Configuration

### MaxMind GeoIP2 Setup

For AS organization detection, you need a MaxMind license key.

#### 1. Get a License Key

1. Sign up at: https://www.maxmind.com/en/geolite2/signup
2. Generate a license key in your account
3. Copy the license key

#### 2. Set Environment Variable

**Windows PowerShell:**
```powershell
$env:MAXMIND_LICENSE_KEY = "your_license_key_here"
```

**Windows CMD:**
```cmd
set MAXMIND_LICENSE_KEY=your_license_key_here
```

**Linux/Mac:**
```bash
export MAXMIND_LICENSE_KEY="your_license_key_here"
```

#### 3. Verify

```python
from lib.utils.maxmind_client import MaxMindClient

try:
    client = MaxMindClient.from_environment()
    print("MaxMind client initialized successfully")
except ValueError as e:
    print(f"Error: {e}")
```

---

## CSV Databases

### Structure

The tool uses **3 CSV databases** to detect dangerous third-party services, plus **1 whitelist** acting as a recursion guard.

All CSV files use **semicolon (;)** as delimiter and require a **`dangerous` column**.

#### 1. Dangerous_SPF_Include.csv

Dangerous SPF includes/redirects.

**Location:** `data/Dangerous_SPF_Include.csv`

**Format:**
```csv
include;service_type;service_name;dangerous
spf.mailjet.com;Email Delivery Service;Mailjet;Yes
_spf.google.com;Email Delivery Service;Google Workspace;No
spf.protection.outlook.com;Email Delivery Service;Microsoft 365;No
```

**Columns:**
- `include`: Include/redirect domain (e.g., `spf.mailjet.com`)
- `service_type`: Type of service (e.g., `Email Delivery Service`, `Shared Hosting`)
- `service_name`: Name of service (e.g., `Mailjet`, `SendGrid`)
- `dangerous`: `Yes` or `No` (only `Yes` entries loaded by default)

#### 2. Dangerous_SPF_Records_IP_Range.csv

Dangerous IP ranges/addresses.

**Location:** `data/Dangerous_SPF_Records_IP_Range.csv`

**Format:**
```csv
spf include;service_type;service_name;dangerous
192.168.1.0/24;Shared Hosting;SharedHostingProvider;Yes
10.0.0.0/8;Private Network;RFC1918;No
```

**Columns:**
- `spf include`: IP range in CIDR notation (e.g., `192.168.1.0/24`)
- `service_type`: Type of service
- `service_name`: Name of service
- `dangerous`: `Yes` or `No`

#### 3. Dangerous_AS_Organization.csv

Dangerous AS organizations (for MaxMind lookup).

**Location:** `data/Dangerous_AS_Organization.csv`

**Format:**
```csv
include;service_type;service_name;dangerous
SENDGRID;Email Marketing;SendGrid;Yes
MAILCHIMP;Email Marketing;Mailchimp;Yes
GOOGLE;Cloud Provider;Google Cloud;No
```

**Columns:**
- `include`: AS organization name (e.g., `SENDGRID`)
- `service_type`: Type of service (e.g., `Email Marketing`)
- `service_name`: Name of service
- `dangerous`: `Yes` or `No`

#### 4. Whitelisted_SPF_Include.csv (whitelist)

Platforms explicitly known as **not** dangerous. This file creates no findings — it **suppresses** them.

**Location:** `data/Whitelisted_SPF_Include.csv`

**Format:** identical to `Dangerous_SPF_Include.csv`, but every row must be `No`.

```csv
include;service_type;service_name;dangerous
amazonses.com;Email Delivery Service;Amazon SES;No
```

##### Why it exists

When a dangerous include is resolved, the tool walks its whole SPF tree and attributes every IP found to that service. Some trees end on a large shared platform:

```
spf.infomaniak.ch → newsletter.infomaniak.com → amazonses.com
```

Without a guard, the 12 AWS SES ranges (`54.240.0.0/18`, `76.223.176.0/20`, …) are recorded as *Infomaniak / Shared Hosting / CRITICAL*. Any unrelated domain legitimately using `include:amazonses.com` is then flagged as using Infomaniak shared hosting.

##### Whitelisted includes are resolved recursively

Exactly like the dangerous side. `_resolve_whitelisted_includes()` walks each whitelisted include's SPF tree (`ip4:`, `ip6:`, `a`, `a:`, `mx`, `mx:`, `include:` followed recursively to depth 10), deduplicates and collapses redundant ranges, and produces `WhitelistedSPFIPRange` objects. Whitelisting `amazonses.com` therefore whitelists its **12 resolved IP ranges**, not just the domain name.

The `ptr` mechanism is deliberately **not** processed in whitelist mode — that list is a blacklist and must never receive whitelist entries.

##### Where the whitelist applies

| # | Point of application | Effect |
|---|---|---|
| 1 | `include:` in a dangerous tree | Sub-tree not walked at all |
| 2 | IP resolved from a dangerous tree | Dropped if contained in whitelisted space (covers a dangerous service inlining `ip4:` of a shared platform) |
| 3 | PTR blacklist build | Reverse lookups landing in a whitelisted namespace are discarded |
| 4 | PTR blacklist load | Stale rows under a whitelisted platform are dropped, so an existing CSV self-heals |
| 5 | `SPFChecker` IP checks | An audited IP/range inside whitelisted space skips both the dangerous-range tier and the AS-organization tier |

Point 5 requires **full containment**: a range that merely clips the platform (e.g. `54.0.0.0/8`) still exposes addresses outside it and stays fully checked.

##### Precedence: declared dangerous always wins

A whitelist entry can never neutralise an explicit dangerous classification. Two guards enforce this, and both are mirror images of guard #1 above:

1. **Dangerous sub-include inside a whitelisted tree** — pruned during the walk. If `amazonses.com` included `sendgrid.net`, SendGrid's space is *not* whitelisted.
2. **Whitelisted range overlapping a declared dangerous range** — dropped after the walk. Overlap (not containment) is enough to drop, so the whitelist yields on any doubt.

Only **CSV-declared** dangerous data participates in these guards, never include-derived IPs — which is why the whitelist tree is resolved *before* the dangerous tree in `load_all()`. See the ordering note in that method's docstring.

Both guards are reported rather than silent, because either one means a whitelist entry is broader than intended:

```
Dangerous kept over whitelist: 1 sub-include(s)
  amazonses.com -> sendgrid.net (declared dangerous, NOT whitelisted)

Whitelist ranges dropped: 1
  54.240.0.0/18 (from amazonses.com) overlaps declared dangerous 54.240.0.0/20 (Evil Host)
```

##### Other behaviour

- A domain listed in **both** files keeps its dangerous status as a root entry — `Dangerous_SPF_Include.csv` wins for top-level detection.
- A row with `dangerous=Yes` raises a `ValueError` (contradicts the file's purpose).
- Normal run summary:

```
Whitelisted Includes:  1
Whitelisted IP Ranges: 12

Pruned by whitelist:   1
  spf.infomaniak.ch -> amazonses.com (not attributed)
```

##### API

```python
loaders.whitelisted_includes            # List[WhitelistedSPFInclude]
loaders.whitelisted_ip_ranges           # List[WhitelistedSPFIPRange] (resolved)
loaders.pruned_includes                 # dangerous root -> pruned sub-includes / ranges
loaders.dangerous_in_whitelist_tree     # whitelisted root -> dangerous sub-includes kept dangerous
loaders.whitelist_conflicts             # [(whitelisted_range, declared_dangerous_range)]

loaders.is_whitelisted_include("amazonses.com")                  # exact domain match
loaders.is_whitelisted_ip("54.240.0.5")                          # IP inside whitelisted space
loaders.is_whitelisted_ip_range("54.240.0.0/24")                 # range fully contained
loaders.find_whitelisted_ip_range("54.240.0.0/24")               # -> WhitelistedSPFIPRange | None
loaders.is_whitelisted_ptr("a192-1.smtp-out.amazonses.com")      # PTR suffix match
```

### Loading Behavior

By default, **only entries with `dangerous=Yes` are loaded**.

```python
# Load only dangerous entries (default)
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

print(len(data_loaders.dangerous_includes))  # Only dangerous=Yes

# Load all entries including non-dangerous
data_loaders.load_all(load_all_entries=True)

print(len(data_loaders.dangerous_includes))  # All entries
```

---

## Output Format

### JSON Output

**Structure:**
```json
[
  {
    "record_id": "example.com",
    "domain": "example.com",
    "spf": {
      "spf_record": "v=spf1 include:spf.mailjet.com -all",
      "all_qualifier": "fail",
      "all_includes": [
        {
          "include": "spf.mailjet.com",
          "dangerous": true,
          "service_type": "Email Delivery Service",
          "service_name": "Mailjet",
          "path": "example.com"
        }
      ],
      "all_ip_addresses": [
        {
          "ip": "223.165.113.0",
          "dangerous": true,
          "as_organization": "SENDGRID",
          "service_type": "Email Marketing",
          "service_name": "SendGrid",
          "path": "example.com→spf.sendgrid.net"
        }
      ],
      "issues": [
        {
          "title": "Dangerous Include Detected",
          "description": "Include 'spf.mailjet.com' is a shared email service",
          "severity": "high",
          "category": "security"
        }
      ]
    },
    "dmarc": {
      "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
      "policy": "reject",
      "subdomain_policy": "reject",
      "percentage": 100,
      "aggregate_report_uris": ["mailto:dmarc@example.com"],
      "issues": [],
      "cname_checks": []
    },
    "dkim": {
      "selectors_tested": 7,
      "selectors_found": [],
      "issues": [{"code": "dkim_cname_target_unregistered", "severity": "critical", "...": "..."}],
      "cname_checks": [
        {
          "protocol": "DKIM",
          "queried_name": "selector1._domainkey.example.com",
          "selector": "selector1",
          "chain": ["selector1._domainkey.example.com", "dkim.old-esp.net"],
          "hops": [
            {"name": "selector1._domainkey.example.com", "status": "NOERROR", "target": "dkim.old-esp.net"},
            {"name": "dkim.old-esp.net", "status": "NXDOMAIN"}
          ],
          "anomaly": "broken_reference",
          "failing_target": "dkim.old-esp.net",
          "dns_status": "NXDOMAIN",
          "txt_status": "NXDOMAIN",
          "relevant_record_found": false,
          "wildcard": {"status": "explicit", "parent": "_domainkey.example.com", "probes": ["..."]},
          "registrable_domain": "old-esp.net",
          "suffix_type": "icann",
          "registration": {"state": "unregistered", "source": "domain_availability_checker", "reason": "whois_available"},
          "confidence": "high",
          "evidence": ["TXT answer section showed: ... (NXDOMAIN)"]
        }
      ]
    }
  }
]
```

`cname_checks` is present (possibly empty) in every `spf`, `dmarc` and `dkim` block.

### Excel Output (check_record mode)

**Sheets:**

1. **Summary** - Overview of all domains
   - Columns: Record ID, Domain, SPF Status, SPF Issues, DMARC Status, DMARC Policy, etc.

2. **SPF Issues** - Detailed SPF issues
   - Columns: Record ID, Domain, Severity, Category, Title, Description

3. **DMARC Issues** - Detailed DMARC issues
   - Columns: Record ID, Domain, Severity, Category, Title, Description

4. **DKIM Issues** - Detailed DKIM issues (weak / perfectible RSA key, syntax, no selector, CNAME takeover)
   - Columns: Record ID, Domain, Severity, Category, Title, Selector, Key Size, CNAME Chain,
     Domain To Buy, Detail

Takeover issues (`*_cname_target_*`, `spf_domain_*unregistered`) also fill **CNAME Chain** /
**Domain To Buy** in the SPF and DMARC Issues sheets. The full CNAME evidence (hops,
wildcard probes, registration source…) stays in the JSON `cname_checks`.

### Excel Output (check_unknown_data mode)

**Sheets:**

1. **Unknown Includes** - Includes not in CSV
   - Columns: Record ID, Include, Path, SPF Record

2. **IP AS Organization** - IP ranges with AS org lookup
   - Columns: Record ID, IP Range, First IP, AS Organization, Country, SPF Record

3. **IP Address AS Org** - Individual IPs with AS org lookup
   - Columns: Record ID, IP Address, AS Organization, Country, SPF Record

4. **IP PTR Records** - PTR lookups (if `--include-ptr` used)
   - Columns: Record ID, IP Range, IP Address, PTR Record, AS Organization, SPF Record

---

## Examples

### Example 1: Full Pipeline

```python
from lib.checkers.spf_checker import SPFChecker
from lib.data.loaders import DataLoaders
from lib.utils.maxmind_client import MaxMindClient
import json
import pandas as pd

# 1. Initialize
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all()

maxmind_client = MaxMindClient.from_environment()

spf_checker = SPFChecker(
    maxmind_client=maxmind_client,
    data_loaders=data_loaders,
    nameservers=["8.8.8.8"]
)

# 2. Check multiple domains
domains = ["example.com", "google.com", "github.com"]
results = []

for domain in domains:
    try:
        result = spf_checker.check(domain)
        results.append(result.to_dict())
        print(f"✓ {domain}: {len(result.issues)} issues")
    except Exception as e:
        print(f"✗ {domain}: {e}")

# 3. Export to JSON
with open("output/scan_results.json", "w") as f:
    json.dump(results, f, indent=2)

# 4. Export to Excel
summary_data = []
for result in results:
    summary_data.append({
        'Domain': result['domain'],
        'SPF Record': result['spf_record'],
        'Issues': len(result['issues']),
        'Dangerous Includes': len([i for i in result['all_includes'] if i.get('dangerous')]),
        'ALL Qualifier': result['all_qualifier']
    })

df = pd.DataFrame(summary_data)
df.to_excel("output/scan_results.xlsx", index=False)

print(f"\nExported {len(results)} results")
```

### Example 2: Batch Processing with CLI

```bash
# 1. Create domains file
cat > domains.txt << EOF
example.com
google.com
github.com
microsoft.com
EOF

# 2. Run scan
python cli.py --hostnames domains.txt \
  --check-types spf dmarc \
  --nameservers 8.8.8.8 \
  --output corporate_scan

# 3. Analyze unknown data
python cli.py --spf-tree-json output/corporate_scan.json \
  --mode check_unknown_data \
  --include-ptr \
  --output corporate_unknown
```

### Example 3: Custom Dangerous Detection

```python
from lib.data.loaders import DataLoaders

# Load all entries (including non-dangerous)
data_loaders = DataLoaders(data_dir="./data")
data_loaders.load_all(load_all_entries=True)

# Filter custom criteria
custom_dangerous = [
    inc for inc in data_loaders.dangerous_includes
    if inc.service_type == "Shared Hosting"
]

print(f"Found {len(custom_dangerous)} shared hosting services")

for service in custom_dangerous:
    print(f"  - {service.include} ({service.service_name})")
```

---

## Architecture

### Project Structure

```
Mail AntiSpoof Policy Checker/
├── cli.py                          # CLI tool entry point
├── lib/
│   ├── checkers/
│   │   ├── spf_checker.py          # SPF validation
│   │   ├── dmarc_checker.py        # DMARC validation
│   │   ├── dkim_checker.py         # DKIM validation
│   │   ├── cname_checker.py        # CNAME chain check (DKIM/DMARC/SPF names, wildcards)
│   │   └── unregistered_domain_checker.py # Registration checks (SPF includes + CNAME targets)
│   ├── analyzers/
│   │   └── unknown_data_analyzer.py # Unknown SPF data analysis
│   ├── data/
│   │   └── loaders.py              # CSV data loaders
│   ├── models/
│   │   ├── spf_result.py           # SPF result model
│   │   ├── dmarc_result.py         # DMARC result model
│   │   ├── dkim_result.py          # DKIM result model
│   │   └── cname_result.py         # CNAMECheck model
│   └── utils/
│       ├── dns_utils.py            # DNS operations (incl. classified queries)
│       ├── cname_chain.py          # Hop-by-hop CNAME chain resolver
│       ├── maxmind_client.py       # MaxMind GeoIP2 client
│       └── ip_utils.py             # IP address utilities
├── data/                           # CSV databases
│   ├── Dangerous_SPF_Include.csv
│   ├── Whitelisted_SPF_Include.csv   # Whitelist (resolved recursively into IP ranges)
│   ├── Dangerous_SPF_Records_IP_Range.csv
│   └── Dangerous_AS_Organization.csv
├── tests/                          # Test suite
│   ├── unit/                       # Unit tests
│   └── integration/                # Integration tests
└── output/                         # Output directory (created automatically)
```

### Cascade Architecture

Both SPF and DMARC checkers use a **3-tier cascade**:

```
Tier 1: check(domain)           → DNS query + full analysis
Tier 2: check_record(string)    → Parse record + analysis
Tier 3: check_*_tree(parsed)    → Analyze parsed structure
```

This allows flexibility in input:
- **DNS query**: `check(domain)`
- **Raw record**: `check_record(spf_string)`
- **Pre-parsed**: `check_spf_tree(parsed_spf)` or `check_parsed_dmarc(parsed_dmarc)`

---

## Recent Updates (v0.0.3 - 2025-12-17)

### Enhanced SPF Parsing
- ✅ **a/mx mechanism parsing**: Now extracts and checks IPs from `a` and `mx` mechanisms
- ✅ **ptr mechanism detection**: Detects dangerous `ptr` and `ptr:domain.com` mechanisms
- ✅ **PTR blacklist building**: Optional reverse DNS lookup to build PTR domain blacklist from dangerous IPs

### DNS Improvements
- ✅ **DNS retry mechanism**: Automatic retry with fallback DNS servers (Google DNS, Cloudflare DNS, NS servers)
- ✅ **Timeout handling**: Fixed HAS_DMARC flag incorrectly set on DNS timeout
- ✅ **Excel export fix**: No longer creates empty DMARC Record rows on timeout

### Configuration Options
- ✅ **Configurable email indicators**: Customize required indicators (`--require-indicators`)
- ✅ **Performance tuning**: Choose which checks to perform (`--email-checks`)
- ✅ **DNS retry configuration**: `--max-dns-retries` parameter

### New CLI Arguments
```bash
--max-dns-retries N                      # DNS retries per server (default: 3)
--require-indicators HAS_MX HAS_SPF      # Required indicators for email domain
--email-checks HAS_MX HAS_SPF            # Which indicators to check
--disable-ptr-blacklist                  # Disable PTR from IPs (ENABLED by default)
--disable-update-ptr-blacklist           # Disable PTR CSV auto-update
--ptr-blacklist-pool-size N              # Parallel PTR lookups (default: 20)
```

### PTR Blacklist Feature

The tool can detect dangerous `ptr` mechanisms in SPF records. PTR domains are collected from **two sources**:

#### 1. Automatic Extraction from SPF Trees (ALWAYS ENABLED - Fast, No DNS)

When resolving dangerous includes, PTR domains from their SPF records are automatically extracted:
- Example: `mx.ovh.com` has SPF `ptr:mail-out.ovh.net ptr:mail.ovh.net`
- Result: Both domains automatically added to blacklist
- **No DNS lookups required** - just parsing SPF records already fetched
- **Always active** - cannot be disabled (it's fast and free)

#### 2. Reverse DNS Lookup of Dangerous IPs (ENABLED BY DEFAULT - Expensive)

- Performs PTR lookups on all dangerous IP ranges via reverse DNS
- Takes 5-10 minutes depending on number of IPs
- Results cached in `./data/Dangerous_SPF_PTR_Records.csv`
- **Enabled by default** on first run
- **Can be disabled** with `--disable-ptr-blacklist`

**Default Behavior (First Run):**

```bash
# PTR blacklist is ENABLED by default
python cli.py --check-spf-records domains.csv

# This will:
# 1. Extract PTR from dangerous includes SPF (always)
# 2. Load CSV if exists, otherwise build from IPs (5-10 min on first run)
# 3. Save results to CSV for next time
```

**Disable Expensive PTR Lookups:**

```bash
# Disable reverse DNS lookups (only use SPF tree extraction)
python cli.py --check-spf-records domains.csv --disable-ptr-blacklist

# Disable auto-update (use existing CSV only)
python cli.py --check-spf-records domains.csv --disable-update-ptr-blacklist
```

**Python API:**

```python
from lib.data.loaders import DataLoaders

# DEFAULT: PTR blacklist enabled (builds from IPs if CSV missing)
loaders = DataLoaders()
loaders.load_all()

# Disable PTR blacklist from IPs (only SPF tree extraction)
loaders = DataLoaders(disable_ptr_blacklist=True)
loaders.load_all()

# Disable auto-update (use existing CSV only, don't rebuild)
loaders = DataLoaders(disable_update_ptr_blacklist=True)
loaders.load_all()

# Disable both (only SPF tree extraction, no CSV)
loaders = DataLoaders(disable_ptr_blacklist=True, disable_update_ptr_blacklist=True)
loaders.load_all()

# Check if PTR domain is dangerous
matches = loaders.find_dangerous_ptr_domain("mail-out.ovh.net")
for match in matches:
    print(f"PTR: {match.ptr_domain}")
    print(f"Service: {match.service_name} ({match.service_type})")
```

---

**Version:** 0.0.3 **Last Updated:** 2025-12-17
