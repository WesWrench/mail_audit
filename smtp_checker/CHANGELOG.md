# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.11.0] - 2026-10-29

### Added

- **Open relay test depth** — `open_relay_mode` (`SMTPChecker`, `DomainChecker`,
  `scan_domains_async`) and CLI `--open-relay-mode {rcpt,data}`. `rcpt` (default, unchanged
  behaviour) stops after `RCPT TO` like MXToolbox; `data` also sends `DATA`, expects `354`,
  then drops the connection without sending any content (no body, no final `.`) like
  Nessus — nothing is relayed. Result gains `mode` and, in `data` mode, `data_code`; a
  `DATA` refusal after an accepted `RCPT TO` is reported `OK` (relay not confirmed).

### Changed

- **Excel export (domain mode) reorganised around the MX server.** *SMTP Tests* and *DANE*
  were repeated for every domain sharing an MX (e.g. 14 domains × 10 tests = 140 identical
  rows for one MX). They are now one row per (MX host, test) / per MX host, with
  **Email Domain Count** and **Email Domains** listing the domains whose MX points to it.
  Rows are merged only when results are identical.
- Sheet *Domains* renamed **Summary**, with roll-up columns (TLS-RPT present, DANE on
  all MX, open relay MX, worst SMTP status). MTA-STS details moved to a new **MTA-STS**
  sheet: DNS record, policy id / mode / max_age / mx patterns, and the MX hosts **not
  covered** by the policy.
- The exporter moved to `lib/excel_export.py` (`export_domain_results_to_excel`, exported
  by `lib`). mail_audit uses it instead of its own copy. JSON output unchanged.
- `lib.__version__` was still `2.0.0`: now `2.11.0`.

- **`target_type`** (`DomainChecker`, `scan_domains_async`, CLI `--target-type
  {auto,domain,mx_hostname}`). `auto` (default, unchanged) audits a target without MX as
  an MX hostname, so an email domain without MX showed up in *SMTP Tests* as its own mail
  server with a "DNS resolution failed" error. `domain` audits it as a domain and says why
  it has no MX row in the new report field **`mx_status`** (`mx` / `implicit_mx` (RFC 5321
  A/AAAA fallback, tested) / `no_mx` / `nxdomain` / `error` / `mx_hostname`), shown as
  **MX Status** in the Summary sheet.

### Fixed

- **A DNS timeout turned a domain into an "MX hostname" target.** `_has_mx_records`
  returned False on any exception, so a transient timeout / SERVFAIL on the MX query made
  `DomainChecker` audit the domain as its own mail server (no DNSSEC / MTA-STS / TLS-RPT,
  `mx_hosts = [domain]`). Seen on `example.com` in a full run. Only NXDOMAIN / no MX
  record now mean "not a domain"; timeouts are retried (3 attempts) and a persistent
  failure is audited as a domain with an error `{"stage": "target_type", ...}`.
- **CLI crash on Windows when output is redirected** — `--help` (and any non-ASCII output)
  raised `UnicodeEncodeError` with the cp1252 console encoding; stdout/stderr now replace
  unencodable characters.

### Fixed

- **Open relay never raised the `smtp_open_relay` issue** — the test reports an accepted
  external `RCPT TO` as `WARNING`, but the issue rule (and mail_audit's Excel) checked for
  `FAIL`, a status the checker never produces. Both statuses are now accepted.

---

## [2.10.1] - 2026-04-15

### Fixed

- **`test_smtp_open_relay`** — `SMTPServerDisconnected` during the relay test
  now returns `status: "OK"` / `ok: True` instead of `status: "PROBLEM"` /
  `ok: False`.

  A server that drops the connection when it receives `MAIL FROM` or `RCPT TO`
  for an external address is **refusing** the relay attempt — this is a common
  defensive behaviour in MTAs (Postfix, Sendmail, Exchange…) that cut the
  session rather than responding with a 5xx code.  Treating it as `"PROBLEM"`
  was a false positive that incorrectly flagged compliant servers as potential
  open relays.

  The new details message explicitly states that no open relay was confirmed
  and explains the server behaviour.

---

## [2.10.0] - 2026-04-15

### Added

#### Per-domain progress output in domain mode CLI

- **Sync mode**: each domain now prints `[i/n] domain... done (N MX)` as it
  completes instead of running silently until the end.
- **Async mode**: new `_run_domain_batch_async()` helper replaces the
  single-checker call — each domain runs in its own thread via
  `asyncio.to_thread`, and `[i/n] domain done (N MX)` is printed on
  completion in arrival order.  Concurrency is still capped by `--max-smtp`.
- Errors per domain are caught and printed inline (`error: <reason>`) rather
  than crashing the whole batch.

#### `--convert-json` flag — convert existing JSON to Excel without re-scanning

```bash
python cli.py --convert-json report.json -o report.xlsx
```

- Loads a JSON result file produced by a previous scan and exports it to Excel.
- `-i` is not required when `--convert-json` is used.
- Auto-detects smtp vs domain format from the result structure
  (`mx_results` / `dnssec` keys → domain mode Excel; otherwise smtp mode Excel).
- Validates that `-o` has an `.xlsx` extension and that the source file exists.

### Changed

- `-i / --input` is now `required=False` — the CLI validates it at runtime
  and raises a clear error if it is missing when `--convert-json` is not set.
- `-o / --output` help text now explicitly states that the file extension
  determines the output format (`.json` → JSON, `.xlsx` → Excel).
- README CLI section updated: format-by-extension rule documented,
  `--convert-json` example added, `--convert-json` row added to the CLI
  reference table.

---

## [2.9.0] - 2026-04-01

### Changed

#### Issue codes migrated from integers to string slugs (`lib/data/issue_definitions.csv` + `lib/domain_checker.py`)

- `issue_definitions.csv` `issue_code` column changed from integers to globally-unique string slugs.
  The slug is now the primary key — no integer-to-slug translation table is needed.

  | Old integer | New slug |
  |---|---|
  | `2`  | `smtp_connection_failure` |
  | `3`  | `smtp_banner_mismatch` |
  | `4`  | `smtp_open_relay` |
  | `5`  | `smtp_no_starttls` |
  | `6`  | `tls_cert_invalid` |
  | `7`  | `tls_cert_expiring_soon` |
  | `8`  | `smtp_rdns_mismatch` |
  | `9`  | `mta_sts_missing` |
  | `10` | `mta_sts_non_enforce` |
  | `11` | `dane_no_tlsa` |
  | `12` | `tlsa_no_dnssec` |

- `_ISSUE_DEFS` dict key type changed from `int` to `str` (slug).
- `_load_issue_definitions()` reads `issue_code` as a plain string — no `int()` conversion.
- `_make_issue(code: str, ...)` updated signature.
- `_collect_domain_issues()` uses `"mta_sts_missing"` / `"mta_sts_non_enforce"`.
- `_collect_mx_issues()` uses all SMTP+DANE slugs in place of integers.

### Added

- `get_issue_definitions() -> dict[str, dict]` — module-level function (also exported
  from `lib/__init__.py`) that returns a copy of all smtp_checker issue definitions
  keyed by slug.  Intended for external consumers (e.g. `mail_audit`) that need to
  enumerate smtp_checker issue codes without hard-coding them.

---

## [2.8.0] - 2026-04-01

### Added

#### Structured issue codes (`lib/data/issue_definitions.csv` + `lib/domain_checker.py`)
- New `lib/data/issue_definitions.csv` declares all smtp_checker issue codes
  with fields `issue_code`, `issue_title`, `category`, `default_severity`, `description`.
- `_load_issue_definitions()` — module-level loader (CSV parsed once at import time).
- `_make_issue(code, **extra)` — builds an issue dict from the registry.
- `_collect_domain_issues(mta_sts)` — maps MTA-STS result to domain-level issues:
  - Code `9`: MTA-STS policy absent or invalid (severity: high)
  - Code `10`: MTA-STS policy not in enforce mode (severity: medium)
- `_collect_mx_issues(smtp_tests, dane)` — maps per-MX results to issue codes:
  - Code `2`: SMTP connection failure
  - Code `3`: SMTP banner mismatch
  - Code `4`: SMTP open relay (status == FAIL)
  - Code `5`: STARTTLS not advertised
  - Code `6`: TLS certificate invalid
  - Code `8`: Reverse DNS mismatch
  - Code `11`: No TLSA (DANE) records for MX host
  - Code `12`: TLSA records without DNSSEC

### Changed
- `DomainChecker.run_all_tests()` now includes:
  - `report["issues"]` — domain-level issues list (MTA-STS codes 9/10)
  - `mx_entry["issues"]` — per-MX issues list (SMTP + DANE codes)
  - Each issue dict: `{"code", "title", "category", "severity"}`
- `run_all_tests()` docstring updated to document the new `issues` fields.

---

## [2.7.0] - 2026-03-24

### Changed

- **`DomainChecker` — `mx_hostname` mode** (`lib/domain_checker.py`): `report["dnssec"]`
  is now `null` instead of checking the MX hostname's own DNS zone.  The MX hostname's
  zone DNSSEC is not the email domain DNSSEC and was meaningless in this context.
  `mta_sts`, `mta_sts_dns`, and `smtp_tls_rpt_dns` were already `null` — this aligns
  `dnssec` with the same principle.

- **`verify_mx_dane()` — `dane_usable_reason`** (`lib/dane.py`): new field in the DANE
  result dict that identifies the first failing condition when `dane_usable` is `false`:
  - `"parent_domain_unknown"` — called from `mx_hostname` mode (no email domain)
  - `"parent_domain_dnssec_invalid"` — domain zone DNSSEC not valid
  - `"mx_host_dnssec_invalid"` — MX hostname zone DNSSEC not valid
  - `"tlsa_dnssec_invalid"` — TLSA zone DNSSEC not valid
  - `"no_tlsa_records"` — no TLSA records at `_25._tcp.<mx>`
  - `"cert_hash_mismatch"` — TLSA records exist but none match the cert
  - `null` when `dane_usable` is `true`

### Fixed

- **`verify_mx_dane()` — redundant DNS query** (`lib/dane.py`): `mx_dnssec` and
  `address_lookup.dnssec` were calling `check_dnssec_chain(hostname)` twice for the
  same hostname.  The result is now computed once and shared between both fields.

---

## [2.6.0] - 2026-03-24

### Changed

- **`check_dnssec_chain()` — proper full-chain DNSSEC validation** (`lib/dane.py`):
  replaced the single-level DS↔DNSKEY check with a two-stage strategy:
  1. **AD bit (primary)** — queries DNSKEY with the DNSSEC-OK (DO) flag set
     and checks whether the recursive resolver (1.1.1.1 / 8.8.8.8) sets the
     AD (Authenticated Data) flag in the response.  If set, the resolver has
     already verified the full cryptographic chain to the ICANN root trust
     anchor.
  2. **Chain walk (fallback)** — if the AD bit is absent, walks every zone
     level from the root (".") down to the target zone:
     - Root ".": verifies a DNSKEY key-tag matches a hardcoded root trust
       anchor (key tags 19036 / 20326 per RFC 7958).
     - Each subsequent level: recomputes `dns.dnssec.make_ds()` and compares
       against the DS record in the parent zone (key_tag, algorithm,
       digest_type, digest must all match).
  - New output field `validation_method`: `"ad_bit"` or `"chain_walk"`.
  - New helper `_build_zone_chain(zone)` returns the ordered list of zones
    from root to the target (e.g. `[".", "com.", "flex-led.com."]`).
  - Root trust anchor constants extracted to `_ROOT_TRUST_ANCHOR_TAGS`.
  - `dns.dnssec.key_tag()` replaced by `make_ds(...).key_tag` for root key-tag
    extraction — more reliable across all dnspython 2.x versions.

### Fixed

- **`matched_ds` serialization** — `algorithm` and `digest_type` are returned
  as `int` (via `int(ds.algorithm)`) rather than dnspython enum objects, which
  would cause `json.dumps()` to raise a `TypeError` in newer dnspython versions.

---

## [2.5.0] - 2026-03-24

### Changed

- **Package renamed** — `smtp_checker/` directory renamed to `lib/`.
  All imports change from `from smtp_checker import ...` to `from lib import ...`.
  This is in preparation for renaming the parent project folder to `smtp_checker`.
  No API changes; all public classes and functions remain identical.

---

## [2.4.0] - 2026-03-23

### Added

- **Concurrency limits for async scanning** — `scan_domains_async()`,
  `DomainChecker.run_all_tests_async()` (list mode), and `SMTPChecker.run_all_tests_async()`
  (list mode) now accept concurrency-control parameters:
  - `max_smtp: int = 10` — `asyncio.Semaphore` capping how many domain scans (= SMTP
    connections) run simultaneously.  ``0`` disables the limit.
  - `max_dns: int = 50` — `threading.Semaphore` capping how many `dns.resolver` calls
    run simultaneously across all threads.  ``0`` disables the limit.
    DNS queries made internally by checkdmarc are not subject to this limit.
  - `max_smtp: int = 10` in `SMTPChecker.run_all_tests_async()` only (no DNS limit
    since SMTPChecker does not perform DNSSEC lookups).
  - Both semaphores are created once per batch and shared across all concurrent
    checker instances, giving a true global cap rather than a per-instance cap.

- **`cli.py` — `--max-smtp` / `--max-dns`** flags expose the concurrency limits
  from the command line (async mode only; both default to 10 / 50).

- **`dane.py`** — internal `_dns_sem` parameter added to `resolve_records()`,
  `check_dnssec_chain()`, and `verify_mx_dane()` for threading-safe DNS throttling.

---

## [2.3.0] - 2026-03-23

### Added

- **`SMTPChecker` — batch input**: `target` now accepts `Union[str, List[str]]`.
  - Single string → `run_all_tests()` returns a `dict` (unchanged, backward compatible).
  - List of strings → `run_all_tests()` returns a `list` of dicts, scanned sequentially.
  - New `run_all_tests_async()` method: single target runs in a thread pool; list of
    targets scans all concurrently via `asyncio.gather`.

- **`DomainChecker` — batch input**: same `Union[str, List[str]]` pattern.
  - Single string → `run_all_tests()` / `run_all_tests_async()` return a dict (unchanged).
  - List of strings → `run_all_tests()` returns a list of dicts (sequential);
    `run_all_tests_async()` scans all concurrently.
  - `scan_domains_async()` remains available as a module-level shorthand.

---

## [2.2.0] - 2026-03-23

### Added

- **`cli.py` — `--mode domain`**: `DomainChecker` is now fully accessible from the CLI.
  Pass `--mode domain` to run a full domain audit (DNSSEC, DANE, MTA-STS, TLS-RPT, TLS cert)
  instead of a raw SMTP check. Accepts domain names or MX hostnames, same as the library.

- **`cli.py` — `--async-mode` / `--sync-mode`**: both modes (`smtp` and `domain`) support
  concurrent scanning. `--sync-mode` is the default (sequential, same behaviour as before).
  `--async-mode` runs all targets concurrently — `asyncio.gather` for domain mode,
  `asyncio.to_thread` pool for smtp mode.

- **`cli.py` — `--dns-timeout`**: DNS query timeout in seconds, forwarded to `DomainChecker`
  (domain mode only, default 5.0).

- **`cli.py` — `--nameservers`**: comma-separated list of DNS resolver IPs forwarded to
  `DomainChecker` (domain mode only, default `1.1.1.1,8.8.8.8`).

- **`cli.py` — Excel export for domain mode** (`export_domain_to_excel`): produces a
  three-sheet workbook:
  - **Domains** — one row per target: DNSSEC, MTA-STS, TLS-RPT summary.
  - **SMTP Tests** — one row per SMTP test per MX host, including TLS certificate columns
    (subject, issuer, expiry, days left, self-signed, hostname match, CA valid, CA error).
  - **DANE** — one row per MX host: MX DNSSEC, TLSA DNSSEC, TLSA records, cert retrieved,
    dane_valid, dane_usable.

### Changed

- `cli.py` default open relay sender/recipient removed — the test is now skipped unless
  `--sender` and `--recipient` are explicitly provided (consistent with library behaviour).

---

## [2.1.0] - 2026-03-23

### Fixed

- **Self-signed certificate detection** (`test_smtp_tls_cert_check`): replaced the naive
  `issuer == subject` heuristic with a proper cryptographic check.
  A certificate is now considered self-signed only when **both** conditions hold:
  1. The issuer DN equals the subject DN.
  2. The certificate's signature is verifiable with the public key embedded in the same
     certificate (`cert.verify_directly_issued_by(cert)` on cryptography ≥ 42; manual
     `pub.verify(signature, tbs_bytes, ...)` fallback for RSA/EC on older versions).
  A certificate where `issuer == subject` by coincidence (e.g. a mis-issued intermediate)
  is no longer incorrectly flagged as self-signed.

- **CA chain validation on Windows** (`fetch_smtp_cert_der`, `verify=True`): Python's
  bundled OpenSSL on Windows does not use the Windows certificate store and may lack
  ISRG Root X1 (Let's Encrypt's root CA). The fix loads the `certifi` CA bundle when
  available, guaranteeing an up-to-date Mozilla root store regardless of platform.
  `certifi` is now listed in `requirements.txt`.

### Added

- `certifi>=2024.0.0` to `requirements.txt`.

---

## [2.0.0] - 2026-03-23

### Added

- **`lib/dane.py`** — New module with standalone DNSSEC / DANE / MTA-STS functions:
  - `check_dnssec_chain()` — full DS ↔ DNSKEY cryptographic chain validation using `dns.resolver` directly (no dependency on `checkdmarc.dnssec.get_dnskey()`).
  - `verify_mx_dane()` — DANE SMTP verification (TLSA record retrieval + cert hash match + DNSSEC chain). Accepts an optional `cert_der` parameter to reuse a pre-captured certificate and avoid a second SMTP connection.
  - `fetch_smtp_cert_der()` — STARTTLS certificate retrieval with configurable `verify` flag (`CERT_NONE` by default for DANE use cases).
  - `compute_tlsa_hash()` — TLSA selector/matching-type hash computation.
  - `check_mta_sts()` — MTA-STS policy check via checkdmarc.
  - `get_mx_hostnames()` — MX hostname resolution via checkdmarc.
  - `resolve_records()` — Generic DNS record resolver.

- **`lib/domain_checker.py`** — New `DomainChecker` class:
  - Accepts a **domain name** or an **MX hostname** as input (auto-detected via MX record lookup).
  - In **domain mode**: resolves MX hosts and runs SMTP tests + DANE + MTA-STS + TLS-RPT + DNSSEC for the domain.
  - In **mx_hostname mode**: runs SMTP tests + DANE on the target directly.
  - **Certificate reuse**: enables `smtp_starttls_cert` on `SMTPChecker` and passes the captured DER cert to `verify_mx_dane()`, avoiding a redundant SMTP connection.
  - `run_all_tests()` — synchronous audit, returns a combined report dict.
  - `run_all_tests_async()` — async wrapper using `asyncio.to_thread`.
  - `scan_domains_async()` — module-level helper for concurrent bulk scanning via `asyncio.gather`.

- **`lib/checker.py`**:
  - New attribute `tls_cert_der: Optional[bytes]` — stores the DER-encoded server certificate after STARTTLS. Persists after `close()` so `DomainChecker` can read it.
  - New test `test_smtp_starttls_cert()` (Test 13) — performs actual STARTTLS negotiation using `CERT_NONE`, captures the certificate, stores it in `self.tls_cert_der`. Runs **last** to avoid disrupting prior plain-text SMTP tests.
  - New test `test_smtp_tls_cert_check()` (Test 14) — full TLS certificate inspection:
    - **Hostname match** — checks Subject Alternative Names (dNSName + IP entries) with wildcard support, falls back to CN. Reports which SANs are present.
    - **Self-signed detection** — cryptographic check: `issuer == subject` AND signature validates against own public key.
    - **Expiry** — PROBLEM if < 14 days or already expired; WARNING if < 30 days. Includes days remaining.
    - **CA chain validation** — opens one additional STARTTLS connection with `ssl.create_default_context()` + certifi bundle. Detects missing intermediates, expired roots, and untrusted CAs.
    - **AIA issuer URL** — extracted from the Authority Information Access extension; included in error messages to help diagnose missing intermediate certificates.
    - **Human-readable SSL error translation** — raw OpenSSL error strings mapped to actionable messages (incomplete chain, self-signed, expired, hostname mismatch, untrusted CA).

- **`lib/config.py`**:
  - New option `smtp_starttls_cert: False` — disabled by default; auto-enabled by `DomainChecker`.
  - New option `smtp_tls_cert_check: False` — disabled by default; auto-enabled by `DomainChecker`.

- **`lib/__init__.py`**:
  - Exports `DomainChecker` and `scan_domains_async`.

- **`requirements.txt`**:
  - Added `checkdmarc>=5.0.0` and `cryptography>=41.0.0`.

- **`README.md`** — Rewritten to cover v2 features.
- **`CHANGELOG.md`** — This file.
- **`TODOLIST.md`** — Future work tracker.

### Fixed

- **DNSSEC chain detection** (`test.py` → `check_dnssec_chain`): replaced `checkdmarc.dnssec.get_dnskey()` call (whose return format was unparseable in practice) with a direct `dns.resolver.resolve(zone, "DNSKEY")` call. This fix makes DNSSEC correctly report `valid=True` for `flex-led.com` and `valid=False` for `granier.be`.

### Changed

- `SMTPChecker` is fully backward-compatible. No breaking changes for existing `v1` code.

---

## [1.0.0] - Initial release

- `SMTPChecker` class with 12 SMTP diagnostic tests.
- `cli.py` CLI with JSON and Excel export.
- Batch scanning from file.
