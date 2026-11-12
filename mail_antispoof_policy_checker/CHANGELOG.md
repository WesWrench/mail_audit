# CHANGELOG — Mail AntiSpoof Policy Checker

## [Unreleased]

### Changed

- **Requires `checkdmarc>=6.0.4,<7`** (RFC 9989 / DMARCbis). checkdmarc 5.13+ renamed
  `timeout_retries` to `retries`: with a fresh install, `parse_spf_record` raised a
  `TypeError` that was silently caught, so SPF fell back to basic parsing (no recursive
  include analysis). Calls now pass `retries=`.
- **DMARC parsing relies on checkdmarc 6 only.** The strip-and-reparse workaround for `np=`
  (`_reparse_tolerating_tags`, `_strip_dmarc_tags`, `_apply_native_tags`) is removed:
  checkdmarc 6 supports `np`, `psd` and `t`, and ignores unknown tags. The inherited
  subdomain policy (RFC 9091) now uses checkdmarc's resolved `sp` / `np` values and its
  `explicit` flags instead of re-tokenising the record.

### Added

- **DKIM RSA key checks** (`lib/utils/rsa_key_checks.py`): the public exponent is rated
  (`dkim_rsa_dangerous_exponent`: `e=1` critical, `e=3` high; `dkim_rsa_nonstandard_exponent`:
  legacy `3 < e < 65537` / `e >= 2^256` low, invalid even or `< 3` medium), and
  `dkim_rsa_known_factorization` (critical) is raised when anyone can compute the private key:
  small prime factor (< 2^16) or prime modulus (offline), or factorization published on
  factordb.com. `n` and `e` are read from the DER directly, so keys `cryptography` refuses to
  load (`e=1`) are rated instead of reported as syntax errors.
- **factordb.com client** (`lib/utils/factordb.py`): reads the search page (not the throttled
  API; reading stores nothing), verifies every factor locally (`n mod p = 0`), follows the
  site's limits (own User-Agent, one request at a time, 0.5 s interval, stops after HTTP 429),
  caches per modulus. Keeps factordb's information box ("Interesting number. ...", e.g. Logjam
  DH prime, RSA challenge) in `notes`; queried even after an offline finding to get it.
  `DKIMChecker(factordb=...)`, CLI `--skip-factordb-check`. Selectors gain `rsa_exponent` and
  `factordb` (`status`, `url`, `notes`, `factor_digits`) in the JSON output.
- **`dmarc_partial_coverage` severity by `pct` range and policy** (`DMARC_PCT_SEVERITY`):
  `p=quarantine` high (0–35) / medium (36–65) / low (66–99); `p=reject` medium (0–35) /
  low (36–99); `p=none` low. `additional_data` gains `escape_rate`, `pct_range`, `policy`,
  `fallback_policy`.
- **`dmarc_testing_mode`** issue for `t=y` (RFC 9989 test mode) on `p=reject` (medium) or
  `p=quarantine` (high). `DMARCResult` gains `testing` and `psd`.

### Fixed

- **`pct` < 100 reported again.** RFC 9989 removed `pct`, so checkdmarc 5.17+/6 drops it from
  the parsed tags and `dmarc_partial_coverage` was never raised. `pct` is now read from the
  raw record: receivers implementing RFC 7489 still apply it.
- **`p=none` no longer reported twice.** checkdmarc fills an implicit `sp` (= `p`), which
  also raised `dmarc_lax_subdomain_policy`. That issue now requires a published `sp=`.
- `InvalidDMARCReportURI` was unreachable (caught as its parent `InvalidDMARCTagValue`).
  Tag/value extraction follows checkdmarc 6 error messages.

## [2.2.0] - 2026-10-29

### Changed (breaking)

- **`--dns-server` renamed to `--nameservers`, now a comma-separated LIST of
  resolver IPs** (e.g. `1.1.1.1,8.8.8.8`), matching the SMTP checker's flag. The
  Python API changed accordingly: `DNSUtils`, `SPFChecker`, `DMARCChecker`,
  `DKIMChecker`, `DataLoaders` and `EmailDomainChecker` now take
  `nameservers: list[str]` instead of `dns_server: str` (a bare string is still
  tolerated for convenience). The old `--dns-server` flag no longer exists.

### Fixed

#### DMARC records with `np=` (RFC 9091) — and any unknown tag — no longer void the parse

`checkdmarc` (through 5.12.27) rejects the RFC 9091 `np=` tag with `InvalidDMARCTag`, and our
wrapper discarded the **entire** record on that exception — a record such as
`v=DMARC1; p=reject; sp=quarantine; np=none; aspf=r` was reported as `policy=None`,
`alignment_spf=None`, `subdomain_policy=None`, i.e. as if the domain had no usable policy.
This mis-scored real domains (e.g. a `p=reject` domain looked unprotected) and understated the
`mail_audit` relaxed-alignment cross-domain severity.

Now the `InvalidDMARCTag` handler, when the refused tag is a **recognised** DMARC tag (RFC 7489
+ RFC 9091 — `np` in particular), strips that tag, re-parses the remainder with `checkdmarc`
(keeping its full validation of the standard tags), and re-applies the stripped tag's value
natively (`_reparse_tolerating_tags` / `_apply_native_tags`). A genuinely unknown/garbage tag
still populates the core fields via a hardened native parser and is reported. The native parser
(`_process_basic_dmarc`, used as the ultimate fallback) was rewritten to be RFC 7489 §6.3
compliant: case-insensitive tag names, lower-cased enum values, **unknown tags ignored**, `sp`
defaults to `p`, and `np` (RFC 9091) parsed and defaulted to the effective `sp`. New
`np_policy` field on `DMARCResult` (and its `to_dict`). No behavior change for records without
`np=` / unknown tags.

#### Subdomain policy inheritance is now RFC 9091-correct (`np` for non-existent subdomains)

When a subdomain has no own `_dmarc` record, the policy inherited from the organizational
domain now depends on whether the subdomain **exists**: an **existing** subdomain inherits
`sp=` (then `p=`, unchanged); a **non-existent** subdomain (NXDOMAIN) inherits **`np=`** (then
`sp=`, then `p=`). `check()` resolves existence only in the inherited branch, via a single
classified `A` query — only a definitive **NXDOMAIN** is treated as non-existent (NODATA, an
answer, or any indeterminate/timeout result is not, so a policy is never wrongly relaxed on
uncertainty). This prevents a **false "spoofable" finding**: a domain with `sp=none` but
`np=reject` is correctly **enforcing** for a spoof whose From is one of its non-existent
subdomains. `_apply_inherited_policy` gained an `is_nonexistent` parameter (default `False`, so
callers and tests are unaffected).

### Added

#### Organizational-domain helpers & org-parent DMARC (relaxed-alignment awareness)

New `lib/utils/org_domains.py`, re-exported from `lib`: `organizational_domain(domain)`
(PSL / `tldextract`, with a last-two-labels fallback), `is_subdomain(domain)` and
`derive_org_parents(domains)` (the organizational parents of a list that are not already in
it, deduplicated, order-stable). `DMARCChecker._organizational_domain` now delegates to the
shared helper (single source of truth).

The **CLI** now adds, when `dmarc` is among the check types, each input subdomain's
organizational (registrable) parent as a **DMARC-only** target (deduplicated; a parent
already listed is not re-added). Rationale: DMARC is evaluated against the From-header domain
with **relaxed** alignment by default, and for a subdomain the policy jumps **directly** to
the organizational domain — so the parent's own DMARC is what governs a `From:@<parent>`
spoof mounted from a weak subdomain. Only the parent's DMARC is fetched (not its SPF/DKIM —
the leverage is the subdomain's); the entry is marked `org_parent_dmarc_only: true`.
`mail_audit` consumes this to raise its *relaxed-alignment cross-domain spoofing* scenario.

#### CNAME chain check on DKIM / DMARC / SPF lookup names

New complementary control detecting obsolete or broken CNAME aliases at the names
where receivers look up authentication records: `<selector>._domainkey.<domain>`
(every selector tested by the enumeration), `_dmarc.<domain>` and `<domain>` itself
(alias only — SPF `include:` / `redirect=` targets stay with the existing, unchanged
"Unregistered Domains in SPF" control).

- `DNSUtils.query_classified()` returns a classified outcome (`NOERROR`, `NODATA`,
  `NXDOMAIN`, `SERVFAIL`, `REFUSED`, `TIMEOUT`, `ERROR`) **and keeps the CNAME links of
  the answer section, including on NXDOMAIN** — so "source absent" is never confused
  with "alias present, target absent", at no extra query cost.
- `lib/utils/cname_chain.py` — hop-by-hop walk (`qtype=CNAME`) with per-hop status, loop
  detection and maximum depth, then TXT lookup at the final target. Absence of A/AAAA is
  never a failure.
- `lib/checkers/cname_checker.py` — classification of the chain (`ok`,
  `broken_reference`, `missing_record`, `resolution_loop`, `max_depth_exceeded`,
  `indeterminate`), recorded as **evidence only** (no issue on its own). SERVFAIL /
  TIMEOUT / REFUSED stay indeterminate. An alias observed in a TXT answer is kept even if
  the hop-by-hop walk fails.
- **DKIM wildcard control**: 3+ random siblings `random-<uuid>.<parent>` per selector
  parent; identical CNAME chains → `wildcard_probable`. Selectors are grouped into one
  issue, not dropped. A CNAME on the parent is not treated as a wildcard; multi-label
  selectors are probed at their own parent.
- **Registration state** of broken targets: registrable domain from the Public Suffix
  List (tldextract), ICANN vs private (hosted) suffix, reserved / special-use names
  (`.invalid`, `.test`, `example.com`…) reported as `reserved` (not buyable → no issue).
  NXDOMAIN alone never means "available".
- **Issues = takeover risk only**: 6 slugs
  `<spf|dmarc|dkim>_cname_target_unregistered` (critical) and
  `<spf|dmarc|dkim>_cname_target_potentially_unregistered` (high), raised when the
  target's registrable domain is (potentially) unregistered — whoever buys it controls the
  SPF / DMARC / DKIM TXT seen through the alias.
- `cname_checks` list in `SPFResult` / `DMARCResult` / `DKIMResult` (`to_dict()`), with
  chain, hops, failing target, DNS status, wildcard assessment, registrable domain,
  registration state + source, anomaly, confidence and evidence.
- Excel: takeover issues show **CNAME Chain** / **Domain To Buy** columns in the SPF / DMARC /
  DKIM Issues sheets (no separate CNAME sheet; full evidence stays in the JSON).
- CLI: `--skip-cname-check`, `--cname-max-depth N` (default 10),
  `--cname-wildcard-probes N` (default/min 3).

#### Custom DKIM selector list — `--dkim-selector-file FILE`

The CLI can now take a custom selector list that **replaces** the bundled
`<data-dir>/DKIM_Selectors.txt` (previously the CLI always used the checker default
`./data/DKIM_Selectors.txt`). The file is validated at start-up (missing / empty →
error) and the number of selectors loaded is printed. Selector files accept `#` comments;
duplicates are removed (`DKIMChecker.load_selector_file()`).

#### DKIM: `Perfectible DKIM key size` (`dkim_perfectible_key`, low)

Keys of **exactly 1024 bits** now raise a low-severity issue (RFC 8301 minimum, 2048
recommended). `dkim_weak_key` (< 1024, high) is unchanged; both now carry
`additional_data = {selector, key_size}`.

#### Excel: `DKIM Issues` sheet

DKIM issues were only counted in the Summary sheet. New **DKIM Issues** sheet (CLI report
and `--convert-json-report-to-excel`) with Selector / Key Size / Detail columns.

### Fixed

- **DKIM key type now honoured.** Size thresholds were applied to any key the parser could
  read, and `k=` was never compared with `p=`. The scan and `check_record()` now share one
  check (`DKIMChecker._check_key`): `k=` is read first (default `rsa`), and the 1024-bit
  thresholds apply to RSA keys only.
  - A valid Ed25519 key (raw 32 bytes, RFC 8463) no longer raises `dkim_syntax_error` in
    `check_record()`. Its key size is reported as 256.
  - An EC key is no longer reported as a weak key: it is a `dkim_syntax_error`.
  - An RSA key under `k=ed25519`, a DER-wrapped Ed25519 key, an unknown `k=` value and an
    unreadable key now raise `dkim_syntax_error` in the scan too (previously silent, or
    reported as a size problem).
- **MaxMind database download race** — in async mode every concurrent SPF check started its
  own update, all writing `./<db>.tar.gz` in the *current directory*: `PermissionError`
  (WinError 32) or truncated archives (`EOFError`) made the SPF check fail for those
  domains. Updates now run once per `MaxMindClient` under a shared lock, download to a
  unique temp file inside `utils/maxmind/`, and the update date is only recorded when the
  download and extraction succeed.
- **CLI crash on Windows when output is redirected** — non-ASCII characters raised
  `UnicodeEncodeError` (cp1252); stdout/stderr now replace unencodable characters.
- **Domain availability without the service checker** — deleting
  `lib/domain/domain_availability_service_checker/` made `DomainAvailabilityChecker()`
  raise at construction, so the whole registration check (SPF includes + CNAME targets)
  was skipped. Stage 3 is now optional: NS and WHOIS/RDAP still decide, undecided domains
  end as `unknown` (→ *potentially unregistered*).
- **DMARC on subdomains without their own `_dmarc` record**: the organizational domain
  was the last two labels (`news.exemple.co.uk` → `co.uk`) and the org's `p=` was applied
  instead of `sp=`. A subdomain under `p=reject; sp=none` was reported as protected (no
  `dmarc_lax_policy`), and the reverse for `p=none; sp=reject`. Now: PSL-based
  organizational domain, effective policy = `sp=` else `p=`, lax issue recomputed on it;
  new `policy_inherited_from` / `organizational_policy` fields.
- `DKIM Records` sheet: the `DKIM Record` column was always empty —
  `DKIMSelectorInfo` now stores the raw record and exports it as `dkim_record`.

### Changed

- **Breaking: DKIM key issue codes renamed**, since they only concern RSA keys:
  `dkim_weak_key` → `dkim_rsa_weak_key` ("Weak DKIM RSA key size") and
  `dkim_perfectible_key` → `dkim_rsa_perfectible_key` ("Perfectible DKIM RSA key size").
  Update any consumer of the JSON output. Python: `create_dkim_rsa_weak_key()`,
  `create_dkim_rsa_perfectible_key()`, `DKIMChecker._rsa_key_size_issue()`;
  `_get_key_size()` is replaced by `_inspect_key()`.
- Excel: **Key Type** column in the DKIM Records sheet.
- SPF include availability: the end-of-run logic of `cli.py` moved to
  `collect_spf_include_sources()` / `apply_spf_include_availability()` (same behaviour,
  same output) so that `mail_audit` can run it too. README: the *Unregistered domain in
  SPF* rows now show the real codes and severities (critical / high, not "Medium").
- **One bulk availability call** — `check_domains_availability()` (returns status +
  deciding stage) now feeds both the SPF include control and the CNAME targets;
  `check_spf_includes_availability()` is kept as a backward-compatible wrapper. The SPF
  include issue logic is unchanged. `--skip-domain-availability-check` now also skips the
  CNAME-target registration check (targets stay `not_verified`).
- DKIM selector enumeration uses `query_classified()` (one TXT query per selector, primary
  servers × retries then fallbacks). The selector is "found" under the same rule as before
  (first TXT string); the per-query NS pre-lookup of `_query_with_retry()` is no longer
  done for selectors, which also makes the enumeration faster.
- `check()` of `SPFChecker` / `DMARCChecker` delegate the former body to `_check_dns()`
  and run the CNAME check afterwards (constructor flag `cname_check=True`).

## [2.1.0] - 2026-08-08

### Added

#### SPF `?all` (Neutral) is now detected — `spf_neutral` issue

The `all`-qualifier check ignored the **Neutral** qualifier (`?all`) entirely: a domain
ending its SPF with `?all` produced no issue at all. `?all` makes SPF return **neutral**
for every sender — explicitly "no opinion", which most receivers treat like having no SPF
assertion, so the domain stays spoofable. Added the `spf_neutral` issue
(`create_spf_neutral_all()`), now emitted in all three `all`-qualifier code paths of
`spf_checker.py`, at severity **HIGH**.

### Changed

#### SPF qualifier severities re-ordered by permissiveness (`+all` > `?all` > `~all`)

Neutral is **more permissive** than SoftFail (Neutral emits no signal at all; SoftFail
emits a negative one), so it must rank higher. Severities are now:

| Qualifier | Issue code | Severity |
|---|---|---|
| `+all` Pass | `spf_pass` | `critical` (equivalent to no SPF) |
| `?all` Neutral | `spf_neutral` | `high` *(new)* |
| `~all` SoftFail | `spf_softfail` | `medium` *(was `high`)* |

Applied consistently across `issue_definitions.py`, `data/Issue_Severity_Config.csv` and
`README.md` (which had also drifted to showing `+all` = High).

### Fixed

#### Recursive SPF walk absorbed shared platforms reached through a dangerous include (`lib/data/loaders.py`)

**Symptom**: resolving `spf.infomaniak.ch` followed the chain
`spf.infomaniak.ch → newsletter.infomaniak.com → amazonses.com` and recorded the 12 AWS SES
ranges (`54.240.0.0/18`, `76.223.176.0/20`, `199.255.192.0/22`, …) as
*Infomaniak / Shared Hosting*. Any unrelated domain publishing `include:amazonses.com` then
matched those ranges and was flagged CRITICAL for Infomaniak shared hosting. The same
mis-attribution had been persisted into `Dangerous_SPF_PTR_Records.csv`
(12 `*.smtp-out*.amazonses.com` PTR entries labelled `Infomaniak`).

**Cause**: `_extract_ips_from_spf_domain()` followed every `include:` token unconditionally,
attributing all collected IPs/PTRs to the root dangerous include.

**Fix**: new whitelist `data/Whitelisted_SPF_Include.csv` (same format as
`Dangerous_SPF_Include.csv`, all rows `dangerous=No`). Whitelisted includes are **resolved
recursively into IP ranges**, exactly like dangerous ones, and applied at five points:

| # | Point of application | Effect |
|---|---|---|
| 1 | `include:` in a dangerous tree | Sub-tree not walked |
| 2 | IP resolved from a dangerous tree | Dropped if contained in whitelisted space |
| 3 | PTR blacklist build | Reverse lookups landing in a whitelisted namespace discarded |
| 4 | PTR blacklist load | Stale rows under a whitelisted platform dropped (existing CSV self-heals) |
| 5 | `SPFChecker` IP checks | Contained IP/range skips the dangerous-range and AS-organization tiers |

Point 2 matters independently of point 1: a dangerous service can inline a shared
platform's addresses with `ip4:`/`a:`/`mx:` without going through `include:`.
Point 5 requires **full containment**, so an over-broad range clipping the platform
(e.g. `54.0.0.0/8`) stays fully checked.

**Precedence — declared dangerous always wins.** A whitelist entry can never neutralise an
explicit dangerous classification. Two mirror guards enforce it:

1. A sub-include declared in `Dangerous_SPF_Include.csv` encountered inside a whitelisted
   tree is pruned — whitelisting `amazonses.com` cannot whitelist a dangerous service it
   includes.
2. A resolved whitelist range overlapping a range declared in
   `Dangerous_SPF_Records_IP_Range.csv` is dropped. Overlap, not containment, is enough:
   the whitelist yields on any doubt.

Only CSV-declared dangerous data feeds these guards, never include-derived IPs — hence the
whitelist tree is resolved *before* the dangerous tree in `load_all()`. Both guards are
reported in the load summary rather than applied silently, since either one means a
whitelist entry is broader than intended.

### Added

- `data/Whitelisted_SPF_Include.csv`, seeded with `amazonses.com` (12 resolved ranges).
- `WhitelistedSPFInclude` and `WhitelistedSPFIPRange` dataclasses.
- `DataLoaders.load_whitelisted_includes()`, `_resolve_whitelisted_includes()`,
  `is_whitelisted_include()`, `find_whitelisted_include()`, `is_whitelisted_ip()`,
  `is_whitelisted_ip_range()`, `find_whitelisted_ip_range()`, `is_whitelisted_ptr()`.
- Properties `whitelisted_includes`, `whitelisted_ip_ranges`, `pruned_includes`,
  `dangerous_in_whitelist_tree`, `whitelist_conflicts`.
- Load summary reports whitelisted includes/ranges, prunes, and both precedence guards.
- Loading a whitelist row with `dangerous=Yes` raises a `ValueError` pointing to
  `Dangerous_SPF_Include.csv` (guards against copy/paste between the two files).

### Changed

- `_extract_ips_from_spf_domain()` now serves both trees via `whitelist_mode`. The four
  duplicated IP-append blocks (`ip4`/`ip6`/`a`/`mx`) are factored into a single local
  helper. The `ptr` mechanism is skipped in whitelist mode — that list is a blacklist.

### Removed

- 12 stale `*.amazonses.com` PTR entries misattributed to `Infomaniak` in
  `data/Dangerous_SPF_PTR_Records.csv`. Point 4 above now prevents such rows from
  surviving a reload.

## [2.2.0] — 2026-04-01

### Changed

#### Issue codes migrated from integers to string slugs (`lib/checkers/issue_definitions.py` + `lib/models/issue.py`)

- All integer constants in `IssueDefinitions` replaced with globally-unique string slugs.
  Slugs are self-documenting, collision-proof across modules, and readable in JSON output.

  | Old integer | New slug | Meaning |
  |---|---|---|
  | `1`   | `spf_missing`           | No SPF record |
  | `2`   | `spf_syntax_error`      | SPF record syntax error |
  | `3`   | `spf_pass`              | `+all` — every server authorised |
  | `4`   | `spf_softfail`          | `~all` — SoftFail qualifier |
  | `5`   | `spf_neutral`           | `?all` — Neutral qualifier |
  | `6`   | `spf_hard_fail`         | `-all` — Hard Fail |
  | `7`   | `spf_too_many_lookups`  | Exceeds 10 DNS lookup limit |
  | `8`   | `spf_dangerous_include` | Include of a dangerous third-party domain |
  | `9`   | `spf_dangerous_ptr`     | `ptr:` mechanism matches dangerous IP range |
  | `10`  | `spf_redirect`          | SPF redirect= modifier present |
  | `11`  | `spf_exp`               | `exp=` modifier present |
  | `12`  | `spf_multiple`          | Multiple SPF records published |
  | `13`  | `spf_include_depth`     | Include chain too deep |
  | `14`  | `spf_ip_range_too_large`| Overly broad IP range |
  | `100` | `no_dmarc`              | No DMARC record |
  | `101` | `dmarc_lax_policy`      | DMARC `p=none` |
  | `102` | `dmarc_missing_rua`     | No aggregate report address |
  | `103` | `dmarc_missing_ruf`     | No forensic report address |
  | `104` | `dmarc_low_pct`         | `pct` < 100 |
  | `105` | `dmarc_subdomain_none`  | `sp=none` exposes subdomains |
  | `200` | `dkim_missing`          | No DKIM selector found |
  | `201` | `dkim_invalid_key`      | DKIM key invalid or unusable |
  | `202` | `dkim_short_key`        | DKIM key length < 2048 bits |
  | `203` | `dkim_weak_algorithm`   | Weak signing algorithm (SHA-1) |

- `_DEFINITIONS` dict keys changed from integers to slugs.
- `get_issue_definitions()` classmethod returns `{slug → metadata}` dict.
- All `create_*` factory methods use `code=cls.<SLUG_CONSTANT>` — unchanged callers,
  because the constants now resolve to slug strings.

- **`lib/models/issue.py`** — `Issue.code` field type changed from `int` to `str`.
  `from_mailspoof_issue()` classmethod replaced by `from_dict()` which accepts a
  plain dict and an `IssueCategory` — decouples the model from the internal
  mailspoof representation.

---

## [2.1.0] — 2026-04-01

### Added

- **`AsyncPooledDNSResolver` — pooled DNS resolver with concurrency control**

  New class `lib/utils/async_dns_resolver.py` that inherits from
  `dns.resolver.Resolver` and adds two levels of thread-safe rate limiting,
  designed to be passed directly to checkdmarc functions via the `resolver=`
  parameter.

  **Why**: checkdmarc is synchronous by design and we do not want to modify it.
  When many domains are processed concurrently via `asyncio.to_thread()`, dozens
  of threads can each trigger multiple checkdmarc DNS queries simultaneously —
  potentially overwhelming the nameserver.  Passing a pooled resolver lets us
  bridge the async world and checkdmarc's sync model cleanly.

  **Two levels of limiting** (both use `threading.Semaphore`, safe from threads):

  | Level | Parameter | Default |
  |---|---|---|
  | Global (all nameservers) | `max_global_concurrent` | `50` |
  | Per individual nameserver | `max_per_nameserver` | `20` |

  The per-nameserver semaphore uses a non-blocking scan first (prefer a less-loaded
  nameserver), then falls back to a blocking wait on the first configured nameserver
  if all are at capacity.

  **Important**: checkdmarc ignores its own `nameservers=` / `timeout=` kwargs
  when a `resolver=` object is supplied.  The resolver must therefore be fully
  pre-configured before being passed in (nameservers, timeout, lifetime).

  ```python
  from lib.utils.async_dns_resolver import AsyncPooledDNSResolver

  resolver = AsyncPooledDNSResolver(
      nameservers=["8.8.8.8", "1.1.1.1"],  # None = system default
      timeout=5.0,
      max_global_concurrent=50,
      max_per_nameserver=20,
  )
  # Pass to SPFChecker / DMARCChecker — they forward it to checkdmarc:
  spf = SPFChecker(resolver=resolver)
  dmarc = DMARCChecker(resolver=resolver)
  ```

  **Checker integration** — `SPFChecker` and `DMARCChecker` both accept a new
  optional `resolver` parameter.  When set:
  - `SPFChecker.check_record()` passes it to `checkdmarc.spf.parse_spf_record()`
  - `DMARCChecker.check_record()` passes it to `checkdmarc.dmarc.parse_dmarc_record()`
  - `None` (default) preserves legacy behaviour (checkdmarc creates its own resolver).

  **CLI** — two new arguments:

  | Argument | Default | Description |
  |---|---|---|
  | `--max-global-concurrent N` | `50` | Global cap on concurrent checkdmarc DNS queries |
  | `--max-per-nameserver N` | `20` | Per-nameserver cap |

  The resolver is created once and shared across all checkers.

  **Files changed**:
  - `lib/utils/async_dns_resolver.py` — new file
  - `lib/utils/__init__.py` — exports `AsyncPooledDNSResolver`
  - `lib/__init__.py` — exports `AsyncPooledDNSResolver`, version bumped to `2.1.0`
  - `lib/checkers/spf_checker.py` — `resolver=` param, passes it to `parse_spf_record`
  - `lib/checkers/dmarc_checker.py` — `resolver=` param, passes it to `parse_dmarc_record`
  - `cli.py` — `--max-global-concurrent`, `--max-per-nameserver` args; shared resolver creation

### Fixed

- **`SPFChecker` passed wrong argument to `DataLoaders` when no `data_loaders` provided**

  `SPFChecker.__init__` called `DataLoaders(build_ptr_blacklist=...)` but the
  correct parameter name is `disable_ptr_blacklist`.  Fixed the mapping:
  `disable_ptr_blacklist=not build_ptr_blacklist`.

  **Files changed**: `lib/checkers/spf_checker.py`

## [2.0.1] — 2026-03-23

### Fixed

- **[BUG] `--async-mode` causes empty `email_domain_indicators` for some domains**

  **Symptom**: With `--async-mode` and multiple domains, certain domains returned
  `"email_domain_indicators": []` even though their SPF/MX records were publicly
  accessible (and `nslookup` confirmed them). The same domains resolved correctly
  in sync mode or when run alone.

  **Root cause**: `EmailDomainChecker.check()` makes up to 4 DNS/network calls
  per domain (MX, SPF, DMARC, SMTP). With `--max-concurrent 50` (default),
  up to ~200 simultaneous DNS queries could be fired, causing the DNS server
  to rate-limit or drop some responses — leading to silent timeouts and empty
  indicator lists.

  **Fix** (`cli.py` — `_process_domains_async`): Added a dedicated
  `email_sem = asyncio.Semaphore(10)` that limits concurrent
  `EmailDomainChecker.check()` calls to **10**, independently of the main domain
  semaphore. Domains exceeding the email-check slot wait only for that step, then
  continue immediately with SPF/DMARC/DKIM at full `--max-concurrent` concurrency.

  **Files changed**: `cli.py`

- **`parse_spf_record` called without `timeout_retries`**

  `SPFChecker.check_record()` called `checkdmarc.spf.parse_spf_record()` with
  `timeout=...` but omitted `timeout_retries`, falling back to the library
  default of `2`. The value is now explicitly forwarded from
  `self.dns_utils.max_retries` (CLI default: `3`) for consistency with the rest
  of the tool's DNS retry strategy.

  **Files changed**: `lib/checkers/spf_checker.py`

## [2.0.0] — 2026-03-22

### Added

- **Async mode — concurrent domain processing (`asyncio`)**

  All blocking DNS/network calls are now wrappable with `asyncio.to_thread()`,
  enabling parallel processing of multiple domains without rewriting the
  underlying synchronous `checkdmarc` / `dnspython` stack.

  **Library / SDK**

  All three checker classes now expose a `check_async()` method:

  | Method | Signature |
  |---|---|
  | `SPFChecker.check_async()` | `(domains, max_concurrent=50, use_checkdmarc=True)` |
  | `DMARCChecker.check_async()` | `(domains, max_concurrent=50, use_checkdmarc=True)` |
  | `DKIMChecker.check_async()` | `(domains, max_concurrent=50, custom_selectors=None)` |

  - Returns a list of result objects in the **same order** as the input list.
  - `max_concurrent=0` removes the concurrency cap (unlimited parallelism).
  - When `SPFChecker` is initialised with `use_ns_record=True`, an internal
    `asyncio.Lock` (`_ns_lock`) serialises the per-domain NS resolver swap to
    prevent thread-safety races; all other concurrent checks run freely.
  - Results that raised an unexpected exception are returned as `Exception`
    instances — callers should check with `isinstance(item, Exception)`.

  Example usage:
  ```python
  import asyncio
  from lib import SPFChecker

  checker = SPFChecker()
  results = asyncio.run(checker.check_async(["example.com", "gmail.com"], max_concurrent=10))
  ```

  **CLI (`cli.py`)**

  Two new arguments:

  | Argument | Description |
  |---|---|
  | `--async-mode` | Enable concurrent processing (requires Python >= 3.9) |
  | `--max-concurrent N` | Max parallel domains (default 50; 0 = unlimited) |

  When `--async-mode` is active, all domains are dispatched concurrently via
  `asyncio.run(_process_domains_async(...))`. Progress lines are printed as
  each domain completes. Sequential (sync) mode remains the default and is
  unchanged in behaviour.

  **Architecture notes**
  - `asyncio.to_thread()` (Python 3.9+) wraps every blocking DNS call.
  - A `ThreadPoolExecutor` sized to `max(64, max_concurrent * 2)` is
    installed as the default executor to ensure enough worker threads.
  - `contextlib.nullcontext()` is used when `max_concurrent=0` (no semaphore).
  - No new third-party packages required — async support is pure stdlib.

  **Files changed**:
  - `lib/checkers/spf_checker.py` — added `check_async()`, `_ns_lock` attribute
  - `lib/checkers/dmarc_checker.py` — added `check_async()`
  - `lib/checkers/dkim_checker.py` — added `check_async()`
  - `cli.py` — added `_process_domains_async()` coroutine, `--async-mode`,
    `--max-concurrent` arguments, async dispatch in `run_check_record_mode()`
  - `requirements.txt` — added Python 3.9+ note (no new packages)

## [1.2.2] — 2026-03-22

### Changed

- **Unregistered domain check now covers all DNS-referencing SPF mechanisms**

  Previously only `include:<domain>` (and `redirect=<domain>`) values were collected for
  the bulk availability check. An attacker can equally exploit an expired domain referenced
  by any mechanism that triggers a DNS lookup.

  Mechanisms now covered:
  - `include:<domain>` (existing)
  - `redirect=<domain>` (existing)
  - `a:<domain>` — A/AAAA record lookup
  - `mx:<domain>` — MX record lookup
  - `ptr:<domain>` — PTR reverse-DNS matching domain
  - `exists:<domain>` — existence check domain

  Only entries with an **explicit** domain value are tracked; bare `a`, `mx`, `ptr` (which
  refer implicitly to the checked domain itself) are ignored.

  **Architecture**:
  - `lib/checkers/spf_checker.py` — `_process_mechanisms_list`: added `all_includes` tracking
    for `a:`, `mx:`, `ptr:`, `exists:` mechanisms (with `value != ""`).
  - `lib/checkers/spf_checker.py` — `_basic_recurse_includes`: same tracking in the fallback
    parsing path.
  - `lib/checkers/unregistered_domain_checker.py` — `extract_registered_domain`: now strips
    mechanism prefixes (`a:`, `mx:`, `ptr:`, `exists:`, `redirect=`) before passing the
    hostname to tldextract, so apex domain extraction works for all formats.

  **Files changed**:
  - `lib/checkers/spf_checker.py` — `_process_mechanisms_list`, `_basic_recurse_includes`
  - `lib/checkers/unregistered_domain_checker.py` — `extract_registered_domain`

## [1.2.1] — 2026-03-22

### Fixed

- **[BUG] `--use-ns-record` crashes with "nameserver is not a valid IP address"**

  **Symptom**: Running with `--use-ns-record` produced:
  `SPF: Error - nameserver ns2.esa.int is not a dns.nameserver.Nameserver instance or text form,
  IP address, nor a valid https URL` for domains whose NS records are hostnames.

  **Root cause**: `get_ns_servers()` returns NS hostnames (e.g. `ns2.esa.int`). dnspython's
  `Resolver.nameservers` only accepts IP addresses, not hostnames.

  **Fix** (`lib/utils/dns_utils.py`):
  - New method `resolve_hostname_to_ip(hostname)` — resolves a hostname to its first A record
    using fallback resolvers (8.8.8.8, 1.1.1.1) to avoid circular dependency.
  - New method `get_ns_ips(domain)` — combines `get_ns_servers()` + `resolve_hostname_to_ip()`
    and returns a list of IP addresses.
  - `SPFChecker.check()` now calls `get_ns_ips()` instead of `get_ns_servers()`.

  **Files changed**: `lib/utils/dns_utils.py`, `lib/checkers/spf_checker.py`

- **[BUG] `--use-ns-record` causes IP-based findings to disappear when `parse_spf_record` falls back to basic parsing**

  **Symptom**: With `--use-ns-record`, state.gov showed 0 issues / 0 IP ranges instead of
  4 issues / 11 ranges. `parsed_spf` was `None` in the JSON output.

  **Root cause (two-part)**:

  *Part 1 (regression, already fixed):* An earlier attempt forwarded NS IPs to
  `parse_spf_record()` via `nameservers=`. checkdmarc then used the domain's authoritative NS
  to resolve all `include:` chains — authoritative NS servers only know their own zone, so
  external includes (`sendgrid.net`, `spf.protection.outlook.com`) silently returned empty.
  Fixed by not forwarding NS IPs to `parse_spf_record`.

  *Part 2 (root cause of the persistent 0-issues bug):* When `parse_spf_record` raises any
  unexpected exception (e.g. `SPFTooManyVoidDNSLookups` from resolving internal state.gov
  domains like `_iplist.state.gov` or `_iplist2.state.gov` from outside the government
  network), `check_record()` catches it via `except Exception` and falls back to
  `_process_basic_spf` → `_basic_recurse_includes`. That method calls
  `self.dns_utils.get_spf_record()` to recursively fetch sub-includes — but at that point
  `self.dns_utils` is still the NS-based resolver (the `finally` block that restores public
  DNS runs *after* `check_record()` returns). The NS server for state.gov returns `None` for
  `spf.protection.outlook.com`, so no CIDR ranges are fetched and no issues are raised.

  **Fix** (`lib/checkers/spf_checker.py`):
  - New attribute `self._base_dns_utils` set once in `__init__` to the original public
    resolver; never swapped when `use_ns_record` activates.
  - `_basic_recurse_includes` now calls `self._base_dns_utils.get_spf_record()` instead of
    `self.dns_utils.get_spf_record()`, ensuring external includes are always resolved via
    public DNS regardless of whether a domain's NS is currently active.

  **Files changed**: `lib/checkers/spf_checker.py`

- **[BUG] `UnicodeEncodeError` crash in Domain Availability Check output on Windows**

  **Symptom**: After the domain availability check, the CLI crashed with:
  `UnicodeEncodeError: 'charmap' codec can't encode character '\u2192'` (arrow `→`) or
  `'\u2014'` (em dash `—`).

  **Root cause**: Python's default `print()` on Windows uses the console code page (cp1252),
  which cannot encode Unicode arrows and em dashes inserted in `cli.py` f-strings.

  **Fix** (`cli.py`):
  - Replaced `→` with `->` and `—` with `-` in all `print()` calls.

  **Files changed**: `cli.py`

- **[BUG] Domain availability check silently skipped with no actionable error message**

  **Symptom**: When `lib/domain/` packages were unavailable (e.g. missing pip dependency),
  the CLI printed only a generic "packages not installed" message with no hint of the actual
  failure, making it impossible to know which package to install.

  **Fix**:
  - `lib/checkers/unregistered_domain_checker.py` — changed `except ImportError` to
    `except Exception as _e`; stores the full exception string in `_CHECKER_IMPORT_ERROR`.
  - `cli.py` — imports `_CHECKER_IMPORT_ERROR` and prints it alongside the skip message,
    e.g.: `Import error: ModuleNotFoundError: No module named 'httpx'`.

  **Files changed**: `lib/checkers/unregistered_domain_checker.py`, `cli.py`

## [1.2.0] — 2026-03-22

### Added

- **Unregistered / Potentially-Unregistered Domain Check (SPF)**

  New SPF issue codes:
  - `17 — Unregistered domain` (`critical`): an SPF `include:` references a domain that is
    currently available for registration. An attacker could register it and publish a malicious
    SPF record that would pass validation for the audited domain.
  - `18 — Potentially unregistered domain` (`high`): domain availability could not be confirmed
    (WHOIS/service-checker returned `unknown`).

  **Architecture**:
  - `lib/checkers/unregistered_domain_checker.py` — new module:
    - `extract_registered_domain(include)` — uses `tldextract` to derive the apex domain from
      any SPF include value (e.g. `spf.protection.outlook.com` → `outlook.com`).
    - `check_spf_includes_availability(domains)` — calls
      `DomainAvailabilityChecker.check_domains()` (bulk), mapping each domain to `available` /
      `unavailable` / `unknown`.
  - `lib/checkers/issue_definitions.py` — new constants `SPF_UNREGISTERED_DOMAIN = 17` and
    `SPF_POTENTIALLY_UNREGISTERED_DOMAIN = 18` with factory methods
    `create_spf_unregistered_domain` and `create_spf_potentially_unregistered_domain`.
  - `lib/domain/__init__.py` — new empty `__init__.py` making `lib/domain/` a proper Python
    package so that relative imports from `lib/checkers/` work correctly.
  - `cli.py` — after the main domain processing loop, all SPF includes are collected, deduplicated
    by registered domain, and sent in a single bulk call to `DomainAvailabilityChecker`. Issues
    are injected back into each result's SPF data before output generation.
    New flag `--skip-domain-availability-check` to opt out.

  **Dependencies**:
  - `tldextract` (PyPI) — apex domain extraction.
  - `hybridwhois`, `whoisit`, `whoisitlegacy`, `domain_availability_checker`,
    `domain_availability_service_checker` — internal Deloitte packages placed in `lib/domain/`
    (see README for download instructions from Azure DevOps OSINT repo).

  **Graceful degradation**: if any `lib/domain/` package is missing the check is skipped with
  a console warning; all other checks continue normally.

  **Files changed**:
  - `lib/checkers/unregistered_domain_checker.py` — new file
  - `lib/checkers/issue_definitions.py` — new constants + factory methods
  - `lib/domain/__init__.py` — new file
  - `cli.py` — bulk domain check block, `--skip-domain-availability-check` flag

## [1.1.0] — 2026-03-22

### Added
- Free Email Provider detection via `Dangerous_SPF_Include.csv` (e.g. `outlook.com`).
  Detection works end-to-end with the recursive include resolution fix below.

### Fixed

- **[BUG] `get_severity_for_service`: Service Name Severity not applied on IPs resolved from dangerous includes**

  **Symptom**: On `esa.int`, findings reported `high` severity for SendGrid and Mailjet even
  though `Service_Name_Severity_Config.csv` defines `SendGrid → critical`.

  **Root cause**: `_resolve_dangerous_includes` stores `DangerousSPFIPRange` objects with
  `service_name = "SendGrid (from sendgrid.net)"` (format `"{name} (from {include})"`).
  `get_severity_for_service` performed an exact dict lookup, which did not match `"SendGrid"`.

  **Fix** (`lib/data/loaders.py` — `get_severity_for_service`):
  - Service Name lookup is now **case-insensitive**.
  - If `service_name` contains a `" (from ...)"` suffix, the base name is also tested.
  - Service Type lookup is also made **case-insensitive**.

  **Files changed**: `lib/data/loaders.py` — `get_severity_for_service`

- **[BUG] Service Name displayed as `"SendGrid (from sendgrid.net)"` in Excel instead of `"SendGrid"`**

  **Root cause**: `_resolve_dangerous_includes` was baking provenance into `service_name`
  for all resolved mechanism types (`ip4`, `ip6`, `a`, `mx`, `ptr`).

  **Fix** (`lib/data/loaders.py` — `_resolve_dangerous_includes`):
  - All constructions now use `service_name=include_entry.service_name` (clean name from CSV).
  - Provenance remains accessible via `source_include`.

  **Files changed**: `lib/data/loaders.py` — `_resolve_dangerous_includes`

- **[BUG] `skip_issue` false positive suppresses findings when `source_include` is a substring of a domain in the path**

  **Symptom**: Adding `outlook.com` to `Dangerous_SPF_Include.csv` produced no findings for
  `state.gov` (which includes `spf.protection.outlook.com`).

  **Root cause**: Substring check `dangerous_range.source_include in path_element` matched
  `"outlook.com"` inside `"include:spf.protection.outlook.com"`.

  **Fix** (`lib/checkers/spf_checker.py` — `_check_dangerous_ip_range`, `_check_dangerous_ip`):
  - Exact path-element matching against `"include:{source_include}"` and
    `"redirect={source_include}"`.

  **Files changed**: `lib/checkers/spf_checker.py` — `_check_dangerous_ip_range`, `_check_dangerous_ip`

- **[BUG] `_resolve_dangerous_includes` does not follow `include:` chains — IPs from nested SPF records never extracted**

  **Symptom**: `outlook.com` in `Dangerous_SPF_Include.csv` produced no findings because
  `outlook.com`'s SPF only contains `include:spf2.outlook.com` (no direct IPs).

  **Root cause**: `_resolve_dangerous_includes` only parsed direct tokens (`ip4:`, `ip6:`,
  `a:`, `mx:`) without following `include:` sub-chains.

  **Fix** (`lib/data/loaders.py`):
  - New recursive helper `_extract_ips_from_spf_domain` follows `include:` chains
    depth-first (max depth 10, loop-protected via `visited` set).
  - `source_include` always set to the original top-level dangerous domain (`root_domain`).
  - PTR entries only collected at depth 0.

  **Files changed**: `lib/data/loaders.py` — new `_extract_ips_from_spf_domain`, refactored `_resolve_dangerous_includes`

- **[BUG] `check_record` silently swallows checkdmarc exceptions — SPF analysis falls back to basic parsing without warning**

  **Symptom**: `state.gov` showed `0 issues, 3 includes, 0 IPs` in the CLI despite having
  resolvable includes with dangerous IP ranges. No error was reported.

  **Root cause**: A bare `except Exception` in `check_record` caught all checkdmarc exceptions
  (including `SPFTooManyVoidDNSLookups`, triggered when internal DNS names such as
  `_iplist.state.gov` return NXDOMAIN from outside the government network) and silently
  fell back to `_process_basic_spf`, which does not recurse into includes.

  **Fix** (`lib/checkers/spf_checker.py` — `check_record`):
  - Each checkdmarc exception type is now caught individually:
    - `SPFSyntaxError` → existing behaviour (syntax issue)
    - `SPFTooManyDNSLookups` → creates a lookup-limit issue + basic fallback
    - `SPFTooManyVoidDNSLookups` → creates a new `INFO`-level warning issue (code 17) explaining partial analysis + basic fallback
    - `DNSException` / `DNSExceptionNXDOMAIN` → creates a DNS timeout/medium issue + basic fallback
    - Generic `Exception` → creates a new `MEDIUM`-level parse-error issue (code 18) + basic fallback
  - Users can now see exactly why an SPF analysis is incomplete.
  - New issue codes added: `SPF_VOID_LOOKUP_WARNING = 17`, `SPF_PARSE_ERROR = 18`.

  **Files changed**:
  - `lib/checkers/spf_checker.py` — `check_record`
  - `lib/checkers/issue_definitions.py` — new constants and factory methods `create_spf_void_lookup_warning`, `create_spf_parse_error`

- **[BUG] `SPFTooManyVoidDNSLookups` and `AttributeError` on `None` addresses/hosts prevent full SPF tree analysis**

  **Symptom**: `state.gov` reported only "SPF Parse Error" — no Outlook.com findings — because
  internal government DNS names (`_iplist.state.gov`, `_msiplista.state.gov`) return NXDOMAIN
  from external networks, causing checkdmarc to abort the entire SPF tree resolution.
  Additionally, `addresses` (for `a:` mechanism) and `hosts` (for `mx:`) can be `None` when
  DNS resolution fails, causing `TypeError`/`AttributeError` inside `_process_mechanisms_list`.

  **Fix** (`lib/checkers/spf_checker.py`):
  - `parse_spf_record` is now called with `ignore_too_many_lookups=True` (checkdmarc parameter).
    Unresolvable/NXDOMAIN includes are skipped and the rest of the chain continues normally.
  - Exception handling in `check_record` is now per-type:
    - `SPFSyntaxError` → existing syntax issue (record not parsable — commas instead of spaces etc.)
    - `SPFTooManyDNSLookups` → existing lookup-limit issue + basic fallback (hard RFC §4.6.4 violation)
    - Any other exception → silent fallback to `_process_basic_spf`, no finding surfaced
      (not a policy issue visible to email receivers; was wrongly surfaced as "SPF Parse Error")
  - `mechanism.get('addresses')` and `mechanism.get('hosts')` now use `or []` / `or {}` to
    guard against `None` values when a DNS lookup failed for a specific mechanism (`AttributeError`).
  - `_basic_recurse_includes` (fallback path) now also processes `ip4:` and `ip6:` mechanisms,
    enabling dangerous IP range detection even when the checkdmarc path is unavailable.

  **Files changed**:
  - `lib/checkers/spf_checker.py` — `check_record`, `_process_mechanisms_list`, `_basic_recurse_includes`

## [1.0.0] — 2026-03-22

### Added
- Initial release of Mail AntiSpoof Policy Checker
- SPF record checking with full include/redirect tree resolution (`include`, `ip4`, `ip6`, `a`, `mx`, `ptr`)
- DMARC policy checking (policy, subdomain policy, alignment, reporting URIs)
- DKIM selector discovery and key validation (838 selectors, weak key detection)
- Dangerous service detection via CSV databases (includes, IP ranges, PTR domains)
- AS Organization lookup via MaxMind GeoIP2 (`Dangerous_AS_Organization.csv`)
- Severity cascade: Service Name > Service Type > Base Severity
- PTR blacklist building from dangerous IPs (optional, reverse DNS)
- Unknown data analyzer with PTR lookups for unrecognized SPF entries
- Email domain detection (HAS_MX, HAS_SPF, HAS_DMARC, HAS_SMTP indicators)
- DNS retry mechanism with fallback servers (Google, Cloudflare, domain NS)
- JSON and Excel output with detailed sheets
- Full-featured CLI (`cli.py`) with bulk domain support

### Fixed

- **[BUG] `get_severity_for_service`: Service Name Severity not applied on IPs resolved from dangerous includes**

  **Symptom**: On `esa.int`, findings reported `high` severity for SendGrid and Mailjet even
  though `Service_Name_Severity_Config.csv` defines `SendGrid → critical`.

  **Root cause**: `_resolve_dangerous_includes` stores `DangerousSPFIPRange` objects with
  `service_name = "SendGrid (from sendgrid.net)"` (format `"{name} (from {include})"`).
  `get_severity_for_service` performed an exact dict lookup (`if service_name in self._service_name_severity`),
  which did not match `"SendGrid"` → fell back to Service Type `"Email Delivery Service"` → `high`.

  **Fix** (`lib/data/loaders.py` — `get_severity_for_service`):
  - Service Name lookup is now **case-insensitive**.
  - If `service_name` contains a `" (from ...)"` suffix, the base name is also tested
    (e.g. `"SendGrid (from sendgrid.net)"` → also tries `"SendGrid"`).
  - Service Type lookup is also made **case-insensitive**.

  **Files changed**:
  - `lib/data/loaders.py` — method `get_severity_for_service`

- **[BUG] Service Name displayed as `"SendGrid (from sendgrid.net)"` in Excel instead of `"SendGrid"`**

  **Symptom**: The Service Name column in the Excel output showed the full provenance string
  (e.g. `"SendGrid (from sendgrid.net)"`) instead of the clean name from the CSV (`"SendGrid"`).

  **Root cause**: `_resolve_dangerous_includes` was baking the provenance into `service_name`
  itself (e.g. `service_name=f"{name} (from {include})"`) for all resolved mechanism types
  (`ip4`, `ip6`, `a`, `mx`, `ptr`). This value propagated unchanged into issues and Excel output.
  The provenance information is already available separately via the `source_include` field.

  **Fix** (`lib/data/loaders.py` — `_resolve_dangerous_includes`):
  - All five `DangerousSPFIPRange` / `DangerousPTRDomain` constructions now use
    `service_name=include_entry.service_name` (clean name from CSV).
  - Provenance remains accessible via `source_include` for any tooling that needs it.

  **Files changed**:
  - `lib/data/loaders.py` — method `_resolve_dangerous_includes`

- **[BUG] `skip_issue` false positive suppresses findings when `source_include` is a substring of a domain in the path**

  **Symptom**: Adding `outlook.com` to `Dangerous_SPF_Include.csv` produced no findings for
  `state.gov`, which includes `spf.protection.outlook.com` (an IP range overlapping with
  `outlook.com`'s resolved ranges).

  **Root cause**: The `skip_issue` guard in `_check_dangerous_ip_range` and `_check_dangerous_ip`
  used a substring check (`dangerous_range.source_include in path_element`).
  Since `"outlook.com"` is a substring of `"include:spf.protection.outlook.com"`, the guard
  incorrectly set `skip_issue = True` and silently dropped the issue.

  **Fix** (`lib/checkers/spf_checker.py` — `_check_dangerous_ip_range` and `_check_dangerous_ip`):
  - Replaced substring check with exact path-element matching against
    `"include:{source_include}"` and `"redirect={source_include}"`.
  - `"outlook.com"` now only suppresses issues when the path literally contains
    `"include:outlook.com"`, not when it contains `"include:spf.protection.outlook.com"`.

  **Files changed**:
  - `lib/checkers/spf_checker.py` — methods `_check_dangerous_ip_range`, `_check_dangerous_ip`

- **[BUG] `_resolve_dangerous_includes` does not follow `include:` chains — IPs from nested SPF records never extracted**

  **Symptom**: Adding `outlook.com` to `Dangerous_SPF_Include.csv` produced no findings for
  domains using `spf.protection.outlook.com` (e.g. `state.gov`, `esa.int`), even though the
  IP ranges published by Microsoft overlap with `outlook.com`'s resolved ranges.

  **Root cause**: `_resolve_dangerous_includes` queried the TXT record of the dangerous include
  domain and parsed `ip4:`, `ip6:`, `a:`, `mx:` tokens directly. When the TXT record only
  contains `include:` sub-chains (e.g. `outlook.com → include:spf2.outlook.com`), no IPs
  were ever extracted, so `dangerous_ip_ranges` stayed empty for that entry.

  **Fix** (`lib/data/loaders.py`):
  - Extracted token-parsing logic into a new recursive helper
    `_extract_ips_from_spf_domain(domain, root_domain, ...)`.
  - `include:sub.domain` tokens are now followed recursively (depth-first, max depth 10,
    loop-protected via a `visited` set).
  - `source_include` is always set to the original top-level dangerous include domain
    (`root_domain`), so the `skip_issue` guard in `SPFChecker` continues to work correctly.
  - PTR entries are only collected at depth 0 (top-level include) to avoid over-populating
    the PTR blacklist with sub-include PTR mechanisms.

  **Files changed**:
  - `lib/data/loaders.py` — replaced `_resolve_dangerous_includes` body with recursive
    `_extract_ips_from_spf_domain` helper
