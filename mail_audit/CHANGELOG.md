# Changelog

All notable changes to `mail_audit` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **DMARC test mode (`t=y`, RFC 9989) and `pct=0`** lower the effective policy by one level in
  the spoofing scenarios: `p=reject` is handled as quarantine, `p=quarantine` as none
  (RFC 7489 §6.6.4: unsampled mail gets the next less strict policy). The effective policy
  also drives the rules that require `dmarc_lax_policy` (*SPF SoftFail (~all) — DMARC
  Monitoring Only*), the parent's enforcement in relaxed-alignment scenarios, and the
  remediation ("remove t=y" / "set pct=100" instead of "publish an enforcing policy").
- **`Spoofing - Partial DMARC Enforcement (pct)`** scenario for `pct` 1–99 with
  `p=quarantine`/`p=reject`: probability by `pct` range (`likelihood_by_pct`: 1–10 very high,
  11–35 high, 36–65 medium, 66–90 low, 91–99 very low), impact by policy (escapes from
  quarantine are delivered → critical; from reject they are quarantined → medium).
- **DKIM scenarios**: *DKIM RSA key with a known factorization* (very high / critical, even at
  `p=reject`) and *dangerous public exponent* `e=1`/`e=3` (very low / low, lenient verifiers only).
- `--skip-factordb-check` / `MailAuditor(factordb_check=False)`. *DKIM Issues* sheet: **RSA
  Exponent**, **factordb** (link) and **factordb Note** columns.
- Relaxed-alignment scenario: **Affected Domains** is now `<org>, *.<org>` (the whole
  namespace, audited or not) instead of the long list of audited siblings. Audited subdomains
  with their own strict-alignment `_dmarc` appear as `*.<org> (except …)`; the covered audited
  subdomains and a caveat for non-audited strict ones are listed in the conditions.
- *DMARC Records* sheet: **Non-existent Subdomain Policy** (`np`) and **Test Mode (t=y)**
  columns.

## [2.2.0] - 2026-10-29

### Added

- **Relaxed-alignment cross-domain spoofing scenario** (`Spoofing - Relaxed DMARC Alignment
  (org-domain)`, new `AttackType`). DMARC uses relaxed alignment by default (`aspf`/`adkim`
  absent = `r`), which compares only the organizational (registrable) domain. So an audited
  **subdomain** with an *aligned-capable* spoof — shared hosting, SPF `+all`, or a
  weak/takeable DKIM — lets an attacker forge `From:@<organizational-parent>` (and any sibling
  subdomain) when the parent enforces DMARC with relaxed alignment. `FORGED_SENDER` is raised
  (envelope/DKIM domain ≠ From) but SPF/DMARC (or DKIM/DMARC) still PASS, even at `p=reject`.
  Risk **critical** when the parent enforces (`p=quarantine`/`reject`), **high** at `p=none`;
  the branch is dropped under **strict** alignment (`aspf=s`/`adkim=s`). Built by
  `AttackScenarioAnalyzer._analyze_relaxed_alignment`.
  **Leverage vs. Affected Domains:** the audited subdomain is the *leverage* (envelope
  `MAIL FROM` / DKIM `d=`, shown in the **Target** column); the **Affected Domains** column now
  lists the *spoofable From identities* — the organizational domain **and** every audited sibling
  sharing it whose alignment is relaxed — not the leverage subdomain. Relaxed alignment is
  bidirectional/symmetric at the org level (a leverage on `sub.example.com` forges
  `From:@example.com` and `From:@othersub.example.com`); a sibling with no own `_dmarc` inherits
  the parent's policy and is a target, a strict-alignment sibling is excluded.
- **Organizational-parent DMARC auto-fetch.** The auditor derives each subdomain's
  organizational (registrable) parent (`tldextract` / PSL, via the shared antispoof helper
  `derive_org_parents`) and fetches **the parent's own DMARC** (the policy that governs a
  `From:@<parent>`) when the parent is not already an audit target — deduplicated, **DMARC
  only** (the parent's SPF/DKIM are not fetched; the leverage is the subdomain's). DMARC jumps
  from a subdomain **directly** to the organizational domain (no label-by-label walk). A
  derived parent appears in the antispoof output with DMARC only.
- **DMARC `np=` (RFC 9091) parsing fix (via `mail_antispoof_policy_checker`).** Records with
  an `np=` tag (or any tag `checkdmarc` refuses) previously came back with `policy=None` /
  `alignment_spf=None`, which made an enforcing parent look unprotected and **understated** the
  relaxed-alignment cross-domain severity (e.g. a `p=reject` parent scored *high* instead of
  *critical*). The antispoof DMARC parser now recovers the policy and alignment, so the scenario
  risk is correct. See the antispoof changelog.
- **CNAME chain check** (from `mail_antispoof_policy_checker` 2.2.0) on DKIM selector,
  `_dmarc` and SPF domain names: results in `spf/dmarc/dkim.cname_checks` of the
  antispoof JSON; takeover issues show **CNAME Chain** / **Domain To Buy** in the Issues sheets.
  Only takeover risks become issues (`*_cname_target_(potentially_)unregistered`).
- **End-of-run registration check** (one bulk, deduplicated call through the antispoof
  `DomainAvailabilityChecker` pipeline):
  - **SPF include / redirect domains** — `spf_domain_unregistered` /
    `spf_domain_potentially_unregistered` were only produced by the antispoof CLI (the
    check lived in its `cli.py`), so `mail_audit` never reported them. The logic is now
    shared (`collect_spf_include_sources` / `apply_spf_include_availability`) and used by
    both;
  - **broken CNAME targets** — `*_cname_target_unregistered` (critical) /
    `*_cname_target_potentially_unregistered` (high). Reserved names (`.invalid`, …) and
    hosted private suffixes are never sent to it.
- **Takeover scenario** — new `attack_type` `Spoofing - Unregistered Domain Takeover`:
  **one scenario per domain** (`_analyze_domain_takeover`, texts in
  `external_spoofing.domain_takeover`) merging every vulnerable name (domain CNAME, SPF
  include, DKIM selector CNAME, `_dmarc` CNAME). It names the domain(s) to buy, the CNAME
  chain, selector and registration source, with one vector (exact steps) per name.
  Bypasses = union (a `_dmarc` takeover alone bypasses DMARC only). Likelihood: confirmed
  high / potentially medium; `_dmarc` one notch lower with SPF `-all`. Status `UNVERIFIED`.
- Rule engine: optional `condition_any_issue_codes` / `condition_absent_issue_codes`.
- CLI flags `--skip-cname-check` and `--skip-domain-availability-check`; matching
  `MailAuditor(cname_check=..., skip_domain_availability_check=...)` parameters.

- `{base}_antispoof.xlsx`: new **DKIM Issues** sheet (weak / perfectible key size,
  syntax, CNAME takeover…) — DKIM issues were previously only counted in the Summary.

### Changed

- **DNS resolver flags unified (breaking): `--dns-server` removed.** A single
  `--nameservers` (comma-separated list, e.g. `1.1.1.1,8.8.8.8`) now drives BOTH the
  SMTP checker and the antispoof (SPF/DKIM/DMARC) checkers. `MailAuditor` takes
  `nameservers: list[str]` in place of `dns_server: str`; the antispoof package was
  normalized to accept a resolver list end-to-end. `--use-ns-record` is unchanged.
- **Scenario-sheet column "Attack Modes" renamed to "Attack Vector(s)"** (matching the
  documentation's *vector* terminology) and it now lists only a scenario's **active**
  vectors — a vector tested and blocked (`status == "blocked"`) is excluded. E.g. SendGrid
  now shows only *Web UI*, not *Web UI, SMTP Server (587/465)*, since its authenticated SMTP
  server is blocked by the service's sender-ownership control.
- **Takeover `Bypass` column no longer lists DMARC as a consequence.** An unregistered-domain
  takeover now tags only the control(s) whose lookup name is actually dangling: an SPF
  `include` / CNAME → `SPF`, a DKIM selector CNAME → `DKIM`, a `_dmarc` CNAME → `DMARC`. DMARC
  is listed **only** when `_dmarc` itself is takeable, not merely because SPF/DKIM alignment
  makes DMARC pass (that consequence is still explained in the Bypass Conditions text). E.g. a
  domain with an SPF include + a DKIM selector CNAME to the same buyable domain → `SPF, DKIM`
  (not `SPF, DKIM, DMARC`).
- **"Well-Configured or Reputation-Bearing Server" scenario now lists its real vectors.** In
  addition to `SMTP Server (25)` (cold direct-MX), it carries `SMTP Server (587/465)`
  (authenticated submission through a reputation-bearing relay) and `Local MTA` (shared-host
  local MTA), matching the finding that a cold server is spam-foldered while a reputation
  relay reaches the inbox. Risk is unchanged (worst vector still drives it).
- **Weak DKIM RSA key scenario retyped, given its real vectors, and down-rated.** Its `attack_type`
  is now the dedicated `Spoofing - DKIM Misconfiguration` (new `AttackType`) instead of the generic
  `Spoofing - SPF/DKIM Misconfiguration`, matching its `Bypass` profile (`DKIM, DMARC` — SPF is
  not involved). It now lists three vectors instead of one: `SMTP Server (25)`,
  `SMTP Server (587/465)` and `Local MTA` — once the factorable key is recovered, the valid,
  aligned DKIM signature travels with the message on any channel. **Likelihood lowered from high
  to medium (risk critical → high):** per RFC 8301 a verifier treats an RSA key < 1024 bits as
  invalid, and Gmail (likely other large providers too) ignores a signature made with such a key —
  so the forged signature does not validate there, DKIM does not pass, DMARC fails (no aligned SPF)
  and the spoof is caught at `p=quarantine/reject`. The attack only lands on lenient / legacy
  receivers; the weak key must still be rotated regardless.
- **AlwaysData / OVH shared-hosting re-tested (2026-10-30).** AlwaysData still works and now
  documents **two modes**: `local_script` (local MTA, no SMTP auth — auth bypass) and
  `smtp_server` (authenticated shared mail server, `smtp-<user>.alwaysdata.net`); both set an
  aligned `MAIL FROM`. The host DKIM-signs with its own key (`alwaysdata.net:s=default`): not
  aligned, but the valid signature avoids an `R_DKIM_NA` penalty, DMARC passing via SPF — noted
  in the shared-hosting DKIM bypass text and in `email_services.json`. OVH still blocked (access
  control on the `MAIL FROM`). Each dated test now pins a specific `vector` (like the Brevo /
  SendGrid tests) instead of confirming every vector blindly, and the shared / mutualised SMTP
  server is marked `shared: true` on the vector, which the `vector` filter can target
  (`{"vector_type": "smtp_server", "shared": true}`). The scenario sheets gain an **Attack
  Modes** column (Web UI / SMTP Server / Shared SMTP Server / Local MTA / …) built from the
  vectors; `AttackVector` carries a `shared` flag. AlwaysData evidence enriched: DMARC passes
  via SPF alignment at `p=reject` (`DMARC_POLICY_ALLOW`) and the spoof lands in the Gmail inbox.
  New dated test 2026-10-31 (`alwaysdata_local_mta_no_dmarc_20261031.json`): the Local MTA spoof
  also lands in the Gmail inbox against a victim with **no DMARC record** (`DMARC_NA` +0.5, SPF +
  DKIM pass). The README gains an **Rspamd DMARC symbol-score** table (`DMARC_POLICY_ALLOW` −1,
  `DMARC_NA` +0.5, `DMARC_POLICY_SOFTFAIL` +1.5, `DMARC_POLICY_QUARANTINE` +3, `DMARC_POLICY_REJECT`
  +5.5): an absent record is penalised *less* than an explicit `p=none` served via a third party.
- **Reputation decides the Gmail inbox for the attacker-server path (2026-10-31).** The
  `generic_custom_server` scenario ("Well-Configured or Reputation-Bearing Server") text now states that a
  *cold* well-configured server (valid PTR/SPF/DKIM for its own domain) is still filed as **spam
  by Gmail even at `p=none` / no-DMARC** — configuration clears authentication, not inbox
  placement. The same unaligned spoof (`FORGED_SENDER`) routed through a **reputation-bearing
  shared/relay host** (example: AlwaysData's outbound pool) reaches the Gmail **inbox** at
  no-DMARC / `p=none`, **spam** at `p=quarantine`, **rejected** at `p=reject` (Rspamd ≈ −1.1 /
  −0.1 / +1.4 / +3.9). README gains the per-policy relay table.
- **SendGrid `web_ui` measured with no DMARC record (2026-10-31).** New `by_dmarc.absent` entry:
  Rspamd scores it lower (`DMARC_NA` +0.5 < `p=none` +1.5), but Gmail still files it as **spam** —
  SendGrid's mixed bulk-IP reputation dominates the no-DMARC relief. The README SendGrid table's
  `absent` row is now measured (was "not tested"): Medium / Medium / **Moderate**.
- **Removed the "Attack Vectors Detail" sheet** (and its per-vector `Status` / CONFIRMED
  column): the scenario sheets **All Attack Scenarios** and **External Attacks** carry the
  needed information, with the **Attack Modes** column summarising the vectors.
- **A confirmed vector now scores probability High** (it was tested and works today) instead
  of its generic default, so e.g. AlwaysData's authenticated `smtp_server` is High / Critical
  like the Local MTA, not Medium / High. A dated `soften` test that sets its own likelihood
  still wins; `blocked` stays Very Low.
- **SMTP transport made explicit.** Vectors carry `port` and `transport`: authenticated
  `smtp_server` = submission 587/465 `client_to_server`; open relay (`auth_mode: none`) and
  `network` = port 25 `server_to_server` (the sender acts as an MTA — reverse DNS / PTR and
  HELO expected); `local_script` = the host's local MTA. Shown in the **Attack Modes** column
  (e.g. *Shared SMTP Server (587/465)*) and documented in the README.
- **SendGrid `web_ui` rated per DMARC policy** — new dated test (2026-10-30, supersedes
  2026-10-29), one domain per policy: `p=none` Medium / Moderate, `p=quarantine` Medium / Low
  (Gmail shows a "not authenticated" warning, so the impact drops), `p=reject` Low / Low (never
  received on Gmail). Tests with effect `soften` accept a `by_dmarc` block (`likelihood`,
  `impact`, `probability`, `note`).
- **Service spoofing texts** — the description no longer announces fixed levels (it said
  CRITICAL / HIGH / MEDIUM whatever the report showed), and the remediation depends on the
  DMARC policy: it no longer tells a `p=reject` domain to enforce `p=reject`.
- **DKIM key rule is now RSA-specific**, following `mail_antispoof_policy_checker`: rule
  `DKIM_WEAK_KEY` → `DKIM_RSA_WEAK_KEY`, triggered by `dkim_rsa_weak_key`. An Ed25519 or EC key
  can no longer trigger the "factor the RSA modulus" scenario. Excel: **Key Type** column in
  the DKIM Records sheet.
- **MITM scenarios corrected.**
  - *Fake Certificate* wrongly assumed that, without DANE, senders validate the MX certificate
    against the Web PKI (so a CA compromise was needed, Low). Without MTA-STS enforce or
    usable DANE, opportunistic senders accept **any** certificate. Now two cases:
    **TLS Interception with an Attacker Certificate (no certificate validation required)**
    (no MTA-STS enforce, no usable DANE: Medium / High), or **Fraudulent CA-Issued
    Certificate** (MTA-STS enforce, no DANE: Low / Moderate).
  - *TLSA without DNSSEC* said attackers spoof the TLSA records; DANE senders actually
    ignore non-DNSSEC TLSA (RFC 7672), so the MX simply has no DANE. Text fixed. It also
    counts as "no usable DANE" for the certificate scenario.
  - SSL stripping: probability lowered to Low when the MX has usable DANE (DANE-aware
    senders refuse the downgrade). MTA-STS `testing` / `none` is now rated like an absent
    policy (Medium, was Low): senders still deliver when TLS fails, TLS-RPT only reports.
  - TLSA without DNSSEC: Low (was Medium) when MTA-STS enforce protects the domain.
  - Full MTA-STS × DANE probability matrix documented in the README and tested.
  - Texts no longer say senders "always" fall back: only opportunistic senders without a
    local TLS policy do. End-to-end encrypted content stays encrypted.
  - Conditions split into **Measured** vs **Assumed (not tested)**.
  - Bypass columns read **N/A (transport attack)**, with the DKIM / DMARC-via-SPF nuance
    in the notes.
  - Service column: **SMTP (TCP 25)**.
  - Remediations detail the MTA-STS TXT record, the policy fields, per-domain publishing
    and TLS-RPT (visibility only), plus DANE: DNSSEC on the recipient zone and on the MX
    zone, `3 1 1`, and key rollover.
  - Tests: `tests/test_mitm_scenarios.py`.
- **"Risk" → "Risk Level" everywhere.** Excel: *Risk* → **Risk Level**, *Scenario Risk*
  → **Scenario Risk Level**, Summary *Critical Risk*… → **Critical Risk Level**…; JSON:
  `risk` → **`risk_level`** (scenarios and vectors), `scenario_count_by_risk` →
  **`scenario_count_by_risk_level`**, `total_scenario_count_by_risk` →
  **`total_scenario_count_by_risk_level`**; console summary. Python attribute / method
  names are unchanged (`AttackScenario.risk`, `scenario_count_by_risk()`).
- **Bypassed controls: certain vs conditional, with explanations.** Scenarios gain
  `conditional_bypasses` (controls defeated only under a condition the audit cannot
  observe) and `bypass_notes` (one line per control: why, or under which condition), next
  to `bypasses` (now: certainly bypassed). Excel scenario sheets: *Bypasses* →
  **Bypassed (certain)** + **Possibly Bypassed** + **Bypass Conditions**; new **Legend**
  sheet; *Attack Vectors Detail* column *DKIM* → **DKIM Signature (observed)** (and its
  column widths fixed). Notes are set for every scenario type (shared hosting: DKIM
  possible if the host signs with the sender domain's key; service in SPF; no DMARC;
  `+all` / `?all` / weak DKIM key; each takeover kind; MITM).
- **Open relay evaluated per domain.** It was tagged "SPF, DMARC bypassed" for every
  domain served by the relay, but SPF only passes when the domain's SPF authorizes the
  relay IP; being the domain's MX is not enough (on example.com, 7 of the 14 domains served
  by `mail.example.com` do not authorize its IP). The relay IP is now matched against the
  resolved SPF IPs / ranges, `+all`, a top-level `mx` and `ptr:` mechanisms (validated PTR).
  Cases: SPF-authorized → **direct SPF/DMARC bypass**, Very High / Critical; not in SPF,
  DMARC not enforced → High / High; not in SPF, DMARC enforced (own or inherited) →
  Low / Moderate; undetermined → Medium / High. **DKIM is
  always "possibly bypassed"**: the relay may sign relayed mail with the domain key
  (OpenDKIM `InternalHosts` too broad, re-injection via 127.0.0.1 after a content filter,
  signer signing whatever the source); the test never sends content. Scenario name now
  states the case; domains are merged per (MX host, case). Relay not in the SPF with
  DMARC not enforced: impact high, probability High → risk level High. `attack_type`
  "Open Relay - Direct Bypass" → **"Open Relay"** (it is not always a direct bypass).
- First unit tests for mail_audit: `tests/test_open_relay_bypass.py`.
- **`<name>_smtp.xlsx` uses smtp_checker's exporter** (`export_domain_results_to_excel`)
  instead of a duplicated copy. Sheets are now Summary / MTA-STS / SMTP Tests / DANE,
  and SMTP Tests and DANE have one row per MX host with an *Email Domains* column (see
  smtp_checker 2.11.0).
- **MX-level scenarios grouped per MX host** — MITM (SSL stripping, fake certificate,
  TLSA without DNSSEC) and open relay scenarios were repeated for every domain sharing
  the same MX. They are now one row per (scenario, MX host): Excel column *Domain* →
  **Target** (MX host for these, domain otherwise) and *MX Host* → **Affected Domains**;
  JSON top-level `mx_scenarios` (`affected_domains`). SSL stripping now carries its MX
  host. Texts re-rendered for the domain list.
- **Open relay scenario never fired** — smtp_checker reports an accepted relay as
  `WARNING` while the issue rule and the Excel *Open Relay* column expected `FAIL`; fixed
  (both accepted). `mail.example.com` now yields the Open Relay scenario.
- **Open relay test depth** — `--open-relay-mode {rcpt,data}` /
  `MailAuditor(open_relay_mode=...)`, passed to smtp_checker (see its CHANGELOG).
- **Probability vs risk level** — the exported `probability` was a severity
  (`critical`…`informational`), which is not a probability. Now three scales:
  impact (low/medium/high/critical), **probability** (`very_low`/`low`/`medium`/`high`/
  `very_high`) and **risk level** (`low`/`moderate`/`high`/`critical`) =
  `risk_matrix[impact][probability]` (new 4×5 matrix). Scenario risk = worst vector risk,
  scenario probability = that vector's probability. JSON: `probability` / `risk` use these
  values, `scenario_count_by_probability` → `scenario_count_by_risk` (also
  `total_scenario_count_by_risk`); new `AttackLikelihood` / `RiskLevel` enums
  (`AttackProbability` is now an internal template baseline only). Excel: *Probability*
  and *Risk* columns with their own labels/colours, Summary counts by risk level
  (Critical / High / Moderate / Low), vector sheet shows *Scenario Risk*, *Impact*,
  *Probability*, *Risk*. MITM vectors get explicit probabilities (same risk levels as
  before), open relay probability Very High (risk Critical); blocked vectors → Very Low.
- **Well-configured attacker server** (`p=none` / absent): probability **Medium**, risk
  **High** (was shown as "CRITICAL" probability at `p=none`): DMARC is still evaluated
  at `p=none` and the attacker server has no sending reputation.
- **MITM naming**: the transport-attack category is now `"MITM"` (was `"Internal"`) in
  JSON (`attack_category`) and Excel; the sheet is renamed **MITM Attacks** (was
  *Internal Attacks*). Code: `AttackCategory.MITM` (`AttackCategory.INTERNAL` kept as a
  deprecated alias). Bundled templates now use `"MITM"`; the legacy `"INTERNAL"` value is
  still accepted.
- **Clearer `attack_type` labels**: `Spoofing - No SPF/DMARC Policy` was used for every
  rule-based scenario, including domains that *do* publish SPF. Now:
  - `Spoofing - No DMARC Enforcement` — well-configured attacker server (DMARC absent /
    `p=none`), e.g. next to a Shared Hosting scenario on `alwaysdatanonedmarc`;
  - `Spoofing - SPF/DKIM Misconfiguration` — `spf_qualifier_rules` (+all, ?all, ~all,
    weak DKIM key) and the critical-SPF-issue scenario;
  - `Spoofing - No SPF/DMARC Policy` — kept only for "no SPF and no DMARC".
  Bypass tags and probabilities are unchanged.
- `-i example.com` (single domain, as documented) failed with "File not found": any
  input with a suffix — i.e. every domain — was taken for a file path. A file is now
  recognised by existence, a path separator or a list extension (`.txt`, `.csv`, `.lst`,
  `.list`).
- **SendGrid `web_ui`** — new dated test (2026-10-29, supersedes 2026-08-06, whose
  `vector` filter used the wrong key `service_type` and therefore never applied): the UI
  works without domain authentication, but `MAIL FROM` stays `bounces@sendgrid.net` →
  `FORGED_SENDER`, no alignment, DMARC fails even at `p=none`; verdict depends on the
  outbound IP reputation (Rspamd 3.2–7.3/11, Gmail spam). Effect `soften`: likelihood
  MEDIUM, scenario MEDIUM. `soften` now accepts `probability`; tests may carry raw
  `observations`.
- **`p=none` wording** — scenarios no longer say "no alignment to satisfy": DMARC is still
  evaluated and scored at `p=none`, only the reject/quarantine instruction is missing.
- `--dkim-selector-file`: a missing file is now an error (it was silently replaced by
  the bundled list); the number of selectors loaded and the file used are logged.

### Fixed

- **Domains without MX tested as their own mail server.** smtp_checker auto-detected
  `dangling.example.com` (NXDOMAIN) and `sendgrid.example.com` (no MX, no A) as MX
  hostnames, hence two "SMTP Connection — DNS resolution failed" rows in *SMTP Tests*
  under fake MX hosts. mail_audit now runs smtp_checker with `target_type="domain"`: these
  domains have no SMTP row and their **MX Status** says "Domain does not exist (NXDOMAIN)"
  / "No MX, no A/AAAA: cannot receive mail".
- **CLI crash on Windows when output is redirected** (`> file.log`) — the `→` in the
  startup banner raised `UnicodeEncodeError` (cp1252); stdout/stderr now replace
  unencodable characters.
- **MaxMind in async mode** — concurrent SPF checks downloaded the GeoLite2 databases at
  the same time and failed (see mail_antispoof_policy_checker CHANGELOG).

---

## [2.1.1] - 2026-09-18

### Fixed

- **`AttributeError: 'AttributeError' object has no attribute 'get'` during the
  SPF / DMARC / DKIM phases.** `SPFChecker` / `DMARCChecker` / `DKIMChecker.check_async()`
  return the raised `Exception` instance *inside* their result list when a single domain's
  check fails (documented contract — callers must test `isinstance(item, Exception)`). The
  auditor result loops did not, so on a failing domain they called `res.get("domain", "")`
  on the exception object, raising a **new** `AttributeError` that both masked the real
  error and aborted the entire check phase for the batch. The three loops now skip
  exception items, keep processing the remaining domains, and log the real error type /
  message **and the offending domain** (e.g. `[SPF  ] WARNING: check failed for <domain>:
  <Type>: <msg>`).

---

## [2.1.0] - 2026-08-08

### Added

#### Three DMARC-bypass scenarios tied to `mail_antispoof` findings

- **`SPF_PASS_ALL` (`+all`) → CRITICAL, DMARC-independent.** With `+all`, an attacker
  who sets `MAIL FROM` = `From` = the victim domain gets an SPF *pass* AND alignment,
  so DMARC passes on the SPF branch **even under `p=reject`**. Replaces the two
  DMARC-gated `SPF_PASS_NO_DMARC` / `SPF_PASS_LAX_DMARC` rules (which under-rated it as
  `HIGH` and only fired with weak DMARC). Bypasses SPF + DMARC.
- **`SPF_NEUTRAL_ALL` (`?all`) → HIGH.** `?all` returns SPF *neutral* (no assertion),
  treated like no SPF. Impact `critical` / likelihood `medium` — neutral is not a
  `pass`, so it does not force DMARC alignment by itself. Bypasses SPF.
- **`DKIM_WEAK_KEY` (< 1024-bit RSA) → CRITICAL, DMARC-independent.** A sub-1024-bit
  DKIM key can be factored (e.g. CADO-NFS); the recovered private key signs a forged
  message as `d={domain}`, so DKIM passes AND aligns → DMARC passes even under
  `p=reject`, regardless of SPF. Bypasses DKIM + DMARC.

### Fixed

- **`_has_issue` never mapped `dkim`** → DKIM issues (e.g. `dkim_weak_key`) could not
  be detected by scenario rules. Added `self.dkim_result` to the lookup map.

### Changed

- Scenario templates can now declare an explicit `bypasses` tag and per-vector
  `impact` / `likelihood` (read by `_make_scenario` / `_build_vectors`); the
  attack-type-derived bypass is only a fallback.
- **Packaging:** removed the unpublished sibling packages (`smtp-checker`,
  `mail-antispoof-policy-checker`) from `dependencies`. They are local editable
  installs, not on any package index, so declaring them made `pip install -e
  mail_audit/` try to resolve them from PyPI. The install-order contract in the
  README (smtp_checker → mail_antispoof_policy_checker → mail_audit) now stands
  as the sole guarantee that the sibling imports resolve. `pandas` / `openpyxl`
  remain declared (real PyPI dependencies).

---

## [2.0.0] - 2026-08-06

Major rework of the external-spoofing engine: a two-axis **risk** model, a
DMARC-state-aware model driven by **alignment vs reputation**, a dated-test
override system, a revised vector taxonomy, and a renamed vector field.

### Added

- **Two-axis risk model — `risk = impact × likelihood`.** Each `AttackVector` now
  carries `impact` (severity if the technique delivers a spoof), `likelihood` (how
  likely it works today), and a derived `risk`; each `AttackScenario` carries a
  `risk` (worst risk across its vectors). Data-driven via `risk_matrix` and
  `vector_defaults` in `scenario_templates.json`.
- **`bypasses` per scenario** — which of SPF / DKIM / DMARC the scenario defeats
  (Shared Hosting / Open Relay → SPF, DMARC; well-configured server → SPF, DKIM;
  service in SPF → SPF). DKIM is *not* padded in when it is only trivial or
  present-but-misaligned.
- **`dkim` per vector** — the actual signature the mail carries (e.g.
  `sendgrid.net:s=smtpapi`, `alwaysdata.net:s=default`); usually not aligned, so
  recorded as information rather than a headline bypass.
- **Dated-test override folder** `lib/data/tests/*.json` (one JSON file per test;
  effects `confirm` / `downgrade` / `soften` / `eliminate`; fields incl. `vector`
  filter, `likelihood`, `probability`, `note`, `source`). `email_services.json`
  now holds only the generic per-service baseline; tests refine it.
- **DMARC policy granularity** — `p=quarantine` is handled separately from
  `p=reject` (read from `dmarc_result.policy`): quarantine only sends the spoof to
  spam (reputation can still inbox it), reject actually stops it.
- **Excel export**: `Risk` + `Bypasses` columns (scenarios); `Impact`,
  `Likelihood`, `Risk`, `DKIM` columns (vector detail).

### Changed

- **External spoofing driven by `f(vector, DMARC state)`** (supersedes the earlier
  flat / all-`CRITICAL` approaches):
  - **Shared Hosting** aligns the `MAIL FROM` on an SPF-listed host → DMARC passes
    **even at `p=reject`** (DMARC-independent). Default **HIGH** (untested),
    **CRITICAL** once confirmed, **LOW** if a test shows the host verifies the
    `MAIL FROM`.
  - **Service in the victim's SPF** (SendGrid, Gmail…) — forged From not aligned,
    but reputation + From-domain SPF match let it land: `p=none` → **CRITICAL**
    (reputation-boosted, > home server), absent / `p=quarantine` → **HIGH**,
    `p=reject` → **LOW**.
  - **Well-configured attacker server** (IP not in SPF) — `p=none` → HIGH, absent →
    HIGH; **blocked once DMARC is enforced**.
  - `p=none` > absent throughout. Open relay remains `CRITICAL`.
- **Scoring principle**: a generic (untested) rule never scores below `MEDIUM` (an
  un-audited third party is assumed exploitable); only a **dated test** reaches `LOW`,
  and the scenario stays at `LOW` (not removed) because a provider can regress —
  `eliminate` is reserved for vectors that structurally no longer exist.
- **Dated tests**: `2026-08-03` OVH → `LOW` (verifies MAIL FROM), AlwaysData →
  `CRITICAL` (local MTA), Outlook.com forwarding → `eliminate` (MFEF → SRS);
  `2026-08-06` SendGrid / Brevo / Mailjet (`web_ui` domain auth, `smtp_server`
  MAIL FROM ownership).
- Docs: `README.md` fully reworked; `Slides.md` S-46/S-48/S-49/S-55/S-56 synced.

### Breaking

- **Vector field renamed `service_type` → `vector_type`** across `AttackVector`
  (and its `to_dict`), `email_services.json`, `scenario_templates.json` and the test
  filters. Disambiguates the vector's technical channel from a mail service's
  category (which keeps `service_type`: *Email Delivery Service*, *Free Mail
  Provider*, *Shared Hosting*). The `network` value is now correctly a `vector_type`,
  not a "service type".
- **Vector taxonomy revised** (`vector_taxonomy.json`, documentation-only reference):
  new vector_type `http_api`; new auth_modes `oauth_token`,
  `trusted_local_submission` (replaces `local_mta`), `none` (open relay / no-policy),
  `not_applicable` (replaces the former `null` for `network`). `models.AttackVector`
  `_AUTH_REQUIRED_MODES` updated accordingly.

---

## [1.2.0] - 2026-04-15

### Added

#### Offline and hybrid operating modes (`--smtp-json` / `--antispoof-json`)

`mail_audit` can now consume pre-computed checker outputs instead of running
checks live.  Four operating modes are supported:

| Mode | How to invoke | Network calls |
|---|---|---|
| Full online (default) | `-i domains.txt` | SMTP + DNS |
| SMTP offline | `-i domains.txt --smtp-json smtp.json` | DNS only |
| Antispoof offline | `-i domains.txt --antispoof-json antispoof.json` | SMTP only |
| Fully offline | `--smtp-json smtp.json --antispoof-json antispoof.json` | None |

- **`--smtp-json FILE`** — load smtp_checker results from a JSON file.
  Accepts `mail_audit` `_smtp.json` output or `smtp_checker` native JSON.
  SMTP checks are skipped entirely when this flag is set.
- **`--antispoof-json FILE`** — load SPF/DMARC/DKIM results from a JSON file.
  Accepts `mail_audit` `_antispoof.json` output or
  `mail_antispoof_policy_checker` native `policy_check_*.json`.
  Antispoof checks are skipped entirely when this flag is set.
- **`-i` is now optional** when at least one JSON file is provided.
  Domains are derived automatically from the JSON files
  (antispoof `"domain"` key first, smtp `"target"` key as fallback).
- `MailAuditor.__init__` gains two new optional parameters:
  `smtp_json_path: Optional[str]` and `antispoof_json_path: Optional[str]`.
- `MailAuditor._load_smtp_json()` and `MailAuditor._load_antispoof_json()`
  static methods for loading and normalising each format.
- `_domains_from_json()` helper in `cli.py` for deriving the domain list
  from JSON files when `-i` is omitted.

#### Real-time progress reporting

All checker phases now print progress lines to stderr so it is always clear
which domain and which check is currently running:

```
[mail-audit] [SMTP ] example.com | starting (MTA-STS, DANE, STARTTLS, open relay: ...)...
[mail-audit] [SPF  ] example.com | checking...
[mail-audit] [DMARC] example.com | checking...
[mail-audit] [DKIM ] example.com | checking...
[mail-audit] [SPF  ] example.com | done
[mail-audit] [DMARC] example.com | done
[mail-audit] [DKIM ] example.com | done
[mail-audit] [SMTP ] example.com | done (N MX host(s) checked)
```

When multiple domains are processed, the label shows `N domain(s)` instead
of an individual domain name.  Offline phases print a single "Loaded N
result(s) from …" line instead.

#### Input validation: file-not-found error for `-i`

Previously, passing a non-existent filename like `hostname.txt` to `-i` would
silently treat it as a domain name.  The CLI now detects inputs that look like
file paths (have an extension or path separator) and raises a clear error:

```
ERROR: File not found: /path/to/hostname.txt
```

### Changed

- `run_async()` restructured to support the four operating modes cleanly —
  coroutines are created only for phases that need to run online; both are
  gathered concurrently when both are needed.
- Startup info line now shows `antispoof=offline (loaded from ...)` or
  `smtp=offline (loaded from ...)` when the corresponding JSON file is used.

---

## [1.1.0] - 2026-04-01

### Added

#### `lib/data/scenario_templates.json` — single source of truth for all scenarios
- All scenario metadata (names, descriptions, conditions text, remediations,
  attack vectors, probability rules) moved out of Python into a JSON file.
- Python owns **only condition evaluation logic** — zero hardcoded strings remain
  in `attack_scenarios.py`.
- Structure: `internal_mitm` / `external_spoofing` / `open_relay` top-level keys.
- `external_spoofing` includes `service_type_attack_type` and
  `service_type_probability` tables (previously hardcoded `if/elif` chains).
- `spf_qualifier_rules` array inside `external_spoofing` drives the four new
  SPF qualifier scenarios.

#### Template rendering helpers in `AttackScenarioAnalyzer`
- `_render(template, **ctx)` — replaces `{key}` placeholders with runtime values.
- `_render_list(templates, **ctx)` — renders a list of condition strings.
- `_build_vectors(vector_templates, **ctx)` — instantiates `AttackVector` objects
  from JSON vector definitions with placeholder substitution.
- `_make_scenario(tpl, prob, **ctx)` — assembles a full `AttackScenario` from a
  template dict + runtime context dict.

#### New attack scenarios — SPF qualifier + DMARC policy combinations
- **SPF Pass All (`+all`) + No DMARC** → `HIGH`
- **SPF Pass All (`+all`) + DMARC `p=none`** → `HIGH`
- **SPF SoftFail (`~all`) + No DMARC** → `MEDIUM`
- **SPF SoftFail (`~all`) + DMARC `p=none`** → `MEDIUM`

All four fire in addition to existing service-specific scenarios.
`_extract_spf_all_qualifier()` parses the `all` mechanism qualifier from the
raw SPF record (returns `"+all"`, `"~all"`, `"-all"`, `"?all"`, or `None`).

### Changed
- `attack_scenarios.py` fully refactored: all `_check_*` and `_build_*` methods
  now call `_make_scenario()` with a template dict from JSON.
- `service_type_attack_type` and `service_type_probability` lookups read from JSON.
- Module-level imports consolidated (`json`, `re`, `pathlib.Path`).
- `scenario_rules.csv` removed — superseded by `scenario_templates.json`.

---

## [1.1.3] - 2026-04-04

### Added

- **`--no-smtp` CLI flag** — skip smtp_checker entirely for fast policy-only audits
  or when port 25 is blocked.

  ```
  python cli.py -i example.com --no-smtp
  ```

  - No SMTP connections are made; MITM and open-relay scenarios are not generated.
  - The `_smtp.json` / `_smtp.xlsx` export files are not written.
  - Implemented as `skip_smtp: bool = False` on `MailAuditor`; `run_async()` bypasses
    `_run_smtp_async()` and passes an empty smtp_results list to `_build_audit_result()`.

- **`--no-open-relay` CLI flag** — disable only the open relay test while keeping
  all other SMTP checks (MTA-STS, DANE, STARTTLS, certificate validation…).

  ```
  python cli.py -i example.com --no-open-relay
  ```

  - Sets `smtp_options["smtp_open_relay"] = False` after loading the smtp-options file
    (if any), so it stacks with other per-test overrides from `--smtp-options FILE.json`.
  - Useful when a valid external RCPT TO address is not configured or when the open
    relay test is considered too intrusive.

- **`--smtp-options` help text** — expanded to list the accepted keys explicitly.

### Changed

- **`MailAuditor.DEFAULT_OPEN_RELAY_SENDER` / `DEFAULT_OPEN_RELAY_RECIPIENT` → `None`**

  The open relay test no longer has built-in default addresses.  If either
  `open_relay_sender` or `open_relay_recipient` is `None` at init time,
  `smtp_options["smtp_open_relay"]` is forced to `False` and an INFO message
  is printed to stderr.  This prevents silent SKIPPED results and makes the
  requirement for a valid sender/recipient explicit.

  **Before**: test ran silently with hardcoded dummy addresses;
  smtp_checker would return `"SKIPPED"` if they were invalid.

  **After**: test is disabled at the `MailAuditor` level with a clear log
  message when not configured.  Pass `--sender` + `--recipient` to enable it.

- **`--sender` / `--recipient` CLI arguments** — default changed from
  `"test@example.net"` / `"osef@domain.com"` to `None`.
  Help text updated to document that the open relay test is disabled when either
  is absent.  Startup print shows sender → recipient when configured.

---

## [1.1.2] - 2026-04-01

### Changed

#### String slug issue codes — end-to-end (all three modules)

- `lib/data/scenario_templates.json` `spf_qualifier_rules` `condition_issue_codes`:
  - `module` field removed — slugs are globally unique, no namespace needed.
  - Integer `code` values replaced by string slugs:
    - SPF_PASS_NO_DMARC:    `3` → `"spf_pass"`,  `100` → `"no_dmarc"`
    - SPF_PASS_LAX_DMARC:   `3` → `"spf_pass"`,  `101` → `"dmarc_lax_policy"`
    - SPF_SOFTFAIL_NO_DMARC:`4` → `"spf_softfail"`, `100` → `"no_dmarc"`
    - SPF_SOFTFAIL_LAX_DMARC:`4` → `"spf_softfail"`, `101` → `"dmarc_lax_policy"`

- `lib/attack_scenarios.py` — all integer issue code references replaced by slugs:
  - `_has_issue("smtp", 9)` → `_has_issue("smtp", "mta_sts_missing")`
  - `_has_issue("smtp", 10)` → `_has_issue("smtp", "mta_sts_non_enforce")`
  - `_mx_has_issue(mx, 11)` → `_mx_has_issue(mx, "dane_no_tlsa")`
  - `_mx_has_issue(mx, 12)` → `_mx_has_issue(mx, "tlsa_no_dnssec")`
  - `_has_issue("dmarc", 100)` → `_has_issue("dmarc", "no_dmarc")`
  - `_has_issue("dmarc", 101)` → `_has_issue("dmarc", "dmarc_lax_policy")`
  - `_mx_has_issue(mx, 4)` → `_mx_has_issue(mx, "smtp_open_relay")`
  - `_has_issue()` / `_mx_has_issue()` parameter types changed from `int` to `str`.

### Removed

- `lib/data/issue_codes.csv` — superseded by the slug approach.
  `mail_audit` reads issue codes directly from the checker result dicts;
  a cross-module reference table is no longer needed.

---

## [1.1.1] - 2026-04-01

### Added

#### Issue code system — `(module, code)` namespaced condition evaluation
- `lib/data/issue_codes.csv` — cross-module reference table listing every
  `(module, result_key, issue_code)` triplet that `mail_audit` uses for
  scenario condition evaluation.  Columns: `module`, `result_key`,
  `issue_code`, `issue_title`, `condition_name`, `scope`, `notes`.
- `AttackScenarioAnalyzer._has_issue(result_key, code)` — checks domain-level
  issues in the named checker result dict (`"spf"`, `"dmarc"`, `"smtp"`).
- `AttackScenarioAnalyzer._mx_has_issue(mx_result, code)` — checks per-MX
  issues in an individual `mx_results` entry.

#### All condition checks now use issue codes — no more field parsing
- `_analyze_external_spoofing()`: DMARC gate replaced by
  `_has_issue("dmarc", 100)` (No DMARC) and `_has_issue("dmarc", 101)` (p=none).
- `_check_ssl_stripping()`: replaced field inspection with
  `_has_issue("smtp", 9)` (absent) and `_has_issue("smtp", 10)` (non-enforce).
- `_check_dane_fake_cert()`: replaced field inspection with `_mx_has_issue(mx, 11)`.
- `_check_tlsa_without_dnssec()`: replaced with `_mx_has_issue(mx, 12)`.
- `_analyze_open_relay()`: replaced `status == "FAIL"` check with `_mx_has_issue(mx, 4)`.
- `_analyze_spf_qualifier_rules()`: `condition_spf_qualifier` / `condition_dmarc_policy`
  keys replaced by `condition_issue_codes` array in `scenario_templates.json`;
  Python evaluates via `_has_issue()` — no more raw SPF string parsing.
  - `_extract_spf_all_qualifier()` removed.

### Changed
- `scenario_templates.json` `spf_qualifier_rules`: each rule now declares
  `condition_issue_codes` (array of `{module, result_key, code}` objects)
  instead of `condition_spf_qualifier` + `condition_dmarc_policy` strings.
  - SPF_PASS_NO_DMARC  → codes spf:3 + dmarc:100
  - SPF_PASS_LAX_DMARC → codes spf:3 + dmarc:101
  - SPF_SOFTFAIL_NO_DMARC  → codes spf:4 + dmarc:100
  - SPF_SOFTFAIL_LAX_DMARC → codes spf:4 + dmarc:101

---

## [1.0.0] - 2026-03-24

### Added

#### Core orchestration
- `MailAuditor` class that concurrently runs `smtp_checker` (DomainChecker) and
  `mail_antispoof_policy_checker` (SPFChecker, DMARCChecker, DKIMChecker) using `asyncio`.
- Synchronous `run()` and asynchronous `run_async()` execution modes.
- `run_and_export()` / `run_and_export_async()` convenience methods.
- `export()` method producing both JSON and Excel output files.
- `print_summary()` method for concise terminal output.
- `importlib`-based sibling module loading to avoid `lib` package name collisions
  between `smtp_checker`, `mail_antispoof_policy_checker`, and `mail_audit`.

#### Attack scenario analysis (`attack_scenarios.py`)
- `AttackScenarioAnalyzer` class that synthesises checker outputs into actionable
  attack scenarios.
- **Internal MITM scenarios:**
  - *STARTTLS Downgrade / SSL Stripping* — triggered when MTA-STS is absent (HIGH)
    or present but not in `enforce` mode (MEDIUM).
  - *Fake Certificate Attack* — triggered when an MX has no TLSA records (MEDIUM).
  - *TLSA Records without DNSSEC* — triggered when TLSA is present but DNSSEC is
    invalid on the MX zone, negating DANE protection (HIGH).
- **External spoofing scenarios:**
  - Per-service spoofing scenarios matched from SPF includes against
    `email_services.json` keywords.  Probability is the maximum of the DMARC
    weakness (CRITICAL for absent, HIGH for `none`) and the service base rating.
  - *No SPF or DMARC* — direct spoofing with no technical barrier (CRITICAL).
  - *Critical SPF misconfiguration* — overly permissive SPF combined with weak
    DMARC (HIGH).
- **Open Relay scenarios:**
  - One CRITICAL scenario per MX that accepted RCPT TO without authentication,
    noting that this bypasses SPF/DMARC entirely.
- Service matching helper `_match_service()` for SPF include → service lookups.

#### Email services database (`lib/data/email_services.json`)
- Curated database of known email services with spoofing vectors, including:
  - **SendGrid** — web UI arbitrary From (verified), SMTP API key (verified),
    SMTP credentials (verified).
  - **Gmail / Google Workspace** — App Password SMTP (verified), Send-as alias
    (potential).
  - **Outlook.com / Hotmail** — SMTP with credentials (verified), forwarding
    rule / alias (verified).
  - **OVH Shared Hosting** — SMTP with credentials (verified), PHP `mail()`
    via local MTA (verified).
  - **Mailjet** — web UI (potential/unverified), SMTP API key (potential).
  - **Amazon SES** — SMTP API key (potential), web UI (potential).
  - **Mailchimp / Mandrill** — SMTP API key (potential).
  - **Postmark** — SMTP API key (potential).
  - **SparkPost** — SMTP API key (potential).
  - **Brevo (Sendinblue)** — SMTP API key (potential), web UI (potential).
- `verified` flag per attack vector distinguishes confirmed from potential vectors.
- Extensible: add new services by editing the JSON or passing `--email-services`.

#### Data models (`lib/models.py`)
- `AttackVector` — single exploitable technique with `service_type`, `auth_mode`,
  `description`, `verified`, `steps`, `probability_note`.
- `AttackScenario` — complete scenario with category, type, probability, conditions,
  vectors, and remediation advice.
- `DomainAudit` — per-domain container for raw checker outputs and derived scenarios.
- `AuditResult` — top-level result for all domains.
- `AttackCategory` enum: `Internal`, `External`.
- `AttackType` enum: 8 attack types covering MITM, spoofing, and open relay.
- `AttackProbability` enum: `critical`, `high`, `medium`, `low`, `informational`.

#### Excel exporter (`lib/excel_exporter.py`)
- 7-sheet colour-coded workbook via `openpyxl`:
  - *Summary* — per-domain KPIs (scenario counts, DMARC, MTA-STS, Open Relay, DANE).
  - *All Attack Scenarios* — all scenarios sorted by severity.
  - *Internal Attacks* — MITM scenarios only.
  - *External Attacks* — Spoofing and Open Relay scenarios only.
  - *Attack Vectors Detail* — one row per attack vector with steps.
  - *SMTP Results* — raw smtp_checker output per MX.
  - *AntiSpoof Results* — raw SPF/DMARC/DKIM data per domain.
- Colour coding: red (critical), orange (high), yellow (medium), light blue (low),
  light grey (informational).
- Frozen header rows, auto column widths, bold headers with dark-blue fill.

#### CLI (`cli.py`)
- Full `argparse` CLI with grouped options:
  - Input (`-i / --input`): single domain, comma-separated list, or file path.
  - SMTP options: `--port`, `--timeout`, `--dns-timeout`, `--nameservers`,
    `--sender`, `--recipient`, `--smtp-options`.
  - AntiSpoof options: `--check-types`, `--dns-server`, `--antispoof-dns-timeout`,
    `--use-ns-record`, `--max-dns-retries`, `--data-dir`, `--maxmind-key`,
    `--dkim-selector-file`.
  - Execution: `--sync-mode` (default), `--async-mode`, `--max-concurrent`,
    `--max-smtp`, `--max-dns`.
  - Output: `-o / --output`, `--output-dir`, `--email-services`.
- Terminal summary showing per-domain and total scenario counts by severity.
- Graceful KeyboardInterrupt handling (exit code 130).

#### Project files
- `pyproject.toml` for all three modules (`mail_audit`, `smtp_checker`,
  `mail_antispoof_policy_checker`) with `setuptools` backend, pinned dependencies,
  and optional `[maxmind]` extras.
- `README.md`, `CHANGELOG.md`, `TODOLIST.md`.

---

[1.0.0]: https://github.com/your-org/mail-audit/releases/tag/v1.0.0
