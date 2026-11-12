# mail_audit

A combined mail security auditing tool that orchestrates two specialised checkers:

- **smtp_checker** - Tests SMTP server security: STARTTLS, STARTTLS downgrade resistance, DANE/TLSA, MTA-STS, DNSSEC, certificate validation, and SMTP open relay.
- **mail_antispoof_policy_checker** - Analyses anti-spoofing DNS policies: SPF record depth analysis, DMARC policy enforcement, DKIM selector discovery, and broken / hijackable CNAME aliases at the DKIM, DMARC and SPF lookup names.

After running both checkers, `mail_audit` synthesises the results into **attack scenarios**: concrete, exploitable weaknesses with a **probability** (Very Low → Very High) and a **risk level** (Low → Critical), technical attack vectors (verified or potential), and remediation guidance.

Results are exported to:
- A structured **JSON** file with all raw checker data and derived scenarios.
- A colour-coded **Excel workbook** with multiple sheets for easy review during security assessments.

---

## Attack Scenario Categories

### MITM Attacks

`attack_category` = `"MITM"`: transport-level attacks on the SMTP connection between the
sending server and the MX (an on-path attacker on the Internet path, not an "internal"
attacker). Scenario templates may still use the legacy value `"INTERNAL"`, read as `"MITM"`.

Impact **High** (mail interception or modification) for all. Every MITM scenario needs an
**on-path position** between a sending MTA and the MX, which the audit cannot test. So
**Conditions Met** separates what is **Measured** (DNS / SMTP results) from what is
**Assumed (not tested)** (on-path position, sender behaviour). These are potential
scenarios, not demonstrated attacks. Service: `SMTP (TCP 25)`. The bypass columns read
**N/A (transport attack)**: SPF / DKIM / DMARC are not bypassed. If the attacker modifies
DKIM-signed parts, DKIM fails, but DMARC can still pass through an aligned SPF pass, because
the attacker relays the original session from the sender's IP.

What the sender checks decides which attack works ("usable DANE" = TLSA records matching
the certificate **and** DNSSEC-validated):

| Recipient side | Sender behaviour | What the attacker needs |
|---|---|---|
| No MTA-STS `enforce`, no usable DANE | Opportunistic STARTTLS (RFC 7435): TLS if offered, **certificate not authenticated** | Strip STARTTLS, **or** present any certificate (self-signed is enough, **no CA compromise**) |
| MTA-STS `enforce` (no DANE) | Compatible senders require TLS + a Web PKI-valid certificate for the listed MX (once the policy is cached) | A **publicly trusted** certificate for the MX (mis-issuance, CA compromise) |
| Usable DANE | DANE-aware senders require TLS + the pinned certificate | Nothing works against DANE-aware senders; the others stay opportunistic |

| Scenario | Trigger (measured) | Probability | Risk Level |
|---|---|---|---|
| STARTTLS Downgrade / SSL Stripping | MTA-STS absent / invalid, or in `testing` / `none` mode | Medium | High |
| STARTTLS Downgrade / SSL Stripping | as above, but the MX has usable DANE (DANE-aware senders refuse it) | Low | Moderate |
| TLS Interception with an Attacker Certificate (no certificate validation required) | No MTA-STS `enforce` **and** no usable DANE | Medium | High |
| Fraudulent CA-Issued Certificate (MTA-STS enforce, no DANE) | MTA-STS `enforce`, no usable DANE: residual PKIX risk | Low | Moderate |
| TLSA Records Without DNSSEC (DANE ignored) | TLSA present but not DNSSEC-validated: DANE senders ignore them (RFC 7672), the MX has no DANE | Medium (Low with MTA-STS `enforce`) | High (Moderate) |

Probability is driven by the prerequisites: the on-path position is common to all; then
"strip STARTTLS / any certificate" (Medium) is far easier than "obtain a publicly trusted
certificate for the MX" (Low).

Full matrix (MTA-STS state of the recipient domain × DANE state of its MX), as produced by
the analyzer. It is checked by `tests/test_mitm_scenarios.py::test_probability_matrix`.

| MTA-STS | DANE on the MX | MITM scenarios → Probability / Risk Level |
|---|---|---|
| absent / invalid | no TLSA | SSL Stripping Medium / High · Attacker Certificate Medium / High |
| absent / invalid | TLSA not DNSSEC-validated | SSL Stripping Medium / High · Attacker Certificate Medium / High · TLSA Without DNSSEC Medium / High |
| absent / invalid | usable DANE | SSL Stripping **Low** / Moderate (DANE-aware senders refuse it) |
| `testing` / `none` | no TLSA | SSL Stripping Medium / High · Attacker Certificate Medium / High |
| `testing` / `none` | TLSA not DNSSEC-validated | SSL Stripping Medium / High · Attacker Certificate Medium / High · TLSA Without DNSSEC Medium / High |
| `testing` / `none` | usable DANE | SSL Stripping **Low** / Moderate |
| `enforce` | no TLSA | Fraudulent CA-Issued Certificate **Low** / Moderate |
| `enforce` | TLSA not DNSSEC-validated | Fraudulent CA-Issued Certificate **Low** / Moderate · TLSA Without DNSSEC **Low** / Moderate |
| `enforce` | usable DANE | none |

`testing` mode is rated like an absent policy: senders still deliver when TLS fails, so
the attacks work; TLS-RPT reports can only reveal them afterwards.

Remediations include the full MTA-STS setup:
- `_mta-sts.<domain>` TXT with an `id`;
- a policy served over HTTPS with `version`, `mode: enforce`, `mx` and `max_age`, for
  **each** recipient domain, since there is no inheritance from a parent domain;
- TLS-RPT for visibility (it does not block anything).

And DANE: DNSSEC on both the recipient domain zone (authenticated MX lookup) and the MX
zone, `TLSA 3 1 1`, and publishing the next key before each rotation.

### External Attacks (Spoofing)

**Risk = Impact × Probability.** Three distinct scales:

| Scale | Values | Meaning |
|---|---|---|
| **Impact** | Low · Medium · High · Critical | severity IF the technique works (how much control it gives) |
| **Probability** | Very Low · Low · Medium · High · Very High | how likely the technique actually works today (JSON field `likelihood` on a vector, `probability` on a scenario) |
| **Risk level** | Low · Moderate · High · Critical | `risk_matrix[impact][probability]` |

A probability is **never** "Critical" — only the risk level is.

| Impact \ Probability | Very Low | Low | Medium | High | Very High |
|---|---|---|---|---|---|
| **Critical** | Low | Moderate | High | Critical | Critical |
| **High** | Low | Moderate | High | High | Critical |
| **Medium** | Low | Low | Moderate | High | High |
| **Low** | Low | Low | Low | Moderate | Moderate |

Each attack *vector* gets its impact and probability (defaults below, then template / dated tests), hence its risk. A scenario's **risk** = the worst vector risk and its **probability** = the probability of that vector. Everything lives in `scenario_templates.json` (`risk_matrix`, `vector_defaults`); each scenario is also tagged with the controls it **bypasses**.

**Per-technique defaults (`vector_defaults`)**

| Vector technique | Impact | Probability | Why |
|---|---|---|---|
| `web_ui` | Medium | High | reachable, but restricted — usually cannot set the `MAIL FROM` |
| `smtp_server` | Critical | Medium | authenticated **submission**, client→server on **587 / 465** (the attacker logs in with an account and sets the `MAIL FROM`); a shared / mutualised mail server is marked `shared: true`. Direct port **25** (server→server) is the open-relay case, see below |
| `local_script` (local MTA) | Critical | High | full `MAIL FROM` control on a shared host |
| `email_forwarding` | Critical | Medium | MFEF alignment (now mostly dead → SRS) |
| `network` (MITM) | High | per scenario | on-path position required |

A `blocked` status forces probability → Very Low (risk → Low). Dated tests can override impact/probability.

**Which scenarios fire, and their DMARC dependency** (the *probability* axis, `f(vector, DMARC state)`):

- **Shared Hosting** — aligns the `MAIL FROM` on an SPF-listed host, so DMARC actually **passes even at `p=reject`** (DMARC-independent). Risk **High** by default (untested), **Critical** once a test confirms it, **Low** if a test shows the host verifies the `MAIL FROM`.
- **Service in the victim's SPF** (SendGrid, Gmail, Outlook…) — the forged From is **not aligned** (the envelope `MAIL FROM` stays the service's bounce domain, e.g. `bounces@sendgrid.net`; the mail is DKIM-signed by the service, e.g. `sendgrid.net:s=smtpapi`, also not aligned). What it buys is **reputation**: the mail leaves IPs the victim lists in its SPF, so the From-domain SPF matches the sending IP and filters like Proofpoint routinely accept it. Probability follows the DMARC state — and **`p=quarantine` is treated separately from `p=reject`**: quarantine only sends the spoof to spam (reputation can still pull it to the inbox), whereas reject actually stops it. Default (untested service) risk levels:
  - `p=none` → risk **Critical** (reputation-boosted)
  - absent → **High** · `p=quarantine` → **High** (lands in spam / possibly inbox)
  - `p=reject` → **Low**

  Dated tests refine this per service (SendGrid below: Moderate at `p=none`, Low once DMARC is enforced).

  **Rspamd DMARC symbol scores (default metric).** How Rspamd scores the DMARC verdict depends on the policy the victim publishes. A *failing* spoof is penalised **least** when the victim has no DMARC record at all:

  | Rspamd symbol | Score | DMARC outcome |
  |---|---|---|
  | `DMARC_POLICY_ALLOW` | **−1.0** | passes (aligned SPF or DKIM) |
  | `DMARC_NA` | **+0.5** | no DMARC record published |
  | `DMARC_POLICY_SOFTFAIL` | **+1.5** | fails, `p=none` |
  | `DMARC_POLICY_QUARANTINE` | **+3.0** | fails, `p=quarantine` |
  | `DMARC_POLICY_REJECT` | **+5.5** | fails, `p=reject` |

  Counter-intuitively, an **absent** record (`DMARC_NA` +0.5) is scored *lower* than an explicit `p=none` (`DMARC_POLICY_SOFTFAIL` +1.5): for Rspamd, publishing nothing is "cheaper" for the attacker than publishing `p=none`. This only affects the margin — an aligned spoof (AlwaysData, below) earns `DMARC_POLICY_ALLOW` −1 and lands regardless; the scores matter for the unaligned paths (reputable service / attacker server) where delivery turns on the final total. Measured 2026-10-31 on AlwaysData against a **no-DMARC** domain (`data/tests/alwaysdata_local_mta_no_dmarc_20261031.json`): `R_SPF_ALLOW` −1, `R_DKIM_ALLOW` −1 `[alwaysdata.net:s=default]`, `DMARC_NA` +0.5 → net negative → Gmail **inbox** (SPF PASS, DKIM PASS, DMARC FAIL, not spam).

  Whether a service's UI actually lets you spoof the From is a per-service dated-test fact (SendGrid's *Dynamic Templates → Test email* exposes a free From; Brevo/Mailjet require domain authentication first → blocked).

  **`p=none` does not mean "no alignment check".** Receivers still evaluate DMARC and score the failure; only the reject/quarantine instruction is gone. SendGrid test 2026-10-29 (`data/tests/sendgrid_web_ui_test_email_dmarc_evaluation.json`): the web UI keeps the envelope `MAIL FROM` = `bounces@sendgrid.net` (not configurable) → `FORGED_SENDER`, SPF/DKIM not aligned → DMARC fails at every policy (Rspamd `DMARC_POLICY_SOFTFAIL` +1.5 at `p=none`, `DMARC_POLICY_QUARANTINE` +3 at `p=quarantine`). The verdict then depends on the **outbound IP reputation** (`RBL_MAILSPIKE_*` on some SendGrid IPs): default Rspamd 3.2–7.3/11, Gmail **spam even at `p=none`** (plus an "unauthenticated sender … via sendgrid.net" warning at `p=quarantine`). Realistic success path: a target that **whitelists the service's IPs** (e.g. because it uses SendGrid itself).

  SendGrid test 2026-10-30 (`data/tests/sendgrid_web_ui_dmarc_policy_comparison.json`) measured one domain per policy, and `web_ui` is rated per policy (risk = impact × probability):

  | DMARC | Rspamd | Gmail | Probability | Impact | Risk Level |
  |---|---|---|---|---|---|
  | `p=none` | 1.70/11 (`DMARC_POLICY_SOFTFAIL` +1.5) | spam | Medium | Medium | **Moderate** |
  | `p=quarantine` | 7.30/11, spam (`DMARC_POLICY_QUARANTINE` +3) | spam + "not authenticated" warning | Medium | Low | **Low** |
  | `p=reject` | 9.80/11, spam (`DMARC_POLICY_REJECT` +5.5) | never received | Low | Medium | **Low** |
  | absent | low (`DMARC_NA` +0.5) | spam | Medium | Medium | **Moderate** |

  `p=none` and `p=quarantine` both reach the Gmail spam folder, so the warning lowers the **impact** rather than the probability: the reader is told not to trust the message. `p=reject` lowers the **probability**: the message does not arrive. **Absent** DMARC is scored *lower* by Rspamd (`DMARC_NA` +0.5 vs `DMARC_POLICY_SOFTFAIL` +1.5), yet Gmail still files it as **spam** — with a mixed-reputation bulk sender like SendGrid the **outbound-IP reputation**, not the DMARC penalty, decides the Gmail verdict (contrast AlwaysData below, whose clean shared pool reaches the inbox at no-DMARC/`p=none`). The outbound IP varies between sends and can be blacklisted (`RBL_MAILSPIKE_WORST` +2 on `159.183.225.35`), which adds to the score at any policy.
- **Well-configured attacker server** (IP not in SPF) — no enforcing DMARC ⇒ the alignment failure carries no reject/quarantine instruction (it is still evaluated and scored) ⇒ delivered by *permissive* receivers, but with **no sending reputation**; **blocked once DMARC is enforced**. `p=none` or absent → probability **Medium** → risk **High**.

  **Reputation decides the inbox, not configuration.** Being well-configured (valid PTR, and SPF + DKIM for the *attacker's own* domain) only clears authentication and sanity checks. Measured on Gmail, a **cold** attacker server is filed as **spam even at `p=none` / no-DMARC**, because Gmail weighs sending-domain / IP reputation and volume. The outcome changes when the *same* unaligned spoof (From on the victim domain, `MAIL FROM`/SPF/DKIM on the relay → `FORGED_SENDER`, DMARC not aligned) is sent through a **reputation-bearing shared/relay host** (e.g. a shared-hosting outbound pool such as AlwaysData):

  | Victim DMARC | Rspamd (relay) | Gmail |
  |---|---|---|
  | no record | ≈ −1.1 (`DMARC_NA` +0.5) | **inbox** (shown "via `alwaysdata.net`") |
  | `p=none` | ≈ −0.1 (`DMARC_POLICY_SOFTFAIL` +1.5) | **inbox** (shown "via `alwaysdata.net`") |
  | `p=quarantine` | ≈ +1.4 (`DMARC_POLICY_QUARANTINE` +3) | spam |
  | `p=reject` | ≈ +3.9 (`DMARC_POLICY_REJECT` +5.5) | never received |

  So a *cold* well-configured server is not enough for Gmail inbox placement, whereas a reputation-bearing relay lands in the inbox while the victim's DMARC is below `p=quarantine`. The Rspamd total stays negative (inbox) through `p=none` because `R_SPF_ALLOW` −1 and `R_DKIM_ALLOW` −1 (the relay's own aligned SPF/DKIM) offset the DMARC penalty until it reaches `p=quarantine`.
- **Open Relay** — per domain: **Very High** → **Critical** when the relay IP is authorized by the domain's SPF (direct SPF/DMARC bypass); otherwise **High** → High (DMARC not enforced) or **Low** → Moderate (DMARC enforced). See [Open Relay](#open-relay).

**`attack_type` labels of the spoofing scenarios**

| `attack_type` | When | Example scenario |
|---|---|---|
| `Spoofing - Shared Hosting` | A shared-hosting provider is in the SPF | Email Spoofing via AlwaysData (Shared Hosting) |
| `Spoofing - Email Service` / `Spoofing - Free Email Provider` | A sending service is in the SPF | Email Spoofing via SendGrid |
| `Spoofing - No DMARC Enforcement` | DMARC absent or `p=none` — **SPF may well exist** | Direct Email Spoofing via a Well-Configured or Reputation-Bearing Server |
| `Spoofing - No SPF/DMARC Policy` | Neither SPF nor DMARC | Direct Email Spoofing - No SPF or DMARC |
| `Spoofing - SPF/DKIM Misconfiguration` | Rule-based: `+all`, `?all`, `~all` + weak DMARC, critical SPF issues | SPF Pass All (+all) |
| `Spoofing - DKIM Misconfiguration` | A published DKIM RSA key is broken. **Known factorization** (factordb.com, small factor, prime modulus): private key rebuilt, accepted by every verifier → **Very High** / **Critical**. **< 1024 bits**: factorable, but RFC 8301 verifiers like Gmail reject the key → **Medium**. **`e=1` / `e=3`**: forgery only on lenient verifiers → **Very Low** / **Low** | DKIM RSA key with a known factorization |
| `Spoofing - Partial DMARC Enforcement (pct)` | `p=quarantine` or `p=reject` with `pct` between 1 and 99: the unsampled share of spoofs gets the next less strict policy. Probability by `pct` range, impact by policy (see [DMARC `pct` and `t=y`](#dmarc-pct-and-ty)) | Partial DMARC enforcement (p=quarantine; pct=50) |
| `Spoofing - Relaxed DMARC Alignment (org-domain)` | An audited **subdomain** has an aligned-capable spoof (shared hosting / `+all`, or a weak/takeable DKIM) **and** its organizational (parent) domain enforces DMARC with **relaxed** alignment (the default) — so the subdomain can forge `From:@<parent>` | Cross-domain spoofing of `spoofin.fr` from subdomain `alwaysdata.spoofin.fr` |
| `Spoofing - Unregistered Domain Takeover` | A CNAME (DKIM selector, `_dmarc`, domain) or an SPF `include:`/`redirect=` points into a buyable domain | DKIM selector CNAME to an unregistered domain |

#### DMARC `pct` and `t=y`

RFC 7489 §6.6.4: a receiver applies the policy to `pct`% of the messages failing DMARC and
the **next less strict policy** to the others: `reject` → `quarantine`, `quarantine` → `none`.
RFC 9989 (DMARCbis) replaced `pct` with `t=y` (test mode). Two cases:

**`pct=0` or `t=y`: the whole policy is one level lower.** No message gets the published
policy, so the DMARC state used by every spoofing scenario is lowered (`_dmarc_state`):

| Record | Handled as |
|---|---|
| `p=reject; pct=0` / `p=reject; t=y` | `quarantine` (spoofs land in spam) |
| `p=quarantine; pct=0` / `p=quarantine; t=y` | `none` (no enforcement: the *well-configured attacker server* scenario fires) |

The effective policy is used everywhere a scenario depends on DMARC (`_effective_policy`):

- every scenario driven by the DMARC state (well-configured attacker server, services in
  the SPF, `~all` rules): `p=quarantine; t=y` gives exactly the scenarios of `p=none`;
- the SPF qualifier rules that require `dmarc_lax_policy` (e.g. *SPF SoftFail (~all) —
  DMARC Monitoring Only*) also fire when the policy is effectively `none`;
- relaxed-alignment cross-domain spoofing: a parent with `p=quarantine; t=y` is **not**
  enforcing (it is applied as `p=none`); `p=reject; pct=0` still is (applied as quarantine);
- remediation: the record already says `p=quarantine`/`p=reject`, so these scenarios start
  with *"remove t=y"* / *"set pct=100"* instead of *"publish an enforcing policy"*.

**`pct` between 1 and 99: `Spoofing - Partial DMARC Enforcement (pct)`.** One scenario,
built by `_analyze_dmarc_pct` from `external_spoofing.partial_enforcement_pct` in
`lib/data/scenario_templates.json`:

- **Probability** = likelihood that one spoof falls in the unsampled share
  (`likelihood_by_pct`, editable):

  | `pct` | Share escaping `p=` | Probability |
  |---|---|---|
  | 1 – 10 | 90 – 99 % | Very High |
  | 11 – 35 | 65 – 89 % | High |
  | 36 – 65 | 35 – 64 % | Medium |
  | 66 – 90 | 10 – 34 % | Low |
  | 91 – 99 | 1 – 9 % | Very Low |

- **Impact** = what happens to an escaped spoof (`impact_by_policy`): `p=quarantine` →
  handled as `p=none`, delivered → **critical**; `p=reject` → quarantined (spam folder) →
  **medium**.
- **Risk** = `risk_matrix[impact][probability]`:

  | `pct` | `p=quarantine` | `p=reject` |
  |---|---|---|
  | 1 – 10 | Critical | High |
  | 11 – 35 | Critical | High |
  | 36 – 65 | High | Moderate |
  | 66 – 90 | Moderate | Low |
  | 91 – 99 | Low | Low |

- The conditions give the odds over several copies: `1 - (pct/100)^n` (e.g. `pct=50`: 88 %
  that at least one of 3 copies escapes).
- *Assumed (not tested)*: the receiver implements RFC 7489 sampling. Receivers implementing
  RFC 9989 ignore `pct` and apply the full policy.
- Not emitted for `pct=100`, `pct=0`, `t=y` (handled above) or `p=none` (nothing enforced).

The `antispoof` side reports the same ranges as issue severities (`dmarc_partial_coverage`,
`dmarc_testing_mode`): see the `mail_antispoof_policy_checker` README.

**Relaxed-alignment cross-domain spoofing (`Spoofing - Relaxed DMARC Alignment (org-domain)`)**

DMARC is evaluated against the **From-header** domain and, by default, with **relaxed**
alignment (`aspf`/`adkim` absent = `r`). Relaxed alignment compares only the
**organizational (registrable) domain**, so an SPF *pass* or a valid DKIM signature on
**any** name sharing that organizational domain satisfies DMARC for a `From:` on the
organizational domain — and on **any of its sibling subdomains**. For a subdomain with no
own `_dmarc`, DMARC jumps **directly to the organizational domain** (no label-by-label walk):
`a.b.sub.example.co.uk` → `example.co.uk`, never the intermediate labels.

Consequence: an audited **subdomain** that is spoofable in an *aligned* way — delegated to
**shared hosting**, SPF ending in **`+all`**, or carrying a **weak/takeable DKIM** — lets an
attacker forge `From: anything@<organizational-domain>` when that organizational domain uses
relaxed alignment (the default). The message trips `FORGED_SENDER` (envelope/DKIM domain ≠
visible `From`), but **SPF/DMARC (or DKIM/DMARC) still PASS, even at `p=reject`**. Risk is
**critical** when the parent enforces (`p=quarantine`/`reject`, the bypass is real), **high**
at `p=none`. The branch is dropped when the parent sets **strict** alignment (`aspf=s` /
`adkim=s`). Built in code by `AttackScenarioAnalyzer._analyze_relaxed_alignment`.

**Leverage vs. Affected Domains.** The audited subdomain is the **leverage** (the envelope
`MAIL FROM` / DKIM `d=`) and appears in the **Target** column; what the attacker can actually
forge in the visible `From:` is the **whole organizational namespace**. Relaxed alignment is
**bidirectional / symmetric at the organizational level**: a leverage on `alwaysdata.spoofin.fr`
forges `From:@spoofin.fr` **and** `From:@ovh.spoofin.fr`, `From:@factures.spoofin.fr` (audited
or not, existing or not), etc. — any name with no own `_dmarc` inherits the parent's policy
and alignment. **Affected Domains** is therefore `spoofin.fr, *.spoofin.fr`:

- audited subdomains covered are listed in the conditions (*"Including the N audited
  subdomains: …"*);
- an audited subdomain whose own `_dmarc` sets **strict** alignment for the active branch is
  excluded: `*.spoofin.fr (except strict.spoofin.fr)`, and listed in the conditions
  (*"Not spoofable this way …"*);
- caveat stated in the conditions: a non-audited subdomain with its own strict-alignment
  `_dmarc` is not affected either, which the audit cannot check.

To make this detectable even when the parent is not an audit target, the auditor **derives
each subdomain's organizational parent** (`tldextract` / PSL) and fetches **the parent's own
DMARC** (policy + `aspf`/`adkim`) when that parent is not already in the list. The parent's
**SPF/DKIM are not fetched** — only its governing DMARC; the leverage is the subdomain's. A
derived parent appears in the antispoof output with DMARC only.

**Takeover scenario (`Spoofing - Unregistered Domain Takeover`)** — **one scenario per
domain**, built from the issues of the end-of-run registration check
(`*_cname_target_(potentially_)unregistered`, `spf_domain_(potentially_)unregistered`).
It lists **the domain(s) to buy** and, for every vulnerable DNS name, one condition and one
vector (CNAME chain, selector, registration source, exact name where the attacker publishes).
Texts live in `scenario_templates.json` → `external_spoofing.domain_takeover`.

| Vulnerable name | Attacker publishes | Bypasses | Probability (confirmed / potentially) |
|---|---|---|---|
| `<domain>` is a CNAME | SPF authorizing their servers | SPF | high / medium |
| SPF `include:` / `redirect=` | SPF authorizing their servers | SPF | high / medium |
| `<selector>._domainkey` CNAME | their DKIM public key | DKIM | high / medium |
| `_dmarc` CNAME | `v=DMARC1; p=none` | DMARC | weak SPF: high / medium — SPF `-all`: medium / low |

The `Bypasses` column names only the control actually hijacked. DMARC then passing via SPF/DKIM alignment is a **consequence** (spelled out in the Bypass Conditions text), so `DMARC` is tagged **only** when a `_dmarc` name is itself dangling — not added to an SPF or DKIM takeover.

Impact is always Critical; scenario risk = worst vector (`risk_matrix`): confirmed (probability
High) → risk Critical, potentially (Medium) → High, `_dmarc` potentially with SPF `-all` (Low) →
Moderate. The
scenario's bypasses are the union over its names — but `DMARC` appears only when a `_dmarc`
name is itself dangling (e.g. `dangling.example.com`, which dangles SPF + a DKIM selector +
`_dmarc`: SPF, DKIM, DMARC; a domain with only an SPF `include` + a DKIM selector CNAME:
SPF, DKIM). Vectors are `UNVERIFIED`: takeover is never confirmed from DNS alone.

Rules in `spf_qualifier_rules` accept `condition_issue_codes` (all required),
`condition_any_issue_codes` (at least one) and `condition_absent_issue_codes` (none).

A domain with a shared-hosting include **and** `p=none` gets both a *Shared Hosting*
scenario and a *No DMARC Enforcement* scenario: they are two independent vectors (an
account on the shared host, vs. any attacker-owned server — the latter only works
because DMARC is not enforced, and disappears with `p=quarantine`/`p=reject`).

### Bypassed controls (SPF / DKIM / DMARC)

Every scenario says which authentication controls it defeats, in three fields (JSON) /
columns (Excel):

| JSON field | Excel column | Meaning |
|---|---|---|
| `bypasses` | **Bypassed (certain)** | Controls the technique defeats **by itself**, whatever the configuration of the servers involved |
| `conditional_bypasses` | **Possibly Bypassed** | Controls defeated **only under a condition the audit cannot observe** (e.g. the relay DKIM-signs relayed mail with the domain key) |
| `bypass_notes` | **Bypass Conditions** | One line per control: why it is bypassed, or under which condition |

Rules used throughout:

- **DMARC passes when SPF OR DKIM passes *aligned*** with the From domain. One aligned pass
  is enough: an aligned SPF pass bypasses DMARC even at `p=reject`, whatever DKIM says.
- **Absent is not bypassed.** A control that is missing or not enforced (no DMARC record,
  `p=none`) is not listed as bypassed: there is nothing to bypass. The note says so.
- A DKIM signature that is **present but not aligned** (signed by the service or the host,
  e.g. `sendgrid.net:s=smtpapi`) is not a DKIM bypass. The signature observed in tests is
  kept per vector (`dkim` field) and reported in the scenario's **Bypass Conditions**.

| Scenario | Bypassed (certain) | Possibly bypassed | Why / condition |
|---|---|---|---|
| **Open relay**, relay IP authorized by the domain's SPF | SPF, DMARC¹ | DKIM | SPF passes aligned (MAIL FROM in the domain, sent from an authorized IP) → DMARC passes. *Direct bypass* |
| **Open relay**, relay IP **not** in the domain's SPF | — | DKIM, DMARC¹ | SPF fails for the domain. DMARC passes only if the relay DKIM-signs relayed mail with the domain key (see [Open Relay](#open-relay)) |
| **Open relay**, SPF verdict undetermined | — | SPF, DKIM, DMARC¹ | The relay IP could not be matched (unresolved `a` / `mx` / `exists` in includes): check it manually |
| **Shared hosting** | SPF, DMARC | DKIM | SPF-authorized host IP + MAIL FROM overwritten to the domain → aligned SPF → DMARC passes even at `p=reject`. DKIM only if the host signs with the sender domain's key without checking that the account owns it (AlwaysData test 2026-10-30: signs `alwaysdata.net:s=default`, not aligned — valid signature avoids an `R_DKIM_NA` penalty, DMARC still passes via SPF) |
| **Well-configured attacker server** / no SPF-DMARC policy / SPF softfail without enforcement | SPF, DKIM *(trivial)* | — | Nothing enforces them: own server, own DKIM key. DMARC absent or `p=none`: not bypassed |
| **Service in SPF** (Free Mail, Email Delivery) | SPF | — | The From domain's SPF matches the service IP (reputation, non-RFC checks); the envelope MAIL FROM stays the service's own domain. DKIM = the service's own signature, not aligned. DMARC not bypassed |
| **SPF `+all`** | SPF, DMARC | — | SPF passes for any IP, aligned → DMARC passes |
| **SPF `?all`** | SPF | — | Neutral for any sender; an enforced DMARC still blocks the spoof |
| **Weak DKIM RSA key** (< 1024 bits, `dkim_rsa_weak_key`) | DKIM, DMARC | — | The key is factored: aligned DKIM signature → DMARC passes. **Reality check:** per RFC 8301 a verifier treats a key < 1024 bits as invalid — Gmail (and likely other large providers) ignores the signature, so DKIM does not pass and DMARC fails; the spoof only lands on lenient/legacy receivers (likelihood **Medium**, not high) |
| **DKIM RSA key with a known factorization** (`dkim_rsa_known_factorization`: factordb.com, small factor, prime modulus) | DKIM, DMARC | — | The private key is rebuilt (`q = n/p`, `d = e^-1 mod φ`). The key size is normal, so every verifier accepts the signature → aligned DKIM → DMARC passes even at `p=reject` (likelihood **Very High**) |
| **Dangerous DKIM RSA exponent** (`dkim_rsa_dangerous_exponent`: `e=1`, `e=3`) | — | DKIM, DMARC | Forgery without the private key, only on a verifier that accepts `e=1` or checks the PKCS#1 v1.5 padding loosely (Bleichenbacher 2006). Mainstream verifiers are strict (likelihood **Very Low**) |
| **Partial DMARC enforcement** (`pct` 1–99) | SPF, DKIM *(own server)* | DMARC | DMARC fails, but the unsampled `(100-pct)`% of spoofs get the next less strict policy (RFC 7489 receivers only) |
| **Domain takeover** | the hijacked control(s) only — SPF (`include`/CNAME), DKIM (selector CNAME), DMARC (only when `_dmarc` itself is a dangling CNAME) | — | See the *Takeover scenario* paragraph above. DMARC passing via SPF/DKIM alignment is a consequence (in Bypass Conditions), not tagged as a separate bypass |
| **Relaxed-alignment cross-domain** (weak subdomain → parent) | SPF and/or DKIM (the subdomain's), DMARC | — | Relaxed alignment on the parent (default) makes an SPF pass / DKIM signature obtained on the subdomain satisfy DMARC for `From:@<parent>`. `FORGED_SENDER` is raised but SPF/DMARC (or DKIM/DMARC) pass even at `p=reject`. See the *Relaxed-alignment cross-domain spoofing* paragraph above |
| **MITM** | — | — | Transport attacks: the mail is read or altered in transit, no authentication bypass |

¹ DMARC is listed only when the domain has a DMARC policy (own record or inherited from the
organizational domain); otherwise the note says "absent, nothing to bypass".

Free Mail could historically reach *true* alignment via MFEF, but that is dead since providers moved to SRS.

#### Service types identified for "service in SPF"

- **Email Delivery Service** — SendGrid, Mailjet, Brevo, Amazon SES, Mandrill, Tipimail, Mailpro, Mailchimp
- **Free Mail Provider** — Gmail, Outlook.com, Yahoo, Proton, iCloud, AOL, GMX, mail.com, 163
- **Shared Hosting** — OVH, Gandi, Infomaniak, AlwaysData, Aruba, NameBright, BeYs Cloud, OS2Switch, VTX.ch, Viaduc

#### Why Shared Hosting is DMARC-independent

On a mutualised mail platform, an attacker with an account (or hosting) can control the envelope `MAIL FROM` (e.g. `mail -f`, the *Sender* field in phpMyAdmin) and set it to the victim domain. The message then leaves an IP that is **already SPF-authorized** for that domain, and the `MAIL FROM` **aligns** with the header `From:` — so DMARC passes on the SPF branch **even under `p=reject`**. This is a direct quickwin that DMARC alone cannot fix; the mitigation is provider-side `MAIL FROM`/Sender ownership enforcement. The scenario is emitted per specific service — e.g. *"Email Spoofing via OVH (Shared Hosting)"*, *"… via AlwaysData (Shared Hosting)"*.

**Two ways in (AlwaysData, tested 2026-10-30).** Either a local script using the host's
local MTA (a PHP `mail()` / PHPMailer script, no SMTP authentication — an auth bypass), or an
authenticated **shared mail server**: create a mailbox and log in to
`smtp-<username>.alwaysdata.net`, then send with a forged From. Both set the `MAIL FROM` to the
hosted domain, so SPF aligns and DMARC passes even at `p=reject`. The host also DKIM-signs with
its own key (`alwaysdata.net:s=default`): not aligned, so no DKIM alignment, but the valid
signature avoids a missing-signature penalty (`R_DKIM_ALLOW` instead of `R_DKIM_NA`). OVH
(tested 2026-10-30) still blocks this via access control on the `MAIL FROM`.

#### Dated tests override the generic baseline (`data/tests/`)

`email_services.json` holds the **generic** per-`service_type` assumption; `mail_audit/lib/data/tests/` refines it with **real, dated test results**. Convention: **one JSON file per test** — the filename is a free slug and is ignored (e.g. `sendgrid_web_ui_domain_verification.json`), each file holding a single test object. The loader reads every `*.json`; the most recent entry per `(service, technique)` wins.

Fields: `service`, `technique`, `date`, `result`, `effect`, `vector` (optional `{vector_type, auth_mode, shared}` filter — all keys must match the vector), `likelihood` (vector probability for `soften`: very_low…very_high), `by_dmarc` (optional, for `soften`: per DMARC state `none` / `absent` / `quarantine` / `reject`, overrides `likelihood`, `impact`, `probability` and adds a `note`), `probability` (internal template baseline, only used for a scenario without vectors), `observations` (optional raw evidence: filter, score, symbols), `note`, `source` (URL or reference).

| effect | meaning |
|---|---|
| `confirm` (PASS) | vectors → `confirmed` |
| `downgrade` (FAIL) | vectors → `blocked` (probability Very Low, risk Low), scenario kept with a dated note |
| `soften` (partial) | lower a vector's probability (`likelihood`, e.g. → Medium) **without** fully blocking it |
| `eliminate` (FAIL) | drop the targeted vector — or the whole service scenario if no `vector` is given |

**Scoring principle — generic never below MEDIUM; only tests reach LOW, and we stay there.**

- A **generic (untested) rule never scores below `MEDIUM`.** An un-audited third-party
  service is *assumed exploitable* until proven otherwise — the tool never silently
  treats an unknown provider as safe. (A lower score you see without a test is the
  target's *own* posture at work, e.g. `p=reject` stopping an unaligned spoof — not an
  assumption about the provider.)
- Only a **dated test** can pull a scenario down to `LOW` (`downgrade` / `soften`).
- We **keep it at `LOW` rather than removing it**: a third party can *regress* — a
  provider update can silently re-open the hole (they change how MAIL FROM / domain
  verification is enforced), so `LOW` keeps the vector on the radar for re-testing.
  `eliminate` is reserved for vectors that **structurally** no longer exist (e.g.
  Outlook MFEF → SRS), not for a provider that merely blocks it today.

**Dated verification log**

| Service | Type | Date | Result |
|---|---|---|---|
| Outlook.com (forwarding MFEF) | Free Mail | 2026-08-03 | forwarding vector **eliminated** (MFEF → SRS, no longer aligns) |
| OVH | Shared Hosting | 2026-08-03 | risk **Low** — verifies the `MAIL FROM` |
| OVH | Shared Hosting | 2026-10-30 | risk **Low** — both vectors `local_script` and `smtp_server` + `shared` blocked (access control on the `MAIL FROM`) |
| AlwaysData | Shared Hosting | 2026-08-03 | risk **Critical** — perfect spoof via local MTA |
| AlwaysData | Shared Hosting | 2026-10-30 | risk **Critical** — vectors `local_script` (Local MTA, auth bypass) **and** `smtp_server` + `shared` (authenticated Shared Mail Server `smtp-<user>.alwaysdata.net`); DMARC **passes** via SPF alignment even at `p=reject` (`DMARC_POLICY_ALLOW [example.com,reject]`, `R_SPF_ALLOW`, `R_DKIM_ALLOW [alwaysdata.net:s=default]`) → delivered to the **Gmail inbox** |
| SendGrid | Email Delivery | 2026-08-06 | `web_ui` **works** (Dynamic Templates → Test email exposes a free From) — only the header From, MAIL FROM stays `bounces@sendgrid.net`, DKIM `sendgrid.net:s=smtpapi` (not aligned) → **no DMARC alignment**, `smtp_server` **blocked** (unverified MAIL FROM → *"You are not authorized to send from that email address"*). |
| SendGrid | Email Delivery | 2026-10-29 | `web_ui` needs **no** domain authentication, but DMARC is still evaluated at `p=none` (Rspamd 3.2–7.3/11, Gmail spam) → probability **Medium**, risk **Moderate** (supersedes the 2026-08-06 web UI result) |
| SendGrid | Email Delivery | 2026-10-30 | `web_ui` per DMARC policy: `p=none` Medium / Moderate, `p=quarantine` Medium / Low (Gmail warning), `p=reject` Low / Low (never received on Gmail) (supersedes the 2026-10-29 result) |
| Brevo | Email Delivery | 2026-08-06 | **blocked** — both `web_ui` and `smtp_server` require domain authentication (DNS TXT code) before any From → risk **Low** |
| Mailjet | Email Delivery | 2026-08-06 | **blocked** — domain validation (DNS record/file, tied to API key) required for both `web_ui` and `smtp_server` → risk **Low** |

### Open Relay

An open relay lets anyone send mail **from that server**, with any From address of the
domains it serves. Whether this bypasses SPF / DMARC depends on **each domain** using that
MX, so the outcome is evaluated per domain, then the domains are merged **per (MX host,
case)**: one row per case, named after it, e.g. on example.com:

| Row | Probability / Risk Level | Affected Domains |
|---|---|---|
| `SMTP Open Relay on mail.example.com (SPF-authorized relay: direct SPF/DMARC bypass)` | Very High / Critical | the 7 domains whose SPF authorizes 51.75.24.36 |
| `… (relay not in the domain's SPF, DMARC not enforced)` | High / High | `alwaysdatanonedmarc`, `ovhnonedmarc` |
| `… (relay not in the domain's SPF, DMARC enforced)` | Low / Moderate | `alwaysdata`, `ovh`, … (own or inherited `p=quarantine`/`reject`) |

Only domains whose MX points to the relay are listed (the same list as smtp_checker's
*Email Domains*); domains without an MX on that server, e.g. `dangling.example.com`, are not.

**Server-to-server on port 25.** Open relay (and delivering a spoof after breaking a weak
DKIM key) means connecting **directly to port 25** of the MX. The sender then speaks as an
**MTA, not a submission client**: the receiver treats it as a server and applies MTA checks —
a valid **reverse DNS / PTR**, a FQDN HELO matching it, banner consistency — none of which
apply to authenticated submission on 587/465. This is why these scenarios are tagged
`transport: server_to_server`, `port: 25`.

**Being the domain's MX is not enough.** The MX is the server that *receives* the domain's
mail. External receivers check the SPF of the `MAIL FROM` against the IP that delivers the
mail (the relay); the MX record is not involved, unless the SPF uses the `mx` mechanism.
Example: `ovh.example.com` has MX `mail.example.com` (51.75.24.36), but its SPF is
`include:mx.ovh.com -all`, so a spoof relayed by `mail.example.com` fails SPF.

| Case | Impact | Probability → Risk Level | Bypassed (certain) | Possibly bypassed |
|---|---|---|---|---|
| Relay IP authorized by the domain's SPF: **direct SPF/DMARC bypass** | critical | **Very High** → Critical | SPF, DMARC | DKIM |
| Relay IP not in the SPF, DMARC not enforced (`p=none` / absent) | high | **High** → High | — | DKIM, DMARC |
| Relay IP not in the SPF, DMARC enforced (`quarantine` / `reject`, own or inherited) | critical | **Low** → Moderate | — | DKIM, DMARC |
| SPF verdict undetermined | critical | **Medium** → High | — | SPF, DKIM, DMARC |

Relay not in the SPF and DMARC not enforced: DMARC does not block the spoof, so it is
**likely delivered** (High) from a legitimate mail server; but SPF fails for the domain and
DKIM only passes if the relay signs, so the spoof stays visibly unauthenticated: impact
**high** instead of critical → risk level **High**.

**SPF verdict** (`_spf_authorizes`): the relay IP (the IP the SMTP tests connected to) is
matched against the SPF IPs / ranges resolved by mail_antispoof_policy_checker (includes
and redirects followed), `+all`, a top-level `mx` (it covers the relay, which is one of the
domain's MX), and `ptr:<domain>` mechanisms (matched against the relay's **validated** PTR
name, RFC 7208 §5.5). Remaining `a` / `mx` / `exists` mechanisms inside includes are not
resolved → *undetermined*. No SPF record → treated as a fail (no pass for the domain).

**DKIM is always "possible", never certain.** The relayed mail carries an aligned
`d=<domain>` signature only if the relay's DKIM signer signs it. Typical causes on
Postfix + OpenDKIM:
- the attacker's source address is covered by `InternalHosts` (too broad a range,
  `0.0.0.0/0`), the file often named `TrustedHosts`;
- relayed mail is re-injected through `127.0.0.1` after a content filter (amavis), and
  localhost is in `InternalHosts` by default;
- a signer configured to sign every message whose From matches its `SigningTable`,
  whatever its source.

The open relay test never sends any content (`rcpt` or `data` mode), so this cannot be
observed. To confirm, relay a real test message to a mailbox you control and read its
`DKIM-Signature` / `Authentication-Results`. If the relay signs, DMARC passes even when
SPF fails.

**The domain's own mailboxes** do not need the relay at all: mail to them is normal
inbound mail, protected only by the server's own SPF/DMARC checks on inbound mail (not
tested here).

Whatever the spoofing outcome, an open relay is abused for spam at scale and gets the
server blacklisted: impact stays **critical** in every case.

The test needs `--sender` and `--recipient` (otherwise it is disabled). `--open-relay-mode`
sets its depth: `rcpt` (default) stops after `RCPT TO` (like MXToolbox), `data` also sends
`DATA`, expects `354` and drops the connection without any content (like Nessus). See the
[smtp_checker README](../smtp_checker/README.md).

### MX-level scenarios: one row per MX host

MITM scenarios (SSL stripping, fake certificate, TLSA without DNSSEC) and the open relay
target the **MX server**, not each domain. They are listed **once per (scenario, MX host)**:
the **Target** column holds the MX hostname (e.g. `mail.example.com`) and **Affected
Domains** lists every audited domain whose MX points to it. Texts are rendered for that
list. For SSL stripping, a domain is listed under an MX when that domain has no enforced
MTA-STS policy (MTA-STS is a per-domain policy, the downgrade hits the MX connection).

JSON: per-domain scenarios stay under `domains[].attack_scenarios`; the grouped ones are in
the top-level `mx_scenarios` (`domain` = MX host, `affected_domains` = list).

---

## Installation

### Prerequisites

Python 3.9 or later. `mail_audit` imports `smtp_checker` and `mail_antispoof_policy_checker`
as regular packages (`from smtp_checker.lib import …`), so all three must be installed in
the active environment. They are not on PyPI: install them from the local folders, in
editable mode. See the [root README](../README.md) for the full setup.

### Install dependencies for all three modules

```bash
# From the repo root (./Mail Audit/)
pip install -r requirements.txt

# equivalent to, in this order:
pip install -e smtp_checker/
pip install -e mail_antispoof_policy_checker/
pip install -e mail_audit/        # pandas + openpyxl for Excel export
```

After installation, `mail-audit` is available as a command from any directory.

MaxMind GeoIP support (AS-organization lookups in SPF analysis) needs no extra package
(`geoip2` comes with `mail_antispoof_policy_checker`). Only a license key is required, in
one of two ways (never write it in the code or a committed file):

1. Environment variable `MAXMIND_LICENSE_KEY` (current terminal session):

   ```powershell
   $env:MAXMIND_LICENSE_KEY = "your_license_key_here"      # PowerShell
   ```
   ```bat
   :: cmd (no quotes, no spaces around =, no comment on the same line)
   set MAXMIND_LICENSE_KEY=your_license_key_here
   ```
   ```bash
   export MAXMIND_LICENSE_KEY="your_license_key_here"      # bash / zsh / Git Bash
   ```

2. Argument `--maxmind-key your_license_key_here` (takes precedence over the variable).

Without a valid key the AS organization lookups are skipped. Details in the
[root README](../README.md#maxmind-license-key).

---

## CLI Usage

### Basic syntax

```
python cli.py -i DOMAINS [options]
```

Run from the `mail_audit/` directory.

### Examples

```bash
# Single domain (sync mode, default)
python cli.py -i example.com

# Multiple domains from a file (one per line)
python cli.py -i domains.txt

# Comma-separated domains
python cli.py -i "example.com,target.org,another.net"

# Async mode (faster for many domains)
python cli.py -i domains.txt --async-mode

# Custom output directory and filename
python cli.py -i example.com --output-dir ./results --output example_audit

# Custom open relay test addresses
python cli.py -i example.com \
    --sender test@example.net \
    --recipient osef@domain.com

# Open relay test up to DATA (354, then connection dropped — nothing is relayed)
python cli.py -i example.com --sender test@example.net \
    --recipient osef@domain.com --open-relay-mode data

# Run only SPF and DMARC checks (skip DKIM)
python cli.py -i example.com --check-types spf,dmarc

# Custom DNS resolver(s) - one --nameservers list drives BOTH the SMTP and antispoof checks
python cli.py -i example.com --nameservers "1.1.1.1,8.8.8.8"

# Use custom email_services.json (to add your own service definitions)
python cli.py -i example.com --email-services ./my_services.json

# MaxMind AS lookups
python cli.py -i example.com --maxmind-key YOUR_LICENSE_KEY

# Custom DKIM selector file (replaces the bundled list; one selector per line, '#' comments)
python cli.py -i example.com --dkim-selector-file ./my_selectors.txt

# Disable the CNAME chain check / the registration check of broken CNAME targets
python cli.py -i example.com --skip-cname-check
python cli.py -i example.com --skip-domain-availability-check

# Do not look DKIM RSA moduli up on factordb.com (offline key checks still run)
python cli.py -i example.com --skip-factordb-check

# Full options example
python cli.py -i example.com \
    --port 25 \
    --timeout 10 \
    --dns-timeout 5 \
    --nameservers "1.1.1.1,8.8.8.8" \
    --sender test@example.net \
    --recipient osef@domain.com \
    --check-types spf,dmarc,dkim \
    --antispoof-dns-timeout 5 \
    --max-dns-retries 3 \
    --async-mode \
    --max-concurrent 50 \
    --max-smtp 10 \
    --max-dns 50 \
    --output-dir ./output \
    --output my_audit
```

---

## Offline and Hybrid Modes

`mail_audit` can consume pre-computed results from `smtp_checker` or `mail_antispoof_policy_checker` instead of running those checks live. This is useful for:

- **Air-gapped or restricted environments** where network access is limited.
- **Re-running scenario analysis** after updating `email_services.json` or `scenario_templates.json` without re-running expensive DNS/SMTP checks.
- **Splitting workloads** across machines or time windows.

### Input formats accepted

| Flag | Accepted file format |
|---|---|
| `--smtp-json FILE` | `mail_audit` `_smtp.json` **or** `smtp_checker` native JSON output |
| `--antispoof-json FILE` | `mail_audit` `_antispoof.json` **or** `mail_antispoof_policy_checker` native `policy_check_*.json` |

### Operating modes

#### Mode 1 — Full online (default)

Both checkers run live. Standard behaviour.

```bash
python cli.py -i domains.txt \
    --sender test@example.com --recipient check@external.com
```

#### Mode 2 — SMTP offline, antispoof online

Provide a pre-computed SMTP result file. SPF/DMARC/DKIM are run live against the domains from `-i`.

```bash
python cli.py -i domains.txt \
    --smtp-json ./output/mail_audit_smtp.json
```

Or use a native `smtp_checker` output:

```bash
python cli.py -i domains.txt \
    --smtp-json ./smtp_output.json
```

#### Mode 3 — Antispoof offline, SMTP online

Provide a pre-computed antispoof result file. SMTP checks are run live against the domains from `-i`.

```bash
python cli.py -i domains.txt \
    --antispoof-json ./output/mail_audit_antispoof.json
```

Or use a native `mail_antispoof_policy_checker` output:

```bash
python cli.py -i domains.txt \
    --antispoof-json ./policy_check_20260415_120000.json
```

#### Mode 4 — Fully offline (no network calls)

Provide both files. `-i` is optional: if omitted, domains are derived automatically from the antispoof JSON (or smtp JSON as fallback).

```bash
# With explicit domain list
python cli.py -i domains.txt \
    --smtp-json ./output/mail_audit_smtp.json \
    --antispoof-json ./output/mail_audit_antispoof.json

# Without -i — domains derived from the JSON files
python cli.py \
    --smtp-json ./output/mail_audit_smtp.json \
    --antispoof-json ./output/mail_audit_antispoof.json
```

### Typical workflow for offline re-analysis

```bash
# Step 1 — collect raw data (online, runs both checkers)
python cli.py -i domains.txt \
    --sender test@example.com --recipient check@external.com \
    --output raw_data

# Step 2 — update attack scenarios config or email_services.json
# (edit lib/data/email_services.json or lib/data/scenario_templates.json)

# Step 3 — re-run scenario analysis from cached data (offline, no network)
python cli.py \
    --smtp-json ./output/raw_data_smtp.json \
    --antispoof-json ./output/raw_data_antispoof.json \
    --output reanalysis
```

### CLI Help

```
python cli.py --help
```

### CNAME chain check (DKIM / DMARC / SPF)

The antispoof phase inspects CNAME aliases at `<selector>._domainkey.<domain>` (each
selector of the list), `_dmarc.<domain>` and `<domain>` itself, and reports broken
references (target NXDOMAIN), targets without the expected TXT, loops and indeterminate
resolutions (SERVFAIL/TIMEOUT/REFUSED). DKIM aliases are compared with 3 random sibling
names to flag probable wildcards (grouped, not dropped).

Only a **takeover risk** raises an issue: a broken alias alone is kept as evidence
(`cname_checks` in the antispoof JSON).

**End-of-run registration check** — once all domains are analysed, `mail_audit` sends in
**one bulk call** (deduplicated across domains) to the antispoof
`DomainAvailabilityChecker` (NS → RDAP/WHOIS → registrar):

- the registered domains of **SPF `include:` / `redirect=`** → `spf_domain_unregistered`
  (critical) / `spf_domain_potentially_unregistered` (high) — same logic as the antispoof
  CLI (shared code);
- the registrable domains of **broken CNAME targets** → `*_cname_target_unregistered`
  (critical) / `*_cname_target_potentially_unregistered` (high).

`NXDOMAIN` alone is never treated as "available"; reserved names such as `.invalid` are
`reserved` (not buyable → no issue). `--skip-domain-availability-check` skips this step.
The resulting issues feed the *Unregistered Domain Takeover* scenario — one per domain,
naming the domain(s) to buy (see [Attack Scenario Categories](#attack-scenario-categories)).

Full details: [mail_antispoof_policy_checker README — CNAME Chain Checks](../mail_antispoof_policy_checker/README.md#cname-chain-checks).

---

## Library Usage

### Basic usage

```python
from mail_audit.lib import MailAuditor

auditor = MailAuditor(
    domains=["example.com", "target.org"],
    open_relay_sender="test@example.net",
    open_relay_recipient="osef@domain.com",
)

result = auditor.run()

# Print summary
auditor.print_summary(result)

# Export JSON + Excel
paths = auditor.export(result, base_filename="security_report")
print(paths)
# {"json": "/path/to/security_report.json", "excel": "/path/to/security_report.xlsx"}
```

### Async usage

```python
import asyncio
from mail_audit.lib import MailAuditor

async def run_audit():
    auditor = MailAuditor(
        domains=["example.com"],
        output_dir="./results",
    )
    result = await auditor.run_async()
    paths = auditor.export(result)
    return paths

paths = asyncio.run(run_audit())
```

### Convenience one-liner

```python
from mail_audit.lib import MailAuditor

paths = MailAuditor(domains=["example.com"]).run_and_export(base_filename="report")
```

### Inspect attack scenarios

```python
from mail_audit.lib import MailAuditor, AttackCategory

auditor = MailAuditor(domains=["example.com"])
result = auditor.run()

for domain_audit in result.domains:
    print(f"\n=== {domain_audit.domain} ===")
    counts = domain_audit.scenario_count_by_risk()   # {"critical": 1, "high": 2, "moderate": 0, "low": 1}
    print(f"Scenarios: {counts}")

    for scenario in domain_audit.sorted_scenarios:
        print(f"\n[risk {scenario.risk} | probability {scenario.probability}] {scenario.scenario_name}")
        print(f"  Type     : {scenario.attack_type.value}")
        print(f"  Category : {scenario.attack_category.value}")
        if scenario.service_name:
            print(f"  Service  : {scenario.service_name}")
        if scenario.mx_host:
            print(f"  MX Host  : {scenario.mx_host}")
        print(f"  Conditions:")
        for cond in scenario.conditions_met:
            print(f"    - {cond}")
        print(f"  Vectors: {len(scenario.attack_vectors)}")
        for vec in scenario.attack_vectors:
            print(f"    [{vec.status.upper()}] {vec.service_type} / {vec.auth_mode}")
```

### Access raw checker results

```python
result = auditor.run()

# Raw smtp_checker results
for smtp_entry in result.smtp_raw:
    print(smtp_entry["target"], smtp_entry.get("mta_sts", {}).get("valid"))

# Raw antispoof results
for domain, checks in result.antispoof_raw.items():
    print(domain, checks["dmarc"]["policy"] if checks.get("dmarc") else "no dmarc")
```

---

## Output Files

With `-o NAME`, the output directory receives:

| File | Content |
|---|---|
| `NAME.json` / `NAME.xlsx` | Combined audit: attack scenarios (described below) |
| `NAME_smtp.json` / `NAME_smtp.xlsx` | Raw smtp_checker results. The Excel file is written by smtp_checker's own exporter: **Summary**, **MTA-STS**, **SMTP Tests** and **DANE**, the last two with one row per MX host plus an **Email Domains** column ([details](../smtp_checker/README.md#excel-output)) |
| `NAME_antispoof.json` / `NAME_antispoof.xlsx` | Raw mail_antispoof_policy_checker results (SPF / DMARC / DKIM issues…) |

### JSON (`mail_audit.json`)

```json
{
  "domains": [
    {
      "domain": "example.com",
      "smtp_result": { ... },
      "spf_result": { ... },
      "dmarc_result": { ... },
      "dkim_result": { ... },
      "attack_scenarios": [
        {
          "domain": "example.com",
          "attack_category": "External",   // or "MITM"
          "attack_type": "Spoofing - Email Service",
          "scenario_name": "Email Spoofing via SendGrid",
          "probability": "medium",
          "risk_level": "moderate",
          "bypasses": ["SPF"],                  // certainly bypassed
          "conditional_bypasses": [],           // bypassed only under a condition (see notes)
          "bypass_notes": ["SPF: the service's IPs are in the domain's SPF ...", "DKIM: signed by the service (sendgrid.net:s=smtpapi), not aligned ...", "DMARC: not bypassed ..."],
          "conditions_met": ["DMARC record is completely absent", "SPF includes SendGrid"],
          "description": "...",
          "attack_vectors": [
            {
              "service_type": "web_ui",
              "auth_mode": "credentials",
              "status": "confirmed",
              "steps": "..."
            }
          ],
          "remediation": "..."
        }
      ],
      "scenario_count_by_risk_level": {
        "critical": 1, "high": 2, "moderate": 1, "low": 0
      }
    }
  ],
  "total_scenario_count_by_risk_level": { ... },
  "smtp_raw": [ ... ],
  "antispoof_raw": { ... }
}
```

### Excel (`mail_audit.xlsx`)

The workbook contains the following sheets:

| Sheet | Contents |
|---|---|
| **Summary** | One row per domain with scenario counts by risk level (Critical / High / Moderate / Low), DMARC/MTA-STS/DANE/Open Relay status |
| **All Attack Scenarios** | All scenarios sorted by risk then probability (columns **Target**, **Probability**, **Risk Level**, **Affected Domains**). MITM / open relay: one row per MX host |
| **MITM Attacks** | Filtered to MITM scenarios (SSL Stripping, Fake Cert, TLSA) |
| **External Attacks** | Filtered to Spoofing and Open Relay scenarios |
| **SMTP Results** | Raw smtp_checker output per MX host |
| **AntiSpoof Results** | Raw SPF/DMARC/DKIM checker output per domain |
| **Legend** | Meaning of the columns (Target, Probability, Risk Level, **Bypassed (certain)**, **Possibly Bypassed**, **Bypass Conditions**) and the bypass rules per scenario type |

Scenario sheets (All / MITM / External) columns: Target, Category, Attack Type, Scenario
Name, Probability, Risk Level, **Bypassed (certain)**, **Possibly Bypassed**, **Bypass
Conditions**, Service, Affected Domains, Conditions Met, Description, Remediation. See
[Bypassed controls](#bypassed-controls-spf--dkim--dmarc).

Colour coding:
- Risk level: **Red** Critical · **Orange** High · **Yellow** Moderate · **Light Blue** Low
- Probability: **Red** Very High · **Orange** High · **Yellow** Medium · **Light Blue** Low · **Light Grey** Very Low

---

## Email Services Configuration

The attack scenario analysis is driven by `lib/data/email_services.json`. Each entry key is the **exact `service_name`** value stored in the `Dangerous_SPF_Include.csv` of `mail_antispoof_policy_checker` — no duplication of the CSV data.

```json
{
  "services": {
    "SendGrid": {
      "attack_vectors": [
        {"service_type": "web_ui",     "auth_mode": "credentials", "status": "confirmed"},
        {"service_type": "smtp_server","auth_mode": "api_key",     "status": "blocked"},
        {"service_type": "smtp_server","auth_mode": "credentials", "status": "blocked"}
      ]
    },
    "OVH": {
      "attack_vectors": [
        {"service_type": "smtp_server","auth_mode": "credentials", "status": "confirmed"},
        {"service_type": "php_script", "auth_mode": "local_mta",   "status": "confirmed"}
      ]
    }
  }
}
```

The `service_type` and `service_name` of the matching SPF include are resolved directly from the CSV by `SPFChecker` — `email_services.json` only adds the attack vectors.

---

## Attack Vector Reference

### `service_type` — All Possible Values

#### External spoofing vectors (defined in `email_services.json`)

| Value | Description |
|---|---|
| `web_ui` | Service's web interface — send a mail directly from the browser dashboard |
| `smtp_server` | Direct SMTP connection to the service's outbound mail server |
| `php_script` | PHP `mail()` function on shared hosting — authenticates locally to the MTA |
| `email_forwarding` | Forwarding rule configured inside the provider's webmail settings |

#### MITM vectors (hardcoded in analyzer)

| Value | Description |
|---|---|
| `network` | Network-level on-path interception (BGP hijack, ARP spoofing, DNS poisoning) |

---

### `auth_mode` — Possible Values

`auth_mode` describes **how the attacker authenticates to the sending service**. It is `null` for vectors where authentication is not the relevant concept (network interception, open relay, no-policy scenarios).

| Value | `auth_required` | Description |
|---|---|---|
| `credentials` | `true` | Standard username + password (web login or SMTP `AUTH LOGIN`) |
| `api_key` | `true` | API key used as password (`AUTH LOGIN apikey:<key>` or REST API) |
| `app_password` | `true` | App-specific password generated by the provider when 2FA is active (Gmail, Yahoo, iCloud, AOL…) |
| `local_mta` | `false` | No external auth — PHP `mail()` submits directly to the local MTA |
| `null` | `false` | Not applicable — network-level attack, open relay, or no-policy scenario |

The `auth_required` boolean is derived automatically from `auth_mode` and exposed in the JSON output.

---

### `shared` — shared / mutualised mail server

Optional boolean on a `smtp_server` vector (default `false`). Set `"shared": true` when the
SMTP endpoint is a **shared / mutualised mail server** — a mailbox on a hosting platform whose
outbound IPs are already in many customers' SPF, reached at a per-user host such as
`smtp-<username>.alwaysdata.net`. It is **not** a dedicated relay: the attacker authenticates
with their own account, sets the `MAIL FROM` to any domain hosted on the platform, and SPF
aligns (so DMARC passes even at `p=reject`). It is carried on `AttackVector`, surfaced in the
scenario sheets' **Attack Vector(s)** column as *Shared SMTP Server*, and a dated test can target
it precisely with `"vector": {"vector_type": "smtp_server", "shared": true}`.

#### `port` and `transport` — how the message is submitted

Two attributes on a vector, **declared in the JSON** — on every `smtp_server` / `local_script`
vector in `email_services.json` and on the `vector` filter of the SMTP dated tests
(`*_smtp_mail_from_ownership.json`, `*_shared_smtp_*`, `*_local_mta_*`). When omitted they
default from `vector_type` + `auth_mode`; either way they are filled onto `AttackVector` and
shown in the **Attack Vector(s)** column:

| `transport` | `port` | When | Note |
|---|---|---|---|
| `client_to_server` | `587/465` | `smtp_server` with an auth mode (submission) | The attacker authenticates with an account and sets the `MAIL FROM`. Standard client submission — **no PTR / reverse DNS requirement** on the client. |
| `server_to_server` | `25` | `smtp_server` with `auth_mode: none` (open relay), `network` (MITM) | A direct MX connection. **The sender connects as an MTA**, so the receiver treats the client as a server and expects a valid **reverse DNS / PTR**, a matching HELO, etc. This is the open-relay path, and the path used to deliver a spoof after forging a DKIM signature. |
| `local_submission` | — | `local_script` (Local MTA) | The shared host's own local MTA injects the message; no network submission by the attacker. |

So AlwaysData's two confirmed modes are both **client→server submission on 587/465** (an
authenticated mailbox or the local MTA), whereas **Open Relay** is a **server→server**
connection on **port 25** — see [Open Relay](#open-relay).

---

### Valid Combinations by Service Context

#### Email Delivery Services (SendGrid, Mailjet, Brevo, Mandrill, Tipimail, Mailpro…)

| `service_type` | `auth_mode` | Meaning |
|---|---|---|
| `web_ui` | `credentials` | Log into the web dashboard and send a test/campaign email with an arbitrary `From` header |
| `smtp_server` | `api_key` | Connect to SMTP (e.g. `smtp.sendgrid.net:587`) and authenticate with `apikey:<key>` as password |
| `smtp_server` | `credentials` | Connect to SMTP and authenticate with account username + password |

#### Free Email Providers (Gmail, Outlook.com, Yahoo, ProtonMail, iCloud, AOL, GMX…)

| `service_type` | `auth_mode` | Meaning |
|---|---|---|
| `smtp_server` | `credentials` | Authenticate to SMTP with standard account credentials (port 587 STARTTLS or 465 SSL) |
| `smtp_server` | `app_password` | Generate an app-specific password (required when 2FA is active); connect with normal SMTP credentials otherwise rejected |
| `email_forwarding` | `credentials` | Configure a forwarding rule inside the provider's webmail — mails forwarded keep a `From` belonging to the target domain while originating from the provider's IPs (whitelisted in target SPF) |

#### Shared Hosting (OVH, Gandi, Infomaniak, AlwaysData, Aruba Business…)

| `service_type` | `auth_mode` | Meaning |
|---|---|---|
| `smtp_server` | `credentials` | Authenticate to the hosting provider's SMTP relay using purchased hosting account credentials — set `From` to the target domain |
| `php_script` | `local_mta` | A PHP script using `mail()` submits to the local MTA without external SMTP authentication — available on any shared hosting plan |

#### MITM (hardcoded by analyzer)

| `service_type` | `auth_mode` | Scenario |
|---|---|---|
| `network` | `null` | STARTTLS downgrade / SSL stripping — strip `250-STARTTLS` from EHLO response |
| `network` | `null` | Fake certificate — present fraudulent CA-signed cert (no TLSA pinning) |
| `network` | `null` | TLSA without DNSSEC — poison DNS to replace TLSA records with attacker-controlled hashes |

#### Open Relay / No Policy (hardcoded by analyzer)

| `service_type` | `auth_mode` | Scenario |
|---|---|---|
| `smtp_server` | `null` | Open relay — no authentication required to relay to any recipient |
| `smtp_server` | `null` | No SPF/DMARC — use any mail server on the internet |
| `smtp_server` | `null` | Critical SPF misconfiguration — overly permissive includes (unverified) |

---

### `status` — Possible Values

| Value | Meaning |
|---|---|
| `confirmed` | Attack vector was tested and **works** |
| `blocked` | Attack vector was tested but is **actively protected/blocked** by the service |
| `unverified` | Attack vector has **not been tested yet** — requires investigation |

To add a new service or modify an existing one, edit `lib/data/email_services.json` directly or pass a custom file via `--email-services` / `email_services_file`. Service names must match exactly the `service_name` column in `mail_antispoof_policy_checker/data/Dangerous_SPF_Include.csv`.

The canonical list of valid `service_type` and `auth_mode` values — including their descriptions, all valid combinations, and typical combinations per CSV service context — is defined in **`lib/data/vector_taxonomy.json`**. This file is the reference to consult before adding a new vector to `email_services.json`.

---

## Directory Structure

```
Mail Audit/
├── smtp_checker/               # SMTP security checker module
│   ├── lib/
│   │   ├── __init__.py         # Exports: DomainChecker, SMTPChecker, SMTPConnectionError
│   │   ├── checker.py
│   │   ├── domain_checker.py
│   │   └── ...
│   ├── cli.py
│   ├── pyproject.toml
│   └── README.md
│
├── mail_antispoof_policy_checker/  # SPF/DMARC/DKIM checker module
│   ├── lib/
│   │   ├── __init__.py         # Exports: SPFChecker, DMARCChecker, DKIMChecker, DataLoaders
│   │   └── ...
│   ├── data/                   # CSV data files + DKIM_Selectors.txt
│   ├── cli.py
│   ├── pyproject.toml
│   └── README.md
│
└── mail_audit/                 # This module
    ├── lib/
    │   ├── __init__.py
    │   ├── auditor.py          # MailAuditor orchestration class
    │   ├── attack_scenarios.py # AttackScenarioAnalyzer
    │   ├── excel_exporter.py   # ExcelExporter
    │   ├── models.py           # Data models (AttackScenario, etc.)
    │   └── data/
    │       └── email_services.json
    ├── cli.py
    ├── pyproject.toml
    ├── README.md
    ├── CHANGELOG.md
    └── TODOLIST.md
```

---

## Requirements

- Python >= 3.9
- dnspython >= 2.0.0
- checkdmarc >= 6.0.4, < 7
- certifi >= 2024.0.0
- cryptography >= 41.0.0
- pandas >= 1.3.0
- openpyxl >= 3.0.0
- pytz >= 2021.1
- requests >= 2.25.0
- tldextract >= 3.0.0
- httpx
- beautifulsoup4
- geoip2 >= 4.0.0 (optional, for MaxMind AS lookups)
