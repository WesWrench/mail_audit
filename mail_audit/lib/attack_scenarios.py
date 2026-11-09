"""
Attack scenario detection and analysis logic.

The AttackScenarioAnalyzer takes the combined outputs from smtp_checker and
mail_antispoof_policy_checker and derives concrete, exploitable attack
scenarios with associated attack vectors and remediation advice.

All scenario metadata (names, descriptions, conditions, remediations, vectors,
probability rules) is declared in ``lib/data/scenario_templates.json``.
Python owns only condition evaluation logic — no hardcoded strings here.
"""

from __future__ import annotations

import json
import re  # used in _match_service() for mechanism prefix stripping
from pathlib import Path
import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    AttackCategory,
    AttackProbability,
    AttackScenario,
    AttackType,
    AttackVector,
    LIKELIHOOD_ORDER,
    RISK_ORDER,
    VectorStatus,
)

# ---------------------------------------------------------------------------
# Module-level template loading (cached after first load)
# ---------------------------------------------------------------------------

_TEMPLATES: Optional[Dict[str, Any]] = None
_TEMPLATES_PATH = Path(__file__).parent / "data" / "scenario_templates.json"


def _load_templates() -> Dict[str, Any]:
    """Load scenario_templates.json, cached at module level."""
    global _TEMPLATES
    if _TEMPLATES is None:
        with open(_TEMPLATES_PATH, encoding="utf-8") as fh:
            _TEMPLATES = json.load(fh)
    return _TEMPLATES


_TESTS: Optional[Dict[str, List[Dict[str, Any]]]] = None
_TESTS_DIR = Path(__file__).parent / "data" / "tests"


def _smtp_transport(vector_type: str, auth_mode: Optional[str]) -> Tuple[str, str]:
    """Default (port, transport) for a vector's SMTP channel.

    * ``smtp_server`` with authentication -> submission (587/465), ``client_to_server``
      (the attacker authenticates with an account; no PTR/rDNS requirement).
    * ``smtp_server`` with ``auth_mode=none`` (open relay) or ``network`` -> port 25,
      ``server_to_server`` (the sender connects as an MTA: the receiver treats the client
      as a server and expects a valid reverse DNS / PTR, HELO, etc.).
    * ``local_script`` -> the host's local MTA, no network submission.
    """
    if vector_type == "smtp_server":
        if (auth_mode or "").lower() == "none":
            return "25", "server_to_server"
        return "587/465", "client_to_server"
    if vector_type == "network":
        return "25", "server_to_server"
    if vector_type == "local_script":
        return "", "local_submission"
    return "", ""


def _load_tests() -> Dict[str, List[Dict[str, Any]]]:
    """Load dated spoofing test results from ``data/tests/*.json``, cached.

    Convention: **one JSON file per test** (the filename is a free slug and is
    ignored — e.g. ``outlook_free_mail_forwarding_mfef.json``); the file holds a
    single test object. A file wrapping several entries in a ``tests`` list is
    also accepted. Real-world tests OVERRIDE the generic per-``service_type``
    baseline for a specific service.

    Returns a mapping ``{service_name: [test_entry, ...]}`` keeping only the most
    recent entry per ``(service, technique)`` pair.
    """
    global _TESTS
    if _TESTS is None:
        by_service: Dict[str, List[Dict[str, Any]]] = {}
        if _TESTS_DIR.is_dir():
            for fp in sorted(_TESTS_DIR.glob("*.json")):
                try:
                    data = json.loads(fp.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                # One test per file (single object), or a {"tests": [...]} wrapper.
                entries = data.get("tests") if isinstance(data, dict) else None
                if entries is None:
                    entries = [data] if isinstance(data, dict) and data.get("service") else []
                for entry in entries:
                    svc = entry.get("service")
                    if svc:
                        by_service.setdefault(svc, []).append(entry)
        # Collapse to the most recent entry per (service, technique).
        for svc, entries in by_service.items():
            latest: Dict[str, Dict[str, Any]] = {}
            for e in sorted(entries, key=lambda x: x.get("date", "")):
                latest[e.get("technique", "")] = e
            by_service[svc] = list(latest.values())
        _TESTS = by_service
    return _TESTS


# ---------------------------------------------------------------------------
# Enum maps (kept here because they reference Python enums)
# ---------------------------------------------------------------------------

_ATTACK_TYPE_MAP: Dict[str, AttackType] = {
    "MITM_SSL_STRIPPING":    AttackType.MITM_SSL_STRIPPING,
    "MITM_FAKE_CERT":        AttackType.MITM_FAKE_CERT,
    "MITM_TLSA_NO_DNSSEC":   AttackType.MITM_TLSA_NO_DNSSEC,
    "SPOOFING_EMAIL_SERVICE": AttackType.SPOOFING_EMAIL_SERVICE,
    "SPOOFING_FREE_EMAIL":   AttackType.SPOOFING_FREE_EMAIL,
    "SPOOFING_SHARED_HOSTING": AttackType.SPOOFING_SHARED_HOSTING,
    "SPOOFING_NO_POLICY":    AttackType.SPOOFING_NO_POLICY,
    "SPOOFING_NO_DMARC_ENFORCEMENT": AttackType.SPOOFING_NO_DMARC_ENFORCEMENT,
    "SPOOFING_AUTH_MISCONFIG": AttackType.SPOOFING_AUTH_MISCONFIG,
    "SPOOFING_DKIM_MISCONFIG": AttackType.SPOOFING_DKIM_MISCONFIG,
    "SPOOFING_RELAXED_ALIGNMENT": AttackType.SPOOFING_RELAXED_ALIGNMENT,
    "SPOOFING_DOMAIN_TAKEOVER": AttackType.SPOOFING_DOMAIN_TAKEOVER,
    "OPEN_RELAY":            AttackType.OPEN_RELAY,
}

_CATEGORY_MAP: Dict[str, AttackCategory] = {
    "MITM":     AttackCategory.MITM,
    "INTERNAL": AttackCategory.MITM,      # legacy templates
    "EXTERNAL": AttackCategory.EXTERNAL,
}

_STATUS_MAP: Dict[str, VectorStatus] = {
    "CONFIRMED":  VectorStatus.CONFIRMED,
    "UNVERIFIED": VectorStatus.UNVERIFIED,
    "BLOCKED":    VectorStatus.BLOCKED,
}


class AttackScenarioAnalyzer:
    """
    Analyse mail security posture and generate actionable attack scenarios.

    Parameters
    ----------
    domain : str
        The domain being audited.
    smtp_result : dict | None
        Result dict from DomainChecker (smtp_checker module).
    spf_result : dict | None
        Result dict from SPFChecker.to_dict() (mail_antispoof module).
    dmarc_result : dict | None
        Result dict from DMARCChecker.to_dict() (mail_antispoof module).
    dkim_result : dict | None
        Result dict from DKIMChecker.to_dict() (mail_antispoof module).
    email_services : dict
        Dict loaded from email_services.json["services"].
    """

    def __init__(
        self,
        domain: str,
        smtp_result: Optional[Dict[str, Any]],
        spf_result: Optional[Dict[str, Any]],
        dmarc_result: Optional[Dict[str, Any]],
        dkim_result: Optional[Dict[str, Any]],
        email_services: Dict[str, Any],
        org_domain: Optional[str] = None,
        org_dmarc_result: Optional[Dict[str, Any]] = None,
        org_family: Optional[List[Tuple[str, Optional[Dict[str, Any]]]]] = None,
    ) -> None:
        self.domain = domain
        self.smtp_result = smtp_result or {}
        self.spf_result = spf_result or {}
        self.dmarc_result = dmarc_result or {}
        self.dkim_result = dkim_result or {}
        self.email_services = email_services
        # Organizational (registrable) parent and its own DMARC, for the
        # relaxed-alignment cross-domain spoofing analysis. ``org_domain`` is set
        # only when ``domain`` is a strict subdomain; both default to None, which
        # disables that analysis (keeps behavior unchanged when not wired).
        self.org_domain = org_domain
        self.org_dmarc_result = org_dmarc_result or {}
        # Other audited domains sharing this org domain (sibling From targets), as
        # (domain, dmarc_result) pairs. Relaxed alignment is symmetric at the org
        # level, so a leverage here can also forge a From on these.
        self.org_family = org_family or []
        self._tpl = _load_templates()
        self._tests = _load_tests()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> List[AttackScenario]:
        """Run all analyses and return a deduplicated list of attack scenarios."""
        scenarios: List[AttackScenario] = []
        scenarios.extend(self._analyze_internal_mitm())
        scenarios.extend(self._analyze_external_spoofing())
        scenarios.extend(self._analyze_spf_qualifier_rules())
        scenarios.extend(self._analyze_domain_takeover())
        scenarios.extend(self._analyze_open_relay())
        scenarios.extend(self._analyze_relaxed_alignment())
        self._assign_risk_and_bypass(scenarios)
        return scenarios

    # ------------------------------------------------------------------
    # Risk (impact x likelihood) and bypass tagging
    # ------------------------------------------------------------------

    _RISK_ORDER = RISK_ORDER
    _LIKELIHOODS = set(LIKELIHOOD_ORDER)
    # Template baseline -> (risk, probability) when a scenario has no vector (fallback)
    _BASELINE_FALLBACK = {
        "critical": ("critical", "very_high"), "high": ("high", "high"),
        "medium": ("moderate", "medium"), "low": ("low", "low"), "informational": ("low", "very_low"),
    }

    def _risk_of(self, impact: str, likelihood: str) -> str:
        """Look up risk_matrix[impact][probability] from scenario_templates.json.

        Impact: low / medium / high / critical.  Probability: very_low / low /
        medium / high / very_high.  Risk: low / moderate / high / critical.
        """
        matrix: Dict[str, Dict[str, str]] = self._tpl.get("risk_matrix", {})
        row = matrix.get((impact or "medium").lower(), {})
        return row.get((likelihood or "medium").lower(), "moderate")

    def _bypass_profile(self, scenario: AttackScenario) -> Tuple[List[str], List[str], List[str]]:
        """(certain bypasses, conditional bypasses, notes) derived from the attack type.

        A control is *certainly* bypassed when the technique defeats it by itself; it
        is *conditionally* bypassed when that depends on a configuration the audit
        cannot observe (the note says which).  Open relay and template-tagged
        scenarios set their own profile at build time.
        """
        at = scenario.attack_type
        signed = ", ".join(sorted({v.dkim for v in scenario.attack_vectors if v.dkim}))
        if at == AttackType.SPOOFING_SHARED_HOSTING:
            return ["SPF", "DMARC"], ["DKIM"], [
                "SPF: the host's outbound IPs are authorized by the domain's SPF and the attacker "
                "sets the MAIL FROM to the domain, so SPF passes aligned.",
                "DMARC: passes through SPF alignment (SPF OR DKIM), whatever the policy, even p=reject.",
                "DKIM (possible): only if the host's MTA signs with the DKIM key of the sender "
                "domain without checking that the sending account owns it (key picked by sender "
                "domain for every domain hosted on the platform). "
                + (f"Observed in tests: signed {signed} (host key, not aligned with the forged "
                      "From -> no DKIM alignment, but the valid signature avoids a missing-signature "
                      "penalty such as Rspamd R_DKIM_NA; DMARC still passes via SPF)." if signed
                      else "Not observed."),
            ]
        if at in (AttackType.SPOOFING_NO_POLICY, AttackType.SPOOFING_NO_DMARC_ENFORCEMENT,
                  AttackType.SPOOFING_AUTH_MISCONFIG):
            return ["SPF", "DKIM"], [], [
                "SPF / DKIM: trivially defeated because nothing enforces them: the attacker sends "
                "from their own server (SPF fails for the domain, or passes for the attacker's own "
                "MAIL FROM domain) and signs with their own DKIM key.",
                "DMARC: not bypassed, it is absent or monitoring-only (p=none): nothing to bypass.",
            ]
        if at in (AttackType.SPOOFING_FREE_EMAIL, AttackType.SPOOFING_EMAIL_SERVICE):
            return ["SPF"], [], [
                "SPF: the service's IPs are in the domain's SPF, so the From domain's SPF matches "
                "the sending IP (reputation / non-RFC checks). The envelope MAIL FROM stays the "
                "service's own domain, so SPF is not aligned.",
                "DKIM: signed by the service" + (f" ({signed})" if signed else "")
                + ", not aligned with the forged From: not bypassed.",
                "DMARC: not bypassed (no alignment). Delivery relies on the service's IP "
                "reputation: works when DMARC is absent / p=none, or when the receiver does not "
                "act on the DMARC result.",
            ]
        return [], [], []

    def _assign_risk_and_bypass(self, scenarios: List[AttackScenario]) -> None:
        """Assign per-vector impact/probability/risk, the scenario risk/probability and bypasses.

        Each vector gets its impact and probability (``likelihood``) from
        ``vector_defaults`` unless set at build time (template, dated test); a
        ``blocked`` vector gets probability ``very_low`` and risk ``low``.  Vector
        risk = ``risk_matrix[impact][probability]``.  The scenario **risk** is the
        worst vector risk and its **probability** the probability of that vector
        (highest one on ties).  Scenarios without vectors fall back to the template
        baseline.
        """
        defaults: Dict[str, Dict[str, str]] = self._tpl.get("vector_defaults", {})
        default_row = defaults.get("default", {"impact": "high", "likelihood": "medium"})

        for sc in scenarios:
            for v in sc.attack_vectors:
                d = defaults.get(v.vector_type, default_row)
                if not v.impact:
                    v.impact = d.get("impact", "high")
                status = (v.status or "").lower()
                blocked = status == "blocked"
                if blocked:
                    v.likelihood = "very_low"
                elif status == "confirmed" and (not v.likelihood or v.likelihood not in self._LIKELIHOODS):
                    # A dated test confirmed the vector works today -> high (a dated
                    # test that softens it sets its own likelihood, kept above).
                    v.likelihood = "high"
                elif not v.likelihood or v.likelihood not in self._LIKELIHOODS:
                    v.likelihood = d.get("likelihood", "medium")
                # A tested-and-blocked vector carries only residual risk.
                v.risk = "low" if blocked else self._risk_of(v.impact, v.likelihood)
                # SMTP transport: submission (587/465, client->server, authenticated) vs
                # direct MX / relay (25, server->server). Explicit values win.
                dp, dt = _smtp_transport(v.vector_type, v.auth_mode)
                if not v.port:
                    v.port = dp
                if not v.transport:
                    v.transport = dt

            if sc.attack_vectors:
                worst = min(sc.attack_vectors, key=lambda v: (
                    self._RISK_ORDER.get(v.risk, 9), LIKELIHOOD_ORDER.get(v.likelihood, 9)))
                sc.risk, sc.probability = worst.risk, worst.likelihood
            else:
                sc.risk, sc.probability = self._BASELINE_FALLBACK.get(
                    sc.baseline.value, ("moderate", "medium"))

            # Reputation, no DMARC enforcement: worse than a home server -> CRITICAL.
            if getattr(sc, "_reputation_none", False) and sc.risk == "high":
                sc.risk = "critical"

            # Keep an explicit per-template / build-time profile; otherwise derive it.
            if not (sc.bypasses or sc.conditional_bypasses or sc.bypass_notes):
                sc.bypasses, sc.conditional_bypasses, sc.bypass_notes = self._bypass_profile(sc)

    # ------------------------------------------------------------------
    # Issue code helpers
    # ------------------------------------------------------------------

    def _has_issue(self, result_key: str, code: str) -> bool:
        """Return True if *code* appears in the issues list of the given result.

        result_key maps to the checker output:
          "spf"   → self.spf_result
          "dmarc" → self.dmarc_result
          "dkim"  → self.dkim_result
          "smtp"  → self.smtp_result  (domain-level issues from smtp_checker)
        """
        result_map = {
            "spf":   self.spf_result,
            "dmarc": self.dmarc_result,
            "dkim":  self.dkim_result,
            "smtp":  self.smtp_result,
        }
        issues = result_map.get(result_key, {}).get("issues", [])
        return any(i.get("code") == code for i in issues)

    @staticmethod
    def _mx_has_issue(mx_result: Dict[str, Any], code: str) -> bool:
        """Return True if *code* appears in a per-MX issues list."""
        return any(i.get("code") == code for i in mx_result.get("issues", []))

    # ------------------------------------------------------------------
    # Template rendering helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _render(template: str, **ctx: Any) -> str:
        """Replace {key} placeholders in *template* with values from *ctx*."""
        for key, value in ctx.items():
            template = template.replace("{" + key + "}", str(value) if value is not None else "")
        return template

    @classmethod
    def _render_list(cls, templates: List[str], **ctx: Any) -> List[str]:
        return [cls._render(t, **ctx) for t in templates]

    @classmethod
    def _build_vectors(
        cls, vector_templates: List[Dict[str, Any]], **ctx: Any
    ) -> List[AttackVector]:
        vectors: List[AttackVector] = []
        for vt in vector_templates:
            steps_raw = vt.get("steps", "") or ""
            steps = cls._render(steps_raw, **ctx) if steps_raw else None
            note_raw = vt.get("probability_note", "") or ""
            note = cls._render(note_raw, **ctx) if note_raw else None
            desc_raw = vt.get("description", "") or ""
            desc = cls._render(desc_raw, **ctx) if desc_raw else ""
            vectors.append(
                AttackVector(
                    vector_type=vt.get("vector_type", "smtp_server"),
                    auth_mode=vt.get("auth_mode"),
                    status=_STATUS_MAP.get(
                        (vt.get("status") or "UNVERIFIED").upper(),
                        VectorStatus.UNVERIFIED,
                    ),
                    description=desc,
                    steps=steps,
                    probability_note=note,
                    dkim=vt.get("dkim", ""),
                    impact=(vt.get("impact") or "").lower(),
                    likelihood=(vt.get("likelihood") or "").lower(),
                    port=vt.get("port", ""),
                    transport=vt.get("transport", ""),
                )
            )
        return vectors

    def _make_scenario(
        self,
        tpl: Dict[str, Any],
        probability: AttackProbability,
        *,
        service_name: Optional[str] = None,
        mx_host: Optional[str] = None,
        extra_conditions: Optional[List[str]] = None,
        **ctx: Any,
    ) -> AttackScenario:
        """Instantiate an AttackScenario from a template dict + runtime context."""
        ctx.setdefault("domain", self.domain)
        if mx_host:
            ctx["mx_host"] = mx_host
        if service_name:
            ctx["service_name"] = service_name

        category = _CATEGORY_MAP.get(
            tpl.get("attack_category", "EXTERNAL").upper(), AttackCategory.EXTERNAL
        )
        attack_type = _ATTACK_TYPE_MAP.get(
            tpl.get("attack_type", "SPOOFING_NO_POLICY"), AttackType.SPOOFING_NO_POLICY
        )
        scenario_name = self._render(tpl.get("scenario_name", ""), **ctx)
        conditions = self._render_list(tpl.get("conditions_met", []), **ctx)
        if extra_conditions:
            conditions.extend(extra_conditions)
        description = self._render(tpl.get("description_template", ""), **ctx)
        remediation = self._render(tpl.get("remediation", ""), **ctx)
        vectors = self._build_vectors(tpl.get("vectors", []), **ctx)

        scenario = AttackScenario(
            domain=self.domain,
            attack_category=category,
            attack_type=attack_type,
            scenario_name=scenario_name,
            baseline=probability,
            conditions_met=conditions,
            description=description,
            attack_vectors=vectors,
            remediation=remediation,
            service_name=service_name,
            mx_host=mx_host,
            bypasses=list(tpl.get("bypasses", [])),  # explicit tag; else derived in _assign_risk_and_bypass
            conditional_bypasses=list(tpl.get("conditional_bypasses", [])),
            bypass_notes=self._render_list(tpl.get("bypass_notes", []), **ctx),
        )
        scenario._tpl = tpl    # kept (not exported) to re-render MX-grouped scenarios
        scenario._ctx = ctx
        return scenario

    # ------------------------------------------------------------------
    # MITM analysis
    # ------------------------------------------------------------------

    def _analyze_internal_mitm(self) -> List[AttackScenario]:
        scenarios: List[AttackScenario] = []
        scenarios.extend(self._check_ssl_stripping())
        scenarios.extend(self._check_dane_fake_cert())
        scenarios.extend(self._check_tlsa_without_dnssec())
        return scenarios

    def _reachable_mx(self) -> List[Dict[str, Any]]:
        """MX results whose SMTP server could be reached.

        A domain without MX falls back to its own name (implicit MX, RFC 5321);
        when that name does not even resolve there is no server to intercept, so
        no MITM scenario is produced for it.
        """
        return [
            mx for mx in self.smtp_result.get("mx_results", [])
            if mx and not (mx.get("smtp") or {}).get("error")
        ]

    _MITM_SERVICE = "SMTP (TCP 25)"

    @staticmethod
    def _mx_dane_usable(mx: Dict[str, Any]) -> bool:
        """DANE that senders actually enforce: TLSA matching the cert AND DNSSEC-validated."""
        dane = mx.get("dane") or {}
        return bool(dane.get("dane_valid") and dane.get("dane_usable"))

    def _tlsa_state(self, mx: Dict[str, Any]) -> str:
        if self._mx_has_issue(mx, "dane_no_tlsa"):
            return "no TLSA records"
        if self._mx_has_issue(mx, "tlsa_no_dnssec"):
            return "TLSA records not DNSSEC-validated, ignored by DANE senders"
        return "TLSA records do not match the certificate"

    def _mta_sts_state(self) -> Tuple[str, str]:
        """("absent" | "non_enforce" | "enforce", mode)."""
        if self._has_issue("smtp", "mta_sts_missing"):
            return "absent", ""
        if self._has_issue("smtp", "mta_sts_non_enforce"):
            mode = (self.smtp_result.get("mta_sts", {}).get("policy") or {}).get("mode") or "testing"
            return "non_enforce", mode
        return "enforce", "enforce"

    def _check_ssl_stripping(self) -> List[AttackScenario]:
        """
        STARTTLS downgrade when MTA-STS is absent or not in enforce mode (smtp_checker
        issues mta_sts_missing / mta_sts_non_enforce).  One scenario per reachable MX
        host (grouped across domains by group_mx_scenarios()).  If the MX has usable
        DANE, DANE-aware senders refuse the downgrade: probability lowered to low.
        """
        mitm = self._tpl["internal_mitm"]
        state, mode = self._mta_sts_state()
        if state == "enforce":
            return []
        tpl = mitm["ssl_stripping_absent" if state == "absent" else "ssl_stripping_non_enforce"]
        scenarios = []
        for mx in self._reachable_mx():
            host = mx.get("hostname", "unknown")
            dane = self._mx_dane_usable(mx)
            ctx = {
                "dane_condition": (f"DANE usable for {host}: DANE-aware senders refuse the "
                                   f"downgrade, the others do not") if dane else
                                  f"no usable DANE for {host} ({self._tlsa_state(mx)})",
                "dane_clause": " (the MX has usable DANE, which only DANE-aware senders enforce)"
                               if dane else " and the MX has no usable DANE",
            }
            sc = self._make_scenario(tpl, AttackProbability.HIGH, mx_host=host, mode=mode,
                                     service_name=self._MITM_SERVICE, **ctx)
            if dane:
                for v in sc.attack_vectors:
                    v.likelihood = "low"
            scenarios.append(sc)
        return scenarios

    def _check_dane_fake_cert(self) -> List[AttackScenario]:
        """
        Interception with a certificate the sender accepts, on an MX without usable DANE:

        * no MTA-STS enforce -> opportunistic senders do not validate the certificate:
          any attacker certificate works (``fake_cert_opportunistic``, medium);
        * MTA-STS enforce -> PKIX validation: a fraudulent publicly trusted certificate
          is needed (``fake_cert_pkix``, low).
        """
        mitm = self._tpl["internal_mitm"]
        state, _ = self._mta_sts_state()
        tpl = mitm["fake_cert_pkix" if state == "enforce" else "fake_cert_opportunistic"]
        sts_condition = {
            "absent": "absent or invalid",
            "non_enforce": "present but not in enforce mode",
            "enforce": "enforce",
        }[state]
        return [
            self._make_scenario(tpl, AttackProbability.MEDIUM, mx_host=mx.get("hostname", "unknown"),
                                service_name=self._MITM_SERVICE, sts_condition=sts_condition,
                                tlsa_state=self._tlsa_state(mx))
            for mx in self._reachable_mx()
            if not self._mx_dane_usable(mx)
        ]

    def _check_tlsa_without_dnssec(self) -> List[AttackScenario]:
        """
        TLSA records without DNSSEC — ignored by DANE senders (RFC 7672): no DANE at all.
        Detected via smtp_checker issue slug 'tlsa_no_dnssec'.
        """
        tpl = self._tpl["internal_mitm"]["tlsa_without_dnssec"]
        # Same exposure as an MX without DANE: medium, or low (fraudulent CA
        # certificate needed) when MTA-STS enforce protects the domain.
        enforce = self._mta_sts_state()[0] == "enforce"
        scenarios = []
        for mx in self._reachable_mx():
            if not self._mx_has_issue(mx, "tlsa_no_dnssec"):
                continue
            sc = self._make_scenario(tpl, AttackProbability.HIGH, mx_host=mx.get("hostname", "unknown"),
                                     service_name=self._MITM_SERVICE)
            if enforce:
                for v in sc.attack_vectors:
                    v.likelihood = "low"
            scenarios.append(sc)
        return scenarios

    # ------------------------------------------------------------------
    # External spoofing analysis
    # ------------------------------------------------------------------

    def _dmarc_state(self) -> Tuple[str, str]:
        """Effective DMARC state ("none" / "absent" / "quarantine" / "reject") + condition text.

        p=quarantine is treated separately from p=reject: a quarantined spoof is
        NOT rejected — it lands in spam, and a reputable sender can still pull it
        to the inbox. So quarantine is far more dangerous than reject.
        """
        if self._has_issue("dmarc", "dmarc_lax_policy"):
            return "none", "DMARC policy is 'none' (monitoring only, no enforcement)"
        if self._has_issue("dmarc", "no_dmarc"):
            return "absent", "DMARC record is completely absent"
        if (self.dmarc_result.get("policy") or "").lower() == "quarantine":
            return "quarantine", "DMARC is enforced with p=quarantine (failing mail is sent to spam, not rejected)"
        return "reject", "DMARC is enforced with p=reject (failing mail is rejected)"

    def _analyze_external_spoofing(self) -> List[AttackScenario]:
        """
        Generate spoofing scenarios. Probability = f(vector, DMARC state); three
        vector classes:

        * **Shared Hosting** *aligns* — with local-MTA auth the attacker sends from
          an SPF-authorized IP and overwrites the MAIL FROM to the victim domain, so
          SPF aligns and DMARC actually PASSES, even at ``p=reject``. DMARC-independent,
          status-driven (confirmed CRITICAL / unverified HIGH), refined by dated tests.
        * **Reputable service in the victim's SPF** (Free Mail, Email Delivery) — the
          forged From is not aligned, but the From-domain's own SPF authorizes the
          sending IP and the service reputation defeats non-RFC heuristics, so it lands
          even at ``p=reject``. Fires at every DMARC state: ``none`` → CRITICAL,
          ``absent`` → HIGH, ``enforced`` → MEDIUM.
        * **Well-configured attacker server** (IP not in the SPF) — with no DMARC
          there is no alignment to satisfy, so it is delivered: ``none`` → CRITICAL,
          ``absent`` → HIGH. Blocked once DMARC is enforced (no reputation fallback).

        ``p=none`` is rated above an absent record throughout (explicit non-enforcement
        vs. a receiver free to reject a no-DMARC domain). Dated tests in
        ``data/tests/`` OVERRIDE the per-service baseline.
        """
        # Issue codes from mail_antispoof_policy_checker are the authoritative source.
        dmarc_missing = self._has_issue("dmarc", "no_dmarc")
        dmarc_none    = self._has_issue("dmarc", "dmarc_lax_policy")
        dmarc_unprotected = dmarc_missing or dmarc_none
        dmarc_policy = (self.dmarc_result.get("policy") or "").lower()

        dmarc_state, dmarc_condition = self._dmarc_state()

        scenarios: List[AttackScenario] = []
        matched_services: Dict[str, Dict[str, Any]] = {}

        # ── Path A: match via SPF includes ──────────────────────────────────
        all_includes: List[Dict[str, Any]] = self.spf_result.get("all_includes", [])
        for include_entry in all_includes:
            match_info = self._match_service(include_entry)
            if match_info is not None:
                svc_name = match_info["service_name"]
                if svc_name not in matched_services:
                    matched_services[svc_name] = match_info

        # ── Path B: match via SPF issues (IP range overlap with known services)
        spf_issues: List[Dict[str, Any]] = self.spf_result.get("issues", [])
        for issue in spf_issues:
            additional_data = issue.get("additional_data") or {}
            svc_name = additional_data.get("service_name")
            svc_type = additional_data.get("service_type", "")
            if not svc_name or svc_name in matched_services:
                continue
            svc_config = self.email_services.get(svc_name)
            if svc_config:
                matched_services[svc_name] = {
                    "service_name":   svc_name,
                    "service_type":   svc_type or svc_config.get("service_type", ""),
                    "attack_vectors": svc_config.get("attack_vectors", []),
                    "include_domain": additional_data.get("ip_range", ""),
                }

        # One scenario per matched service (a service listed in the victim's SPF).
        # These fire at ANY DMARC state: shared hosting via alignment (CRITICAL even
        # at p=reject), reputable services via reputation + the From-domain SPF
        # matching the sending IP (dmarc_none CRITICAL / absent HIGH / enforced MEDIUM).
        for match_info in matched_services.values():
            is_shared = match_info.get("service_type") == "Shared Hosting"
            if is_shared and not dmarc_unprotected:
                svc_condition = (
                    "DMARC is enforced but bypassed via an aligned MAIL FROM on "
                    "shared infrastructure (works even under p=reject)"
                )
            else:
                svc_condition = dmarc_condition
            scenario = self._build_service_spoofing_scenario(match_info, svc_condition, dmarc_state)
            if scenario:
                scenarios.append(scenario)

        spf_record = self.spf_result.get("spf_record")

        # Direct spoof via a well-configured attacker-owned server (IP NOT in the
        # victim's SPF): with no DMARC there is no alignment to satisfy, so it lands.
        # DMARC-gated (blocked once enforced) and independent of whether SPF exists.
        # none -> CRITICAL, absent -> HIGH.
        if dmarc_unprotected:
            scenarios.append(self._build_generic_scenario(dmarc_condition, dmarc_state))

        # Extra detail: SPF present with critical issues but no known service matched.
        if dmarc_unprotected and spf_record and not matched_services:
            critical_issues = [
                i for i in spf_issues
                if i.get("severity") in ("critical", "high")
            ]
            if critical_issues:
                scenarios.append(
                    self._build_spf_issue_scenario(critical_issues, dmarc_condition)
                )

        return scenarios

    def _apply_test_overrides(
        self, svc_name: str, svc_vectors: List[Dict[str, Any]], dmarc_state: str
    ) -> Optional[Dict[str, Any]]:
        """Apply dated ``data/tests/`` overrides for a service.

        Returns ``None`` if the whole scenario is eliminated, otherwise a dict
        ``{"vectors", "probability_override", "notes"}``. ``svc_vectors`` is not
        mutated (a shallow copy of each vector is used). A ``soften`` test may carry
        a ``by_dmarc`` entry per DMARC state, overriding its likelihood, impact,
        probability and adding a note.
        """
        vectors = [dict(v) for v in svc_vectors]
        override_prob: Optional[AttackProbability] = None
        notes: List[str] = []

        def _matches(vec: Dict[str, Any], vfilter: Dict[str, Any]) -> bool:
            return all(vec.get(k) == val for k, val in vfilter.items())

        for t in self._tests.get(svc_name, []):
            effect = (t.get("effect") or "").lower()
            vfilter = t.get("vector")
            date = t.get("date", "")
            note = t.get("note")
            src = t.get("source")
            note_suffix = f" (source: {src})" if src else ""
            if effect == "eliminate":
                if vfilter:
                    vectors = [v for v in vectors if not _matches(v, vfilter)]
                    if note:
                        notes.append(f"[test {date}] {note}{note_suffix}")
                else:
                    return None  # whole service scenario eliminated
            elif effect == "confirm":
                for v in vectors:
                    if not vfilter or _matches(v, vfilter):
                        v["status"] = "confirmed"
                if t.get("probability"):
                    override_prob = self._parse_probability(t["probability"])
                if note:
                    notes.append(f"[test {date} PASS] {note}{note_suffix}")
            elif effect == "downgrade":
                # Tested and blocked (residual risk only).
                for v in vectors:
                    if not vfilter or _matches(v, vfilter):
                        v["status"] = "blocked"
                if t.get("probability"):
                    override_prob = self._parse_probability(t["probability"])
                if note:
                    notes.append(f"[test {date} FAIL] {note}{note_suffix}")
            elif effect == "soften":
                # Still reachable but much less likely (e.g. web_ui domain
                # verification): lower the likelihood, keep the vector visible.
                row = (t.get("by_dmarc") or {}).get(dmarc_state, {})
                lk = (row.get("likelihood") or t.get("likelihood") or "low").lower()
                for v in vectors:
                    if not vfilter or _matches(v, vfilter):
                        v["likelihood"] = lk
                        if row.get("impact"):
                            v["impact"] = row["impact"].lower()
                probability = row.get("probability") or t.get("probability")
                if probability:
                    override_prob = self._parse_probability(probability)
                if note:
                    detail = f" {row['note']}" if row.get("note") else ""
                    notes.append(f"[test {date}] {note}{detail}{note_suffix}")

        if not vectors:
            return None
        return {"vectors": vectors, "probability_override": override_prob, "notes": notes}

    def _build_service_spoofing_scenario(
        self,
        match_info: Dict[str, Any],
        dmarc_condition: str,
        dmarc_state: str,
    ) -> Optional[AttackScenario]:
        """Build a spoofing scenario for a matched service using JSON templates.

        Probability:

        * **Shared Hosting** *aligns* (bypass even ``p=reject``) → driven by vector
          status (confirmed → CRITICAL, unverified → HIGH).
        * **Non-aligned services** (Free Mail, Email Delivery) → driven by the DMARC
          state: ``p=none`` → CRITICAL, absent → HIGH (p=none is worse — explicit
          non-enforcement + the forged From-domain SPF matches the whitelisted IP).

        A dated test override, when present, wins; ``all_blocked`` → LOW.
        """
        svc_name: str = match_info.get("service_name", "Unknown Service")
        csv_service_type: str = match_info.get("service_type", "")
        is_shared = csv_service_type == "Shared Hosting"

        overrides = self._apply_test_overrides(
            svc_name, match_info.get("attack_vectors", []), dmarc_state
        )
        if overrides is None:
            return None  # eliminated by a dated test (e.g. Outlook MFEF → SRS)
        svc_vectors = overrides["vectors"]

        # Reputation services (in the victim's SPF, non-shared): the forged From is
        # NOT aligned (the MAIL FROM stays the service's bounce domain), but the
        # service's sending reputation makes it land — and the outcome depends on the
        # DMARC state (p=none > absent > enforced). Set each non-blocked vector's
        # likelihood from the DMARC state unless a dated test already pinned it.
        if not is_shared:
            # p=none/absent/quarantine still deliver (quarantine = spam, reputation can
            # inbox it) -> high; only p=reject actually stops it -> low.
            rep_lk = {"none": "high", "absent": "high", "quarantine": "high", "reject": "low"}.get(dmarc_state, "medium")
            for vec in svc_vectors:
                if (vec.get("status") or "").lower() != "blocked" and not vec.get("likelihood"):
                    vec["likelihood"] = rep_lk

        ext = self._tpl["external_spoofing"]

        # Attack type from JSON config.
        at_map: Dict[str, str] = ext["service_type_attack_type"]
        attack_type = _ATTACK_TYPE_MAP.get(
            at_map.get(csv_service_type, at_map.get("default", "SPOOFING_EMAIL_SERVICE")),
            AttackType.SPOOFING_EMAIL_SERVICE,
        )

        # Base probability: shared hosting is status-driven (it aligns), non-aligned
        # services are DMARC-state-driven (p=none > absent).
        prob_rules: Dict[str, Dict[str, str]] = ext["service_type_probability"]
        service_probs = prob_rules.get(csv_service_type, prob_rules.get("default", {}))
        statuses = [(v.get("status") or "unverified").lower() for v in svc_vectors]
        if all(s == "blocked" for s in statuses):
            prob_key = "all_blocked"
        elif is_shared:
            prob_key = "confirmed" if "confirmed" in statuses else "unverified"
        else:
            prob_key = {
                "none": "dmarc_none",
                "absent": "dmarc_absent",
                "quarantine": "dmarc_enforced",
                "reject": "dmarc_enforced",
            }.get(dmarc_state, "dmarc_absent")
        base_prob = self._parse_probability(service_probs.get(prob_key, "MEDIUM"))

        # A dated test override wins over the reputation baseline.
        final_prob = overrides["probability_override"] or base_prob
        prob_label = final_prob.value

        # Build vectors from email_services.json (post-override).
        attack_vectors: List[AttackVector] = []
        for vec in svc_vectors:
            attack_vectors.append(
                AttackVector(
                    vector_type=vec.get("vector_type", "unknown"),
                    auth_mode=vec.get("auth_mode"),
                    status=_STATUS_MAP.get(
                        (vec.get("status") or "UNVERIFIED").upper(),
                        VectorStatus.UNVERIFIED,
                    ),
                    description=vec.get("notes", ""),
                    impact=(vec.get("impact") or "").lower(),
                    likelihood=(vec.get("likelihood") or "").lower(),
                    dkim=vec.get("dkim", ""),
                    shared=bool(vec.get("shared")),
                    port=vec.get("port", ""),
                    transport=vec.get("transport", ""),
                )
            )

        # Shared Hosting uses a dedicated, DMARC-independent template/name.
        svc_tpl = (
            ext["shared_hosting_spoofing_template"]
            if is_shared
            else ext["service_spoofing_template"]
        )
        ctx = {
            "domain":                self.domain,
            "service_name":          svc_name,
            "service_type":          csv_service_type,
            "dmarc_condition":       dmarc_condition,
            "dmarc_condition_lower": dmarc_condition.lower(),
            "prob_label":            prob_label,
        }
        conditions = self._render_list(svc_tpl["conditions_met"], **ctx)
        conditions.extend(overrides["notes"])  # dated-test provenance

        scenario = AttackScenario(
            domain=self.domain,
            attack_category=AttackCategory.EXTERNAL,
            attack_type=attack_type,
            scenario_name=self._render(svc_tpl["scenario_name"], **ctx),
            baseline=final_prob,
            conditions_met=conditions,
            description=self._render(svc_tpl["description_template"], **ctx),
            attack_vectors=attack_vectors,
            remediation=self._render(
                svc_tpl.get("remediation_by_dmarc", {}).get(dmarc_state, svc_tpl["remediation"]), **ctx
            ),
            service_name=svc_name,
        )
        # Reputation boost: a forged From delivered from a high-reputation, SPF-listed
        # sender with NO DMARC enforcement is worse than the same spoof from a
        # reputation-less home server (which spam heuristics catch more often). Bump
        # the scenario to CRITICAL. Handled in _assign_risk_and_bypass.
        if not is_shared and dmarc_state == "none" and any(
            (v.status or "").lower() != "blocked" for v in attack_vectors
        ):
            setattr(scenario, "_reputation_none", True)
        return scenario

    def _build_generic_scenario(self, dmarc_condition: str, dmarc_state: str) -> AttackScenario:
        """Direct spoof via a well-configured attacker server (IP not in the SPF).

        No DMARC means no alignment to satisfy: ``none`` → CRITICAL, ``absent`` →
        HIGH. Not emitted when DMARC is enforced (this vector has no reputation to
        fall back on).
        """
        tpl = self._tpl["external_spoofing"]["generic_custom_server"]
        by_state: Dict[str, str] = tpl.get("probability_by_dmarc", {})
        prob = self._parse_probability(by_state.get(dmarc_state, tpl.get("probability", "HIGH")))
        return self._make_scenario(
            tpl,
            prob,
            dmarc_condition=dmarc_condition,
            dmarc_condition_lower=dmarc_condition.lower(),
            prob_label=prob.value,
        )

    def _build_no_policy_scenario(self, dmarc_condition: str) -> AttackScenario:
        """Generate a generic spoofing scenario when neither SPF nor DMARC is present."""
        tpl = self._tpl["external_spoofing"]["no_policy"]
        prob = self._parse_probability(tpl["probability"])
        return self._make_scenario(
            tpl, prob, dmarc_condition=dmarc_condition
        )

    def _build_spf_issue_scenario(
        self,
        critical_issues: List[Dict[str, Any]],
        dmarc_condition: str,
    ) -> AttackScenario:
        """Generate a scenario when SPF has critical issues but no matched service."""
        tpl = self._tpl["external_spoofing"]["spf_issue"]
        prob = self._parse_probability(tpl["probability"])

        issue_titles = [i.get("title", "Unknown issue") for i in critical_issues[:3]]
        extra = [f"SPF issue: {t}" for t in issue_titles]

        return self._make_scenario(
            tpl,
            prob,
            extra_conditions=extra,
            dmarc_condition=dmarc_condition,
            dmarc_condition_lower=dmarc_condition.lower(),
            issue_count=str(len(critical_issues)),
        )

    # ------------------------------------------------------------------
    # SPF qualifier rule-based scenarios (driven by scenario_templates.json)
    # ------------------------------------------------------------------

    def _analyze_spf_qualifier_rules(self) -> List[AttackScenario]:
        """Generate scenarios from the spf_qualifier_rules list in scenario_templates.json.

        Each rule declares ``condition_issue_codes`` — a list of
        ``{"module", "result_key", "code"}`` entries that ALL must be present
        in the corresponding checker result for the rule to fire.  Optional:

        - ``condition_any_issue_codes``: at least ONE of these must be present
          (e.g. "SPF is weak": ``spf_softfail`` / ``spf_neutral`` / ``no_spf``…);
        - ``condition_absent_issue_codes``: NONE of these may be present (used to
          keep a weaker variant from duplicating a stronger one, e.g.
          "potentially unregistered" when "unregistered" already fired).

        Issue slugs used (from mail_antispoof_policy_checker):
          spf_pass         = +all (Pass all)   → authorises every sender
          spf_softfail     = ~all (SoftFail)   → marks but does not reject
          no_dmarc         = No DMARC          → zero enforcement
          dmarc_lax_policy = p=none            → monitoring only
          *_cname_target_(potentially_)unregistered, spf_domain_(potentially_)unregistered
                           = buyable domain behind a CNAME / an SPF include
        """
        rules: List[Dict[str, Any]] = (
            self._tpl.get("external_spoofing", {}).get("spf_qualifier_rules", [])
        )
        scenarios: List[AttackScenario] = []

        def present(c: Dict[str, Any]) -> bool:
            return self._has_issue(c["result_key"], c["code"])

        for rule in rules:
            condition_codes: List[Dict[str, Any]] = rule.get("condition_issue_codes", [])
            if not condition_codes:
                continue
            # All declared issue codes must be present
            if not all(present(c) for c in condition_codes):
                continue
            any_codes = rule.get("condition_any_issue_codes") or []
            if any_codes and not any(present(c) for c in any_codes):
                continue
            if any(present(c) for c in rule.get("condition_absent_issue_codes") or []):
                continue

            prob = self._parse_probability(rule.get("probability", "MEDIUM"))
            scenarios.append(self._make_scenario(rule, prob))

        return scenarios

    # ------------------------------------------------------------------
    # Unregistered domain takeover (CNAME targets / SPF includes)
    # ------------------------------------------------------------------

    # issue code -> (kind in templates, registration state)
    _TAKEOVER_CODES = {
        "spf_cname_target_unregistered":               ("spf_cname",   "unregistered"),
        "spf_cname_target_potentially_unregistered":   ("spf_cname",   "potentially_unregistered"),
        "spf_domain_unregistered":                     ("spf_include", "unregistered"),
        "spf_domain_potentially_unregistered":         ("spf_include", "potentially_unregistered"),
        "dkim_cname_target_unregistered":              ("dkim_cname",  "unregistered"),
        "dkim_cname_target_potentially_unregistered":  ("dkim_cname",  "potentially_unregistered"),
        "dmarc_cname_target_unregistered":             ("dmarc_cname", "unregistered"),
        "dmarc_cname_target_potentially_unregistered": ("dmarc_cname", "potentially_unregistered"),
    }
    _CONTROL_ORDER = ("SPF", "DKIM", "DMARC")

    def _analyze_domain_takeover(self) -> List[AttackScenario]:
        """One scenario per domain for every DNS name pointing into a buyable domain.

        Built from the registration issues of mail_antispoof_policy_checker
        (``*_cname_target_(potentially_)unregistered`` and
        ``spf_domain_(potentially_)unregistered``): one condition and one vector
        per vulnerable name, naming the domain to buy.  Bypasses tag only the
        hijacked control (SPF for an include/CNAME, DKIM for a selector CNAME,
        DMARC for a ``_dmarc`` CNAME); DMARC passing via SPF/DKIM alignment is a
        consequence (kept in the bypass note), so ``DMARC`` is tagged only for a
        dangling ``_dmarc``.  Likelihood: confirmed ``high`` / potentially ``medium``;
        a DMARC-only takeover is one notch lower when SPF ends in ``-all``.
        """
        tpl = self._tpl.get("external_spoofing", {}).get("domain_takeover")
        if not tpl:
            return []

        findings: List[Dict[str, Any]] = []
        for key, result in (("spf", self.spf_result), ("dkim", self.dkim_result), ("dmarc", self.dmarc_result)):
            for issue in (result or {}).get("issues", []):
                mapped = self._TAKEOVER_CODES.get(issue.get("code"))
                if mapped:
                    findings.append({"kind": mapped[0], "state": mapped[1],
                                     "data": issue.get("additional_data") or {}})
        if not findings:
            return []

        weak_spf = any(self._has_issue("spf", c) for c in tpl.get("weak_spf_codes", []))
        spf_state = "SPF weak/absent" if weak_spf else "SPF -all still applies"
        step_down = {"high": "medium", "medium": "low", "low": "low"}

        conditions: List[str] = []
        vectors: List[AttackVector] = []
        remediations: List[str] = []
        controls: List[str] = []
        controls_long: List[str] = []
        bypasses: set = set()
        bypass_notes: List[str] = []
        reg_domains: List[str] = []
        all_potential = True
        aligned_via: List[str] = []

        for f in findings:
            kind_tpl = tpl["kinds"][f["kind"]]
            data = f["data"]
            names = data.get("names") or []
            chain = data.get("chain") or []
            selectors = data.get("selectors") or []
            reg_domain = data.get("registrable_domain") or data.get("registered_domain") or "?"
            ctx = {
                "domain": self.domain,
                "name": names[0] if names else self.domain,
                "names": ", ".join(names),
                "chain": " -> ".join(chain),
                "target": data.get("failing_target") or data.get("include") or reg_domain,
                "include": data.get("include", ""),
                "reg_domain": reg_domain,
                "reason": data.get("registration_reason") or "domain availability check",
                "state_label": tpl["state_labels"][f["state"]],
                "selectors": ", ".join(f"'{s}'" for s in selectors) or "?",
                "first_selector": selectors[0] if selectors else "<selector>",
                "spf_state": spf_state,
            }
            likelihood = "high" if f["state"] == "unregistered" else "medium"
            if f["kind"] == "dmarc_cname" and not weak_spf:
                likelihood = step_down[likelihood]
            if f["state"] == "unregistered":
                all_potential = False

            conditions.append(self._render(kind_tpl["condition"], **ctx))
            vectors.append(AttackVector(
                vector_type="smtp_server",
                auth_mode="none",
                status=VectorStatus.UNVERIFIED,
                description=self._render(kind_tpl["vector_description"], **ctx),
                steps=self._render(kind_tpl["steps"], **ctx),
                impact="critical",
                likelihood=likelihood,
                port="25",
                transport="server_to_server",
            ))
            remediations.append(self._render(kind_tpl["remediation"], **ctx))
            bypasses.update(kind_tpl["bypasses"])
            bypass_notes.append(self._render(kind_tpl["bypass_note"], **ctx))
            if kind_tpl["control"] not in controls:
                controls.append(kind_tpl["control"])
            controls_long.append(self._render(kind_tpl["control_long"], **ctx))
            if reg_domain not in reg_domains:
                reg_domains.append(reg_domain)
            if f["kind"] in ("spf_cname", "spf_include") and "SPF" not in aligned_via:
                aligned_via.append("SPF")
            if f["kind"] == "dkim_cname" and "DKIM" not in aligned_via:
                aligned_via.append("DKIM")

        controls.sort(key=self._CONTROL_ORDER.index)
        ctx = {
            "domain": self.domain,
            "reg_domains": ", ".join(f"'{d}'" for d in reg_domains),
            "controls": " / ".join(controls),
            "controls_long": "; ".join(controls_long),
            "aligned_via": " or ".join(aligned_via),
        }
        if aligned_via:
            impact = self._render(tpl["impact_aligned"], **ctx)
        else:
            impact = self._render(tpl["impact_dmarc_weak_spf" if weak_spf else "impact_dmarc_strong_spf"], **ctx)
        ctx["impact_sentence"] = impact
        conditions.insert(0, f"Domain(s) to buy: {ctx['reg_domains']}")
        conditions.append(tpl["footer_condition"])

        return [AttackScenario(
            domain=self.domain,
            attack_category=AttackCategory.EXTERNAL,
            attack_type=_ATTACK_TYPE_MAP[tpl.get("attack_type", "SPOOFING_DOMAIN_TAKEOVER")],
            scenario_name=self._render(
                tpl["scenario_name_potential" if all_potential else "scenario_name"], **ctx),
            baseline=AttackProbability.HIGH,
            conditions_met=conditions,
            description=self._render(tpl["description_template"], **ctx),
            attack_vectors=vectors,
            remediation=" ".join(remediations),
            bypasses=[c for c in self._CONTROL_ORDER if c in bypasses],
            bypass_notes=bypass_notes,
        )]

    # ------------------------------------------------------------------
    # Relaxed DMARC alignment: weak subdomain -> spoof the organizational domain
    # ------------------------------------------------------------------

    def _spf_aligned_capability(self) -> Optional[str]:
        """Can an attacker obtain an SPF *pass* with an envelope MAIL FROM on THIS
        domain (so it aligns, relaxed, to any name sharing the org domain)?

        Returns the capability kind or None. Only cases where the envelope is on
        the domain count — a service/free-mail include keeps the envelope on the
        service's own domain (not aligned), so it is excluded.
        """
        for inc in (self.spf_result.get("all_includes") or []):
            mi = self._match_service(inc)
            if mi and mi.get("service_type") == "Shared Hosting":
                return "shared_hosting"
        if self._has_issue("spf", "spf_pass"):   # +all -> SPF passes for any IP
            return "spf_pass_all"
        return None

    def _dkim_aligned_capability(self) -> Optional[str]:
        """Can an attacker produce a VALID DKIM signature with ``d=`` on THIS domain
        (so it aligns, relaxed, to any name sharing the org domain)?"""
        if self._has_issue("dkim", "dkim_rsa_weak_key"):     # factorable key
            return "weak_key"
        for code in ("dkim_cname_target_unregistered",
                     "dkim_cname_target_potentially_unregistered"):
            if self._has_issue("dkim", code):                # takeable selector CNAME
                return "selector_cname_takeover"
        return None

    _XALIGN_CAP_DESC = {
        "shared_hosting":          "it is delegated to a shared-hosting provider whose outbound IPs are SPF-authorized and that lets an account overwrite the MAIL FROM",
        "spf_pass_all":            "its SPF ends with +all, so SPF passes for any sending IP",
        "weak_key":                "it publishes a factorable DKIM RSA key (< 1024 bits) whose private key can be recovered",
        "selector_cname_takeover": "a DKIM selector is a CNAME to a buyable/unregistered domain, so an attacker can publish their own key",
    }

    def _analyze_relaxed_alignment(self) -> List[AttackScenario]:
        """Weak SUBDOMAIN leveraged to spoof its organizational (parent) domain.

        DMARC is evaluated against the From-header domain and, by default, with
        **relaxed** alignment (``aspf``/``adkim`` absent = ``r``): an SPF pass or a
        valid DKIM signature on ANY name sharing the organizational domain
        satisfies DMARC for a ``From:`` on the organizational domain (and on any of
        its siblings). So if this domain is a subdomain with an aligned-capable
        spoof (shared hosting / ``+all`` SPF, or a weak/takeable DKIM) and the
        organizational domain's DMARC uses relaxed alignment, the attacker can
        forge ``From: anything@<org_domain>`` — ``FORGED_SENDER`` is raised
        (MAIL FROM != From) but SPF/DMARC (or DKIM/DMARC) still PASS, even at
        ``p=reject``.

        Requires the org-domain context (``org_domain`` + ``org_dmarc_result``) to
        be wired by the auditor; otherwise returns nothing.
        """
        if not self.org_domain:
            return []
        dm = self.org_dmarc_result or {}
        if not dm.get("dmarc_record"):
            # The organizational domain has no DMARC of its own: there is no
            # enforcement to bypass via alignment (From:@org is spoofable anyway).
            return []
        org_policy = (dm.get("policy") or "none").lower()
        aspf = (dm.get("alignment_spf") or "r").lower()
        adkim = (dm.get("alignment_dkim") or "r").lower()
        spf_relaxed = not aspf.startswith("s")
        dkim_relaxed = not adkim.startswith("s")

        spf_cap = self._spf_aligned_capability()
        dkim_cap = self._dkim_aligned_capability()

        branches: List[Tuple[str, str]] = []
        if spf_relaxed and spf_cap:
            branches.append(("SPF", spf_cap))
        if dkim_relaxed and dkim_cap:
            branches.append(("DKIM", dkim_cap))
        if not branches:
            return []

        org = self.org_domain
        enforcing = org_policy in ("quarantine", "reject")
        # Bypassing an ENFORCING parent policy is the dangerous case; with p=none the
        # parent is unprotected anyway (the aligned path only adds authentication).
        likelihood = "high" if enforcing else "medium"
        baseline = AttackProbability.HIGH if enforcing else AttackProbability.MEDIUM

        controls = [b[0] for b in branches]
        bypasses = [c for c in ("SPF", "DKIM") if c in controls] + ["DMARC"]
        align_tag = {"SPF": f"aspf={aspf}", "DKIM": f"adkim={adkim}"}

        # Spoofable From targets (these go in "Affected Domains"): the organizational
        # domain + any audited sibling sharing it whose alignment is relaxed for an
        # active branch. Relaxed alignment is SYMMETRIC at the organizational level, so
        # a leverage on this subdomain forges a From: on ANY of these identities — the
        # parent AND its siblings (a sibling with no own _dmarc inherits the parent's
        # policy and alignment) — not merely on the subdomain itself.
        spf_branch = "SPF" in controls
        dkim_branch = "DKIM" in controls

        def _relaxed_target(t_aspf: Optional[str], t_adkim: Optional[str]) -> bool:
            return ((spf_branch and not (t_aspf or "r").lower().startswith("s")) or
                    (dkim_branch and not (t_adkim or "r").lower().startswith("s")))

        sibling_targets: List[str] = []
        for sib, sdm in self.org_family:
            if sib in (self.domain, org):
                continue
            sdm = sdm or {}
            if _relaxed_target(sdm.get("alignment_spf"), sdm.get("alignment_dkim")):
                sibling_targets.append(sib)
        sibling_targets = sorted(dict.fromkeys(sibling_targets))
        affected_domains = [org] + sibling_targets  # the org domain is always a target
        siblings_clause = (
            f" and {len(sibling_targets)} audited sibling "
            f"identit{'y' if len(sibling_targets) == 1 else 'ies'} "
            f"({', '.join(sibling_targets)})" if sibling_targets else "")

        bypass_notes: List[str] = []
        concretely: List[str] = []
        for ctrl, cap in branches:
            how = self._XALIGN_CAP_DESC.get(cap, cap)
            if ctrl == "SPF":
                concretely.append(
                    f"the subdomain '{self.domain}' can emit an SPF-passing message "
                    f"(MAIL FROM on '{self.domain}') because {how}, and relaxed SPF alignment "
                    f"({align_tag['SPF']}, default) compares only the organizational domain")
                bypass_notes.append(
                    f"SPF: the subdomain '{self.domain}' can emit an SPF-passing message "
                    f"(MAIL FROM on '{self.domain}') because {how}. Relaxed SPF alignment "
                    f"({align_tag['SPF']}, default) compares only the organizational domain, "
                    f"so a From: on '{org}' is aligned -> DMARC passes on the SPF branch.")
            else:
                concretely.append(
                    f"the subdomain '{self.domain}' can be signed d='{self.domain}' because {how}, "
                    f"and relaxed DKIM alignment ({align_tag['DKIM']}, default) compares only the "
                    f"organizational domain")
                bypass_notes.append(
                    f"DKIM: the subdomain '{self.domain}' can be signed d='{self.domain}' because {how}. "
                    f"Relaxed DKIM alignment ({align_tag['DKIM']}, default) compares only the "
                    f"organizational domain, so a From: on '{org}' is aligned -> DMARC passes on the DKIM branch.")
        bypass_notes.append(
            f"FORGED_SENDER is raised (MAIL FROM/DKIM domain '{self.domain}' != the visible From "
            f"domain), but the DMARC verdict is a PASS, even at p={org_policy}. Relaxed alignment is "
            f"bidirectional: the SAME leverage on '{self.domain}' forges a From: on the organizational "
            f"domain '{org}'{siblings_clause}, and on any other name sharing '{org}' (a sibling with no "
            f"own _dmarc inherits '{org}''s policy).")

        affected_str = ", ".join(f"'{d}'" for d in affected_domains)
        conditions = [
            f"Leverage (MAIL FROM / DKIM d=): '{self.domain}', a subdomain of the organizational domain '{org}'",
            f"Spoofable From identities (Affected Domains): {affected_str}",
            f"'{org}' publishes an enforcing DMARC policy (p={org_policy})" if enforcing
                else f"'{org}' publishes a DMARC record (p={org_policy}, not enforcing)",
        ]
        for ctrl, cap in branches:
            conditions.append(
                f"{ctrl}: {self._XALIGN_CAP_DESC.get(cap, cap)}; "
                f"relaxed {ctrl} alignment ({align_tag[ctrl]}, the RFC 7489 default)")
        conditions.append(
            "DMARC jumps from a subdomain DIRECTLY to the organizational domain (no label-by-label "
            "walk), so the policy that governs a From:@" + org + " is the organizational domain's own record")

        via = " and ".join(f"{c} alignment" for c in controls)
        description = (
            f"The subdomain '{self.domain}' is the LEVERAGE (it is set as the envelope MAIL FROM / DKIM "
            f"d=), used to forge the visible From: on the organizational domain '{org}'{siblings_clause} "
            f"— the Affected Domains, not '{self.domain}' itself. DMARC checks the From-header domain with "
            f"relaxed alignment by default, so a {via} obtained on '{self.domain}' satisfies DMARC "
            f"for a From: on any identity sharing '{org}'. Concretely: "
            + "; ".join(concretely)
            + f". The message trips FORGED_SENDER (envelope/DKIM domain '{self.domain}' differs from the "
            f"visible From '{org}'), yet SPF/DMARC (or DKIM/DMARC) PASS — even under p={org_policy}. "
            f"Example: From: emission@{org} with MAIL FROM emission@{self.domain}."
        )
        remediation = (
            f"Set strict DMARC alignment on '{org}' (aspf=s / adkim=s) if subdomains must not be able to "
            f"authenticate the parent, AND fix the leverage on '{self.domain}': "
            + "; ".join(sorted({
                {"shared_hosting": "do not delegate a subdomain to a shared-hosting SPF you do not control",
                 "spf_pass_all": "replace +all with -all on the subdomain",
                 "weak_key": "rotate the weak DKIM key to >= 2048-bit RSA",
                 "selector_cname_takeover": "remove/repoint the dangling DKIM selector CNAME",
                 }.get(cap, cap) for _c, cap in branches}))
            + ". Note: strict alignment also breaks legitimate subdomain senders, so scope it carefully."
        )

        # Vectors: the attacker sends with MAIL FROM / DKIM d= on the subdomain and
        # From: on the organizational domain. Direct-MX (25) always applies; a local
        # MTA applies for shared-hosting and DKIM-signing leverage.
        caps = {cap for _c, cap in branches}
        vectors = [AttackVector(
            vector_type="smtp_server",
            auth_mode="none",
            status=VectorStatus.UNVERIFIED,
            description=f"Direct submission with MAIL FROM/DKIM on '{self.domain}', From: on '{org}'.",
            steps=(f"1. Obtain the aligned-on-'{self.domain}' capability ({', '.join(sorted(caps))}).\n"
                   f"2. Craft From: <emission@{org}> (visible) with the envelope MAIL FROM "
                   f"(and/or DKIM d=) on '{self.domain}'.\n"
                   f"3. Send to the recipient's MX (port 25).\n"
                   f"4. Relaxed alignment on '{org}' makes DMARC PASS on the {('/'.join(controls))} "
                   f"branch, even at p={org_policy}; FORGED_SENDER is raised but the spoof is authenticated."),
            impact="critical",
            likelihood=likelihood,
            port="25",
            transport="server_to_server",
        )]
        if "shared_hosting" in caps or "weak_key" in caps or "selector_cname_takeover" in caps:
            vectors.append(AttackVector(
                vector_type="local_script",
                auth_mode="none",
                status=VectorStatus.UNVERIFIED,
                description=f"Local MTA on the leverage infrastructure, From: on '{org}'.",
                steps=(f"1. Obtain the aligned-on-'{self.domain}' capability ({', '.join(sorted(caps))}).\n"
                       f"2. Hand a message From: <emission@{org}> with MAIL FROM (and/or DKIM d=) on "
                       f"'{self.domain}' to the host's local MTA (no SMTP auth).\n"
                       f"3. Relaxed alignment on '{org}' makes DMARC PASS even at p={org_policy}."),
                impact="critical",
                likelihood=likelihood,
                transport="local_submission",
            ))

        name_policy = f"p={org_policy}"
        return [AttackScenario(
            domain=self.domain,
            attack_category=AttackCategory.EXTERNAL,
            attack_type=AttackType.SPOOFING_RELAXED_ALIGNMENT,
            scenario_name=(f"Cross-domain spoofing of '{org}' via relaxed DMARC alignment "
                           f"from subdomain '{self.domain}' ({'/'.join(controls)}, {name_policy})"),
            baseline=baseline,
            conditions_met=conditions,
            description=description,
            attack_vectors=vectors,
            remediation=remediation,
            bypasses=bypasses,
            bypass_notes=bypass_notes,
            affected_domains=affected_domains,
        )]

    # ------------------------------------------------------------------
    # Open relay analysis
    # ------------------------------------------------------------------

    def _analyze_open_relay(self) -> List[AttackScenario]:
        """
        One scenario per MX of this domain that is an open relay (smtp_checker issue
        ``smtp_open_relay``), with a bypass profile evaluated for THIS domain:

        * **SPF** — passes aligned only if the relay IP is authorized by the domain's
          SPF (checked against the resolved SPF IPs / ranges, ``+all``, top-level
          ``mx``); otherwise it fails, or is *unknown* when the IP or unresolved
          ``a`` / ``mx`` / ``exists`` / ``ptr`` mechanisms prevent a verdict.
        * **DKIM** — always *conditional*: the relayed mail carries an aligned
          signature only if the relay's signer signs it (OpenDKIM InternalHosts too
          broad, re-injection via 127.0.0.1 after a content filter, ...). The relay
          test never sends content, so this is never observed.
        * **DMARC** — passes through SPF alignment when SPF passes; otherwise only
          through that conditional DKIM signature.

        Probability / risk level: SPF pass -> very_high / critical; SPF fail with DMARC
        enforced -> low / moderate (needs the relay to DKIM-sign); SPF fail, DMARC not
        enforced -> high / high (impact high); undetermined -> medium / high.
        """
        tpl = self._tpl["open_relay"]
        prob = self._parse_probability(tpl["probability"])
        dmarc_state, _ = self._dmarc_state()
        scenarios: List[AttackScenario] = []
        for mx in self.smtp_result.get("mx_results", []):
            if not self._mx_has_issue(mx, "smtp_open_relay"):
                continue
            ip = self._mx_server_ip(mx)
            spf = self._spf_authorizes(ip, self._mx_validated_ptr(mx, ip))
            case, impact, likelihood, certain, conditional = self._relay_profile(spf, dmarc_state)
            ctx = self._relay_texts(tpl, case, spf, dmarc_state, ip or "unknown")
            sc = self._make_scenario(tpl, prob, mx_host=mx.get("hostname", "unknown"), **ctx)
            for v in sc.attack_vectors:
                v.impact, v.likelihood = impact, likelihood
            sc.bypasses, sc.conditional_bypasses = certain, conditional
            sc.bypass_notes = [ctx["spf_line"], ctx["dkim_line"], ctx["dmarc_line"]]
            scenarios.append(sc)
        return scenarios

    @staticmethod
    def _mx_server_ip(mx: Dict[str, Any]) -> Optional[str]:
        """IP the SMTP tests connected to (None if unknown)."""
        smtp = mx.get("smtp") or {}
        tests = smtp.get("tests") or {}
        for name in ("smtp_reverse_lookup", "smtp_reverse_dns_mismatch"):
            ip = (tests.get(name) or {}).get("server_ip")
            if ip:
                return ip
        try:
            return str(ipaddress.ip_address(smtp.get("target") or ""))
        except ValueError:
            return None

    @staticmethod
    def _mx_validated_ptr(mx: Dict[str, Any], ip: Optional[str]) -> Optional[str]:
        """PTR name of the relay IP that resolves back to it (RFC 7208 validated name)."""
        test = ((mx.get("smtp") or {}).get("tests") or {}).get("smtp_reverse_lookup") or {}
        host = (test.get("reverse_dns_host") or "").rstrip(".").lower()
        if host and ip and ip in (test.get("forward_ips_from_ptr") or []):
            return host
        return None

    def _spf_authorizes(self, ip: Optional[str], ptr_name: Optional[str] = None) -> str:
        """Does the domain's SPF authorize *ip*? "pass" / "fail" / "unknown" / "none" (no SPF).

        Uses the SPF IPs / ranges resolved by mail_antispoof_policy_checker, ``+all``,
        a top-level ``mx`` and ``ptr:<domain>`` (matched against the validated PTR
        name of *ip*).  Other unresolved mechanisms (``a`` / ``mx`` / ``exists`` in
        includes) leave the verdict "unknown".
        """
        spf = self.spf_result or {}
        if not spf.get("spf_record"):
            return "none"
        if self._has_issue("spf", "spf_pass"):        # +all
            return "pass"
        mechanisms = ((spf.get("parsed_spf") or {}).get("parsed") or {}).get("mechanisms") or []
        # A top-level 'mx' authorizes every MX of the domain, the relay included.
        for m in mechanisms:
            if (m.get("mechanism") == "mx" and (m.get("value") or self.domain) == self.domain
                    and m.get("action", "pass") == "pass"):
                return "pass"
        if not ip:
            return "unknown"
        addr = ipaddress.ip_address(ip)
        if any(e.get("ip") == ip for e in spf.get("all_ip_addresses") or []):
            return "pass"
        for e in spf.get("all_ip_ranges") or []:
            try:
                if addr in ipaddress.ip_network(e.get("ip_range", ""), strict=False):
                    return "pass"
            except ValueError:
                continue
        names = [str(i.get("include", "")) for i in spf.get("all_includes") or []]
        names += [f"{m.get('mechanism')}:{m.get('value') or ''}" for m in mechanisms]
        unresolved = False
        for name in names:
            kind, _, target = name.partition(":")
            if kind == "ptr" and target and ptr_name:
                target = target.rstrip(".").lower()
                if ptr_name == target or ptr_name.endswith("." + target):
                    return "pass"
            elif kind in ("a", "mx", "exists", "ptr"):
                unresolved = True
        return "unknown" if unresolved else "fail"

    @staticmethod
    def _relay_profile(spf: str, dmarc_state: str) -> Tuple[str, str, str, List[str], List[str]]:
        """(case, impact, probability, certain bypasses, conditional bypasses) of an open relay.

        Impact is critical when the spoof can pass authentication for the domain; it is
        high when DMARC does not block it but SPF fails for the domain (the spoof is
        delivered from a legitimate server, yet stays visibly unauthenticated).
        """
        dmarc = ["DMARC"] if dmarc_state != "absent" else []
        if spf == "pass":
            return "spf_pass", "critical", "very_high", ["SPF"] + dmarc, ["DKIM"]
        if spf == "unknown":
            return "spf_unknown", "critical", "medium", [], ["SPF", "DKIM"] + dmarc
        if dmarc_state in ("quarantine", "reject"):
            return "spf_fail_enforced", "critical", "low", [], ["DKIM"] + dmarc
        return "spf_fail_not_enforced", "high", "high", [], ["DKIM"] + dmarc

    def _relay_texts(self, tpl: Dict[str, Any], case: str, spf: str, dmarc_state: str,
                     ip: str) -> Dict[str, str]:
        """Template context of an open relay scenario.  Texts depend on the case (and
        on SPF / DMARC presence), so the domains of one case merge per MX host."""
        texts = dict(tpl["cases"][case])
        if dmarc_state == "absent" and "dmarc_line_absent" in texts:
            texts["dmarc_line"] = texts["dmarc_line_absent"]
        texts.pop("dmarc_line_absent", None)
        if spf == "none":
            texts["spf_line"] = tpl["spf_none_line"]
        texts["dkim_line"] = tpl["dkim_line"]
        ctx = {k: self._render(v, relay_ip=ip) for k, v in texts.items()}
        ctx.update(relay_ip=ip, relay_case=case)
        return ctx

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _match_service(
        self, include_entry: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Match a SPF include entry against a known email service.

        Two-path resolution:

        1. **CSV path** (primary): if ``dangerous=True`` and ``service_name``
           is populated by SPFChecker from ``Dangerous_SPF_Include.csv``, look
           up that name directly in ``email_services.json``.

        2. **Domain path** (fallback): strip any mechanism prefix (``a:``,
           ``include:``, etc.) from the raw include value, then search every
           service's ``spf_includes`` list for an exact or suffix match.

        Parameters
        ----------
        include_entry : dict
            A single entry from ``spf_result["all_includes"]``.

        Returns
        -------
        dict | None
            ``{"service_name", "service_type", "attack_vectors", "include_domain"}``
            or ``None`` if no service matched.
        """
        # ── Path 1: CSV-based (dangerous flag + service_name set by SPFChecker) ──
        if include_entry.get("dangerous"):
            service_name: str = include_entry.get("service_name") or ""
            svc_config = self.email_services.get(service_name)
            if svc_config is not None:
                return {
                    "service_name":   service_name,
                    "service_type":   include_entry.get("service_type") or svc_config.get("service_type", ""),
                    "attack_vectors": svc_config.get("attack_vectors", []),
                    "include_domain": include_entry.get("include", ""),
                }

        # ── Path 2: Direct domain matching against spf_includes ─────────────
        raw_include = include_entry.get("include", "")
        m = re.match(r'^(?:[a-z0-9]+:)?(.*)', raw_include, re.IGNORECASE)
        include_domain = (m.group(1) if m else raw_include).lower().strip()
        if not include_domain:
            return None

        for svc_name, svc_config in self.email_services.items():
            for pattern in svc_config.get("spf_includes", []):
                pattern_lower = pattern.lower()
                if include_domain == pattern_lower or include_domain.endswith("." + pattern_lower):
                    return {
                        "service_name":   svc_name,
                        "service_type":   svc_config.get("service_type", ""),
                        "attack_vectors": svc_config.get("attack_vectors", []),
                        "include_domain": include_domain,
                    }

        return None

    @staticmethod
    def _parse_probability(prob_str: str) -> AttackProbability:
        """Parse a probability string to AttackProbability enum."""
        mapping = {
            "critical":      AttackProbability.CRITICAL,
            "high":          AttackProbability.HIGH,
            "medium":        AttackProbability.MEDIUM,
            "low":           AttackProbability.LOW,
            "informational": AttackProbability.INFORMATIONAL,
        }
        return mapping.get(prob_str.lower(), AttackProbability.MEDIUM)

    @staticmethod
    def _max_probability(
        p1: AttackProbability, p2: AttackProbability
    ) -> AttackProbability:
        """Return the more severe of two probabilities."""
        order = {
            AttackProbability.CRITICAL:      0,
            AttackProbability.HIGH:          1,
            AttackProbability.MEDIUM:        2,
            AttackProbability.LOW:           3,
            AttackProbability.INFORMATIONAL: 4,
        }
        return p1 if order[p1] <= order[p2] else p2


# ---------------------------------------------------------------------------
# MX-level scenarios grouped across domains
# ---------------------------------------------------------------------------

MX_LEVEL_TYPES = frozenset({
    AttackType.MITM_SSL_STRIPPING,
    AttackType.MITM_FAKE_CERT,
    AttackType.MITM_TLSA_NO_DNSSEC,
    AttackType.OPEN_RELAY,
})


def is_mx_level(scenario: AttackScenario) -> bool:
    """True for scenarios whose target is an MX host (MITM, open relay)."""
    return scenario.attack_type in MX_LEVEL_TYPES and bool(scenario.mx_host)


def group_mx_scenarios(scenarios: List[AttackScenario]) -> List[AttackScenario]:
    """Merge per-domain MX-level scenarios into one scenario per (scenario, MX host).

    The target of a MITM or open-relay scenario is the MX server, not each
    domain: ``mail.example.fr`` serving 15 domains gives one row whose
    ``affected_domains`` lists those domains.  Texts are re-rendered from the
    template with ``{domain}`` = the comma-separated domain list; risk,
    probability, bypasses and vector risk values are those of the per-domain
    scenarios (identical within a group).
    """
    groups: Dict[tuple, List[AttackScenario]] = {}
    for sc in scenarios:
        if not is_mx_level(sc):
            continue
        ctx = getattr(sc, "_ctx", {}) or {}
        # Open relay: the case (SPF authorization x DMARC) is in the name and the bypass
        # fields, so its domains are merged per (MX host, case).
        key = (sc.attack_type, sc.scenario_name, sc.mx_host, ctx.get("mode"), sc.risk,
               sc.probability, tuple(sc.bypasses), tuple(sc.conditional_bypasses),
               tuple(sc.bypass_notes))
        groups.setdefault(key, []).append(sc)

    grouped: List[AttackScenario] = []
    for members in groups.values():
        first = members[0]
        domains = sorted({m.domain for m in members})
        tpl = getattr(first, "_tpl", None)
        if tpl is None:
            continue
        ctx = dict(getattr(first, "_ctx", {}) or {})
        ctx["domain"] = ", ".join(domains)
        render = AttackScenarioAnalyzer._render
        vectors = AttackScenarioAnalyzer._build_vectors(tpl.get("vectors", []), **ctx)
        for new_v, old_v in zip(vectors, first.attack_vectors):
            new_v.impact, new_v.likelihood, new_v.risk = old_v.impact, old_v.likelihood, old_v.risk
            new_v.status = old_v.status
            # Keep the original vector's identity/transport fields (the template rebuild
            # above does not carry them): otherwise the Attack Modes label loses the port.
            new_v.auth_mode = old_v.auth_mode
            new_v.port, new_v.transport = old_v.port, old_v.transport
            new_v.dkim, new_v.shared = old_v.dkim, old_v.shared
        sc = AttackScenario(
            domain=first.mx_host,
            attack_category=first.attack_category,
            attack_type=first.attack_type,
            scenario_name=render(tpl.get("scenario_name", ""), **ctx),
            baseline=first.baseline,
            conditions_met=AttackScenarioAnalyzer._render_list(tpl.get("conditions_met", []), **ctx),
            description=render(tpl.get("description_template", ""), **ctx),
            attack_vectors=vectors,
            remediation=render(tpl.get("remediation", ""), **ctx),
            mx_host=first.mx_host,
            service_name=first.service_name,
            affected_domains=domains,
            probability=first.probability,
            risk=first.risk,
            bypasses=list(first.bypasses),
            conditional_bypasses=list(first.conditional_bypasses),
            bypass_notes=list(first.bypass_notes),
        )
        grouped.append(sc)
    return sorted(grouped, key=lambda s: s.risk_order)

