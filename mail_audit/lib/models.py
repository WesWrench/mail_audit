"""
Data models for the mail_audit module.

Defines the attack scenario taxonomy and aggregated audit result structures.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class AttackCategory(str, Enum):
    MITM = "MITM"              # transport-level attacks on the MX connection
    EXTERNAL = "External"
    INTERNAL = "MITM"          # deprecated alias of MITM (former "Internal" category)


class AttackType(str, Enum):
    MITM_SSL_STRIPPING = "MITM - SSL Stripping"
    MITM_FAKE_CERT = "MITM - Fake Certificate"
    MITM_TLSA_NO_DNSSEC = "MITM - TLSA without DNSSEC"
    SPOOFING_EMAIL_SERVICE = "Spoofing - Email Service"
    SPOOFING_FREE_EMAIL = "Spoofing - Free Email Provider"
    SPOOFING_SHARED_HOSTING = "Spoofing - Shared Hosting"
    SPOOFING_NO_POLICY = "Spoofing - No SPF/DMARC Policy"          # neither SPF nor DMARC
    SPOOFING_NO_DMARC_ENFORCEMENT = "Spoofing - No DMARC Enforcement"  # DMARC absent or p=none
    SPOOFING_AUTH_MISCONFIG = "Spoofing - SPF/DKIM Misconfiguration"   # +all, ~all, critical SPF...
    SPOOFING_DKIM_MISCONFIG = "Spoofing - DKIM Misconfiguration"       # weak DKIM RSA key (factorable)
    SPOOFING_RELAXED_ALIGNMENT = "Spoofing - Relaxed DMARC Alignment (org-domain)"  # weak subdomain spoofs the parent
    SPOOFING_DOMAIN_TAKEOVER = "Spoofing - Unregistered Domain Takeover"  # buyable domain behind CNAME / SPF include
    OPEN_RELAY = "Open Relay"


class AttackProbability(str, Enum):
    """Template *baseline* severity (internal, legacy ``probability`` key of the
    templates / dated tests).  Not exported: the scenario's exported probability
    is an :class:`AttackLikelihood` and its risk a :class:`RiskLevel`."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AttackLikelihood(str, Enum):
    """Probability that the attack works (5-level scale)."""
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"


class RiskLevel(str, Enum):
    """Risk = impact x probability (risk_matrix in scenario_templates.json)."""
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


LIKELIHOOD_LABELS = {
    "very_high": "Very High", "high": "High", "medium": "Medium", "low": "Low", "very_low": "Very Low",
}
RISK_LABELS = {"critical": "Critical", "high": "High", "moderate": "Moderate", "low": "Low"}

# Ordering for sorting / comparison (lower = more severe / more likely)
RISK_ORDER = {"critical": 0, "high": 1, "moderate": 2, "low": 3}
LIKELIHOOD_ORDER = {"very_high": 0, "high": 1, "medium": 2, "low": 3, "very_low": 4}


class VectorStatus(str, Enum):
    CONFIRMED = "confirmed"      # Tested — works
    BLOCKED = "blocked"          # Tested — protected/blocked by the service
    UNVERIFIED = "unverified"    # Not yet tested


@dataclass
class AttackVector:
    """A single technical vector for executing an attack scenario.

    Risk is a two-axis assessment:
      * ``impact``     — severity IF this technique delivers a spoof (how much
                         control it gives: e.g. smtp_server can set the MAIL FROM
                         → CRITICAL, web_ui is restricted → MEDIUM). Intrinsic to
                         the technique.
      * ``likelihood`` — how likely this technique actually works today (web_ui is
                         commonly reachable → HIGH; a misconfigured smtp_server
                         that lets you set MAIL FROM is now rare → MEDIUM; a
                         provider that verifies ownership → blocked/LOW).
      * ``risk``       — derived from the impact × likelihood matrix.
    """

    vector_type: str                     # the TECHNICAL channel of this vector: "web_ui", "http_api", "smtp_server",
                                         # "local_script", "email_forwarding", "network". (NOT the email-service category,
                                         # which is AttackScenario.service_name's service_type, e.g. "Email Delivery Service".)
    auth_mode: Optional[str] = None      # auth-required: "credentials", "api_key", "app_password", "oauth_token"
                                         # no auth: "trusted_local_submission", "none", "not_applicable" (see vector_taxonomy.json)
    status: str = VectorStatus.UNVERIFIED  # "confirmed" | "blocked" | "unverified"
    description: str = ""
    steps: Optional[str] = None
    probability_note: Optional[str] = None
    impact: str = ""                     # "critical" | "high" | "medium" | "low" ("" = fill from vector_defaults)
    likelihood: str = ""                 # "high" | "medium" | "low" ("" = fill from vector_defaults)
    risk: str = "medium"                 # derived = matrix(impact, likelihood)
    dkim: str = ""                       # DKIM signature the mail carries, "d=domain:s=selector"
                                         # (e.g. "sendgrid.net:s=smtpapi"). Usually NOT aligned with
                                         # the spoofed From — informational, not an alignment.
    shared: bool = False                 # smtp_server on a shared / mutualised mail server (e.g.
                                         # smtp-<user>.alwaysdata.net), vs. a dedicated relay.
    port: str = ""                       # SMTP port of this vector: "587/465" (submission) or "25"
                                         # (direct MX / relay). "" when not an SMTP channel.
    transport: str = ""                  # "client_to_server" (authenticated submission, 587/465),
                                         # "server_to_server" (MTA on port 25: PTR/rDNS expected),
                                         # "local_submission" (host's local MTA), or "".

    # Auth modes that require authenticating to the sending service (see
    # vector_taxonomy.json). Everything else (trusted_local_submission, none,
    # not_applicable, unset) needs no service authentication.
    _AUTH_REQUIRED_MODES = frozenset({"credentials", "api_key", "app_password", "oauth_token"})

    @property
    def auth_required(self) -> bool:
        """True when the vector requires authentication to access the sending service."""
        return self.auth_mode in self._AUTH_REQUIRED_MODES

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vector_type": self.vector_type,
            "auth_mode": self.auth_mode,
            "auth_required": self.auth_required,
            "status": self.status,
            "description": self.description,
            "steps": self.steps,
            "probability_note": self.probability_note,
            "impact": self.impact,
            "likelihood": self.likelihood,
            "risk_level": self.risk,
            "dkim": self.dkim,
            "shared": self.shared,
            "port": self.port,
            "transport": self.transport,
        }


@dataclass
class AttackScenario:
    """
    A complete, actionable attack scenario derived from a combination of
    misconfigurations detected during the mail audit.
    """

    domain: str
    attack_category: AttackCategory
    attack_type: AttackType
    scenario_name: str
    baseline: AttackProbability    # template baseline (internal; fallback only)
    conditions_met: List[str]
    description: str
    attack_vectors: List[AttackVector]
    remediation: str
    service_name: Optional[str] = None
    mx_host: Optional[str] = None  # For per-MX scenarios (MITM / Open Relay)
    affected_domains: List[str] = field(default_factory=list)  # MX-grouped scenarios: domains using mx_host
    probability: str = "medium"    # AttackLikelihood value of the vector carrying the risk
    risk: str = "moderate"         # RiskLevel value: worst risk across attack_vectors (impact x likelihood)
    bypasses: List[str] = field(default_factory=list)  # controls ("SPF"/"DKIM"/"DMARC") certainly bypassed
    # Controls bypassed only under a condition the audit cannot observe (e.g. the open
    # relay DKIM-signs relayed mail with the domain key); the condition is in bypass_notes.
    conditional_bypasses: List[str] = field(default_factory=list)
    bypass_notes: List[str] = field(default_factory=list)  # one line per control: why / under which condition

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "attack_category": self.attack_category.value,
            "attack_type": self.attack_type.value,
            "scenario_name": self.scenario_name,
            "probability": self.probability,
            "risk_level": self.risk,
            "bypasses": self.bypasses,
            "conditional_bypasses": self.conditional_bypasses,
            "bypass_notes": self.bypass_notes,
            "conditions_met": self.conditions_met,
            "description": self.description,
            "attack_vectors": [v.to_dict() for v in self.attack_vectors],
            "remediation": self.remediation,
            "service_name": self.service_name,
            "mx_host": self.mx_host,
            "affected_domains": self.affected_domains,
        }

    @property
    def risk_order(self) -> tuple:
        """Sort key: risk first, then probability (lower = more severe)."""
        return (RISK_ORDER.get(self.risk, 99), LIKELIHOOD_ORDER.get(self.probability, 99))


@dataclass
class DomainAudit:
    """
    Aggregated audit result for a single domain, containing raw checker
    outputs and derived attack scenarios.
    """

    domain: str
    smtp_result: Optional[Dict[str, Any]]
    spf_result: Optional[Dict[str, Any]]
    dmarc_result: Optional[Dict[str, Any]]
    dkim_result: Optional[Dict[str, Any]]
    attack_scenarios: List[AttackScenario] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "smtp_result": self.smtp_result,
            "spf_result": self.spf_result,
            "dmarc_result": self.dmarc_result,
            "dkim_result": self.dkim_result,
            "attack_scenarios": [s.to_dict() for s in self.attack_scenarios],
            "scenario_count_by_risk_level": self.scenario_count_by_risk(),
        }

    def scenario_count_by_risk(self) -> Dict[str, int]:
        """Return counts of scenarios grouped by risk level."""
        counts: Dict[str, int] = {r.value: 0 for r in RiskLevel}
        for scenario in self.attack_scenarios:
            counts[scenario.risk] = counts.get(scenario.risk, 0) + 1
        return counts

    @property
    def sorted_scenarios(self) -> List[AttackScenario]:
        """Attack scenarios sorted from highest to lowest risk."""
        return sorted(self.attack_scenarios, key=lambda s: s.risk_order)


@dataclass
class AuditResult:
    """
    Top-level result container holding audits for all requested domains plus
    the raw outputs from the underlying checkers.
    """

    domains: List[DomainAudit]
    # MX-level scenarios (MITM, open relay) grouped across domains: one per (scenario, MX host)
    mx_scenarios: List[AttackScenario] = field(default_factory=list)
    smtp_raw: List[Dict[str, Any]] = field(default_factory=list)
    antispoof_raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domains": [d.to_dict() for d in self.domains],
            "total_scenario_count_by_risk_level": self.total_scenario_count_by_risk(),
            "mx_scenarios": [s.to_dict() for s in sorted(self.mx_scenarios, key=lambda s: s.risk_order)],
            "smtp_raw": self.smtp_raw,
            "antispoof_raw": self.antispoof_raw,
        }

    def total_scenario_count_by_risk(self) -> Dict[str, int]:
        counts: Dict[str, int] = {r.value: 0 for r in RiskLevel}
        for domain_audit in self.domains:
            for risk, cnt in domain_audit.scenario_count_by_risk().items():
                counts[risk] = counts.get(risk, 0) + cnt
        return counts
