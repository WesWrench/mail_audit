"""Issue slug definitions for all checkers.

Issue codes are globally-unique string slugs shared across all mail-audit
modules.  No two modules may use the same slug.
"""

from typing import Dict, Any
from ..models.issue import Issue, IssueCategory, IssueSeverity


class IssueDefinitions:
    """Centralized issue definitions for all security checks."""

    # SPF slugs
    SPF_NX_DOMAIN                    = "domain_not_exist"
    SPF_NO_SPF                       = "no_spf"
    SPF_NO_ALL                       = "spf_no_all"
    SPF_PASS_ALL                     = "spf_pass"
    SPF_NEUTRAL_ALL                  = "spf_neutral"
    SPF_SOFT_FAIL_ALL                = "spf_softfail"
    SPF_LOOKUP_ERROR                 = "spf_too_many_lookups"
    SPF_UNREGISTERED_DOMAINS         = "spf_unregistered_domains_chain"
    SPF_DNS_TIMEOUT                  = "spf_dns_timeout"
    SPF_RECURSE                      = "spf_recurse"
    SPF_DANGEROUS_INCLUDE            = "spf_dangerous_include"
    SPF_DANGEROUS_IP_RANGE           = "spf_dangerous_ip"
    SPF_DANGEROUS_AS_ORGANIZATION    = "spf_dangerous_as"
    SPF_SYNTAX_ERROR                 = "spf_syntax_error"
    SPF_UNREGISTERED_DOMAIN          = "spf_domain_unregistered"
    SPF_POTENTIALLY_UNREGISTERED_DOMAIN = "spf_domain_potentially_unregistered"

    # DMARC slugs
    DMARC_NO_DMARC              = "no_dmarc"
    DMARC_LAX_POLICY            = "dmarc_lax_policy"
    DMARC_LAX_SUBDOMAIN_POLICY  = "dmarc_lax_subdomain_policy"
    DMARC_NOT_100_PCT           = "dmarc_partial_coverage"
    DMARC_DNS_TIMEOUT           = "dmarc_dns_timeout"
    DMARC_SYNTAX_ERROR          = "dmarc_syntax_error"
    DMARC_INVALID_TAG           = "dmarc_invalid_tag"
    DMARC_INVALID_TAG_VALUE     = "dmarc_invalid_tag_value"
    DMARC_INVALID_REPORT_URI    = "dmarc_invalid_report_uri"
    DMARC_MULTIPLE_RECORDS      = "dmarc_multiple_records"

    # DKIM slugs
    DKIM_NO_SELECTORS_FOUND = "dkim_no_selectors"
    DKIM_RSA_WEAK_KEY       = "dkim_rsa_weak_key"
    DKIM_RSA_PERFECTIBLE_KEY = "dkim_rsa_perfectible_key"
    DKIM_DNS_TIMEOUT        = "dkim_dns_timeout"
    DKIM_SYNTAX_ERROR       = "dkim_syntax_error"

    # CNAME takeover slugs — one family per protocol: "<spf|dmarc|dkim>_<suffix>".
    # Raised only when the registrable domain of a CNAME target is (potentially)
    # unregistered: whoever buys it controls the SPF / DMARC / DKIM TXT seen
    # through the alias.  Pure DNS anomalies (broken alias, loop...) are kept as
    # evidence in ``cname_checks`` but are not issues.
    CNAME_SLUG_SUFFIXES = {
        "unregistered":             "cname_target_unregistered",
        "potentially_unregistered": "cname_target_potentially_unregistered",
    }

    # ---------------------------------------------------------------------------
    # Issue registry — exposed for external consumers (e.g. mail_audit)
    # ---------------------------------------------------------------------------

    _DEFINITIONS: Dict[str, Dict[str, Any]] = {
        "domain_not_exist":                     {"title": "Non-existent domain",                       "category": "SPF",   "severity": "high"},
        "no_spf":                               {"title": "No SPF",                                    "category": "SPF",   "severity": "critical"},
        "spf_no_all":                           {"title": "No 'all' mechanism",                        "category": "SPF",   "severity": "high"},
        "spf_pass":                             {"title": "'Pass' qualifier for 'all' mechanism",      "category": "SPF",   "severity": "critical"},
        "spf_neutral":                          {"title": "'Neutral' qualifier for 'all' mechanism",   "category": "SPF",   "severity": "high"},
        "spf_softfail":                         {"title": "'SoftFail' qualifier for 'all' mechanism",  "category": "SPF",   "severity": "medium"},
        "spf_too_many_lookups":                 {"title": "Too many lookups for SPF validation",       "category": "SPF",   "severity": "medium"},
        "spf_unregistered_domains_chain":       {"title": "Unregistered domains in SPF chain",        "category": "SPF",   "severity": "critical"},
        "spf_dns_timeout":                      {"title": "DNS Timeout on Email Domain",               "category": "SPF",   "severity": "high"},
        "spf_recurse":                          {"title": "Trivial SPF recurse",                       "category": "SPF",   "severity": "medium"},
        "spf_dangerous_include":                {"title": "Dangerous SPF include",                     "category": "SPF",   "severity": "high"},
        "spf_dangerous_ip":                     {"title": "Dangerous SPF IP range",                    "category": "SPF",   "severity": "high"},
        "spf_dangerous_as":                     {"title": "Dangerous AS organization",                 "category": "SPF",   "severity": "high"},
        "spf_dangerous_ptr":                    {"title": "Dangerous PTR mechanism",                   "category": "SPF",   "severity": "high"},
        "spf_syntax_error":                     {"title": "SPF Syntax Error",                          "category": "SPF",   "severity": "high"},
        "spf_domain_unregistered":              {"title": "Unregistered domain in SPF",                "category": "SPF",   "severity": "critical"},
        "spf_domain_potentially_unregistered":  {"title": "Potentially unregistered domain in SPF",   "category": "SPF",   "severity": "high"},
        "no_dmarc":                             {"title": "No DMARC",                                  "category": "DMARC", "severity": "critical"},
        "dmarc_lax_policy":                     {"title": "Lax DMARC policy",                         "category": "DMARC", "severity": "high"},
        "dmarc_lax_subdomain_policy":           {"title": "Lax DMARC subdomain policy",               "category": "DMARC", "severity": "medium"},
        "dmarc_partial_coverage":               {"title": "Partial DMARC coverage",                   "category": "DMARC", "severity": "medium"},
        "dmarc_dns_timeout":                    {"title": "DNS Timeout on Email Domain",               "category": "DMARC", "severity": "high"},
        "dmarc_syntax_error":                   {"title": "DMARC Syntax Error",                        "category": "DMARC", "severity": "high"},
        "dmarc_invalid_tag":                    {"title": "Invalid DMARC Tag",                         "category": "DMARC", "severity": "medium"},
        "dmarc_invalid_tag_value":              {"title": "Invalid DMARC Tag Value",                   "category": "DMARC", "severity": "medium"},
        "dmarc_invalid_report_uri":             {"title": "Invalid DMARC Report URI",                  "category": "DMARC", "severity": "low"},
        "dmarc_multiple_records":               {"title": "Multiple DMARC Records",                    "category": "DMARC", "severity": "high"},
        "dkim_no_selectors":                    {"title": "No DKIM selectors found",                   "category": "DKIM",  "severity": "medium"},
        "dkim_rsa_weak_key":                    {"title": "Weak DKIM RSA key size",                    "category": "DKIM",  "severity": "high"},
        "dkim_rsa_perfectible_key":             {"title": "Perfectible DKIM RSA key size",             "category": "DKIM",  "severity": "low"},
        "dkim_dns_timeout":                     {"title": "DNS Timeout on Email Domain",               "category": "DKIM",  "severity": "high"},
        "dkim_syntax_error":                    {"title": "DKIM Syntax Error",                         "category": "DKIM",  "severity": "medium"},
        "spf_cname_target_unregistered":                {"title": "SPF domain CNAME points to an unregistered domain",  "category": "SPF",   "severity": "critical"},
        "spf_cname_target_potentially_unregistered":    {"title": "SPF domain CNAME points to a potentially unregistered domain", "category": "SPF", "severity": "high"},
        "dmarc_cname_target_unregistered":              {"title": "_dmarc CNAME points to an unregistered domain",     "category": "DMARC", "severity": "critical"},
        "dmarc_cname_target_potentially_unregistered":  {"title": "_dmarc CNAME points to a potentially unregistered domain", "category": "DMARC", "severity": "high"},
        "dkim_cname_target_unregistered":               {"title": "DKIM selector CNAME points to an unregistered domain", "category": "DKIM", "severity": "critical"},
        "dkim_cname_target_potentially_unregistered":   {"title": "DKIM selector CNAME points to a potentially unregistered domain", "category": "DKIM", "severity": "high"},
    }

    # What each protocol expects to find at the end of the CNAME chain
    _CNAME_RECORD_LABEL = {
        "SPF":   "SPF TXT record (v=spf1)",
        "DMARC": "DMARC TXT record (v=DMARC1)",
        "DKIM":  "DKIM public-key TXT record",
    }

    @classmethod
    def cname_slug(cls, protocol: str, kind: str) -> str:
        """Return the slug for a CNAME *kind* (anomaly or registration state) of *protocol*."""
        return f"{protocol.lower()}_{cls.CNAME_SLUG_SUFFIXES[kind]}"

    @classmethod
    def create_cname_issue(
        cls,
        protocol: str,
        kind: str,
        names: list,
        chain: list,
        failing_target: str = None,
        registrable_domain: str = None,
        registration_reason: str = None,
        note: str = None,
        additional_data: Dict[str, Any] = None,
    ) -> Issue:
        """CNAME at a DKIM / DMARC / SPF lookup name pointing into an unregistered domain.

        *kind* is ``unregistered`` (availability pipeline: available) or
        ``potentially_unregistered`` (no NS, registration not confirmed).
        *names* lists every lookup name grouped under this issue (several DKIM
        selectors behind a wildcard).  *note* is appended to the detail.
        """
        slug = cls.cname_slug(protocol, kind)
        definition = cls._DEFINITIONS[slug]
        record = cls._CNAME_RECORD_LABEL[protocol]
        chain_str = " -> ".join(chain) if chain else ""
        names_str = ", ".join(f"'{n}'" for n in names[:10])
        if len(names) > 10:
            names_str += f" (+{len(names) - 10} more)"

        if kind == "unregistered":
            detail = (
                f"{names_str} is a CNAME alias ({chain_str}) whose target '{failing_target}' "
                f"belongs to the registrable domain '{registrable_domain}', which appears to be "
                f"unregistered (source: {registration_reason}). Whoever registers it could publish "
                f"their own {record} that receivers would accept for this name. Takeover is NOT "
                f"confirmed: verify with the registry/registrar before concluding."
            )
        elif kind == "potentially_unregistered":
            detail = (
                f"{names_str} is a CNAME alias ({chain_str}) whose target '{failing_target}' "
                f"belongs to the registrable domain '{registrable_domain}'. The domain has no NS "
                f"records and its registration status could not be confirmed (source: "
                f"{registration_reason}). If it is unregistered, whoever registers it could publish "
                f"their own {record}. Takeover is NOT confirmed."
            )
        else:
            raise ValueError(f"Unknown CNAME issue kind: {kind}")

        if note:
            detail += f" {note}"

        data: Dict[str, Any] = {
            "names": list(names),
            "chain": list(chain or []),
            "cname_kind": kind,
        }
        if failing_target:
            data["failing_target"] = failing_target
        if registrable_domain:
            data["registrable_domain"] = registrable_domain
        if registration_reason:
            data["registration_reason"] = registration_reason
        if additional_data:
            data.update(additional_data)

        severity = {s.value: s for s in IssueSeverity}[definition["severity"]]
        return Issue(
            code=slug,
            title=definition["title"],
            detail=detail,
            category=IssueCategory(protocol),
            severity=severity,
            additional_data=data,
        )

    @classmethod
    def get_issue_definitions(cls) -> Dict[str, Dict[str, Any]]:
        """Return all issue definitions keyed by slug.

        Consumed by external modules (e.g. mail_audit) to validate that
        slugs referenced in scenario rules actually exist.
        """
        return dict(cls._DEFINITIONS)

    @classmethod
    def create_spf_nx_domain(cls, domain: str) -> Issue:
        """Non-existent domain"""
        return Issue(
            code=cls.SPF_NX_DOMAIN,
            title="Non-existent domain",
            detail=f"The DNS resolver raised an NXDomain error for '{domain}'",
            category=IssueCategory.SPF,
            severity=IssueSeverity.HIGH
        )

    @classmethod
    def create_spf_no_spf(cls) -> Issue:
        """No SPF record"""
        return Issue(
            code=cls.SPF_NO_SPF,
            title="No SPF",
            detail="There is no SPF DNS record for the domain.",
            category=IssueCategory.SPF,
            severity=IssueSeverity.CRITICAL
        )

    @classmethod
    def create_spf_no_all(cls) -> Issue:
        """No 'all' mechanism"""
        return Issue(
            code=cls.SPF_NO_ALL,
            title="No 'all' mechanism",
            detail="There is no all mechanism in the record. It may be possible to spoof the domain without causing an SPF failure.",
            category=IssueCategory.SPF,
            severity=IssueSeverity.HIGH
        )

    @classmethod
    def create_spf_pass_all(cls) -> Issue:
        """Pass qualifier for 'all' mechanism"""
        return Issue(
            code=cls.SPF_PASS_ALL,
            title="'Pass' qualifier for 'all' mechanism",
            detail="The 'all' mechanism uses the 'Pass' qualifier '+'. It should be possible to spoof the domain without causing an SPF failure.",
            category=IssueCategory.SPF,
            severity=IssueSeverity.CRITICAL
        )

    @classmethod
    def create_spf_neutral_all(cls) -> Issue:
        """Neutral qualifier for 'all' mechanism"""
        return Issue(
            code=cls.SPF_NEUTRAL_ALL,
            title="'Neutral' qualifier for 'all' mechanism",
            detail="The 'all' mechanism uses the 'Neutral' qualifier '?'. SPF then returns 'neutral' for any sender — explicitly 'no opinion', which most receivers treat like having no SPF assertion at all. This is more permissive than SoftFail (which at least emits a negative signal), so the domain can be spoofed without SPF pushing back.",
            category=IssueCategory.SPF,
            severity=IssueSeverity.HIGH
        )

    @classmethod
    def create_spf_soft_fail_all(cls) -> Issue:
        """SoftFail qualifier for 'all' mechanism"""
        return Issue(
            code=cls.SPF_SOFT_FAIL_ALL,
            title="'SoftFail' qualifier for 'all' mechanism",
            detail="The 'all' mechanism uses the 'SoftFail' qualifier '~'. It should be possible to spoof the domain by only causing a soft SPF failure. Most filters will let this through by only raising the total spam score. (Less permissive than Neutral '?', which emits no negative signal at all.)",
            category=IssueCategory.SPF,
            severity=IssueSeverity.MEDIUM
        )

    @classmethod
    def create_spf_lookup_error(cls) -> Issue:
        """Too many lookups"""
        return Issue(
            code=cls.SPF_LOOKUP_ERROR,
            title="Too many lookups for SPF validation",
            detail="The SPF record requires more than 10 DNS lookups for the validation process. The RFC states that maximum 10 lookups are allowed. As a result, recipients may throw a PermError instead of proceeding with SPF validation.",
            category=IssueCategory.SPF,
            severity=IssueSeverity.MEDIUM
        )

    @classmethod
    def create_spf_unregistered_domains(cls, domains: list) -> Issue:
        """Unregistered domains in SPF chain"""
        return Issue(
            code=cls.SPF_UNREGISTERED_DOMAINS,
            title="Unregistered domains in SPF validation chain",
            detail=f"One or more domains used in the SPF validation process are presently unregistered. An attacker could register these and configure his own SPF record to be included in the validation logic. The affected domains are: {', '.join(domains)}",
            category=IssueCategory.SPF,
            severity=IssueSeverity.CRITICAL
        )

    @classmethod
    def create_spf_dns_timeout(cls, domain: str, severity: IssueSeverity = IssueSeverity.HIGH) -> Issue:
        """DNS timeout on email domain"""
        return Issue(
            code=cls.SPF_DNS_TIMEOUT,
            title="DNS Timeout on Email Domain",
            detail=f"DNS timeout when querying '{domain}'. This domain appears to be used for email based on detected indicators (MX/SPF/DMARC/SMTP).",
            category=IssueCategory.SPF,
            severity=severity
        )

    @classmethod
    def create_spf_recurse(cls, recursive_domain: str, domain: str) -> Issue:
        """Trivial SPF recurse"""
        return Issue(
            code=cls.SPF_RECURSE,
            title="Trivial SPF recurse",
            detail=f"Infinite recurse loop with the domain {recursive_domain} included in the validation chain for {domain}",
            category=IssueCategory.SPF,
            severity=IssueSeverity.MEDIUM
        )

    @classmethod
    def create_spf_dangerous_include(cls, include: str, service_type: str, service_name: str, severity: IssueSeverity = None) -> Issue:
        """Dangerous SPF include"""
        # Use provided severity or fallback to legacy logic
        if severity is None:
            severity = IssueSeverity.CRITICAL if service_type == "Shared Hosting" else IssueSeverity.HIGH

        return Issue(
            code=cls.SPF_DANGEROUS_INCLUDE,
            title=f"Dangerous SPF include: {service_type}",
            detail=f"The SPF record includes '{include}' which is a {service_type} ({service_name}). This allows anyone using this service to send emails on behalf of this domain.",
            category=IssueCategory.SPF,
            severity=severity,
            additional_data={'include': include, 'service_type': service_type, 'service_name': service_name}
        )

    @classmethod
    def create_spf_dangerous_ip_range(cls, ip_range: str, service_type: str, service_name: str, match_type: str = None, dangerous_range: str = None, overlap_details: dict = None, severity: IssueSeverity = None) -> Issue:
        """Dangerous SPF IP range"""
        # Use provided severity or fallback to legacy logic
        if severity is None:
            severity = IssueSeverity.CRITICAL if service_type == "Shared Hosting" else IssueSeverity.HIGH

        # Build title with match type if provided
        if match_type == 'subnet':
            title = f"Dangerous SPF IP range (exact match): {service_type}"
        elif match_type == 'contains_dangerous_subnet':
            title = f"Dangerous SPF IP range (contains dangerous subnet): {service_type}"
        elif match_type == 'partial_overlap':
            title = f"Dangerous SPF IP range (partial overlap): {service_type}"
        else:
            title = f"Dangerous SPF IP range: {service_type}"

        # Prepare additional_data
        data = {
            'ip_range': ip_range,
            'service_type': service_type,
            'service_name': service_name
        }

        if match_type:
            data['match_type'] = match_type
        if dangerous_range:
            data['dangerous_range'] = dangerous_range
        if overlap_details:
            data.update(overlap_details)

        return Issue(
            code=cls.SPF_DANGEROUS_IP_RANGE,
            title=title,
            detail=f"The SPF record contains IP range '{ip_range}' which belongs to a {service_type} ({service_name}). This allows anyone using this service to send emails on behalf of this domain.",
            category=IssueCategory.SPF,
            severity=severity,
            additional_data=data
        )

    @classmethod
    def create_spf_dangerous_as_organization(cls, ip: str, as_organization: str, service_type: str, service_name: str, severity: IssueSeverity = None) -> Issue:
        """Dangerous AS organization"""
        # Use provided severity or fallback to legacy logic
        if severity is None:
            severity = IssueSeverity.CRITICAL if service_type == "Shared Hosting" else IssueSeverity.HIGH

        return Issue(
            code=cls.SPF_DANGEROUS_AS_ORGANIZATION,
            title=f"Dangerous AS organization: {service_type}",
            detail=f"The SPF record contains IP '{ip}' which belongs to AS organization '{as_organization}', a {service_type} ({service_name}). This allows anyone using this service to send emails on behalf of this domain.",
            category=IssueCategory.SPF,
            severity=severity,
            additional_data={'ip': ip, 'as_organization': as_organization, 'service_type': service_type, 'service_name': service_name}
        )

    @classmethod
    def create_spf_dangerous_ptr(cls, ptr_domain: str, service_type: str, service_name: str, severity: IssueSeverity = None) -> Issue:
        """Dangerous PTR mechanism"""
        # Use provided severity or fallback to legacy logic
        if severity is None:
            severity = IssueSeverity.CRITICAL if service_type == "Shared Hosting" else IssueSeverity.HIGH

        return Issue(
            code="spf_dangerous_ptr",
            title=f"Dangerous PTR mechanism: {service_type}",
            detail=f"The SPF record uses 'ptr' or 'ptr:{ptr_domain}' mechanism which allows hosts with PTR records ending in '{ptr_domain}', a {service_type} ({service_name}). This allows anyone using this service to send emails on behalf of this domain.",
            category=IssueCategory.SPF,
            severity=severity,
            additional_data={'ptr_domain': ptr_domain, 'service_type': service_type, 'service_name': service_name}
        )

    @classmethod
    def create_dmarc_no_dmarc(cls) -> Issue:
        """No DMARC"""
        return Issue(
            code=cls.DMARC_NO_DMARC,
            title="No DMARC",
            detail="There is no DMARC DNS record associated for the domain.",
            category=IssueCategory.DMARC,
            severity=IssueSeverity.CRITICAL
        )

    @classmethod
    def create_dmarc_lax_policy(cls, policy: str, inherited_from: str = None) -> Issue:
        """Lax DMARC policy (optionally inherited from the organizational domain)"""
        source = (
            f" (no _dmarc record on this subdomain: policy inherited from the organizational "
            f"domain {inherited_from})" if inherited_from else ""
        )
        data = {'policy': policy}
        if inherited_from:
            data['inherited_from'] = inherited_from
        return Issue(
            code=cls.DMARC_LAX_POLICY,
            title="Lax DMARC policy",
            detail=f"The DMARC policy is set to '{policy}'{source}. If the DMARC policy is neither 'reject' nor 'quarantine', spoofed emails are likely to be accepted.",
            category=IssueCategory.DMARC,
            severity=IssueSeverity.HIGH,
            additional_data=data
        )

    @classmethod
    def create_dmarc_lax_subdomain_policy(cls, policy: str) -> Issue:
        """Lax DMARC subdomain policy"""
        return Issue(
            code=cls.DMARC_LAX_SUBDOMAIN_POLICY,
            title="Lax DMARC subdomain policy",
            detail=f"The DMARC policy for subdomains is set to '{policy}'. If the DMARC policy is neither 'reject' nor 'quarantine', spoofed emails from subdomains are likely to be accepted.",
            category=IssueCategory.DMARC,
            severity=IssueSeverity.MEDIUM,
            additional_data={'subdomain_policy': policy}
        )

    @classmethod
    def create_dmarc_not_100_pct(cls, pct: int) -> Issue:
        """Partial DMARC coverage"""
        return Issue(
            code=cls.DMARC_NOT_100_PCT,
            title="Partial DMARC coverage",
            detail=f"The DMARC 'pct' value is '{pct}', meaning the DMARC policy will only be applied to {pct}% of incoming mail.",
            category=IssueCategory.DMARC,
            severity=IssueSeverity.MEDIUM,
            additional_data={'percentage': pct}
        )

    @classmethod
    def create_dmarc_dns_timeout(cls, domain: str, severity: IssueSeverity = IssueSeverity.HIGH) -> Issue:
        """DNS timeout on email domain"""
        return Issue(
            code=cls.DMARC_DNS_TIMEOUT,
            title="DNS Timeout on Email Domain",
            detail=f"DNS timeout when querying '{domain}'. This domain appears to be used for email based on detected indicators (MX/SPF/DMARC/SMTP).",
            category=IssueCategory.DMARC,
            severity=severity
        )

    @classmethod
    def create_dkim_no_selectors_found(cls) -> Issue:
        """No DKIM selectors found"""
        return Issue(
            code=cls.DKIM_NO_SELECTORS_FOUND,
            title="No DKIM selectors found",
            detail="None of the tested DKIM selectors were found for this domain. The domain may not be using DKIM, or uses custom selectors not in the test list.",
            category=IssueCategory.DKIM,
            severity=IssueSeverity.MEDIUM
        )

    @classmethod
    def create_dkim_rsa_weak_key(cls, selector: str, key_size: int) -> Issue:
        """Weak DKIM RSA key size (below 1024 bits)"""
        return Issue(
            code=cls.DKIM_RSA_WEAK_KEY,
            title="Weak DKIM RSA key size",
            detail=f"DKIM selector '{selector}' uses a {key_size}-bit RSA key, which is below the RFC 8301 minimum of 1024 bits. A key this short can be factored to recover the private key.",
            category=IssueCategory.DKIM,
            severity=IssueSeverity.HIGH,
            additional_data={'selector': selector, 'key_size': key_size}
        )

    @classmethod
    def create_dkim_rsa_perfectible_key(cls, selector: str, key_size: int) -> Issue:
        """Perfectible DKIM RSA key size (exactly 1024 bits)"""
        return Issue(
            code=cls.DKIM_RSA_PERFECTIBLE_KEY,
            title="Perfectible DKIM RSA key size",
            detail=f"DKIM selector '{selector}' uses a {key_size}-bit RSA key. 1024 bits is the RFC 8301 minimum and is not practically factorable today, but 2048 bits is the recommended size (RFC 8301, M3AAWG). Plan a rotation to a 2048-bit key.",
            category=IssueCategory.DKIM,
            severity=IssueSeverity.LOW,
            additional_data={'selector': selector, 'key_size': key_size}
        )

    @classmethod
    def create_dkim_dns_timeout(cls, domain: str, severity: IssueSeverity = IssueSeverity.HIGH) -> Issue:
        """DNS timeout on email domain"""
        return Issue(
            code=cls.DKIM_DNS_TIMEOUT,
            title="DNS Timeout on Email Domain",
            detail=f"DNS timeout when querying '{domain}'. This domain appears to be used for email based on detected indicators (MX/SPF/DMARC/SMTP).",
            category=IssueCategory.DKIM,
            severity=severity
        )

    @classmethod
    def create_spf_syntax_error(cls, error_message: str) -> Issue:
        """SPF syntax error"""
        return Issue(
            code=cls.SPF_SYNTAX_ERROR,
            title="SPF Syntax Error",
            detail=f"The SPF record has a syntax error: {error_message}",
            category=IssueCategory.SPF,
            severity=IssueSeverity.HIGH,
            additional_data={'error_message': error_message}
        )

    @classmethod
    def create_dmarc_syntax_error(cls, error_message: str) -> Issue:
        """DMARC syntax error"""
        return Issue(
            code=cls.DMARC_SYNTAX_ERROR,
            title="DMARC Syntax Error",
            detail=f"The DMARC record has a syntax error: {error_message}",
            category=IssueCategory.DMARC,
            severity=IssueSeverity.HIGH,
            additional_data={'error_message': error_message}
        )

    @classmethod
    def create_dmarc_invalid_tag(cls, tag_name: str, error_message: str) -> Issue:
        """Invalid DMARC tag"""
        return Issue(
            code=cls.DMARC_INVALID_TAG,
            title="Invalid DMARC Tag",
            detail=f"The DMARC record contains an invalid tag '{tag_name}': {error_message}",
            category=IssueCategory.DMARC,
            severity=IssueSeverity.MEDIUM,
            additional_data={'tag_name': tag_name, 'error_message': error_message}
        )

    @classmethod
    def create_dmarc_invalid_tag_value(cls, tag_name: str, value: str, error_message: str) -> Issue:
        """Invalid DMARC tag value"""
        return Issue(
            code=cls.DMARC_INVALID_TAG_VALUE,
            title="Invalid DMARC Tag Value",
            detail=f"The DMARC tag '{tag_name}' has an invalid value '{value}': {error_message}",
            category=IssueCategory.DMARC,
            severity=IssueSeverity.MEDIUM,
            additional_data={'tag_name': tag_name, 'value': value, 'error_message': error_message}
        )

    @classmethod
    def create_dmarc_invalid_report_uri(cls, uri: str, error_message: str) -> Issue:
        """Invalid DMARC report URI"""
        return Issue(
            code=cls.DMARC_INVALID_REPORT_URI,
            title="Invalid DMARC Report URI",
            detail=f"The DMARC record contains an invalid report URI '{uri}': {error_message}",
            category=IssueCategory.DMARC,
            severity=IssueSeverity.LOW,
            additional_data={'uri': uri, 'error_message': error_message}
        )

    @classmethod
    def create_dmarc_multiple_records(cls, error_message: str) -> Issue:
        """Multiple DMARC records"""
        return Issue(
            code=cls.DMARC_MULTIPLE_RECORDS,
            title="Multiple DMARC Records",
            detail=f"Multiple DMARC records were found for this domain: {error_message}",
            category=IssueCategory.DMARC,
            severity=IssueSeverity.HIGH,
            additional_data={'error_message': error_message}
        )

    @classmethod
    def create_dkim_syntax_error(cls, selector: str, error_message: str) -> Issue:
        """DKIM syntax error"""
        return Issue(
            code=cls.DKIM_SYNTAX_ERROR,
            title="DKIM Syntax Error",
            detail=f"DKIM selector '{selector}' has a syntax error: {error_message}",
            category=IssueCategory.DKIM,
            severity=IssueSeverity.MEDIUM,
            additional_data={'selector': selector, 'error_message': error_message}
        )

    @classmethod
    def create_spf_unregistered_domain(cls, include: str, registered_domain: str) -> Issue:
        """SPF include references an unregistered domain"""
        return Issue(
            code=cls.SPF_UNREGISTERED_DOMAIN,
            title="Unregistered domain",
            detail=(
                f"The SPF include '{include}' references the domain '{registered_domain}' "
                f"which is currently unregistered. An attacker could register this domain "
                f"and configure a malicious SPF record to be included in the validation chain."
            ),
            category=IssueCategory.SPF,
            severity=IssueSeverity.CRITICAL,
            additional_data={'include': include, 'registered_domain': registered_domain}
        )

    @classmethod
    def create_spf_potentially_unregistered_domain(cls, include: str, registered_domain: str) -> Issue:
        """SPF include references a potentially unregistered domain"""
        return Issue(
            code=cls.SPF_POTENTIALLY_UNREGISTERED_DOMAIN,
            title="Potentially unregistered domain",
            detail=(
                f"The SPF include '{include}' references the domain '{registered_domain}' "
                f"which may be unregistered (availability could not be confirmed). "
                f"An attacker may be able to register this domain and configure a malicious "
                f"SPF record to be included in the validation chain."
            ),
            category=IssueCategory.SPF,
            severity=IssueSeverity.HIGH,
            additional_data={'include': include, 'registered_domain': registered_domain}
        )
