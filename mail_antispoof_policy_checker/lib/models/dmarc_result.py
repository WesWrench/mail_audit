"""DMARC check result models"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from .issue import Issue
from .cname_result import CNAMECheck


@dataclass
class DMARCResult:
    """Result of DMARC policy checking"""

    domain: str
    dmarc_record: Optional[str] = None
    issues: List[Issue] = field(default_factory=list)
    policy: Optional[str] = None
    subdomain_policy: Optional[str] = None
    np_policy: Optional[str] = None  # RFC 9091 non-existent-subdomain policy (np=)
    testing: bool = False  # RFC 9989 t=y: policy published in test mode (not to be applied)
    psd: Optional[str] = None  # RFC 9989 psd= flag (y / n / u)
    percentage: int = 100  # RFC 7489 pct= (removed in RFC 9989, still honoured by older receivers)
    aggregate_reports: List[str] = field(default_factory=list)
    forensic_reports: List[str] = field(default_factory=list)
    alignment_spf: Optional[str] = None
    alignment_dkim: Optional[str] = None
    parsed_dmarc: Optional[Dict[str, Any]] = None  # Complete parsed structure from checkdmarc
    dmarc_domain_checked: Optional[str] = None  # The actual domain where DMARC was found (for subdomain fallback)
    policy_inherited_from: Optional[str] = None  # e.g. "exemple.fr (sp=none)" when inherited from the org domain
    organizational_policy: Optional[str] = None  # org domain's own p= (policy above is the effective sp=/p=)
    cname_checks: List[CNAMECheck] = field(default_factory=list)  # CNAME chain at the lookup name(s)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            'domain': self.domain,
            'dmarc_record': self.dmarc_record,
            'issues': [issue.to_dict() for issue in self.issues],
            'policy': self.policy,
            'subdomain_policy': self.subdomain_policy,
            'np_policy': self.np_policy,
            'testing': self.testing,
            'psd': self.psd,
            'percentage': self.percentage,
            'aggregate_reports': self.aggregate_reports,
            'forensic_reports': self.forensic_reports,
            'alignment_spf': self.alignment_spf,
            'alignment_dkim': self.alignment_dkim,
            'cname_checks': [check.to_dict() for check in self.cname_checks],
            'statistics': {
                'total_issues': len(self.issues),
                'critical_issues': sum(1 for i in self.issues if i.severity.value == 'critical'),
                'high_issues': sum(1 for i in self.issues if i.severity.value == 'high'),
                'medium_issues': sum(1 for i in self.issues if i.severity.value == 'medium'),
                'low_issues': sum(1 for i in self.issues if i.severity.value == 'low')
            }
        }

        # Add DMARC domain checked if different from queried domain
        if self.dmarc_domain_checked and self.dmarc_domain_checked != self.domain:
            result['dmarc_domain_checked'] = self.dmarc_domain_checked
        if self.policy_inherited_from:
            result['policy_inherited_from'] = self.policy_inherited_from
            result['organizational_policy'] = self.organizational_policy

        # Add parsed DMARC if available
        if self.parsed_dmarc is not None:
            result['parsed_dmarc'] = self.parsed_dmarc

        return result

    def add_issue(self, issue: Issue):
        """Add an issue to the result"""
        self.issues.append(issue)
