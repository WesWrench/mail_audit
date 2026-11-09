"""SPF check result models"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from .issue import Issue
from .cname_result import CNAMECheck


@dataclass
class SPFResolutionPath:
    """Represents a resolution path in the SPF tree"""

    path: List[str]
    mechanism_type: str  # 'include', 'a', 'mx', 'ip4', 'ip6', 'redirect'
    value: str
    issue: Optional[Issue] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            'path': ' -> '.join(self.path),
            'mechanism_type': self.mechanism_type,
            'value': self.value
        }

        if self.issue:
            result['issue'] = self.issue.to_dict()

        return result


@dataclass
class SPFResult:
    """Result of SPF policy checking"""

    domain: str
    spf_record: Optional[str] = None
    issues: List[Issue] = field(default_factory=list)
    resolution_paths: List[SPFResolutionPath] = field(default_factory=list)
    all_includes: List[Dict[str, Any]] = field(default_factory=list)
    all_ip_ranges: List[Dict[str, Any]] = field(default_factory=list)
    all_ip_addresses: List[Dict[str, Any]] = field(default_factory=list)
    lookup_count: int = 0
    has_all_mechanism: bool = False
    all_qualifier: Optional[str] = None
    parsed_spf: Optional[Dict[str, Any]] = None  # Complete parsed structure from checkdmarc
    cname_checks: List[CNAMECheck] = field(default_factory=list)  # CNAME chain at the lookup name(s)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            'domain': self.domain,
            'spf_record': self.spf_record,
            'issues': [issue.to_dict() for issue in self.issues],
            'resolution_paths': [path.to_dict() for path in self.resolution_paths],
            'all_includes': self.all_includes,
            'all_ip_ranges': self.all_ip_ranges,
            'all_ip_addresses': self.all_ip_addresses,
            'lookup_count': self.lookup_count,
            'has_all_mechanism': self.has_all_mechanism,
            'all_qualifier': self.all_qualifier,
            'cname_checks': [check.to_dict() for check in self.cname_checks],
            'statistics': {
                'total_issues': len(self.issues),
                'critical_issues': sum(1 for i in self.issues if i.severity.value == 'critical'),
                'high_issues': sum(1 for i in self.issues if i.severity.value == 'high'),
                'medium_issues': sum(1 for i in self.issues if i.severity.value == 'medium'),
                'low_issues': sum(1 for i in self.issues if i.severity.value == 'low')
            }
        }

        # Add parsed SPF if available
        if self.parsed_spf is not None:
            result['parsed_spf'] = self.parsed_spf

        return result

    def add_issue(self, issue: Issue, resolution_path: Optional[List[str]] = None):
        """Add an issue to the result"""
        if resolution_path:
            issue.resolution_path = resolution_path
        self.issues.append(issue)
