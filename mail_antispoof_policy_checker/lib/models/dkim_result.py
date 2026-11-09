"""DKIM check result models"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from .issue import Issue
from .cname_result import CNAMECheck


@dataclass
class DKIMSelectorInfo:
    """Information about a discovered DKIM selector"""

    selector: str
    found: bool
    key_size: Optional[int] = None
    public_key: Optional[str] = None
    key_type: Optional[str] = None
    record: Optional[str] = None  # raw DKIM TXT record
    issues: List[Issue] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            'selector': self.selector,
            'found': self.found
        }

        if self.found:
            result.update({
                'dkim_record': self.record,
                'key_size': self.key_size,
                'key_type': self.key_type,
                'issues': [issue.to_dict() for issue in self.issues]
            })

        return result


@dataclass
class DKIMResult:
    """Result of DKIM policy checking"""

    domain: str
    selectors_tested: List[str] = field(default_factory=list)
    selectors_found: List[DKIMSelectorInfo] = field(default_factory=list)
    issues: List[Issue] = field(default_factory=list)
    cname_checks: List[CNAMECheck] = field(default_factory=list)  # CNAME chains at selector names

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'domain': self.domain,
            'selectors_tested': len(self.selectors_tested),
            'selectors_found': [selector.to_dict() for selector in self.selectors_found],
            'issues': [issue.to_dict() for issue in self.issues],
            'cname_checks': [check.to_dict() for check in self.cname_checks],
            'statistics': {
                'total_selectors_found': len(self.selectors_found),
                'total_issues': len(self.issues),
                'critical_issues': sum(1 for i in self.issues if i.severity.value == 'critical'),
                'high_issues': sum(1 for i in self.issues if i.severity.value == 'high'),
                'medium_issues': sum(1 for i in self.issues if i.severity.value == 'medium'),
                'low_issues': sum(1 for i in self.issues if i.severity.value == 'low')
            }
        }

    def add_issue(self, issue: Issue):
        """Add an issue to the result"""
        self.issues.append(issue)

    def add_selector(self, selector_info: DKIMSelectorInfo):
        """Add a discovered selector"""
        if selector_info.found:
            self.selectors_found.append(selector_info)
            # Aggregate selector-specific issues to the main result
            for issue in selector_info.issues:
                self.add_issue(issue)
