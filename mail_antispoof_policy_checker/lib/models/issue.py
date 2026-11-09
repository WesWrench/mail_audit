"""Issue model for representing security issues found during checks"""

from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


class IssueCategory(Enum):
    """Category of the security issue"""
    SPF = "SPF"
    DMARC = "DMARC"
    DKIM = "DKIM"


class IssueSeverity(Enum):
    """Severity level of the issue"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Issue:
    """Represents a security issue found during policy checking"""

    code: str  # Globally-unique slug, e.g. "no_dmarc", "spf_softfail"
    title: str
    detail: str
    category: IssueCategory
    severity: IssueSeverity
    resolution_path: Optional[list] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert issue to dictionary for JSON serialization"""
        result = {
            'code': self.code,
            'title': self.title,
            'detail': self.detail,
            'category': self.category.value,
            'severity': self.severity.value
        }

        if self.resolution_path:
            result['resolution_path'] = self.resolution_path

        if self.additional_data:
            result['additional_data'] = self.additional_data

        return result

    @classmethod
    def from_dict(cls, d: Dict[str, Any], category: IssueCategory) -> 'Issue':
        """Create an Issue from a dict (e.g. when loading from JSON output)."""
        sev_map = {s.value: s for s in IssueSeverity}
        return cls(
            code=str(d['code']),
            title=d.get('title', ''),
            detail=d.get('detail', ''),
            category=category,
            severity=sev_map.get(d.get('severity', 'medium'), IssueSeverity.MEDIUM),
            additional_data=d.get('additional_data', {}),
        )
