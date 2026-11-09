"""mail_audit - Combined mail security auditing package."""
from .lib import (
    MailAuditor,
    AuditResult,
    DomainAudit,
    AttackScenario,
    AttackType,
    AttackCategory,
    AttackProbability,
    AttackLikelihood,
    RiskLevel,
)

__version__ = "2.2.0"
__all__ = [
    "MailAuditor",
    "AuditResult",
    "DomainAudit",
    "AttackScenario",
    "AttackType",
    "AttackCategory",
    "AttackProbability",
    "AttackLikelihood",
    "RiskLevel",
]
