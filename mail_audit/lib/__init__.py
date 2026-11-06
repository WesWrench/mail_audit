"""
mail_audit.lib - Combined mail security auditing library.

Orchestrates smtp_checker (DomainChecker) and mail_antispoof_policy_checker
(SPF/DMARC/DKIM) and generates a structured attack scenario analysis with
Excel and JSON export capabilities.

Usage::

    from mail_audit.lib import MailAuditor

    auditor = MailAuditor(
        domains=["example.com", "target.org"],
        open_relay_sender="test@example.net",
        open_relay_recipient="osef@domain.com",
    )
    result = auditor.run()
    paths = auditor.export(result, base_filename="report")
    print(paths)
    # {"json": "/path/to/report.json", "excel": "/path/to/report.xlsx"}
"""

from .auditor import MailAuditor
from .models import (
    AuditResult,
    AttackCategory,
    AttackLikelihood,
    AttackProbability,
    AttackScenario,
    AttackType,
    AttackVector,
    VectorStatus,
    DomainAudit,
    RiskLevel,
)

__version__ = "2.2.0"

__all__ = [
    "MailAuditor",
    "AuditResult",
    "DomainAudit",
    "AttackScenario",
    "AttackVector",
    "AttackType",
    "AttackCategory",
    "AttackProbability",
    "AttackLikelihood",
    "RiskLevel",
]
