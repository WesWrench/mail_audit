"""Models for the Mail AntiSpoof Policy Checker"""

from .issue import Issue, IssueCategory, IssueSeverity
from .spf_result import SPFResult, SPFResolutionPath
from .dmarc_result import DMARCResult
from .dkim_result import DKIMResult
from .cname_result import CNAMECheck

__all__ = [
    'CNAMECheck',
    'Issue',
    'IssueCategory',
    'IssueSeverity',
    'SPFResult',
    'SPFResolutionPath',
    'DMARCResult',
    'DKIMResult'
]
