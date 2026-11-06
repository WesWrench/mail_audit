"""
SMTP Checker - Comprehensive SMTP server and mail-security testing library.
"""

from .checker import SMTPChecker
from .domain_checker import DomainChecker, get_issue_definitions, scan_domains_async
from .exceptions import SMTPConnectionError
from .excel_export import export_domain_results_to_excel

__version__ = "2.11.0"
__all__ = ["SMTPChecker", "DomainChecker", "scan_domains_async", "SMTPConnectionError", "get_issue_definitions",
           "export_domain_results_to_excel"]
