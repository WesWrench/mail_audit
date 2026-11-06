"""
DomainAvailabilityChecker — fast three-stage domain availability checker.

Pipeline: DNS NS lookup → WHOIS (hybridwhois) → service checker
"""

from .checker import DomainAvailabilityChecker, STATUS_AVAILABLE, STATUS_UNAVAILABLE, STATUS_UNKNOWN
from .dns_check import check_ns_async, check_ns_sync, DNSResult

__version__ = "1.0.0"

__all__ = [
    "DomainAvailabilityChecker",
    "STATUS_AVAILABLE",
    "STATUS_UNAVAILABLE",
    "STATUS_UNKNOWN",
    "check_ns_async",
    "check_ns_sync",
    "DNSResult",
]
