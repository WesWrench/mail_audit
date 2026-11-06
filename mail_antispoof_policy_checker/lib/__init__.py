"""
Mail AntiSpoof Policy Checker Library

A comprehensive library for checking DMARC, SPF, and DKIM policies
with advanced detection of dangerous configurations.
"""

from .checkers.spf_checker import SPFChecker
from .checkers.dmarc_checker import DMARCChecker
from .checkers.dkim_checker import DKIMChecker
from .utils.email_domain_checker import EmailDomainChecker
from .utils.maxmind_client import MaxMindClient, InvalidLicenseKeyError
from .utils.async_dns_resolver import AsyncPooledDNSResolver
from .utils.org_domains import organizational_domain, is_subdomain, derive_org_parents
from .data.loaders import DataLoaders

__all__ = [
    'SPFChecker',
    'DMARCChecker',
    'DKIMChecker',
    'EmailDomainChecker',
    'MaxMindClient',
    'InvalidLicenseKeyError',
    'AsyncPooledDNSResolver',
    'organizational_domain',
    'is_subdomain',
    'derive_org_parents',
    'DataLoaders'
]
__version__ = '2.2.0'
