"""mail_antispoof_policy_checker - SPF, DMARC, DKIM policy analysis package."""
from .lib import (
    SPFChecker,
    DMARCChecker,
    DKIMChecker,
    EmailDomainChecker,
    MaxMindClient,
    InvalidLicenseKeyError,
    DataLoaders,
)

__version__ = "2.2.0"
__all__ = [
    "SPFChecker",
    "DMARCChecker",
    "DKIMChecker",
    "EmailDomainChecker",
    "MaxMindClient",
    "InvalidLicenseKeyError",
    "DataLoaders",
]
