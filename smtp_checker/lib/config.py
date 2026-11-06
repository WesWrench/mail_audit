"""
Configuration and default options for SMTP Checker.
"""

from typing import Dict

# Default test options
DEFAULT_OPTIONS: Dict[str, bool] = {
    "smtp_banner_check": True,
    "smtp_connect": True,
    "smtp_connection_time": False,
    "smtp_dns_resolution": True,
    "smtp_open_relay": True,
    "smtp_reverse_dns_mismatch": True,
    "smtp_valid_hostname": True,
    "smtp_reverse_dns_resolution": True,
    "smtp_server_disconnected": True,
    "smtp_tls": True,
    "smtp_transaction_time": False,
    "smtp_reverse_lookup": True,
    "smtp_starttls_cert": False,
    "smtp_tls_cert_check": False,
}


def validate_options(options: Dict[str, bool]) -> Dict[str, bool]:
    """
    Validate and merge user options with defaults.

    :param options: User-provided test options.
    :return: Merged options dictionary.
    """
    validated = DEFAULT_OPTIONS.copy()

    for key, value in options.items():
        if key in DEFAULT_OPTIONS:
            if not isinstance(value, bool):
                raise ValueError(f"Option '{key}' must be a boolean value")
            validated[key] = value
        else:
            raise ValueError(f"Unknown option: '{key}'")

    return validated
