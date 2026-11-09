"""
Exception classes for WhoisItLegacy.
"""


class WhoisError(Exception):
    """Base exception for all WHOIS-related errors."""
    pass


class WhoisConnectionError(WhoisError):
    """Raised when connection to WHOIS server fails."""
    pass


class WhoisParseError(WhoisError):
    """Raised when parsing WHOIS response fails."""
    pass


class WhoisNotFoundError(WhoisError):
    """Raised when WHOIS object is not found."""
    pass
