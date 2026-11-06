"""
Custom exceptions for SMTP Checker.
"""


class SMTPConnectionError(Exception):
    """Raised when unable to connect to the SMTP server."""

    def __init__(self, message: str, original_error: Exception = None):
        super().__init__(message)
        self.original_error = original_error
