"""Exception hierarchy for the scanner.

A single root exception (:class:`ScannerError`) lets callers distinguish
errors raised by this package from arbitrary runtime errors, which keeps
``except Exception`` out of the codebase.
"""

from __future__ import annotations


class ScannerError(Exception):
    """Base class for every error raised by this package."""


class ConfigurationError(ScannerError):
    """Raised when user-supplied configuration is invalid."""


class ScopeError(ScannerError):
    """Raised when a URL cannot be reconciled with the authorised scope."""


class HttpError(ScannerError):
    """Base class for transport-level failures."""


class RequestFailed(HttpError):
    """Raised when a request could not be completed (DNS, TLS, timeout...)."""


class ResponseTooLarge(HttpError):
    """Raised when a response body exceeds the configured size limit."""


class BudgetExceeded(ScannerError):
    """Raised when the global request budget has been spent.

    This is a hard stop: it aborts the current phase instead of being
    retried, because continuing would mean sending unauthorised load.
    """


class ScanCancelled(ScannerError):
    """Raised when the operator asked for the run to stop.

    Cancellation is checked at the HTTP chokepoint, so a cancelled run stops
    at the next request boundary rather than mid-flight: a request already on
    the wire is allowed to finish and be accounted for. Unlike every other
    :class:`ScannerError`, this one is never swallowed per-scanner — the whole
    run is meant to end, not just the check that happened to notice.
    """
