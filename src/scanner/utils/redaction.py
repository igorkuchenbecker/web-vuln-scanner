"""Redaction helpers.

The scanner handles session cookies and ``Authorization`` headers supplied by
the operator. Those must never reach a log file or an HTML report, which are
routinely pasted into tickets and chat. Redaction happens at the single point
where such data would otherwise be rendered.
"""

from __future__ import annotations

from typing import Mapping

__all__ = ["SENSITIVE_HEADERS", "redact_headers", "redact_text"]

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "api-key",
    }
)

_PLACEHOLDER = "[REDACTED]"


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return ``headers`` with sensitive values replaced by a placeholder."""
    return {
        name: (_PLACEHOLDER if name.lower() in SENSITIVE_HEADERS else value)
        for name, value in headers.items()
    }


def redact_text(text: str, secrets: tuple[str, ...]) -> str:
    """Replace every occurrence of ``secrets`` in ``text``.

    Used before evidence taken from a live response is written to a report:
    a reflected value could otherwise carry a session cookie into the file.
    """
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, _PLACEHOLDER)
    return redacted
