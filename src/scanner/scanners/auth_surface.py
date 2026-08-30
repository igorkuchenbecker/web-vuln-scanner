"""Authentication-surface discovery.

This scanner *maps* where authentication happens; it never tries to defeat it.
There is no brute force, no credential guessing and no bypass. Findings are
INFO-severity inventory items that help a human focus manual testing.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..core.models import (
    Confidence,
    HttpMethod,
    ScanResult,
    Severity,
)
from .base import ScanContext, Scanner, register

__all__ = ["AuthSurfaceScanner"]

_LOGIN_PATH_HINTS = (
    "login",
    "signin",
    "sign-in",
    "auth",
    "authenticate",
    "session",
    "account/login",
    "admin",
)


@register
class AuthSurfaceScanner(Scanner):
    """Reports likely authentication endpoints (discovery only)."""

    name = "auth-surface"
    description = "Discovers likely login/authentication surface (no exploitation)."

    def scan(self, context: ScanContext) -> list[ScanResult]:
        findings: list[ScanResult] = []
        seen: set[str] = set()

        for form in context.site_map.forms:
            if self._looks_like_login_form(form) and form.action not in seen:
                seen.add(form.action)
                findings.append(self._form_finding(form))

        for page in context.site_map.pages:
            path = urlsplit(page.url).path.lower()
            if any(hint in path for hint in _LOGIN_PATH_HINTS) and page.url not in seen:
                seen.add(page.url)
                findings.append(self._path_finding(page.url))

        return findings

    @staticmethod
    def _looks_like_login_form(form) -> bool:
        has_password = any(f.field_type == "password" for f in form.fields)
        names = " ".join(form.field_names).lower()
        looks_like_credentials = has_password or (
            "user" in names and "pass" in names
        )
        return looks_like_credentials

    def _form_finding(self, form) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            vulnerability="Authentication surface discovered (login form)",
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            url=form.action,
            method=form.method,
            evidence=f"Form with fields {list(form.field_names)} posting to {form.action}.",
            description=(
                "A form resembling a login/authentication form was discovered. This "
                "is surface-mapping only; the scanner does not attempt to "
                "authenticate, bypass, or brute-force it."
            ),
            remediation=(
                "Ensure authentication endpoints enforce rate limiting, account "
                "lockout/backoff, MFA where appropriate and transport security."
            ),
            impact=(
                "Informational: identifies where authentication is handled so a human "
                "tester can review it under proper authorisation."
            ),
            severity_rationale=(
                "INFO: this is inventory, not a vulnerability. No weakness is claimed."
            ),
        )

    def _path_finding(self, url: str) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            vulnerability="Authentication surface discovered (URL pattern)",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            url=url,
            method=HttpMethod.GET,
            evidence=f"URL path matches a known authentication pattern: {url}",
            description=(
                "A URL whose path suggests authentication was discovered. Reported "
                "for manual review; no authentication attempt was made."
            ),
            remediation=(
                "Confirm the endpoint's protections (rate limiting, MFA, secure "
                "session handling) during manual assessment."
            ),
            impact="Informational: helps target manual authorised testing.",
            severity_rationale="INFO: heuristic path match only; low confidence.",
        )
