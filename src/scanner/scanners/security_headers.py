"""Security-header and cookie misconfiguration checks.

These are the highest-confidence checks in the tool: presence or absence of a
response header is a fact, not an inference. Severity is still context-aware —
a missing HSTS header only matters over HTTPS, a missing CSP is medium rather
than high because it is defence-in-depth — so nothing is blanket-rated high.
"""

from __future__ import annotations

from ..core.exceptions import HttpError, ScopeError
from ..core.models import Confidence, HttpMethod, ScanResult, Severity, SiteMap
from ..http.client import HttpResponse
from .base import ScanContext, Scanner, register

__all__ = ["SecurityHeadersScanner"]


@register
class SecurityHeadersScanner(Scanner):
    """Checks security-relevant response headers on the target's base page."""

    name = "headers"
    description = "Missing or weak security response headers and cookie flags."

    def scan(self, context: ScanContext) -> list[ScanResult]:
        page = self._representative_page(context.site_map)
        if page is None:
            return []

        response = self._response_for(page.url, context)
        if response is None:
            return []

        findings: list[ScanResult] = []
        findings.extend(self._check_hsts(response))
        findings.extend(self._check_csp(response))
        findings.extend(self._check_frame_options(response))
        findings.extend(self._check_content_type_options(response))
        findings.extend(self._check_referrer_policy(response))
        findings.extend(self._check_cookies(response))
        return findings

    @staticmethod
    def _representative_page(site_map: SiteMap):
        html_pages = [p for p in site_map.pages if p.content_type == "text/html"]
        pages = html_pages or site_map.pages
        return pages[0] if pages else None

    def _response_for(self, url: str, context: ScanContext) -> HttpResponse | None:
        try:
            return context.client.get(url)
        except (HttpError, ScopeError) as exc:
            self._log.warning("could not fetch headers for %s: %s", url, exc)
            return None

    def _finding(
        self,
        response: HttpResponse,
        *,
        vulnerability: str,
        severity: Severity,
        description: str,
        remediation: str,
        impact: str,
        rationale: str,
        evidence: str,
        confidence: Confidence = Confidence.HIGH,
    ) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            vulnerability=vulnerability,
            severity=severity,
            confidence=confidence,
            url=response.url,
            method=HttpMethod.GET,
            evidence=evidence,
            description=description,
            remediation=remediation,
            impact=impact,
            severity_rationale=rationale,
        )

    def _check_hsts(self, response: HttpResponse) -> list[ScanResult]:
        is_https = response.url.lower().startswith("https://")
        header = response.header("Strict-Transport-Security")
        if not is_https:
            # HSTS is only meaningful over TLS; reporting it on http is noise.
            return []
        if header:
            if "max-age=0" in header.replace(" ", "").lower():
                return [
                    self._finding(
                        response,
                        vulnerability="Weak Strict-Transport-Security (max-age=0)",
                        severity=Severity.LOW,
                        description="HSTS is present but disabled with max-age=0.",
                        remediation="Set a non-zero max-age, e.g. "
                        "'max-age=31536000; includeSubDomains'.",
                        impact="Browsers will not enforce HTTPS, leaving users "
                        "exposed to SSL-stripping downgrade attacks.",
                        rationale="LOW: TLS is already in use; this only weakens "
                        "downgrade protection.",
                        evidence=f"Strict-Transport-Security: {header}",
                    )
                ]
            return []
        return [
            self._finding(
                response,
                vulnerability="Missing Strict-Transport-Security header",
                severity=Severity.MEDIUM,
                description="The HTTPS response does not send an HSTS header.",
                remediation="Add 'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains'.",
                impact="A network attacker can strip TLS on the first request and "
                "downgrade the connection to plaintext.",
                rationale="MEDIUM: requires an active network position to exploit, "
                "but affects every user of the site.",
                evidence="No Strict-Transport-Security header in response.",
            )
        ]

    def _check_csp(self, response: HttpResponse) -> list[ScanResult]:
        header = response.header("Content-Security-Policy")
        if header:
            return []
        return [
            self._finding(
                response,
                vulnerability="Missing Content-Security-Policy header",
                severity=Severity.MEDIUM,
                description="No Content-Security-Policy header restricts resource "
                "loading or inline script execution.",
                remediation="Define a policy starting from 'default-src \\'self\\'' "
                "and tighten it per resource type.",
                impact="Removes a strong defence-in-depth control against XSS and "
                "data injection; it does not itself grant an attacker access.",
                rationale="MEDIUM: CSP is a mitigating control, so its absence is "
                "not directly exploitable but materially raises XSS impact.",
                evidence="No Content-Security-Policy header in response.",
            )
        ]

    def _check_frame_options(self, response: HttpResponse) -> list[ScanResult]:
        header = response.header("X-Frame-Options")
        csp = (response.header("Content-Security-Policy") or "").lower()
        if header or "frame-ancestors" in csp:
            return []
        return [
            self._finding(
                response,
                vulnerability="Missing clickjacking protection (X-Frame-Options)",
                severity=Severity.LOW,
                description="Neither X-Frame-Options nor a CSP frame-ancestors "
                "directive is set.",
                remediation="Send 'X-Frame-Options: DENY' or a CSP "
                "'frame-ancestors \\'none\\'' directive.",
                impact="The page can be embedded in a hostile frame and used for "
                "clickjacking.",
                rationale="LOW: exploitation needs user interaction and only affects "
                "framing-sensitive pages.",
                evidence="No X-Frame-Options header and no frame-ancestors directive.",
            )
        ]

    def _check_content_type_options(self, response: HttpResponse) -> list[ScanResult]:
        header = (response.header("X-Content-Type-Options") or "").strip().lower()
        if header == "nosniff":
            return []
        return [
            self._finding(
                response,
                vulnerability="Missing X-Content-Type-Options: nosniff",
                severity=Severity.LOW,
                description="Responses do not disable MIME-type sniffing.",
                remediation="Send 'X-Content-Type-Options: nosniff'.",
                impact="Browsers may interpret responses as a different content type, "
                "enabling some XSS and drive-by scenarios.",
                rationale="LOW: exploitation is narrow and browser-dependent.",
                evidence=f"X-Content-Type-Options: {header or 'absent'}",
            )
        ]

    def _check_referrer_policy(self, response: HttpResponse) -> list[ScanResult]:
        if response.header("Referrer-Policy"):
            return []
        return [
            self._finding(
                response,
                vulnerability="Missing Referrer-Policy header",
                severity=Severity.INFO,
                description="No Referrer-Policy header is set.",
                remediation="Send e.g. 'Referrer-Policy: strict-origin-when-cross-origin'.",
                impact="Full URLs (which may contain sensitive path/query data) can "
                "leak to third parties via the Referer header.",
                rationale="INFO: privacy hardening rather than a direct vulnerability.",
                evidence="No Referrer-Policy header in response.",
                confidence=Confidence.HIGH,
            )
        ]

    def _check_cookies(self, response: HttpResponse) -> list[ScanResult]:
        set_cookie = response.header("Set-Cookie")
        if not set_cookie:
            return []
        attributes = set_cookie.lower()
        is_https = response.url.lower().startswith("https://")
        findings: list[ScanResult] = []

        if "httponly" not in attributes:
            findings.append(
                self._finding(
                    response,
                    vulnerability="Cookie set without HttpOnly flag",
                    severity=Severity.LOW,
                    description="A Set-Cookie response omits the HttpOnly attribute.",
                    remediation="Add the HttpOnly attribute to session cookies.",
                    impact="If an XSS flaw exists, the cookie can be read from "
                    "JavaScript and exfiltrated.",
                    rationale="LOW: only exploitable in combination with an XSS flaw.",
                    evidence="Set-Cookie without HttpOnly (value redacted).",
                )
            )
        if is_https and "secure" not in attributes:
            findings.append(
                self._finding(
                    response,
                    vulnerability="Cookie set without Secure flag",
                    severity=Severity.LOW,
                    description="A cookie on an HTTPS response omits the Secure "
                    "attribute.",
                    remediation="Add the Secure attribute so the cookie is never sent "
                    "over plaintext.",
                    impact="The cookie may be transmitted over an unencrypted "
                    "connection and intercepted.",
                    rationale="LOW: needs a downgraded/plaintext request to exploit.",
                    evidence="Set-Cookie without Secure (value redacted).",
                )
            )
        return findings
