"""Reflected XSS detection with context awareness.

The scanner injects a unique, unlikely marker and inspects how (and whether)
it is reflected. It deliberately distinguishes three outcomes, because calling
every reflection an "XSS" is the single biggest source of false positives in
naive scanners:

* **reflection detected** — the marker appears, but HTML-encoded. Not a finding
  on its own; reported as INFO only when it lands in a dangerous sink.
* **potential XSS** — the marker is reflected *unencoded* inside an HTML context
  where it could break out (element text, an unquoted/quoted attribute, or a
  script block). This is the MEDIUM/HIGH finding.
* **confirmed XSS** — genuine confirmation needs a real browser to execute the
  script. The scanner cannot do that, so it never claims execution; the
  limitation is stated on every finding and in the report.
"""

from __future__ import annotations

import html
import re
import secrets as _secrets

from ..core.models import (
    Confidence,
    Endpoint,
    ScanResult,
    Severity,
)
from ..utils.redaction import redact_text
from ._probing import send_probe
from .base import ScanContext, Scanner, register

__all__ = ["ReflectedXssScanner"]

# An alphanumeric marker: reflected verbatim in any context, and cannot itself
# be mistaken for HTML, so its raw presence is unambiguous.
_MARKER_PREFIX = "xssprobe"
# The active payload carries characters that must be encoded in safe output.
_BREAKOUT_CHARS = "<>\"'"


@register
class ReflectedXssScanner(Scanner):
    """Detects reflected, unencoded parameter values in HTML responses."""

    name = "xss"
    description = "Reflected cross-site scripting via unencoded parameter reflection."

    def scan(self, context: ScanContext) -> list[ScanResult]:
        """Return reflected-XSS findings across every discovered parameter."""
        findings: list[ScanResult] = []
        for endpoint in context.site_map.endpoints:
            for parameter in endpoint.params:
                finding = self._test_parameter(context, endpoint, parameter)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _test_parameter(
        self, context: ScanContext, endpoint: Endpoint, parameter: str
    ) -> ScanResult | None:
        marker = f"{_MARKER_PREFIX}{_secrets.token_hex(6)}"
        payload = f"{marker}{_BREAKOUT_CHARS}"

        probe = send_probe(context.client, endpoint, parameter, payload)
        if probe is None or not probe.response.is_html:
            return None

        body = probe.response.body
        if marker not in body:
            return None  # not reflected at all

        raw_hit = f"{marker}{_BREAKOUT_CHARS}" in body
        encoded_hit = f"{marker}{html.escape(_BREAKOUT_CHARS, quote=True)}" in body

        if not raw_hit:
            if encoded_hit:
                return self._encoded_reflection(endpoint, parameter, marker)
            return None  # reflected but neutralised in some other way

        context_label = self._reflection_context(body, marker)
        return self._unencoded_reflection(
            endpoint, parameter, marker, context_label, context.secrets, body
        )

    def _reflection_context(self, body: str, marker: str) -> str:
        """Classify where the marker landed, to justify severity."""
        index = body.find(marker)
        window = body[max(0, index - 120) : index]
        lowered = window.lower()

        last_script_open = lowered.rfind("<script")
        last_script_close = lowered.rfind("</script")
        if last_script_open > last_script_close:
            return "script block"

        last_lt = window.rfind("<")
        last_gt = window.rfind(">")
        if last_lt > last_gt:
            return "attribute"
        return "HTML text"

    def _unencoded_reflection(
        self,
        endpoint: Endpoint,
        parameter: str,
        marker: str,
        context_label: str,
        run_secrets: tuple[str, ...],
        body: str,
    ) -> ScanResult:
        severity = Severity.HIGH if context_label == "script block" else Severity.MEDIUM
        snippet = self._snippet(body, marker, run_secrets)
        return ScanResult(
            scanner=self.name,
            vulnerability="Potential Reflected XSS",
            severity=severity,
            confidence=Confidence.MEDIUM,
            url=endpoint.url,
            method=endpoint.method,
            parameter=parameter,
            evidence=(
                f"Injected characters {_BREAKOUT_CHARS!r} were reflected unencoded in "
                f"a {context_label} context. Reflected snippet: {snippet!r}"
            ),
            description=(
                f"Parameter {parameter!r} is reflected without output encoding, so "
                "the special characters needed to inject markup survive intact. "
                "Confirmation of script execution requires a browser, which this "
                "scanner does not use."
            ),
            remediation=(
                "Context-aware output encoding (HTML-encode by default), validate "
                "input, and deploy a restrictive Content-Security-Policy."
            ),
            impact=(
                "Reflected XSS lets an attacker run script in a victim's session: "
                "session theft, action forgery and credential phishing."
            ),
            severity_rationale=(
                f"{severity.label.upper()}: unencoded reflection in a {context_label} "
                "context is a strong indicator of exploitability; script-block "
                "context is rated higher because breakout is trivial. Confidence is "
                "MEDIUM because execution was not browser-confirmed."
            ),
        )

    def _encoded_reflection(self, endpoint: Endpoint, parameter: str, marker: str) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            vulnerability="Parameter reflection (output encoded)",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            url=endpoint.url,
            method=endpoint.method,
            parameter=parameter,
            evidence="Marker reflected but special characters were HTML-encoded.",
            description=(
                f"Parameter {parameter!r} is reflected but its special characters are "
                "correctly encoded. This is informational: the application appears to "
                "encode output here."
            ),
            remediation=(
                "No action required for this parameter if encoding is applied "
                "consistently across all output contexts."
            ),
            impact=("None observed: the reflection is neutralised by output encoding."),
            severity_rationale=(
                "INFO: encoded reflection is not exploitable but is worth noting as "
                "surface where encoding must not regress."
            ),
        )

    @staticmethod
    def _snippet(body: str, marker: str, run_secrets: tuple[str, ...]) -> str:
        index = body.find(marker)
        raw = body[max(0, index - 30) : index + len(marker) + 30]
        collapsed = re.sub(r"\s+", " ", raw).strip()
        return redact_text(collapsed, run_secrets)
