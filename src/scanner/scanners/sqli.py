"""Non-destructive SQL injection heuristics.

Two independent signals are used, and a finding is only raised when a signal
is corroborated:

* **Error-based** — a probe that injects a syntactically breaking quote elicits
  a database error string that a control request does not. The control step is
  what prevents flagging pages that always contain the word "error".

* **Boolean-based** — a always-true condition and an always-false condition are
  injected. A finding needs the true-page to closely resemble the baseline
  while the false-page differs *and* the two injected pages differ from each
  other. Requiring divergence between true and false is what stops ordinary
  dynamic pages (which differ on every request) from reading as injectable.

No data is ever extracted; probes are limited to breaking and boolean payloads.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

from ..core.models import (
    Confidence,
    Endpoint,
    ScanResult,
    Severity,
)
from ..utils.redaction import redact_text
from ._probing import Probe, send_probe
from .base import ScanContext, Scanner, register

__all__ = ["SqlInjectionScanner"]

# Vendor-agnostic error fingerprints. Kept deliberately specific so generic
# prose ("an error occurred") does not match.
_SQL_ERROR_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"you have an error in your sql syntax",
        r"warning:\s+mysqli?",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"pg_query\(\):",
        r"psql:.*error",
        r"sqlite3?\.(operational|programming)error",
        r"org\.hibernate\.exception",
        r"ora-\d{5}",
        r"microsoft ole db provider for sql server",
        r"odbc sql server driver",
        r"sqlstate\[",
    )
)

_BREAKING_PROBE = "'\""
_TRUE_PROBE = "' OR '1'='1"
_FALSE_PROBE = "' AND '1'='2"
_BASELINE_VALUE = "1"

# Boolean-based similarity thresholds.
_SIMILAR = 0.95  # true-page must look like the baseline
_DIVERGENT = 0.95  # false-page must look meaningfully different


@register
class SqlInjectionScanner(Scanner):
    """Error-based and boolean-based SQL injection detection."""

    name = "sqli"
    description = "Non-destructive error-based and boolean-based SQL injection checks."

    def scan(self, context: ScanContext) -> list[ScanResult]:
        """Return SQL-injection findings across every discovered parameter."""
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
        baseline = send_probe(context.client, endpoint, parameter, _BASELINE_VALUE)
        if baseline is None:
            return None

        error_finding = self._error_based(context, endpoint, parameter, baseline)
        if error_finding is not None:
            return error_finding
        return self._boolean_based(context, endpoint, parameter, baseline)

    def _error_based(
        self,
        context: ScanContext,
        endpoint: Endpoint,
        parameter: str,
        baseline: Probe,
    ) -> ScanResult | None:
        if self._matched_error(baseline.response.body) is not None:
            # Baseline already errors: we cannot attribute an error to our probe.
            return None

        probe = send_probe(context.client, endpoint, parameter, _BREAKING_PROBE)
        if probe is None:
            return None
        match = self._matched_error(probe.response.body)
        if match is None:
            return None

        evidence = redact_text(match, context.secrets)
        return self._build_finding(
            endpoint,
            parameter,
            confidence=Confidence.HIGH,
            technique="error-based",
            evidence=f"Database error triggered by breaking probe: {evidence!r}",
        )

    def _boolean_based(
        self,
        context: ScanContext,
        endpoint: Endpoint,
        parameter: str,
        baseline: Probe,
    ) -> ScanResult | None:
        true_probe = send_probe(context.client, endpoint, parameter, _TRUE_PROBE)
        false_probe = send_probe(context.client, endpoint, parameter, _FALSE_PROBE)
        if true_probe is None or false_probe is None:
            return None
        if true_probe.response.status_code >= 500 or false_probe.response.status_code >= 500:
            return None

        baseline_body = baseline.response.body
        true_body = true_probe.response.body
        false_body = false_probe.response.body

        true_vs_baseline = _similarity(baseline_body, true_body)
        false_vs_baseline = _similarity(baseline_body, false_body)
        true_vs_false = _similarity(true_body, false_body)

        looks_injectable = (
            true_vs_baseline >= _SIMILAR
            and false_vs_baseline < _DIVERGENT
            and true_vs_false < _DIVERGENT
        )
        if not looks_injectable:
            return None

        evidence = (
            "Boolean payloads produced diverging responses "
            f"(true~baseline={true_vs_baseline:.2f}, "
            f"false~baseline={false_vs_baseline:.2f}, "
            f"true~false={true_vs_false:.2f})."
        )
        return self._build_finding(
            endpoint,
            parameter,
            confidence=Confidence.MEDIUM,
            technique="boolean-based",
            evidence=evidence,
        )

    @staticmethod
    def _matched_error(body: str) -> str | None:
        for pattern in _SQL_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                return match.group(0)
        return None

    def _build_finding(
        self,
        endpoint: Endpoint,
        parameter: str,
        *,
        confidence: Confidence,
        technique: str,
        evidence: str,
    ) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            vulnerability="Potential SQL Injection",
            severity=Severity.HIGH,
            confidence=confidence,
            url=endpoint.url,
            method=endpoint.method,
            parameter=parameter,
            evidence=evidence,
            description=(
                f"Parameter {parameter!r} shows {technique} SQL injection behaviour. "
                "The scanner injects only breaking and boolean test payloads and "
                "never extracts data."
            ),
            remediation=(
                "Use parameterised queries / prepared statements, validate input "
                "types, and apply least-privilege database accounts."
            ),
            impact=(
                "SQL injection can allow reading or modifying arbitrary database "
                "records and, depending on privileges, full database compromise."
            ),
            severity_rationale=(
                "HIGH: injection into a database query is directly exploitable with "
                "severe impact. Confidence reflects how strong the evidence is: "
                "error-based is HIGH, boolean-based is MEDIUM because dynamic content "
                "can occasionally mimic the signal."
            ),
        )


def _similarity(left: str, right: str) -> float:
    """Return a 0..1 ratio of how similar two response bodies are."""
    if not left and not right:
        return 1.0
    return SequenceMatcher(a=left, b=right).ratio()
