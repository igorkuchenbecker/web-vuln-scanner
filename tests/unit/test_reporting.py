"""Tests for report generation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from scanner.core.models import (
    Confidence,
    HttpMethod,
    ScanReport,
    ScanResult,
    Severity,
    Target,
)
from scanner.reporting.html import render_html_report


def _report(findings: list[ScanResult]) -> ScanReport:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    return ScanReport(
        target=Target("http://x.test/", "x.test", "http"),
        started_at=start,
        finished_at=start + timedelta(seconds=2),
        pages_discovered=3,
        endpoints_discovered=2,
        forms_discovered=1,
        requests_sent=10,
        scanners_run=("xss", "headers"),
        findings=findings,
    )


def _finding(evidence: str = "ev", severity: Severity = Severity.HIGH) -> ScanResult:
    return ScanResult(
        scanner="xss",
        vulnerability="Potential Reflected XSS",
        severity=severity,
        confidence=Confidence.MEDIUM,
        url="http://x.test/s?q=1",
        method=HttpMethod.GET,
        parameter="q",
        evidence=evidence,
        description="desc",
        remediation="fix",
        impact="impact",
        severity_rationale="because",
    )


def test_html_report_contains_core_sections() -> None:
    html = render_html_report(_report([_finding()]))
    assert "Web Application Vulnerability Scan" in html
    assert "http://x.test/" in html
    assert "Potential Reflected XSS" in html
    assert "Executive summary" in html
    assert "Scanner limitations" in html


def test_html_report_escapes_evidence() -> None:
    html = render_html_report(_report([_finding(evidence="<script>alert(1)</script>")]))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_report_with_no_findings() -> None:
    html = render_html_report(_report([]))
    assert "No findings" in html


def test_severity_counts_sorted_high_first() -> None:
    report = _report([_finding(severity=Severity.LOW), _finding(severity=Severity.HIGH)])
    counts = list(report.severity_counts().items())
    assert counts[0][0] is Severity.CRITICAL  # highest rank first
    assert report.severity_counts()[Severity.HIGH] == 1
