"""End-to-end scan against the deliberately vulnerable local app.

These tests prove the whole pipeline (crawl -> scan -> report) works and that
the detectors fire on real, known flaws while leaving the safe endpoint alone.
"""

from __future__ import annotations

import pytest

from scanner.core.config import ScanConfig
from scanner.core.engine import ScanEngine
from scanner.core.models import Severity
from scanner.reporting.html import render_html_report
from tests.fixtures.vulnerable_app import VulnerableAppServer


@pytest.fixture()
def report():
    with VulnerableAppServer() as app:
        config = ScanConfig(delay=0.0, max_depth=2, max_pages=30, verify_tls=True)
        yield ScanEngine(config).run(app.base_url)


def test_crawler_discovers_pages_and_forms(report) -> None:
    assert report.pages_discovered >= 4
    assert report.forms_discovered >= 1
    assert report.endpoints_discovered >= 2


def test_reflected_xss_detected(report) -> None:
    xss = [f for f in report.findings if f.scanner == "xss" and f.severity.rank > 0]
    assert any("/search" in f.url for f in xss)


def test_safe_endpoint_not_flagged_as_vulnerable(report) -> None:
    vulnerable_xss = [
        f
        for f in report.findings
        if f.scanner == "xss" and "/safe" in f.url and f.severity.rank > 0
    ]
    assert vulnerable_xss == []


def test_sql_injection_detected(report) -> None:
    sqli = [f for f in report.findings if f.scanner == "sqli"]
    assert any("/item" in f.url for f in sqli)
    assert all(f.severity is Severity.HIGH for f in sqli)


def test_security_headers_reported(report) -> None:
    headers = [f for f in report.findings if f.scanner == "headers"]
    assert any("Content-Security-Policy" in f.vulnerability for f in headers)


def test_auth_surface_discovered(report) -> None:
    auth = [f for f in report.findings if f.scanner == "auth-surface"]
    assert auth  # login form and/or /login path
    assert all(f.severity is Severity.INFO for f in auth)


def test_html_report_renders(report) -> None:
    html = render_html_report(report)
    assert "<html" in html.lower()
    assert report.target.host in html


def test_request_budget_respected(report) -> None:
    assert report.requests_sent <= ScanConfig().max_requests
