"""Tests for the security-headers scanner."""

from __future__ import annotations

from scanner.core.models import Page, Severity, SiteMap
from scanner.scanners.base import ScanContext
from scanner.scanners.security_headers import SecurityHeadersScanner
from tests.unit.fake_client import FakeHttpClient, make_response


def _context(url: str, headers: dict[str, str]) -> ScanContext:
    site_map = SiteMap()
    site_map.pages.append(
        Page(
            url=url,
            status_code=200,
            headers=headers,
            content_type="text/html",
            body="<html>",
            depth=0,
        )
    )
    client = FakeHttpClient(lambda u, m, d: make_response(u, "<html>", headers=headers))
    return ScanContext(site_map, client)  # type: ignore[arg-type]


def test_flags_missing_headers_on_https() -> None:
    context = _context("https://example.test/", {"Content-Type": "text/html"})
    findings = {f.vulnerability for f in SecurityHeadersScanner().scan(context)}
    assert any("Strict-Transport-Security" in v for v in findings)
    assert any("Content-Security-Policy" in v for v in findings)
    assert any("X-Frame-Options" in v for v in findings)


def test_no_findings_when_headers_present() -> None:
    headers = {
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    context = _context("https://example.test/", headers)
    assert SecurityHeadersScanner().scan(context) == []


def test_hsts_not_reported_on_http() -> None:
    context = _context("http://example.test/", {"Content-Type": "text/html"})
    findings = {f.vulnerability for f in SecurityHeadersScanner().scan(context)}
    assert not any("Strict-Transport-Security" in v for v in findings)


def test_missing_csp_is_medium_not_high() -> None:
    context = _context("https://example.test/", {"Content-Type": "text/html"})
    csp = next(
        f
        for f in SecurityHeadersScanner().scan(context)
        if "Content-Security-Policy" in f.vulnerability
    )
    assert csp.severity is Severity.MEDIUM
