"""Tests for authentication-surface discovery."""

from __future__ import annotations

from scanner.core.models import Form, FormField, HttpMethod, Page, Severity, SiteMap
from scanner.scanners.auth_surface import AuthSurfaceScanner
from scanner.scanners.base import ScanContext
from tests.unit.fake_client import FakeHttpClient, make_response


def _context(site_map: SiteMap) -> ScanContext:
    return ScanContext(site_map, FakeHttpClient(lambda u, m, d: make_response(u)))  # type: ignore[arg-type]


def test_login_form_is_discovered() -> None:
    site_map = SiteMap()
    site_map.forms.append(
        Form(
            action="http://x.test/login",
            method=HttpMethod.POST,
            fields=(FormField("username", "text"), FormField("password", "password")),
            source_url="http://x.test/login",
        )
    )
    findings = AuthSurfaceScanner().scan(_context(site_map))
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO
    assert "login form" in findings[0].vulnerability


def test_login_path_is_discovered() -> None:
    site_map = SiteMap()
    site_map.pages.append(
        Page("http://x.test/signin", 200, {}, "text/html", "<html>", 0)
    )
    findings = AuthSurfaceScanner().scan(_context(site_map))
    assert any("URL pattern" in f.vulnerability for f in findings)
    assert all(f.severity is Severity.INFO for f in findings)


def test_ordinary_form_is_not_auth() -> None:
    site_map = SiteMap()
    site_map.forms.append(
        Form(
            action="http://x.test/search",
            method=HttpMethod.GET,
            fields=(FormField("q", "text"),),
            source_url="http://x.test/",
        )
    )
    assert AuthSurfaceScanner().scan(_context(site_map)) == []
