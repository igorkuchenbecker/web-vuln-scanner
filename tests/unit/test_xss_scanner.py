"""Tests for the reflected-XSS scanner."""

from __future__ import annotations

import html
from collections.abc import Mapping

from scanner.core.models import Endpoint, HttpMethod, Severity, SiteMap
from scanner.scanners.base import ScanContext
from scanner.scanners.xss import ReflectedXssScanner
from tests.unit.fake_client import FakeHttpClient, make_response


def _context(responder) -> ScanContext:
    site_map = SiteMap()
    site_map.add_endpoint(Endpoint("http://x.test/search?q=hi", HttpMethod.GET, ("q",)))
    return ScanContext(site_map, FakeHttpClient(responder))  # type: ignore[arg-type]


def _injected_value(url: str) -> str:
    from urllib.parse import parse_qs, urlsplit

    return parse_qs(urlsplit(url).query)["q"][0]


def test_unencoded_reflection_is_flagged() -> None:
    def responder(url: str, method: HttpMethod, data: Mapping[str, str]):
        value = _injected_value(url)
        return make_response(url, f"<p>You searched: {value}</p>")

    findings = ReflectedXssScanner().scan(_context(responder))
    assert len(findings) == 1
    assert findings[0].vulnerability == "Potential Reflected XSS"
    assert findings[0].severity is Severity.MEDIUM


def test_encoded_reflection_is_info_only() -> None:
    def responder(url: str, method: HttpMethod, data: Mapping[str, str]):
        value = _injected_value(url)
        return make_response(url, f"<p>You searched: {html.escape(value)}</p>")

    findings = ReflectedXssScanner().scan(_context(responder))
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO


def test_no_reflection_no_finding() -> None:
    def responder(url: str, method: HttpMethod, data: Mapping[str, str]):
        return make_response(url, "<p>static</p>")

    assert ReflectedXssScanner().scan(_context(responder)) == []


def test_script_context_is_high() -> None:
    def responder(url: str, method: HttpMethod, data: Mapping[str, str]):
        value = _injected_value(url)
        return make_response(url, f"<script>var q = {value};</script>")

    findings = ReflectedXssScanner().scan(_context(responder))
    assert findings[0].severity is Severity.HIGH


def test_non_html_response_ignored() -> None:
    def responder(url: str, method: HttpMethod, data: Mapping[str, str]):
        value = _injected_value(url)
        return make_response(
            url, f"reflected {value}", headers={"Content-Type": "application/json"}
        )

    assert ReflectedXssScanner().scan(_context(responder)) == []
