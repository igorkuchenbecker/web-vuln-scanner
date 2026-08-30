"""Tests for the SQL injection scanner's detection logic."""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import unquote_plus

from scanner.core.models import Endpoint, HttpMethod, SiteMap
from scanner.scanners.base import ScanContext
from scanner.scanners.sqli import SqlInjectionScanner
from tests.unit.fake_client import FakeHttpClient, make_response


def _context_with_endpoint(responder) -> ScanContext:
    site_map = SiteMap()
    site_map.add_endpoint(Endpoint("http://x.test/item?id=1", HttpMethod.GET, ("id",)))
    return ScanContext(site_map, FakeHttpClient(responder))  # type: ignore[arg-type]


def test_error_based_detection() -> None:
    def responder(url: str, method: HttpMethod, data: Mapping[str, str]):
        decoded = unquote_plus(url)
        if "'\"" in decoded:  # the breaking probe
            return make_response(url, "You have an error in your SQL syntax near ...")
        return make_response(url, "<html>item 1</html>")

    findings = SqlInjectionScanner().scan(_context_with_endpoint(responder))
    assert len(findings) == 1
    assert findings[0].confidence.label == "high"
    assert "error-based" in findings[0].description


def test_boolean_based_detection() -> None:
    baseline = "<html>" + "row " * 200 + "</html>"

    def responder(url: str, method: HttpMethod, data: Mapping[str, str]):
        decoded = unquote_plus(url).upper()
        if "AND '1'='2".upper() in decoded:
            return make_response(url, "<html>no rows</html>")  # false differs
        # baseline and true-condition both return the full listing
        return make_response(url, baseline)

    findings = SqlInjectionScanner().scan(_context_with_endpoint(responder))
    assert len(findings) == 1
    assert findings[0].confidence.label == "medium"
    assert "boolean-based" in findings[0].description


def test_no_false_positive_on_static_page() -> None:
    def responder(url: str, method: HttpMethod, data: Mapping[str, str]):
        return make_response(url, "<html>always identical</html>")

    assert SqlInjectionScanner().scan(_context_with_endpoint(responder)) == []


def test_no_finding_when_baseline_already_errors() -> None:
    def responder(url: str, method: HttpMethod, data: Mapping[str, str]):
        return make_response(url, "You have an error in your SQL syntax")

    # Baseline already contains the error string, so error-based must not fire.
    assert SqlInjectionScanner().scan(_context_with_endpoint(responder)) == []
