"""Tests for the HTTP client's safety controls against the local app."""

from __future__ import annotations

import pytest

from scanner.core.config import ScanConfig
from scanner.core.exceptions import BudgetExceeded, ResponseTooLarge, ScopeError
from scanner.core.scope import Scope
from scanner.http.client import HttpClient
from scanner.http.session import RequestBudget
from tests.fixtures.vulnerable_app import VulnerableAppServer


@pytest.fixture()
def app():
    with VulnerableAppServer() as server:
        yield server


def _client(app: VulnerableAppServer, **overrides) -> HttpClient:
    config = ScanConfig(delay=0.0, **overrides)
    scope = Scope.from_target(app.base_url)
    return HttpClient(config, scope)


def test_get_returns_response(app: VulnerableAppServer) -> None:
    with _client(app) as client:
        response = client.get(app.base_url + "/")
        assert response.status_code == 200
        assert response.is_html
        assert "Vulnerable Test App" in response.body


def test_out_of_scope_request_is_refused(app: VulnerableAppServer) -> None:
    with _client(app) as client:
        with pytest.raises(ScopeError):
            client.get("http://evil.test/")


def test_budget_is_enforced(app: VulnerableAppServer) -> None:
    config = ScanConfig(delay=0.0, max_requests=2)
    scope = Scope.from_target(app.base_url)
    with HttpClient(config, scope, budget=RequestBudget(2)) as client:
        client.get(app.base_url + "/")
        client.get(app.base_url + "/")
        with pytest.raises(BudgetExceeded):
            client.get(app.base_url + "/")


def test_response_size_limit_rejects_oversized(app: VulnerableAppServer) -> None:
    # The app declares Content-Length, so an oversized body is refused up front
    # rather than partially read. The crawler treats this as a skipped page.
    with _client(app, max_response_bytes=10) as client:
        with pytest.raises(ResponseTooLarge):
            client.get(app.base_url + "/")


def test_response_within_limit_is_read(app: VulnerableAppServer) -> None:
    with _client(app, max_response_bytes=1024) as client:
        response = client.get(app.base_url + "/")
        assert not response.truncated
        assert "Vulnerable Test App" in response.body


def test_secrets_are_tracked_for_redaction(app: VulnerableAppServer) -> None:
    config = ScanConfig(delay=0.0, cookies={"session": "supersecret"})
    scope = Scope.from_target(app.base_url)
    with HttpClient(config, scope) as client:
        assert "supersecret" in client.secrets
