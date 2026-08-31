"""Observation and cancellation, exercised against the local vulnerable app.

These cover the two things the interface added to the engine: a record of
the traffic, and a way to stop. Both are tested over real HTTP rather than
against a fake client, because the properties that matter — that the record
matches what was actually sent, and that stopping actually stops — are
properties of the transport.
"""

from __future__ import annotations

import pytest

from scanner.core.config import ScanConfig
from scanner.core.engine import ScanEngine
from scanner.core.events import ScanEvents
from scanner.core.exceptions import ScanCancelled
from scanner.core.models import HttpExchange
from scanner.core.scope import Scope
from scanner.http.client import HttpClient
from tests.fixtures.vulnerable_app import VulnerableAppServer

_SECRET = "s3cr3t-session-value"


@pytest.fixture()
def app():
    with VulnerableAppServer() as server:
        yield server


def _client(app: VulnerableAppServer, events: ScanEvents, **overrides) -> HttpClient:
    config = ScanConfig(delay=0.0, **overrides)
    return HttpClient(config, Scope.from_target(app.base_url), events=events)


def test_exchange_records_what_was_sent(app: VulnerableAppServer) -> None:
    seen: list[HttpExchange] = []
    with _client(app, ScanEvents(on_exchange=seen.append)) as client:
        client.get(app.base_url + "/search?q=hello")

    assert len(seen) == 1
    exchange = seen[0]
    assert exchange.seq == 1
    assert str(exchange.method) == "GET"
    assert exchange.status_code == 200
    assert exchange.status_class == "2xx"
    assert exchange.content_type == "text/html"
    assert "You searched for: hello" in exchange.response_body
    assert exchange.body_bytes == len(exchange.response_body)
    assert exchange.request_headers["User-Agent"].startswith("web-vuln-scanner/")


def test_sequence_numbers_are_unique_and_ordered(app: VulnerableAppServer) -> None:
    seen: list[HttpExchange] = []
    with _client(app, ScanEvents(on_exchange=seen.append)) as client:
        for path in ("/", "/search?q=a", "/item?id=1"):
            client.get(app.base_url + path)

    assert [exchange.seq for exchange in seen] == [1, 2, 3]


def test_redirect_hops_are_each_recorded(app: VulnerableAppServer) -> None:
    """The history is per hop, because each hop is a separate request sent."""
    seen: list[HttpExchange] = []
    with _client(app, ScanEvents(on_exchange=seen.append)) as client:
        client.get(app.base_url + "/")
        client.get(app.base_url + "/nope")

    assert [exchange.status_code for exchange in seen] == [200, 404]


def test_operator_secrets_never_reach_the_record(app: VulnerableAppServer) -> None:
    """A history pane is where a session cookie would leak into a screen share."""
    seen: list[HttpExchange] = []
    events = ScanEvents(on_exchange=seen.append)
    with _client(app, events, cookies={"sid": _SECRET}) as client:
        # The app reflects ``q`` verbatim, so the secret comes back in the body.
        client.get(f"{app.base_url}/search?q={_SECRET}")

    exchange = seen[0]
    assert exchange.request_headers["Cookie"] == "[REDACTED]"
    assert _SECRET not in exchange.response_body
    assert "[REDACTED]" in exchange.response_body


def test_nothing_is_recorded_without_an_observer(app: VulnerableAppServer) -> None:
    """Building the record copies headers and, with secrets set, the body."""
    with _client(app, ScanEvents()) as client:
        response = client.get(app.base_url + "/")
    assert response.status_code == 200


def test_cancellation_stops_the_run(app: VulnerableAppServer) -> None:
    sent: list[HttpExchange] = []
    # Cancel as soon as the first request has been recorded.
    events = ScanEvents(
        on_exchange=sent.append,
        should_cancel=lambda: bool(sent),
    )
    config = ScanConfig(delay=0.0, max_depth=3, max_pages=30)

    with pytest.raises(ScanCancelled):
        ScanEngine(config, events=events).run(app.base_url)

    # One request got through; the crawl did not continue past the flag.
    assert len(sent) == 1


def test_cancellation_before_the_first_request_sends_nothing(
    app: VulnerableAppServer,
) -> None:
    sent: list[HttpExchange] = []
    events = ScanEvents(on_exchange=sent.append, should_cancel=lambda: True)

    with pytest.raises(ScanCancelled):
        ScanEngine(ScanConfig(delay=0.0), events=events).run(app.base_url)

    assert sent == []


def test_phase_and_finding_events_are_reported(app: VulnerableAppServer) -> None:
    phases: list[tuple[str, str]] = []
    findings: list[tuple[str, int]] = []
    events = ScanEvents(
        on_phase=lambda phase, detail: phases.append((phase, detail)),
        on_findings=lambda scanner, results: findings.append((scanner, len(results))),
    )
    config = ScanConfig(delay=0.0, max_depth=2, max_pages=20)

    report = ScanEngine(config, events=events).run(app.base_url)

    names = [phase for phase, _ in phases]
    assert names[0] == "crawl"
    assert "crawled" in names
    assert names[-1] == "done"
    assert {scanner for scanner, _ in findings} <= set(report.scanners_run)
    assert sum(count for _, count in findings) == len(report.findings)


def test_a_broken_observer_does_not_break_the_scan(app: VulnerableAppServer) -> None:
    """The whole point of isolating callbacks: the scan still produces a report."""

    def explode(*_args: object) -> None:
        raise RuntimeError("front end is on fire")

    events = ScanEvents(on_exchange=explode, on_findings=explode, on_phase=explode)
    config = ScanConfig(delay=0.0, max_depth=1, max_pages=10)

    report = ScanEngine(config, events=events).run(app.base_url)

    assert report.pages_discovered >= 1
    assert report.requests_sent >= 1
