"""Tests for the scan event callbacks.

The point of these is that a front end cannot break a scan. Callbacks come
from outside the package, so the engine has to survive whatever they do.
"""

from __future__ import annotations

from datetime import UTC, datetime

from scanner.core.events import ScanEvents
from scanner.core.models import (
    Confidence,
    HttpExchange,
    HttpMethod,
    ScanResult,
    Severity,
)


def _exchange(seq: int = 1) -> HttpExchange:
    return HttpExchange(
        seq=seq,
        timestamp=datetime.now(UTC),
        method=HttpMethod.GET,
        url="http://127.0.0.1/",
        status_code=200,
        reason="OK",
        request_headers={},
        request_body={},
        response_headers={},
        response_body="",
        content_type="text/html",
        body_bytes=0,
        elapsed_seconds=0.0,
    )


def _finding() -> ScanResult:
    return ScanResult(
        scanner="xss",
        vulnerability="Reflected XSS",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        url="http://127.0.0.1/search",
        description="",
        remediation="",
        impact="",
        severity_rationale="",
    )


def test_no_callbacks_is_a_no_op() -> None:
    events = ScanEvents()
    events.emit_exchange(_exchange())
    events.emit_findings("xss", [_finding()])
    events.emit_phase("crawl", "starting")
    assert events.cancelled() is False


def test_callbacks_receive_their_arguments() -> None:
    seen: dict[str, object] = {}
    events = ScanEvents(
        on_exchange=lambda exchange: seen.update(exchange=exchange.seq),
        on_findings=lambda scanner, findings: seen.update(scanner=scanner, count=len(findings)),
        on_phase=lambda phase, detail: seen.update(phase=phase, detail=detail),
    )

    events.emit_exchange(_exchange(seq=7))
    events.emit_findings("sqli", [_finding(), _finding()])
    events.emit_phase("crawl", "starting")

    assert seen == {
        "exchange": 7,
        "scanner": "sqli",
        "count": 2,
        "phase": "crawl",
        "detail": "starting",
    }


def test_a_raising_callback_does_not_abort_the_scan() -> None:
    """A broken observer must not end a run that was authorised to continue."""

    def explode(*_args: object) -> None:
        raise RuntimeError("front end is on fire")

    events = ScanEvents(on_exchange=explode, on_findings=explode, on_phase=explode)

    events.emit_exchange(_exchange())
    events.emit_findings("xss", [_finding()])
    events.emit_phase("crawl", "starting")


def test_a_raising_should_cancel_is_read_as_not_cancelled() -> None:
    """Guessing "stop" from a broken control would abort an uncancelled run."""

    def explode() -> bool:
        raise RuntimeError("front end is on fire")

    assert ScanEvents(should_cancel=explode).cancelled() is False


def test_should_cancel_result_is_coerced_to_bool() -> None:
    assert ScanEvents(should_cancel=lambda: True).cancelled() is True
    assert ScanEvents(should_cancel=lambda: False).cancelled() is False
