"""Tests for the scan session's buffering and bounds.

The session is the boundary between the scanning thread and the UI thread,
so the properties worth asserting are the ones that fail badly in production
and quietly in a demo: the buffers stay bounded, nothing is lost silently,
and a drain hands over each event exactly once.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from scanner.core.config import ScanConfig
from scanner.core.models import (
    Confidence,
    HttpExchange,
    HttpMethod,
    ScanResult,
    Severity,
)
from scanner.tui.session import ScanSession, SessionState


@pytest.fixture()
def session() -> ScanSession:
    return ScanSession(
        ScanConfig(delay=0.0),
        "http://127.0.0.1:8000",
        history_limit=5,
        body_chars=10,
    )


def _exchange(seq: int, body: str = "") -> HttpExchange:
    return HttpExchange(
        seq=seq,
        timestamp=datetime.now(UTC),
        method=HttpMethod.GET,
        url=f"http://127.0.0.1:8000/page/{seq}",
        status_code=200,
        reason="OK",
        request_headers={"User-Agent": "test"},
        request_body={},
        response_headers={"Content-Type": "text/html"},
        response_body=body,
        content_type="text/html",
        body_bytes=len(body),
        elapsed_seconds=0.01,
    )


def _finding(severity: Severity = Severity.HIGH) -> ScanResult:
    return ScanResult(
        scanner="xss",
        vulnerability="Reflected XSS",
        severity=severity,
        confidence=Confidence.MEDIUM,
        url="http://127.0.0.1:8000/search",
        description="",
        remediation="",
        impact="",
        severity_rationale="",
    )


def test_starts_idle(session: ScanSession) -> None:
    assert session.state is SessionState.IDLE
    assert session.report is None
    assert session.findings == []
    assert session.elapsed_seconds == 0.0


def test_drain_hands_over_each_event_once(session: ScanSession) -> None:
    events = session.build_events()
    events.emit_exchange(_exchange(1))
    events.emit_findings("xss", [_finding()])
    events.emit_phase("crawl", "starting")

    drained = session.drain()
    assert [entry.seq for entry in drained.exchanges] == [1]
    assert len(drained.findings) == 1
    assert [phase.phase for phase in drained.phases] == ["crawl"]

    assert not session.drain()


def test_history_stops_recording_at_the_limit_and_counts_the_rest(
    session: ScanSession,
) -> None:
    """Requests past the cap still happened; the count must say so."""
    events = session.build_events()
    for seq in range(1, 9):
        events.emit_exchange(_exchange(seq))

    assert len(session.history) == 5
    assert session.not_recorded == 3
    assert [entry.seq for entry in session.history] == [1, 2, 3, 4, 5]


def test_body_is_clipped_for_display_and_says_so(session: ScanSession) -> None:
    session.build_events().emit_exchange(_exchange(1, body="x" * 50))
    entry = session.entry(1)

    assert entry is not None
    assert len(entry.body) == 10
    assert entry.body_clipped is True
    # The transport did not truncate anything; only the viewer did. Conflating
    # the two would misreport what the scanner actually fetched.
    assert entry.exchange.truncated is False
    assert entry.exchange.body_bytes == 50


def test_short_body_is_not_marked_clipped(session: ScanSession) -> None:
    session.build_events().emit_exchange(_exchange(1, body="short"))
    entry = session.entry(1)

    assert entry is not None
    assert entry.body == "short"
    assert entry.body_clipped is False


def test_empty_findings_are_not_buffered(session: ScanSession) -> None:
    session.build_events().emit_findings("headers", [])
    assert not session.drain()
    assert session.findings == []


def test_cancel_is_visible_to_the_engine(session: ScanSession) -> None:
    events = session.build_events()
    assert events.cancelled() is False

    session.cancel()

    assert session.cancel_requested is True
    assert events.cancelled() is True


def test_entry_lookup_misses_return_none(session: ScanSession) -> None:
    assert session.entry(99) is None
