"""The terminal interface driven end to end against the local vulnerable app.

These run the real app object through Textual's headless pilot, not a mock of
it, because the defects this interface has actually had were not logic errors:
a timer that outlived the widgets, and a worker thread that outlived the
window. Neither is visible to a test that only calls methods.

``asyncio.run`` is used directly rather than adding an async test plugin: the
suite has five async tests and no other need for one.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TypeVar
from urllib.parse import urlsplit

import pytest
from textual.widgets import Button, Checkbox, DataTable, Input, Static, Tree

from scanner.core.models import Severity
from scanner.tui.app import ScannerTUI
from scanner.tui.session import SessionState
from tests.fixtures.vulnerable_app import VulnerableAppServer

_T = TypeVar("_T")

#: Ceiling on how long a test waits for a scan of the local app. A full scan
#: of it takes well under a second, so this is a large margin for a loaded CI
#: box and still small enough that a stalled interface fails the test quickly
#: instead of looking like a hung suite.
_TIMEOUT_SECONDS = 20.0
_POLL = 0.02


@pytest.fixture()
def app():
    with VulnerableAppServer() as server:
        yield server


def _run(coro_factory: Callable[[], Awaitable[_T]]) -> _T:
    return asyncio.run(coro_factory())


async def _await_terminal(app_under_test: ScannerTUI, pilot) -> SessionState:
    """Pump the UI until it has finished reacting to the end of the scan.

    The wait is on the interface catching up, not on the worker thread
    stopping. Those are different moments: the session goes terminal the
    instant the thread returns, while the panes only match it after the next
    drain. Asserting on the earlier moment makes every table assertion a race
    that passes alone and fails in a full suite run.
    """
    waited = 0.0
    while waited < _TIMEOUT_SECONDS:
        await pilot.pause()
        state = app_under_test._last_state
        if state is not None and state.is_terminal:
            return state
        await asyncio.sleep(_POLL)
        waited += _POLL
    raise AssertionError("scan did not finish within the timeout")


def _text(widget: Static) -> str:
    content = getattr(widget, "_content", None)
    return str(content) if content is not None else str(widget.render())


@pytest.mark.parametrize("size", [(80, 24), (100, 30), (150, 48), (220, 60)])
def test_every_control_is_actually_on_screen(size) -> None:
    """A layout bug this interface shipped with, and its whole class.

    An Input defaults to the full width of its container, so inside a row it
    takes everything and lays its siblings out past the right edge. Those
    buttons are still in the DOM, so a query finds them and a test that only
    queries passes while the operator cannot see them. Checking geometry is
    what catches it.
    """

    async def scenario() -> None:
        tui = ScannerTUI(target="http://127.0.0.1:8000")
        async with tui.run_test(size=size) as pilot:
            await pilot.pause()
            width, height = tui.size.width, tui.size.height
            offscreen = [
                (widget.__class__.__name__, widget.id, str(widget.region))
                for widget in (*tui.query(Input), *tui.query(Button), *tui.query(Checkbox))
                if widget.region.x < 0
                or widget.region.right > width
                or widget.region.y < 0
                or widget.region.bottom > height
            ]
            assert offscreen == []

    _run(scenario)


def test_a_scan_populates_every_pane(app: VulnerableAppServer) -> None:
    async def scenario() -> None:
        tui = ScannerTUI(target=app.base_url)
        async with tui.run_test(size=(150, 48)) as pilot:
            tui.query_one("#delay", Input).value = "0"
            tui.action_start_scan()
            state = await _await_terminal(tui, pilot)

            assert state is SessionState.COMPLETED
            session = tui._session
            assert session is not None and session.report is not None

            history = tui.query_one("#history-table", DataTable)
            findings = tui.query_one("#findings-table", DataTable)
            assert history.row_count == len(session.history)
            assert findings.row_count == len(session.findings)
            assert findings.row_count > 0

            # The known flaws in the bundled app must show up.
            labels = {f.vulnerability for f in session.findings}
            assert any("XSS" in label for label in labels)
            assert any("SQL" in label for label in labels)

            assert tui.query_one("#export", Button).disabled is False
            assert "requests sent" in _text(tui.query_one("#run-stats", Static))

    _run(scenario)


def test_selecting_rows_renders_request_response_and_evidence(
    app: VulnerableAppServer,
) -> None:
    async def scenario() -> None:
        tui = ScannerTUI(target=app.base_url)
        async with tui.run_test(size=(150, 48)) as pilot:
            tui.query_one("#delay", Input).value = "0"
            tui.action_start_scan()
            await _await_terminal(tui, pilot)

            tui.query_one("#history-table", DataTable).move_cursor(row=0)
            await pilot.pause()
            detail = _text(tui.query_one("#history-detail", Static))
            assert "REQUEST" in detail
            assert "RESPONSE" in detail
            assert "User-Agent" in detail

            tui.query_one("#findings-table", DataTable).move_cursor(row=0)
            await pilot.pause()
            evidence = _text(tui.query_one("#finding-detail", Static))
            assert "DESCRIPTION" in evidence
            assert "REMEDIATION" in evidence
            assert "WHY THIS SEVERITY" in evidence

    _run(scenario)


def test_the_site_tree_is_browsable_and_resolves_every_path(
    app: VulnerableAppServer,
) -> None:
    """Two defects that only a rendered screen showed.

    The tree filled up behind a collapsed root, so a finished scan looked like
    a scan that found nothing; and the site root was keyed as ``//`` because
    ``/`` was walked as if it were a path segment, so selecting it reported no
    exchanges for the one URL every crawl starts from.
    """

    async def scenario() -> None:
        tui = ScannerTUI(target=app.base_url)
        async with tui.run_test(size=(150, 48)) as pilot:
            tui.query_one("#delay", Input).value = "0"
            tui.action_start_scan()
            await _await_terminal(tui, pilot)

            tree = tui.query_one("#site-tree", Tree)
            assert tree.root.is_expanded
            assert len(tree.root.children) > 0

            # Every node's key must be a path some exchange actually has,
            # otherwise selecting it can only ever say "nothing recorded".
            session = tui._session
            assert session is not None
            recorded = {urlsplit(e.exchange.url).path for e in session.history}
            keys = set(tui._tree_nodes)
            assert "/" in keys, "the site root needs its own selectable node"
            assert keys <= recorded, f"nodes with no matching exchange: {keys - recorded}"

            for path in ("/", "/search"):
                node = tui._tree_nodes[path]
                tree.select_node(node)
                await pilot.pause()
                detail = _text(tui.query_one("#target-detail", Static))
                assert "No exchange recorded" not in detail
                assert path in detail

    _run(scenario)


def test_severity_filter_narrows_the_findings_table(app: VulnerableAppServer) -> None:
    async def scenario() -> None:
        tui = ScannerTUI(target=app.base_url)
        async with tui.run_test(size=(150, 48)) as pilot:
            tui.query_one("#delay", Input).value = "0"
            tui.action_start_scan()
            await _await_terminal(tui, pilot)

            table = tui.query_one("#findings-table", DataTable)
            total = table.row_count

            tui._filter = Severity.INFO
            tui._rebuild_findings_table()
            await pilot.pause()
            info_only = table.row_count
            expected = sum(1 for f in tui._findings if f.severity is Severity.INFO)

            assert info_only == expected
            assert info_only < total

            # Cycling comes back round to the unfiltered view, which is the
            # only way back with a single key.
            for _ in range(len(Severity) + 1):
                tui.action_cycle_filter()
                if tui._filter is None:
                    break
            await pilot.pause()
            assert tui._filter is None
            assert table.row_count == total

    _run(scenario)


def test_export_writes_a_report(app: VulnerableAppServer, tmp_path: Path) -> None:
    async def scenario() -> None:
        tui = ScannerTUI(target=app.base_url)
        async with tui.run_test(size=(150, 48)) as pilot:
            tui.query_one("#delay", Input).value = "0"
            tui.action_start_scan()
            await _await_terminal(tui, pilot)
            tui.action_export_report()
            await pilot.pause()

    cwd = Path.cwd()
    import os

    os.chdir(tmp_path)
    try:
        _run(scenario)
    finally:
        os.chdir(cwd)

    written = list(tmp_path.glob("scan-*.html"))
    assert len(written) == 1
    assert "web-vuln-scanner" in written[0].read_text(encoding="utf-8").lower()


def test_export_refuses_when_there_is_no_completed_report(
    app: VulnerableAppServer, tmp_path: Path
) -> None:
    """A cancelled run has no report, and must not produce one that looks whole."""

    async def scenario() -> None:
        tui = ScannerTUI(target=app.base_url)
        async with tui.run_test(size=(150, 48)) as pilot:
            tui.action_export_report()
            await pilot.pause()
            assert tui.query_one("#export", Button).disabled is True

    cwd = Path.cwd()
    import os

    os.chdir(tmp_path)
    try:
        _run(scenario)
    finally:
        os.chdir(cwd)

    assert list(tmp_path.glob("scan-*.html")) == []


def test_cancelling_stops_the_run_and_keeps_what_it_found(
    app: VulnerableAppServer,
) -> None:
    async def scenario() -> None:
        tui = ScannerTUI(target=app.base_url)
        async with tui.run_test(size=(150, 48)) as pilot:
            # Pace the scan so there is a run to cancel.
            tui.query_one("#delay", Input).value = "0.2"
            tui.action_start_scan()

            waited = 0.0
            while waited < _TIMEOUT_SECONDS:
                await pilot.pause()
                if tui._session and tui._session.history:
                    break
                await asyncio.sleep(_POLL)
                waited += _POLL

            tui.action_cancel_scan()
            state = await _await_terminal(tui, pilot)

            assert state is SessionState.CANCELLED
            session = tui._session
            assert session is not None
            assert session.report is None
            # Whatever it reached is still on screen, and still labelled.
            assert tui.query_one("#history-table", DataTable).row_count > 0
            assert tui.query_one("#export", Button).disabled is True

    _run(scenario)


def test_quitting_mid_scan_neither_crashes_nor_leaves_the_scan_running(
    app: VulnerableAppServer,
) -> None:
    """The two defects found by actually running this thing.

    The drain timer used to fire after the widgets were gone, raising
    ``NoMatches`` from inside a timer callback; and the worker thread used to
    keep sending requests at the target after the window closed.
    """
    captured: dict[str, object] = {}

    async def scenario() -> None:
        tui = ScannerTUI(target=app.base_url)
        async with tui.run_test(size=(150, 48)) as pilot:
            tui.query_one("#delay", Input).value = "0.2"
            tui.action_start_scan()
            await pilot.pause()
            captured["session"] = tui._session
        # Leaving the context unmounts the app; Textual re-raises anything the
        # app raised, so reaching this line is the assertion about the timer.

    _run(scenario)

    session = captured["session"]
    assert session is not None
    assert session.cancel_requested is True  # type: ignore[union-attr]


def test_an_empty_target_does_not_start_a_scan() -> None:
    async def scenario() -> None:
        tui = ScannerTUI()
        async with tui.run_test(size=(120, 40)) as pilot:
            tui.action_start_scan()
            await pilot.pause()
            assert tui._session is None

    _run(scenario)


def test_invalid_limits_do_not_start_a_scan(app: VulnerableAppServer) -> None:
    async def scenario() -> None:
        tui = ScannerTUI(target=app.base_url)
        async with tui.run_test(size=(120, 40)) as pilot:
            tui.query_one("#max-pages", Input).value = "not-a-number"
            tui.action_start_scan()
            await pilot.pause()
            assert tui._session is None

    _run(scenario)


def test_deselecting_every_scanner_does_not_start_a_scan(
    app: VulnerableAppServer,
) -> None:
    """An empty selection is a configuration error, not a scan that finds nothing."""

    async def scenario() -> None:
        from textual.widgets import Checkbox

        tui = ScannerTUI(target=app.base_url)
        async with tui.run_test(size=(120, 40)) as pilot:
            for checkbox in tui.query(Checkbox):
                checkbox.value = False
            await pilot.pause()
            tui.action_start_scan()
            await pilot.pause()
            assert tui._session is None

    _run(scenario)
