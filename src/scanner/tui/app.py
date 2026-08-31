"""The terminal user interface.

A scan has four questions an operator asks while it runs — *what is it
touching*, *what has it found*, *what did the traffic look like*, and *is it
still going* — and this interface gives each one a pane instead of making
them compete for one scrolling log.

The shape is borrowed from intercepting proxies: a target tree, a request
history with the full request and response beneath it, and a findings list
with the evidence for each. The palette, the severity vocabulary and the
refusal to signal anything by colour alone are inherited from the HTML
report, so a finding looks like itself in the terminal, in a browser and in
a ticket.

Nothing here can widen what the scanner does. The interface builds the same
:class:`~scanner.core.config.ScanConfig` the CLI builds and hands it to the
same engine; scope, pacing and the request budget are enforced where they
always were, at the HTTP chokepoint.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import deque
from collections.abc import Mapping, Sequence
from datetime import datetime
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.timer import Timer
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Input,
    Label,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)
from textual.widgets.tree import TreeNode

from ..core.config import DEFAULT_USER_AGENT, ScanConfig
from ..core.exceptions import ConfigurationError
from ..core.models import ScanResult, Severity
from ..reporting.html import write_html_report
from ..scanners.base import available_scanners
from ..utils.logging import get_logger
from .session import DrainedEvents, HistoryEntry, PhaseEvent, ScanSession, SessionState
from .theme import ACCENT, INK, MUTED, SEVERITY_COLOURS, STATUS_COLOURS, css_variables
from .widgets import SeverityBar, StatusLine, severity_text

__all__ = ["ScannerTUI", "load_stylesheet", "main"]

_AUTHORISED_USE = (
    "Authorised use only: scan systems you own or have explicit written permission to test."
)

#: How often the UI picks up what the scanning thread has buffered. Fast
#: enough to feel live, slow enough that a burst of requests costs one redraw
#: rather than one per request.
_DRAIN_INTERVAL = 0.15

#: Cap on rows kept in the log pane and the two tables. The session bounds
#: what it records; these bound what is rendered, which is a different and
#: much smaller number -- a table nobody can scroll to the end of is not
#: information.
_LOG_LINES = 2_000

_SEVERITY_FILTERS: tuple[Severity | None, ...] = (None, *reversed(list(Severity)))


def load_stylesheet() -> str:
    """Return the stylesheet with the shared palette prepended.

    The sheet ships as package data and is read through
    :mod:`importlib.resources`, not from a path relative to this file, so it
    resolves from an installed wheel and not only from a source checkout.
    """
    sheet = resources.files("scanner.tui").joinpath("app.tcss").read_text(encoding="utf-8")
    return f"{css_variables()}\n{sheet}"


class _UiLogHandler(logging.Handler):
    """Buffers log records for the UI thread to render.

    ``RichLog`` may only be written from the UI thread, and log records are
    emitted from the scanning thread. Buffering here and draining on the
    timer keeps the boundary in one place; the deque is bounded because a
    verbose scan can outrun any reader.
    """

    def __init__(self, buffer: deque[logging.LogRecord]) -> None:
        super().__init__()
        self._buffer = buffer

    def emit(self, record: logging.LogRecord) -> None:
        """Queue ``record`` for the next drain."""
        self._buffer.append(record)


class ScannerTUI(App[int]):
    """Terminal front end for the scanner."""

    CSS = load_stylesheet()
    TITLE = "web-vuln-scanner"

    BINDINGS = [
        Binding("ctrl+r", "start_scan", "Scan", priority=True),
        Binding("ctrl+x", "cancel_scan", "Stop", priority=True),
        Binding("ctrl+e", "export_report", "Export", priority=True),
        Binding("f", "cycle_filter", "Filter severity"),
        Binding("ctrl+q", "quit", "Quit", priority=True),
    ]

    _LEVEL_COLOURS = {
        logging.DEBUG: MUTED,
        logging.INFO: INK,
        logging.WARNING: "#ffd166",
        logging.ERROR: "#ff2d6f",
        logging.CRITICAL: "#ff2d6f",
    }

    def __init__(self, *, target: str = "", verbose: bool = False) -> None:
        super().__init__()
        self._initial_target = target
        self._verbose = verbose
        self._session: ScanSession | None = None
        self._log_buffer: deque[logging.LogRecord] = deque(maxlen=_LOG_LINES)
        self._log_handler: _UiLogHandler | None = None
        self._tree_nodes: dict[str, TreeNode[str]] = {}
        self._findings: list[ScanResult] = []
        self._filter: Severity | None = None
        self._last_state: SessionState | None = None
        self._drain_timer: Timer | None = None
        self._closing = False

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Build the widget tree."""
        yield Static(self._banner(), id="banner")

        with Vertical(id="controls"):
            with Horizontal(classes="control-row"):
                yield Label("target", classes="field-label")
                yield Input(
                    value=self._initial_target,
                    placeholder="http://127.0.0.1:8000",
                    id="target",
                )
                yield Button("SCAN", id="scan", variant="success")
                yield Button("STOP", id="stop", variant="error", disabled=True)
                yield Button("EXPORT", id="export", disabled=True)
            # The limits and the scanner toggles are separate rows rather than
            # one long one. A Horizontal does not wrap, so a single row of
            # eight limit controls plus a checkbox per scanner runs off the
            # right edge of an 80- or 100-column terminal -- and every one of
            # those widgets stays in the DOM while being invisible.
            with Horizontal(classes="control-row"):
                yield Label("depth", classes="field-label")
                yield Input(value="3", id="max-depth", classes="tiny")
                yield Label("pages", classes="field-label")
                yield Input(value="50", id="max-pages", classes="tiny")
                yield Label("budget", classes="field-label")
                yield Input(value="500", id="max-requests", classes="tiny")
                yield Label("delay", classes="field-label")
                yield Input(value="0.5", id="delay", classes="tiny")
            with Horizontal(classes="control-row"):
                yield Label("checks", classes="field-label")
                for name in available_scanners():
                    yield Checkbox(name, value=True, id=f"sc-{name}", classes="scanner-toggle")

        with TabbedContent(id="tabs"):
            with TabPane("Dashboard", id="tab-dashboard"):
                yield from self._compose_dashboard()
            with TabPane("Target", id="tab-target"):
                yield from self._compose_target()
            with TabPane("HTTP history", id="tab-history"):
                yield from self._compose_history()
            with TabPane("Findings", id="tab-findings"):
                yield from self._compose_findings()
            with TabPane("Log", id="tab-log"):
                yield RichLog(id="log", markup=False, wrap=True, max_lines=_LOG_LINES)

        yield StatusLine(id="status")
        yield Footer()

    def _compose_dashboard(self) -> ComposeResult:
        with VerticalScroll(classes="pane"):
            yield Label("SEVERITY DISTRIBUTION", classes="section")
            yield SeverityBar(id="severity-bar")
            yield Label("RUN", classes="section")
            yield Static(Text("No scan yet.", style=MUTED), id="run-stats")
            yield Label("NON-FATAL ERRORS", classes="section")
            yield Static(Text("None.", style=MUTED), id="run-errors")
            yield Label("NOTICE", classes="section")
            yield Static(Text(_AUTHORISED_USE, style=MUTED), id="notice")

    def _compose_target(self) -> ComposeResult:
        with Horizontal(classes="split"):
            tree: Tree[str] = Tree("(no target)", id="site-tree")
            tree.show_root = True
            yield tree
            with VerticalScroll(classes="detail"):
                yield Static(
                    Text("Select a URL to see the exchanges recorded for it.", style=MUTED),
                    id="target-detail",
                )

    def _compose_history(self) -> ComposeResult:
        with Vertical(classes="split-v"):
            yield DataTable(id="history-table", cursor_type="row", zebra_stripes=False)
            with VerticalScroll(classes="detail"):
                yield Static(
                    Text("Select a row to see the request and response.", style=MUTED),
                    id="history-detail",
                )

    def _compose_findings(self) -> ComposeResult:
        with Vertical(classes="split-v"):
            yield Static(self._filter_text(), id="filter-line")
            yield DataTable(id="findings-table", cursor_type="row", zebra_stripes=False)
            with VerticalScroll(classes="detail"):
                yield Static(
                    Text("Select a finding to see its evidence.", style=MUTED),
                    id="finding-detail",
                )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        """Set up tables, logging capture and the drain timer."""
        history = self.query_one("#history-table", DataTable)
        history.add_column("#", width=5)
        history.add_column("method", width=6)
        history.add_column("status", width=6)
        history.add_column("type", width=18)
        history.add_column("bytes", width=8)
        history.add_column("ms", width=6)
        history.add_column("url")

        findings = self.query_one("#findings-table", DataTable)
        findings.add_column("severity", width=9)
        findings.add_column("conf", width=6)
        # No fixed width: a truncated vulnerability name is the one cell in
        # this table that cannot be guessed from its neighbours, and pinning a
        # width here would silently clip the next scanner someone adds.
        findings.add_column("vulnerability")
        findings.add_column("param")
        findings.add_column("url")

        self._attach_log_capture()
        self._drain_timer = self.set_interval(_DRAIN_INTERVAL, self._drain)
        self.query_one("#target", Input).focus()

    def on_unmount(self) -> None:
        """Stop the drain timer and hand the package logger back.

        Both matter on the way out. A tick that runs after the widgets are
        gone raises ``NoMatches`` from inside a timer callback, which Textual
        surfaces as a crash on quit — quitting mid-scan is exactly when the
        timer is busiest. Stopping it here closes the window, and
        :attr:`_closing` catches a tick already queued behind this one.
        """
        self._closing = True
        if self._drain_timer is not None:
            self._drain_timer.stop()
            self._drain_timer = None
        self._cancel_running_scan()
        self._detach_log_capture()

    def _cancel_running_scan(self) -> None:
        """Stop a scan that is still running as the interface goes away.

        The scan runs on a worker thread that does not end when the interface
        does. Without this, closing the window would leave a process quietly
        sending authorised-but-unwatched traffic at the target with nobody
        reading the results. Quitting is a decision to stop scanning.
        """
        session = self._session
        if session is not None and session.state is SessionState.RUNNING:
            session.cancel()

    def _attach_log_capture(self) -> None:
        logger = get_logger()
        logger.setLevel(logging.DEBUG if self._verbose else logging.INFO)
        logger.propagate = False
        # The package logger writes to stderr by default, which would paint
        # over the interface. The UI takes ownership of it for as long as it
        # is running and hands it back on unmount.
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
        self._log_handler = _UiLogHandler(self._log_buffer)
        logger.addHandler(self._log_handler)

    def _detach_log_capture(self) -> None:
        if self._log_handler is not None:
            get_logger().removeHandler(self._log_handler)
            self._log_handler = None

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_start_scan(self) -> None:
        """Validate the form and start a scan on a worker thread."""
        if self._session is not None and self._session.state is SessionState.RUNNING:
            self.notify("A scan is already running.", severity="warning")
            return

        target = self.query_one("#target", Input).value.strip()
        if not target:
            self.notify("Enter a target URL first.", severity="error")
            self.query_one("#target", Input).focus()
            return

        try:
            config = self._config_from_form()
        except ConfigurationError as exc:
            self.notify(str(exc), title="Invalid configuration", severity="error")
            return

        self._reset_panes()
        session = ScanSession(config, target)
        self._session = session
        self.query_one("#status", StatusLine).bind_session(session)
        self._set_running(True)
        tree = self.query_one("#site-tree", Tree)
        tree.root.set_label(Text(target, style=ACCENT))
        # Expand the root up front. A tree that fills up behind a collapsed
        # root looks like a scan that found nothing.
        tree.root.expand()
        self.run_worker(session.execute, thread=True, name="scan", group="scan")

    def action_cancel_scan(self) -> None:
        """Ask a running scan to stop at the next request boundary."""
        session = self._session
        if session is None or session.state is not SessionState.RUNNING:
            self.notify("No scan is running.", severity="warning")
            return
        session.cancel()
        self.query_one("#status", StatusLine).set_phase("stopping at next request")
        self.notify("Stopping after the request in flight.", severity="warning")

    def action_export_report(self) -> None:
        """Write the completed run's HTML report next to the working directory."""
        session = self._session
        report = session.report if session else None
        if report is None:
            self.notify(
                "Only a completed scan can be exported; a cancelled run has no report.",
                title="Nothing to export",
                severity="warning",
            )
            return

        host = urlsplit(report.target.url).netloc.replace(":", "_") or "target"
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = Path.cwd() / f"scan-{host}-{stamp}.html"
        try:
            write_html_report(report, path)
        except OSError as exc:
            self.notify(str(exc), title="Could not write report", severity="error")
            return
        self.notify(str(path), title="Report written")

    def action_cycle_filter(self) -> None:
        """Step the findings pane through the severity filters."""
        index = _SEVERITY_FILTERS.index(self._filter)
        self._filter = _SEVERITY_FILTERS[(index + 1) % len(_SEVERITY_FILTERS)]
        self.query_one("#filter-line", Static).update(self._filter_text())
        self._rebuild_findings_table()

    @on(Button.Pressed, "#scan")
    def _on_scan_pressed(self) -> None:
        self.action_start_scan()

    @on(Button.Pressed, "#stop")
    def _on_stop_pressed(self) -> None:
        self.action_cancel_scan()

    @on(Button.Pressed, "#export")
    def _on_export_pressed(self) -> None:
        self.action_export_report()

    @on(Input.Submitted, "#target")
    def _on_target_submitted(self) -> None:
        self.action_start_scan()

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _config_from_form(self) -> ScanConfig:
        """Build a :class:`ScanConfig` from the control bar.

        Field-level errors are raised as :class:`ConfigurationError` with the
        offending field named, because "must be > 0" on its own leaves the
        operator hunting through four inputs.
        """
        selected = tuple(
            name for name in available_scanners() if self.query_one(f"#sc-{name}", Checkbox).value
        )
        if not selected:
            raise ConfigurationError("select at least one scanner")

        return ScanConfig(
            max_depth=self._int_field("max-depth", "depth"),
            max_pages=self._int_field("max-pages", "pages"),
            max_requests=self._int_field("max-requests", "budget"),
            delay=self._float_field("delay", "delay"),
            user_agent=DEFAULT_USER_AGENT,
            enabled_scanners=selected,
        )

    def _int_field(self, widget_id: str, label: str) -> int:
        raw = self.query_one(f"#{widget_id}", Input).value.strip()
        try:
            return int(raw)
        except ValueError:
            raise ConfigurationError(f"{label}: expected a whole number, got {raw!r}") from None

    def _float_field(self, widget_id: str, label: str) -> float:
        raw = self.query_one(f"#{widget_id}", Input).value.strip()
        try:
            return float(raw)
        except ValueError:
            raise ConfigurationError(f"{label}: expected a number, got {raw!r}") from None

    # ------------------------------------------------------------------
    # Draining the scanning thread
    # ------------------------------------------------------------------

    def _drain(self) -> None:
        """Move everything the scan has buffered into the widgets.

        Textual unmounts children before parents, so the app's own
        ``on_unmount`` runs *after* the widgets are gone and a tick scheduled
        just before it lands on an empty screen. The guard looks for the
        status line and does nothing if it has left.

        It is a look-before-you-leap check rather than a caught exception on
        purpose. Draining is destructive — :meth:`ScanSession.drain` hands the
        buffers over and empties them — so a batch taken and then half applied
        is history that no later tick can recover. Nothing here awaits, and
        Textual runs the UI on one thread, so no widget can disappear between
        this check and the work below.
        """
        if self._closing or not self.query("#status"):
            return
        self._drain_once()

    def _drain_once(self) -> None:
        self._drain_logs()

        session = self._session
        if session is None:
            return

        self._apply(session.drain())
        self.query_one("#status", StatusLine).refresh()

        state = session.state
        if state is not self._last_state:
            self._last_state = state
            if state.is_terminal:
                # The worker keeps buffering between the drain above and the
                # moment it sets its final state, so there is almost always a
                # last batch outstanding here. Flush it before announcing a
                # total, or the toast says nine findings while the table shows
                # five for the length of one tick.
                self._apply(session.drain())
                self._on_run_finished(session, state)

    def _apply(self, drained: DrainedEvents) -> None:
        """Render one batch of buffered events."""
        for entry in drained.exchanges:
            self._append_history_row(entry)
            self._add_to_tree(entry)
        if drained.findings:
            self._findings.extend(drained.findings)
            self._rebuild_findings_table()
            self._refresh_severity_bar()
        for phase in drained.phases:
            self._apply_phase(phase)

    def _drain_logs(self) -> None:
        if not self._log_buffer:
            return
        pane = self.query_one("#log", RichLog)
        while self._log_buffer:
            record = self._log_buffer.popleft()
            pane.write(self._format_record(record))

    def _format_record(self, record: logging.LogRecord) -> Text:
        stamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        colour = self._LEVEL_COLOURS.get(record.levelno, INK)
        line = Text()
        line.append(f"{stamp} ", style=MUTED)
        line.append(f"{record.levelname:<8}", style=colour)
        line.append(f"{record.name.removeprefix('scanner.'):<10} ", style=MUTED)
        line.append(record.getMessage(), style=INK)
        return line

    def _apply_phase(self, phase: PhaseEvent) -> None:
        readable = {
            "crawl": "crawling",
            "crawled": "crawl finished",
            "scan": "running scanner",
            "done": "finished",
        }.get(phase.phase, phase.phase)
        detail = f"{readable}: {phase.detail}" if phase.detail else readable
        self.query_one("#status", StatusLine).set_phase(detail)

    def _on_run_finished(self, session: ScanSession, state: SessionState) -> None:
        self._set_running(False)
        report = session.report
        self.query_one("#export", Button).disabled = report is None
        self._refresh_run_stats(session)
        self._refresh_severity_bar()

        if state is SessionState.COMPLETED:
            count = len(session.findings)
            self.query_one("#status", StatusLine).set_phase("finished")
            self.notify(f"Scan finished with {count} finding(s).", title="Done")
        elif state is SessionState.CANCELLED:
            self.query_one("#status", StatusLine).set_phase("cancelled by operator")
            self.notify(
                "Findings and history below are only what the run reached before it stopped.",
                title="Scan cancelled",
                severity="warning",
            )
        else:
            self.query_one("#status", StatusLine).set_phase("failed")
            self.notify(session.failure or "unknown error", title="Scan failed", severity="error")

    # ------------------------------------------------------------------
    # Panes
    # ------------------------------------------------------------------

    def _reset_panes(self) -> None:
        self._findings = []
        self._tree_nodes = {}
        self.query_one("#history-table", DataTable).clear()
        self.query_one("#findings-table", DataTable).clear()
        self.query_one("#log", RichLog).clear()
        tree = self.query_one("#site-tree", Tree)
        tree.clear()
        self.query_one("#severity-bar", SeverityBar).set_counts({})
        self.query_one("#run-stats", Static).update(Text("Scan running...", style=MUTED))
        self.query_one("#run-errors", Static).update(Text("None.", style=MUTED))
        self.query_one("#history-detail", Static).update(
            Text("Select a row to see the request and response.", style=MUTED)
        )
        self.query_one("#finding-detail", Static).update(
            Text("Select a finding to see its evidence.", style=MUTED)
        )
        self.query_one("#target-detail", Static).update(
            Text("Select a URL to see the exchanges recorded for it.", style=MUTED)
        )

    def _set_running(self, running: bool) -> None:
        self.query_one("#scan", Button).disabled = running
        self.query_one("#stop", Button).disabled = not running
        if running:
            self.query_one("#export", Button).disabled = True

    def _append_history_row(self, entry: HistoryEntry) -> None:
        exchange = entry.exchange
        table = self.query_one("#history-table", DataTable)
        table.add_row(
            Text(str(exchange.seq), style=MUTED),
            Text(str(exchange.method), style=INK),
            Text(
                str(exchange.status_code),
                style=f"bold {STATUS_COLOURS.get(exchange.status_class, MUTED)}",
            ),
            Text(exchange.content_type or "-", style=MUTED),
            Text(str(exchange.body_bytes), style=MUTED),
            Text(f"{exchange.elapsed_seconds * 1000:.0f}", style=MUTED),
            Text(exchange.url, style=INK),
            key=str(exchange.seq),
        )

    def _add_to_tree(self, entry: HistoryEntry) -> None:
        """Place the exchange's URL in the site tree, creating parents as needed.

        A node's ``data`` is the path it stands for, and the detail pane looks
        exchanges up by matching that against ``urlsplit(url).path``. The two
        have to agree exactly, which is why the site root is handled on its own
        line: treating ``/`` as a path segment would build the node under the
        key ``//``, and it would then match no exchange ever recorded.
        """
        tree = self.query_one("#site-tree", Tree)
        segments = [segment for segment in urlsplit(entry.exchange.url).path.split("/") if segment]

        if not segments:
            self._ensure_node(tree.root, "/", "/")
            return

        node = tree.root
        walked = ""
        for segment in segments:
            walked = f"{walked}/{segment}"
            node = self._ensure_node(node, segment, walked)

    def _ensure_node(self, parent: TreeNode[str], label: str, path: str) -> TreeNode[str]:
        """Return the node for ``path``, adding it under ``parent`` if new."""
        existing = self._tree_nodes.get(path)
        if existing is None:
            existing = parent.add(label, data=path, expand=True)
            self._tree_nodes[path] = existing
        return existing

    def _rebuild_findings_table(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        for index, finding in enumerate(self._visible_findings()):
            table.add_row(
                severity_text(finding.severity),
                Text(finding.confidence.label, style=MUTED),
                Text(finding.vulnerability, style=INK),
                Text(finding.parameter or "-", style=MUTED),
                Text(finding.url, style=INK),
                key=str(index),
            )

    def _visible_findings(self) -> list[ScanResult]:
        findings = sorted(self._findings, key=lambda f: f.sort_key())
        if self._filter is None:
            return findings
        return [f for f in findings if f.severity is self._filter]

    def _filter_text(self) -> Text:
        line = Text()
        line.append("severity filter  ", style=MUTED)
        if self._filter is None:
            line.append("ALL", style=f"bold {ACCENT}")
        else:
            line.append_text(severity_text(self._filter))
        line.append("    press f to cycle", style=MUTED)
        return line

    def _refresh_severity_bar(self) -> None:
        counts = {severity: 0 for severity in Severity}
        for finding in self._findings:
            counts[finding.severity] += 1
        self.query_one("#severity-bar", SeverityBar).set_counts(counts)

    def _refresh_run_stats(self, session: ScanSession) -> None:
        report = session.report
        body = Text()
        if report is None:
            body.append("Run did not complete, so there is no report.\n", style=MUTED)
            body.append(f"Exchanges recorded: {len(session.history)}\n", style=INK)
            body.append(f"Findings so far: {len(session.findings)}", style=INK)
            self.query_one("#run-stats", Static).update(body)
            return

        rows = [
            ("target", report.target.url),
            ("duration", f"{report.duration_seconds:.2f}s"),
            ("pages", str(report.pages_discovered)),
            ("endpoints", str(report.endpoints_discovered)),
            ("forms", str(report.forms_discovered)),
            ("requests sent", f"{report.requests_sent}/{session.config.max_requests}"),
            ("scanners", ", ".join(report.scanners_run) or "-"),
            ("findings", str(len(report.findings))),
        ]
        for label, value in rows:
            body.append(f"{label:<15}", style=MUTED)
            body.append(f"{value}\n", style=INK)
        self.query_one("#run-stats", Static).update(body)

        errors = Text()
        if report.errors:
            for message in report.errors[:20]:
                errors.append(f"- {message}\n", style=MUTED)
            if len(report.errors) > 20:
                errors.append(f"...and {len(report.errors) - 20} more", style=MUTED)
        else:
            errors.append("None.", style=MUTED)
        self.query_one("#run-errors", Static).update(errors)

    # ------------------------------------------------------------------
    # Selection handlers
    # ------------------------------------------------------------------

    @on(DataTable.RowHighlighted, "#history-table")
    def _on_history_row(self, event: DataTable.RowHighlighted) -> None:
        session = self._session
        if session is None or event.row_key.value is None:
            return
        entry = session.entry(int(event.row_key.value))
        if entry is None:
            return
        self.query_one("#history-detail", Static).update(self._render_exchange(entry))

    @on(DataTable.RowHighlighted, "#findings-table")
    def _on_finding_row(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key.value is None:
            return
        visible = self._visible_findings()
        index = int(event.row_key.value)
        if index >= len(visible):
            return
        self.query_one("#finding-detail", Static).update(self._render_finding(visible[index]))

    @on(Tree.NodeSelected, "#site-tree")
    def _on_tree_node(self, event: Tree.NodeSelected[str]) -> None:
        session = self._session
        path = event.node.data
        if session is None or path is None:
            return
        matching = [entry for entry in session.history if urlsplit(entry.exchange.url).path == path]
        detail = Text()
        detail.append(f"{path}\n\n", style=f"bold {ACCENT}")
        if not matching:
            detail.append("No exchange recorded for this exact path.", style=MUTED)
        else:
            for entry in matching:
                exchange = entry.exchange
                detail.append(f"#{exchange.seq} ", style=MUTED)
                detail.append(f"{exchange.method} ", style=INK)
                detail.append(
                    f"{exchange.status_code} ",
                    style=STATUS_COLOURS.get(exchange.status_class, MUTED),
                )
                detail.append(f"{exchange.body_bytes}b ", style=MUTED)
                detail.append(f"{exchange.url}\n", style=INK)
        self.query_one("#target-detail", Static).update(detail)

    # ------------------------------------------------------------------
    # Rendering detail
    # ------------------------------------------------------------------

    def _render_exchange(self, entry: HistoryEntry) -> Text:
        exchange = entry.exchange
        out = Text()
        out.append("REQUEST\n", style=f"bold {ACCENT}")
        out.append(f"{exchange.method} {exchange.url}\n", style=INK)
        self._append_headers(out, exchange.request_headers)
        if exchange.request_body:
            out.append("\n")
            for name, value in exchange.request_body.items():
                out.append(f"  {name}=", style=MUTED)
                out.append(f"{value}\n", style=INK)

        out.append("\nRESPONSE\n", style=f"bold {ACCENT}")
        out.append(
            f"{exchange.status_code} {exchange.reason}\n",
            style=f"bold {STATUS_COLOURS.get(exchange.status_class, MUTED)}",
        )
        self._append_headers(out, exchange.response_headers)

        out.append("\nBODY", style=f"bold {ACCENT}")
        notes = self._body_notes(entry)
        if notes:
            out.append(f"  ({notes})", style=MUTED)
        out.append("\n")
        out.append(entry.body or "(empty or non-textual)", style=INK if entry.body else MUTED)
        return out

    @staticmethod
    def _body_notes(entry: HistoryEntry) -> str:
        notes = []
        if entry.exchange.truncated:
            notes.append("truncated by max-response-bytes")
        if entry.body_clipped:
            notes.append("clipped for display")
        return "; ".join(notes)

    @staticmethod
    def _append_headers(out: Text, headers: Mapping[str, str]) -> None:
        for name, value in headers.items():
            out.append(f"  {name}: ", style=MUTED)
            out.append(f"{value}\n", style=INK)

    def _render_finding(self, finding: ScanResult) -> Text:
        out = Text()
        out.append_text(severity_text(finding.severity))
        out.append(f"  {finding.vulnerability}\n", style=f"bold {INK}")
        out.append(f"{finding.method} {finding.url}\n", style=INK)
        if finding.parameter:
            out.append(f"parameter: {finding.parameter}\n", style=MUTED)
        out.append(
            f"scanner: {finding.scanner}    confidence: {finding.confidence.label}\n\n",
            style=MUTED,
        )

        for heading, text in (
            ("DESCRIPTION", finding.description),
            ("IMPACT", finding.impact),
            ("WHY THIS SEVERITY", finding.severity_rationale),
            ("REMEDIATION", finding.remediation),
        ):
            out.append(f"{heading}\n", style=f"bold {SEVERITY_COLOURS[finding.severity]}")
            out.append(f"{text}\n\n", style=INK)

        if finding.evidence:
            out.append("EVIDENCE\n", style=f"bold {ACCENT}")
            out.append(finding.evidence, style=INK)
        return out

    # ------------------------------------------------------------------

    @staticmethod
    def _banner() -> Text:
        line = Text()
        line.append("// WEB-VULN-SCANNER", style=f"bold {ACCENT}")
        line.append("   non-destructive · scope-bound · authorised targets only", style=MUTED)
        return line


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``web-vuln-scanner-tui``."""
    parser = argparse.ArgumentParser(
        prog="web-vuln-scanner-tui",
        description="Terminal interface for the web vulnerability scanner.",
        epilog=_AUTHORISED_USE,
    )
    parser.add_argument("--target", default="", help="Pre-fill the target URL.")
    parser.add_argument("--verbose", action="store_true", help="Show debug records in the log.")
    args = parser.parse_args(argv)

    app = ScannerTUI(target=args.target, verbose=args.verbose)
    app.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
