"""Custom widgets: the severity distribution bar and the status line.

Both exist because the stock widgets would have said the same thing less
precisely. Everything here follows one rule inherited from the HTML report:
**severity is never carried by colour alone.** Each bar segment and each
status field is labelled in writing, so the interface survives a monochrome
terminal, a screen reader and a reader who cannot separate the hues.
"""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Static

from ..core.models import Severity
from .session import ScanSession, SessionState
from .theme import ACCENT, INK, MUTED, SEVERITY_COLOURS

__all__ = ["SeverityBar", "StatusLine", "severity_text"]

#: Solid block for bar segments; a full cell so adjacent segments meet.
_BLOCK = "█"


def severity_text(severity: Severity) -> Text:
    """Return the severity's written label in its colour."""
    return Text(severity.label.upper(), style=f"bold {SEVERITY_COLOURS[severity]}")


class SeverityBar(Static):
    """A proportional bar of findings per severity, plus a written legend.

    The bar is drawn to the widget's actual width rather than a fixed size,
    and every severity present gets at least one cell: rounding a real
    finding down to zero width would hide it, which is the one thing this
    widget must not do. The legend beneath carries the counts in text, so the
    bar is decoration and the numbers are the message.
    """

    DEFAULT_CSS = """
    SeverityBar { height: auto; }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._counts: dict[Severity, int] = {severity: 0 for severity in Severity}

    def set_counts(self, counts: dict[Severity, int]) -> None:
        """Replace the counts and redraw."""
        self._counts = {severity: counts.get(severity, 0) for severity in Severity}
        self.refresh()

    def on_resize(self) -> None:
        """Redraw at the new width, since the segments are proportional."""
        self.refresh()

    def render(self) -> Text:
        """Draw the bar followed by its legend."""
        ordered = sorted(self._counts.items(), key=lambda item: item[0].rank, reverse=True)
        total = sum(count for _, count in ordered)
        width = max(self.size.width, 10)

        bar = Text()
        if total == 0:
            bar.append("─" * width, style=MUTED)
            bar.append("\n")
            bar.append("no findings", style=f"bold {ACCENT}")
            return bar

        # A one-cell gap between segments, matching the gap the HTML report
        # leaves for the same reason: without it two adjacent severities read
        # as a single block and the boundary between them is invisible.
        segments = self._segments(ordered, total, width)
        for index, (severity, cells) in enumerate(segments):
            if index:
                bar.append(" ")
            bar.append(_BLOCK * cells, style=SEVERITY_COLOURS[severity])
        bar.append("\n")

        legend = Text()
        for severity, count in ordered:
            if legend.cell_len:
                legend.append("  ", style=MUTED)
            legend.append(f"{severity.label.upper()} ", style=SEVERITY_COLOURS[severity])
            legend.append(str(count), style=f"bold {INK}" if count else MUTED)
        bar.append_text(legend)
        return bar

    @staticmethod
    def _segments(
        ordered: list[tuple[Severity, int]],
        total: int,
        width: int,
    ) -> list[tuple[Severity, int]]:
        """Split ``width`` cells across the severities that have findings.

        Uses largest-remainder allocation so the segments plus the gaps
        between them always sum to the full width: repeated rounding would
        leave a ragged run of background at the end that reads as a sixth,
        unlabelled category.

        Every severity that has findings gets at least one cell. Rounding a
        real finding down to zero width would delete it from the chart, which
        is the one failure this widget must not have.
        """
        present = [(severity, count) for severity, count in ordered if count]
        if not present:
            return []

        # One cell is spent on each gap between neighbouring segments.
        width -= len(present) - 1
        if width < len(present):
            # Too narrow to draw proportionally and still show every
            # severity; give each one cell and let the legend carry the
            # counts, which it does in writing regardless.
            return [(severity, 1) for severity, _ in present]

        exact = [(severity, count * width / total) for severity, count in present]
        floors = [(severity, max(1, int(value))) for severity, value in exact]
        shortfall = width - sum(cells for _, cells in floors)

        # Hand the leftover cells to the largest fractional parts first.
        order = sorted(
            range(len(exact)),
            key=lambda index: exact[index][1] - int(exact[index][1]),
            reverse=True,
        )
        result = [cells for _, cells in floors]
        position = 0
        while shortfall > 0 and order:
            result[order[position % len(order)]] += 1
            shortfall -= 1
            position += 1
        while shortfall < 0:
            # Over-allocated because every segment was floored up to 1. Take
            # cells back from the widest segment, never below one.
            widest = max(range(len(result)), key=lambda index: result[index])
            if result[widest] <= 1:
                break
            result[widest] -= 1
            shortfall += 1

        return [(present[index][0], result[index]) for index in range(len(present))]


class StatusLine(Static):
    """The bottom bar: what the run is doing and what it has spent.

    The request counter is shown against the budget rather than alone. A bare
    "412 requests" says nothing about whether the scan is about to stop; the
    budget is the number that decides that.
    """

    DEFAULT_CSS = """
    StatusLine { height: 1; }
    """

    _STATE_COLOURS = {
        SessionState.IDLE: MUTED,
        SessionState.RUNNING: ACCENT,
        SessionState.COMPLETED: ACCENT,
        SessionState.CANCELLED: "#ffd166",
        SessionState.FAILED: "#ff2d6f",
    }

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._session: ScanSession | None = None
        self._phase = ""

    def bind_session(self, session: ScanSession | None) -> None:
        """Point the status line at ``session`` (or at nothing)."""
        self._session = session
        self._phase = ""
        self.refresh()

    def set_phase(self, phase: str) -> None:
        """Show ``phase`` as the current activity."""
        self._phase = phase
        self.refresh()

    def render(self) -> Text:
        """Draw the status fields."""
        line = Text()
        session = self._session
        if session is None:
            line.append(" IDLE ", style=f"bold {MUTED}")
            line.append(" no scan configured", style=MUTED)
            return line

        state = session.state
        line.append(f" {state.value.upper()} ", style=f"bold {self._STATE_COLOURS[state]}")
        if self._phase:
            line.append(f"{self._phase} ", style=INK)

        budget = session.config.max_requests
        report = session.report
        sent = report.requests_sent if report else len(session.history) + session.not_recorded

        self._field(line, "req", f"{sent}/{budget}")
        self._field(line, "findings", str(len(session.findings)))
        self._field(line, "elapsed", f"{session.elapsed_seconds:.1f}s")
        if session.not_recorded:
            self._field(line, "not recorded", str(session.not_recorded))
        return line

    @staticmethod
    def _field(line: Text, label: str, value: str) -> None:
        line.append(" │ ", style=MUTED)
        line.append(f"{label} ", style=MUTED)
        line.append(value, style=INK)
