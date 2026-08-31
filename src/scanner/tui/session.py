"""State for one scan run, and the hand-off between the scan and the UI.

The scan runs on a worker thread; Textual widgets may only be touched from
the UI thread. Rather than marshal every event across that boundary the
moment it happens, the scanning thread appends to bounded buffers here and
the UI drains them on a timer.

That choice is about pacing, not tidiness. A scan can complete a request
every few milliseconds, and waking the UI thread once per request would
spend more time scheduling redraws than scanning. Draining in batches keeps
the interface responsive under load and, more importantly, keeps the
observer callbacks cheap: they run on the scanning thread, where blocking
would change the request rate the operator configured.

Every buffer here is bounded. An unbounded history is a memory leak with a
progress bar: the request budget alone allows hundreds of responses of up to
``max_response_bytes`` each.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from ..core.config import ScanConfig
from ..core.engine import ScanEngine
from ..core.events import ScanEvents
from ..core.exceptions import ScanCancelled, ScannerError
from ..core.models import HttpExchange, ScanReport, ScanResult

__all__ = [
    "SessionState",
    "HistoryEntry",
    "PhaseEvent",
    "DrainedEvents",
    "ScanSession",
    "DEFAULT_HISTORY_LIMIT",
    "DEFAULT_BODY_CHARS",
]

#: How many exchanges the history pane keeps. Above the default request
#: budget of 500, so an ordinary run loses nothing.
DEFAULT_HISTORY_LIMIT = 2_000

#: How much of a body the viewer holds per exchange. A response may legally
#: be two megabytes; two thousand of those is not a user interface.
DEFAULT_BODY_CHARS = 256 * 1024


class SessionState(Enum):
    """Lifecycle of a scan session."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        """Whether no further events will arrive."""
        return self in {SessionState.COMPLETED, SessionState.CANCELLED, SessionState.FAILED}


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """One exchange as the history pane holds it.

    ``body`` may be shorter than the body the scanner actually received:
    ``body_clipped`` says so. This is kept distinct from the exchange's own
    ``truncated`` flag, which means the *transport* stopped reading at
    ``max_response_bytes``. One is a display limit, the other is a fact about
    what was fetched, and conflating them would misreport the scan.
    """

    exchange: HttpExchange
    body: str
    body_clipped: bool

    @property
    def seq(self) -> int:
        """The exchange's sequence number within the run."""
        return self.exchange.seq


@dataclass(frozen=True, slots=True)
class PhaseEvent:
    """A phase transition reported by the engine."""

    at: datetime
    phase: str
    detail: str


@dataclass(slots=True)
class DrainedEvents:
    """What the UI picked up on one drain."""

    exchanges: list[HistoryEntry] = field(default_factory=list)
    findings: list[ScanResult] = field(default_factory=list)
    phases: list[PhaseEvent] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.exchanges or self.findings or self.phases)


class ScanSession:
    """Runs one scan and buffers its events for a user interface.

    A session is single-use: once it reaches a terminal state it keeps its
    results for inspection, and a new run needs a new session. Reusing one
    would mean deciding whether to clear the previous findings, and every
    answer to that is a way to show an operator stale results.
    """

    def __init__(
        self,
        config: ScanConfig,
        target: str,
        *,
        history_limit: int = DEFAULT_HISTORY_LIMIT,
        body_chars: int = DEFAULT_BODY_CHARS,
    ) -> None:
        self.config = config
        self.target = target
        self._history_limit = history_limit
        self._body_chars = body_chars

        self._lock = threading.Lock()
        self._cancel = threading.Event()

        self._state = SessionState.IDLE
        self._report: ScanReport | None = None
        self._failure: str | None = None
        self._started_at: datetime | None = None
        self._finished_at: datetime | None = None

        self._history: list[HistoryEntry] = []
        self._by_seq: dict[int, HistoryEntry] = {}
        self._not_recorded = 0
        self._findings: list[ScanResult] = []

        self._pending_exchanges: list[HistoryEntry] = []
        self._pending_findings: list[ScanResult] = []
        self._pending_phases: list[PhaseEvent] = []

    # ------------------------------------------------------------------
    # Reading state (safe from any thread)
    # ------------------------------------------------------------------

    @property
    def state(self) -> SessionState:
        """The session's current lifecycle state."""
        with self._lock:
            return self._state

    @property
    def report(self) -> ScanReport | None:
        """The completed report, or ``None`` until a run finishes cleanly."""
        with self._lock:
            return self._report

    @property
    def failure(self) -> str | None:
        """Why the run failed, if it did."""
        with self._lock:
            return self._failure

    @property
    def findings(self) -> list[ScanResult]:
        """Every finding reported so far, in the order the scanners produced them."""
        with self._lock:
            return list(self._findings)

    @property
    def history(self) -> list[HistoryEntry]:
        """Every recorded exchange, oldest first."""
        with self._lock:
            return list(self._history)

    @property
    def not_recorded(self) -> int:
        """Exchanges that happened after the history limit was reached.

        These requests were still sent, paced and charged to the budget; only
        the record of them was dropped. The count is surfaced so an operator
        never reads a short history as a short scan.
        """
        with self._lock:
            return self._not_recorded

    @property
    def history_limit(self) -> int:
        """How many exchanges this session will record."""
        return self._history_limit

    @property
    def elapsed_seconds(self) -> float:
        """Wall-clock seconds since the run started (frozen once it ends)."""
        with self._lock:
            if self._started_at is None:
                return 0.0
            end = self._finished_at or datetime.now(UTC)
            return (end - self._started_at).total_seconds()

    def entry(self, seq: int) -> HistoryEntry | None:
        """Return the recorded exchange numbered ``seq``, if it is still held."""
        with self._lock:
            return self._by_seq.get(seq)

    # ------------------------------------------------------------------
    # Driving the run
    # ------------------------------------------------------------------

    def cancel(self) -> None:
        """Ask the run to stop at the next request boundary."""
        self._cancel.set()

    @property
    def cancel_requested(self) -> bool:
        """Whether :meth:`cancel` has been called."""
        return self._cancel.is_set()

    def build_events(self) -> ScanEvents:
        """Return the callbacks that wire an engine run into this session."""
        return ScanEvents(
            on_exchange=self._record_exchange,
            on_findings=self._record_findings,
            on_phase=self._record_phase,
            should_cancel=self._cancel.is_set,
        )

    def execute(self) -> None:
        """Run the scan to completion. Blocking; call this on a worker thread.

        Never raises: the outcome is recorded as state so the UI has one place
        to read it from, whether the run succeeded, was cancelled or failed.
        """
        with self._lock:
            self._state = SessionState.RUNNING
            self._started_at = datetime.now(UTC)

        try:
            report = ScanEngine(self.config, events=self.build_events()).run(self.target)
        except ScanCancelled:
            self._finish(SessionState.CANCELLED, None, None)
        except ScannerError as exc:
            self._finish(SessionState.FAILED, None, str(exc))
        else:
            self._finish(SessionState.COMPLETED, report, None)

    def _finish(
        self,
        state: SessionState,
        report: ScanReport | None,
        failure: str | None,
    ) -> None:
        with self._lock:
            self._state = state
            self._report = report
            self._failure = failure
            self._finished_at = datetime.now(UTC)

    # ------------------------------------------------------------------
    # Observer callbacks — these run on the scanning thread
    # ------------------------------------------------------------------

    def _record_exchange(self, exchange: HttpExchange) -> None:
        body = exchange.response_body
        clipped = len(body) > self._body_chars
        entry = HistoryEntry(
            exchange=exchange,
            body=body[: self._body_chars] if clipped else body,
            body_clipped=clipped,
        )
        with self._lock:
            if len(self._history) >= self._history_limit:
                # Stop recording rather than evict the oldest. The start of a
                # run is its most interesting part -- the crawl and the first
                # probes of each check -- and "capped at N, M more not
                # recorded" is a clearer claim than a window that silently
                # slid past whatever the operator was looking for.
                self._not_recorded += 1
                return
            self._history.append(entry)
            self._by_seq[entry.seq] = entry
            self._pending_exchanges.append(entry)

    def _record_findings(self, scanner: str, findings: Sequence[ScanResult]) -> None:
        del scanner  # the finding carries its own scanner name
        if not findings:
            return
        with self._lock:
            self._findings.extend(findings)
            self._pending_findings.extend(findings)

    def _record_phase(self, phase: str, detail: str) -> None:
        event = PhaseEvent(at=datetime.now(UTC), phase=phase, detail=detail)
        with self._lock:
            self._pending_phases.append(event)

    # ------------------------------------------------------------------
    # Draining — called on the UI thread
    # ------------------------------------------------------------------

    def drain(self) -> DrainedEvents:
        """Take everything buffered since the last call."""
        with self._lock:
            drained = DrainedEvents(
                exchanges=self._pending_exchanges,
                findings=self._pending_findings,
                phases=self._pending_phases,
            )
            self._pending_exchanges = []
            self._pending_findings = []
            self._pending_phases = []
        return drained
