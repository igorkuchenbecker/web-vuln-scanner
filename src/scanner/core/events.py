"""Optional progress callbacks for a running scan.

The CLI needs nothing from a scan until it finishes; a user interface needs
to know what is happening while it happens. Rather than teach the engine
about any particular front end, it accepts a bundle of callbacks and calls
them if they are present.

Two rules make this safe to hand to arbitrary code:

* **Callbacks are advisory.** Dispatch happens through the ``emit_*`` methods
  below, which swallow and log whatever the callback raises. A broken
  observer must never abort an authorised scan, and must never truncate one
  halfway and leave the operator reading a report that looks complete.
* **Callbacks run on the scanning thread.** They are expected to hand the
  event off (append to a queue, set a flag) and return immediately. Anything
  that blocks here slows the scan and, for a rate-limited scanner, silently
  changes the request pacing the operator asked for.

This is the one place in the package where ``except Exception`` is correct:
the callables are supplied by a caller outside the package, so their failure
modes are not part of :class:`~scanner.core.exceptions.ScannerError` and
cannot be enumerated.

``should_cancel`` is polled rather than pushed: the engine asks before each
request instead of being interrupted, so cancellation always lands on a
request boundary and never mid-flight.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from ..utils.logging import get_logger
from .models import HttpExchange, ScanResult

__all__ = ["ScanEvents"]

_log = get_logger("events")


@dataclass(frozen=True, slots=True)
class ScanEvents:
    """Callbacks a front end may supply to observe and steer a scan."""

    #: Called once per completed request hop, with a redacted record of it.
    on_exchange: Callable[[HttpExchange], None] | None = None

    #: Called after each scanner finishes, with its name and its findings.
    on_findings: Callable[[str, Sequence[ScanResult]], None] | None = None

    #: Called when the run enters a new phase (``"crawl"``, ``"scan"``...),
    #: with the phase name and a short human-readable detail.
    on_phase: Callable[[str, str], None] | None = None

    #: Polled before each request. Returning ``True`` ends the run with
    #: :class:`~scanner.core.exceptions.ScanCancelled`.
    should_cancel: Callable[[], bool] | None = None

    def emit_exchange(self, exchange: HttpExchange) -> None:
        """Report a completed request/response pair."""
        self._dispatch("on_exchange", self.on_exchange, exchange)

    def emit_findings(self, scanner: str, findings: Sequence[ScanResult]) -> None:
        """Report the findings produced by one scanner."""
        self._dispatch("on_findings", self.on_findings, scanner, findings)

    def emit_phase(self, phase: str, detail: str = "") -> None:
        """Report that the run has entered ``phase``."""
        self._dispatch("on_phase", self.on_phase, phase, detail)

    def cancelled(self) -> bool:
        """Whether the operator has asked for the run to stop.

        A ``should_cancel`` that raises is read as "not cancelled": a broken
        control did not ask for anything, and guessing that it meant *stop*
        would abort a scan the operator never cancelled.
        """
        if self.should_cancel is None:
            return False
        try:
            return bool(self.should_cancel())
        except Exception:  # noqa: BLE001 - foreign callback, see module docstring
            _log.exception("should_cancel raised; treating the run as not cancelled")
            return False

    @staticmethod
    def _dispatch(name: str, callback: Callable[..., None] | None, *args: object) -> None:
        if callback is None:
            return
        try:
            callback(*args)
        except Exception:  # noqa: BLE001 - foreign callback, see module docstring
            _log.exception("scan event callback %s raised; continuing the scan", name)
