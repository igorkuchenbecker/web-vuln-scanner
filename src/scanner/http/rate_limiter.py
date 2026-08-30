"""Request pacing.

A single :class:`RateLimiter` instance is shared by the crawler and every
scanner, so the configured rate is a property of the whole run rather than of
each component. It is thread-safe because the engine may fan out scanners
across a small worker pool.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

__all__ = ["RateLimiter"]


class RateLimiter:
    """Enforces a minimum interval between consecutive requests."""

    def __init__(
        self,
        min_interval: float,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Create a limiter allowing one request every ``min_interval`` seconds.

        ``monotonic`` and ``sleep`` are injected so tests can drive the clock
        instead of really waiting.
        """
        if min_interval < 0:
            raise ValueError("min_interval must be >= 0")
        self._min_interval = min_interval
        self._monotonic = monotonic
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_allowed: float | None = None

    @property
    def min_interval(self) -> float:
        """Configured minimum spacing between requests, in seconds."""
        return self._min_interval

    def acquire(self) -> float:
        """Block until the next request is allowed; return the time waited.

        The slot is reserved while holding the lock and the sleep happens
        outside it, so N threads spread out over N intervals instead of all
        waking at the same instant.
        """
        if self._min_interval == 0:
            return 0.0

        with self._lock:
            now = self._monotonic()
            if self._next_allowed is None or self._next_allowed <= now:
                slot = now
            else:
                slot = self._next_allowed
            self._next_allowed = slot + self._min_interval

        wait = slot - self._monotonic()
        if wait > 0:
            self._sleep(wait)
            return wait
        return 0.0
