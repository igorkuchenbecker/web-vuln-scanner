"""Session construction and the request budget.

Two concerns live here because both are process-wide state that the HTTP
client depends on but should not own: how a ``requests.Session`` is built,
and how many requests the run is still allowed to make.
"""

from __future__ import annotations

import threading

import requests

from ..core.config import ScanConfig

__all__ = ["RequestBudget", "SessionFactory"]


class RequestBudget:
    """A thread-safe countdown of the requests a run may still send.

    This is the last line of defence against a runaway scan: even if a
    scanner loops, it cannot send more than ``limit`` requests in total.
    """

    def __init__(self, limit: int) -> None:
        if limit <= 0:
            raise ValueError("limit must be > 0")
        self._limit = limit
        self._used = 0
        self._lock = threading.Lock()

    @property
    def limit(self) -> int:
        """Total number of requests allowed for the run."""
        return self._limit

    @property
    def used(self) -> int:
        """Number of requests already consumed."""
        with self._lock:
            return self._used

    @property
    def remaining(self) -> int:
        """Number of requests still available."""
        with self._lock:
            return self._limit - self._used

    def try_consume(self) -> bool:
        """Consume one unit; return ``False`` when the budget is exhausted."""
        with self._lock:
            if self._used >= self._limit:
                return False
            self._used += 1
            return True


class SessionFactory:
    """Creates pre-configured :class:`requests.Session` objects.

    ``requests.Session`` is not documented as thread-safe, so the HTTP client
    keeps one session per thread and gets it from here rather than sharing a
    single object; this keeps the client safe to use from multiple threads.
    """

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    def create(self) -> requests.Session:
        """Return a new session carrying the configured headers and cookies."""
        session = requests.Session()
        session.max_redirects = max(self._config.max_redirects, 1)
        session.headers.update({"User-Agent": self._config.user_agent})
        session.headers.update(dict(self._config.headers))
        for name, value in self._config.cookies.items():
            session.cookies.set(name, value)
        return session
