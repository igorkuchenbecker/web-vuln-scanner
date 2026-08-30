"""Central configuration.

Every operational limit lives here so that no module has to invent a magic
number, and so a reviewer can audit the tool's blast radius by reading a
single file. Defaults are deliberately conservative: a default run is slow
and small rather than fast and noisy.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from .exceptions import ConfigurationError

__all__ = ["ScanConfig", "DEFAULT_USER_AGENT"]

DEFAULT_USER_AGENT = "web-vuln-scanner/1.0 (+authorized-testing-only)"


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Immutable configuration for a single scan run."""

    # Crawling limits
    max_depth: int = 3
    max_pages: int = 50
    max_requests: int = 500

    # Transport limits
    timeout: float = 10.0
    max_redirects: int = 5
    max_response_bytes: int = 2 * 1024 * 1024
    verify_tls: bool = True

    # Politeness
    delay: float = 0.5
    requests_per_second: float | None = None

    # Request shaping
    user_agent: str = DEFAULT_USER_AGENT
    headers: Mapping[str, str] = field(default_factory=dict)
    cookies: Mapping[str, str] = field(default_factory=dict)

    # Scope
    allow_subdomains: bool = False
    extra_hosts: tuple[str, ...] = ()
    path_prefix: str | None = None

    # Scanner selection ( empty == run every registered scanner )
    enabled_scanners: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self._require_positive("max_depth", self.max_depth, allow_zero=True)
        self._require_positive("max_pages", self.max_pages)
        self._require_positive("max_requests", self.max_requests)
        self._require_positive("timeout", self.timeout)
        self._require_positive("max_response_bytes", self.max_response_bytes)

        if self.max_redirects < 0:
            raise ConfigurationError("max_redirects must be >= 0")
        if self.delay < 0:
            raise ConfigurationError("delay must be >= 0")
        if self.requests_per_second is not None and self.requests_per_second <= 0:
            raise ConfigurationError("requests_per_second must be > 0")

    @staticmethod
    def _require_positive(name: str, value: float, *, allow_zero: bool = False) -> None:
        if allow_zero and value < 0:
            raise ConfigurationError(f"{name} must be >= 0")
        if not allow_zero and value <= 0:
            raise ConfigurationError(f"{name} must be > 0")

    @property
    def min_interval(self) -> float:
        """Minimum number of seconds between two requests.

        The stricter of ``delay`` and ``1 / requests_per_second`` wins, so the
        two knobs can never cancel each other out.
        """
        interval = self.delay
        if self.requests_per_second is not None:
            interval = max(interval, 1.0 / self.requests_per_second)
        return interval

    def with_overrides(self, **overrides: object) -> ScanConfig:
        """Return a copy of this config with ``overrides`` applied."""
        return replace(self, **overrides)  # type: ignore[arg-type]
