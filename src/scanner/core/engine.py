"""Scan orchestration.

The engine wires the pieces together and owns the run's lifecycle: build the
scope and HTTP client, crawl, run each selected scanner with failures
isolated, and assemble a :class:`ScanReport`. It depends on the scanner
*interface* and registry, never on concrete scanner classes, so new scanners
require no change here.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..crawler.crawler import Crawler
from ..http.client import HttpClient

# Importing scanners.base runs scanners/__init__.py, which registers every
# built-in scanner; build_scanners then resolves them by name.
from ..scanners.base import ScanContext, Scanner, build_scanners
from ..utils.logging import get_logger
from ..utils.urls import registrable_host
from .config import ScanConfig
from .events import ScanEvents
from .exceptions import ScanCancelled, ScannerError
from .models import ScanReport, Target
from .scope import Scope

__all__ = ["ScanEngine"]


class ScanEngine:
    """Runs a full scan: crawl, then each selected scanner."""

    def __init__(self, config: ScanConfig, *, events: ScanEvents | None = None) -> None:
        self._config = config
        self._events = events or ScanEvents()
        self._log = get_logger("engine")

    def run(self, target_url: str) -> ScanReport:
        """Scan ``target_url`` and return the aggregated report.

        Raises :class:`~scanner.core.exceptions.ScanCancelled` if the caller's
        ``should_cancel`` callback asked the run to stop. A cancelled run
        produces no report on purpose: a half-crawled target summarised as a
        :class:`~scanner.core.models.ScanReport` reads as "we looked and found
        this much", which is exactly the claim a cancelled scan cannot make.
        Live callers already hold what was found via ``on_findings``.
        """
        scope = Scope.from_target(
            target_url,
            extra_hosts=self._config.extra_hosts,
            allow_subdomains=self._config.allow_subdomains,
            path_prefix=self._config.path_prefix,
        )
        target = self._build_target(target_url)
        scanners = build_scanners(self._config.enabled_scanners or None)
        self._log.info(
            "scanning %s | scope: %s | scanners: %s",
            target.url,
            scope.describe(),
            ", ".join(s.name for s in scanners),
        )

        started = datetime.now(UTC)
        errors: list[str] = []

        with HttpClient(self._config, scope, events=self._events) as client:
            self._events.emit_phase("crawl", f"crawling {target.url}")
            crawl = Crawler(client, self._config, scope).crawl(target.url)
            errors.extend(crawl.errors)
            site_map = crawl.site_map
            self._events.emit_phase(
                "crawled",
                f"{len(site_map.pages)} page(s), {len(site_map.endpoints)} endpoint(s)",
            )

            context = ScanContext(site_map, client)
            findings = []
            for scanner in scanners:
                self._events.emit_phase("scan", scanner.name)
                findings.extend(self._run_scanner(scanner, context, errors))

            requests_sent = client.requests_sent

        finished = datetime.now(UTC)
        self._events.emit_phase("done", f"{len(findings)} finding(s)")
        return ScanReport(
            target=target,
            started_at=started,
            finished_at=finished,
            pages_discovered=len(site_map.pages),
            endpoints_discovered=len(site_map.endpoints),
            forms_discovered=len(site_map.forms),
            requests_sent=requests_sent,
            scanners_run=tuple(s.name for s in scanners),
            findings=findings,
            errors=errors,
        )

    def _run_scanner(self, scanner: Scanner, context: ScanContext, errors: list[str]) -> list:
        """Run one scanner, converting its failure into a recorded error.

        A single scanner blowing up must not lose the findings of the others,
        so scanner-level errors are caught here and reported rather than
        propagated. Cancellation is the exception: it is not this scanner
        failing, it is the operator ending the run, so it passes through
        instead of being recorded as an error and followed by the next check.
        """
        try:
            results = scanner.scan(context)
            self._log.info("scanner %s produced %d finding(s)", scanner.name, len(results))
            self._events.emit_findings(scanner.name, results)
            return results
        except ScanCancelled:
            raise
        except ScannerError as exc:
            message = f"scanner {scanner.name} failed: {exc}"
            self._log.warning(message)
            errors.append(message)
            return []

    @staticmethod
    def _build_target(target_url: str) -> Target:
        from urllib.parse import urlsplit

        parts = urlsplit(target_url)
        return Target(
            url=target_url,
            host=registrable_host(target_url),
            scheme=parts.scheme.lower(),
        )
