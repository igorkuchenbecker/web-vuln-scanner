"""Breadth-first, scope-bounded crawler.

The crawler only discovers attack surface; it never tests anything. Keeping
discovery and testing apart means a scanner can be unit-tested against a
hand-built :class:`SiteMap`, and the crawler against static HTML.
"""

from __future__ import annotations

from collections import deque

from ..core.config import ScanConfig
from ..core.exceptions import BudgetExceeded, HttpError, ScopeError
from ..core.models import Endpoint, Form, HttpMethod, Page, SiteMap
from ..core.scope import Scope
from ..http.client import HttpClient
from ..utils.logging import get_logger
from ..utils.urls import normalize_url, query_params
from .parser import extract_forms, extract_links

__all__ = ["Crawler", "CrawlOutcome"]


class CrawlOutcome:
    """Result of a crawl: the site map plus non-fatal errors encountered."""

    def __init__(self, site_map: SiteMap, errors: list[str]) -> None:
        self.site_map = site_map
        self.errors = errors


class Crawler:
    """Walks in-scope pages up to the configured depth and page limits."""

    def __init__(self, client: HttpClient, config: ScanConfig, scope: Scope) -> None:
        self._client = client
        self._config = config
        self._scope = scope
        self._log = get_logger("crawler")

    def crawl(self, start_url: str) -> CrawlOutcome:
        """Crawl from ``start_url`` and return everything discovered.

        Transport failures on individual pages are collected and skipped: one
        broken endpoint must not end the run. Budget exhaustion does stop the
        crawl, because continuing would exceed the authorised request count.
        """
        site_map = SiteMap()
        errors: list[str] = []
        start = normalize_url(start_url)

        if not self._scope.is_in_scope(start):
            raise ScopeError(f"start URL is outside the configured scope: {start_url}")

        queue: deque[tuple[str, int]] = deque([(start, 0)])
        visited: set[str] = {start}

        while queue:
            if len(site_map.pages) >= self._config.max_pages:
                self._log.info("page limit reached (%s)", self._config.max_pages)
                break

            url, depth = queue.popleft()
            try:
                response = self._client.get(url)
            except BudgetExceeded as exc:
                errors.append(str(exc))
                self._log.warning("stopping crawl: %s", exc)
                break
            except (HttpError, ScopeError) as exc:
                errors.append(f"{url}: {exc}")
                self._log.warning("skipping %s: %s", url, exc)
                continue

            page = Page(
                url=response.url,
                status_code=response.status_code,
                headers=dict(response.headers),
                content_type=response.content_type,
                body=response.body,
                depth=depth,
            )
            site_map.pages.append(page)
            self._record_get_endpoint(site_map, response.url)

            if not response.is_html or not response.body:
                continue

            self._record_forms(site_map, page)

            if depth >= self._config.max_depth:
                continue

            for link in extract_links(page.body, page.url):
                if link in visited or not self._scope.is_in_scope(link):
                    continue
                visited.add(link)
                queue.append((link, depth + 1))

        self._log.info(
            "crawl finished: %d pages, %d endpoints, %d forms",
            len(site_map.pages),
            len(site_map.endpoints),
            len(site_map.forms),
        )
        return CrawlOutcome(site_map, errors)

    def _record_get_endpoint(self, site_map: SiteMap, url: str) -> None:
        params = query_params(url)
        if not params:
            return
        site_map.add_endpoint(
            Endpoint(url=normalize_url(url), method=HttpMethod.GET, params=params)
        )

    def _record_forms(self, site_map: SiteMap, page: Page) -> None:
        for form in extract_forms(page.body, page.url):
            if not self._scope.is_in_scope(form.action):
                self._log.debug("ignoring out-of-scope form action: %s", form.action)
                continue
            if self._is_known_form(site_map, form):
                continue
            site_map.forms.append(form)
            site_map.add_endpoint(
                Endpoint(
                    url=form.action,
                    method=form.method,
                    params=tuple(f.name for f in form.fuzzable_fields()),
                    form=form,
                )
            )

    @staticmethod
    def _is_known_form(site_map: SiteMap, form: Form) -> bool:
        """Treat forms with the same action, method and fields as duplicates.

        Sitewide search forms would otherwise be re-tested on every page.
        """
        signature = (form.action, form.method, form.field_names)
        return any(
            (known.action, known.method, known.field_names) == signature for known in site_map.forms
        )
