"""The single outbound HTTP chokepoint.

No other module calls ``requests`` directly. Centralising it means scope
enforcement, pacing, the request budget, size limits, redirect handling and
error translation are applied to every request by construction rather than by
convention.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from urllib.parse import urljoin

import requests

from ..core.config import ScanConfig
from ..core.events import ScanEvents
from ..core.exceptions import (
    BudgetExceeded,
    RequestFailed,
    ResponseTooLarge,
    ScanCancelled,
    ScopeError,
)
from ..core.models import HttpExchange, HttpMethod
from ..core.scope import Scope
from ..utils.logging import get_logger
from ..utils.redaction import redact_headers, redact_text
from .rate_limiter import RateLimiter
from .session import RequestBudget, SessionFactory

__all__ = ["HttpResponse", "HttpClient"]

_TEXTUAL_TYPES = ("text/", "application/json", "application/xml", "+xml", "+json")


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """An immutable snapshot of a response, decoupled from ``requests``."""

    url: str
    status_code: int
    headers: Mapping[str, str]
    body: str
    elapsed_seconds: float
    redirect_chain: tuple[str, ...] = ()
    truncated: bool = False
    request_method: HttpMethod = HttpMethod.GET
    request_body: Mapping[str, str] = field(default_factory=dict)

    @property
    def content_type(self) -> str:
        """The response's media type, lower-cased and without parameters."""
        raw = self.headers.get("Content-Type", "")
        return raw.split(";", 1)[0].strip().lower()

    @property
    def is_html(self) -> bool:
        """Whether the body can be parsed as HTML."""
        return self.content_type in {"text/html", "application/xhtml+xml"}

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup."""
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None


class HttpClient:
    """Performs scope-checked, rate-limited, budgeted HTTP requests."""

    def __init__(
        self,
        config: ScanConfig,
        scope: Scope,
        *,
        rate_limiter: RateLimiter | None = None,
        budget: RequestBudget | None = None,
        session_factory: SessionFactory | None = None,
        events: ScanEvents | None = None,
    ) -> None:
        self._config = config
        self._scope = scope
        self._rate_limiter = rate_limiter or RateLimiter(config.min_interval)
        self._budget = budget or RequestBudget(config.max_requests)
        self._session_factory = session_factory or SessionFactory(config)
        self._events = events or ScanEvents()
        self._local = threading.local()
        self._sessions: list[requests.Session] = []
        self._sessions_lock = threading.Lock()
        self._seq = 0
        self._seq_lock = threading.Lock()
        self._log = get_logger("http")
        self._secrets = tuple(config.cookies.values()) + tuple(
            value
            for name, value in config.headers.items()
            if name.lower() in {"authorization", "cookie", "x-api-key"}
        )

    @property
    def budget(self) -> RequestBudget:
        """The shared request budget for the run."""
        return self._budget

    @property
    def secrets(self) -> tuple[str, ...]:
        """Operator-supplied secret values that must never be reported."""
        return self._secrets

    @property
    def requests_sent(self) -> int:
        """How many requests have been consumed from the budget so far."""
        return self._budget.used

    def get(self, url: str) -> HttpResponse:
        """Send a GET request."""
        return self.request(HttpMethod.GET, url)

    def post(self, url: str, data: Mapping[str, str]) -> HttpResponse:
        """Send a form-encoded POST request."""
        return self.request(HttpMethod.POST, url, data=data)

    def request(
        self,
        method: HttpMethod,
        url: str,
        *,
        data: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        """Send one request, following redirects manually.

        Redirects are followed by hand (rather than by ``requests``) so every
        hop is scope-checked and charged to the budget; an open redirect on
        the target can therefore never make the scanner touch a third party.
        """
        current_url = url
        chain: list[str] = []
        payload = dict(data or {})

        for hop in range(self._config.max_redirects + 1):
            response = self._send(method, current_url, payload if hop == 0 else None)
            location = response.header("Location")

            if not (300 <= response.status_code < 400 and location):
                return replace(response, redirect_chain=tuple(chain))

            next_url = urljoin(current_url, location)
            chain.append(next_url)
            if not self._scope.is_in_scope(next_url):
                self._log.info("stopping redirect chain at out-of-scope location: %s", next_url)
                return replace(response, redirect_chain=tuple(chain))

            current_url = next_url
            # Subsequent hops are GETs: re-posting a body to a new location is
            # both wrong per RFC 9110 and a way to submit data twice.
            method = HttpMethod.GET
            payload = {}

        raise RequestFailed(f"too many redirects while requesting {url}")

    def close(self) -> None:
        """Close every session created by this client."""
        with self._sessions_lock:
            sessions = list(self._sessions)
            self._sessions.clear()
        for session in sessions:
            session.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = self._session_factory.create()
            self._local.session = session
            with self._sessions_lock:
                self._sessions.append(session)
        return session

    def _send(
        self,
        method: HttpMethod,
        url: str,
        data: Mapping[str, str] | None,
    ) -> HttpResponse:
        """Perform a single hop with every safety control applied."""
        self._check_cancelled()
        if not self._scope.is_in_scope(url):
            raise ScopeError(f"refusing out-of-scope request: {url}")

        # The pacing wait happens before the budget is charged and is followed
        # by a second cancellation check. With a slow ``--delay`` the wait is
        # where a run spends most of its time, so checking only on the way in
        # would leave "stop" unresponsive for as long as the interval.
        self._rate_limiter.acquire()
        self._check_cancelled()

        if not self._budget.try_consume():
            raise BudgetExceeded(f"request budget exhausted after {self._budget.limit} requests")

        self._log.debug("%s %s", method, url)

        try:
            raw = self._session().request(
                method.value,
                url,
                data=dict(data) if data else None,
                timeout=self._config.timeout,
                allow_redirects=False,
                stream=True,
                verify=self._config.verify_tls,
            )
        except requests.exceptions.RequestException as exc:
            raise RequestFailed(f"{method} {url} failed: {exc.__class__.__name__}") from exc

        try:
            body, truncated, body_bytes = self._read_body(raw)
        finally:
            raw.close()

        headers = dict(raw.headers)
        self._log.debug(
            "%s %s -> %s %s",
            method,
            url,
            raw.status_code,
            redact_headers(headers).get("Content-Type", ""),
        )
        response = HttpResponse(
            url=raw.url,
            status_code=raw.status_code,
            headers=headers,
            body=body,
            elapsed_seconds=raw.elapsed.total_seconds(),
            truncated=truncated,
            request_method=method,
            request_body=dict(data or {}),
        )
        self._record(url, method, data, raw, response, body_bytes)
        return response

    def _check_cancelled(self) -> None:
        """Abort the run if the operator asked it to stop."""
        if self._events.cancelled():
            raise ScanCancelled("scan cancelled by the operator")

    def _record(
        self,
        url: str,
        method: HttpMethod,
        data: Mapping[str, str] | None,
        raw: requests.Response,
        response: HttpResponse,
        body_bytes: int,
    ) -> None:
        """Hand a redacted record of the exchange to the observer, if any.

        Skipped entirely when nobody is listening: building the record copies
        two header maps and, when the operator supplied secrets, the whole
        response body. That is wasted work on a CLI run.
        """
        if self._events.on_exchange is None:
            return

        with self._seq_lock:
            self._seq += 1
            seq = self._seq

        request_headers = dict(raw.request.headers) if raw.request is not None else {}
        self._events.emit_exchange(
            HttpExchange(
                seq=seq,
                timestamp=datetime.now(UTC),
                method=method,
                url=url,
                status_code=response.status_code,
                reason=raw.reason or "",
                request_headers=redact_headers(request_headers),
                request_body=self._redact_mapping(data or {}),
                response_headers=redact_headers(response.headers),
                response_body=self._redact(response.body),
                content_type=response.content_type,
                body_bytes=body_bytes,
                elapsed_seconds=response.elapsed_seconds,
                truncated=response.truncated,
            )
        )

    def _redact(self, text: str) -> str:
        """Strip operator secrets from ``text``, skipping the copy when there are none."""
        if not self._secrets:
            return text
        return redact_text(text, self._secrets)

    def _redact_mapping(self, mapping: Mapping[str, str]) -> dict[str, str]:
        return {name: self._redact(value) for name, value in mapping.items()}

    def _read_body(self, raw: requests.Response) -> tuple[str, bool, int]:
        """Read at most ``max_response_bytes`` and decode textual content.

        Returns the decoded body, whether it was truncated, and how many body
        bytes were actually read. That last figure is *what the scanner
        downloaded*, not what the server offered: a non-textual response is
        never read at all and reports zero, while its declared length remains
        visible in the response headers.
        """
        declared = raw.headers.get("Content-Length")
        if declared and declared.isdigit():
            if int(declared) > self._config.max_response_bytes:
                raise ResponseTooLarge(
                    f"{raw.url} declares {declared} bytes, "
                    f"limit is {self._config.max_response_bytes}"
                )

        content_type = raw.headers.get("Content-Type", "").lower()
        if content_type and not any(token in content_type for token in _TEXTUAL_TYPES):
            return "", False, 0

        limit = self._config.max_response_bytes
        chunks: list[bytes] = []
        size = 0
        truncated = False
        try:
            for chunk in raw.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                chunks.append(chunk)
                size += len(chunk)
                if size >= limit:
                    truncated = True
                    break
        except requests.exceptions.RequestException as exc:
            raise RequestFailed(
                f"failed reading body of {raw.url}: {exc.__class__.__name__}"
            ) from exc

        payload = b"".join(chunks)[:limit]
        encoding = raw.encoding or "utf-8"
        return payload.decode(encoding, errors="replace"), truncated, len(payload)
