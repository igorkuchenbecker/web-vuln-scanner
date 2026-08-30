"""A fake HttpClient for scanner unit tests.

Scanners depend only on ``HttpClient.get``/``post`` and ``.secrets``, so a small
fake keyed on request signature lets each scanner be tested deterministically
without a socket.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from scanner.core.models import HttpMethod
from scanner.http.client import HttpResponse

Responder = Callable[[str, HttpMethod, Mapping[str, str]], HttpResponse]


def make_response(
    url: str,
    body: str = "",
    *,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
    method: HttpMethod = HttpMethod.GET,
) -> HttpResponse:
    """Build an :class:`HttpResponse` with sensible defaults for tests."""
    hdrs = {"Content-Type": "text/html; charset=utf-8"}
    if headers is not None:
        hdrs = dict(headers)
    return HttpResponse(
        url=url,
        status_code=status,
        headers=hdrs,
        body=body,
        elapsed_seconds=0.0,
        request_method=method,
    )


class FakeHttpClient:
    """Routes requests to a user-supplied responder callable."""

    def __init__(self, responder: Responder, *, secrets: tuple[str, ...] = ()) -> None:
        self._responder = responder
        self._secrets = secrets
        self.calls: list[tuple[HttpMethod, str, Mapping[str, str]]] = []

    @property
    def secrets(self) -> tuple[str, ...]:
        return self._secrets

    def get(self, url: str) -> HttpResponse:
        self.calls.append((HttpMethod.GET, url, {}))
        return self._responder(url, HttpMethod.GET, {})

    def post(self, url: str, data: Mapping[str, str]) -> HttpResponse:
        self.calls.append((HttpMethod.POST, url, dict(data)))
        return self._responder(url, HttpMethod.POST, data)
