"""Scope enforcement: the safety boundary of the whole tool.

Every outbound request funnels through :meth:`Scope.is_in_scope`. The scope
is built once from the user-supplied target and is immutable afterwards, so
nothing discovered mid-scan (a redirect, a link, a form action) can widen the
set of hosts the scanner is allowed to touch.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ..utils.urls import normalize_url, registrable_host
from .exceptions import ConfigurationError

__all__ = ["Scope"]


@dataclass(frozen=True, slots=True)
class Scope:
    """An immutable set of authorised hosts plus an optional path prefix."""

    target_url: str
    hosts: frozenset[str]
    path_prefix: str = "/"
    allow_subdomains: bool = False

    @classmethod
    def from_target(
        cls,
        target_url: str,
        *,
        extra_hosts: tuple[str, ...] = (),
        allow_subdomains: bool = False,
        path_prefix: str | None = None,
    ) -> Scope:
        """Build a scope from the target URL.

        ``extra_hosts`` exists for applications legitimately split across
        hostnames (e.g. ``app.example.test`` and ``api.example.test``); the
        operator must name them explicitly, they are never inferred.
        """
        parts = urlsplit(target_url.strip())
        if parts.scheme.lower() not in {"http", "https"}:
            raise ConfigurationError(f"target must be an http(s) URL, got: {target_url!r}")
        host = (parts.hostname or "").lower()
        if not host:
            raise ConfigurationError(f"target has no host: {target_url!r}")

        hosts = {host}
        for extra in extra_hosts:
            extra_host = registrable_host(extra) or extra.strip().lower()
            if not extra_host:
                raise ConfigurationError(f"invalid scope host: {extra!r}")
            hosts.add(extra_host)

        prefix = path_prefix if path_prefix is not None else "/"
        if not prefix.startswith("/"):
            prefix = "/" + prefix

        return cls(
            target_url=normalize_url(target_url),
            hosts=frozenset(hosts),
            path_prefix=prefix,
            allow_subdomains=allow_subdomains,
        )

    def is_in_scope(self, url: str) -> bool:
        """Return whether ``url`` may be requested.

        A URL is in scope when its scheme is HTTP(S), its host is authorised
        and its path sits under the configured prefix.
        """
        parts = urlsplit(url.strip())
        if parts.scheme.lower() not in {"http", "https"}:
            return False

        host = (parts.hostname or "").lower()
        if not host:
            return False
        if not self._host_allowed(host):
            return False

        path = parts.path or "/"
        if self.path_prefix == "/":
            return True
        return path == self.path_prefix or path.startswith(self.path_prefix.rstrip("/") + "/")

    def _host_allowed(self, host: str) -> bool:
        if host in self.hosts:
            return True
        if not self.allow_subdomains:
            return False
        return any(host.endswith("." + allowed) for allowed in self.hosts)

    def describe(self) -> str:
        """Return a human-readable summary for logs and reports."""
        hosts = ", ".join(sorted(self.hosts))
        suffix = " (+subdomains)" if self.allow_subdomains else ""
        return f"{hosts}{suffix} under {self.path_prefix}"
