"""URL normalisation helpers.

Normalisation is what stops the crawler from looping: ``/a``, ``/a/``,
``/a#frag`` and ``/a?b=1&a=2`` must collapse to a stable identity, otherwise
the frontier grows without bound on any site with fragments or reordered
query strings.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

__all__ = [
    "normalize_url",
    "absolutize",
    "registrable_host",
    "query_params",
    "with_query_param",
    "strip_query",
]

_DEFAULT_PORTS = {"http": 80, "https": 443}
_NON_HTTP_SCHEMES = frozenset(
    {"mailto", "javascript", "tel", "data", "ftp", "file", "about", "sms"}
)


def normalize_url(url: str) -> str:
    """Return a canonical form of ``url``.

    Lower-cases scheme and host, drops the fragment, removes a default port,
    sorts query parameters and normalises an empty path to ``/``.
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()

    netloc = hostname
    if parts.port is not None and parts.port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{hostname}:{parts.port}"

    path = parts.path or "/"
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((scheme, netloc, path, query, ""))


def absolutize(base_url: str, href: str) -> str | None:
    """Resolve ``href`` against ``base_url``.

    Returns ``None`` for empty links, pure fragments and non-HTTP schemes
    (``mailto:``, ``javascript:`` ...), which are not fetchable targets.
    """
    candidate = href.strip()
    if not candidate or candidate.startswith("#"):
        return None

    scheme = urlsplit(candidate).scheme.lower()
    if scheme in _NON_HTTP_SCHEMES:
        return None

    resolved = urljoin(base_url, candidate)
    if urlsplit(resolved).scheme.lower() not in {"http", "https"}:
        return None
    return normalize_url(resolved)


def registrable_host(url: str) -> str:
    """Return the lower-cased host of ``url`` without the port."""
    return (urlsplit(url).hostname or "").lower()


def query_params(url: str) -> tuple[str, ...]:
    """Return the query parameter names of ``url``, de-duplicated and sorted."""
    names = {name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)}
    return tuple(sorted(names))


def with_query_param(url: str, name: str, value: str) -> str:
    """Return ``url`` with ``name`` replaced by ``value``.

    Every other parameter is preserved so the request stays as close to the
    observed traffic as possible; only the tested parameter changes.
    """
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    updated = [(key, value if key == name else existing) for key, existing in pairs]
    if name not in {key for key, _ in pairs}:
        updated.append((name, value))
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(updated), "")
    )


def strip_query(url: str) -> str:
    """Return ``url`` without its query string or fragment."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
