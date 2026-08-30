"""A deliberately vulnerable web app for local, offline testing.

Built on :mod:`http.server` from the standard library so the test suite needs
no web framework and no network. It intentionally contains classic flaws
(reflected XSS, error- and boolean-based SQL injection, missing security
headers, a login form) so the scanner has something real to detect.

This app binds to localhost only and is for automated testing of THIS scanner.
Do not deploy it.
"""

from __future__ import annotations

import html
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# A tiny in-memory "database" of users, queried with string-built SQL so the
# handler can emulate real injection behaviour without a real database.
_USERS = {"1": "alice", "2": "bob", "3": "carol"}


class _Handler(BaseHTTPRequestHandler):
    """Request handler exposing the vulnerable endpoints."""

    server_version = "VulnApp/1.0"

    def log_message(self, *_args: object) -> None:  # noqa: D401 - silence test noise
        """Suppress default stderr logging during tests."""

    # -- routing -------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        parts = urlsplit(self.path)
        params = parse_qs(parts.query, keep_blank_values=True)
        routes = {
            "/": self._home,
            "/search": self._search_xss,
            "/item": self._item_sqli,
            "/safe": self._safe_reflection,
            "/login": self._login_page,
        }
        handler = routes.get(parts.path, self._not_found)
        handler(params)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(body, keep_blank_values=True)
        if urlsplit(self.path).path == "/login":
            self._login_submit(params)
        else:
            self._not_found(params)

    # -- endpoints -----------------------------------------------------------

    def _home(self, _params: dict[str, list[str]]) -> None:
        self._send_html(
            "<h1>Vulnerable Test App</h1>"
            "<ul>"
            '<li><a href="/search?q=hello">search (reflected XSS)</a></li>'
            '<li><a href="/item?id=1">item (SQL injection)</a></li>'
            '<li><a href="/safe?q=hello">safe reflection</a></li>'
            '<li><a href="/login">login</a></li>'
            "</ul>"
        )

    def _search_xss(self, params: dict[str, list[str]]) -> None:
        term = params.get("q", [""])[0]
        # VULNERABLE: reflects raw input into HTML with no encoding.
        self._send_html(f"<h1>Results</h1><p>You searched for: {term}</p>")

    def _safe_reflection(self, params: dict[str, list[str]]) -> None:
        term = params.get("q", [""])[0]
        # SAFE: reflects, but encodes. The scanner should NOT flag this.
        self._send_html(f"<h1>Results</h1><p>You searched for: {html.escape(term)}</p>")

    def _item_sqli(self, params: dict[str, list[str]]) -> None:
        raw_id = params.get("id", [""])[0]
        query = f"SELECT name FROM users WHERE id = '{raw_id}'"
        result = self._emulate_sql(query, raw_id)
        if result is _SQL_ERROR:
            body = (
                "<h1>Item</h1><p>Database error: You have an error in your SQL "
                f"syntax near '{html.escape(raw_id)}'</p>"
            )
            self._send_html(body, status=500)
            return
        if result:
            names = ", ".join(html.escape(name) for name in result)
            self._send_html(f"<h1>Item</h1><p>Found: {names}</p>")
        else:
            self._send_html("<h1>Item</h1><p>No such item.</p>")

    def _login_page(self, _params: dict[str, list[str]]) -> None:
        self._send_html(
            "<h1>Login</h1>"
            '<form action="/login" method="POST">'
            '<input type="text" name="username">'
            '<input type="password" name="password">'
            '<button type="submit">Sign in</button>'
            "</form>"
        )

    def _login_submit(self, _params: dict[str, list[str]]) -> None:
        # Always fails: the app never authenticates. Present only as surface.
        self._send_html("<h1>Login</h1><p>Invalid credentials.</p>", status=401)

    def _not_found(self, _params: dict[str, list[str]]) -> None:
        self._send_html("<h1>Not Found</h1>", status=404)

    # -- SQL emulation -------------------------------------------------------

    def _emulate_sql(self, _query: str, raw_id: str):
        """Emulate a string-built SQL query's observable behaviour.

        * An unbalanced quote yields a syntax error (error-based signal).
        * ``' OR '1'='1`` returns all rows (boolean-true).
        * ``' AND '1'='2`` returns no rows (boolean-false).
        * A bare id returns that row.
        """
        upper = raw_id.upper()
        if raw_id.count("'") % 2 == 1 and "OR" not in upper and "AND" not in upper:
            return _SQL_ERROR
        if re.search(r"OR\s+'1'\s*=\s*'1", raw_id, re.IGNORECASE):
            return list(_USERS.values())
        if re.search(r"AND\s+'1'\s*=\s*'2", raw_id, re.IGNORECASE):
            return []
        name = _USERS.get(raw_id)
        return [name] if name else []

    # -- helpers -------------------------------------------------------------

    def _send_html(self, body: str, status: int = 200) -> None:
        # VULNERABLE by omission: no CSP, HSTS, X-Frame-Options, etc.
        payload = f"<!DOCTYPE html><html><body>{body}</body></html>".encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _SqlError:
    """Sentinel marking an emulated SQL syntax error."""


_SQL_ERROR = _SqlError()


class VulnerableAppServer:
    """A context-managed, threaded instance of the vulnerable app."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        """The root URL the app is listening on."""
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> VulnerableAppServer:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


if __name__ == "__main__":  # pragma: no cover - manual local use
    with VulnerableAppServer(port=8000) as app:
        print(f"Vulnerable test app on {app.base_url} (Ctrl-C to stop)")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
