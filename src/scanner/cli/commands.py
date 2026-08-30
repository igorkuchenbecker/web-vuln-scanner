"""Command-line interface.

``argparse`` from the standard library is used deliberately: the CLI surface
is small and stable, and avoiding a third-party CLI framework keeps the
dependency list to what the scanning logic genuinely needs.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from ..core.config import DEFAULT_USER_AGENT, ScanConfig
from ..core.engine import ScanEngine
from ..core.exceptions import ConfigurationError, ScannerError
from ..reporting.console import render_console_report
from ..reporting.html import write_html_report
from ..scanners.base import available_scanners
from ..utils.logging import configure_logging

__all__ = ["main", "build_parser"]

_EPILOG = (
    "Authorised use only. Run this tool exclusively against systems you own or "
    "have explicit, written permission to test."
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Modular, non-destructive web application vulnerability scanner.",
        epilog=_EPILOG,
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Root URL to scan, e.g. https://example.test",
    )

    limits = parser.add_argument_group("crawl limits")
    limits.add_argument("--max-depth", type=int, default=3, help="Maximum crawl depth.")
    limits.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl.")
    limits.add_argument(
        "--max-requests", type=int, default=500, help="Hard cap on total requests."
    )

    transport = parser.add_argument_group("transport")
    transport.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (s).")
    transport.add_argument(
        "--max-redirects", type=int, default=5, help="Maximum redirects to follow."
    )
    transport.add_argument(
        "--max-response-bytes",
        type=int,
        default=2 * 1024 * 1024,
        help="Maximum response body size to read.",
    )
    transport.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (staging targets only).",
    )

    pace = parser.add_argument_group("pacing")
    pace.add_argument("--delay", type=float, default=0.5, help="Minimum delay between requests (s).")
    pace.add_argument(
        "--requests-per-second",
        type=float,
        default=None,
        help="Cap request rate; combined with --delay, the stricter wins.",
    )
    pace.add_argument(
        "--concurrency", type=int, default=1, help="Worker threads (1-8, default 1)."
    )

    shaping = parser.add_argument_group("request shaping")
    shaping.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent header.")
    shaping.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="Extra request header (repeatable).",
    )
    shaping.add_argument(
        "--cookie",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Request cookie (repeatable).",
    )

    scope = parser.add_argument_group("scope")
    scope.add_argument(
        "--scope-host",
        action="append",
        default=[],
        metavar="HOST",
        help="Additional in-scope host (repeatable).",
    )
    scope.add_argument(
        "--allow-subdomains",
        action="store_true",
        help="Treat subdomains of in-scope hosts as in scope.",
    )
    scope.add_argument(
        "--path-prefix",
        default=None,
        help="Restrict scope to URLs under this path prefix.",
    )

    selection = parser.add_argument_group("scanner selection")
    selection.add_argument(
        "--scanner",
        action="append",
        default=[],
        choices=list(available_scanners()),
        help="Run only the named scanner (repeatable). Default: all.",
    )

    output = parser.add_argument_group("output")
    output.add_argument("--output", default=None, metavar="FILE.html", help="Write an HTML report.")
    output.add_argument("--no-color", action="store_true", help="Disable coloured console output.")
    verbosity = output.add_mutually_exclusive_group()
    verbosity.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    verbosity.add_argument("--quiet", action="store_true", help="Only log warnings and errors.")

    return parser


def _parse_headers(raw_headers: Sequence[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in raw_headers:
        if ":" not in item:
            raise ConfigurationError(f"invalid --header (expected NAME:VALUE): {item!r}")
        name, value = item.split(":", 1)
        if not name.strip():
            raise ConfigurationError(f"invalid --header name: {item!r}")
        headers[name.strip()] = value.strip()
    return headers


def _parse_cookies(raw_cookies: Sequence[str]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in raw_cookies:
        if "=" not in item:
            raise ConfigurationError(f"invalid --cookie (expected NAME=VALUE): {item!r}")
        name, value = item.split("=", 1)
        if not name.strip():
            raise ConfigurationError(f"invalid --cookie name: {item!r}")
        cookies[name.strip()] = value.strip()
    return cookies


def _config_from_args(args: argparse.Namespace) -> ScanConfig:
    return ScanConfig(
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        max_requests=args.max_requests,
        timeout=args.timeout,
        max_redirects=args.max_redirects,
        max_response_bytes=args.max_response_bytes,
        verify_tls=not args.insecure,
        delay=args.delay,
        requests_per_second=args.requests_per_second,
        concurrency=args.concurrency,
        user_agent=args.user_agent,
        headers=_parse_headers(args.header),
        cookies=_parse_cookies(args.cookie),
        allow_subdomains=args.allow_subdomains,
        extra_hosts=tuple(args.scope_host),
        path_prefix=args.path_prefix,
        enabled_scanners=tuple(args.scanner),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = configure_logging(verbose=args.verbose, quiet=args.quiet)

    try:
        config = _config_from_args(args)
    except ConfigurationError as exc:
        parser.error(str(exc))
        return 2  # unreachable: parser.error exits, kept for type-checkers

    if args.insecure:
        logger.warning("TLS verification disabled (--insecure)")

    try:
        report = ScanEngine(config).run(args.target)
    except ConfigurationError as exc:
        parser.error(str(exc))
        return 2
    except ScannerError as exc:
        logger.error("scan aborted: %s", exc)
        return 1

    render_console_report(report, no_color=args.no_color)

    if args.output:
        write_html_report(report, args.output)
        logger.info("HTML report written to %s", args.output)

    # Exit non-zero when actionable (non-INFO) findings exist, so the tool is
    # usable as a CI gate.
    actionable = [f for f in report.findings if f.severity.rank > 0]
    return 1 if actionable else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
