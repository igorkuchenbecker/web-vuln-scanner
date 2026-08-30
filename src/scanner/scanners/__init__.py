"""Vulnerability scanners.

Importing this package registers every built-in scanner as a side effect, so
that :func:`scanner.scanners.base.available_scanners` reflects the full set
without the engine having to know each module by name.
"""

from __future__ import annotations

from .auth_surface import AuthSurfaceScanner
from .base import (
    ScanContext,
    Scanner,
    available_scanners,
    build_scanners,
    get_scanner,
    register,
)
from .security_headers import SecurityHeadersScanner
from .sqli import SqlInjectionScanner
from .xss import ReflectedXssScanner

__all__ = [
    "ScanContext",
    "Scanner",
    "available_scanners",
    "build_scanners",
    "get_scanner",
    "register",
    "AuthSurfaceScanner",
    "SecurityHeadersScanner",
    "SqlInjectionScanner",
    "ReflectedXssScanner",
]
