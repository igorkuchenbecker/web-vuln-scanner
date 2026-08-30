"""Core domain: configuration, models, scope, engine and exceptions."""

from __future__ import annotations

from .config import ScanConfig
from .exceptions import ScannerError
from .models import (
    Confidence,
    Endpoint,
    Form,
    FormField,
    ScanReport,
    ScanResult,
    Severity,
    SiteMap,
    Target,
)
from .scope import Scope

__all__ = [
    "ScanConfig",
    "ScannerError",
    "Confidence",
    "Endpoint",
    "Form",
    "FormField",
    "ScanReport",
    "ScanResult",
    "Severity",
    "SiteMap",
    "Target",
    "Scope",
]
