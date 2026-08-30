"""Report renderers for the console and for self-contained HTML."""

from __future__ import annotations

from .console import render_console_report
from .html import render_html_report, write_html_report

__all__ = ["render_console_report", "render_html_report", "write_html_report"]
