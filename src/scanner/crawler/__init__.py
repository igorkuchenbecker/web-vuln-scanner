"""Crawler: scope-bounded discovery of pages, endpoints and forms."""

from __future__ import annotations

from .crawler import Crawler, CrawlOutcome
from .parser import extract_forms, extract_links, parse_html

__all__ = ["Crawler", "CrawlOutcome", "extract_forms", "extract_links", "parse_html"]
