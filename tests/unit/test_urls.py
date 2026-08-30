"""Tests for URL normalisation helpers."""

from __future__ import annotations

import pytest

from scanner.utils.urls import (
    absolutize,
    normalize_url,
    query_params,
    strip_query,
    with_query_param,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("HTTP://Example.TEST/", "http://example.test/"),
        ("http://example.test", "http://example.test/"),
        ("http://example.test:80/a", "http://example.test/a"),
        ("https://example.test:443/a", "https://example.test/a"),
        ("http://example.test/a#frag", "http://example.test/a"),
        ("http://example.test/a?b=2&a=1", "http://example.test/a?a=1&b=2"),
    ],
)
def test_normalize_url(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


def test_normalize_url_is_idempotent() -> None:
    once = normalize_url("http://Example.test:80/x?b=2&a=1#z")
    assert normalize_url(once) == once


@pytest.mark.parametrize(
    "href",
    ["", "#section", "mailto:a@b.test", "javascript:alert(1)", "tel:+100", "data:x"],
)
def test_absolutize_rejects_non_fetchable(href: str) -> None:
    assert absolutize("http://example.test/", href) is None


def test_absolutize_resolves_relative() -> None:
    assert absolutize("http://example.test/dir/page", "../other") == "http://example.test/other"


def test_with_query_param_replaces_only_target() -> None:
    url = "http://example.test/s?a=1&b=2"
    assert with_query_param(url, "a", "X") == "http://example.test/s?a=X&b=2"


def test_with_query_param_appends_when_missing() -> None:
    assert with_query_param("http://example.test/s", "q", "1") == "http://example.test/s?q=1"


def test_query_params_are_sorted_and_unique() -> None:
    assert query_params("http://example.test/s?b=1&a=2&a=3") == ("a", "b")


def test_strip_query() -> None:
    assert strip_query("http://example.test/p?x=1#y") == "http://example.test/p"
