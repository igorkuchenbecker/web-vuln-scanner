"""Tests for domain models."""

from __future__ import annotations

import pytest

from scanner.core.models import (
    Confidence,
    Endpoint,
    Form,
    FormField,
    HttpMethod,
    Severity,
    SiteMap,
)


def test_severity_ordering() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank
    assert Severity.from_label("HIGH") is Severity.HIGH


def test_severity_unknown_label() -> None:
    with pytest.raises(ValueError):
        Severity.from_label("nope")


def test_form_field_submittable() -> None:
    assert FormField("q", "text").is_submittable
    assert not FormField("go", "submit").is_submittable


def test_form_baseline_and_fuzzable() -> None:
    form = Form(
        action="http://x.test/s",
        method=HttpMethod.GET,
        fields=(FormField("q", "text", "hi"), FormField("go", "submit", "Go")),
        source_url="http://x.test/",
    )
    assert form.baseline_data() == {"q": "hi", "go": "Go"}
    assert tuple(f.name for f in form.fuzzable_fields()) == ("q",)


def test_sitemap_dedupes_endpoints() -> None:
    site_map = SiteMap()
    endpoint = Endpoint("http://x.test/s", HttpMethod.GET, ("q",))
    assert site_map.add_endpoint(endpoint) is True
    assert site_map.add_endpoint(endpoint) is False
    assert len(site_map.endpoints) == 1


def test_confidence_ranks() -> None:
    assert Confidence.HIGH.rank > Confidence.LOW.rank
