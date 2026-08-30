"""Tests for scope enforcement."""

from __future__ import annotations

import pytest

from scanner.core.exceptions import ConfigurationError
from scanner.core.scope import Scope


def test_target_host_is_in_scope() -> None:
    scope = Scope.from_target("https://example.test/app")
    assert scope.is_in_scope("https://example.test/app/page")
    assert scope.is_in_scope("https://example.test/other")


def test_external_host_is_out_of_scope() -> None:
    scope = Scope.from_target("https://example.test/")
    assert not scope.is_in_scope("https://evil.test/")
    assert not scope.is_in_scope("https://sub.example.test/")


def test_subdomains_allowed_when_enabled() -> None:
    scope = Scope.from_target("https://example.test/", allow_subdomains=True)
    assert scope.is_in_scope("https://api.example.test/")
    assert not scope.is_in_scope("https://example.test.evil.test/")


def test_extra_hosts_are_in_scope() -> None:
    scope = Scope.from_target("https://example.test/", extra_hosts=("https://api.example.test",))
    assert scope.is_in_scope("https://api.example.test/v1")


def test_path_prefix_restricts_scope() -> None:
    scope = Scope.from_target("https://example.test/app", path_prefix="/app")
    assert scope.is_in_scope("https://example.test/app/x")
    assert not scope.is_in_scope("https://example.test/admin")


def test_non_http_scheme_is_out_of_scope() -> None:
    scope = Scope.from_target("https://example.test/")
    assert not scope.is_in_scope("ftp://example.test/")


@pytest.mark.parametrize("bad", ["ftp://example.test", "notaurl", "http://"])
def test_invalid_target_rejected(bad: str) -> None:
    with pytest.raises(ConfigurationError):
        Scope.from_target(bad)
