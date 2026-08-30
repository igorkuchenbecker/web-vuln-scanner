"""Tests for configuration validation and derived values."""

from __future__ import annotations

import pytest

from scanner.core.config import ScanConfig
from scanner.core.exceptions import ConfigurationError


def test_defaults_are_conservative() -> None:
    config = ScanConfig()
    assert config.max_depth == 3
    assert config.delay == 0.5
    assert config.verify_tls is True


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_pages": 0},
        {"timeout": 0},
        {"delay": -1},
        {"requests_per_second": 0},
        {"concurrency": 0},
        {"concurrency": 9},
        {"max_redirects": -1},
    ],
)
def test_invalid_config_rejected(kwargs: dict) -> None:
    with pytest.raises(ConfigurationError):
        ScanConfig(**kwargs)


def test_min_interval_uses_stricter_of_delay_and_rps() -> None:
    assert ScanConfig(delay=0.1, requests_per_second=2).min_interval == pytest.approx(0.5)
    assert ScanConfig(delay=1.0, requests_per_second=2).min_interval == pytest.approx(1.0)


def test_with_overrides_returns_new_config() -> None:
    base = ScanConfig()
    changed = base.with_overrides(max_pages=10)
    assert changed.max_pages == 10
    assert base.max_pages == 50
