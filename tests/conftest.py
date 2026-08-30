"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from tests.fixtures.vulnerable_app import VulnerableAppServer


@pytest.fixture()
def vulnerable_app():
    """Start the deliberately vulnerable app on a random localhost port."""
    with VulnerableAppServer() as app:
        yield app
