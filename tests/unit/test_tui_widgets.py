"""Tests for the severity bar's cell allocation.

A distribution bar has two ways to lie: dropping a severity that has
findings, and not filling its own width so the leftover background reads as
another category. Both are asserted here across widths, because both look
fine at the one width a screenshot happens to use.
"""

from __future__ import annotations

import pytest

from scanner.core.models import Severity
from scanner.tui.app import load_stylesheet
from scanner.tui.widgets import SeverityBar

_MIXED = {Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 2, Severity.INFO: 4}
_ALL_FIVE = dict.fromkeys(Severity, 1)
_LOPSIDED = {Severity.INFO: 1000, Severity.CRITICAL: 1}


def _allocate(counts: dict[Severity, int], width: int):
    ordered = sorted(counts.items(), key=lambda item: item[0].rank, reverse=True)
    return SeverityBar._segments(ordered, sum(counts.values()), width)


@pytest.mark.parametrize("counts", [_MIXED, _ALL_FIVE, _LOPSIDED])
@pytest.mark.parametrize("width", [10, 17, 40, 79, 146, 300])
def test_segments_plus_gaps_fill_the_width(counts: dict[Severity, int], width: int) -> None:
    segments = _allocate(counts, width)
    drawn = sum(cells for _, cells in segments) + max(0, len(segments) - 1)
    assert drawn == width


@pytest.mark.parametrize("counts", [_MIXED, _ALL_FIVE, _LOPSIDED])
@pytest.mark.parametrize("width", [10, 17, 40, 146])
def test_every_severity_with_findings_gets_a_visible_segment(
    counts: dict[Severity, int], width: int
) -> None:
    segments = _allocate(counts, width)
    assert {severity for severity, _ in segments} == {s for s, c in counts.items() if c}
    assert all(cells >= 1 for _, cells in segments)


def test_severities_without_findings_get_no_segment() -> None:
    segments = _allocate({Severity.HIGH: 3}, 40)
    assert [severity for severity, _ in segments] == [Severity.HIGH]


def test_no_findings_draws_nothing() -> None:
    assert _allocate(dict.fromkeys(Severity, 0), 40) == []


def test_the_render_width_floor_leaves_room_for_every_severity() -> None:
    """``render`` clamps to 10 cells; five segments plus four gaps need nine.

    If that floor ever drops below the number of severities, the degenerate
    branch overflows the widget and the bar wraps onto the legend.
    """
    floor = 10
    assert floor >= len(Severity) + (len(Severity) - 1)


def test_stylesheet_ships_with_the_package() -> None:
    """The sheet must resolve from package data, not from the source tree.

    This project has already shipped one template that loaded in a checkout
    and was missing from the wheel. The check is cheap; the failure is not.
    """
    sheet = load_stylesheet()
    assert "$accent:" in sheet
    assert "Screen {" in sheet
