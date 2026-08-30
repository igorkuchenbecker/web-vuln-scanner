"""Tests for the rate limiter, driven by a fake clock."""

from __future__ import annotations

from scanner.http.rate_limiter import RateLimiter


class FakeClock:
    """A controllable monotonic clock plus a sleep that advances it."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_zero_interval_never_sleeps() -> None:
    clock = FakeClock()
    limiter = RateLimiter(0.0, monotonic=clock.monotonic, sleep=clock.sleep)
    assert limiter.acquire() == 0.0
    assert clock.sleeps == []


def test_first_request_is_immediate() -> None:
    clock = FakeClock()
    limiter = RateLimiter(0.5, monotonic=clock.monotonic, sleep=clock.sleep)
    assert limiter.acquire() == 0.0


def test_second_request_waits_min_interval() -> None:
    clock = FakeClock()
    limiter = RateLimiter(0.5, monotonic=clock.monotonic, sleep=clock.sleep)
    limiter.acquire()
    waited = limiter.acquire()
    assert waited == 0.5
    assert clock.sleeps == [0.5]


def test_spacing_accumulates_across_calls() -> None:
    clock = FakeClock()
    limiter = RateLimiter(1.0, monotonic=clock.monotonic, sleep=clock.sleep)
    limiter.acquire()
    limiter.acquire()
    limiter.acquire()
    # Three requests, one interval each between them.
    assert clock.sleeps == [1.0, 1.0]
