"""Retry with exponential backoff (stdlib only, so it is unit-testable)."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


def backoff_delays(attempts: int, base: float = 2.0, cap: float = 30.0) -> list[float]:
    """Seconds to wait after each failed attempt except the last: base, 2*base, 4*base ... cap."""
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    return [min(cap, base * 2**i) for i in range(attempts - 1)]


def seconds_until_next(interval: float, elapsed: float) -> float:
    """Sleep so cycles start ``interval`` apart; never negative when a cycle overruns."""
    return max(0.0, interval - elapsed)


def retry(
    call: Callable[[], T],
    *,
    attempts: int = 3,
    base: float = 2.0,
    cap: float = 30.0,
    catch: tuple[type[BaseException], ...] = (Exception,),
    sleep: Callable[[float], None] = time.sleep,
    on_retry: Callable[[int, BaseException, float], None] | None = None,
) -> T:
    """Call ``call`` until it succeeds or ``attempts`` are used up; re-raise the last error."""
    delays = backoff_delays(attempts, base, cap)
    for number in range(1, attempts + 1):
        try:
            return call()
        except catch as exc:
            if number == attempts:
                raise
            delay = delays[number - 1]
            if on_retry:
                on_retry(number, exc, delay)
            sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover
