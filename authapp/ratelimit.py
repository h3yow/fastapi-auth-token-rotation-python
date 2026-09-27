"""Per-subject fixed-window rate limiter, thread-safe and deterministic.

Semantics
---------
* A key's window starts on its first observed request (no global alignment),
  so behaviour after process restart or :meth:`reset` is deterministic: the
  next request always opens a fresh window with count = 1.
* Count increment and decision happen in one lock-held critical section, so
  concurrent callers can never lose increments or race past the threshold.
* ``retry_after_seconds`` is the whole seconds remaining until the window
  resets (rounded up), suitable for a ``Retry-After`` header.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class RateLimitResult:
    allowed: bool
    key: str
    count: int
    limit: int
    window_start: float
    window_seconds: int
    now: float = field(compare=False)

    @property
    def window_end(self) -> float:
        return self.window_start + self.window_seconds

    @property
    def retry_after_seconds(self) -> int:
        return max(0, math.ceil(self.window_end - self.now))


class FixedWindowRateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: int,
        clock: Callable[[], float],
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be >= 1")
        self._limit = limit
        self._window_seconds = window_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[float, int]] = {}

    def check(self, key: str) -> RateLimitResult:
        now = self._clock()
        with self._lock:
            state = self._windows.get(key)
            if state is None or now >= state[0] + self._window_seconds:
                window_start = now if state is None else state[0] + self._window_seconds
                count = 1
                self._windows[key] = (window_start, count)
            else:
                window_start, count = state
                count += 1
                self._windows[key] = (window_start, count)

        return RateLimitResult(
            allowed=count <= self._limit,
            key=key,
            count=count,
            limit=self._limit,
            window_start=window_start,
            window_seconds=self._window_seconds,
            now=now,
        )

    def reset(self, key: str | None = None) -> None:
        """Reset one key, or all keys when ``key`` is None."""
        with self._lock:
            if key is None:
                self._windows.clear()
            else:
                self._windows.pop(key, None)
