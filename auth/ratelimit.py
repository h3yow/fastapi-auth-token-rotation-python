"""限流：按调用主体的并发安全固定窗口限流。

语义：
- 窗口起点按 wall-clock 对齐（window = floor(now / window_seconds)），
  因此服务重启后无需任何持久化状态，行为也是确定的：
  重启等价于「当前窗口计数清零」，窗口边界不漂移。
- 计数与判定在同一把锁内完成，高并发下不会因竞态而失准。
- reset() 清空全部计数，重置后行为与冷启动完全一致。
"""

from __future__ import annotations

import threading
import time
from typing import Callable


class RateLimiter:
    """固定窗口限流器。"""

    def __init__(self, max_requests: int, window_seconds: int,
                 now: Callable[[], float] | None = None) -> None:
        if max_requests < 1:
            raise ValueError("max_requests 必须 >= 1")
        if window_seconds < 1:
            raise ValueError("window_seconds 必须 >= 1")
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._now = now or time.time
        self._lock = threading.Lock()
        # key -> (窗口编号, 当前窗口内已计数)
        self._counters: dict[str, tuple[int, int]] = {}

    def _window_index(self, now: float) -> int:
        return int(now // self._window_seconds)

    def check(self, key: str) -> tuple[bool, int, int]:
        """对 key 计一次数。

        返回 (是否放行, 剩余额度, 重试等待秒数)。
        被拒时 retry_after 为到下一窗口起点的秒数（至少 1 秒）。
        """
        now = self._now()
        window = self._window_index(now)
        with self._lock:
            cur_window, count = self._counters.get(key, (window, 0))
            if cur_window != window:
                # 窗口已滚动（或首次访问 / 重启后），计数从零开始。
                cur_window, count = window, 0
            count += 1
            self._counters[key] = (cur_window, count)
            allowed = count <= self._max_requests
            remaining = max(0, self._max_requests - count)

        retry_after = 0
        if not allowed:
            retry_after = max(1, int((window + 1) * self._window_seconds - now) + 1)
        return allowed, remaining, retry_after

    def reset(self) -> None:
        """清空全部限流状态，重置后行为与冷启动一致。"""
        with self._lock:
            self._counters.clear()
