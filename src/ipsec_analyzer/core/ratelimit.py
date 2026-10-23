"""In-process login rate limiter.

Single-instance correctness only: a multi-instance deployment must back this with
Redis (shared counters) — that limitation is deliberate and documented rather than
silently pretending process-local limits are global.
"""

import threading
import time
from collections import defaultdict


class LoginRateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> list[float]:
        attempts = [t for t in self._attempts[key] if now - t < self._window]
        self._attempts[key] = attempts
        return attempts

    def is_limited(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key, time.monotonic())) >= self._max

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            self._recent(key, now).append(now)

    def clear(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
