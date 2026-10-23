"""Limiting password attempts: the ``allow(key) -> bool`` protocol and an in-memory default.

A host decides what to count (one client on one link, every wrong password a link
takes, ...) and keys the limiter accordingly. The protocol is the shape of
``heed.security``'s limiters, so its ``RedisRateLimiter`` (one count shared by every
worker) fits wherever a :class:`RateLimiter` is asked for.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from typing import Callable, Protocol, runtime_checkable

#: attempts one key may make in each window, by default
DFLT_MAX_PER_WINDOW = 10
DFLT_WINDOW_S = 300.0
#: keys tracked at most, so a flood of addresses cannot exhaust memory
DFLT_MAX_KEYS = 50_000


@runtime_checkable
class RateLimiter(Protocol):
    """Decide whether one more attempt keyed by ``key`` is allowed now."""

    def allow(self, key: str) -> bool: ...


class SlidingWindowLimiter:
    """At most ``max_per_window`` hits per key per window; in memory, per process.

    Each worker counts alone (two workers allow twice the attempts); pass a shared
    limiter when that matters. The least recently seen keys are dropped past
    ``max_keys``.

    >>> t = [0.0]
    >>> lim = SlidingWindowLimiter(max_per_window=2, window_s=10, clock=lambda: t[0])
    >>> [lim.allow("a"), lim.allow("a"), lim.allow("a"), lim.allow("b")]
    [True, True, False, True]
    >>> t[0] = 10.0; lim.allow("a")
    True
    """

    def __init__(
        self,
        *,
        max_per_window: int = DFLT_MAX_PER_WINDOW,
        window_s: float = DFLT_WINDOW_S,
        max_keys: int = DFLT_MAX_KEYS,
        clock: Callable[[], float] = time.monotonic,
    ):
        if max_per_window < 1 or max_keys < 1:
            raise ValueError("max_per_window and max_keys must be at least 1")
        self.max_per_window = max_per_window
        self.window_s = window_s
        self.max_keys = max_keys
        self._clock = clock
        self._hits: OrderedDict[str, deque] = OrderedDict()
        self._lock = threading.Lock()  # web hosts call limiters from a threadpool

    def allow(self, key: str) -> bool:
        with self._lock:
            now = self._clock()
            hits = self._hits.setdefault(key, deque())
            self._hits.move_to_end(key)
            while len(self._hits) > self.max_keys:
                self._hits.popitem(last=False)
            while hits and hits[0] <= now - self.window_s:
                hits.popleft()
            if len(hits) >= self.max_per_window:
                return False
            hits.append(now)
            return True
