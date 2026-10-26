"""The per-link lock-out: limit password tries, and lock a link that takes too many.

Two counts, because they defend against different things. Tries of one client on one
link are limited so that a guesser locks out only itself; the wrong passwords a link
takes from *everyone* are limited too, and past that the link's unlock is closed for a
while (a distributed guess). A host calls :meth:`AttemptGuard.allow` before it checks a
password and :meth:`AttemptGuard.failed` after a wrong one.

>>> t = [0.0]
>>> guard = AttemptGuard(
...     client_limiter=SlidingWindowLimiter(max_per_window=5, clock=lambda: t[0]),
...     link_limiter=SlidingWindowLimiter(max_per_window=1, clock=lambda: t[0]),
...     lock_s=60, clock=lambda: t[0])
>>> guard.allow("link", "1.2.3.4")
True
>>> guard.failed("link"); guard.failed("link")  # the second one locks the link
>>> guard.allow("link", "5.6.7.8")
False
>>> t[0] = 61.0; guard.allow("link", "5.6.7.8")
True
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from caplinks.limits import (
    DFLT_WINDOW_S,
    RateLimiter,
    SlidingWindowLimiter,
)

#: tries one client gets on one link per window
DFLT_MAX_ATTEMPTS = 10
#: wrong passwords one link takes from everyone per window before it locks
DFLT_MAX_LINK_FAILURES = 100


class AttemptGuard:
    """Decide whether a password try may be made, and lock a link that is being guessed.

    ``client_limiter`` counts every try of one client on one link; ``link_limiter``
    counts the wrong passwords a link takes from everyone and, past its limit, locks the
    link for ``lock_s`` seconds. Both are anything with ``allow(key) -> bool`` (a Redis
    one shares the count between workers); the lock itself is per process. ``clock``
    returns a monotonic time in seconds (tests pin it).
    """

    def __init__(
        self,
        *,
        client_limiter: RateLimiter | None = None,
        link_limiter: RateLimiter | None = None,
        lock_s: float = DFLT_WINDOW_S,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.client_limiter = client_limiter or SlidingWindowLimiter(
            max_per_window=DFLT_MAX_ATTEMPTS, window_s=DFLT_WINDOW_S
        )
        self.link_limiter = link_limiter or SlidingWindowLimiter(
            max_per_window=DFLT_MAX_LINK_FAILURES, window_s=DFLT_WINDOW_S
        )
        self.lock_s = lock_s
        self._clock = clock
        self._locked: dict[str, float] = {}  # link -> when its lock ends
        self._lock = threading.Lock()

    def allow(self, link: str, client: str) -> bool:
        """Whether ``client`` may try a password on ``link`` now (counts the try)."""
        with self._lock:
            ends = self._locked.get(link, 0.0)
            if ends > self._clock():
                return False
            if ends:
                del self._locked[link]  # expired: do not keep it
        return self.client_limiter.allow(f"{link}:{client}")

    def failed(self, link: str) -> None:
        """Record a wrong password on ``link``; lock the link if it takes too many."""
        if self.link_limiter.allow(link):
            return
        with self._lock:
            self._locked[link] = self._clock() + self.lock_s
