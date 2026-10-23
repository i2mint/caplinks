# caplinks.limits

Limiting password attempts: the `allow(key) -> bool` protocol and an in-memory default.

A host decides what to count (one client on one link, every wrong password a link
takes, …) and keys the limiter accordingly. The protocol is the shape of
`heed.security`’s limiters, so its `RedisRateLimiter` (one count shared by every
worker) fits wherever a [`RateLimiter`](#caplinks.limits.RateLimiter) is asked for.

### Module Attributes

| [`DFLT_MAX_PER_WINDOW`](#caplinks.limits.DFLT_MAX_PER_WINDOW)   | attempts one key may make in each window, by default                |
|------------------------------------------------------------------------|---------------------------------------------------------------------|
| [`DFLT_MAX_KEYS`](#caplinks.limits.DFLT_MAX_KEYS)         | keys tracked at most, so a flood of addresses cannot exhaust memory |

### Classes

| [`RateLimiter`](#caplinks.limits.RateLimiter)(\*args, \*\*kwargs)                 | Decide whether one more attempt keyed by `key` is allowed now.            |
|--------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| [`SlidingWindowLimiter`](#caplinks.limits.SlidingWindowLimiter)(\*[, max_per_window, ...]) | At most `max_per_window` hits per key per window; in memory, per process. |

### caplinks.limits.DFLT_MAX_KEYS *= 50000*

keys tracked at most, so a flood of addresses cannot exhaust memory

### caplinks.limits.DFLT_MAX_PER_WINDOW *= 10*

attempts one key may make in each window, by default

### *class* caplinks.limits.RateLimiter(\*args, \*\*kwargs)

Bases: [`Protocol`](https://docs.python.org/3/library/typing.html#typing.Protocol)

Decide whether one more attempt keyed by `key` is allowed now.

### *class* caplinks.limits.SlidingWindowLimiter(\*, max_per_window=10, window_s=300.0, max_keys=50000, clock=<built-in function monotonic>)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

At most `max_per_window` hits per key per window; in memory, per process.

Each worker counts alone (two workers allow twice the attempts); pass a shared
limiter when that matters. The least recently seen keys are dropped past
`max_keys`.

```pycon
>>> t = [0.0]
>>> lim = SlidingWindowLimiter(max_per_window=2, window_s=10, clock=lambda: t[0])
>>> [lim.allow("a"), lim.allow("a"), lim.allow("a"), lim.allow("b")]
[True, True, False, True]
>>> t[0] = 10.0; lim.allow("a")
True
```
