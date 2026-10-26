# caplinks.guard

The per-link lock-out: limit password tries, and lock a link that takes too many.

Two counts, because they defend against different things. Tries of one client on one
link are limited so that a guesser locks out only itself; the wrong passwords a link
takes from *everyone* are limited too, and past that the link’s unlock is closed for a
while (a distributed guess). A host calls [`AttemptGuard.allow()`](#caplinks.guard.AttemptGuard.allow) before it checks a
password and [`AttemptGuard.failed()`](#caplinks.guard.AttemptGuard.failed) after a wrong one.

```pycon
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
```

### Module Attributes

| [`DFLT_MAX_ATTEMPTS`](#caplinks.guard.DFLT_MAX_ATTEMPTS)      | tries one client gets on one link per window                            |
|-------------------------------------------------------------------------|-------------------------------------------------------------------------|
| [`DFLT_MAX_LINK_FAILURES`](#caplinks.guard.DFLT_MAX_LINK_FAILURES) | wrong passwords one link takes from everyone per window before it locks |

### Classes

| [`AttemptGuard`](#caplinks.guard.AttemptGuard)(\*[, client_limiter, ...])   | Decide whether a password try may be made, and lock a link that is being guessed.   |
|--------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|

### *class* caplinks.guard.AttemptGuard(\*, client_limiter=None, link_limiter=None, lock_s=300.0, clock=<built-in function monotonic>)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Decide whether a password try may be made, and lock a link that is being guessed.

`client_limiter` counts every try of one client on one link; `link_limiter`
counts the wrong passwords a link takes from everyone and, past its limit, locks the
link for `lock_s` seconds. Both are anything with `allow(key) -> bool` (a Redis
one shares the count between workers); the lock itself is per process. `clock`
returns a monotonic time in seconds (tests pin it; the default limiters use it too).
Keep `lock_s` at least the limiter’s window, or the first failure after a lock ends
locks the link again at once.

#### allow(link, client)

Whether `client` may try a password on `link` now (counts the try).

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

#### failed(link)

Record a wrong password on `link`; lock the link if it takes too many.

* **Return type:**
  [`None`](https://docs.python.org/3/builtins/constants.html#None)

### caplinks.guard.DFLT_MAX_ATTEMPTS *= 10*

tries one client gets on one link per window

### caplinks.guard.DFLT_MAX_LINK_FAILURES *= 100*

wrong passwords one link takes from everyone per window before it locks
