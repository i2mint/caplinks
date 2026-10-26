# caplinks

Capability links: an unguessable token, an optional password gate, expiry, attempt limits.

The parts every app needs to hand someone a link to one thing, with no account: the
token is the permission, a password may gate it, it expires, it can be revoked, and
password attempts are limited. Standard library only; no web framework. What a link
reaches (its scope) and how it is served stay with the app.

```pycon
>>> links = CapabilityLinks()  # records in a dict; pass any MutableMapping to persist
>>> rec = links.create({"doc": "report-1"}, password="open sesame", expires="7d")
>>> state, stored = links.status(rec["token"])
>>> state, links.check_password(stored, "open sesame")
('ok', True)
>>> cookie = links.unlock_value(stored)
>>> links.unlocked(stored, cookie, max_age_s=3600)
True
```

### Functions

| [`check_token`](#caplinks.check_token)(token)              | Return `token`; raise `ValueError` on anything that could not be one.               |
|----------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| [`is_expired`](#caplinks.is_expired)(record, \*[, now])   | True when the record has an expiry and it is reached (a bad one counts as reached). |
| [`new_token`](#caplinks.new_token)()                     | A fresh link token: 128 random bits, url-safe.                                      |
| [`now_utc`](#caplinks.now_utc)()                       | The current time, UTC, second precision (the clock every default reads).            |
| [`parse_expires`](#caplinks.parse_expires)(value, \*[, now]) | An expiry as an ISO UTC timestamp, or `None` for never.                             |
| [`public_record`](#caplinks.public_record)(record)           | A record without its password hash; `protected` says whether it has one.            |

### Classes

| [`CapabilityLinks`](#caplinks.CapabilityLinks)([store, hasher, clock, ...])    | Create, read, list and revoke capability links, and gate them on a password.    |
|--------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| [`PasswordHasher`](#caplinks.PasswordHasher)(\*args, \*\*kwargs)              | What a link needs to gate on a password: `verify` returns a bool, never raises. |
| [`RateLimiter`](#caplinks.RateLimiter)(\*args, \*\*kwargs)                 | Decide whether one more attempt keyed by `key` is allowed now.                  |
| [`ScryptHasher`](#caplinks.ScryptHasher)([n, r, p, salt_bytes, dklen])      | Stdlib `hashlib.scrypt`, stored as `scrypt$n$r$p$salt$hash` (base64).           |
| [`SlidingWindowLimiter`](#caplinks.SlidingWindowLimiter)(\*[, max_per_window, ...]) | At most `max_per_window` hits per key per window; in memory, per process.       |

### *class* caplinks.CapabilityLinks(store=None, \*, hasher=None, clock=<function now_utc>, min_password_len=8)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Create, read, list and revoke capability links, and gate them on a password.

`store` maps token to record (a `dict` by default, in process); `hasher`
hashes link passwords (stdlib scrypt by default); `clock` returns the current UTC
`datetime` (tests pin it); `min_password_len` is the shortest password accepted.

#### check_password(record, password)

Whether `password` opens `record` (constant time inside the hasher).

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

#### create(fields=None, , password=None, expires='7d', token=None)

Make a link carrying the host’s `fields`; return its record without the hash.

`expires` is anything [`caplinks.expiry.parse_expires()`](caplinks.expiry.html.md#caplinks.expiry.parse_expires) reads, 7 days by
default (`"never"` for none); `password` gates the link. `token` gates an
id that already exists (a host whose links must not change): it must look like
a token ([`check_token()`](#caplinks.check_token)) and be unused; leave it out for a fresh one. The
caller then owns the id’s randomness: use 128 random bits, as [`new_token()`](#caplinks.new_token).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### list(, include_inactive=False)

Every live link, newest first, without hashes; `include_inactive` adds
revoked and expired ones.

Each record gains `active` (neither revoked nor expired).

* **Return type:**
  [`list`](#caplinks.CapabilityLinks.list)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### record(token)

A copy of the stored record (hash included), revoked or not; `None` if none.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict) | [`None`](https://docs.python.org/3/builtins/constants.html#None)

#### revoke(token)

End a link now (idempotent). The record stays, as a tombstone.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### set_expires(token, expires)

Move an unrevoked link’s expiry (anything [`parse_expires()`](#caplinks.parse_expires) reads;
`"never"` for none). An expired link may be given a later one; a revoked link
stays revoked (`KeyError`).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### set_password(token, password)

Give an unrevoked link a new password, or `None` to open it.

A new password ends every open unlock at once. A revoked link stays revoked
(`KeyError`).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### status(token)

`("ok" | "expired" | "missing", record)`; a revoked link is `missing`.

* **Return type:**
  [`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict) | [`None`](https://docs.python.org/3/builtins/constants.html#None)]

#### unlock_max_age(record, , max_age_s)

How long an unlock should last, in seconds: `max_age_s`, never past expiry.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

#### unlock_value(record)

What a correct password earns, to send back on later requests: `<epoch>.<mac>`.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### unlocked(record, value, , max_age_s)

Whether `value` is a live unlock of `record` (no password: always).

A revoked record is never unlocked, whatever the caller checked before.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

### *class* caplinks.PasswordHasher(\*args, \*\*kwargs)

Bases: [`Protocol`](https://docs.python.org/3/library/typing.html#typing.Protocol)

What a link needs to gate on a password: `verify` returns a bool, never raises.

### *class* caplinks.RateLimiter(\*args, \*\*kwargs)

Bases: [`Protocol`](https://docs.python.org/3/library/typing.html#typing.Protocol)

Decide whether one more attempt keyed by `key` is allowed now.

### *class* caplinks.ScryptHasher(n=16384, r=8, p=1, salt_bytes=16, dklen=32)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Stdlib `hashlib.scrypt`, stored as `scrypt$n$r$p$salt$hash` (base64).

The parameters travel with the hash, so raising `n` later still verifies old
hashes. `n=2**14, r=8` costs ~16 MB and tens of ms per check, which a host’s
attempt limit ([`caplinks.limits`](caplinks.limits.html.md#module-caplinks.limits)) bounds.

### *class* caplinks.SlidingWindowLimiter(\*, max_per_window=10, window_s=300.0, max_keys=50000, clock=<built-in function monotonic>)

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

### caplinks.check_token(token)

Return `token`; raise `ValueError` on anything that could not be one.

```pycon
>>> check_token("../../etc/passwd")
Traceback (most recent call last):
...
ValueError: not a link token
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### caplinks.is_expired(record, , now=None)

True when the record has an expiry and it is reached (a bad one counts as reached).

```pycon
>>> is_expired({"expires": None}), is_expired({"expires": "garbage"})
(False, True)
```

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

### caplinks.new_token()

A fresh link token: 128 random bits, url-safe.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### caplinks.now_utc()

The current time, UTC, second precision (the clock every default reads).

* **Return type:**
  [`datetime`](https://docs.python.org/3/library/datetime.html#datetime.datetime)

### caplinks.parse_expires(value, , now=None)

An expiry as an ISO UTC timestamp, or `None` for never.

`None`, `""` and `"never"` mean never. Accepts a duration (`30m`, `12h`,
`7d`, `2w`), a date (`2026-11-01`: the END of that day, UTC, so the link works
through the day named), an ISO timestamp (a naive one is UTC), or a `datetime`.
A moment already past is refused.

```pycon
>>> t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
>>> parse_expires("2d", now=t0)
'2026-01-03T00:00:00+00:00'
>>> parse_expires("2026-01-05", now=t0)
'2026-01-05T23:59:59+00:00'
>>> parse_expires("never") is None
True
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str) | [`None`](https://docs.python.org/3/builtins/constants.html#None)

### caplinks.public_record(record)

A record without its password hash; `protected` says whether it has one.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

### Modules

| [`expiry`](caplinks.expiry.html.md#module-caplinks.expiry)       | When a link stops working: reading an expiry the way a person writes one.               |
|--------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| [`limits`](caplinks.limits.html.md#module-caplinks.limits)       | Limiting password attempts: the `allow(key) -> bool` protocol and an in-memory default. |
| [`links`](caplinks.links.html.md#module-caplinks.links)         | Capability links: a record behind an unguessable token, with an optional password gate. |
| [`passwords`](caplinks.passwords.html.md#module-caplinks.passwords) | Password hashing for a link's password gate: a protocol and a stdlib default.           |
