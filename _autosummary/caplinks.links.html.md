# caplinks.links

Capability links: a record behind an unguessable token, with an optional password gate.

Knowing the token is the permission. A record is a plain dict, stored in any
`MutableMapping` keyed by token; the generic fields are [`RECORD_FIELDS`](#caplinks.links.RECORD_FIELDS), and a
host puts what the link reaches (its scope) in fields of its own beside them:

```default
{"token": "<22 url-safe chars, 128 random bits>",
 "created": "<iso>", "expires": "<iso>" | None,
 "password": "scrypt$..." | None,     # a hash; the password is never stored
 "revoked": "<iso>" | None,           # a tombstone: a revoked link is missing
 ...the host's fields...}
```

A correct password earns an unlock value (a cookie, for a web host): an HMAC keyed by
the stored hash, so a new password, or a revoke, which clears the hash, ends every open
session at once.

The store contract: a store that cannot vouch for a record (unreadable, damaged, or
missing the host’s own fields) raises `KeyError`, `ValueError` or `OSError` when
it is read, and the link is then missing. A record whose generic fields have the wrong
types is missing too: every failure closes the link.

```pycon
>>> links = CapabilityLinks()
>>> rec = links.create({"what": "report-1"}, password="open sesame", expires="7d")
>>> links.status(rec["token"])[0], rec["protected"], "password" in rec
('ok', True, False)
```

### Module Attributes

| [`RECORD_FIELDS`](#caplinks.links.RECORD_FIELDS)    | the fields every record has; a host's own fields may not reuse these names             |
|-------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| [`DFLT_EXPIRES`](#caplinks.links.DFLT_EXPIRES)     | a link lasts this long unless told otherwise (`"never"` for no expiry)                 |
| [`MIN_PASSWORD_LEN`](#caplinks.links.MIN_PASSWORD_LEN) | the shortest link password accepted (a gate tried from anywhere must not be guessable) |

### Functions

| [`check_token`](#caplinks.links.check_token)(token)    | Return `token`; raise `ValueError` on anything that could not be one.    |
|------------------------------------------------------------------------|--------------------------------------------------------------------------|
| [`new_token`](#caplinks.links.new_token)()           | A fresh link token: 128 random bits, url-safe.                           |
| [`public_record`](#caplinks.links.public_record)(record) | A record without its password hash; `protected` says whether it has one. |

### Classes

| [`CapabilityLinks`](#caplinks.links.CapabilityLinks)([store, hasher, clock, ...])   | Create, read, list and revoke capability links, and gate them on a password.   |
|-------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|

### *class* caplinks.links.CapabilityLinks(store=None, \*, hasher=None, clock=<function now_utc>, min_password_len=8)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Create, read, list and revoke capability links, and gate them on a password.

`store` maps token to record (a `dict` by default, in process); `hasher`
hashes link passwords (stdlib scrypt by default); `clock` returns the current UTC
`datetime` (tests pin it); `min_password_len` is the shortest password accepted.

#### check_password(record, password)

Whether `password` opens `record` (constant time inside the hasher).

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

#### create(fields=None, , password=None, expires='7d')

Make a link carrying the host’s `fields`; return its record without the hash.

`expires` is anything [`caplinks.expiry.parse_expires()`](caplinks.expiry.html.md#caplinks.expiry.parse_expires) reads, 7 days by
default (`"never"` for none); `password` gates the link.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### list(, include_inactive=False)

Every live link, newest first, without hashes; `include_inactive` adds
revoked and expired ones.

Each record gains `active` (neither revoked nor expired).

* **Return type:**
  [`list`](#caplinks.links.CapabilityLinks.list)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### record(token)

A copy of the stored record (hash included), revoked or not; `None` if none.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict) | [`None`](https://docs.python.org/3/builtins/constants.html#None)

#### revoke(token)

End a link now (idempotent). The record stays, as a tombstone.

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

### caplinks.links.DFLT_EXPIRES *= '7d'*

a link lasts this long unless told otherwise (`"never"` for no expiry)

### caplinks.links.MIN_PASSWORD_LEN *= 8*

the shortest link password accepted (a gate tried from anywhere must not be guessable)

### caplinks.links.RECORD_FIELDS *= ('token', 'created', 'expires', 'password', 'revoked')*

the fields every record has; a host’s own fields may not reuse these names

### caplinks.links.check_token(token)

Return `token`; raise `ValueError` on anything that could not be one.

```pycon
>>> check_token("../../etc/passwd")
Traceback (most recent call last):
...
ValueError: not a link token
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### caplinks.links.new_token()

A fresh link token: 128 random bits, url-safe.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### caplinks.links.public_record(record)

A record without its password hash; `protected` says whether it has one.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)
