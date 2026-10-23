# caplinks.expiry

When a link stops working: reading an expiry the way a person writes one.

An expiry is stored as an ISO UTC timestamp (or `None` for never). [`parse_expires()`](#caplinks.expiry.parse_expires)
reads what a person types (`7d`, `2026-11-01`, an ISO timestamp, `never`);
[`is_expired()`](#caplinks.expiry.is_expired) checks a record against the clock and fails closed on a value it
cannot read.

### Module Attributes

| [`DURATION_UNITS`](#caplinks.expiry.DURATION_UNITS)   | duration suffixes accepted by [`parse_expires()`](#caplinks.expiry.parse_expires) (`30m`, `12h`, `7d`, `2w`)   |
|-------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| [`NEVER`](#caplinks.expiry.NEVER)            | words that mean "no expiry"                                                                                                 |

### Functions

| [`expires_at`](#caplinks.expiry.expires_at)(record)              | The record's expiry as a UTC `datetime`, `None` for never.                          |
|----------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| [`is_expired`](#caplinks.expiry.is_expired)(record, \*[, now])   | True when the record has an expiry and it is reached (a bad one counts as reached). |
| [`now_utc`](#caplinks.expiry.now_utc)()                       | The current time, UTC, second precision (the clock every default reads).            |
| [`parse_expires`](#caplinks.expiry.parse_expires)(value, \*[, now]) | An expiry as an ISO UTC timestamp, or `None` for never.                             |

### caplinks.expiry.DURATION_UNITS *= {'d': 'days', 'h': 'hours', 'm': 'minutes', 'w': 'weeks'}*

duration suffixes accepted by [`parse_expires()`](#caplinks.expiry.parse_expires) (`30m`, `12h`, `7d`, `2w`)

### caplinks.expiry.NEVER *= frozenset({'', 'never', 'no', 'none'})*

words that mean “no expiry”

### caplinks.expiry.expires_at(record)

The record’s expiry as a UTC `datetime`, `None` for never.

Raises `ValueError` on a value that is not a timestamp.

* **Return type:**
  [`datetime`](https://docs.python.org/3/library/datetime.html#datetime.datetime) | [`None`](https://docs.python.org/3/builtins/constants.html#None)

### caplinks.expiry.is_expired(record, , now=None)

True when the record has an expiry and it is reached (a bad one counts as reached).

```pycon
>>> is_expired({"expires": None}), is_expired({"expires": "garbage"})
(False, True)
```

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

### caplinks.expiry.now_utc()

The current time, UTC, second precision (the clock every default reads).

* **Return type:**
  [`datetime`](https://docs.python.org/3/library/datetime.html#datetime.datetime)

### caplinks.expiry.parse_expires(value, , now=None)

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
