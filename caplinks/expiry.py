"""When a link stops working: reading an expiry the way a person writes one.

An expiry is stored as an ISO UTC timestamp (or ``None`` for never). :func:`parse_expires`
reads what a person types (``7d``, ``2026-11-01``, an ISO timestamp, ``never``);
:func:`is_expired` checks a record against the clock and fails closed on a value it
cannot read.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

#: duration suffixes accepted by :func:`parse_expires` (``30m``, ``12h``, ``7d``, ``2w``)
DURATION_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
_DURATION_RE = re.compile(r"^(\d+)\s*([mhdw])$", re.I)
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
#: words that mean "no expiry"
NEVER = frozenset({"never", "none", "no", ""})


def now_utc() -> datetime:
    """The current time, UTC, second precision (the clock every default reads)."""
    return datetime.now(timezone.utc).replace(microsecond=0)


def _as_utc(when: datetime) -> datetime:
    when = when if when.tzinfo else when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).replace(microsecond=0)


def parse_expires(value, *, now: datetime | None = None) -> str | None:
    """An expiry as an ISO UTC timestamp, or ``None`` for never.

    ``None``, ``""`` and ``"never"`` mean never. Accepts a duration (``30m``, ``12h``,
    ``7d``, ``2w``), a date (``2026-11-01``: the END of that day, UTC, so the link works
    through the day named), an ISO timestamp (a naive one is UTC), or a ``datetime``.
    A moment already past is refused.

    >>> t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    >>> parse_expires("2d", now=t0)
    '2026-01-03T00:00:00+00:00'
    >>> parse_expires("2026-01-05", now=t0)
    '2026-01-05T23:59:59+00:00'
    >>> parse_expires("never") is None
    True
    """
    now = now or now_utc()
    if value is None or (isinstance(value, str) and value.strip().lower() in NEVER):
        return None
    if isinstance(value, datetime):
        when = value
    else:
        s = str(value).strip()
        m = _DURATION_RE.match(s)
        if m:
            n, unit = int(m.group(1)), DURATION_UNITS[m.group(2).lower()]
            try:
                when = now + timedelta(**{unit: n})
            except OverflowError:
                raise ValueError(f"expiry {value!r} is too far away") from None
        elif _DATE_RE.fullmatch(s):
            when = datetime.fromisoformat(s).replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
        else:
            try:
                when = datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError(
                    f"not an expiry: {value!r}; give a duration (7d, 12h), a date "
                    "(2026-11-01) or an ISO timestamp"
                ) from None
    try:
        when = _as_utc(when)
    except OverflowError:
        raise ValueError(f"expiry {value!r} is too far away") from None
    if when <= now:
        raise ValueError(f"expiry {when.isoformat()} is already past")
    return when.isoformat()


def expires_at(record: dict) -> datetime | None:
    """The record's expiry as a UTC ``datetime``, ``None`` for never.

    Raises ``ValueError`` on a value that is not a timestamp.
    """
    exp = record.get("expires")
    if exp is None:
        return None
    try:
        return _as_utc(datetime.fromisoformat(exp))
    except (TypeError, OverflowError):
        raise ValueError(f"not a timestamp: {exp!r}") from None


def is_expired(record: dict, *, now: datetime | None = None) -> bool:
    """True when the record has an expiry and it is reached (a bad one counts as reached).

    >>> is_expired({"expires": None}), is_expired({"expires": "garbage"})
    (False, True)
    """
    try:
        when = expires_at(record)
    except ValueError:
        return True  # fail closed
    return when is not None and (now or now_utc()) >= when
