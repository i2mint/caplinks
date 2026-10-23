"""Capability links: an unguessable token, an optional password gate, expiry, attempt limits.

The parts every app needs to hand someone a link to one thing, with no account: the
token is the permission, a password may gate it, it expires, it can be revoked, and
password attempts are limited. Standard library only; no web framework. What a link
reaches (its scope) and how it is served stay with the app.

>>> links = CapabilityLinks()  # records in a dict; pass any MutableMapping to persist
>>> rec = links.create({"doc": "report-1"}, password="open sesame", expires="7d")
>>> state, stored = links.status(rec["token"])
>>> state, links.check_password(stored, "open sesame")
('ok', True)
>>> cookie = links.unlock_value(stored)
>>> links.unlocked(stored, cookie, max_age_s=3600)
True
"""

from caplinks.expiry import is_expired, now_utc, parse_expires
from caplinks.limits import RateLimiter, SlidingWindowLimiter
from caplinks.links import (
    DFLT_EXPIRES,
    MIN_PASSWORD_LEN,
    RECORD_FIELDS,
    CapabilityLinks,
    check_token,
    new_token,
    public_record,
)
from caplinks.passwords import PasswordHasher, ScryptHasher

__all__ = [
    "CapabilityLinks",
    "DFLT_EXPIRES",
    "MIN_PASSWORD_LEN",
    "PasswordHasher",
    "RECORD_FIELDS",
    "RateLimiter",
    "ScryptHasher",
    "SlidingWindowLimiter",
    "check_token",
    "is_expired",
    "new_token",
    "now_utc",
    "parse_expires",
    "public_record",
]
