"""Capability links: a record behind an unguessable token, with an optional password gate.

Knowing the token is the permission. A record is a plain dict, stored in any
``MutableMapping`` keyed by token; the generic fields are :data:`RECORD_FIELDS`, and a
host puts what the link reaches (its scope) in fields of its own beside them::

    {"token": "<22 url-safe chars, 128 random bits>",
     "created": "<iso>", "expires": "<iso>" | None,
     "password": "scrypt$..." | None,     # a hash; the password is never stored
     "revoked": "<iso>" | None,           # a tombstone: a revoked link is missing
     ...the host's fields...}

A correct password earns an unlock value (a cookie, for a web host): an HMAC keyed by
the stored hash, so a new password, or a revoke, which clears the hash, ends every open
session at once.

The store contract: a store that cannot vouch for a record (unreadable, damaged, or
missing the host's own fields) raises ``KeyError``, ``ValueError`` or ``OSError`` when
it is read, and the link is then missing. A record whose generic fields have the wrong
types is missing too: every failure closes the link.

>>> links = CapabilityLinks()
>>> rec = links.create({"what": "report-1"}, password="open sesame", expires="7d")
>>> links.status(rec["token"])[0], rec["protected"], "password" in rec
('ok', True, False)
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Mapping, MutableMapping
from datetime import datetime

from caplinks.expiry import expires_at, is_expired, now_utc, parse_expires
from caplinks.passwords import PasswordHasher, ScryptHasher

TOKEN_BYTES = 16  # 128 bits
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")
#: the fields every record has; a host's own fields may not reuse these names
RECORD_FIELDS = ("token", "created", "expires", "password", "revoked")
#: fields the owner's view of a record adds (:func:`public_record`, ``list``)
_VIEW_FIELDS = ("protected", "active")
#: a link lasts this long unless told otherwise (``"never"`` for no expiry)
DFLT_EXPIRES = "7d"
#: the shortest link password accepted (a gate tried from anywhere must not be guessable)
MIN_PASSWORD_LEN = 8
#: an unlock value issued this far in the future still counts (clock skew between workers)
_UNLOCK_SKEW_S = 60


def new_token() -> str:
    """A fresh link token: 128 random bits, url-safe."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def check_token(token: str) -> str:
    """Return ``token``; raise ``ValueError`` on anything that could not be one.

    >>> check_token("../../etc/passwd")
    Traceback (most recent call last):
    ...
    ValueError: not a link token
    """
    if not isinstance(token, str) or not TOKEN_RE.match(token):
        raise ValueError("not a link token")
    return token


def public_record(record: dict) -> dict:
    """A record without its password hash; ``protected`` says whether it has one."""
    out = {k: v for k, v in record.items() if k != "password"}
    out["protected"] = bool(record.get("password"))
    return out


class CapabilityLinks:
    """Create, read, list and revoke capability links, and gate them on a password.

    ``store`` maps token to record (a ``dict`` by default, in process); ``hasher``
    hashes link passwords (stdlib scrypt by default); ``clock`` returns the current UTC
    ``datetime`` (tests pin it); ``min_password_len`` is the shortest password accepted.
    """

    def __init__(
        self,
        store: MutableMapping[str, dict] | None = None,
        *,
        hasher: PasswordHasher | None = None,
        clock: Callable[[], datetime] = now_utc,
        min_password_len: int = MIN_PASSWORD_LEN,
    ):
        self.store = {} if store is None else store
        self.hasher = hasher or ScryptHasher()
        self.clock = clock
        self.min_password_len = min_password_len

    # -- create / read / list / revoke --

    def create(
        self,
        fields: Mapping | None = None,
        *,
        password: str | None = None,
        expires=DFLT_EXPIRES,
        token: str | None = None,
    ) -> dict:
        """Make a link carrying the host's ``fields``; return its record without the hash.

        ``expires`` is anything :func:`caplinks.expiry.parse_expires` reads, 7 days by
        default (``"never"`` for none); ``password`` gates the link. ``token`` gates an
        id that already exists (a host whose links must not change): it must look like
        a token (:func:`check_token`) and be unused; leave it out for a fresh one. The
        caller then owns the id's randomness: use 128 random bits, as :func:`new_token`.
        """
        fields = dict(fields or {})
        if token is not None:
            check_token(token)
            if token in self.store:  # even a damaged record is not free to overwrite
                raise ValueError("a link with this token already exists")
        clash = sorted(set(fields) & {*RECORD_FIELDS, *_VIEW_FIELDS})
        if clash:
            raise ValueError(f"fields {clash} are the link's own; name yours otherwise")
        hashed = self._hash_password(password)
        now = self.clock()
        record = {
            "token": token or new_token(),
            "created": now.isoformat(),
            **fields,
            "expires": parse_expires(expires, now=now),
            "password": hashed,
            "revoked": None,
        }
        self.store[record["token"]] = record
        return public_record(record)

    def record(self, token: str) -> dict | None:
        """A copy of the stored record (hash included), revoked or not; ``None`` if none."""
        try:
            rec = self.store[check_token(token)]
        except (KeyError, ValueError, OSError):
            return None
        if not _well_formed(rec, token):
            return None  # damaged, or filed under another name: grants nothing
        return dict(rec)

    def status(self, token: str) -> tuple[str, dict | None]:
        """``("ok" | "expired" | "missing", record)``; a revoked link is ``missing``."""
        rec = self.record(token)
        if rec is None or rec.get("revoked"):
            return "missing", None
        if is_expired(rec, now=self.clock()):
            return "expired", rec
        return "ok", rec

    def list(self, *, include_inactive: bool = False) -> list[dict]:
        """Every live link, newest first, without hashes; ``include_inactive`` adds
        revoked and expired ones.

        Each record gains ``active`` (neither revoked nor expired).
        """
        now = self.clock()
        out = []
        for token in list(self.store):
            rec = self.record(token)
            if rec is None:
                continue
            rec = public_record(rec)
            rec["active"] = not rec.get("revoked") and not is_expired(rec, now=now)
            if include_inactive or rec["active"]:
                out.append(rec)
        return sorted(out, key=lambda r: r["created"], reverse=True)

    def set_password(self, token: str, password: str | None) -> dict:
        """Give an unrevoked link a new password, or ``None`` to open it.

        A new password ends every open unlock at once. A revoked link stays revoked
        (``KeyError``).
        """
        return self._update(token, password=self._hash_password(password))

    def set_expires(self, token: str, expires) -> dict:
        """Move an unrevoked link's expiry (anything :func:`parse_expires` reads;
        ``"never"`` for none). An expired link may be given a later one; a revoked link
        stays revoked (``KeyError``).
        """
        return self._update(token, expires=parse_expires(expires, now=self.clock()))

    def _update(self, token: str, **changes) -> dict:
        # The store has no compare-and-set: the record is read just before the write (the
        # slow hashing is done by the caller) so a revoke that landed meanwhile is not
        # undone. Hosts with several workers writing the
        # same link still need to serialise writes per token.
        rec = self._unrevoked(token)
        if rec is None:
            raise KeyError(token)
        rec.update(changes)
        self.store[token] = rec
        return public_record(rec)

    def _unrevoked(self, token: str) -> dict | None:
        rec = self.record(token)
        return None if rec is None or rec.get("revoked") else rec

    def _hash_password(self, password: str | None) -> str | None:
        if password is None:
            return None
        if len(password) < self.min_password_len:
            raise ValueError(
                f"a link password needs at least {self.min_password_len} characters "
                "(anyone can try it); omit it for no password"
            )
        return self.hasher.hash(password)

    def revoke(self, token: str) -> dict:
        """End a link now (idempotent). The record stays, as a tombstone."""
        rec = self.record(token)
        if rec is None:
            raise KeyError(token)
        if not rec.get("revoked"):
            rec = {**rec, "revoked": self.clock().isoformat(), "password": None}
            self.store[token] = rec  # no hash left: nothing to guess, no session lives
        return public_record(rec)

    # -- the password gate --

    def check_password(self, record: dict, password: str) -> bool:
        """Whether ``password`` opens ``record`` (constant time inside the hasher)."""
        hashed = record.get("password")
        return bool(hashed) and self.hasher.verify(hashed, password)

    def unlock_value(self, record: dict) -> str:
        """What a correct password earns, to send back on later requests: ``<epoch>.<mac>``."""
        issued = int(self.clock().timestamp())
        return f"{issued}.{_unlock_mac(record, issued)}"

    def unlocked(self, record: dict, value: str | None, *, max_age_s: int) -> bool:
        """Whether ``value`` is a live unlock of ``record`` (no password: always).

        A revoked record is never unlocked, whatever the caller checked before.
        """
        if record.get("revoked"):
            return False
        if not record.get("password"):
            return True
        if not value or "." not in value:
            return False
        issued_s, _, mac = value.partition(".")
        try:
            issued = int(issued_s)
        except ValueError:
            return False
        now = int(self.clock().timestamp())
        if not (now - max_age_s <= issued <= now + _UNLOCK_SKEW_S):
            return False
        expected = _unlock_mac(record, issued)
        return hmac.compare_digest(mac.encode("utf-8"), expected.encode("ascii"))

    def unlock_max_age(self, record: dict, *, max_age_s: int) -> int:
        """How long an unlock should last, in seconds: ``max_age_s``, never past expiry."""
        try:
            ends = expires_at(record)
        except ValueError:
            return 1
        if ends is None:
            return max_age_s
        left = int((ends - self.clock()).total_seconds())
        return max(1, min(max_age_s, left))


def _well_formed(rec, token: str) -> bool:
    """The generic fields have the types every method relies on."""
    optional_str = lambda v: v is None or isinstance(v, str)  # noqa: E731
    return (
        isinstance(rec, dict)
        and rec.get("token") == token
        and isinstance(rec.get("created"), str)
        and all(optional_str(rec.get(k)) for k in ("expires", "password", "revoked"))
    )


def _unlock_mac(record: dict, issued: int) -> str:
    # Keyed by the password hash: it holds a random salt and never leaves the server, and
    # a new password (or a revoke, which clears it) invalidates every unlock at once.
    key = (record.get("password") or "").encode("utf-8")
    msg = f"{record['token']}:{issued}".encode("ascii")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
