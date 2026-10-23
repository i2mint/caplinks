"""Password hashing for a link's password gate: a protocol and a stdlib default.

A link password is a gate, not an account: it is hashed once when the link is made and
checked on each unlock. :class:`ScryptHasher` needs nothing beyond the standard library;
anything with the same two methods (an argon2id adapter, say) fits the ``hasher`` seam
of :class:`caplinks.CapabilityLinks`.

>>> h = ScryptHasher(n=2**4)  # tiny cost, for the example only
>>> stored = h.hash("correct horse")
>>> stored.startswith("scrypt$"), h.verify(stored, "correct horse"), h.verify(stored, "x")
(True, True, False)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@runtime_checkable
class PasswordHasher(Protocol):
    """What a link needs to gate on a password: ``verify`` returns a bool, never raises."""

    def hash(self, password: str) -> str: ...

    def verify(self, hashed: str, password: str) -> bool: ...


@dataclass(frozen=True)
class ScryptHasher:
    """Stdlib ``hashlib.scrypt``, stored as ``scrypt$n$r$p$salt$hash`` (base64).

    The parameters travel with the hash, so raising ``n`` later still verifies old
    hashes. ``n=2**14, r=8`` costs ~16 MB and tens of ms per check, which a host's
    attempt limit (:mod:`caplinks.limits`) bounds.
    """

    n: int = 2**14
    r: int = 8
    p: int = 1
    salt_bytes: int = 16
    dklen: int = 32

    def _derive(self, password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=self.dklen,
            maxmem=2 * 128 * r * n + 2**20,
        )

    def hash(self, password: str) -> str:
        salt = secrets.token_bytes(self.salt_bytes)
        dk = self._derive(password, salt, self.n, self.r, self.p)
        b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
        return f"scrypt${self.n}${self.r}${self.p}${b64(salt)}${b64(dk)}"

    def verify(self, hashed: str, password: str) -> bool:
        try:
            scheme, n, r, p, salt, dk = hashed.split("$")
            if scheme != "scrypt":
                return False
            expected = base64.b64decode(dk)
            got = self._derive(password, base64.b64decode(salt), int(n), int(r), int(p))
        except (ValueError, TypeError, AttributeError):
            return False
        return hmac.compare_digest(got, expected)
