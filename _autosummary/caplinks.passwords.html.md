# caplinks.passwords

Password hashing for a link’s password gate: a protocol and a stdlib default.

A link password is a gate, not an account: it is hashed once when the link is made and
checked on each unlock. [`ScryptHasher`](#caplinks.passwords.ScryptHasher) needs nothing beyond the standard library;
anything with the same two methods (an argon2id adapter, say) fits the `hasher` seam
of [`caplinks.CapabilityLinks`](caplinks.html.md#caplinks.CapabilityLinks).

```pycon
>>> h = ScryptHasher(n=2**4)  # tiny cost, for the example only
>>> stored = h.hash("correct horse")
>>> stored.startswith("scrypt$"), h.verify(stored, "correct horse"), h.verify(stored, "x")
(True, True, False)
```

### Classes

| [`PasswordHasher`](#caplinks.passwords.PasswordHasher)(\*args, \*\*kwargs)         | What a link needs to gate on a password: `verify` returns a bool, never raises.   |
|---------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| [`ScryptHasher`](#caplinks.passwords.ScryptHasher)([n, r, p, salt_bytes, dklen]) | Stdlib `hashlib.scrypt`, stored as `scrypt$n$r$p$salt$hash` (base64).             |

### *class* caplinks.passwords.PasswordHasher(\*args, \*\*kwargs)

Bases: [`Protocol`](https://docs.python.org/3/library/typing.html#typing.Protocol)

What a link needs to gate on a password: `verify` returns a bool, never raises.

### *class* caplinks.passwords.ScryptHasher(n=16384, r=8, p=1, salt_bytes=16, dklen=32)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Stdlib `hashlib.scrypt`, stored as `scrypt$n$r$p$salt$hash` (base64).

The parameters travel with the hash, so raising `n` later still verifies old
hashes. `n=2**14, r=8` costs ~16 MB and tens of ms per check, which a host’s
attempt limit ([`caplinks.limits`](caplinks.limits.html.md#module-caplinks.limits)) bounds.
