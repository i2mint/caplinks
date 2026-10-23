from datetime import datetime, timedelta, timezone

import pytest

from caplinks import (
    CapabilityLinks,
    RateLimiter,
    ScryptHasher,
    SlidingWindowLimiter,
    is_expired,
    parse_expires,
)

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
PW = "correct horse"


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def links(clock):
    return CapabilityLinks(hasher=ScryptHasher(n=2**4), clock=clock)


def test_smoke_create_open_unlock_revoke():
    """The one-command path, every seam on its default."""
    links = CapabilityLinks()
    rec = links.create({"doc": "d1"}, password=PW)
    state, stored = links.status(rec["token"])
    assert state == "ok" and stored["doc"] == "d1"
    assert links.check_password(stored, PW)
    cookie = links.unlock_value(stored)
    assert links.unlocked(stored, cookie, max_age_s=60)
    links.revoke(rec["token"])
    assert links.status(rec["token"]) == ("missing", None)


def test_create_keeps_host_fields_and_never_returns_the_hash(links):
    rec = links.create({"root": {"id": "x"}, "docs": {"x": ["a.md"]}}, password=PW)
    assert rec["root"] == {"id": "x"} and rec["protected"] is True
    assert "password" not in rec
    stored = links.store[rec["token"]]
    assert stored["password"].startswith("scrypt$") and PW not in stored["password"]
    assert stored["expires"] == (T0 + timedelta(days=7)).isoformat()


def test_create_refuses_reserved_fields_and_short_passwords(links):
    with pytest.raises(ValueError, match="link's own"):
        links.create({"expires": "never"})
    with pytest.raises(ValueError, match="at least 8"):
        links.create(password="short")
    assert links.create(password=None)["protected"] is False


def test_status_ok_expired_missing(links, clock):
    tok = links.create(expires="1h")["token"]
    assert links.status(tok)[0] == "ok"
    clock.t = T0 + timedelta(hours=1)
    assert links.status(tok)[0] == "expired"
    assert links.status("A" * 22) == ("missing", None)
    assert links.status("../etc") == ("missing", None)


def test_a_record_the_store_cannot_vouch_for_is_missing(clock):
    class Picky(dict):
        def __getitem__(self, k):
            raise ValueError("damaged")

    links = CapabilityLinks(Picky(), clock=clock)
    links.store["A" * 22] = {"token": "A" * 22}
    assert links.record("A" * 22) is None


def test_a_record_filed_under_another_token_grants_nothing(links):
    rec = links.create()
    other = "B" * 22
    links.store[other] = dict(links.store[rec["token"]])
    assert links.record(other) is None and links.status(other)[0] == "missing"


def test_list_newest_first_and_all_adds_inactive(links, clock):
    a = links.create(expires="1h")["token"]
    clock.t = T0 + timedelta(minutes=1)
    b = links.create()["token"]
    c = links.create()["token"]
    links.revoke(c)
    assert [r["token"] for r in links.list()] == [b, a]
    clock.t = T0 + timedelta(hours=2)
    assert [r["token"] for r in links.list()] == [b]
    everything = links.list(include_inactive=True)
    assert {r["token"] for r in everything} == {a, b, c}
    assert all("password" not in r for r in everything)
    assert {r["token"]: r["active"] for r in everything} == {
        a: False,
        b: True,
        c: False,
    }


def test_revoke_is_idempotent_clears_the_hash_and_raises_on_unknown(links, clock):
    tok = links.create(password=PW)["token"]
    first = links.revoke(tok)
    clock.t = T0 + timedelta(hours=1)
    assert links.revoke(tok)["revoked"] == first["revoked"]
    assert links.store[tok]["password"] is None
    with pytest.raises(KeyError):
        links.revoke("C" * 22)


def test_unlock_value_lifecycle(links, clock):
    rec = links.store[links.create(password=PW)["token"]]
    value = links.unlock_value(rec)
    assert links.unlocked(rec, value, max_age_s=3600)
    assert not links.unlocked(
        rec, value[:-1] + ("1" if value[-1] == "0" else "0"), max_age_s=3600
    )
    assert not links.unlocked(rec, None, max_age_s=3600)
    assert not links.unlocked(rec, "nonsense", max_age_s=3600)
    clock.t = T0 + timedelta(hours=2)
    assert not links.unlocked(rec, value, max_age_s=3600)  # too old


def test_a_new_password_ends_every_unlock(links):
    rec = links.store[links.create(password=PW)["token"]]
    value = links.unlock_value(rec)
    rec = {**rec, "password": links.hasher.hash("another one")}
    assert not links.unlocked(rec, value, max_age_s=3600)


def test_an_open_link_is_always_unlocked(links):
    rec = links.store[links.create()["token"]]
    assert links.unlocked(rec, None, max_age_s=1)
    assert not links.check_password(rec, "anything")


def test_unlock_max_age_never_outlives_the_link(links, clock):
    rec = links.store[links.create(expires="1h")["token"]]
    assert links.unlock_max_age(rec, max_age_s=7 * 86400) == 3600
    assert links.unlock_max_age(rec, max_age_s=60) == 60
    never = links.store[links.create(expires="never")["token"]]
    assert links.unlock_max_age(never, max_age_s=60) == 60
    clock.t = T0 + timedelta(hours=3)
    assert links.unlock_max_age(rec, max_age_s=60) == 1


def test_hasher_rejects_foreign_or_broken_hashes():
    h = ScryptHasher(n=2**4)
    assert not h.verify("argon2$whatever", PW)
    assert not h.verify("scrypt$not$enough", PW)
    assert not h.verify(None, PW)
    assert h.hash(PW) != h.hash(PW)  # salted


@pytest.mark.parametrize(
    "value, expected",
    [
        ("30m", T0 + timedelta(minutes=30)),
        ("12H", T0 + timedelta(hours=12)),
        ("2w", T0 + timedelta(weeks=2)),
        ("2026-01-02", datetime(2026, 1, 2, 23, 59, 59, tzinfo=timezone.utc)),
        ("2026-01-02T10:00:00Z", datetime(2026, 1, 2, 10, tzinfo=timezone.utc)),
        ("2026-01-02T10:00:00", datetime(2026, 1, 2, 10, tzinfo=timezone.utc)),
        (
            datetime(2026, 2, 1, tzinfo=timezone.utc),
            datetime(2026, 2, 1, tzinfo=timezone.utc),
        ),
    ],
)
def test_parse_expires_reads_what_people_write(value, expected):
    assert parse_expires(value, now=T0) == expected.isoformat()


@pytest.mark.parametrize("value", [None, "", "never", " None "])
def test_parse_expires_never(value):
    assert parse_expires(value, now=T0) is None


@pytest.mark.parametrize("value", ["2025-12-31", "yesterday", "0d"])
def test_parse_expires_refuses_the_past_and_nonsense(value):
    with pytest.raises(ValueError):
        parse_expires(value, now=T0)


def test_is_expired_fails_closed():
    assert is_expired({"expires": 12345})
    assert is_expired({"expires": "not a date"})
    assert not is_expired({})


def test_limiter_bounds_its_keys_and_fits_the_protocol():
    lim = SlidingWindowLimiter(max_per_window=1, max_keys=2, clock=lambda: 0.0)
    assert lim.allow("a") and not lim.allow("a")
    lim.allow("b"), lim.allow("c")  # "a" is evicted
    assert lim.allow("a")
    assert isinstance(lim, RateLimiter)

    class Redisish:  # heed.security.RedisRateLimiter's shape
        def allow(self, key):
            return True

    assert isinstance(Redisish(), RateLimiter)


def test_view_fields_are_reserved_too(links):
    for name in ("protected", "active"):
        with pytest.raises(ValueError, match="link's own"):
            links.create({name: 1})


def test_a_hostile_unlock_value_is_refused_not_raised(links, clock):
    rec = links.record(links.create(password=PW)["token"])
    now = int(clock().timestamp())
    assert not links.unlocked(rec, f"{now}.é", max_age_s=60)


def test_a_revoked_record_is_never_unlocked(links):
    tok = links.create(password=PW)["token"]
    links.revoke(tok)
    assert not links.unlocked(links.record(tok), None, max_age_s=60)


@pytest.mark.parametrize(
    "damage",
    [{"password": 123}, {"created": 5}, {"expires": 7}, {"revoked": []}],
)
def test_a_record_with_mistyped_fields_is_missing_and_spares_the_list(links, damage):
    good = links.create()["token"]
    bad = links.create()["token"]
    links.store[bad] = {**links.store[bad], **damage}
    assert links.record(bad) is None and links.status(bad)[0] == "missing"
    assert [r["token"] for r in links.list(include_inactive=True)] == [good]


def test_a_store_raising_oserror_closes_the_link(clock):
    class Flaky(dict):
        def __getitem__(self, k):
            raise OSError("ssh dropped")

    assert CapabilityLinks(Flaky(), clock=clock).record("A" * 22) is None


def test_record_is_a_copy(links):
    tok = links.create(password=PW)["token"]
    links.record(tok).pop("password")
    assert links.record(tok)["password"]


@pytest.mark.parametrize("value", ["99999999d", "9999-12-31T23:59:59-05:00"])
def test_parse_expires_far_future_is_a_value_error(value):
    with pytest.raises(ValueError, match="too far"):
        parse_expires(value, now=T0)


@pytest.mark.parametrize("kw", [{"max_keys": 0}, {"max_per_window": 0}])
def test_limiter_refuses_settings_that_disable_it(kw):
    with pytest.raises(ValueError):
        SlidingWindowLimiter(**kw)
