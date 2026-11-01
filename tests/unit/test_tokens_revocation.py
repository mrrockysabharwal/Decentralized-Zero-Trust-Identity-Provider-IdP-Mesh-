"""Unit tests for the Token Revocation Store (revocation.py).

All tests use the in-memory fallback backend so no Redis server is required.
Tests cover:
  - Fresh JTI is not revoked
  - Revoking a JTI marks it as revoked
  - Multiple JTIs tracked independently
  - Cleared store starts fresh
  - backend_type property reflects the active backend
  - End-to-end: revoked JTI rejected by verify flow
"""

import sys
import time
from types import SimpleNamespace

import pytest

from app.modules.tokens.revocation import (
    MAX_TTL_SECONDS,
    RevocationRecordError,
    RevocationStoreCapacityError,
    RevocationStoreUnavailable,
    TokenRevocationStore,
    _RedisRevocationStore,
)
from app.modules.tokens.jwt_engine import generate_signing_keypair, issue_token, verify_token
import jwt as pyjwt


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store():
    """Create an explicitly ephemeral test store without requiring Redis.

    The development fallback is opt-in and remains bounded and TTL-aware.
    """
    s = TokenRevocationStore(
        redis_url="redis://localhost:0/99",
        allow_in_memory_fallback=True,
    )
    s.clear_in_memory()
    return s


@pytest.fixture(scope="module")
def keypair():
    return generate_signing_keypair()


# ---------------------------------------------------------------------------
# Test: Initial state
# ---------------------------------------------------------------------------


def test_fresh_jti_is_not_revoked(store):
    """A JTI that was never revoked must not appear in the deny-list."""
    assert store.is_revoked("some-fresh-jti-abc123") is False


def test_multiple_fresh_jtis_not_revoked(store):
    """Multiple unrevoked JTIs must all return False."""
    jtis = ["jti-alpha", "jti-beta", "jti-gamma"]
    for jti in jtis:
        assert store.is_revoked(jti) is False


# ---------------------------------------------------------------------------
# Test: Revocation
# ---------------------------------------------------------------------------


def test_revoke_and_check_revoked(store):
    """After revoking a JTI it must immediately appear as revoked."""
    jti = "test-revoke-001"
    store.revoke(jti, ttl_seconds=3600)
    assert store.is_revoked(jti) is True


def test_revoke_does_not_affect_other_jtis(store):
    """Revoking one JTI must not affect unrelated JTIs."""
    revoked_jti = "revoked-jti-x"
    other_jti = "clean-jti-y"

    store.revoke(revoked_jti, ttl_seconds=3600)

    assert store.is_revoked(revoked_jti) is True
    assert store.is_revoked(other_jti) is False


def test_revoke_multiple_jtis_independently_tracked(store):
    """Multiple JTIs can be revoked and each is tracked independently."""
    jtis = ["multi-jti-1", "multi-jti-2", "multi-jti-3"]
    for jti in jtis:
        store.revoke(jti, ttl_seconds=3600)

    for jti in jtis:
        assert store.is_revoked(jti) is True


# ---------------------------------------------------------------------------
# Test: Clear
# ---------------------------------------------------------------------------


def test_clear_in_memory_removes_all_revocations(store):
    """clear_in_memory() must remove all previously revoked JTIs."""
    store.revoke("clear-test-jti-1", ttl_seconds=3600)
    store.revoke("clear-test-jti-2", ttl_seconds=3600)

    store.clear_in_memory()

    assert store.is_revoked("clear-test-jti-1") is False
    assert store.is_revoked("clear-test-jti-2") is False


# ---------------------------------------------------------------------------
# Test: backend_type
# ---------------------------------------------------------------------------


def test_backend_type_is_in_memory_when_redis_unavailable(store):
    """The explicit development fallback is labeled as in-memory."""
    assert store.backend_type == "in-memory"
    assert store.is_durable is False


def test_admin_auth_cannot_treat_memory_backend_as_durable(store):
    with pytest.raises(RevocationStoreUnavailable, match="persistence"):
        store.require_durable()


def test_redis_unavailable_without_explicit_fallback_fails_closed(monkeypatch):
    def fail_connection(*_args, **_kwargs):
        raise ConnectionError("simulated connection failure")

    monkeypatch.setitem(sys.modules, "redis", SimpleNamespace(from_url=fail_connection))
    unavailable = TokenRevocationStore(redis_url="redis://unavailable/0")

    assert unavailable.backend_type == "unavailable"
    with pytest.raises(RevocationStoreUnavailable):
        unavailable.is_revoked("admin-jti")


def test_redis_ping_timeout_does_not_enable_memory_fallback(monkeypatch):
    class TimedOutRedis:
        def ping(self):
            raise TimeoutError("simulated ping timeout")

    monkeypatch.setitem(
        sys.modules,
        "redis",
        SimpleNamespace(from_url=lambda *_args, **_kwargs: TimedOutRedis()),
    )
    unavailable = TokenRevocationStore(redis_url="redis://timeout/0")

    assert unavailable.backend_type == "unavailable"
    with pytest.raises(RevocationStoreUnavailable):
        unavailable.is_revoked("admin-jti")


def test_memory_fallback_expires_entries_and_enforces_capacity():
    store = TokenRevocationStore(
        redis_url="redis://localhost:0/99",
        allow_in_memory_fallback=True,
        max_memory_entries=1,
    )
    store.revoke("short-lived-jti", ttl_seconds=1)

    with pytest.raises(RevocationStoreCapacityError):
        store.revoke("second-jti", ttl_seconds=10)

    time.sleep(1.05)
    assert store.is_revoked("short-lived-jti") is False
    store.revoke("second-jti", ttl_seconds=10)
    assert store.is_revoked("second-jti") is True


class _FakeRedis:
    def __init__(self, value=b"1", ttl=60):
        self.value = value
        self.expiry = ttl
        self.last_write = None

    def get(self, _key):
        return self.value

    def ttl(self, _key):
        return self.expiry

    def eval(self, _script, _key_count, key, ttl):
        if self.value not in (None, "1", b"1") or self.expiry == -1:
            raise RuntimeError("malformed fake Redis revocation record")
        if self.value is None or self.expiry == -2 or self.expiry < ttl:
            self.last_write = (key, ttl, "1")
            self.expiry = ttl
            self.value = b"1"
        return self.expiry


def _store_with_redis_client(client):
    store = TokenRevocationStore.__new__(TokenRevocationStore)
    store._backend = _RedisRevocationStore(client)
    return store


def test_redis_operation_timeout_fails_closed():
    class TimeoutRedis(_FakeRedis):
        def get(self, _key):
            raise TimeoutError("simulated Redis read timeout")

        def eval(self, *_args):
            raise TimeoutError("simulated Redis write timeout")

    store = _store_with_redis_client(TimeoutRedis())

    with pytest.raises(RevocationStoreUnavailable):
        store.is_revoked("admin-jti")
    with pytest.raises(RevocationStoreUnavailable):
        store.revoke("new-jti", ttl_seconds=30)


def test_redis_revocation_writes_value_with_expiry():
    redis_client = _FakeRedis(value=None, ttl=-2)
    store = _store_with_redis_client(redis_client)

    store.revoke("redis-test-jti", ttl_seconds=45)

    assert redis_client.last_write == ("revoked_jti:redis-test-jti", 45, "1")
    assert store.is_revoked("redis-test-jti") is True


@pytest.mark.parametrize(
    ("value", "ttl"),
    [(b"unexpected", 60), (b"1", -1), (b"1", MAX_TTL_SECONDS + 1)],
)
def test_malformed_redis_records_fail_closed(value, ttl):
    store = _store_with_redis_client(_FakeRedis(value=value, ttl=ttl))

    with pytest.raises(RevocationRecordError):
        store.is_revoked("admin-jti")


def test_redis_record_expiring_between_read_and_ttl_is_not_revoked():
    store = _store_with_redis_client(_FakeRedis(value=b"1", ttl=-2))

    assert store.is_revoked("just-expired-jti") is False


def test_redis_revocation_ttl_accepts_maximum_and_rejects_above_boundary():
    redis_client = _FakeRedis(value=None, ttl=-2)
    store = _store_with_redis_client(redis_client)

    store.revoke("maximum-retention-jti", ttl_seconds=MAX_TTL_SECONDS)
    assert redis_client.last_write == (
        "revoked_jti:maximum-retention-jti",
        MAX_TTL_SECONDS,
        "1",
    )

    with pytest.raises(ValueError, match="TTL"):
        store.revoke("too-long-retention-jti", ttl_seconds=MAX_TTL_SECONDS + 1)


def test_redis_revocation_update_never_shortens_existing_retention():
    redis_client = _FakeRedis(value=None, ttl=-2)
    store = _store_with_redis_client(redis_client)
    store.revoke("reused-jti", ttl_seconds=120)
    first_write = redis_client.last_write

    store.revoke("reused-jti", ttl_seconds=30)

    assert redis_client.last_write == first_write
    assert redis_client.expiry == 120


def test_memory_revocation_update_never_shortens_existing_retention():
    store = TokenRevocationStore(
        redis_url="redis://localhost:0/99",
        allow_in_memory_fallback=True,
    )
    store.revoke("reused-memory-jti", ttl_seconds=120)
    original_expiry = store._backend._revoked["reused-memory-jti"]

    store.revoke("reused-memory-jti", ttl_seconds=30)

    assert store._backend._revoked["reused-memory-jti"] >= original_expiry


def test_redis_record_with_zero_reported_ttl_is_still_revoked():
    store = _store_with_redis_client(_FakeRedis(value=b"1", ttl=0))

    assert store.is_revoked("expires-within-this-second") is True


# ---------------------------------------------------------------------------
# Test: End-to-end revocation in verify flow
# ---------------------------------------------------------------------------


def test_revoked_jti_causes_verify_to_reject_token(store, keypair):
    """A revoked JTI must be detected during the token verify flow.

    This simulates the router's verify logic: verify signature first,
    then check revocation list.
    """
    private_pem, public_pem = keypair
    token_str, jti = issue_token(
        did="did:mesh:key:z6MkuRevocationTest",
        scope=["read:profile"],
        private_key_pem=private_pem,
        expiry_seconds=3600,
    )

    # Token is valid before revocation
    claims = verify_token(token_str, public_pem)
    assert claims["jti"] == jti
    assert store.is_revoked(jti) is False

    # Revoke it
    store.revoke(jti, ttl_seconds=3600)

    # Now the revocation store reports it as revoked
    assert store.is_revoked(jti) is True

    # The JWT itself is still cryptographically valid (signature/expiry fine),
    # but the application layer must reject it based on the deny-list
    claims_after = verify_token(token_str, public_pem)
    assert claims_after["jti"] == jti  # sig still valid
    assert store.is_revoked(claims_after["jti"]) is True  # but deny-listed
