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

import pytest

from app.modules.tokens.revocation import TokenRevocationStore
from app.modules.tokens.jwt_engine import generate_signing_keypair, issue_token, verify_token
import jwt as pyjwt


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store():
    """Create a fresh in-memory revocation store for each test.

    We pass an invalid Redis URL so it always falls back to in-memory.
    """
    s = TokenRevocationStore(redis_url="redis://localhost:0/99")  # guaranteed to fail connect
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
    """When Redis is unavailable the backend_type must be 'in-memory'."""
    assert store.backend_type == "in-memory"


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
