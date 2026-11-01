"""Unit tests for the Zero-Trust Policy Engine (policy.py).

Tests cover:
  - Happy-path: registered, active DID with valid scopes → ALLOW
  - Deny: DID not registered (no ledger records)
  - Deny: DID deactivated (DEACTIVATE operation is latest)
  - Deny: Ledger integrity compromised (tampered chain)
  - Deny: Scope not in allowed list
  - Deny reason is always a non-empty human-readable string
  - Multiple scope validation (all invalid, some invalid)
"""

import pytest

from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.models import LedgerOperation
from app.modules.ledger.hasher import hash_did_document
from app.modules.tokens.policy import ZeroTrustPolicyEngine
from app.modules.tokens.models import ALLOWED_SCOPES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ledger(*dids_and_ops) -> SimulatedLedger:
    """Create a fresh ledger and append records for each (did, operation) pair."""
    ledger = SimulatedLedger(auto_genesis=True)
    for did, op in dids_and_ops:
        doc_hash = hash_did_document({"id": did, "op": op.value})
        ledger.append_record(did=did, doc_hash=doc_hash, operation=op)
    return ledger


ACTIVE_DID = "did:mesh:key:z6MkuPolicyTest001"
DEACTIVATED_DID = "did:mesh:key:z6MkuPolicyTest002"
UNKNOWN_DID = "did:mesh:key:z6MkuPolicyTestUnknown"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def active_ledger():
    """Ledger containing one active DID."""
    return _make_ledger((ACTIVE_DID, LedgerOperation.CREATE))


@pytest.fixture
def deactivated_ledger():
    """Ledger containing a DID whose latest operation is DEACTIVATE."""
    return _make_ledger(
        (DEACTIVATED_DID, LedgerOperation.CREATE),
        (DEACTIVATED_DID, LedgerOperation.DEACTIVATE),
    )


@pytest.fixture
def tampered_ledger():
    """Ledger with one valid record that is then tampered with."""
    ledger = _make_ledger((ACTIVE_DID, LedgerOperation.CREATE))
    # Tamper with the genesis block's doc_hash to break integrity
    ledger.tamper_record(index=0, field="doc_hash", new_value="a" * 64)
    return ledger


# ---------------------------------------------------------------------------
# Test: Happy path
# ---------------------------------------------------------------------------


def test_policy_allows_registered_active_did(active_ledger):
    """A registered, active DID requesting a valid scope must be ALLOWED."""
    engine = ZeroTrustPolicyEngine(ledger=active_ledger)
    result = engine.evaluate(did=ACTIVE_DID, requested_scope=["read:profile"])

    assert result.allowed is True
    assert result.did == ACTIVE_DID
    assert "read:profile" in result.checked_scope


def test_policy_allows_multiple_valid_scopes(active_ledger):
    """Multiple valid scopes must all pass the policy check."""
    engine = ZeroTrustPolicyEngine(ledger=active_ledger)
    scopes = ["read:profile", "write:did"]
    result = engine.evaluate(did=ACTIVE_DID, requested_scope=scopes)

    assert result.allowed is True
    assert result.checked_scope == scopes


# ---------------------------------------------------------------------------
# Test: DID not registered
# ---------------------------------------------------------------------------


def test_policy_denies_unknown_did(active_ledger):
    """A DID with no ledger records must be DENIED."""
    engine = ZeroTrustPolicyEngine(ledger=active_ledger)
    result = engine.evaluate(did=UNKNOWN_DID, requested_scope=["read:profile"])

    assert result.allowed is False
    assert result.did == UNKNOWN_DID


def test_policy_deny_reason_contains_did_for_unknown(active_ledger):
    """The deny reason for an unknown DID must reference the DID string."""
    engine = ZeroTrustPolicyEngine(ledger=active_ledger)
    result = engine.evaluate(did=UNKNOWN_DID, requested_scope=["read:profile"])

    assert UNKNOWN_DID in result.reason


# ---------------------------------------------------------------------------
# Test: DID deactivated
# ---------------------------------------------------------------------------


def test_policy_denies_deactivated_did(deactivated_ledger):
    """A DID whose latest operation is DEACTIVATE must be DENIED."""
    engine = ZeroTrustPolicyEngine(ledger=deactivated_ledger)
    result = engine.evaluate(did=DEACTIVATED_DID, requested_scope=["read:profile"])

    assert result.allowed is False


def test_policy_deny_reason_mentions_deactivation(deactivated_ledger):
    """The deny reason for a deactivated DID must mention deactivation."""
    engine = ZeroTrustPolicyEngine(ledger=deactivated_ledger)
    result = engine.evaluate(did=DEACTIVATED_DID, requested_scope=["read:profile"])

    assert "deactivat" in result.reason.lower()


# ---------------------------------------------------------------------------
# Test: Ledger integrity failure
# ---------------------------------------------------------------------------


def test_policy_denies_on_tampered_ledger(tampered_ledger):
    """If the ledger fails integrity verification, token issuance must be DENIED."""
    engine = ZeroTrustPolicyEngine(ledger=tampered_ledger)
    result = engine.evaluate(did=ACTIVE_DID, requested_scope=["read:profile"])

    assert result.allowed is False


def test_policy_deny_reason_mentions_integrity(tampered_ledger):
    """The deny reason for a tampered ledger must mention integrity failure."""
    engine = ZeroTrustPolicyEngine(ledger=tampered_ledger)
    result = engine.evaluate(did=ACTIVE_DID, requested_scope=["read:profile"])

    assert "integrity" in result.reason.lower()


# ---------------------------------------------------------------------------
# Test: Invalid scopes
# ---------------------------------------------------------------------------


def test_policy_denies_invalid_scope(active_ledger):
    """A scope not in the allowed list must cause a DENY."""
    engine = ZeroTrustPolicyEngine(ledger=active_ledger)
    result = engine.evaluate(did=ACTIVE_DID, requested_scope=["superadmin:destroy"])

    assert result.allowed is False


def test_policy_deny_reason_lists_invalid_scopes(active_ledger):
    """The deny reason for an invalid scope must list the offending scopes."""
    engine = ZeroTrustPolicyEngine(ledger=active_ledger)
    result = engine.evaluate(did=ACTIVE_DID, requested_scope=["invalid:scope"])

    assert "invalid:scope" in result.reason


def test_policy_denies_if_any_scope_invalid(active_ledger):
    """If one scope is invalid among valid ones, the whole request must be DENIED."""
    engine = ZeroTrustPolicyEngine(ledger=active_ledger)
    result = engine.evaluate(
        did=ACTIVE_DID, requested_scope=["read:profile", "hack:everything"]
    )
    assert result.allowed is False


def test_policy_denies_admin_scope_even_if_custom_allowlist_contains_it(active_ledger):
    """Ordinary token policy must never grant scopes reserved for admin JWTs."""
    engine = ZeroTrustPolicyEngine(
        ledger=active_ledger,
        allowed_scopes=["read:profile", "admin:ledger"],
    )

    result = engine.evaluate(did=ACTIVE_DID, requested_scope=["admin:ledger"])

    assert result.allowed is False
    assert "admin:ledger" not in engine.get_allowed_scopes()


# ---------------------------------------------------------------------------
# Test: Reason string always populated
# ---------------------------------------------------------------------------


def test_policy_result_reason_always_non_empty(active_ledger):
    """PolicyCheckResult.reason must always be a non-empty string."""
    engine = ZeroTrustPolicyEngine(ledger=active_ledger)

    allow_result = engine.evaluate(did=ACTIVE_DID, requested_scope=["read:profile"])
    deny_result = engine.evaluate(did=UNKNOWN_DID, requested_scope=["read:profile"])

    assert allow_result.reason != ""
    assert deny_result.reason != ""


# ---------------------------------------------------------------------------
# Test: get_allowed_scopes
# ---------------------------------------------------------------------------


def test_get_allowed_scopes_returns_list(active_ledger):
    """get_allowed_scopes() must return a non-empty list of strings."""
    engine = ZeroTrustPolicyEngine(ledger=active_ledger)
    scopes = engine.get_allowed_scopes()

    assert isinstance(scopes, list)
    assert len(scopes) > 0
    assert all(isinstance(s, str) for s in scopes)


def test_custom_allowed_scopes_override(active_ledger):
    """Passing custom allowed_scopes should override the defaults."""
    custom_scopes = ["custom:read", "custom:write"]
    engine = ZeroTrustPolicyEngine(ledger=active_ledger, allowed_scopes=custom_scopes)

    result = engine.evaluate(did=ACTIVE_DID, requested_scope=["read:profile"])
    # Default scope should now be invalid
    assert result.allowed is False

    result2 = engine.evaluate(did=ACTIVE_DID, requested_scope=["custom:read"])
    assert result2.allowed is True
