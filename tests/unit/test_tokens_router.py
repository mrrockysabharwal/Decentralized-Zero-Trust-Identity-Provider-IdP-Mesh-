"""Unit tests for the JWT Token FastAPI Router (router.py).

Uses the HTTPX TestClient against the router to test HTTP-level behaviour.
All singleton dependencies (keys, ledger, policy engine, revocation store)
are replaced with fresh test instances via module-level monkeypatching.

Tests cover:
  POST /tokens/issue          - Fails closed with HTTP 503 pending verified caller authentication
  POST /tokens/verify         — valid token, expired token, revoked token
  POST /tokens/revoke         - Fails closed with HTTP 503 pending token ownership authorization
  GET  /tokens/public-key     — returns PEM and algorithm
  GET  /tokens/policy/scopes  — returns allowed scopes list
"""

import pytest
import time
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.models import LedgerOperation
from app.modules.ledger.hasher import hash_did_document
from app.modules.tokens import tokens_router
from app.modules.tokens.jwt_engine import generate_signing_keypair, issue_token
from app.modules.tokens.policy import ZeroTrustPolicyEngine
from app.modules.tokens.revocation import TokenRevocationStore
import app.modules.tokens.router as tokens_router_module


# ---------------------------------------------------------------------------
# Test App & Client Setup
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def app_client():
    """Wire a fresh FastAPI test app with isolated token module dependencies."""
    # Fresh Ed25519 keypair
    private_pem, public_pem = generate_signing_keypair()

    # Ledger with one active DID pre-registered
    test_ledger = SimulatedLedger(auto_genesis=True)
    active_did = "did:mesh:key:z6MkuRouterTest001"
    doc_hash = hash_did_document({"id": active_did})
    test_ledger.append_record(
        did=active_did, doc_hash=doc_hash, operation=LedgerOperation.CREATE
    )

    # Policy engine and revocation store
    test_policy = ZeroTrustPolicyEngine(ledger=test_ledger)
    test_revocation = TokenRevocationStore(redis_url="redis://localhost:0/99")
    test_revocation.clear_in_memory()

    # Patch router module singletons
    tokens_router_module._private_key_pem = private_pem
    tokens_router_module._public_key_pem = public_pem
    tokens_router_module._shared_ledger = test_ledger
    tokens_router_module._policy_engine = test_policy
    tokens_router_module._revocation_store = test_revocation

    # Override dependency getters
    tokens_router_module.get_private_key = lambda: private_pem
    tokens_router_module.get_public_key = lambda: public_pem
    tokens_router_module.get_ledger = lambda: test_ledger
    tokens_router_module.get_policy_engine = lambda: test_policy
    tokens_router_module.get_revocation_store = lambda: test_revocation

    # Build the test FastAPI app
    test_app = FastAPI()
    test_app.include_router(tokens_router, prefix="/api/v1")

    return TestClient(test_app), active_did, private_pem, public_pem, test_revocation


# ---------------------------------------------------------------------------
# Test: POST /tokens/issue
# ---------------------------------------------------------------------------


def test_issue_endpoint_fails_closed_without_authenticated_principal(app_client):
    """Ledger registration alone must not authorize token issuance."""
    client, active_did, *_ = app_client
    response = client.post(
        "/api/v1/tokens/issue",
        json={"did": active_did, "scope": ["read:profile"]},
    )
    assert response.status_code == 503
    assert "authenticated did" in response.json()["detail"].lower()


def test_issue_endpoint_cannot_act_for_another_identity(app_client):
    """An unauthenticated caller cannot request a token for an arbitrary DID."""
    client, *_ = app_client
    response = client.post(
        "/api/v1/tokens/issue",
        json={"did": "did:mesh:key:z6MkuAnotherIdentity", "scope": ["read:profile"]},
    )
    assert response.status_code == 503


def test_issue_endpoint_unregistered_did_fails_closed_without_auth(app_client):
    """Unknown DID requests are unavailable before identity authorization."""
    client, *_ = app_client
    response = client.post(
        "/api/v1/tokens/issue",
        json={"did": "did:mesh:key:z6MkuNONEXISTENT", "scope": ["read:profile"]},
    )
    assert response.status_code == 503


def test_issue_endpoint_invalid_scope_fails_closed_without_auth(app_client):
    """Scope validation cannot replace authenticated caller authorization."""
    client, active_did, *_ = app_client
    response = client.post(
        "/api/v1/tokens/issue",
        json={"did": active_did, "scope": ["hack:everything"]},
    )
    assert response.status_code == 503


def test_issue_endpoint_extra_claims_request_fails_closed_without_auth(app_client):
    """Scope escalation payloads cannot bypass missing caller authentication."""
    client, active_did, *_ = app_client
    response = client.post(
        "/api/v1/tokens/issue",
        json={
            "did": active_did,
            "scope": ["read:profile"],
            "extra_claims": {"scope": ["root:admin:unrestricted"]},
        },
    )

    assert response.status_code == 503


# ---------------------------------------------------------------------------
# Test: POST /tokens/verify
# ---------------------------------------------------------------------------


def test_verify_endpoint_valid_token(app_client):
    """Verifying a freshly issued, non-revoked token must return valid=True."""
    client, active_did, private_pem, *_ = app_client

    # Exercise verification independently of the intentionally unavailable
    # HTTP issuance endpoint.
    token, _ = issue_token(
        did=active_did,
        scope=["read:profile"],
        private_key_pem=private_pem,
    )

    # Verify
    response = client.post("/api/v1/tokens/verify", json={"token": token})
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["claims"]["sub"] == active_did


def test_verify_endpoint_invalid_token_string_returns_invalid(app_client):
    """Verifying a garbage string must return valid=False with an error."""
    client, *_ = app_client
    response = client.post("/api/v1/tokens/verify", json={"token": "not.a.real.token"})
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert data["error"] is not None


def test_verify_endpoint_revoked_token_returns_invalid(app_client):
    """A revoked token must be rejected by the verify endpoint."""
    client, active_did, private_pem, _, revocation_store = app_client

    # Issue a token directly and revoke its JTI
    token_str, jti = issue_token(
        did=active_did,
        scope=["read:profile"],
        private_key_pem=private_pem,
        expiry_seconds=3600,
    )
    revocation_store.revoke(jti, ttl_seconds=3600)

    response = client.post("/api/v1/tokens/verify", json={"token": token_str})
    data = response.json()
    assert data["valid"] is False
    assert "revoked" in data["error"].lower()


# ---------------------------------------------------------------------------
# Test: POST /tokens/revoke
# ---------------------------------------------------------------------------


def test_revoke_endpoint_rejects_arbitrary_jti_without_auth(app_client):
    """An unauthenticated caller cannot revoke a JTI belonging to another DID."""
    client, _active_did, private_pem, _public_pem, revocation_store = app_client
    another_did = "did:mesh:key:z6MkuAnotherIdentity"
    _token, jti = issue_token(
        did=another_did,
        scope=["read:profile"],
        private_key_pem=private_pem,
    )
    response = client.post(
        "/api/v1/tokens/revoke",
        json={"jti": jti, "reason": "unauthorized cross-identity revocation"},
    )
    assert response.status_code == 503
    assert "authenticated token ownership" in response.json()["detail"].lower()
    assert revocation_store.is_revoked(jti) is False


# ---------------------------------------------------------------------------
# Test: GET /tokens/public-key
# ---------------------------------------------------------------------------


def test_public_key_endpoint_returns_pem(app_client):
    """The public-key endpoint must return a PEM string and algorithm name."""
    client, *_ = app_client
    response = client.get("/api/v1/tokens/public-key")
    assert response.status_code == 200
    data = response.json()
    assert "PUBLIC KEY" in data["public_key_pem"]
    assert data["algorithm"] == "EdDSA"
    assert data["issuer"] != ""


# ---------------------------------------------------------------------------
# Test: GET /tokens/policy/scopes
# ---------------------------------------------------------------------------


def test_policy_scopes_endpoint_returns_list(app_client):
    """The policy/scopes endpoint must return a non-empty list of scope strings."""
    client, *_ = app_client
    response = client.get("/api/v1/tokens/policy/scopes")
    assert response.status_code == 200
    data = response.json()
    assert "scopes" in data
    assert isinstance(data["scopes"], list)
    assert len(data["scopes"]) > 0
    assert all(isinstance(s, str) for s in data["scopes"])
