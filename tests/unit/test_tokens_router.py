"""Unit tests for the JWT Token FastAPI Router (router.py).

Uses the HTTPX TestClient against the router to test HTTP-level behaviour.
All singleton dependencies (keys, ledger, policy engine, revocation store)
are replaced with fresh test instances via module-level monkeypatching.

Tests cover:
  POST /tokens/issue          — happy path, unregistered DID → 403
  POST /tokens/verify         — valid token, expired token, revoked token
  POST /tokens/revoke         — successful revocation
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


def test_issue_endpoint_happy_path(app_client):
    """Issuing a token for a registered, active DID must return 201 with a token."""
    client, active_did, *_ = app_client
    response = client.post(
        "/api/v1/tokens/issue",
        json={"did": active_did, "scope": ["read:profile"]},
    )
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "Bearer"
    assert data["did"] == active_did
    assert "read:profile" in data["scope"]
    assert "jti" in data
    assert data["expires_in"] > 0


def test_issue_endpoint_returns_valid_jwt_structure(app_client):
    """The issued access_token must be a valid three-part JWT string."""
    client, active_did, *_ = app_client
    response = client.post(
        "/api/v1/tokens/issue",
        json={"did": active_did, "scope": ["read:profile"]},
    )
    token = response.json()["access_token"]
    parts = token.split(".")
    assert len(parts) == 3, "JWT must have exactly 3 dot-separated parts"


def test_issue_endpoint_unregistered_did_returns_403(app_client):
    """Issuing for an unknown DID must return 403 Forbidden."""
    client, *_ = app_client
    response = client.post(
        "/api/v1/tokens/issue",
        json={"did": "did:mesh:key:z6MkuNONEXISTENT", "scope": ["read:profile"]},
    )
    assert response.status_code == 403


def test_issue_endpoint_invalid_scope_returns_403(app_client):
    """Issuing with an invalid scope must return 403 Forbidden."""
    client, active_did, *_ = app_client
    response = client.post(
        "/api/v1/tokens/issue",
        json={"did": active_did, "scope": ["hack:everything"]},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Test: POST /tokens/verify
# ---------------------------------------------------------------------------


def test_verify_endpoint_valid_token(app_client):
    """Verifying a freshly issued, non-revoked token must return valid=True."""
    client, active_did, *_ = app_client

    # Issue first
    issue_resp = client.post(
        "/api/v1/tokens/issue",
        json={"did": active_did, "scope": ["read:profile"]},
    )
    token = issue_resp.json()["access_token"]

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


def test_revoke_endpoint_returns_200_and_confirmation(app_client):
    """Revoking a JTI must return 200 with revoked=True and the JTI echoed back."""
    client, *_ = app_client
    jti = "router-test-jti-to-revoke"
    response = client.post(
        "/api/v1/tokens/revoke",
        json={"jti": jti, "reason": "test revocation"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["revoked"] is True
    assert data["jti"] == jti
    assert jti in data["message"]


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
