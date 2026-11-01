"""Unit tests for the JWT Token FastAPI Router (router.py).

Uses the HTTPX TestClient against the router to test HTTP-level behaviour.
All singleton dependencies (keys, ledger, policy engine, revocation store)
are replaced with fresh test instances via module-level monkeypatching.

Tests cover:
  POST /tokens/issue          — fail-closed until caller authorization exists
  POST /tokens/verify         — valid token, expired token, revoked token
  POST /tokens/revoke         — fail-closed until token ownership authorization exists
  GET  /tokens/public-key     — returns PEM and algorithm
  GET  /tokens/policy/scopes  — returns allowed scopes list
"""

import pytest
import time
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.models import LedgerOperation
from app.modules.ledger.hasher import hash_did_document
from app.modules.tokens import tokens_router
from app.modules.tokens.jwt_engine import generate_signing_keypair, issue_token
from app.modules.tokens.models import TokenIssueRequest
from app.modules.tokens.policy import ZeroTrustPolicyEngine
from app.modules.tokens.revocation import RevocationStoreUnavailable, TokenRevocationStore
import app.modules.tokens.router as tokens_router_module
import app.modules.revocation_provider as revocation_provider


# ---------------------------------------------------------------------------
# Test App & Client Setup
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def app_client(request):
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
    test_revocation = TokenRevocationStore(
        redis_url="redis://localhost:0/99",
        allow_in_memory_fallback=True,
    )
    test_revocation.clear_in_memory()
    original_revocation_store = revocation_provider._revocation_store
    revocation_provider.set_revocation_store(test_revocation)
    request.addfinalizer(
        lambda: revocation_provider.set_revocation_store(original_revocation_store)
    )

    # Patch router module singletons
    tokens_router_module._private_key_pem = private_pem
    tokens_router_module._public_key_pem = public_pem
    tokens_router_module._shared_ledger = test_ledger
    tokens_router_module._policy_engine = test_policy

    # Override dependency getters
    tokens_router_module.get_private_key = lambda: private_pem
    tokens_router_module.get_public_key = lambda: public_pem
    tokens_router_module.get_ledger = lambda: test_ledger
    tokens_router_module.get_policy_engine = lambda: test_policy

    # Build the test FastAPI app
    test_app = FastAPI()
    test_app.include_router(tokens_router, prefix="/api/v1")

    return TestClient(test_app), active_did, private_pem, public_pem, test_revocation


# ---------------------------------------------------------------------------
# Test: POST /tokens/issue
# ---------------------------------------------------------------------------


def test_issue_endpoint_fails_closed_for_registered_did(app_client):
    """A registered DID is not proof that the caller controls it."""
    client, active_did, *_ = app_client
    response = client.post(
        "/api/v1/tokens/issue",
        json={"did": active_did, "scope": ["read:profile"]},
    )
    assert response.status_code == 503
    assert "authenticated caller authorization" in response.json()["detail"]


def test_issue_and_revoke_without_request_bodies_return_503(app_client):
    """Disabled operations return 503 even when an anonymous caller sends no body."""
    client, *_ = app_client

    issue_response = client.post("/api/v1/tokens/issue")
    revoke_response = client.post("/api/v1/tokens/revoke")

    assert issue_response.status_code == 503
    assert revoke_response.status_code == 503


def test_issue_endpoint_ignores_untrusted_identity_and_scope_for_authorization(app_client):
    """Caller-selected identities/scopes cannot reach the signing path."""
    client, *_ = app_client
    response = client.post(
        "/api/v1/tokens/issue",
        json={
            "did": "did:mesh:key:another-user",
            "scope": ["admin:ledger"],
            "audience": "another-service",
            "extra_claims": {"scope": ["admin:ledger"]},
        },
    )
    assert response.status_code == 503
    assert "access_token" not in response.json()


def test_issue_request_model_rejects_admin_scope_and_caller_audience():
    """The request schema cannot encode admin scopes or select a token audience."""
    with pytest.raises(ValidationError, match="not permitted"):
        TokenIssueRequest(did="did:mesh:key:user", scope=["admin:ledger"])

    with pytest.raises(ValidationError, match="audience"):
        TokenIssueRequest(
            did="did:mesh:key:user",
            scope=["read:profile"],
            audience="another-service",
        )


# ---------------------------------------------------------------------------
# Test: POST /tokens/verify
# ---------------------------------------------------------------------------


def test_verify_endpoint_valid_token(app_client):
    """Verifying a freshly issued, non-revoked token must return valid=True."""
    client, active_did, *_ = app_client

    # Construct a signed token directly so this test covers verification only.
    token, _ = issue_token(
        did=active_did,
        scope=["read:profile"],
        private_key_pem=app_client[2],
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


def test_verify_endpoint_fails_closed_when_revocation_status_is_unavailable(
    app_client, monkeypatch
):
    client, active_did, private_pem, *_ = app_client
    token, _ = issue_token(
        did=active_did,
        scope=["read:profile"],
        private_key_pem=private_pem,
    )

    class UnavailableStore:
        def is_revoked(self, _jti):
            raise RevocationStoreUnavailable("simulated Redis timeout")

    monkeypatch.setattr(
        tokens_router_module,
        "get_revocation_store",
        lambda: UnavailableStore(),
    )
    response = client.post("/api/v1/tokens/verify", json={"token": token})

    assert response.status_code == 503


# ---------------------------------------------------------------------------
# Test: POST /tokens/revoke
# ---------------------------------------------------------------------------


def test_revoke_endpoint_fails_closed_without_mutating_revocation_state(app_client):
    """A caller-supplied JTI does not authorize revocation."""
    client, _, _, _, revocation_store = app_client
    jti = "router-test-jti-to-revoke"
    response = client.post(
        "/api/v1/tokens/revoke",
        json={"jti": jti, "reason": "test revocation"},
    )
    assert response.status_code == 503
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
    assert "admin:ledger" not in data["scopes"]
