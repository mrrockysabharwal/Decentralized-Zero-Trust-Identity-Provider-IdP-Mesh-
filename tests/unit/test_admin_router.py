"""
tests/unit/test_admin_router.py — Unit tests for Module D (Admin Dashboard API)
================================================================================

Tests use FastAPI's TestClient with the shared SimulatedLedger, CredentialStore,
and a durable-contract revocation-store test double — no Redis server required.

Coverage:
  - GET /admin/dashboard
  - GET /admin/identities
  - GET /admin/identities/{did}
  - GET /admin/ledger
  - GET /admin/ledger/verify
  - GET /admin/credentials
  - POST /admin/tokens/{jti}/revoke
  - GET /admin/tokens/policy
  - POST /admin/ledger/simulate-tamper
  - GET /admin/health
  - 404/503 error paths
"""

import pytest
import subprocess
import sys
import time
import uuid
from fastapi import FastAPI
from fastapi.testclient import TestClient
import jwt

from app.modules.admin import admin_router
import app.modules.admin.router as _admin_module

from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.models import LedgerOperation
from app.modules.ledger.hasher import hash_did_document
from app.modules.webauthn.credential_store import CredentialStore
from app.modules.tokens.revocation import (
    RevocationRecordError,
    RevocationStoreUnavailable,
    TokenRevocationStore,
)
from app.modules.tokens.models import MAX_TOKEN_LIFETIME_SECONDS
from app.modules.tokens.jwt_engine import generate_signing_keypair
from app.modules.admin.security import MAX_ADMIN_TOKEN_LIFETIME_SECONDS
import app.modules.revocation_provider as _revocation_provider
from tests.revocation_helpers import DurableRevocationStoreStub

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ledger() -> SimulatedLedger:
    """Fresh SimulatedLedger with genesis block."""
    return SimulatedLedger(auto_genesis=True)


@pytest.fixture()
def cred_store() -> CredentialStore:
    return CredentialStore()


@pytest.fixture()
def rev_store() -> DurableRevocationStoreStub:
    return DurableRevocationStoreStub()


def _authorized_client(app: FastAPI, monkeypatch, rev_store) -> TestClient:
    private_key, public_key = generate_signing_keypair()
    admin_did = "did:mesh:admin:test"
    token = _make_admin_token(admin_did, ["admin:ledger"], private_key)
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", public_key.decode())
    monkeypatch.setattr(_revocation_provider, "_revocation_store", rev_store)
    monkeypatch.setenv("ADMIN_DIDS", admin_did)
    monkeypatch.setenv("ENABLE_LEDGER_TAMPER_DEMO", "true")
    return TestClient(app, headers={"Authorization": f"Bearer {token}"})


def _make_admin_token(did, scopes, private_key, extra_claims=None):
    claims = {
        "sub": did,
        "jti": str(uuid.uuid4()),
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "idp-mesh-admin",
        "aud": "idp-mesh-admin",
        "scope": scopes,
    }
    claims.update(extra_claims or {})
    return jwt.encode(claims, private_key, algorithm="EdDSA")


@pytest.fixture()
def client(ledger, cred_store, rev_store, monkeypatch) -> TestClient:
    """Wire all stores into the admin module, return a TestClient."""
    _admin_module._shared_ledger    = ledger
    _admin_module._credential_store = cred_store

    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")
    return _authorized_client(app, monkeypatch, rev_store)


@pytest.fixture()
def populated_client(ledger, cred_store, rev_store, monkeypatch) -> TestClient:
    """Client with a DID anchored on the ledger and a WebAuthn credential registered."""
    # Anchor a DID
    did = "did:mesh:key:deadbeef1234"
    doc = {"id": did, "verificationMethod": [{"publicKeyMultibase": "zABC"}]}
    doc_hash = hash_did_document(doc)
    ledger.append_record(did=did, doc_hash=doc_hash, operation=LedgerOperation.CREATE)

    # Register a fake credential
    import os
    fake_pub_key = os.urandom(32)
    cred_store.register(did=did, public_key_bytes=fake_pub_key)

    _admin_module._shared_ledger    = ledger
    _admin_module._credential_store = cred_store

    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")
    return _authorized_client(app, monkeypatch, rev_store), did


def test_admin_import_does_not_initialize_ordinary_token_router():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys\n"
                "import app.modules.admin.router\n"
                "assert 'app.modules.tokens.router' not in sys.modules\n"
            ),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "Admin router import check failed in a fresh Python process.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class TestDashboard:
    def test_dashboard_returns_200(self, client):
        resp = client.get("/api/v1/admin/dashboard")
        assert resp.status_code == 200

    def test_dashboard_schema(self, client):
        data = client.get("/api/v1/admin/dashboard").json()
        assert "total_dids" in data
        assert "active_dids" in data
        assert "deactivated_dids" in data
        assert "total_ledger_records" in data
        assert "ledger_integrity" in data
        assert "total_credentials" in data
        assert "revocation_backend" in data
        assert isinstance(data["subsystems"], list)

    def test_dashboard_ledger_integrity_true_on_fresh(self, client):
        data = client.get("/api/v1/admin/dashboard").json()
        assert data["ledger_integrity"] is True

    def test_dashboard_revocation_backend_redis(self, client):
        data = client.get("/api/v1/admin/dashboard").json()
        assert data["revocation_backend"] == "redis"

    def test_dashboard_counts_populated_did(self, populated_client):
        tc, did = populated_client
        data = tc.get("/api/v1/admin/dashboard").json()
        assert data["total_dids"] >= 1
        assert data["active_dids"] >= 1
        assert data["total_credentials"] >= 1


# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------


class TestIdentities:
    def test_identities_returns_200(self, client):
        resp = client.get("/api/v1/admin/identities")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_identities_empty_on_fresh_ledger(self, client):
        data = client.get("/api/v1/admin/identities").json()
        # Fresh ledger has only genesis DID which is excluded
        assert data == []

    def test_identities_contains_did_after_anchor(self, populated_client):
        tc, did = populated_client
        data = tc.get("/api/v1/admin/identities").json()
        dids = [row["did"] for row in data]
        assert did in dids

    def test_identity_status_active(self, populated_client):
        tc, did = populated_client
        data = tc.get("/api/v1/admin/identities").json()
        row = next(r for r in data if r["did"] == did)
        assert row["status"] == "ACTIVE"
        assert row["credential_count"] == 1

    def test_identity_deactivated_status(self, ledger, cred_store, rev_store, monkeypatch):
        did = "did:mesh:key:aabbccdd"
        doc_hash = hash_did_document({"id": did})
        ledger.append_record(did=did, doc_hash=doc_hash, operation=LedgerOperation.CREATE)
        ledger.append_record(did=did, doc_hash=doc_hash, operation=LedgerOperation.DEACTIVATE)

        _admin_module._shared_ledger    = ledger
        _admin_module._credential_store = cred_store
        app = FastAPI()
        app.include_router(admin_router, prefix="/api/v1")
        tc = _authorized_client(app, monkeypatch, rev_store)

        data = tc.get("/api/v1/admin/identities").json()
        row = next(r for r in data if r["did"] == did)
        assert row["status"] == "DEACTIVATED"


class TestIdentityDetail:
    def test_detail_200_for_registered_did(self, populated_client):
        tc, did = populated_client
        resp = tc.get(f"/api/v1/admin/identities/{did}")
        assert resp.status_code == 200

    def test_detail_schema(self, populated_client):
        tc, did = populated_client
        data = tc.get(f"/api/v1/admin/identities/{did}").json()
        assert data["did"] == did
        assert data["status"] == "ACTIVE"
        assert isinstance(data["ledger_history"], list)
        assert isinstance(data["credentials"], list)
        assert data["credential_count"] == 1

    def test_detail_404_for_unknown_did(self, client):
        resp = client.get("/api/v1/admin/identities/did:mesh:key:unknown9999")
        assert resp.status_code == 404

    def test_detail_ledger_history_length(self, populated_client):
        tc, did = populated_client
        data = tc.get(f"/api/v1/admin/identities/{did}").json()
        # We anchored exactly one CREATE record
        assert len(data["ledger_history"]) == 1


# ---------------------------------------------------------------------------
# Ledger Admin
# ---------------------------------------------------------------------------


class TestLedgerAdmin:
    def test_ledger_returns_200(self, client):
        resp = client.get("/api/v1/admin/ledger")
        assert resp.status_code == 200

    def test_ledger_contains_genesis(self, client):
        data = client.get("/api/v1/admin/ledger").json()
        assert data["total_records"] >= 1
        genesis = data["records"][0]
        assert genesis["operation"] == "GENESIS"

    def test_ledger_integrity_valid_on_fresh(self, client):
        data = client.get("/api/v1/admin/ledger").json()
        assert data["integrity_valid"] is True
        assert data["integrity_error"] is None

    def test_ledger_verify_endpoint(self, client):
        resp = client.get("/api/v1/admin/ledger/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["integrity_valid"] is True


# ---------------------------------------------------------------------------
# Credentials Admin
# ---------------------------------------------------------------------------


class TestCredentialsAdmin:
    def test_credentials_empty_on_fresh(self, client):
        data = client.get("/api/v1/admin/credentials").json()
        assert data["total_credentials"] == 0
        assert data["credentials"] == []

    def test_credentials_listed_after_registration(self, populated_client):
        tc, did = populated_client
        data = tc.get("/api/v1/admin/credentials").json()
        assert data["total_credentials"] == 1
        assert data["credentials"][0]["did"] == did

    def test_credential_has_expected_fields(self, populated_client):
        tc, did = populated_client
        cred = tc.get("/api/v1/admin/credentials").json()["credentials"][0]
        assert "credential_id" in cred
        assert "did" in cred
        assert "public_key_b64" in cred
        assert "registered_at" in cred
        assert "sign_count" in cred


# ---------------------------------------------------------------------------
# Token Admin
# ---------------------------------------------------------------------------


class TestTokenAdmin:
    def test_force_revoke_returns_200(self, client, monkeypatch):
        monkeypatch.setattr(
            _admin_module,
            "_verified_target_expiration",
            lambda _token, _jti: time.time() + 3600,
        )
        resp = client.post(
            "/api/v1/admin/tokens/test-jti-1234/revoke",
            json={"jti": "test-jti-1234", "target_token": "verified-target"},
        )
        assert resp.status_code == 200

    def test_force_revoke_response_schema(self, client, monkeypatch):
        monkeypatch.setattr(
            _admin_module,
            "_verified_target_expiration",
            lambda _token, _jti: time.time() + 3600,
        )
        data = client.post(
            "/api/v1/admin/tokens/my-test-jti/revoke",
            json={"jti": "my-test-jti", "target_token": "verified-target"},
        ).json()
        assert data["revoked"] is True
        assert data["jti"] == "my-test-jti"
        assert "message" in data

    def test_force_revoke_retention_covers_token_lifetime_over_24_hours(
        self, rev_store, client, monkeypatch
    ):
        jti = "long-lived-target-jti"
        expires_at = time.time() + 48 * 60 * 60
        monkeypatch.setattr(
            _admin_module,
            "_verified_target_expiration",
            lambda _token, _expected_jti: expires_at,
        )
        response = client.post(
            f"/api/v1/admin/tokens/{jti}/revoke",
            json={"jti": jti, "target_token": "verified-48-hour-target"},
        )
        assert response.status_code == 200
        assert rev_store.is_revoked(jti) is True
        assert rev_store._revoked_until[jti] - time.monotonic() > (48 * 60 * 60) - 3

    def test_force_revoke_rejects_missing_target_token_without_mutation(self, client, rev_store):
        jti = "missing-target-token-jti"
        response = client.post(
            f"/api/v1/admin/tokens/{jti}/revoke",
            json={"jti": jti},
        )
        assert response.status_code == 422
        assert rev_store.is_revoked(jti) is False

    def test_force_revoke_rejects_caller_supplied_expiry(self, client, rev_store):
        jti = "caller-expiry-jti"
        response = client.post(
            f"/api/v1/admin/tokens/{jti}/revoke",
            json={
                "jti": jti,
                "target_token": "signed-target",
                "exp": time.time() + 365 * 24 * 60 * 60,
            },
        )
        assert response.status_code == 422
        assert rev_store.is_revoked(jti) is False

    def test_force_revoke_rejects_path_body_jti_mismatch(self, client, rev_store, monkeypatch):
        monkeypatch.setattr(
            _admin_module,
            "_verified_target_expiration",
            lambda _token, _jti: time.time() + 3600,
        )
        response = client.post(
            "/api/v1/admin/tokens/path-jti/revoke",
            json={"jti": "body-jti", "target_token": "verified-target"},
        )
        assert response.status_code == 422
        assert rev_store.is_revoked("path-jti") is False

    def test_force_revoke_rejects_invalid_target_token(self, client, rev_store, monkeypatch):
        def reject_target(_token, _jti):
            raise ValueError("Target token could not be verified.")

        monkeypatch.setattr(
            _admin_module,
            "_verified_target_expiration",
            reject_target,
        )
        jti = "invalid-target-jti"
        response = client.post(
            f"/api/v1/admin/tokens/{jti}/revoke",
            json={"jti": jti, "target_token": "invalid"},
        )
        assert response.status_code == 422
        assert rev_store.is_revoked(jti) is False

    def test_token_policy_returns_200(self, client):
        resp = client.get("/api/v1/admin/tokens/policy")
        assert resp.status_code == 200

    def test_token_policy_schema(self, client):
        data = client.get("/api/v1/admin/tokens/policy").json()
        assert "allowed_scopes" in data
        assert "token_issuer" in data
        assert "token_audience" in data
        assert "default_expiry_seconds" in data
        assert data["signing_algorithm"] == "EdDSA"

    def test_token_policy_scopes_not_empty(self, client):
        data = client.get("/api/v1/admin/tokens/policy").json()
        assert len(data["allowed_scopes"]) >= 3
        assert "admin:ledger" not in data["allowed_scopes"]


# ---------------------------------------------------------------------------
# Tamper Demo
# ---------------------------------------------------------------------------


class TestTamperDemo:
    def test_simulate_tamper_returns_200(self, populated_client):
        tc, _ = populated_client
        # Tamper with the genesis block's did field (index 0)
        resp = tc.post(
            "/api/v1/admin/ledger/simulate-tamper",
            params={"index": 0, "field": "did", "new_value": "did:mesh:evil"},
        )
        assert resp.status_code == 200

    def test_simulate_tamper_breaks_integrity(self, populated_client):
        tc, _ = populated_client
        data = tc.post(
            "/api/v1/admin/ledger/simulate-tamper",
            params={"index": 0, "field": "doc_hash", "new_value": "aabbccdd" * 8},
        ).json()
        assert data["integrity_valid"] is False
        assert data["integrity_error"] is not None
        assert _admin_module._shared_ledger.verify_integrity() == (True, None)

    def test_simulate_tamper_bad_index_returns_400(self, client):
        resp = client.post(
            "/api/v1/admin/ledger/simulate-tamper",
            params={"index": 9999, "field": "did", "new_value": "bad"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class TestSystemHealth:
    def test_health_returns_200(self, client):
        resp = client.get("/api/v1/admin/health")
        assert resp.status_code == 200

    def test_health_schema(self, client):
        data = client.get("/api/v1/admin/health").json()
        assert "overall_status" in data
        assert "ledger_integrity" in data
        assert "ledger_records" in data
        assert "total_dids" in data
        assert "total_credentials" in data
        assert data["revocation_redis_available"] is True
        assert data["revocation_persistence"] == "verified"
        assert data["revocation_eviction"] == "verified"
        assert data["revocation_durability"] == "configuration_verified"
        assert isinstance(data["subsystems"], list)

    def test_health_overall_healthy_on_fresh_ledger(self, client):
        data = client.get("/api/v1/admin/health").json()
        assert data["overall_status"] == "healthy"
        assert data["ledger_integrity"] is True

    def test_health_subsystems_all_present(self, client):
        data = client.get("/api/v1/admin/health").json()
        subsystem_names = {s["name"] for s in data["subsystems"]}
        assert "ledger" in subsystem_names
        assert "did_registry" in subsystem_names
        assert "webauthn" in subsystem_names
        assert "tokens" in subsystem_names


# ---------------------------------------------------------------------------
# 503 when not wired
# ---------------------------------------------------------------------------


class TestUnwiredStores:
    def test_dashboard_503_when_not_wired(self, monkeypatch):
        _admin_module._shared_ledger    = None
        _admin_module._credential_store = None
        app = FastAPI()
        app.include_router(admin_router, prefix="/api/v1")
        rev_store = TokenRevocationStore(redis_url="redis://localhost:9999/0")
        tc = _authorized_client(app, monkeypatch, rev_store)
        resp = tc.get("/api/v1/admin/dashboard")
        assert resp.status_code == 503


def test_anonymous_admin_request_is_rejected(ledger, cred_store, rev_store):
    _admin_module._shared_ledger = ledger
    _admin_module._credential_store = cred_store
    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")
    assert TestClient(app).get("/api/v1/admin/dashboard").status_code == 401


def test_invalid_admin_token_is_rejected(client):
    assert client.get("/api/v1/admin/dashboard", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_correctly_formed_admin_jwt_signed_with_wrong_key_is_rejected(client, monkeypatch):
    signing_key, _ = generate_signing_keypair()
    _, configured_public_key = generate_signing_keypair()
    admin_did = "did:mesh:admin:wrong-signing-key"
    token = _make_admin_token(admin_did, ["admin:ledger"], signing_key)
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", configured_public_key.decode())
    monkeypatch.setenv("ADMIN_DIDS", admin_did)

    response = client.get(
        "/api/v1/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    ("claim", "value"),
    [("iss", "wrong-issuer"), ("aud", "wrong-audience")],
)
def test_wrong_admin_issuer_or_audience_is_rejected(client, monkeypatch, claim, value):
    private_key, public_key = generate_signing_keypair()
    admin_did = "did:mesh:admin:wrong-claim"
    token = _make_admin_token(
        admin_did,
        ["admin:ledger"],
        private_key,
        extra_claims={claim: value},
    )
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", public_key.decode())
    monkeypatch.setenv("ADMIN_DIDS", admin_did)

    response = client.get(
        "/api/v1/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    "extra_claims",
    [
        {"exp": int(time.time()) - 5},
        {"nbf": int(time.time()) + 300},
    ],
    ids=["expired", "future-not-before"],
)
def test_expired_or_not_yet_valid_admin_jwt_is_rejected(
    client, monkeypatch, extra_claims
):
    private_key, public_key = generate_signing_keypair()
    admin_did = "did:mesh:admin:time-claims"
    token = _make_admin_token(
        admin_did,
        ["admin:ledger"],
        private_key,
        extra_claims=extra_claims,
    )
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", public_key.decode())
    monkeypatch.setenv("ADMIN_DIDS", admin_did)

    response = client.get(
        "/api/v1/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_admin_jwt_missing_scope_claim_is_rejected(client, monkeypatch):
    private_key, public_key = generate_signing_keypair()
    admin_did = "did:mesh:admin:missing-scope"
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": admin_did,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 3600,
            "iss": "idp-mesh-admin",
            "aud": "idp-mesh-admin",
        },
        private_key,
        algorithm="EdDSA",
    )
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", public_key.decode())
    monkeypatch.setenv("ADMIN_DIDS", admin_did)

    response = client.get(
        "/api/v1/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_ordinary_user_jwt_with_admin_scope_is_rejected(client, monkeypatch):
    private_key, public_key = generate_signing_keypair()
    user_did = "did:mesh:user:claims-admin-scope"
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": user_did,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 3600,
            "iss": "idp-mesh-v1",
            "aud": "idp-mesh-api",
            "scope": ["admin:ledger"],
        },
        private_key,
        algorithm="EdDSA",
    )
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", public_key.decode())
    monkeypatch.setenv("ADMIN_DIDS", user_did)

    response = client.get(
        "/api/v1/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_signed_non_admin_token_is_forbidden(client, monkeypatch):
    private_key, public_key = generate_signing_keypair()
    token = _make_admin_token(
        "did:mesh:user:test", ["read:profile"], private_key, extra_claims={"role": "admin"}
    )
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", public_key.decode())
    response = client.get("/api/v1/admin/dashboard", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_signed_admin_jwt_allows_admin_access(client):
    assert client.get("/api/v1/admin/dashboard").status_code == 200


def test_signed_admin_scope_for_unlisted_identity_is_forbidden(client, monkeypatch):
    private_key, public_key = generate_signing_keypair()
    token = _make_admin_token("did:mesh:user:test", ["admin:ledger"], private_key)
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", public_key.decode())
    response = client.get("/api/v1/admin/dashboard", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_admin_token_lifetime_cannot_exceed_revocation_ttl(client, monkeypatch):
    private_key, public_key = generate_signing_keypair()
    admin_did = "did:mesh:admin:long-lived-test"
    token = _make_admin_token(
        admin_did,
        ["admin:ledger"],
        private_key,
        extra_claims={"exp": int(time.time()) + MAX_ADMIN_TOKEN_LIFETIME_SECONDS + 60},
    )
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", public_key.decode())
    monkeypatch.setenv("ADMIN_DIDS", admin_did)

    response = client.get(
        "/api/v1/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_revoked_admin_token_is_rejected(ledger, cred_store, monkeypatch):
    private_key, public_key = generate_signing_keypair()
    admin_did = "did:mesh:admin:revoked-test"
    jti = "already-revoked-admin-jti"
    token = _make_admin_token(admin_did, ["admin:ledger"], private_key, extra_claims={"jti": jti})
    rev_store = DurableRevocationStoreStub()
    rev_store.revoke(jti, ttl_seconds=3600)
    _admin_module._shared_ledger = ledger
    _admin_module._credential_store = cred_store
    monkeypatch.setattr(_revocation_provider, "_revocation_store", rev_store)
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", public_key.decode())
    monkeypatch.setenv("ADMIN_DIDS", admin_did)
    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")

    response = TestClient(app).get(
        "/api/v1/admin/dashboard",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_admin_auth_fails_closed_with_ephemeral_revocation_store(
    ledger, cred_store, monkeypatch
):
    ephemeral_store = TokenRevocationStore(
        redis_url="redis://localhost:0/99",
        allow_in_memory_fallback=True,
    )
    _admin_module._shared_ledger = ledger
    _admin_module._credential_store = cred_store
    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")
    client = _authorized_client(app, monkeypatch, ephemeral_store)

    response = client.get("/api/v1/admin/dashboard")

    assert response.status_code == 503


def test_admin_auth_returns_503_when_redis_is_unavailable(
    ledger, cred_store, monkeypatch
):
    unavailable_store = TokenRevocationStore(redis_url="redis://localhost:0/99")
    assert unavailable_store.backend_type == "unavailable"
    _admin_module._shared_ledger = ledger
    _admin_module._credential_store = cred_store
    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")
    client = _authorized_client(app, monkeypatch, unavailable_store)

    response = client.get("/api/v1/admin/dashboard")

    assert response.status_code == 503


def test_admin_auth_fails_closed_when_redis_lookup_errors(ledger, cred_store, monkeypatch):
    class FailingDurableStore(DurableRevocationStoreStub):
        def is_revoked(self, jti: str) -> bool:
            raise RevocationStoreUnavailable("simulated Redis timeout")

    rev_store = FailingDurableStore()
    _admin_module._shared_ledger = ledger
    _admin_module._credential_store = cred_store
    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")
    client = _authorized_client(app, monkeypatch, rev_store)

    response = client.get("/api/v1/admin/dashboard")

    assert response.status_code == 503


def test_admin_auth_fails_closed_on_malformed_redis_record(
    ledger, cred_store, monkeypatch
):
    class MalformedRecordStore(DurableRevocationStoreStub):
        def is_revoked(self, jti: str) -> bool:
            raise RevocationRecordError("malformed Redis record")

    rev_store = MalformedRecordStore()
    _admin_module._shared_ledger = ledger
    _admin_module._credential_store = cred_store
    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")
    client = _authorized_client(app, monkeypatch, rev_store)

    response = client.get("/api/v1/admin/dashboard")

    assert response.status_code == 503


def test_admin_revoke_returns_503_when_redis_write_errors(
    ledger, cred_store, monkeypatch
):
    class FailingWriteStore(DurableRevocationStoreStub):
        def revoke(self, jti: str, ttl_seconds: int = 3600) -> None:
            raise RevocationStoreUnavailable("simulated Redis write timeout")

    rev_store = FailingWriteStore()
    _admin_module._shared_ledger = ledger
    _admin_module._credential_store = cred_store
    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")
    client = _authorized_client(app, monkeypatch, rev_store)
    monkeypatch.setattr(
        _admin_module,
        "_verified_target_expiration",
        lambda _token, _jti: time.time() + 3600,
    )

    response = client.post(
        "/api/v1/admin/tokens/failing-jti/revoke",
        json={"jti": "failing-jti", "target_token": "verified-target"},
    )

    assert response.status_code == 503


def test_admin_route_uses_the_shared_revocation_provider(client, rev_store, monkeypatch):
    assert _revocation_provider.get_revocation_store() is rev_store
    monkeypatch.setattr(
        _admin_module,
        "_verified_target_expiration",
        lambda _token, _jti: time.time() + 3600,
    )
    jti = "shared-provider-jti"

    response = client.post(
        f"/api/v1/admin/tokens/{jti}/revoke",
        json={"jti": jti, "target_token": "verified-target"},
    )

    assert response.status_code == 200
    assert rev_store.is_revoked(jti) is True


def test_validated_target_claims_allow_48_hour_lifetime(
    monkeypatch,
):
    now = time.time()
    target_jti = "signed-long-lived-target"
    claims = {
        "jti": target_jti,
        "iat": now,
        "exp": now + (48 * 60 * 60),
    }
    monkeypatch.setattr(_admin_module, "_get_ordinary_token_public_key", lambda: b"test-public-key")
    monkeypatch.setattr(_admin_module, "verify_token", lambda _token, _key: claims)

    expires_at = _admin_module._verified_target_expiration(
        "test-token-after-verifier", target_jti
    )

    ttl = _admin_module._remaining_revocation_ttl(expires_at, now=now)
    assert ttl > 24 * 60 * 60
    assert ttl <= MAX_TOKEN_LIFETIME_SECONDS


@pytest.mark.parametrize(
    "claims",
    [
        {"jti": "target", "iat": 100.0},
        {"jti": "target", "iat": 100.0, "exp": "not-a-timestamp"},
        {"jti": "target", "iat": 100.0, "exp": 10**1000},
        {"jti": "different-jti", "iat": 100.0, "exp": 200.0},
    ],
)
def test_target_token_verification_rejects_missing_malformed_or_mismatched_claims(
    monkeypatch, claims
):
    monkeypatch.setattr(_admin_module, "_get_ordinary_token_public_key", lambda: b"test-public-key")
    monkeypatch.setattr(_admin_module, "verify_token", lambda _token, _key: claims)
    with pytest.raises(ValueError):
        _admin_module._verified_target_expiration("signed-target", "target")


def test_unverifiable_or_expired_target_token_is_rejected(monkeypatch):
    monkeypatch.setattr(_admin_module, "_get_ordinary_token_public_key", lambda: b"test-public-key")

    def reject_token(*_args, **_kwargs):
        raise ValueError("invalid signature or expired token")

    monkeypatch.setattr(_admin_module, "verify_token", reject_token)
    monkeypatch.setattr(_admin_module.jwt, "decode", reject_token)
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", "test-admin-public-key")
    with pytest.raises(ValueError, match="could not be verified"):
        _admin_module._verified_target_expiration("unverifiable-target", "target")


@pytest.mark.parametrize(
    ("expires_at", "now", "expected"),
    [(100.1, 100.0, 1), (86_500.2, 100.0, 86_401)],
)
def test_revocation_ttl_rounds_up_to_cover_expiry(expires_at, now, expected):
    assert _admin_module._remaining_revocation_ttl(expires_at, now=now) == expected


def test_revocation_ttl_rejects_expiry_beyond_storage_limit():
    expires_at = 100 + MAX_TOKEN_LIFETIME_SECONDS + 0.1
    with pytest.raises(ValueError, match="storage policy"):
        _admin_module._remaining_revocation_ttl(expires_at, now=100)


def test_expired_target_token_cannot_receive_a_revocation_entry(rev_store, client, monkeypatch):
    jti = "already-expired-target"
    monkeypatch.setattr(_admin_module, "_verified_target_expiration", lambda *_: time.time() - 1)
    response = client.post(
        f"/api/v1/admin/tokens/{jti}/revoke",
        json={"jti": jti, "target_token": "expired-target"},
    )
    assert response.status_code == 422
    assert rev_store.is_revoked(jti) is False


def test_tamper_demo_is_disabled_without_explicit_setting(client, monkeypatch):
    monkeypatch.setenv("ENABLE_LEDGER_TAMPER_DEMO", "false")
    response = client.post(
        "/api/v1/admin/ledger/simulate-tamper",
        params={"index": 0, "field": "did", "new_value": "did:mesh:evil"},
    )
    assert response.status_code == 404
    assert _admin_module._shared_ledger.verify_integrity() == (True, None)
