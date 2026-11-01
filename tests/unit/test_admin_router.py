"""
tests/unit/test_admin_router.py — Unit tests for Module D (Admin Dashboard API)
================================================================================

Tests use FastAPI's TestClient with the shared SimulatedLedger, CredentialStore,
and TokenRevocationStore injected directly — no running server required.

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
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.modules.admin import admin_router
import app.modules.admin.router as _admin_module

from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.models import LedgerOperation
from app.modules.ledger.hasher import hash_did_document
from app.modules.webauthn.credential_store import CredentialStore
from app.modules.tokens.revocation import TokenRevocationStore
from app.modules.audit.event_store import AuditEventStore
from app.modules.tokens.jwt_engine import issue_token
import app.modules.tokens.router as _token_module


def _auth_headers(role: str = "admin") -> dict[str, str]:
    token, _ = issue_token(
        did="did:mesh:key:admin-test",
        scope=["admin:ledger"],
        private_key_pem=_token_module.get_private_key(),
        extra_claims={"role": role},
    )
    return {"Authorization": f"Bearer {token}"}

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
def rev_store() -> TokenRevocationStore:
    return TokenRevocationStore(redis_url="redis://localhost:9999/0")  # forces in-memory fallback


@pytest.fixture()
def client(ledger, cred_store, rev_store, tmp_path, monkeypatch) -> TestClient:
    """Wire all stores into the admin module, return a TestClient."""
    _admin_module._shared_ledger    = ledger
    _admin_module._credential_store = cred_store
    _admin_module._revocation_store = rev_store
    monkeypatch.setattr(_admin_module, "audit_event_store", AuditEventStore(str(tmp_path / "admin-events.sqlite3")))

    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")
    return TestClient(app, headers=_auth_headers())


@pytest.fixture()
def populated_client(ledger, cred_store, rev_store, tmp_path, monkeypatch) -> TestClient:
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
    _admin_module._revocation_store = rev_store
    monkeypatch.setattr(_admin_module, "audit_event_store", AuditEventStore(str(tmp_path / "populated-events.sqlite3")))

    app = FastAPI()
    app.include_router(admin_router, prefix="/api/v1")
    return TestClient(app, headers=_auth_headers()), did


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

    def test_dashboard_revocation_backend_in_memory(self, client):
        data = client.get("/api/v1/admin/dashboard").json()
        assert data["revocation_backend"] == "in-memory"

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

    def test_identity_deactivated_status(self, ledger, cred_store, rev_store):
        did = "did:mesh:key:aabbccdd"
        doc_hash = hash_did_document({"id": did})
        ledger.append_record(did=did, doc_hash=doc_hash, operation=LedgerOperation.CREATE)
        ledger.append_record(did=did, doc_hash=doc_hash, operation=LedgerOperation.DEACTIVATE)

        _admin_module._shared_ledger    = ledger
        _admin_module._credential_store = cred_store
        _admin_module._revocation_store = rev_store
        app = FastAPI()
        app.include_router(admin_router, prefix="/api/v1")
        tc = TestClient(app, headers=_auth_headers())

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
    def test_force_revoke_returns_200(self, client):
        resp = client.post("/api/v1/admin/tokens/test-jti-1234/revoke")
        assert resp.status_code == 200

    def test_force_revoke_response_schema(self, client):
        data = client.post("/api/v1/admin/tokens/my-test-jti/revoke").json()
        assert data["revoked"] is True
        assert data["jti"] == "my-test-jti"
        assert "message" in data

    def test_force_revoke_jti_is_revoked(self, rev_store, client):
        jti = "sentinel-jti-9999"
        client.post(f"/api/v1/admin/tokens/{jti}/revoke")
        assert rev_store.is_revoked(jti) is True

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
        assert len(data["allowed_scopes"]) >= 4


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
    def test_dashboard_503_when_not_wired(self):
        _admin_module._shared_ledger    = None
        _admin_module._credential_store = None
        _admin_module._revocation_store = None
        app = FastAPI()
        app.include_router(admin_router, prefix="/api/v1")
        tc = TestClient(app, headers=_auth_headers())
        resp = tc.get("/api/v1/admin/dashboard")
        assert resp.status_code == 503


class TestAdminAuthorization:
    def test_admin_route_requires_authentication(self, client):
        response = client.get("/api/v1/admin/dashboard", headers={"Authorization": ""})
        assert response.status_code == 401

    def test_regular_user_cannot_access_admin_route(self, client):
        response = client.get("/api/v1/admin/dashboard", headers=_auth_headers("user"))
        assert response.status_code == 403

    def test_admin_can_access_admin_route(self, client):
        response = client.get("/api/v1/admin/dashboard")
        assert response.status_code == 200


class TestSecurityEvents:
    def test_events_list_filter_detail_and_pagination(self, client):
        store = _admin_module.audit_event_store
        first = store.record(event_type="authentication", outcome="success", reason="assertion_verified")
        store.record(event_type="authentication", outcome="failure", reason="assertion_verification_failed")
        store.record(event_type="token_revocation", outcome="success", reason="owner_revoked_token")

        response = client.get("/api/v1/admin/events?page=1&page_size=1&event_type=authentication")
        assert response.status_code == 200
        payload = response.json()
        assert payload["total"] == 2
        assert len(payload["events"]) == 1
        assert payload["events"][0]["event_type"] == "authentication"

        detail = client.get(f"/api/v1/admin/events/{first['event_id']}")
        assert detail.status_code == 200
        assert detail.json()["reason"] == "assertion_verified"
        assert client.get("/api/v1/admin/events/missing").status_code == 404

    def test_dashboard_summary_includes_event_counts(self, client):
        _admin_module.audit_event_store.record(event_type="authentication", outcome="success", reason="ok")
        _admin_module.audit_event_store.record(event_type="policy_decision", outcome="deny", reason="denied")
        data = client.get("/api/v1/admin/dashboard").json()
        assert data["security_events_total"] == 2
        assert data["authentication_successes"] == 1
        assert data["access_denied"] == 1
