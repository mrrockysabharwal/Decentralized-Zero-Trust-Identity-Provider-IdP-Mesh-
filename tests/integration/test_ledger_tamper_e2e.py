"""End-to-end checks for isolated ledger tamper demonstrations."""

from __future__ import annotations

import os
import time
import uuid

import pytest
import jwt
from fastapi.testclient import TestClient

from app.main import app
from app.modules.tokens.jwt_engine import generate_signing_keypair
import app.modules.revocation_provider as revocation_provider
from tests.revocation_helpers import DurableRevocationStoreStub


@pytest.fixture(scope="module")
def client():
    from app.modules.ledger.router import ledger_instance

    orig_chain = list(ledger_instance._chain)
    old_admin_dids = os.environ.get("ADMIN_DIDS")
    old_admin_public_key = os.environ.get("ADMIN_JWT_PUBLIC_KEY")
    old_tamper_demo = os.environ.get("ENABLE_LEDGER_TAMPER_DEMO")
    old_revocation_store = revocation_provider._revocation_store
    revocation_provider.set_revocation_store(DurableRevocationStoreStub())
    admin_did = "did:mesh:admin:tamper-e2e"
    private_key, public_key = generate_signing_keypair()
    token = jwt.encode(
        {
            "sub": admin_did,
            "jti": str(uuid.uuid4()),
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "iss": "idp-mesh-admin",
            "aud": "idp-mesh-admin",
            "scope": ["admin:ledger"],
        },
        private_key,
        algorithm="EdDSA",
    )
    os.environ["ADMIN_DIDS"] = admin_did
    os.environ["ADMIN_JWT_PUBLIC_KEY"] = public_key.decode()
    os.environ["ENABLE_LEDGER_TAMPER_DEMO"] = "true"
    with TestClient(app, headers={"Authorization": f"Bearer {token}"}) as test_client:
        yield test_client
    with ledger_instance._lock:
        ledger_instance._chain.clear()
        ledger_instance._chain.extend(orig_chain)
    for name, value in (
        ("ADMIN_DIDS", old_admin_dids),
        ("ADMIN_JWT_PUBLIC_KEY", old_admin_public_key),
        ("ENABLE_LEDGER_TAMPER_DEMO", old_tamper_demo),
    ):
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    revocation_provider.set_revocation_store(old_revocation_store)


class TestLedgerTamperChainReaction:
    did: str = ""

    def test_01_create_and_anchor_did(self, client):
        response = client.post("/api/v1/did/create", json={"display_name": "TamperTestDID"})
        assert response.status_code == 201
        TestLedgerTamperChainReaction.did = response.json()["did"]

    def test_02_token_issue_unavailable_before_tamper(self, client):
        response = client.post(
            "/api/v1/tokens/issue", json={"did": self.did, "scope": ["read:profile"]}
        )
        assert response.status_code == 503, response.text

    def test_03_ledger_integrity_ok_before_tamper(self, client):
        assert client.get("/api/v1/admin/ledger/verify").json()["integrity_valid"] is True

    def test_04_admin_tamper_demo_breaks_integrity(self, client):
        response = client.post(
            "/api/v1/admin/ledger/simulate-tamper",
            params={"index": 0, "field": "doc_hash", "new_value": "cafebabe" * 8},
        )
        assert response.status_code == 200, response.text
        assert response.json()["integrity_valid"] is False
        assert client.get("/api/v1/admin/ledger/verify").json()["integrity_valid"] is True

    def test_05_ledger_verify_returns_false_after_tamper(self, client):
        assert client.get("/api/v1/admin/ledger/verify").json()["integrity_valid"] is True

    def test_06_token_issuance_remains_unavailable_after_tamper(self, client):
        response = client.post(
            "/api/v1/tokens/issue", json={"did": self.did, "scope": ["read:profile"]}
        )
        assert response.status_code == 503, response.text

    def test_07_admin_health_shows_degraded(self, client):
        health = client.get("/api/v1/admin/health").json()
        assert health["ledger_integrity"] is True
        assert health["overall_status"] == "healthy"

    def test_08_admin_dashboard_ledger_integrity_false(self, client):
        assert client.get("/api/v1/admin/dashboard").json()["ledger_integrity"] is True

    def test_09_ledger_subsystem_degraded_in_health(self, client):
        data = client.get("/api/v1/admin/health").json()
        ledger_subsystem = next(item for item in data["subsystems"] if item["name"] == "ledger")
        assert ledger_subsystem["status"] == "healthy"
        health = client.get("/api/v1/admin/health").json()
        assert health["ledger_integrity"] is True
        assert health["overall_status"] == "healthy"
