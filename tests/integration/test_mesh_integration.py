"""Integration tests for the Decentralized Zero-Trust IdP Mesh.

Verifies end-to-end contracts and interactions between:
- Member 4: Module C (Simulated Blockchain Ledger)
- Member 5: Module E (JWT Access Token & Zero-Trust Policy Engine)
- Member 6: Dashboard verification contracts and cross-module telemetry
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.modules.ledger import (
    SimulatedLedger,
    ledger_router,
)
from app.modules.ledger.hasher import hash_did_document
from app.modules.tokens import (
    tokens_router,
    ZeroTrustPolicyEngine,
    TokenRevocationStore,
)
import app.modules.ledger.router as ledger_router_module
import app.modules.tokens.router as tokens_router_module
from app.modules.tokens.jwt_engine import generate_signing_keypair


@pytest.fixture
def mesh_app():
    """Create a composite FastAPI app with both ledger and tokens routers mounted.

    Preserves and restores the ledger singleton state to ensure full test isolation.
    """
    app = FastAPI(title="TrustMesh Integration Test App")

    # Save original state of ledger singleton
    ledger = ledger_router_module.ledger_instance
    original_chain = list(ledger._chain)

    # Reset ledger with fresh genesis block
    with ledger._lock:
        ledger._chain.clear()
        ledger._create_genesis_record()

    private_pem, public_pem = generate_signing_keypair()
    isolated_policy = ZeroTrustPolicyEngine(ledger=ledger)
    isolated_revocation = TokenRevocationStore(redis_url="redis://localhost:0/99")
    isolated_revocation.clear_in_memory()

    # Save original token router dependencies
    orig_priv = tokens_router_module._private_key_pem
    orig_pub = tokens_router_module._public_key_pem
    orig_ledger = tokens_router_module._shared_ledger
    orig_policy = tokens_router_module._policy_engine
    orig_rev = tokens_router_module._revocation_store
    orig_get_priv = tokens_router_module.get_private_key
    orig_get_pub = tokens_router_module.get_public_key
    orig_get_ledger = tokens_router_module.get_ledger
    orig_get_policy = tokens_router_module.get_policy_engine
    orig_get_rev = tokens_router_module.get_revocation_store

    # Wire tokens to use the same ledger instance
    tokens_router_module._private_key_pem = private_pem
    tokens_router_module._public_key_pem = public_pem
    tokens_router_module._shared_ledger = ledger
    tokens_router_module._policy_engine = isolated_policy
    tokens_router_module._revocation_store = isolated_revocation

    tokens_router_module.get_private_key = lambda: private_pem
    tokens_router_module.get_public_key = lambda: public_pem
    tokens_router_module.get_ledger = lambda: ledger
    tokens_router_module.get_policy_engine = lambda: isolated_policy
    tokens_router_module.get_revocation_store = lambda: isolated_revocation

    # Mount routers under /api/v1 prefix as agreed in api-contract.md
    app.include_router(ledger_router, prefix="/api/v1")
    app.include_router(tokens_router, prefix="/api/v1")

    client = TestClient(app)

    yield client, ledger, isolated_revocation, public_pem

    # Teardown: restore original state
    with ledger._lock:
        ledger._chain = original_chain

    tokens_router_module._private_key_pem = orig_priv
    tokens_router_module._public_key_pem = orig_pub
    tokens_router_module._shared_ledger = orig_ledger
    tokens_router_module._policy_engine = orig_policy
    tokens_router_module._revocation_store = orig_rev
    tokens_router_module.get_private_key = orig_get_priv
    tokens_router_module.get_public_key = orig_get_pub
    tokens_router_module.get_ledger = orig_get_ledger
    tokens_router_module.get_policy_engine = orig_get_policy
    tokens_router_module.get_revocation_store = orig_get_rev


class TestMeshCrossModuleIntegration:
    """Verify contracts between Ledger and Token/Policy subsystems."""

    def test_complete_zero_trust_lifecycle(self, mesh_app):
        """Lifecycle: DID Anchor -> ZT Policy Token Issuance -> Token Verify -> Token Revoke -> Verify Rejection."""
        client, ledger, revocation, public_key = mesh_app
        test_did = "did:mesh:key:z6MkuIntegrationUser01"
        doc_hash = hash_did_document({"id": test_did, "publicKey": "sample_ed25519_key"})

        # 1. Anchor DID to Ledger (Member 4) - returns 201 Created
        anchor_resp = client.post(
            "/api/v1/ledger/anchor",
            json={
                "did": test_did,
                "doc_hash": doc_hash,
                "operation": "CREATE",
                "metadata": {"creator": "member6_integration_test"},
            },
        )
        assert anchor_resp.status_code == 201
        record_data = anchor_resp.json()
        assert record_data["did"] == test_did
        assert record_data["operation"] == "CREATE"

        # Verify ledger integrity holds
        verify_ledger_resp = client.get("/api/v1/ledger/verify")
        assert verify_ledger_resp.status_code == 200
        assert verify_ledger_resp.json()["valid"] is True

        # 2. Issue Token with Zero-Trust evaluation (Member 5)
        issue_resp = client.post(
            "/api/v1/tokens/issue",
            json={
                "did": test_did,
                "scope": ["read:profile", "write:did"],
            },
        )
        assert issue_resp.status_code == 201
        token_info = issue_resp.json()
        access_token = token_info["access_token"]
        jti = token_info["jti"]
        assert token_info["did"] == test_did
        assert "read:profile" in token_info["scope"]

        # 3. Verify Token
        verify_token_resp = client.post(
            "/api/v1/tokens/verify",
            json={"token": access_token},
        )
        assert verify_token_resp.status_code == 200
        verify_data = verify_token_resp.json()
        assert verify_data["valid"] is True
        assert verify_data["claims"]["sub"] == test_did
        assert verify_data["claims"]["jti"] == jti

        # 4. Revoke Token by JTI
        revoke_resp = client.post(
            "/api/v1/tokens/revoke",
            json={"jti": jti, "reason": "Administrative revocation test"},
        )
        assert revoke_resp.status_code == 200
        assert revoke_resp.json()["revoked"] is True
        assert revoke_resp.json()["jti"] == jti

        # 5. Verify Token again - must be rejected due to revocation
        verify_after_revoke = client.post(
            "/api/v1/tokens/verify",
            json={"token": access_token},
        )
        assert verify_after_revoke.status_code == 200
        after_data = verify_after_revoke.json()
        assert after_data["valid"] is False
        assert "revoked" in after_data["error"].lower()

    def test_zero_trust_halts_on_ledger_tampering(self, mesh_app):
        """Zero-Trust principle: If ledger integrity fails, token issuance is immediately blocked."""
        client, ledger, _, _ = mesh_app
        active_did = "did:mesh:key:z6MkuLegitUser99"
        doc_hash = hash_did_document({"id": active_did})

        # Anchor valid user
        anchor_resp = client.post(
            "/api/v1/ledger/anchor",
            json={"did": active_did, "doc_hash": doc_hash, "operation": "CREATE"},
        )
        assert anchor_resp.status_code == 201

        # Confirm token can be issued when ledger is intact
        valid_issue = client.post(
            "/api/v1/tokens/issue",
            json={"did": active_did, "scope": ["read:profile"]},
        )
        assert valid_issue.status_code == 201

        # Simulate tampering on record #1's doc_hash (preserving the did so DID exists, but hash linkage is broken)
        tamper_resp = client.post(
            "/api/v1/ledger/simulate-tamper",
            json={
                "index": 1,
                "field": "doc_hash",
                "new_value": "f" * 64,
                "recalculate_record_hash": False,
            },
        )
        assert tamper_resp.status_code == 200
        assert tamper_resp.json()["valid"] is False

        # Attempt to issue a token now — must be rejected with 403 Forbidden due to ledger integrity failure
        tampered_issue = client.post(
            "/api/v1/tokens/issue",
            json={"did": active_did, "scope": ["read:profile"]},
        )
        assert tampered_issue.status_code == 403
        assert "integrity" in tampered_issue.json()["detail"].lower()

    def test_zero_trust_denies_deactivated_identity(self, mesh_app):
        """Zero-Trust principle: Deactivated DIDs are immediately denied token issuance."""
        client, ledger, _, _ = mesh_app
        did = "did:mesh:key:z6MkuToDeactivate"
        doc_hash = hash_did_document({"id": did})

        # Register
        reg_resp = client.post(
            "/api/v1/ledger/anchor",
            json={"did": did, "doc_hash": doc_hash, "operation": "CREATE"},
        )
        assert reg_resp.status_code == 201

        # Deactivate on ledger
        deactivate_resp = client.post(
            "/api/v1/ledger/anchor",
            json={"did": did, "doc_hash": doc_hash, "operation": "DEACTIVATE"},
        )
        assert deactivate_resp.status_code == 201

        # Attempt token issuance
        issue_resp = client.post(
            "/api/v1/tokens/issue",
            json={"did": did, "scope": ["read:profile"]},
        )
        assert issue_resp.status_code == 403
        assert "deactivated" in issue_resp.json()["detail"].lower()

    def test_dashboard_public_endpoints(self, mesh_app):
        """Verify endpoints consumed by dashboard: public-key and policy scopes."""
        client, _, _, _ = mesh_app

        # Public key
        pk_resp = client.get("/api/v1/tokens/public-key")
        assert pk_resp.status_code == 200
        pk_data = pk_resp.json()
        assert "PUBLIC KEY" in pk_data["public_key_pem"]
        assert pk_data["algorithm"] == "EdDSA"

        # Policy scopes
        scopes_resp = client.get("/api/v1/tokens/policy/scopes")
        assert scopes_resp.status_code == 200
        scopes = scopes_resp.json()["scopes"]
        assert "read:profile" in scopes
        assert "admin:ledger" in scopes

    def test_main_app_health_and_subsystem_matrix(self):
        """Verify app.main composite health endpoint accurately reports subsystem state."""
        from app.main import app
        from fastapi.testclient import TestClient

        main_client = TestClient(app)

        # Root health check
        health_resp = main_client.get("/health")
        assert health_resp.status_code == 200
        health_data = health_resp.json()
        assert health_data["status"] == "healthy"
        assert "subsystems" in health_data
        assert health_data["subsystems"]["ledger"]["status"] == "healthy"
        assert health_data["subsystems"]["tokens_and_policy"]["status"] == "healthy"
        assert health_data["subsystems"]["tokens_and_policy"]["signing_algorithm"] == "EdDSA (Ed25519)"

        # API v1 health check alias
        v1_resp = main_client.get("/api/v1/health")
        assert v1_resp.status_code == 200
        assert v1_resp.json()["status"] == "healthy"

    def test_main_app_root_metadata(self):
        """Verify app.main root path returns operational metadata and doc links."""
        from app.main import app
        from fastapi.testclient import TestClient

        main_client = TestClient(app)
        root_resp = main_client.get("/")
        assert root_resp.status_code == 200
        root_data = root_resp.json()
        assert root_data["status"] == "operational"
        assert root_data["api_docs"] == "/docs"
        assert "/api/v1/ledger" in root_data["endpoints"]["ledger"]

    def test_main_app_dashboard_static_mount(self):
        """Verify app.main serves the frontend dashboard HTML."""
        from app.main import app
        from fastapi.testclient import TestClient

        main_client = TestClient(app)
        dash_resp = main_client.get("/dashboard/")
        assert dash_resp.status_code == 200
        assert "TrustMesh" in dash_resp.text
        assert "Zero-Trust" in dash_resp.text
