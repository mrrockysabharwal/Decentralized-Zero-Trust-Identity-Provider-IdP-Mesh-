"""
tests/integration/test_full_flow.py — End-to-End Integration Tests
===================================================================

Tests the complete user lifecycle ceremony against the full FastAPI
application (all 5 active modules wired together via main.py lifespan):

  1. DID Create           POST /api/v1/did/create
  2. WebAuthn Register    POST /api/v1/webauthn/register/begin
                          POST /api/v1/webauthn/register/complete
  3. WebAuthn Authenticate POST /api/v1/webauthn/authenticate/begin
                           POST /api/v1/webauthn/authenticate/complete
  4. Token Issue          POST /api/v1/tokens/issue
  5. Token Verify         POST /api/v1/tokens/verify
  6. Token Revoke         POST /api/v1/tokens/revoke
  7. Token Verify (after revoke) → invalid
  8. Admin Dashboard      GET  /api/v1/admin/dashboard
  9. DID Deactivate       POST /api/v1/did/deactivate/{did}
  10. Token Issue (after deactivate) → 403

All operations run in-process using the TestClient against the real app.
No external dependencies (Redis, browser, FIDO2) are needed.
"""

from __future__ import annotations

import base64
import hashlib
import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fastapi.testclient import TestClient
from app.main import app
from app.modules.webauthn.session_store import auth_session_store
from app.modules.tokens.jwt_engine import issue_token
import app.modules.tokens.router as token_router


# ---------------------------------------------------------------------------
# Module-level client (lifespan wires all shared singletons once)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    admin_jwt, _ = issue_token(
        did="did:mesh:key:test-admin", scope=["admin:ledger"],
        private_key_pem=token_router.get_private_key(), extra_claims={"role": "admin"},
    )
    with TestClient(app, headers={"Authorization": f"Bearer {admin_jwt}"}) as c:
        yield c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_ceremony(private_key_b64: str, challenge_b64: str, did: str, tag: bytes) -> str:
    """Reproduce the WebAuthn signing formula used by Module B."""
    priv_bytes = base64.urlsafe_b64decode(private_key_b64 + "==")
    priv_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    challenge_bytes = base64.urlsafe_b64decode(challenge_b64 + "==")
    pre_image = hashlib.sha256(challenge_bytes + did.encode() + tag).digest()
    signature = priv_key.sign(pre_image)
    return _b64(signature)


# ---------------------------------------------------------------------------
# Full lifecycle test
# ---------------------------------------------------------------------------


class TestFullIdentityLifecycle:
    """
    Single test class that runs the complete ceremony as one sequential flow.
    Each method asserts its own postconditions AND stores state on `self` for
    subsequent steps. pytest runs methods in definition order within a class.
    """

    # Shared state (populated step by step)
    did: str = ""
    public_key_b64: str = ""
    private_key_b64: str = ""
    credential_id: str = ""
    access_token: str = ""
    jti: str = ""
    session_token: str = ""

    # ------------------------------------------------------------------
    # Step 1 — DID Create
    # ------------------------------------------------------------------

    def test_01_did_create(self, client):
        resp = client.post("/api/v1/did/create", json={"display_name": "Integration-Alice"})
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["did"].startswith("did:mesh:key:")
        assert data["public_key_b64"]
        assert data["private_key_b64"]
        assert data["ledger_record_index"] >= 1

        TestFullIdentityLifecycle.did = data["did"]
        TestFullIdentityLifecycle.public_key_b64 = data["public_key_b64"]
        TestFullIdentityLifecycle.private_key_b64 = data["private_key_b64"]

    # ------------------------------------------------------------------
    # Step 2 — WebAuthn Registration
    # ------------------------------------------------------------------

    def test_02_webauthn_register_begin(self, client):
        resp = client.post(
            "/api/v1/webauthn/register/begin",
            json={"did": self.did, "display_name": "Integration-Alice"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["challenge"]
        TestFullIdentityLifecycle._reg_challenge = data["challenge"]

    def test_03_webauthn_register_complete(self, client):
        challenge = self._reg_challenge  # type: ignore[attr-defined]
        signature_b64 = _sign_ceremony(
            self.private_key_b64, challenge, self.did, b"register"
        )
        resp = client.post(
            "/api/v1/webauthn/register/complete",
            json={
                "did": self.did,
                "challenge": challenge,
                "public_key_b64": self.public_key_b64,
                "signature_b64": signature_b64,
            },
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["success"] is True
        TestFullIdentityLifecycle.credential_id = data["credential_id"]

    # ------------------------------------------------------------------
    # Step 3 — WebAuthn Authentication
    # ------------------------------------------------------------------

    def test_04_webauthn_authenticate_begin(self, client):
        resp = client.post(
            "/api/v1/webauthn/authenticate/begin",
            json={"did": self.did},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert self.credential_id in data["credential_ids"]
        TestFullIdentityLifecycle._auth_challenge = data["challenge"]

    def test_05_webauthn_authenticate_complete(self, client):
        challenge = self._auth_challenge  # type: ignore[attr-defined]
        signature_b64 = _sign_ceremony(
            self.private_key_b64, challenge, self.did, b"authenticate"
        )
        resp = client.post(
            "/api/v1/webauthn/authenticate/complete",
            json={
                "did": self.did,
                "challenge": challenge,
                "credential_id": self.credential_id,
                "signature_b64": signature_b64,
            },
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["success"] is True
        TestFullIdentityLifecycle.session_token = resp.json()["session_token"]
        audit = client.get("/api/v1/admin/events?event_type=authentication&outcome=success")
        assert audit.status_code == 200, audit.text
        assert any(event["did_ref"] != self.did for event in audit.json()["events"])

    # ------------------------------------------------------------------
    # Step 4 — Token Issuance
    # ------------------------------------------------------------------

    def test_06_token_issue(self, client):
        resp = client.post(
            "/api/v1/tokens/issue",
            headers={"Authorization": f"Bearer {self.session_token}"},
            json={"did": self.did, "scope": ["read:profile", "auth:webauthn"]},
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["access_token"]
        assert data["did"] == self.did
        TestFullIdentityLifecycle.access_token = data["access_token"]
        TestFullIdentityLifecycle.jti = data["jti"]

    def test_07_token_issue_with_require_webauthn(self, client):
        """require_webauthn=True must pass because we completed registration above."""
        resp = client.post(
            "/api/v1/tokens/issue",
            headers={"Authorization": f"Bearer {self.session_token}"},
            json={
                "did": self.did,
                "scope": ["read:profile"],
                "require_webauthn": True,
            },
        )
        assert resp.status_code == 201, resp.text

    # ------------------------------------------------------------------
    # Step 5 — Token Verify
    # ------------------------------------------------------------------

    def test_08_token_verify_valid(self, client):
        resp = client.post(
            "/api/v1/tokens/verify",
            json={"token": self.access_token},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["valid"] is True
        assert data["claims"]["sub"] == self.did
        protected = client.get("/api/v1/tokens/protected/profile", headers={"Authorization": f"Bearer {self.access_token}"})
        assert protected.status_code == 200
        assert protected.json()["did"] == self.did

    # ------------------------------------------------------------------
    # Step 6 — Token Revoke
    # ------------------------------------------------------------------

    def test_09_token_revoke(self, client):
        resp = client.post(
            "/api/v1/tokens/revoke",
            headers={"Authorization": f"Bearer {self.access_token}"},
            json={"jti": self.jti, "reason": "Integration test teardown"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["revoked"] is True

    def test_10_token_verify_after_revoke_is_invalid(self, client):
        resp = client.post(
            "/api/v1/tokens/verify",
            json={"token": self.access_token},
        )
        data = resp.json()
        assert data["valid"] is False
        assert "revoked" in data["error"].lower()
        protected = client.get("/api/v1/tokens/protected/profile", headers={"Authorization": f"Bearer {self.access_token}"})
        assert protected.status_code == 401

    # ------------------------------------------------------------------
    # Step 7 — Admin Dashboard reflects the lifecycle
    # ------------------------------------------------------------------

    def test_11_admin_dashboard_sees_did(self, client):
        resp = client.get("/api/v1/admin/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_dids"] >= 1
        assert data["total_credentials"] >= 1
        assert data["ledger_integrity"] is True

    def test_12_admin_identities_sees_did(self, client):
        data = client.get("/api/v1/admin/identities").json()
        dids = [r["did"] for r in data]
        assert self.did in dids

    def test_13_admin_identity_detail(self, client):
        data = client.get(f"/api/v1/admin/identities/{self.did}").json()
        assert data["did"] == self.did
        assert data["status"] == "ACTIVE"
        assert data["credential_count"] >= 1

    # ------------------------------------------------------------------
    # Step 8 — DID Deactivate → Token issuance denied
    # ------------------------------------------------------------------

    def test_14_did_deactivate(self, client):
        resp = client.post(f"/api/v1/did/deactivate/{self.did}")
        assert resp.status_code == 200, resp.text
        assert resp.json()["deactivated"] is True

    def test_15_token_issue_denied_after_deactivation(self, client):
        resp = client.post(
            "/api/v1/tokens/issue",
            headers={"Authorization": f"Bearer {self.session_token}"},
            json={"did": self.did, "scope": ["read:profile"]},
        )
        assert resp.status_code == 403, resp.text
        assert "deactivated" in resp.json()["detail"].lower()

    def test_16_admin_shows_deactivated_status(self, client):
        data = client.get(f"/api/v1/admin/identities/{self.did}").json()
        assert data["status"] == "DEACTIVATED"

    # ------------------------------------------------------------------
    # Step 9 — Admin force-revoke + ledger integrity
    # ------------------------------------------------------------------

    def test_17_admin_force_revoke(self, client):
        resp = client.post("/api/v1/admin/tokens/some-other-jti/revoke")
        assert resp.status_code == 200
        assert resp.json()["revoked"] is True

    def test_18_admin_health_healthy(self, client):
        data = client.get("/api/v1/admin/health").json()
        # Ledger integrity must still be valid (we deactivated via proper API, no tamper)
        assert data["ledger_integrity"] is True


# ---------------------------------------------------------------------------
# Require-WebAuthn gate — DID without credentials
# ---------------------------------------------------------------------------


class TestRequireWebAuthnGate:
    """Verifies that require_webauthn=True blocks DIDs with no credentials."""

    def test_token_denied_without_credential(self, client):
        # Create a brand-new DID (no WebAuthn credential registered)
        resp = client.post("/api/v1/did/create", json={"display_name": "NoCredDID"})
        assert resp.status_code == 201
        did = resp.json()["did"]
        session, _ = auth_session_store.create(did)

        resp = client.post(
            "/api/v1/tokens/issue",
            headers={"Authorization": f"Bearer {session}"},
            json={"did": did, "scope": ["read:profile"], "require_webauthn": True},
        )
        assert resp.status_code == 403
        assert "webauthn" in resp.json()["detail"].lower()

    def test_token_allowed_without_webauthn_when_flag_false(self, client):
        """Default require_webauthn=False — credential not required."""
        resp = client.post("/api/v1/did/create", json={"display_name": "FlagFalseDID"})
        assert resp.status_code == 201
        did = resp.json()["did"]
        session, _ = auth_session_store.create(did)

        resp = client.post(
            "/api/v1/tokens/issue",
            headers={"Authorization": f"Bearer {session}"},
            json={"did": did, "scope": ["read:profile"], "require_webauthn": False},
        )
        assert resp.status_code == 201
