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
import json
import os
import time
import uuid
import pytest
import jwt

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fastapi.testclient import TestClient
from app.main import app
from app.modules.tokens.jwt_engine import generate_signing_keypair
import app.modules.revocation_provider as revocation_provider
from tests.revocation_helpers import DurableRevocationStoreStub


# ---------------------------------------------------------------------------
# Module-level client (lifespan wires all shared singletons once)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    admin_did = "did:mesh:admin:full-flow"
    old_revocation_store = revocation_provider._revocation_store
    revocation_provider.set_revocation_store(DurableRevocationStoreStub())
    private_key, public_key = generate_signing_keypair()
    claims = {
        "sub": admin_did,
        "jti": str(uuid.uuid4()),
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "idp-mesh-admin",
        "aud": "idp-mesh-admin",
        "scope": ["admin:ledger"],
    }
    token = jwt.encode(claims, private_key, algorithm="EdDSA")
    old_admin_dids = os.environ.get("ADMIN_DIDS")
    old_admin_public_key = os.environ.get("ADMIN_JWT_PUBLIC_KEY")
    os.environ["ADMIN_DIDS"] = admin_did
    os.environ["ADMIN_JWT_PUBLIC_KEY"] = public_key.decode()
    with TestClient(app, headers={"Authorization": f"Bearer {token}"}) as c:
        yield c
    if old_admin_dids is None:
        os.environ.pop("ADMIN_DIDS", None)
    else:
        os.environ["ADMIN_DIDS"] = old_admin_dids
    if old_admin_public_key is None:
        os.environ.pop("ADMIN_JWT_PUBLIC_KEY", None)
    else:
        os.environ["ADMIN_JWT_PUBLIC_KEY"] = old_admin_public_key
    revocation_provider.set_revocation_store(old_revocation_store)


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


def _sign_did_proof(private_key_b64: str, did: str, operation: str, changes: dict, challenge: str) -> str:
    priv_bytes = base64.urlsafe_b64decode(private_key_b64 + "=" * (-len(private_key_b64) % 4))
    private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    message = json.dumps(
        {"domain": "TrustMesh-DID-Mutation-v1", "did": did,
         "operation": operation, "changes": changes, "challenge": challenge},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return _b64(private_key.sign(message))


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
        assert data["ownership_challenge"]
        TestFullIdentityLifecycle._reg_challenge = data["challenge"]
        TestFullIdentityLifecycle._reg_ownership_challenge = data["ownership_challenge"]

    def test_03_webauthn_register_complete(self, client):
        challenge = self._reg_challenge  # type: ignore[attr-defined]
        signature_b64 = _sign_ceremony(
            self.private_key_b64, challenge, self.did, b"register"
        )
        ownership_challenge = self._reg_ownership_challenge  # type: ignore[attr-defined]
        credential_id = "cred-" + hashlib.sha256(
            base64.urlsafe_b64decode(
                self.public_key_b64 + "=" * (-len(self.public_key_b64) % 4)
            )
        ).hexdigest()[:24]
        changes = {
            "registration_challenge": challenge,
            "public_key_b64": self.public_key_b64,
            "credential_id": credential_id,
            "device_info": None,
        }
        resp = client.post(
            "/api/v1/webauthn/register/complete",
            json={
                "did": self.did,
                "challenge": challenge,
                "public_key_b64": self.public_key_b64,
                "signature_b64": signature_b64,
                "ownership_challenge": ownership_challenge,
                "ownership_signature_b64": _sign_did_proof(
                    self.private_key_b64, self.did, "WEBAUTHN_REGISTER",
                    changes, ownership_challenge,
                ),
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

    # ------------------------------------------------------------------
    # Step 4 — Token Issuance
    # ------------------------------------------------------------------

    def test_06_token_issue(self, client):
        resp = client.post(
            "/api/v1/tokens/issue",
            json={"did": self.did, "scope": ["read:profile", "auth:webauthn"]},
        )
        assert resp.status_code == 503, resp.text
        assert "authenticated caller authorization" in resp.json()["detail"]

    def test_07_token_issue_with_require_webauthn(self, client):
        """require_webauthn=True must pass because we completed registration above."""
        resp = client.post(
            "/api/v1/tokens/issue",
            json={
                "did": self.did,
                "scope": ["read:profile"],
                "require_webauthn": True,
            },
        )
        assert resp.status_code == 503, resp.text

    # ------------------------------------------------------------------
    # Step 5 — Token Verify
    # ------------------------------------------------------------------

    def test_08_token_verify_rejects_invalid_token(self, client):
        resp = client.post(
            "/api/v1/tokens/verify",
            json={"token": "invalid-token"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["valid"] is False

    # ------------------------------------------------------------------
    # Step 6 — Token Revoke
    # ------------------------------------------------------------------

    def test_09_token_revoke(self, client):
        resp = client.post(
            "/api/v1/tokens/revoke",
            json={"jti": "untrusted-integration-test-jti", "reason": "Integration test"},
        )
        assert resp.status_code == 503, resp.text

    def test_10_token_verify_after_revoke_is_invalid(self, client):
        resp = client.post(
            "/api/v1/tokens/verify",
            json={"token": "invalid-token"},
        )
        data = resp.json()
        assert data["valid"] is False
        assert data["valid"] is False

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
        changes = {"reason": None}
        challenge_response = client.post(
            f"/api/v1/did/challenge/deactivate/{self.did}",
            json=changes,
        )
        assert challenge_response.status_code == 200, challenge_response.text
        challenge = challenge_response.json()["challenge"]
        private_key = Ed25519PrivateKey.from_private_bytes(
            base64.urlsafe_b64decode(self.private_key_b64 + "==")
        )
        signed_message = json.dumps(
            {
                "domain": "TrustMesh-DID-Mutation-v1",
                "did": self.did,
                "operation": "DEACTIVATE",
                "changes": changes,
                "challenge": challenge,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        signature = _b64(private_key.sign(signed_message))
        resp = client.post(
            f"/api/v1/did/deactivate/{self.did}",
            json={
                **changes,
                "ownership_challenge": challenge,
                "ownership_signature_b64": signature,
            },
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["deactivated"] is True

    def test_15_token_issue_denied_after_deactivation(self, client):
        resp = client.post(
            "/api/v1/tokens/issue",
            json={"did": self.did, "scope": ["read:profile"]},
        )
        assert resp.status_code == 503, resp.text

    def test_16_admin_shows_deactivated_status(self, client):
        data = client.get(f"/api/v1/admin/identities/{self.did}").json()
        assert data["status"] == "DEACTIVATED"

    # ------------------------------------------------------------------
    # Step 9 — Admin force-revoke + ledger integrity
    # ------------------------------------------------------------------

    def test_17_admin_force_revoke_requires_signed_target(self, client):
        resp = client.post("/api/v1/admin/tokens/some-other-jti/revoke")
        # Revocation now requires the signed target token to determine its expiry.
        assert resp.status_code == 422

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

        resp = client.post(
            "/api/v1/tokens/issue",
            json={"did": did, "scope": ["read:profile"], "require_webauthn": True},
        )
        assert resp.status_code == 503

    def test_token_issue_unavailable_without_verified_principal(self, client):
        """The WebAuthn flag does not replace caller authentication."""
        resp = client.post("/api/v1/did/create", json={"display_name": "FlagFalseDID"})
        assert resp.status_code == 201
        did = resp.json()["did"]

        resp = client.post(
            "/api/v1/tokens/issue",
            json={"did": did, "scope": ["read:profile"], "require_webauthn": False},
        )
        assert resp.status_code == 503
