"""
tests/unit/test_did_router.py — Module A: DID Registry & Cryptography API Tests
=================================================================================
Owner  : Member 3 (DID Registry & Cryptography)
Module : A — DID Registry HTTP API

Tests all 7 endpoints of the DID Registry router using FastAPI's TestClient.

No external services required — all operations are in-process.

Run:
    pytest tests/unit/test_did_router.py -v
"""

from __future__ import annotations

import base64
import hashlib
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.modules.identity.did_service import DIDService
from app.modules.identity.ed25519_service import Ed25519Service

# ---------------------------------------------------------------------------
# Module-level: wire the DID router to the ledger router's singleton so that
# anchor calls from Module A are visible via Module C endpoints in tests.
# (The app lifespan hook does this automatically at runtime, but TestClient
# does not trigger the lifespan by default.)
# ---------------------------------------------------------------------------
import app.modules.did.router as _did_router_module
import app.modules.ledger.router as _ledger_router_module

_did_router_module._shared_ledger = _ledger_router_module.ledger_instance


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_did_registry():
    """Isolate each test by resetting the in-process DID registry."""
    DIDService.registry_reset()
    yield
    DIDService.registry_reset()


@pytest.fixture
def client():
    """FastAPI TestClient bound to the app."""
    return TestClient(app)


def _b64url_decode(encoded: str) -> bytes:
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += "=" * padding
    return base64.urlsafe_b64decode(encoded)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Helper: create a DID via the API
# ---------------------------------------------------------------------------

def _create_did(client: TestClient, display_name: str = "Test User", anchor: bool = True) -> dict:
    """POST /did/create and return the response JSON."""
    resp = client.post(
        "/api/v1/did/create",
        json={"display_name": display_name, "anchor_to_ledger": anchor},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# ===========================================================================
# POST /api/v1/did/create
# ===========================================================================

class TestDIDCreate:
    def test_create_returns_201(self, client):
        resp = client.post("/api/v1/did/create", json={})
        assert resp.status_code == 201

    def test_create_response_contains_did(self, client):
        data = _create_did(client)
        assert data["did"].startswith("did:mesh:key:")

    def test_create_response_contains_public_key(self, client):
        data = _create_did(client)
        pub_bytes = _b64url_decode(data["public_key_b64"])
        assert len(pub_bytes) == 32

    def test_create_response_contains_private_key(self, client):
        data = _create_did(client)
        priv_bytes = _b64url_decode(data["private_key_b64"])
        assert len(priv_bytes) == 32

    def test_create_response_contains_did_document(self, client):
        data = _create_did(client)
        doc = data["did_document"]
        assert doc["id"] == data["did"]
        assert "verificationMethod" in doc
        assert len(doc["verificationMethod"]) == 1

    def test_create_with_ledger_anchor_returns_block_index(self, client):
        data = _create_did(client, anchor=True)
        assert data["ledger_record_index"] is not None
        assert data["ledger_record_index"] >= 1  # genesis is 0

    def test_create_without_ledger_anchor(self, client):
        resp = client.post(
            "/api/v1/did/create",
            json={"anchor_to_ledger": False},
        )
        assert resp.status_code == 201
        assert resp.json()["ledger_record_index"] is None

    def test_create_two_dids_are_unique(self, client):
        did1 = _create_did(client)["did"]
        did2 = _create_did(client)["did"]
        assert did1 != did2

    def test_create_private_and_public_key_match(self, client):
        """The returned private key must correspond to the returned public key."""
        data = _create_did(client)
        priv_bytes = _b64url_decode(data["private_key_b64"])
        pub_bytes = _b64url_decode(data["public_key_b64"])

        priv_key = Ed25519Service.private_key_from_bytes(priv_bytes)
        pub_key_from_priv = priv_key.public_key()
        assert Ed25519Service.public_key_to_bytes(pub_key_from_priv) == pub_bytes

    def test_create_message_field_present(self, client):
        data = _create_did(client)
        assert "message" in data
        assert data["did"] in data["message"]

    def test_create_with_display_name_in_metadata(self, client):
        data = _create_did(client, display_name="Alice")
        assert data["did"].startswith("did:mesh:key:")

    def test_create_with_extra_metadata(self, client):
        resp = client.post(
            "/api/v1/did/create",
            json={"metadata": {"org": "ACME"}, "anchor_to_ledger": True},
        )
        assert resp.status_code == 201


# ===========================================================================
# GET /api/v1/did/resolve/{did}
# ===========================================================================

class TestDIDResolve:
    def test_resolve_existing_did(self, client):
        did = _create_did(client)["did"]
        resp = client.get(f"/api/v1/did/resolve/{did}")
        assert resp.status_code == 200

    def test_resolve_returns_did_document(self, client):
        did = _create_did(client)["did"]
        data = client.get(f"/api/v1/did/resolve/{did}").json()
        assert data["did"] == did
        assert data["did_document"]["id"] == did

    def test_resolve_deactivated_flag_false_initially(self, client):
        did = _create_did(client)["did"]
        data = client.get(f"/api/v1/did/resolve/{did}").json()
        assert data["deactivated"] is False

    def test_resolve_unknown_did_returns_404(self, client):
        resp = client.get("/api/v1/did/resolve/did:mesh:key:unknownxxx")
        assert resp.status_code == 404

    def test_resolve_malformed_did_returns_400(self, client):
        resp = client.get("/api/v1/did/resolve/not-a-did")
        assert resp.status_code == 400

    def test_resolve_did_document_has_verification_method(self, client):
        did = _create_did(client)["did"]
        doc = client.get(f"/api/v1/did/resolve/{did}").json()["did_document"]
        assert "verificationMethod" in doc
        assert doc["verificationMethod"][0]["type"] == "Ed25519VerificationKey2020"

    def test_resolve_did_document_has_authentication(self, client):
        did = _create_did(client)["did"]
        doc = client.get(f"/api/v1/did/resolve/{did}").json()["did_document"]
        assert "authentication" in doc


# ===========================================================================
# GET /api/v1/did/exists/{did}
# ===========================================================================

class TestDIDExists:
    def test_exists_true_for_registered_did(self, client):
        did = _create_did(client)["did"]
        data = client.get(f"/api/v1/did/exists/{did}").json()
        assert data["exists"] is True

    def test_exists_false_for_unknown_did(self, client):
        data = client.get("/api/v1/did/exists/did:mesh:key:doesnotexist").json()
        assert data["exists"] is False

    def test_exists_never_returns_404(self, client):
        resp = client.get("/api/v1/did/exists/did:mesh:key:ghost")
        assert resp.status_code == 200

    def test_exists_deactivated_is_none_when_not_found(self, client):
        data = client.get("/api/v1/did/exists/did:mesh:key:nobody").json()
        assert data["deactivated"] is None

    def test_exists_deactivated_is_false_for_active_did(self, client):
        did = _create_did(client)["did"]
        data = client.get(f"/api/v1/did/exists/{did}").json()
        assert data["deactivated"] is False


# ===========================================================================
# GET /api/v1/did/list
# ===========================================================================

class TestDIDList:
    def test_list_empty_initially(self, client):
        data = client.get("/api/v1/did/list").json()
        assert data["total"] == 0
        assert data["dids"] == []

    def test_list_after_creating_one_did(self, client):
        did = _create_did(client)["did"]
        data = client.get("/api/v1/did/list").json()
        assert data["total"] == 1
        assert did in data["dids"]

    def test_list_after_creating_multiple_dids(self, client):
        dids = [_create_did(client)["did"] for _ in range(3)]
        data = client.get("/api/v1/did/list").json()
        assert data["total"] == 3
        for did in dids:
            assert did in data["dids"]

    def test_list_returns_200(self, client):
        resp = client.get("/api/v1/did/list")
        assert resp.status_code == 200


# ===========================================================================
# POST /api/v1/did/update/{did}
# ===========================================================================

class TestDIDUpdate:
    def test_update_returns_200(self, client):
        created = _create_did(client)
        did = created["did"]
        # Generate a new key pair for the update
        _, new_pub = Ed25519Service.generate_key_pair()
        new_pub_b64 = _b64url_encode(Ed25519Service.public_key_to_bytes(new_pub))

        resp = client.post(
            f"/api/v1/did/update/{did}",
            json={"new_public_key_b64": new_pub_b64},
        )
        assert resp.status_code == 200

    def test_update_anchors_on_ledger(self, client):
        did = _create_did(client)["did"]
        _, new_pub = Ed25519Service.generate_key_pair()
        new_pub_b64 = _b64url_encode(Ed25519Service.public_key_to_bytes(new_pub))

        data = client.post(
            f"/api/v1/did/update/{did}",
            json={"new_public_key_b64": new_pub_b64},
        ).json()
        assert "ledger_record_index" in data
        assert data["ledger_record_index"] >= 1

    def test_update_changes_public_key_in_registry(self, client):
        did = _create_did(client)["did"]
        _, new_pub = Ed25519Service.generate_key_pair()
        new_pub_bytes = Ed25519Service.public_key_to_bytes(new_pub)
        new_pub_b64 = _b64url_encode(new_pub_bytes)

        client.post(
            f"/api/v1/did/update/{did}",
            json={"new_public_key_b64": new_pub_b64},
        )

        # Resolve and check the new key is in the document
        doc = client.get(f"/api/v1/did/resolve/{did}").json()["did_document"]
        vm = doc["verificationMethod"][0]
        key_b58 = vm["publicKeyMultibase"].lstrip("z")
        from app.modules.identity.did_service import DIDService as DS
        recovered = DS._base58btc_decode(key_b58)
        assert recovered == new_pub_bytes

    def test_update_unknown_did_returns_404(self, client):
        _, new_pub = Ed25519Service.generate_key_pair()
        new_pub_b64 = _b64url_encode(Ed25519Service.public_key_to_bytes(new_pub))
        resp = client.post(
            "/api/v1/did/update/did:mesh:key:ghost",
            json={"new_public_key_b64": new_pub_b64},
        )
        assert resp.status_code == 404

    def test_update_invalid_public_key_returns_422(self, client):
        did = _create_did(client)["did"]
        resp = client.post(
            f"/api/v1/did/update/{did}",
            json={"new_public_key_b64": "not_valid_key_data_aaaaaaaa"},
        )
        assert resp.status_code == 422

    def test_update_message_contains_did(self, client):
        did = _create_did(client)["did"]
        _, new_pub = Ed25519Service.generate_key_pair()
        new_pub_b64 = _b64url_encode(Ed25519Service.public_key_to_bytes(new_pub))
        data = client.post(
            f"/api/v1/did/update/{did}",
            json={"new_public_key_b64": new_pub_b64},
        ).json()
        assert did in data["message"]


# ===========================================================================
# POST /api/v1/did/deactivate/{did}
# ===========================================================================

class TestDIDDeactivate:
    def test_deactivate_returns_200(self, client):
        did = _create_did(client)["did"]
        resp = client.post(f"/api/v1/did/deactivate/{did}", json={})
        assert resp.status_code == 200

    def test_deactivate_sets_deactivated_flag(self, client):
        did = _create_did(client)["did"]
        client.post(f"/api/v1/did/deactivate/{did}", json={})
        data = client.get(f"/api/v1/did/resolve/{did}").json()
        assert data["deactivated"] is True

    def test_deactivate_anchors_on_ledger(self, client):
        did = _create_did(client)["did"]
        data = client.post(f"/api/v1/did/deactivate/{did}", json={}).json()
        assert data["ledger_record_index"] is not None

    def test_deactivate_unknown_did_returns_404(self, client):
        resp = client.post("/api/v1/did/deactivate/did:mesh:key:ghost", json={})
        assert resp.status_code == 404

    def test_deactivate_twice_returns_409(self, client):
        did = _create_did(client)["did"]
        client.post(f"/api/v1/did/deactivate/{did}", json={})
        resp = client.post(f"/api/v1/did/deactivate/{did}", json={})
        assert resp.status_code == 409

    def test_deactivate_with_reason(self, client):
        did = _create_did(client)["did"]
        resp = client.post(
            f"/api/v1/did/deactivate/{did}",
            json={"reason": "Key compromised"},
        )
        assert resp.status_code == 200
        assert resp.json()["deactivated"] is True

    def test_deactivated_did_visible_in_exists(self, client):
        did = _create_did(client)["did"]
        client.post(f"/api/v1/did/deactivate/{did}", json={})
        data = client.get(f"/api/v1/did/exists/{did}").json()
        assert data["exists"] is True
        assert data["deactivated"] is True


# ===========================================================================
# POST /api/v1/did/verify-signature
# ===========================================================================

class TestDIDVerifySignature:
    def _make_sig_payload(self, did: str, priv_b64: str, message: bytes) -> dict:
        priv_bytes = _b64url_decode(priv_b64)
        priv_key = Ed25519Service.private_key_from_bytes(priv_bytes)
        signature = priv_key.sign(message)
        return {
            "did": did,
            "message_b64": _b64url_encode(message),
            "signature_b64": _b64url_encode(signature),
        }

    def test_valid_signature_returns_valid_true(self, client):
        created = _create_did(client)
        payload = self._make_sig_payload(
            created["did"], created["private_key_b64"], b"hello world"
        )
        resp = client.post("/api/v1/did/verify-signature", json=payload)
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_invalid_signature_returns_valid_false(self, client):
        created = _create_did(client)
        # Generate a different private key to sign — should fail
        other_priv, _ = Ed25519Service.generate_key_pair()
        bad_sig = other_priv.sign(b"hello world")
        payload = {
            "did": created["did"],
            "message_b64": _b64url_encode(b"hello world"),
            "signature_b64": _b64url_encode(bad_sig),
        }
        resp = client.post("/api/v1/did/verify-signature", json=payload)
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    def test_tampered_message_fails_verification(self, client):
        created = _create_did(client)
        payload = self._make_sig_payload(
            created["did"], created["private_key_b64"], b"original message"
        )
        # Tamper with the message
        payload["message_b64"] = _b64url_encode(b"tampered message")
        resp = client.post("/api/v1/did/verify-signature", json=payload)
        assert resp.json()["valid"] is False

    def test_verify_unknown_did_returns_404(self, client):
        payload = {
            "did": "did:mesh:key:nobody",
            "message_b64": _b64url_encode(b"msg"),
            "signature_b64": _b64url_encode(b"x" * 64),
        }
        resp = client.post("/api/v1/did/verify-signature", json=payload)
        assert resp.status_code == 404

    def test_verify_deactivated_did_returns_403(self, client):
        created = _create_did(client)
        did = created["did"]
        client.post(f"/api/v1/did/deactivate/{did}", json={})
        payload = self._make_sig_payload(did, created["private_key_b64"], b"msg")
        resp = client.post("/api/v1/did/verify-signature", json=payload)
        assert resp.status_code == 403

    def test_verify_returns_did_in_response(self, client):
        created = _create_did(client)
        payload = self._make_sig_payload(
            created["did"], created["private_key_b64"], b"test"
        )
        data = client.post("/api/v1/did/verify-signature", json=payload).json()
        assert data["did"] == created["did"]

    def test_verify_empty_message(self, client):
        created = _create_did(client)
        payload = self._make_sig_payload(
            created["did"], created["private_key_b64"], b""
        )
        resp = client.post("/api/v1/did/verify-signature", json=payload)
        assert resp.status_code == 200
        assert resp.json()["valid"] is True


# ===========================================================================
# End-to-End Integration: DID → Ledger → Token
# ===========================================================================

class TestDIDEndToEndIntegration:
    def test_full_lifecycle_create_anchor_token(self, client):
        """
        Create a DID (anchored on the shared ledger) → verify it appears on the
        ledger endpoint → issue a JWT token for it.
        """
        # Also wire the tokens policy engine to use the same shared ledger
        import app.modules.tokens.router as _tokens_router_module
        from app.modules.tokens.policy import ZeroTrustPolicyEngine
        shared = _ledger_router_module.ledger_instance
        _tokens_router_module._shared_ledger = shared
        _tokens_router_module._policy_engine = ZeroTrustPolicyEngine(ledger=shared)

        # 1. Create DID (anchors to ledger automatically)
        created = _create_did(client)
        did = created["did"]
        assert created["ledger_record_index"] is not None

        # 2. Confirm it's on the ledger
        ledger_resp = client.get(f"/api/v1/ledger/latest/{did}")
        assert ledger_resp.status_code == 200, ledger_resp.text
        ledger_data = ledger_resp.json()
        assert ledger_data["did"] == did
        assert ledger_data["operation"] == "CREATE"

        # 3. Issue a JWT for the DID
        token_resp = client.post(
            "/api/v1/tokens/issue",
            json={"did": did, "scope": ["read:profile"]},
        )
        assert token_resp.status_code == 201, token_resp.text
        assert "access_token" in token_resp.json()

    def test_deactivated_did_cannot_get_token(self, client):
        """
        After deactivating a DID, the Zero-Trust policy engine must
        reject token issuance for it.
        """
        # Create and anchor the DID
        created = _create_did(client)
        did = created["did"]

        # Deactivate via Module A
        deact_resp = client.post(f"/api/v1/did/deactivate/{did}", json={})
        assert deact_resp.status_code == 200

        # Attempt token issuance — must be denied
        token_resp = client.post(
            "/api/v1/tokens/issue",
            json={"did": did, "scope": ["read:profile"]},
        )
        assert token_resp.status_code == 403

    def test_did_document_public_key_used_for_signature_verification(self, client):
        """
        Sign a message with the private key returned at creation, then
        verify the signature using the /verify-signature endpoint.
        """
        created = _create_did(client)
        message = b"zero-trust identity proof"
        priv_bytes = _b64url_decode(created["private_key_b64"])
        priv_key = Ed25519Service.private_key_from_bytes(priv_bytes)
        signature = priv_key.sign(message)

        verify_resp = client.post(
            "/api/v1/did/verify-signature",
            json={
                "did": created["did"],
                "message_b64": _b64url_encode(message),
                "signature_b64": _b64url_encode(signature),
            },
        )
        assert verify_resp.status_code == 200
        assert verify_resp.json()["valid"] is True

    def test_ledger_integrity_after_did_lifecycle(self, client):
        """
        After create → update → deactivate operations, the ledger chain
        must remain cryptographically valid.
        """
        # Create
        created = _create_did(client)
        did = created["did"]

        # Update key
        _, new_pub = Ed25519Service.generate_key_pair()
        new_pub_b64 = _b64url_encode(Ed25519Service.public_key_to_bytes(new_pub))
        client.post(f"/api/v1/did/update/{did}", json={"new_public_key_b64": new_pub_b64})

        # Deactivate
        client.post(f"/api/v1/did/deactivate/{did}", json={})

        # Verify ledger integrity
        integrity = client.get("/api/v1/ledger/verify").json()
        assert integrity["valid"] is True, f"Ledger corrupted: {integrity['error']}"

    def test_did_history_shows_all_lifecycle_events(self, client):
        """
        After create → update → deactivate, the ledger history for the DID
        must contain CREATE, UPDATE, and DEACTIVATE records.
        Both Module A and Module C must share the same ledger instance.
        """
        created = _create_did(client)
        did = created["did"]

        _, new_pub = Ed25519Service.generate_key_pair()
        new_pub_b64 = _b64url_encode(Ed25519Service.public_key_to_bytes(new_pub))
        client.post(f"/api/v1/did/update/{did}", json={"new_public_key_b64": new_pub_b64})
        client.post(f"/api/v1/did/deactivate/{did}", json={})

        history_resp = client.get(f"/api/v1/ledger/history/{did}")
        assert history_resp.status_code == 200, history_resp.text
        history = history_resp.json()
        assert isinstance(history, list), f"Expected list, got: {type(history)}"
        operations = [r["operation"] for r in history]
        assert "CREATE" in operations
        assert "UPDATE" in operations
        assert "DEACTIVATE" in operations
