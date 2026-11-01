"""
tests/unit/test_webauthn.py — Unit Tests for Module B (WebAuthn/FIDO2)
======================================================================
Owner  : Member 2 (WebAuthn / FIDO2 Biometric Auth)
Branch : feature/webauthn-module

Coverage:
  - ChallengeStore: creation, consumption, TTL expiry, replay prevention
  - CredentialStore: registration, lookup, sign-count, DID index
  - WebAuthnService: begin/complete registration + authentication
  - FastAPI router: all 5 endpoints via TestClient
  - Integration: full end-to-end register → authenticate → token flow
"""

import base64
import hashlib
import time
import unittest
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.modules.webauthn.challenge_store import ChallengeStore
from app.modules.webauthn.credential_store import CredentialStore
from app.modules.webauthn.webauthn_service import (
    WebAuthnService,
    _build_pre_image,
    _decode_b64url,
    _verify_ed25519,
)
import app.modules.webauthn.router as webauthn_router_module
from app.modules.webauthn.router import router as webauthn_api_router
import app.modules.did.router as did_router_module
from app.modules.identity.did_service import DIDService, _did_registry
from app.modules.ledger.chain import SimulatedLedger


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _generate_keypair():
    """Return (private_key, public_key_bytes, public_key_b64url)."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    pub_b64 = base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()
    return priv, pub_bytes, pub_b64


def _sign_ceremony(private_key, challenge_bytes: bytes, did: str, ceremony: str) -> str:
    """Produce a base64url-encoded Ed25519 signature for the canonical pre-image."""
    pre_image = _build_pre_image(challenge_bytes, did, ceremony)
    sig_bytes = private_key.sign(pre_image)
    return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()


def _make_fresh_service(ledger=None):
    """Return a fresh WebAuthnService with isolated stores."""
    return WebAuthnService(
        challenge_store=ChallengeStore(),
        credential_store=CredentialStore(),
        ledger=ledger,
    )


# ===========================================================================
# ChallengeStore Tests
# ===========================================================================

class TestChallengeStore(unittest.TestCase):
    """Validates challenge issuance, single-use consumption, and TTL semantics."""

    def setUp(self):
        self.store = ChallengeStore(ttl_seconds=60)

    def test_create_returns_bytes_and_b64(self):
        ch_bytes, ch_b64 = self.store.create_challenge("did:mesh:key:abc", "register")
        self.assertIsInstance(ch_bytes, bytes)
        self.assertEqual(len(ch_bytes), 32)
        self.assertIsInstance(ch_b64, str)
        self.assertGreater(len(ch_b64), 0)

    def test_create_challenge_different_each_call(self):
        _, b1 = self.store.create_challenge("did:mesh:key:abc", "register")
        _, b2 = self.store.create_challenge("did:mesh:key:abc", "register")
        self.assertNotEqual(b1, b2)

    def test_consume_returns_correct_bytes(self):
        ch_bytes, ch_b64 = self.store.create_challenge("did:mesh:key:abc", "register")
        consumed = self.store.consume_challenge(ch_b64, "did:mesh:key:abc", "register")
        self.assertEqual(consumed, ch_bytes)

    def test_consume_is_single_use(self):
        _, ch_b64 = self.store.create_challenge("did:mesh:key:abc", "register")
        self.store.consume_challenge(ch_b64, "did:mesh:key:abc", "register")
        with self.assertRaises(ValueError):
            self.store.consume_challenge(ch_b64, "did:mesh:key:abc", "register")

    def test_consume_unknown_challenge_raises(self):
        with self.assertRaises(ValueError):
            self.store.consume_challenge("nonexistent_challenge_xyz", "did:mesh:key:abc", "register")

    def test_consume_wrong_did_raises(self):
        _, ch_b64 = self.store.create_challenge("did:mesh:key:alice", "register")
        with self.assertRaises(ValueError):
            self.store.consume_challenge(ch_b64, "did:mesh:key:bob", "register")

    def test_consume_wrong_ceremony_raises(self):
        _, ch_b64 = self.store.create_challenge("did:mesh:key:abc", "register")
        with self.assertRaises(ValueError):
            self.store.consume_challenge(ch_b64, "did:mesh:key:abc", "authenticate")

    def test_expired_challenge_raises(self):
        store = ChallengeStore(ttl_seconds=1)
        _, ch_b64 = store.create_challenge("did:mesh:key:abc", "register")
        time.sleep(1.1)
        with self.assertRaises(ValueError) as ctx:
            store.consume_challenge(ch_b64, "did:mesh:key:abc", "register")
        self.assertIn("expired", str(ctx.exception).lower())

    def test_has_challenge_returns_true_before_consume(self):
        _, ch_b64 = self.store.create_challenge("did:mesh:key:abc", "register")
        self.assertTrue(self.store.has_challenge(ch_b64))

    def test_has_challenge_returns_false_after_consume(self):
        _, ch_b64 = self.store.create_challenge("did:mesh:key:abc", "register")
        self.store.consume_challenge(ch_b64, "did:mesh:key:abc", "register")
        self.assertFalse(self.store.has_challenge(ch_b64))

    def test_clear_empties_store(self):
        self.store.create_challenge("did:mesh:key:abc", "register")
        self.store.clear()
        self.assertEqual(self.store.pending_count(), 0)

    def test_pending_count_increments(self):
        self.store.create_challenge("did:mesh:key:a", "register")
        self.store.create_challenge("did:mesh:key:b", "authenticate")
        self.assertGreaterEqual(self.store.pending_count(), 2)


# ===========================================================================
# CredentialStore Tests
# ===========================================================================

class TestCredentialStore(unittest.TestCase):
    """Validates credential registration, lookup, and sign-count behavior."""

    def setUp(self):
        self.store = CredentialStore()
        _, self.pub_bytes, self.pub_b64 = _generate_keypair()
        self.did = "did:mesh:key:test001"

    def test_register_returns_stored_credential(self):
        cred = self.store.register(self.did, self.pub_bytes)
        self.assertEqual(cred.did, self.did)
        self.assertEqual(cred.public_key_bytes, self.pub_bytes)
        self.assertIsNotNone(cred.credential_id)
        self.assertEqual(cred.sign_count, 0)

    def test_derive_credential_id_is_deterministic(self):
        id1 = CredentialStore.derive_credential_id(self.pub_bytes)
        id2 = CredentialStore.derive_credential_id(self.pub_bytes)
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("cred-"))

    def test_register_duplicate_raises(self):
        self.store.register(self.did, self.pub_bytes)
        with self.assertRaises(ValueError):
            self.store.register(self.did, self.pub_bytes)

    def test_register_custom_credential_id(self):
        cred = self.store.register(self.did, self.pub_bytes, credential_id="custom-id-xyz")
        self.assertEqual(cred.credential_id, "custom-id-xyz")

    def test_get_credential_returns_registered(self):
        cred = self.store.register(self.did, self.pub_bytes)
        found = self.store.get_credential(cred.credential_id)
        self.assertIsNotNone(found)
        self.assertEqual(found.credential_id, cred.credential_id)

    def test_get_credential_returns_none_for_unknown(self):
        result = self.store.get_credential("nonexistent-cred-id")
        self.assertIsNone(result)

    def test_list_credentials_for_did(self):
        _, pub2, _ = _generate_keypair()
        cred1 = self.store.register(self.did, self.pub_bytes)
        cred2 = self.store.register(self.did, pub2, credential_id="cred-second")
        results = self.store.list_credentials_for_did(self.did)
        ids = [c.credential_id for c in results]
        self.assertIn(cred1.credential_id, ids)
        self.assertIn(cred2.credential_id, ids)

    def test_list_credentials_empty_for_unknown_did(self):
        self.assertEqual(self.store.list_credentials_for_did("did:mesh:key:unknown"), [])

    def test_increment_sign_count(self):
        cred = self.store.register(self.did, self.pub_bytes)
        new_count = self.store.increment_sign_count(cred.credential_id)
        self.assertEqual(new_count, 1)
        new_count = self.store.increment_sign_count(cred.credential_id)
        self.assertEqual(new_count, 2)

    def test_increment_sign_count_unknown_raises(self):
        with self.assertRaises(KeyError):
            self.store.increment_sign_count("nonexistent-id")

    def test_has_credentials_for_did(self):
        self.assertFalse(self.store.has_credentials_for_did(self.did))
        self.store.register(self.did, self.pub_bytes)
        self.assertTrue(self.store.has_credentials_for_did(self.did))

    def test_clear_removes_all(self):
        self.store.register(self.did, self.pub_bytes)
        self.store.clear()
        self.assertEqual(self.store.total_count(), 0)


# ===========================================================================
# WebAuthnService Tests
# ===========================================================================

class TestWebAuthnServiceRegistration(unittest.TestCase):
    """Tests the server-side registration ceremony logic."""

    def setUp(self):
        self.did = "did:mesh:key:service001"
        self.priv, self.pub_bytes, self.pub_b64 = _generate_keypair()
        self.service = _make_fresh_service()

    def _do_begin(self) -> str:
        response = self.service.begin_registration(self.did)
        return response.challenge

    def _sign_and_complete(self, challenge_b64: str) -> object:
        ch_bytes = _decode_b64url(challenge_b64)
        sig_b64 = _sign_ceremony(self.priv, ch_bytes, self.did, "register")
        return self.service.complete_registration(
            did=self.did,
            challenge_b64=challenge_b64,
            public_key_b64=self.pub_b64,
            signature_b64=sig_b64,
        )

    def test_begin_registration_returns_challenge(self):
        resp = self.service.begin_registration(self.did)
        self.assertIsNotNone(resp.challenge)
        self.assertEqual(resp.did, self.did)
        self.assertEqual(resp.rp_id, "idp-mesh-v1")

    def test_complete_registration_success(self):
        ch_b64 = self._do_begin()
        result = self._sign_and_complete(ch_b64)
        self.assertTrue(result.success)
        self.assertEqual(result.did, self.did)
        self.assertIsNotNone(result.credential_id)

    def test_registration_with_invalid_did_raises(self):
        with self.assertRaises(ValueError):
            self.service.begin_registration("not-a-valid-did")

    def test_complete_registration_wrong_signature_raises(self):
        ch_b64 = self._do_begin()
        # Sign with a different key
        other_priv, _, _ = _generate_keypair()
        ch_bytes = _decode_b64url(ch_b64)
        bad_sig = _sign_ceremony(other_priv, ch_bytes, self.did, "register")
        with self.assertRaises(ValueError) as ctx:
            self.service.complete_registration(
                did=self.did,
                challenge_b64=ch_b64,
                public_key_b64=self.pub_b64,
                signature_b64=bad_sig,
            )
        self.assertIn("Signature verification failed", str(ctx.exception))

    def test_complete_registration_wrong_ceremony_tag_raises(self):
        ch_b64 = self._do_begin()
        ch_bytes = _decode_b64url(ch_b64)
        # Sign with "authenticate" tag instead of "register"
        wrong_sig = _sign_ceremony(self.priv, ch_bytes, self.did, "authenticate")
        with self.assertRaises(ValueError):
            self.service.complete_registration(
                did=self.did,
                challenge_b64=ch_b64,
                public_key_b64=self.pub_b64,
                signature_b64=wrong_sig,
            )

    def test_complete_registration_replay_raises(self):
        """Consuming same challenge twice must fail."""
        ch_b64 = self._do_begin()
        self._sign_and_complete(ch_b64)
        with self.assertRaises(ValueError):
            self._sign_and_complete(ch_b64)

    def test_complete_registration_invalid_b64_public_key_raises(self):
        ch_b64 = self._do_begin()
        ch_bytes = _decode_b64url(ch_b64)
        sig_b64 = _sign_ceremony(self.priv, ch_bytes, self.did, "register")
        with self.assertRaises(ValueError):
            self.service.complete_registration(
                did=self.did,
                challenge_b64=ch_b64,
                public_key_b64="!!!invalid-base64!!!",
                signature_b64=sig_b64,
            )


class TestWebAuthnServiceAuthentication(unittest.TestCase):
    """Tests the server-side authentication ceremony logic."""

    def setUp(self):
        self.did = "did:mesh:key:authtest"
        self.priv, self.pub_bytes, self.pub_b64 = _generate_keypair()
        self.service = _make_fresh_service()
        # Pre-register a credential
        reg_begin = self.service.begin_registration(self.did)
        ch_bytes = _decode_b64url(reg_begin.challenge)
        sig_b64 = _sign_ceremony(self.priv, ch_bytes, self.did, "register")
        reg_result = self.service.complete_registration(
            did=self.did,
            challenge_b64=reg_begin.challenge,
            public_key_b64=self.pub_b64,
            signature_b64=sig_b64,
        )
        self.credential_id = reg_result.credential_id

    def test_begin_authentication_returns_challenge_and_cred_ids(self):
        resp = self.service.begin_authentication(self.did)
        self.assertIsNotNone(resp.challenge)
        self.assertIn(self.credential_id, resp.credential_ids)

    def test_begin_authentication_unregistered_did_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self.service.begin_authentication("did:mesh:key:nobody")
        self.assertIn("No credentials registered", str(ctx.exception))

    def test_complete_authentication_success(self):
        auth_begin = self.service.begin_authentication(self.did)
        ch_bytes = _decode_b64url(auth_begin.challenge)
        sig_b64 = _sign_ceremony(self.priv, ch_bytes, self.did, "authenticate")
        result = self.service.complete_authentication(
            did=self.did,
            challenge_b64=auth_begin.challenge,
            credential_id=self.credential_id,
            signature_b64=sig_b64,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.did, self.did)

    def test_complete_authentication_sign_count_increments(self):
        for expected_count in [1, 2, 3]:
            auth_begin = self.service.begin_authentication(self.did)
            ch_bytes = _decode_b64url(auth_begin.challenge)
            sig_b64 = _sign_ceremony(self.priv, ch_bytes, self.did, "authenticate")
            result = self.service.complete_authentication(
                did=self.did,
                challenge_b64=auth_begin.challenge,
                credential_id=self.credential_id,
                signature_b64=sig_b64,
            )
            self.assertIn(f"sign_count={expected_count}", result.message)

    def test_complete_authentication_wrong_signature_raises(self):
        auth_begin = self.service.begin_authentication(self.did)
        ch_bytes = _decode_b64url(auth_begin.challenge)
        other_priv, _, _ = _generate_keypair()
        bad_sig = _sign_ceremony(other_priv, ch_bytes, self.did, "authenticate")
        with self.assertRaises(ValueError):
            self.service.complete_authentication(
                did=self.did,
                challenge_b64=auth_begin.challenge,
                credential_id=self.credential_id,
                signature_b64=bad_sig,
            )

    def test_complete_authentication_unknown_credential_raises(self):
        auth_begin = self.service.begin_authentication(self.did)
        ch_bytes = _decode_b64url(auth_begin.challenge)
        sig_b64 = _sign_ceremony(self.priv, ch_bytes, self.did, "authenticate")
        with self.assertRaises(ValueError) as ctx:
            self.service.complete_authentication(
                did=self.did,
                challenge_b64=auth_begin.challenge,
                credential_id="cred-does-not-exist",
                signature_b64=sig_b64,
            )
        self.assertIn("not registered", str(ctx.exception))

    def test_complete_authentication_credential_did_mismatch_raises(self):
        """Using credential from DID-A to authenticate as DID-B must fail."""
        other_did = "did:mesh:key:other"
        other_priv, other_pub_bytes, other_pub_b64 = _generate_keypair()
        reg2 = self.service.begin_registration(other_did)
        ch2 = _decode_b64url(reg2.challenge)
        sig2 = _sign_ceremony(other_priv, ch2, other_did, "register")
        reg2_result = self.service.complete_registration(
            did=other_did,
            challenge_b64=reg2.challenge,
            public_key_b64=other_pub_b64,
            signature_b64=sig2,
        )

        # Now try to authenticate as original DID using other_did's credential
        auth_begin = self.service.begin_authentication(self.did)
        ch_bytes = _decode_b64url(auth_begin.challenge)
        sig_b64 = _sign_ceremony(self.priv, ch_bytes, self.did, "authenticate")
        with self.assertRaises(ValueError) as ctx:
            self.service.complete_authentication(
                did=self.did,
                challenge_b64=auth_begin.challenge,
                credential_id=reg2_result.credential_id,  # Wrong credential
                signature_b64=sig_b64,
            )
        self.assertIn("belongs to DID", str(ctx.exception))


# ===========================================================================
# Router / HTTP Endpoint Tests
# ===========================================================================

class TestWebAuthnRouter(unittest.TestCase):
    """End-to-end HTTP tests for all 5 WebAuthn endpoints via FastAPI TestClient."""

    def setUp(self):
        # Isolate router singletons from other tests
        webauthn_router_module._challenge_store = ChallengeStore()
        webauthn_router_module._credential_store = CredentialStore()
        self.ledger = SimulatedLedger(auto_genesis=True)
        webauthn_router_module._shared_ledger = self.ledger
        did_router_module._shared_ledger = self.ledger
        did_router_module._did_mutation_challenge_store = ChallengeStore(ttl_seconds=300)
        webauthn_router_module._webauthn_service = WebAuthnService(
            challenge_store=webauthn_router_module._challenge_store,
            credential_store=webauthn_router_module._credential_store,
            ledger=self.ledger,
        )
        _did_registry.clear()
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(webauthn_api_router)
        self.client = TestClient(app, raise_server_exceptions=False)

        self.priv, self.pub_bytes, self.pub_b64 = _generate_keypair()
        self.did = DIDService.create_did(self.priv.public_key())
        self.other_priv, _, _ = _generate_keypair()
        self.other_did = DIDService.create_did(self.other_priv.public_key())

    def _ownership_signature(self, did, private_key, challenge, changes, operation="WEBAUTHN_REGISTER"):
        from app.modules.did.router import did_mutation_proof_message
        message = did_mutation_proof_message(did, operation, changes, challenge)
        return base64.urlsafe_b64encode(private_key.sign(message)).rstrip(b"=").decode()

    def _register(self):
        """Helper: perform full registration via HTTP and return credential_id."""
        begin_resp = self.client.post(
            "/webauthn/register/begin",
            json={"did": self.did, "display_name": "Test User"},
        )
        self.assertEqual(begin_resp.status_code, 200)
        challenge_b64 = begin_resp.json()["challenge"]
        ownership_challenge = begin_resp.json()["ownership_challenge"]

        ch_bytes = _decode_b64url(challenge_b64)
        sig_b64 = _sign_ceremony(self.priv, ch_bytes, self.did, "register")

        credential_id = CredentialStore.derive_credential_id(self.pub_bytes)
        changes = {
            "registration_challenge": challenge_b64,
            "public_key_b64": self.pub_b64,
            "credential_id": credential_id,
            "device_info": None,
        }
        complete_resp = self.client.post(
            "/webauthn/register/complete",
            json={
                "did": self.did,
                "challenge": challenge_b64,
                "public_key_b64": self.pub_b64,
                "signature_b64": sig_b64,
                "ownership_challenge": ownership_challenge,
                "ownership_signature_b64": self._ownership_signature(
                    self.did, self.priv, ownership_challenge, changes
                ),
            },
        )
        self.assertEqual(complete_resp.status_code, 201)
        return complete_resp.json()["credential_id"]

    def test_register_begin_returns_200(self):
        resp = self.client.post(
            "/webauthn/register/begin",
            json={"did": self.did},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("challenge", data)
        self.assertIn("ownership_challenge", data)
        self.assertEqual(data["did"], self.did)

    def test_register_begin_invalid_did_returns_400(self):
        resp = self.client.post(
            "/webauthn/register/begin",
            json={"did": "not-a-did"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_register_complete_success_returns_201(self):
        cred_id = self._register()
        self.assertIsNotNone(cred_id)
        self.assertEqual(webauthn_router_module._credential_store.total_count(), 1)
        self.assertEqual(self.ledger.verify_integrity(), (True, None))

    def test_register_complete_bad_signature_returns_401(self):
        begin_resp = self.client.post(
            "/webauthn/register/begin", json={"did": self.did}
        )
        challenge_b64 = begin_resp.json()["challenge"]
        ownership_challenge = begin_resp.json()["ownership_challenge"]
        ch_bytes = _decode_b64url(challenge_b64)
        # Sign with a different key
        other_priv, _, _ = _generate_keypair()
        bad_sig = _sign_ceremony(other_priv, ch_bytes, self.did, "register")
        changes = {
            "registration_challenge": challenge_b64,
            "public_key_b64": self.pub_b64,
            "credential_id": CredentialStore.derive_credential_id(self.pub_bytes),
            "device_info": None,
        }
        resp = self.client.post(
            "/webauthn/register/complete",
            json={
                "did": self.did,
                "challenge": challenge_b64,
                "public_key_b64": self.pub_b64,
                "signature_b64": bad_sig,
                "ownership_challenge": ownership_challenge,
                "ownership_signature_b64": self._ownership_signature(
                    self.did, self.priv, ownership_challenge, changes
                ),
            },
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(webauthn_router_module._credential_store.total_count(), 0)
        self.assertEqual(len(self.ledger), 1)
        self.assertEqual(self.ledger.verify_integrity(), (True, None))

    def test_authenticate_begin_no_credentials_returns_404(self):
        resp = self.client.post(
            "/webauthn/authenticate/begin",
            json={"did": self.did},
        )
        self.assertEqual(resp.status_code, 404)

    def test_authenticate_begin_after_registration_returns_200(self):
        self._register()
        resp = self.client.post(
            "/webauthn/authenticate/begin",
            json={"did": self.did},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("challenge", data)
        self.assertIn("credential_ids", data)

    def test_authenticate_complete_success_returns_200(self):
        cred_id = self._register()
        begin_resp = self.client.post(
            "/webauthn/authenticate/begin", json={"did": self.did}
        )
        ch_b64 = begin_resp.json()["challenge"]
        ch_bytes = _decode_b64url(ch_b64)
        sig_b64 = _sign_ceremony(self.priv, ch_bytes, self.did, "authenticate")

        resp = self.client.post(
            "/webauthn/authenticate/complete",
            json={
                "did": self.did,
                "challenge": ch_b64,
                "credential_id": cred_id,
                "signature_b64": sig_b64,
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])

    def test_authenticate_complete_wrong_signature_returns_401(self):
        cred_id = self._register()
        begin_resp = self.client.post(
            "/webauthn/authenticate/begin", json={"did": self.did}
        )
        ch_b64 = begin_resp.json()["challenge"]
        ch_bytes = _decode_b64url(ch_b64)
        other_priv, _, _ = _generate_keypair()
        bad_sig = _sign_ceremony(other_priv, ch_bytes, self.did, "authenticate")

        resp = self.client.post(
            "/webauthn/authenticate/complete",
            json={
                "did": self.did,
                "challenge": ch_b64,
                "credential_id": cred_id,
                "signature_b64": bad_sig,
            },
        )
        self.assertEqual(resp.status_code, 401)

    def test_list_credentials_returns_registered(self):
        cred_id = self._register()
        proof = self._list_proof(self.did, self.priv)
        resp = self.client.get(f"/webauthn/credentials/{self.did}", params=proof)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["did"], self.did)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["credentials"][0]["credential_id"], cred_id)

    def test_list_credentials_unknown_did_returns_404(self):
        resp = self.client.get("/webauthn/credentials/did:mesh:key:nobody")
        self.assertEqual(resp.status_code, 404)

    def _list_proof(self, did, private_key):
        challenge = self.client.post(f"/webauthn/credentials/challenge/{did}")
        self.assertEqual(challenge.status_code, 200, challenge.text)
        challenge_b64 = challenge.json()["challenge"]
        sig = self._ownership_signature(
            did, private_key, challenge_b64, {"purpose": "credential-list"},
            operation="WEBAUTHN_CREDENTIAL_LIST",
        )
        return {
            "ownership_challenge": challenge_b64,
            "ownership_signature_b64": sig,
        }

    def test_anonymous_registration_rejected_without_state_changes(self):
        begin = self.client.post("/webauthn/register/begin", json={"did": self.did}).json()
        challenge = begin["challenge"]
        signature = _sign_ceremony(self.priv, _decode_b64url(challenge), self.did, "register")
        before = list(self.ledger._chain)
        response = self.client.post("/webauthn/register/complete", json={
            "did": self.did, "challenge": challenge, "public_key_b64": self.pub_b64,
            "signature_b64": signature,
        })
        self.assertEqual(response.status_code, 401)
        self.assertEqual(webauthn_router_module._credential_store.total_count(), 0)
        self.assertEqual(self.ledger._chain, before)
        self.assertEqual(self.ledger.verify_integrity(), (True, None))

    def test_registration_rejects_did_mismatch_and_invalid_owner_signature(self):
        begin = self.client.post("/webauthn/register/begin", json={"did": self.did}).json()
        changes = {
            "registration_challenge": begin["challenge"],
            "public_key_b64": self.pub_b64,
            "credential_id": CredentialStore.derive_credential_id(self.pub_bytes),
            "device_info": None,
        }
        signature = _sign_ceremony(self.priv, _decode_b64url(begin["challenge"]), self.did, "register")
        before = list(self.ledger._chain)
        mismatch = self.client.post("/webauthn/register/complete", json={
            "did": self.other_did, "challenge": begin["challenge"],
            "public_key_b64": self.pub_b64, "signature_b64": signature,
            "ownership_challenge": begin["ownership_challenge"],
            "ownership_signature_b64": self._ownership_signature(
                self.did, self.priv, begin["ownership_challenge"], changes
            ),
        })
        self.assertEqual(mismatch.status_code, 401)
        self.assertEqual(webauthn_router_module._credential_store.total_count(), 0)
        self.assertEqual(self.ledger._chain, before)

        begin = self.client.post("/webauthn/register/begin", json={"did": self.did}).json()
        invalid = self.client.post("/webauthn/register/complete", json={
            "did": self.did, "challenge": begin["challenge"],
            "public_key_b64": self.pub_b64, "signature_b64": signature,
            "ownership_challenge": begin["ownership_challenge"],
            "ownership_signature_b64": base64.urlsafe_b64encode(b"x" * 64).decode().rstrip("="),
        })
        self.assertEqual(invalid.status_code, 401)
        self.assertEqual(webauthn_router_module._credential_store.total_count(), 0)
        self.assertEqual(self.ledger._chain, before)
        self.assertEqual(self.ledger.verify_integrity(), (True, None))

    def test_registration_rejects_reused_and_expired_ownership_proofs(self):
        begin = self.client.post("/webauthn/register/begin", json={"did": self.did}).json()
        changes = {
            "registration_challenge": begin["challenge"], "public_key_b64": self.pub_b64,
            "credential_id": CredentialStore.derive_credential_id(self.pub_bytes), "device_info": None,
        }
        payload = {
            "did": self.did, "challenge": begin["challenge"], "public_key_b64": self.pub_b64,
            "signature_b64": _sign_ceremony(self.priv, _decode_b64url(begin["challenge"]), self.did, "register"),
            "ownership_challenge": begin["ownership_challenge"],
            "ownership_signature_b64": self._ownership_signature(
                self.did, self.priv, begin["ownership_challenge"], changes
            ),
        }
        before = list(self.ledger._chain)
        self.assertEqual(self.client.post("/webauthn/register/complete", json=payload).status_code, 201)
        after_success = list(self.ledger._chain)
        self.assertEqual(self.ledger.verify_integrity(), (True, None))
        replay = self.client.post("/webauthn/register/complete", json=payload)
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(self.ledger._chain, after_success)
        self.assertEqual(self.ledger.verify_integrity(), (True, None))

        begin = self.client.post("/webauthn/register/begin", json={"did": self.did}).json()
        with did_router_module._did_mutation_challenge_store._lock:
            did_router_module._did_mutation_challenge_store._store[begin["ownership_challenge"]].issued_at -= 301
        payload = {
            "did": self.did, "challenge": begin["challenge"], "public_key_b64": self.pub_b64,
            "signature_b64": _sign_ceremony(self.priv, _decode_b64url(begin["challenge"]), self.did, "register"),
            "ownership_challenge": begin["ownership_challenge"],
            "ownership_signature_b64": base64.urlsafe_b64encode(b"x" * 64).decode().rstrip("="),
        }
        expired = self.client.post("/webauthn/register/complete", json=payload)
        self.assertEqual(expired.status_code, 401)
        self.assertEqual(self.ledger._chain, after_success)
        self.assertEqual(self.ledger.verify_integrity(), (True, None))

    def test_anonymous_credential_listing_is_rejected(self):
        self._register()
        response = self.client.get(f"/webauthn/credentials/{self.did}")
        self.assertEqual(response.status_code, 401)


# ===========================================================================
# Integration: Register → Authenticate → Token issuance
# ===========================================================================

class TestWebAuthnEndToEndIntegration(unittest.TestCase):
    """Validates the full WebAuthn → Token pipeline with a simulated ledger."""

    def test_full_registration_and_authentication_flow(self):
        """Full ceremony: register → authenticate verifies sign_count increments."""
        from app.modules.webauthn.challenge_store import ChallengeStore
        from app.modules.webauthn.credential_store import CredentialStore
        from app.modules.webauthn.webauthn_service import WebAuthnService

        did = "did:mesh:key:integration_e2e"
        priv, pub_bytes, pub_b64 = _generate_keypair()
        service = _make_fresh_service()

        # Registration
        reg_begin = service.begin_registration(did)
        ch_bytes = _decode_b64url(reg_begin.challenge)
        sig = _sign_ceremony(priv, ch_bytes, did, "register")
        reg_result = service.complete_registration(
            did=did,
            challenge_b64=reg_begin.challenge,
            public_key_b64=pub_b64,
            signature_b64=sig,
        )
        self.assertTrue(reg_result.success)
        cred_id = reg_result.credential_id

        # Two successive authentications — sign_count must increment each time
        for expected_count in [1, 2]:
            auth_begin = service.begin_authentication(did)
            ch_bytes = _decode_b64url(auth_begin.challenge)
            sig = _sign_ceremony(priv, ch_bytes, did, "authenticate")
            auth_result = service.complete_authentication(
                did=did,
                challenge_b64=auth_begin.challenge,
                credential_id=cred_id,
                signature_b64=sig,
            )
            self.assertTrue(auth_result.success)
            self.assertIn(f"sign_count={expected_count}", auth_result.message)

    def test_registration_anchors_on_ledger(self):
        """When a ledger is wired, complete_registration must create a ledger record."""
        from app.modules.ledger.chain import SimulatedLedger

        ledger = SimulatedLedger(auto_genesis=True)
        initial_count = len(ledger)

        did = "did:mesh:key:ledger_integration"
        priv, pub_bytes, pub_b64 = _generate_keypair()
        service = _make_fresh_service(ledger=ledger)

        reg_begin = service.begin_registration(did)
        ch_bytes = _decode_b64url(reg_begin.challenge)
        sig = _sign_ceremony(priv, ch_bytes, did, "register")
        reg_result = service.complete_registration(
            did=did,
            challenge_b64=reg_begin.challenge,
            public_key_b64=pub_b64,
            signature_b64=sig,
        )

        self.assertTrue(reg_result.success)
        self.assertIsNotNone(reg_result.ledger_record_index)
        # Ledger must have one more record than before
        self.assertEqual(len(ledger), initial_count + 1)

        # The new ledger record must reference the correct DID
        record = ledger.get_record_by_index(reg_result.ledger_record_index)
        self.assertIsNotNone(record)
        self.assertEqual(record.did, did)

    def test_ledger_integrity_preserved_after_webauthn_registration(self):
        """Ledger integrity must remain intact after WebAuthn-triggered anchoring."""
        from app.modules.ledger.chain import SimulatedLedger

        ledger = SimulatedLedger(auto_genesis=True)
        did = "did:mesh:key:integrity_check"
        priv, pub_bytes, pub_b64 = _generate_keypair()
        service = _make_fresh_service(ledger=ledger)

        reg_begin = service.begin_registration(did)
        ch_bytes = _decode_b64url(reg_begin.challenge)
        sig = _sign_ceremony(priv, ch_bytes, did, "register")
        service.complete_registration(
            did=did,
            challenge_b64=reg_begin.challenge,
            public_key_b64=pub_b64,
            signature_b64=sig,
        )

        is_valid, error = ledger.verify_integrity()
        self.assertTrue(is_valid, f"Ledger integrity failed: {error}")
        self.assertIsNone(error)


if __name__ == "__main__":
    unittest.main()
