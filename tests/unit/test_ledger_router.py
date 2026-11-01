"""Tests for the FastAPI Ledger router endpoints."""

import unittest
import os
import time
import uuid
import jwt
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.modules.ledger.router import router as ledger_router, ledger_instance
from app.modules.ledger.models import LedgerOperation
from app.modules.tokens.jwt_engine import generate_signing_keypair
import app.modules.revocation_provider as revocation_provider
from app.modules.identity.ed25519_service import Ed25519Service
from app.modules.identity.did_service import DIDService
from app.modules.ledger.hasher import hash_did_document
from tests.anchor_helpers import anchor_owned_did
from tests.revocation_helpers import DurableRevocationStoreStub


class TestLedgerRouterEndpoints(unittest.TestCase):
    """Test suite for HTTP REST endpoints of the Simulated Ledger."""

    def setUp(self):
        # Reset the singleton ledger instance for a clean test run
        ledger_instance._chain.clear()
        ledger_instance._create_genesis_record()

        private_key, public_key = generate_signing_keypair()
        self._old_revocation_store = revocation_provider._revocation_store
        revocation_provider.set_revocation_store(DurableRevocationStoreStub())
        self._old_admin_dids = os.environ.get("ADMIN_DIDS")
        self._old_admin_public_key = os.environ.get("ADMIN_JWT_PUBLIC_KEY")
        self._old_tamper_demo = os.environ.get("ENABLE_LEDGER_TAMPER_DEMO")
        os.environ["ADMIN_DIDS"] = "did:mesh:admin:ledger-tests"
        os.environ["ENABLE_LEDGER_TAMPER_DEMO"] = "true"
        os.environ["ADMIN_JWT_PUBLIC_KEY"] = public_key.decode()
        token = jwt.encode(
            {
                "sub": "did:mesh:admin:ledger-tests",
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

        app = FastAPI(title="Test App")
        app.include_router(ledger_router, prefix="/api/v1")
        self.client = TestClient(app, headers={"Authorization": f"Bearer {token}"})
        self.owner_key, owner_public_key = Ed25519Service.generate_key_pair()
        self.owner_did = DIDService.create_did(owner_public_key)

    def tearDown(self):
        revocation_provider.set_revocation_store(self._old_revocation_store)
        for name, value in (
            ("ADMIN_DIDS", self._old_admin_dids),
            ("ADMIN_JWT_PUBLIC_KEY", self._old_admin_public_key),
            ("ENABLE_LEDGER_TAMPER_DEMO", self._old_tamper_demo),
        ):
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_get_all_records(self):
        """GET /ledger should return the list of records including genesis."""
        response = self.client.get("/api/v1/ledger")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["index"], 0)
        self.assertEqual(data[0]["did"], "did:mesh:genesis")

    def test_verify_ledger_integrity(self):
        """GET /ledger/verify should confirm that the unaltered ledger is valid."""
        response = self.client.get("/api/v1/ledger/verify")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["valid"])
        self.assertIsNone(data["error"])
        self.assertEqual(data["total_records"], 1)

    def test_anchor_did_record(self):
        """POST /ledger/anchor should create a new record and link it."""
        doc_hash = hash_did_document({"id": self.owner_did, "test": "router"})
        response = anchor_owned_did(
            self.client,
            self.owner_did,
            self.owner_key,
            doc_hash,
            metadata={"creator": "TestSuite"},
        )
        self.assertEqual(response.status_code, 201)
        record = response.json()
        self.assertEqual(record["index"], 1)
        self.assertEqual(record["did"], self.owner_did)
        self.assertEqual(record["doc_hash"], doc_hash)

        # History endpoint check
        hist_response = self.client.get(f"/api/v1/ledger/history/{self.owner_did}")
        self.assertEqual(hist_response.status_code, 200)
        self.assertEqual(len(hist_response.json()), 1)

        # Latest endpoint check
        latest_response = self.client.get(f"/api/v1/ledger/latest/{self.owner_did}")
        self.assertEqual(latest_response.status_code, 200)
        self.assertEqual(latest_response.json()["doc_hash"], doc_hash)

    def test_simulate_tamper_attack(self):
        """POST /ledger/simulate-tamper reports tampering without altering shared state."""
        # Anchor a block first
        anchor_owned_did(
            self.client,
            self.owner_did,
            self.owner_key,
            hash_did_document({"id": self.owner_did, "test": "tamper"}),
        )

        # Inject tamper attack into block #1
        tamper_payload = {
            "index": 1,
            "field": "did",
            "new_value": "did:mesh:key:HackedIdentity",
            "recalculate_record_hash": False
        }
        tamper_response = self.client.post("/api/v1/ledger/simulate-tamper", json=tamper_payload)
        self.assertEqual(tamper_response.status_code, 200)
        data = tamper_response.json()
        self.assertFalse(data["valid"])
        self.assertIn("Data tampering detected at record #1", data["error"])
        self.assertEqual(ledger_instance.verify_integrity(), (True, None))


if __name__ == "__main__":
    unittest.main()
