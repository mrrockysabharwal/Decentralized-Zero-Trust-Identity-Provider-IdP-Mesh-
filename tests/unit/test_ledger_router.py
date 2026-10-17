"""Tests for the FastAPI Ledger router endpoints."""

import unittest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.modules.ledger.router import router as ledger_router, ledger_instance
from app.modules.ledger.models import LedgerOperation


class TestLedgerRouterEndpoints(unittest.TestCase):
    """Test suite for HTTP REST endpoints of the Simulated Ledger."""

    def setUp(self):
        # Reset the singleton ledger instance for a clean test run
        ledger_instance._chain.clear()
        ledger_instance._create_genesis_record()

        app = FastAPI(title="Test App")
        app.include_router(ledger_router)
        self.client = TestClient(app)

    def test_get_all_records(self):
        """GET /ledger should return the list of records including genesis."""
        response = self.client.get("/ledger")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["index"], 0)
        self.assertEqual(data[0]["did"], "did:mesh:genesis")

    def test_verify_ledger_integrity(self):
        """GET /ledger/verify should confirm that the unaltered ledger is valid."""
        response = self.client.get("/ledger/verify")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["valid"])
        self.assertIsNone(data["error"])
        self.assertEqual(data["total_records"], 1)

    def test_anchor_did_record(self):
        """POST /ledger/anchor should create a new record and link it."""
        payload = {
            "did": "did:mesh:key:z6MkuTestRouter",
            "doc_hash": "a" * 64,
            "operation": "CREATE",
            "metadata": {"creator": "TestSuite"}
        }
        response = self.client.post("/ledger/anchor", json=payload)
        self.assertEqual(response.status_code, 201)
        record = response.json()
        self.assertEqual(record["index"], 1)
        self.assertEqual(record["did"], payload["did"])
        self.assertEqual(record["doc_hash"], payload["doc_hash"])

        # History endpoint check
        hist_response = self.client.get(f"/ledger/history/{payload['did']}")
        self.assertEqual(hist_response.status_code, 200)
        self.assertEqual(len(hist_response.json()), 1)

        # Latest endpoint check
        latest_response = self.client.get(f"/ledger/latest/{payload['did']}")
        self.assertEqual(latest_response.status_code, 200)
        self.assertEqual(latest_response.json()["doc_hash"], payload["doc_hash"])

    def test_simulate_tamper_attack(self):
        """POST /ledger/simulate-tamper should alter state and immediately reflect detection."""
        # Anchor a block first
        self.client.post("/ledger/anchor", json={
            "did": "did:mesh:key:z6MkuTamperTarget",
            "doc_hash": "b" * 64,
            "operation": "CREATE"
        })

        # Inject tamper attack into block #1
        tamper_payload = {
            "index": 1,
            "field": "did",
            "new_value": "did:mesh:key:HackedIdentity",
            "recalculate_record_hash": False
        }
        tamper_response = self.client.post("/ledger/simulate-tamper", json=tamper_payload)
        self.assertEqual(tamper_response.status_code, 200)
        data = tamper_response.json()
        self.assertFalse(data["valid"])
        self.assertIn("Data tampering detected at record #1", data["error"])


if __name__ == "__main__":
    unittest.main()
