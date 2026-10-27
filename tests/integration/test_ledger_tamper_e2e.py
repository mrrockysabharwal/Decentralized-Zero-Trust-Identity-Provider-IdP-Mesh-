"""
tests/integration/test_ledger_tamper_e2e.py — Ledger Tamper End-to-End Tests
==============================================================================

Verifies the Zero-Trust chain reaction:

  Tamper ledger block  →  verify_integrity() returns False
                       →  ZeroTrustPolicyEngine.Check 3 fails
                       →  POST /tokens/issue returns 403
                       →  GET /admin/health shows degraded status

All tests run against the full FastAPI app in-process.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


class TestLedgerTamperChainReaction:
    """
    Tests that a tampered ledger immediately cascades into a 403 on token issuance
    and a degraded status on the admin health endpoint.

    Because tamper_record mutates in-memory state, this test class is isolated
    in scope=module — the tamper is permanent for the lifetime of the test session.
    Use a separate test session if you need a pristine ledger afterward.
    """

    did: str = ""

    def test_01_create_and_anchor_did(self, client):
        """Establish a valid DID so we have something to issue tokens for."""
        resp = client.post("/api/v1/did/create", json={"display_name": "TamperTestDID"})
        assert resp.status_code == 201
        TestLedgerTamperChainReaction.did = resp.json()["did"]

    def test_02_token_issue_works_before_tamper(self, client):
        """Confirm token issuance succeeds with a clean ledger."""
        resp = client.post(
            "/api/v1/tokens/issue",
            json={"did": self.did, "scope": ["read:profile"]},
        )
        assert resp.status_code == 201, resp.text

    def test_03_ledger_integrity_ok_before_tamper(self, client):
        resp = client.get("/api/v1/admin/ledger/verify")
        assert resp.json()["integrity_valid"] is True

    def test_04_admin_tamper_demo_breaks_integrity(self, client):
        """Use the admin tamper endpoint to corrupt the genesis block."""
        resp = client.post(
            "/api/v1/admin/ledger/simulate-tamper",
            params={
                "index": 0,
                "field": "doc_hash",
                "new_value": "cafebabe" * 8,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["integrity_valid"] is False
        assert data["integrity_error"] is not None

    def test_05_ledger_verify_returns_false_after_tamper(self, client):
        resp = client.get("/api/v1/admin/ledger/verify")
        assert resp.json()["integrity_valid"] is False

    def test_06_token_issuance_blocked_after_tamper(self, client):
        """
        Zero-Trust Check 3: tampered ledger must block ALL token issuance.
        This is the core security guarantee.
        """
        resp = client.post(
            "/api/v1/tokens/issue",
            json={"did": self.did, "scope": ["read:profile"]},
        )
        assert resp.status_code == 403, resp.text
        detail = resp.json()["detail"].lower()
        assert "integrity" in detail or "tamper" in detail or "failed" in detail

    def test_07_admin_health_shows_degraded(self, client):
        """Admin health must reflect the broken ledger state."""
        data = client.get("/api/v1/admin/health").json()
        assert data["ledger_integrity"] is False
        assert data["overall_status"] == "degraded"

    def test_08_admin_dashboard_ledger_integrity_false(self, client):
        data = client.get("/api/v1/admin/dashboard").json()
        assert data["ledger_integrity"] is False

    def test_09_ledger_subsystem_degraded_in_health(self, client):
        data = client.get("/api/v1/admin/health").json()
        ledger_sub = next(s for s in data["subsystems"] if s["name"] == "ledger")
        assert ledger_sub["status"] == "degraded"
