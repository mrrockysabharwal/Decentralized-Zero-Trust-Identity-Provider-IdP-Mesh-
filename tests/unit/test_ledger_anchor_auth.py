"""Ownership-proof tests for the ledger anchor API."""

import base64
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.modules.identity.did_service import DIDService
from app.modules.ledger.router import (
    _anchor_challenge_store,
    ledger_instance,
    router as ledger_router,
)
from tests.anchor_helpers import create_owned_did, make_anchor_payload


@pytest.fixture
def anchor_client():
    original_chain = list(ledger_instance._chain)
    with ledger_instance._lock:
        ledger_instance._chain.clear()
        ledger_instance._create_genesis_record()
    _anchor_challenge_store.clear()
    app = FastAPI()
    app.include_router(ledger_router, prefix="/api/v1")
    with TestClient(app) as client:
        yield client
    with ledger_instance._lock:
        ledger_instance._chain.clear()
        ledger_instance._chain.extend(original_chain)
    _anchor_challenge_store.clear()


def _hash(char="a"):
    return char * 64


def test_anonymous_anchor_request_is_rejected(anchor_client):
    response = anchor_client.post(
        "/api/v1/ledger/anchor",
        json={"did": "did:mesh:key:unknown", "doc_hash": _hash(), "operation": "CREATE"},
    )
    assert response.status_code == 401
    assert ledger_instance.verify_integrity() == (True, None)


def test_missing_ownership_proof_is_rejected(anchor_client):
    did, _ = create_owned_did()
    response = anchor_client.post(
        "/api/v1/ledger/anchor",
        json={"did": did, "doc_hash": _hash(), "operation": "CREATE"},
    )
    assert response.status_code == 401
    assert len(ledger_instance) == 1
    assert ledger_instance.verify_integrity() == (True, None)


def test_invalid_signature_is_rejected(anchor_client):
    did, owner_key = create_owned_did()
    payload = make_anchor_payload(anchor_client, did, owner_key, _hash())
    payload["ownership_signature_b64"] = base64.urlsafe_b64encode(b"x" * 64).decode()
    response = anchor_client.post("/api/v1/ledger/anchor", json=payload)
    assert response.status_code == 401
    assert len(ledger_instance) == 1
    assert ledger_instance.verify_integrity() == (True, None)


def test_challenge_did_mismatch_is_rejected(anchor_client):
    first_did, first_key = create_owned_did()
    other_did, _ = create_owned_did()
    payload = make_anchor_payload(anchor_client, first_did, first_key, _hash())
    payload["did"] = other_did
    response = anchor_client.post("/api/v1/ledger/anchor", json=payload)
    assert response.status_code == 401
    assert len(ledger_instance) == 1
    assert ledger_instance.verify_integrity() == (True, None)


def test_valid_controller_proof_anchors_record_and_preserves_integrity(anchor_client):
    did, owner_key = create_owned_did()
    response = anchor_client.post(
        "/api/v1/ledger/anchor",
        json=make_anchor_payload(anchor_client, did, owner_key, _hash("b"), metadata={"source": "test"}),
    )
    assert response.status_code == 201, response.text
    assert response.json()["did"] == did
    assert len(ledger_instance) == 2
    assert ledger_instance.verify_integrity() == (True, None)


def test_another_users_did_cannot_be_anchored(anchor_client):
    owner_did, _ = create_owned_did()
    attacker_did, attacker_key = create_owned_did()
    payload = make_anchor_payload(anchor_client, owner_did, attacker_key, _hash("c"))
    response = anchor_client.post("/api/v1/ledger/anchor", json=payload)
    assert response.status_code == 401
    assert owner_did != attacker_did
    assert len(ledger_instance) == 1
    assert ledger_instance.verify_integrity() == (True, None)


def test_registry_key_replacement_cannot_authorize_a_did(anchor_client):
    victim_did, _ = create_owned_did()
    attacker_did, _ = create_owned_did()
    victim_document = DIDService.resolve_did(victim_did)
    attacker_document = DIDService.resolve_did(attacker_did)
    victim_document["verificationMethod"][0]["publicKeyMultibase"] = (
        attacker_document["verificationMethod"][0]["publicKeyMultibase"]
    )
    response = anchor_client.post(
        "/api/v1/ledger/anchor/challenge",
        json={"did": victim_did, "doc_hash": _hash("e"), "operation": "CREATE"},
    )
    assert response.status_code == 403
    assert len(ledger_instance) == 1
    assert ledger_instance.verify_integrity() == (True, None)


def test_expired_anchor_challenge_is_rejected(anchor_client):
    did, owner_key = create_owned_did()
    payload = make_anchor_payload(anchor_client, did, owner_key, _hash("d"))
    entry = _anchor_challenge_store._store[payload["ownership_challenge"]]
    entry.issued_at -= entry.ttl_seconds + 1
    response = anchor_client.post("/api/v1/ledger/anchor", json=payload)
    assert response.status_code == 401
    assert len(ledger_instance) == 1
    assert ledger_instance.verify_integrity() == (True, None)
