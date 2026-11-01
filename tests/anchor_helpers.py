"""Client helpers for tests exercising DID-signed ledger anchors."""

import base64

from app.modules.identity.did_service import DIDService
from app.modules.identity.ed25519_service import Ed25519Service
from app.modules.ledger.models import LedgerOperation
from app.modules.ledger.router import anchor_proof_message


def create_owned_did():
    private_key, public_key = Ed25519Service.generate_key_pair()
    did = DIDService.create_did(public_key)
    return did, private_key


def make_anchor_payload(client, did, private_key, doc_hash, operation="CREATE", metadata=None):
    metadata = metadata or {}
    challenge_response = client.post(
        "/api/v1/ledger/anchor/challenge",
        json={
            "did": did,
            "doc_hash": doc_hash,
            "operation": operation,
            "metadata": metadata,
        },
    )
    assert challenge_response.status_code == 200, challenge_response.text
    challenge = challenge_response.json()["challenge"]
    message = anchor_proof_message(
        did,
        doc_hash,
        LedgerOperation(operation),
        metadata,
        challenge,
    )
    signature = Ed25519Service.sign(private_key, message)
    return {
        "did": did,
        "doc_hash": doc_hash,
        "operation": operation,
        "metadata": metadata,
        "ownership_challenge": challenge,
        "ownership_signature_b64": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
    }


def anchor_owned_did(client, did, private_key, doc_hash, operation="CREATE", metadata=None):
    return client.post(
        "/api/v1/ledger/anchor",
        json=make_anchor_payload(client, did, private_key, doc_hash, operation, metadata),
    )
