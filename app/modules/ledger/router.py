"""FastAPI Router for Simulated Blockchain Ledger (Identity Integrity Anchoring).

Provides endpoints for:
- Listing blocks
- Querying DID history and latest state
- Anchoring new DID identity events (used by Member 3 & Member 1)
- Audit integrity verification (used by Member 6 for the Admin Security Dashboard)
- Interactive tamper demonstration endpoint for security audits
"""

import base64
import binascii
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.hasher import hash_did_document
from app.modules.ledger.models import (
    LedgerRecord,
    LedgerOperation,
    RecordCreateInput,
)
from app.modules.admin.security import require_admin, require_tamper_demo_enabled
from app.modules.ledger.simulation import isolated_ledger_copy
from app.modules.webauthn.challenge_store import ChallengeStore
from app.modules.identity.did_service import DIDResolutionError, DIDService
from app.modules.identity.ed25519_service import Ed25519Service

logger = logging.getLogger("idp_mesh.ledger.router")

router = APIRouter(prefix="/ledger", tags=["Simulated Ledger"])

# Shared singleton instance (can be overridden via dependency injection)
ledger_instance = SimulatedLedger(auto_genesis=True)
_anchor_challenge_store = ChallengeStore()
_ANCHOR_CHALLENGE_CEREMONY = "ledger-anchor"
_ANCHOR_CHALLENGE_TTL_SECONDS = 300


def get_ledger() -> SimulatedLedger:
    """Dependency injection helper returning the active SimulatedLedger instance."""
    return ledger_instance


class IntegrityStatusResponse(BaseModel):
    """Integrity audit result for the Admin Security Dashboard."""
    valid: bool = Field(description="True if chain is completely intact and untampered")
    error: Optional[str] = Field(default=None, description="Diagnostic error message if tampering detected")
    total_records: int = Field(description="Total number of records currently on the ledger")
    head_hash: Optional[str] = Field(default=None, description="Current head record hash")


class TamperSimulationRequest(BaseModel):
    """Payload to simulate a malicious tamper attack for demonstration."""
    index: int = Field(ge=0, description="Block index to tamper with")
    field: str = Field(description="Field to modify (e.g., 'did', 'doc_hash', 'previous_hash')")
    new_value: Any = Field(description="Malicious value to inject")
    recalculate_record_hash: bool = Field(
        default=False,
        description="Whether attacker tries to forge this block's hash (linkage still breaks)"
    )


class AnchorChallengeRequest(BaseModel):
    """Anchor fields the DID controller will approve with an Ed25519 signature."""

    did: str = Field(min_length=3)
    doc_hash: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    operation: LedgerOperation = LedgerOperation.CREATE
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AnchorChallengeResponse(BaseModel):
    did: str
    challenge: str
    expires_in_seconds: int


@router.get("", response_model=List[LedgerRecord], summary="List all ledger records")
def get_all_records() -> List[LedgerRecord]:
    """Retrieve the complete list of append-only blocks on the simulated ledger."""
    return ledger_instance.get_all_records()


@router.get("/verify", response_model=IntegrityStatusResponse, summary="Verify ledger integrity")
def verify_ledger_integrity() -> IntegrityStatusResponse:
    """Audit the cryptographic integrity of the entire ledger chain.

    Used by the administrative security dashboard to display the live integrity status.
    """
    is_valid, error = ledger_instance.verify_integrity()
    head = ledger_instance.get_head()
    return IntegrityStatusResponse(
        valid=is_valid,
        error=error,
        total_records=len(ledger_instance),
        head_hash=head.record_hash if head else None,
    )


@router.get("/history/{did}", response_model=List[LedgerRecord], summary="Get DID record history")
def get_did_history(did: str) -> List[LedgerRecord]:
    """Retrieve the chronological update history for a specific DID."""
    records = ledger_instance.get_records_by_did(did)
    if not records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No ledger records found for DID '{did}'"
        )
    return records


@router.get("/latest/{did}", response_model=LedgerRecord, summary="Get latest DID record")
def get_latest_did_record(did: str) -> LedgerRecord:
    """Retrieve the most recent verified state for a given DID."""
    record = ledger_instance.get_latest_record(did)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DID '{did}' is not registered on the ledger"
        )
    return record


def _resolve_anchor_public_key(did: str):
    """Resolve an active self-certifying DID to its registered Ed25519 key."""
    try:
        document = DIDService.resolve_did(did)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except DIDResolutionError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    if document.get("deactivated", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Deactivated DIDs cannot anchor records.")
    try:
        multibase_key = document["verificationMethod"][0]["publicKeyMultibase"]
        if not isinstance(multibase_key, str) or not multibase_key.startswith("z"):
            raise ValueError("Expected a base58btc multibase public key.")
        public_key_bytes = DIDService._base58btc_decode(multibase_key[1:])
        public_key = Ed25519Service.public_key_from_bytes(public_key_bytes)
        expected_identifier = DIDService._derive_did_identifier(public_key)
    except Exception as exc:
        logger.warning("Unable to resolve public key for anchor DID %s: %s", did, exc)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The DID document does not contain a valid controller key.",
        ) from exc

    # A DID's initial key must match its self-certifying identifier. After a
    # controller-authorized key rotation, accept the registered key only when
    # the current document is exactly the latest state in an intact ledger.
    if did.rsplit(":", 1)[-1] != expected_identifier:
        integrity_ok, _ = ledger_instance.verify_integrity()
        latest_record = ledger_instance.get_latest_record(did)
        if (
            not integrity_ok
            or latest_record is None
            or latest_record.operation not in {LedgerOperation.CREATE, LedgerOperation.UPDATE}
            or latest_record.doc_hash != hash_did_document(document)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="The DID controller key is not bound to this DID's verified ledger state.",
            )
    return public_key


def anchor_proof_message(
    did: str,
    doc_hash: str,
    operation: LedgerOperation,
    metadata: Dict[str, Any],
    challenge: str,
) -> bytes:
    """Build domain-separated canonical bytes the DID controller must sign."""
    message = {
        "domain": "TrustMesh-Ledger-Anchor-v1",
        "challenge": challenge,
        "did": did,
        "doc_hash": doc_hash.lower(),
        "operation": operation.value,
        "metadata": metadata,
    }
    return json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@router.post(
    "/anchor/challenge",
    response_model=AnchorChallengeResponse,
    summary="Issue a one-time challenge for a DID ledger anchor",
)
def create_anchor_challenge(payload: AnchorChallengeRequest) -> AnchorChallengeResponse:
    """Issue a short-lived nonce for the DID controller to sign."""
    if payload.operation == LedgerOperation.GENESIS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Genesis records cannot be submitted through this endpoint.")
    _resolve_anchor_public_key(payload.did)
    _, challenge = _anchor_challenge_store.create_challenge(payload.did, _ANCHOR_CHALLENGE_CEREMONY)
    return AnchorChallengeResponse(
        did=payload.did,
        challenge=challenge,
        expires_in_seconds=_ANCHOR_CHALLENGE_TTL_SECONDS,
    )


@router.post(
    "/anchor",
    response_model=LedgerRecord,
    status_code=status.HTTP_201_CREATED,
    summary="Anchor a DID document with cryptographic controller proof",
)
def anchor_did_record(payload: RecordCreateInput) -> LedgerRecord:
    """Append a DID event only after verifying a fresh controller signature."""
    if not payload.ownership_challenge or not payload.ownership_signature_b64:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A DID ownership challenge and signature are required.",
        )
    if payload.operation == LedgerOperation.GENESIS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Genesis records cannot be submitted through this endpoint.")

    try:
        _anchor_challenge_store.consume_challenge(
            challenge_b64=payload.ownership_challenge,
            did=payload.did,
            ceremony=_ANCHOR_CHALLENGE_CEREMONY,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    public_key = _resolve_anchor_public_key(payload.did)
    try:
        signature = base64.b64decode(
            payload.ownership_signature_b64 + "=" * (-len(payload.ownership_signature_b64) % 4),
            altchars=b"-_",
            validate=True,
        )
        if len(signature) != 64:
            raise ValueError("Ed25519 signatures must contain 64 bytes.")
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid ownership signature encoding.") from exc

    signed_message = anchor_proof_message(
        did=payload.did,
        doc_hash=payload.doc_hash,
        operation=payload.operation,
        metadata=payload.metadata,
        challenge=payload.ownership_challenge,
    )
    if not Ed25519Service.verify(public_key, signed_message, signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="DID ownership signature is invalid.")

    try:
        return ledger_instance.append_record(
            did=payload.did,
            doc_hash=payload.doc_hash,
            operation=payload.operation,
            metadata=payload.metadata,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to anchor record to ledger: {str(exc)}",
        ) from exc


@router.post(
    "/simulate-tamper",
    response_model=IntegrityStatusResponse,
    summary="Simulate a tampering attack (Demonstration only)",
    dependencies=[Depends(require_admin)],
)
def simulate_tampering_attack(payload: TamperSimulationRequest) -> IntegrityStatusResponse:
    """Simulate tampering on an isolated snapshot, leaving the shared ledger intact."""
    require_tamper_demo_enabled()
    simulation = isolated_ledger_copy(ledger_instance)
    try:
        simulation.tamper_record(
            index=payload.index,
            field=payload.field,
            new_value=payload.new_value,
            recalculate_record_hash=payload.recalculate_record_hash,
        )
    except IndexError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Tampering simulation failed: {str(e)}")

    # Return updated integrity status immediately
    is_valid, error = simulation.verify_integrity()
    head = simulation.get_head()
    return IntegrityStatusResponse(
        valid=is_valid,
        error=error,
        total_records=len(simulation),
        head_hash=head.record_hash if head else None,
    )
