"""
app/modules/did/router.py — DID Registry & Cryptography FastAPI Router
=======================================================================
Owner  : Member 3 (DID Registry & Cryptography)
Module : A — DID Registry HTTP API
Branch : feature/identity-module
Status : Fully Implemented

Exposes the Ed25519Service and DIDService via REST endpoints, with automatic
ledger anchoring (Module C integration) so every DID lifecycle event is
cryptographically immortalised on the SimulatedLedger.

Endpoints (all mounted under /api/v1/did by Member 1's main.py):

    POST   /did/create              — Generate key pair + register DID + anchor
    GET    /did/resolve/{did}       — Resolve DID → DID Document
    GET    /did/exists/{did}        — Check DID registration status
    GET    /did/list                — List all registered DIDs
    POST   /did/update/{did}        — Update DID's public key + anchor UPDATE
    POST   /did/deactivate/{did}    — Deactivate DID + anchor DEACTIVATE
    POST   /did/verify-signature    — Verify Ed25519 signature with DID's public key

Integration for Member 1 (mount in app/main.py):

    from app.modules.did import did_router
    app.include_router(did_router, prefix="/api/v1")
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, status

from app.modules.did.models import (
    DIDCreateRequest,
    DIDCreateResponse,
    DIDDeactivateRequest,
    DIDDeactivateChallengeRequest,
    DIDDeactivateResponse,
    DIDExistsResponse,
    DIDListResponse,
    DIDResolveResponse,
    DIDUpdateRequest,
    DIDUpdateChallengeRequest,
    DIDUpdateResponse,
    DIDMutationChallengeResponse,
    SignatureVerifyRequest,
    SignatureVerifyResponse,
)
from app.modules.identity.did_service import DIDResolutionError, DIDService
from app.modules.identity.ed25519_service import Ed25519Service
from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.hasher import hash_did_document
from app.modules.ledger.models import LedgerOperation
from app.modules.webauthn.challenge_store import ChallengeStore

logger = logging.getLogger("idp_mesh.did.router")

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/did", tags=["DID Registry & Cryptography"])

# ---------------------------------------------------------------------------
# Shared ledger singleton (replaced by main.py _wire_shared_ledger at startup)
# ---------------------------------------------------------------------------

_shared_ledger: SimulatedLedger = SimulatedLedger(auto_genesis=True)
_did_mutation_challenge_store = ChallengeStore(ttl_seconds=300)
_DID_MUTATION_CHALLENGE_TTL_SECONDS = 300
_DID_MUTATION_DOMAIN = "TrustMesh-DID-Mutation-v1"
_DID_MUTATION_CHALLENGE_DOMAIN = "TrustMesh-DID-Mutation-Challenge-v1"


def get_ledger() -> SimulatedLedger:
    """Dependency helper — returns the active shared SimulatedLedger instance."""
    return _shared_ledger


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(encoded: str) -> bytes:
    """URL-safe base64 decode; handles missing padding gracefully."""
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += "=" * padding
    return base64.urlsafe_b64decode(encoded)


def _strict_b64url_decode(encoded: str, *, expected_length: int, label: str) -> bytes:
    """Decode unpadded base64url strictly and enforce the raw byte length."""
    if not isinstance(encoded, str) or not encoded:
        raise ValueError(f"{label} is required.")
    try:
        decoded = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{label} must be valid base64url.") from exc
    if len(decoded) != expected_length:
        raise ValueError(f"{label} must decode to {expected_length} bytes.")
    return decoded


def _canonical_json_bytes(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def did_mutation_proof_message(
    did: str,
    operation: str,
    changes: Dict[str, Any],
    challenge: str,
) -> bytes:
    """Canonical domain-separated message signed by the current DID controller."""
    return _canonical_json_bytes(
        {
            "domain": _DID_MUTATION_DOMAIN,
            "did": did,
            "operation": operation,
            "changes": changes,
            "challenge": challenge,
        }
    )


def _mutation_ceremony(did: str, operation: str, changes: Dict[str, Any]) -> str:
    """Bind the one-time challenge to a DID, operation, and exact change set."""
    binding = _canonical_json_bytes(
        {
            "domain": _DID_MUTATION_CHALLENGE_DOMAIN,
            "did": did,
            "operation": operation,
            "changes": changes,
        }
    )
    return f"did-mutation:{hashlib.sha256(binding).hexdigest()}"


def _resolve_active_did_public_key(did: str):
    """Resolve the active DID document and its currently registered Ed25519 key."""
    try:
        document = DIDService.resolve_did(did)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except DIDResolutionError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    if document.get("deactivated", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive DIDs cannot be mutated.")
    try:
        if document.get("id") != did:
            raise ValueError("DID document identifier does not match the requested DID.")
        verification_methods = document["verificationMethod"]
        if not verification_methods:
            raise ValueError("DID document has no verification method.")
        verification_method = verification_methods[0]
        if (
            verification_method.get("controller") != did
            or verification_method.get("id") != f"{did}#key-1"
        ):
            raise ValueError("DID verification method is bound to a different identity.")
        multibase_key = verification_method["publicKeyMultibase"]
        if not isinstance(multibase_key, str) or not multibase_key.startswith("z"):
            raise ValueError("Expected a base58btc multibase Ed25519 public key.")
        public_key_bytes = DIDService._base58btc_decode(multibase_key[1:])
        return Ed25519Service.public_key_from_bytes(public_key_bytes)
    except Exception as exc:
        logger.warning("Invalid registered controller key for DID %s: %s", did, exc)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The DID document does not contain a valid key bound to this DID.",
        ) from exc


def _authorize_did_mutation(
    *,
    did: str,
    operation: str,
    changes: Dict[str, Any],
    challenge: Optional[str],
    signature_b64: Optional[str],
) -> None:
    """Consume and verify ownership proof before a DID mutation can take place."""
    verify_did_ownership_proof(
        did=did,
        operation=operation,
        challenge_binding=changes,
        signed_changes=changes,
        challenge=challenge,
        signature_b64=signature_b64,
    )


def issue_did_ownership_challenge(
    did: str,
    operation: str,
    challenge_binding: Dict[str, Any],
) -> str:
    """Issue a five-minute, one-use challenge for an active DID and operation."""
    _resolve_active_did_public_key(did)
    ceremony = _mutation_ceremony(did, operation, challenge_binding)
    _, challenge = _did_mutation_challenge_store.create_challenge(did, ceremony)
    return challenge


def verify_did_ownership_proof(
    *,
    did: str,
    operation: str,
    challenge_binding: Dict[str, Any],
    signed_changes: Dict[str, Any],
    challenge: Optional[str],
    signature_b64: Optional[str],
) -> None:
    """Consume an operation-bound challenge and verify its controller signature.

    ``challenge_binding`` binds the server challenge to the ceremony known at
    challenge issuance. ``signed_changes`` additionally binds final request
    data that may only be supplied when the ceremony completes.
    """
    public_key = _resolve_active_did_public_key(did)
    if not challenge or not signature_b64:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A DID ownership challenge and signature are required.",
        )

    ceremony = _mutation_ceremony(did, operation, challenge_binding)
    try:
        _did_mutation_challenge_store.consume_challenge(
            challenge_b64=challenge,
            did=did,
            ceremony=ceremony,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    try:
        signature = _strict_b64url_decode(
            signature_b64,
            expected_length=64,
            label="Ownership signature",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    message = did_mutation_proof_message(did, operation, signed_changes, challenge)
    if not Ed25519Service.verify(public_key, message, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="DID ownership signature is invalid.",
        )


def _anchor_did(
    did: str,
    did_document: Dict[str, Any],
    operation: LedgerOperation,
    metadata: Optional[Dict[str, Any]] = None,
) -> int:
    """Anchor a DID document to the shared ledger and return the block index."""
    doc_hash = hash_did_document(did_document)
    record = _shared_ledger.append_record(
        did=did,
        doc_hash=doc_hash,
        operation=operation,
        metadata=metadata or {},
    )
    logger.info(
        "Anchored DID %s on ledger at block #%d (operation=%s, doc_hash=%s…)",
        did,
        record.index,
        operation.value,
        doc_hash[:12],
    )
    return record.index


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/create",
    response_model=DIDCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a key pair and register a new DID",
)
def create_did(payload: DIDCreateRequest) -> DIDCreateResponse:
    """Generate a fresh Ed25519 key pair, derive a `did:mesh:key` DID, register it
    in the in-process DID registry, and optionally anchor a CREATE event on the
    SimulatedLedger (Module C).

    ⚠️ The `private_key_b64` field is returned **once** in this response.
    The server does **not** retain the private key — store it securely.
    """
    # 1. Generate key pair
    private_key, public_key = Ed25519Service.generate_key_pair()

    # 2. Derive and register DID
    did = DIDService.create_did(public_key)
    did_document = DIDService.resolve_did(did)

    # 3. Serialise keys for response
    pub_bytes = Ed25519Service.public_key_to_bytes(public_key)
    priv_bytes = Ed25519Service.private_key_to_bytes(private_key)
    public_key_b64 = _b64url_encode(pub_bytes)
    private_key_b64 = _b64url_encode(priv_bytes)

    # 4. Optionally anchor on ledger
    ledger_record_index: Optional[int] = None
    if payload.anchor_to_ledger:
        meta: Dict[str, Any] = {**payload.metadata}
        if payload.display_name:
            meta["display_name"] = payload.display_name
        meta["created_by"] = "did_registry_api"
        ledger_record_index = _anchor_did(
            did=did,
            did_document=did_document,
            operation=LedgerOperation.CREATE,
            metadata=meta,
        )

    logger.info("Registered new DID: %s", did)

    return DIDCreateResponse(
        did=did,
        public_key_b64=public_key_b64,
        private_key_b64=private_key_b64,
        did_document=did_document,
        ledger_record_index=ledger_record_index,
        message=(
            f"DID '{did}' successfully created and registered."
            + (
                f" Anchored at ledger block #{ledger_record_index}."
                if ledger_record_index is not None
                else " (Not anchored to ledger per request.)"
            )
        ),
    )


@router.get(
    "/resolve/{did:path}",
    response_model=DIDResolveResponse,
    summary="Resolve a DID and return its DID Document",
)
def resolve_did(did: str) -> DIDResolveResponse:
    """Resolve a `did:mesh:key` DID and return its W3C DID Core 1.0 compliant
    DID Document from the in-process registry.

    Returns **404** if the DID is not registered.
    """
    try:
        doc = DIDService.resolve_did(did)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except DIDResolutionError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DID '{did}' is not registered in the in-process registry.",
        )

    return DIDResolveResponse(
        did=did,
        did_document=doc,
        deactivated=doc.get("deactivated", False),
    )


@router.get(
    "/exists/{did:path}",
    response_model=DIDExistsResponse,
    summary="Check whether a DID is registered",
)
def did_exists(did: str) -> DIDExistsResponse:
    """Return whether a DID is present in the in-process registry.

    Does **not** raise 404 — instead returns `exists: false`.
    Useful for pre-registration checks and admin dashboard polling.
    """
    exists = DIDService.did_exists(did)
    deactivated: Optional[bool] = None
    if exists:
        try:
            doc = DIDService.resolve_did(did)
            deactivated = doc.get("deactivated", False)
        except DIDResolutionError:
            deactivated = None

    return DIDExistsResponse(did=did, exists=exists, deactivated=deactivated)


@router.get(
    "/list",
    response_model=DIDListResponse,
    summary="List all registered DIDs",
)
def list_dids() -> DIDListResponse:
    """Return a snapshot of all DIDs currently registered in the in-process registry.

    Intended for Admin Dashboard use — provides an overview of all active
    and deactivated identities.
    """
    dids = DIDService.list_dids()
    return DIDListResponse(dids=dids, total=len(dids))


@router.post(
    "/challenge/update/{did:path}",
    response_model=DIDMutationChallengeResponse,
    summary="Issue a one-time challenge for an exact DID key update",
)
def create_update_challenge(
    did: str,
    payload: DIDUpdateChallengeRequest,
) -> DIDMutationChallengeResponse:
    """Issue a challenge bound to the proposed new key and update metadata."""
    _resolve_active_did_public_key(did)
    try:
        new_public_key_bytes = _strict_b64url_decode(
            payload.new_public_key_b64,
            expected_length=32,
            label="New Ed25519 public key",
        )
        Ed25519Service.public_key_from_bytes(new_public_key_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    changes = {
        "new_public_key_b64": _b64url_encode(new_public_key_bytes),
        "metadata": payload.metadata,
    }
    ceremony = _mutation_ceremony(did, LedgerOperation.UPDATE.value, changes)
    _, challenge = _did_mutation_challenge_store.create_challenge(did, ceremony)
    return DIDMutationChallengeResponse(
        did=did,
        operation=LedgerOperation.UPDATE.value,
        challenge=challenge,
        expires_in_seconds=_DID_MUTATION_CHALLENGE_TTL_SECONDS,
    )


@router.post(
    "/update/{did:path}",
    response_model=DIDUpdateResponse,
    summary="Update a DID's public key with controller proof and anchor an UPDATE record",
)
def update_did(did: str, payload: DIDUpdateRequest) -> DIDUpdateResponse:
    """Replace the public key associated with an existing DID and anchor an
    `UPDATE` operation on the SimulatedLedger.

    The caller must supply the **new** Ed25519 public key bytes (base64url-encoded).
    The DID identifier itself is immutable — only the DID Document's
    `verificationMethod` is updated.

    Returns **404** if the DID is not registered.
    Returns **422** if the provided public key bytes are invalid.
    """
    # Validate and canonicalize the proposed new key before consuming the proof.
    try:
        pub_bytes = _strict_b64url_decode(
            payload.new_public_key_b64,
            expected_length=32,
            label="New Ed25519 public key",
        )
        new_public_key = Ed25519Service.public_key_from_bytes(pub_bytes)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid public key: {exc}",
        ) from exc

    changes = {
        "new_public_key_b64": _b64url_encode(pub_bytes),
        "metadata": payload.metadata,
    }
    _authorize_did_mutation(
        did=did,
        operation=LedgerOperation.UPDATE.value,
        changes=changes,
        challenge=payload.ownership_challenge,
        signature_b64=payload.ownership_signature_b64,
    )

    # Rebuild the DID Document with the new key
    try:
        updated_doc = DIDService.build_did_document(did, new_public_key)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # Anchor UPDATE on ledger
    meta: Dict[str, Any] = {**payload.metadata, "updated_by": "did_registry_api"}
    ledger_index = _anchor_did(
        did=did,
        did_document=updated_doc,
        operation=LedgerOperation.UPDATE,
        metadata=meta,
    )

    # Change registry state only after the authorized ledger append succeeds.
    from app.modules.identity.did_service import _did_registry
    _did_registry[did] = updated_doc
    logger.info("Updated DID document for: %s", did)

    return DIDUpdateResponse(
        did=did,
        ledger_record_index=ledger_index,
        message=(
            f"DID '{did}' public key updated successfully. "
            f"UPDATE anchored at ledger block #{ledger_index}."
        ),
    )


@router.post(
    "/challenge/deactivate/{did:path}",
    response_model=DIDMutationChallengeResponse,
    summary="Issue a one-time challenge for a DID deactivation",
)
def create_deactivate_challenge(
    did: str,
    payload: DIDDeactivateChallengeRequest,
) -> DIDMutationChallengeResponse:
    """Issue a challenge bound to the deactivation reason."""
    _resolve_active_did_public_key(did)
    changes = {"reason": payload.reason}
    ceremony = _mutation_ceremony(did, LedgerOperation.DEACTIVATE.value, changes)
    _, challenge = _did_mutation_challenge_store.create_challenge(did, ceremony)
    return DIDMutationChallengeResponse(
        did=did,
        operation=LedgerOperation.DEACTIVATE.value,
        challenge=challenge,
        expires_in_seconds=_DID_MUTATION_CHALLENGE_TTL_SECONDS,
    )


@router.post(
    "/deactivate/{did:path}",
    response_model=DIDDeactivateResponse,
    summary="Deactivate a DID with controller proof and anchor a DEACTIVATE record",
)
def deactivate_did(
    did: str,
    payload: Optional[DIDDeactivateRequest] = None,
) -> DIDDeactivateResponse:
    """Mark a DID as deactivated in the in-process registry and anchor a
    `DEACTIVATE` event on the SimulatedLedger.

    Per W3C DID Core spec, deactivated DIDs remain in the registry (append-only)
    but must no longer be used for authentication or token issuance.

    Returns **404** if the DID is not registered.
    Returns **409** if the DID is already deactivated.
    """
    if not DIDService.did_exists(did):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DID '{did}' is not registered.",
        )

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A DID ownership challenge and signature are required.",
        )

    changes = {"reason": payload.reason}
    _authorize_did_mutation(
        did=did,
        operation=LedgerOperation.DEACTIVATE.value,
        changes=changes,
        challenge=payload.ownership_challenge,
        signature_b64=payload.ownership_signature_b64,
    )

    # Guard: reject double-deactivation
    try:
        doc = DIDService.resolve_did(did)
        if doc.get("deactivated", False):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"DID '{did}' is already deactivated.",
            )
    except DIDResolutionError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DID '{did}' could not be resolved.",
        )

    # Build the target document without changing registry state yet.
    deactivated_doc = dict(doc)
    deactivated_doc["deactivated"] = True
    deactivated_doc["updated"] = datetime.now(timezone.utc).isoformat()

    # Anchor DEACTIVATE on ledger
    meta: Dict[str, Any] = {"deactivated_by": "did_registry_api"}
    if payload and payload.reason:
        meta["reason"] = payload.reason
    ledger_index = _anchor_did(
        did=did,
        did_document=deactivated_doc,
        operation=LedgerOperation.DEACTIVATE,
        metadata=meta,
    )

    # Apply registry state only after ownership proof and ledger append succeed.
    from app.modules.identity.did_service import _did_registry
    _did_registry[did] = deactivated_doc

    logger.info("Deactivated DID: %s (ledger block #%d)", did, ledger_index)

    return DIDDeactivateResponse(
        did=did,
        deactivated=True,
        ledger_record_index=ledger_index,
        message=(
            f"DID '{did}' has been deactivated. "
            f"DEACTIVATE event anchored at ledger block #{ledger_index}."
        ),
    )


@router.post(
    "/verify-signature",
    response_model=SignatureVerifyResponse,
    summary="Verify an Ed25519 signature using a registered DID's public key",
)
def verify_signature(payload: SignatureVerifyRequest) -> SignatureVerifyResponse:
    """Verify a 64-byte Ed25519 signature against a message using the public key
    embedded in a registered DID's `verificationMethod`.

    This implements the core **Zero-Trust** verification step:
    a service can validate that a message was signed by the DID controller
    without any private key involvement.

    Returns **404** if the DID is not registered.
    Returns **422** if the supplied base64url data cannot be decoded.
    """
    # Resolve DID
    try:
        doc = DIDService.resolve_did(payload.did)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except DIDResolutionError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DID '{payload.did}' is not registered.",
        )

    if doc.get("deactivated", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"DID '{payload.did}' is deactivated — signature verification rejected.",
        )

    # Extract public key from DID Document verificationMethod
    try:
        vm = doc["verificationMethod"][0]
        multibase_key: str = vm["publicKeyMultibase"]
        # Strip the 'z' multibase prefix then base58btc decode
        key_b58 = multibase_key.lstrip("z")
        pub_bytes = DIDService._base58btc_decode(key_b58)
        public_key = Ed25519Service.public_key_from_bytes(pub_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to extract public key from DID Document: {exc}",
        )

    # Decode message and signature
    try:
        message_bytes = _b64url_decode(payload.message_b64)
        signature_bytes = _b64url_decode(payload.signature_b64)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to decode base64url payload: {exc}",
        )

    # Verify
    is_valid = Ed25519Service.verify(
        public_key=public_key,
        message=message_bytes,
        signature=signature_bytes,
    )

    return SignatureVerifyResponse(
        did=payload.did,
        valid=is_valid,
        message=(
            f"Signature verified successfully for DID '{payload.did}'."
            if is_valid
            else f"Signature verification FAILED for DID '{payload.did}'. "
            "The signature does not match or the message was tampered."
        ),
    )
