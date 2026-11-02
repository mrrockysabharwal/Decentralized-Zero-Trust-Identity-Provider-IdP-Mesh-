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
import hashlib
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, status

from app.modules.did.models import (
    DIDCreateRequest,
    DIDCreateResponse,
    DIDDeactivateRequest,
    DIDDeactivateResponse,
    DIDExistsResponse,
    DIDListResponse,
    DIDResolveResponse,
    DIDUpdateRequest,
    DIDUpdateResponse,
    SignatureVerifyRequest,
    SignatureVerifyResponse,
)
from app.modules.identity.did_service import DIDResolutionError, DIDService
from app.modules.identity.ed25519_service import Ed25519Service
from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.hasher import hash_did_document
from app.modules.ledger.models import LedgerOperation

logger = logging.getLogger("idp_mesh.did.router")

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/did", tags=["DID Registry & Cryptography"])

# ---------------------------------------------------------------------------
# Shared ledger singleton (replaced by main.py _wire_shared_ledger at startup)
# ---------------------------------------------------------------------------

_shared_ledger: SimulatedLedger = SimulatedLedger(auto_genesis=True)


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
    "/update/{did:path}",
    response_model=DIDUpdateResponse,
    summary="Update a DID's public key and anchor an UPDATE record",
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
    # Verify DID exists
    if not DIDService.did_exists(did):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DID '{did}' is not registered.",
        )

    # Decode and validate the new public key
    try:
        pub_bytes = _b64url_decode(payload.new_public_key_b64)
        new_public_key = Ed25519Service.public_key_from_bytes(pub_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid public key: {exc}",
        )

    # Rebuild the DID Document with the new key
    try:
        updated_doc = DIDService.build_did_document(did, new_public_key)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    # Overwrite registry entry with updated document
    from app.modules.identity.did_service import _did_registry, persist_registry
    _did_registry[did] = updated_doc
    persist_registry()
    logger.info("Updated DID document for: %s", did)

    # Anchor UPDATE on ledger
    meta: Dict[str, Any] = {**payload.metadata, "updated_by": "did_registry_api"}
    ledger_index = _anchor_did(
        did=did,
        did_document=updated_doc,
        operation=LedgerOperation.UPDATE,
        metadata=meta,
    )

    return DIDUpdateResponse(
        did=did,
        ledger_record_index=ledger_index,
        message=(
            f"DID '{did}' public key updated successfully. "
            f"UPDATE anchored at ledger block #{ledger_index}."
        ),
    )


@router.post(
    "/deactivate/{did:path}",
    response_model=DIDDeactivateResponse,
    summary="Deactivate a DID and anchor a DEACTIVATE record",
)
def deactivate_did(
    did: str,
    payload: Optional[DIDDeactivateRequest] = None,
) -> DIDDeactivateResponse:
    if payload is None:
        payload = DIDDeactivateRequest()
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

    # Deactivate in registry
    try:
        DIDService.deactivate_did(did)
    except DIDResolutionError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    # Fetch updated document for ledger anchoring
    deactivated_doc = DIDService.resolve_did(did)

    # Anchor DEACTIVATE on ledger
    meta: Dict[str, Any] = {"deactivated_by": "did_registry_api"}
    if payload.reason:
        meta["reason"] = payload.reason
    ledger_index = _anchor_did(
        did=did,
        did_document=deactivated_doc,
        operation=LedgerOperation.DEACTIVATE,
        metadata=meta,
    )

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
