"""
app/modules/did/models.py — Pydantic Schemas for the DID Registry API
======================================================================
Owner  : Member 3 (DID Registry & Cryptography)
Module : A — DID Registry HTTP API

All request and response schemas used by the DID Registry FastAPI router.

Security contract
-----------------
* Private key bytes are returned ONCE at DID creation time (base64url-encoded).
* The private key is NEVER stored on the server; it is the caller's sole
  responsibility to persist and protect it.
* Ledger stores only public keys / doc_hash — never private key material.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class DIDCreateRequest(BaseModel):
    """Request to generate a fresh key pair and register a new DID."""

    display_name: Optional[str] = Field(
        default=None,
        description="Human-readable label stored in ledger metadata (not in DID Document).",
        max_length=128,
    )
    anchor_to_ledger: bool = Field(
        default=True,
        description=(
            "If True (default), the new DID is immediately anchored on the "
            "SimulatedLedger with a CREATE operation."
        ),
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-sensitive metadata to embed in the ledger record.",
    )


class DIDUpdateRequest(BaseModel):
    """Request to update an existing DID's public key and re-anchor on the ledger."""

    new_public_key_b64: str = Field(
        description=(
            "Base64url-encoded raw 32-byte Ed25519 public key to associate with this DID. "
            "The corresponding private key must be held by the controller."
        )
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata to embed in the UPDATE ledger record.",
    )


class DIDDeactivateRequest(BaseModel):
    """Request to deactivate an existing DID."""

    reason: Optional[str] = Field(
        default=None,
        description="Human-readable reason for deactivation (stored in ledger metadata).",
        max_length=256,
    )


class SignatureVerifyRequest(BaseModel):
    """Request to verify an Ed25519 signature against a message using a DID's public key."""

    did: str = Field(description="The DID whose registered public key will be used for verification.")
    message_b64: str = Field(
        description="Base64url-encoded bytes of the original message that was signed."
    )
    signature_b64: str = Field(
        description="Base64url-encoded 64-byte Ed25519 signature to verify."
    )


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class DIDCreateResponse(BaseModel):
    """Response returned after a successful DID creation."""

    did: str = Field(description="The newly created DID string, e.g. 'did:mesh:key:a1b2c3d4e5f6a7b8'.")
    public_key_b64: str = Field(
        description="Base64url-encoded raw 32-byte Ed25519 public key (safe to share)."
    )
    private_key_b64: str = Field(
        description=(
            "Base64url-encoded raw 32-byte Ed25519 private key seed. "
            "⚠️ Store this securely — it is shown ONCE and never retained by the server."
        )
    )
    did_document: Dict[str, Any] = Field(description="W3C DID Core 1.0 compliant DID Document.")
    ledger_record_index: Optional[int] = Field(
        default=None,
        description="Ledger block index of the CREATE anchor record (None if not anchored).",
    )
    message: str = Field(description="Human-readable status message.")


class DIDResolveResponse(BaseModel):
    """Response returned when resolving a DID."""

    did: str = Field(description="The resolved DID.")
    did_document: Dict[str, Any] = Field(description="W3C DID Core 1.0 compliant DID Document.")
    deactivated: bool = Field(
        default=False,
        description="True if the DID has been deactivated and should no longer be trusted.",
    )


class DIDExistsResponse(BaseModel):
    """Response indicating whether a DID is registered."""

    did: str
    exists: bool
    deactivated: Optional[bool] = Field(
        default=None,
        description="True if the DID exists but is deactivated. None if DID does not exist.",
    )


class DIDListResponse(BaseModel):
    """Response listing all registered DIDs."""

    dids: List[str] = Field(description="List of all DID strings currently registered in the in-process registry.")
    total: int = Field(description="Total count of registered DIDs.")


class DIDUpdateResponse(BaseModel):
    """Response after updating a DID's public key."""

    did: str
    ledger_record_index: int = Field(description="Block index of the UPDATE anchor record on the ledger.")
    message: str


class DIDDeactivateResponse(BaseModel):
    """Response after deactivating a DID."""

    did: str
    deactivated: bool
    ledger_record_index: Optional[int] = Field(
        default=None,
        description="Block index of the DEACTIVATE anchor record on the ledger.",
    )
    message: str


class SignatureVerifyResponse(BaseModel):
    """Result of an Ed25519 signature verification."""

    did: str
    valid: bool = Field(description="True if the signature is cryptographically valid.")
    message: str = Field(description="Human-readable verification outcome.")
