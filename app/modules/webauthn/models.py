"""
app/modules/webauthn/models.py — Pydantic Schemas for WebAuthn/FIDO2 Module
============================================================================
Owner  : Member 2 (WebAuthn / FIDO2 Biometric Auth)
Branch : feature/webauthn-module

Defines all request and response models for the simulated WebAuthn
challenge-response ceremony. Follows the FIDO2 / W3C WebAuthn Level 2
vocabulary where applicable, adapted for Ed25519-based simulation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Registration models
# ---------------------------------------------------------------------------


class RegistrationBeginRequest(BaseModel):
    """Request to initiate a WebAuthn credential registration ceremony."""

    did: str = Field(
        description="DID to bind this credential to (e.g., 'did:mesh:key:abc123').",
        examples=["did:mesh:key:a1b2c3d4e5f6a7b8"],
    )
    display_name: Optional[str] = Field(
        default=None,
        description="Human-readable display name for the credential owner.",
        examples=["Alice Smith"],
    )


class RegistrationBeginResponse(BaseModel):
    """Challenge payload returned to the client for the registration ceremony."""

    challenge: str = Field(
        description="Base64url-encoded 32-byte random challenge nonce."
    )
    did: str = Field(description="DID this registration challenge is bound to.")
    rp_id: str = Field(description="Relying Party identifier (domain).")
    rp_name: str = Field(description="Relying Party display name.")
    expires_in_seconds: int = Field(
        description="Challenge TTL — must be completed before this elapses."
    )


class RegistrationCompleteRequest(BaseModel):
    """Credential submission for completing the WebAuthn registration ceremony.

    The client signs a canonical message with its Ed25519 private key and
    submits the public key + signature for server-side verification.

    Canonical message (SHA-256 pre-image):
        ``challenge_bytes + did.encode() + b"register"``
    """

    did: str = Field(description="DID being registered.")
    challenge: str = Field(description="The exact challenge string returned by /register/begin.")
    public_key_b64: str = Field(
        description=(
            "Base64url-encoded raw 32-byte Ed25519 public key "
            "(the authenticator's public key)."
        )
    )
    signature_b64: str = Field(
        description=(
            "Base64url-encoded 64-byte Ed25519 signature over "
            "SHA256(challenge_bytes + did_bytes + b'register')."
        )
    )
    credential_id: Optional[str] = Field(
        default=None,
        description=(
            "Optional client-provided credential identifier. "
            "If omitted, the server derives one from the public key."
        ),
    )
    device_info: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional authenticator device metadata (e.g., type, platform).",
    )


class RegistrationCompleteResponse(BaseModel):
    """Confirmation returned after a successful credential registration."""

    success: bool = Field(description="True if credential was successfully registered.")
    credential_id: str = Field(description="Unique identifier for the registered credential.")
    did: str = Field(description="DID the credential was bound to.")
    ledger_record_index: Optional[int] = Field(
        default=None,
        description="Index of the CREATE record anchored to the SimulatedLedger.",
    )
    message: str = Field(description="Human-readable confirmation message.")


# ---------------------------------------------------------------------------
# Authentication models
# ---------------------------------------------------------------------------


class AuthenticationBeginRequest(BaseModel):
    """Request to initiate a WebAuthn authentication ceremony for a registered DID."""

    did: str = Field(
        description="DID to authenticate.",
        examples=["did:mesh:key:a1b2c3d4e5f6a7b8"],
    )


class AuthenticationBeginResponse(BaseModel):
    """Challenge payload returned to the client for the authentication ceremony."""

    challenge: str = Field(
        description="Base64url-encoded 32-byte random challenge nonce."
    )
    did: str = Field(description="DID this authentication challenge is bound to.")
    credential_ids: List[str] = Field(
        description="List of credential IDs the user may use to authenticate."
    )
    expires_in_seconds: int = Field(
        description="Challenge TTL — must be completed before this elapses."
    )


class AuthenticationCompleteRequest(BaseModel):
    """Signed response for completing the WebAuthn authentication ceremony.

    Canonical message (SHA-256 pre-image):
        ``challenge_bytes + did.encode() + b"authenticate"``
    """

    did: str = Field(description="DID being authenticated.")
    challenge: str = Field(description="The exact challenge string returned by /authenticate/begin.")
    credential_id: str = Field(
        description="The credential ID being used for this authentication."
    )
    signature_b64: str = Field(
        description=(
            "Base64url-encoded 64-byte Ed25519 signature over "
            "SHA256(challenge_bytes + did_bytes + b'authenticate')."
        )
    )


class AuthenticationCompleteResponse(BaseModel):
    """Result of a completed WebAuthn authentication ceremony."""

    success: bool = Field(description="True if authentication was successful.")
    did: str = Field(description="Authenticated DID.")
    credential_id: str = Field(description="Credential used for authentication.")
    message: str = Field(description="Human-readable result message.")


# ---------------------------------------------------------------------------
# Credential info model (for list endpoint)
# ---------------------------------------------------------------------------


class CredentialInfo(BaseModel):
    """Public metadata for a registered credential."""

    credential_id: str = Field(description="Unique credential identifier.")
    did: str = Field(description="DID this credential is bound to.")
    public_key_b64: str = Field(
        description="Base64url-encoded public key (32 raw bytes)."
    )
    registered_at: str = Field(description="ISO 8601 UTC timestamp of registration.")
    device_info: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional authenticator device metadata."
    )
    sign_count: int = Field(
        default=0,
        description=(
            "Number of successful authentications with this credential. "
            "Monotonically increasing — used for replay-attack detection."
        ),
    )


class CredentialListResponse(BaseModel):
    """Response containing all credentials registered for a DID."""

    did: str = Field(description="DID queried.")
    credentials: List[CredentialInfo] = Field(
        description="List of registered credentials for this DID."
    )
    total: int = Field(description="Total count of credentials.")
