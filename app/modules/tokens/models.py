"""Pydantic request/response models for the JWT Access Token & Zero-Trust Policy Engine.

All models follow strict validation to prevent malformed data from entering the
token issuance or verification pipeline.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Allowed Scopes (configurable by policy engine)
# ---------------------------------------------------------------------------

ALLOWED_SCOPES: List[str] = [
    "read:profile",
    "write:did",
    "admin:ledger",
    "auth:webauthn",
]

# Default token lifetime in seconds (1 hour)
DEFAULT_TOKEN_EXPIRY_SECONDS: int = 3600

# JWT issuer and audience identifiers
TOKEN_ISSUER: str = "idp-mesh-v1"
TOKEN_AUDIENCE: str = "idp-mesh-api"


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class TokenIssueRequest(BaseModel):
    """Payload to request a new JWT access token for an authenticated DID."""

    did: str = Field(
        min_length=3,
        description="Decentralized Identifier (e.g. did:mesh:key:z6Mku...) to issue the token for",
    )
    scope: List[str] = Field(
        default_factory=lambda: ["read:profile"],
        description="List of requested permission scopes",
    )
    audience: Optional[str] = Field(
        default=None,
        description="Optional JWT audience override (defaults to 'idp-mesh-api')",
    )
    extra_claims: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional additional claims to embed in the token payload",
    )

    @field_validator("scope")
    @classmethod
    def validate_scope_not_empty(cls, v: List[str]) -> List[str]:
        """Ensure at least one scope is requested."""
        if not v:
            raise ValueError("scope must contain at least one entry")
        return v


class TokenVerifyRequest(BaseModel):
    """Payload to verify and decode a raw JWT access token string."""

    token: str = Field(description="Raw JWT string (Bearer token value) to verify")


class TokenRevokeRequest(BaseModel):
    """Payload to revoke a specific token by its unique JWT ID (JTI)."""

    jti: str = Field(
        min_length=1,
        description="JWT ID (jti claim) of the token to revoke",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Optional human-readable reason for revocation (for audit logs)",
    )


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------


class TokenIssueResponse(BaseModel):
    """Response returned after successfully issuing a JWT access token."""

    access_token: str = Field(description="Signed JWT access token string")
    token_type: str = Field(default="Bearer", description="Token type (always 'Bearer')")
    expires_in: int = Field(description="Token lifetime in seconds from time of issuance")
    jti: str = Field(description="Unique JWT ID — use this to revoke the token if needed")
    did: str = Field(description="DID this token was issued for")
    scope: List[str] = Field(description="Granted permission scopes")


class TokenVerifyResponse(BaseModel):
    """Response returned after verifying a JWT access token."""

    valid: bool = Field(description="True if the token is valid, unexpired, and not revoked")
    claims: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Decoded token claims if valid, None otherwise",
    )
    error: Optional[str] = Field(
        default=None,
        description="Human-readable error message if the token is invalid",
    )


class TokenRevokeResponse(BaseModel):
    """Response returned after revoking a token."""

    revoked: bool = Field(description="True if revocation was recorded successfully")
    jti: str = Field(description="The JTI that was revoked")
    message: str = Field(description="Human-readable confirmation message")


class PublicKeyResponse(BaseModel):
    """Response returning the server's current JWT signing public key."""

    public_key_pem: str = Field(description="Ed25519 public key in PEM format")
    algorithm: str = Field(default="EdDSA", description="JWT signing algorithm")
    issuer: str = Field(description="Token issuer identifier")


class AllowedScopesResponse(BaseModel):
    """Response listing all policy-allowed permission scopes."""

    scopes: List[str] = Field(description="List of valid scope strings for token requests")


# ---------------------------------------------------------------------------
# Internal Policy Model
# ---------------------------------------------------------------------------


class PolicyCheckResult(BaseModel):
    """Internal result of a Zero-Trust policy evaluation."""

    allowed: bool = Field(description="True if the DID is permitted to receive a token")
    reason: str = Field(description="Human-readable explanation of the allow/deny decision")
    did: str = Field(description="The DID that was evaluated")
    checked_scope: List[str] = Field(
        default_factory=list,
        description="The scopes that were checked against policy",
    )
