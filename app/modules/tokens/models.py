"""Pydantic request/response models for the JWT Access Token & Zero-Trust Policy Engine.

All models follow strict validation to prevent malformed data from entering the
token issuance or verification pipeline.
"""

from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from fastapi import HTTPException, Header, status


# ---------------------------------------------------------------------------
# Allowed Scopes (configurable by policy engine)
# ---------------------------------------------------------------------------

ALLOWED_SCOPES: List[str] = [
    "read:profile",
    "write:did",
    "auth:webauthn",
]

# These claims are assigned by trusted token-issuance code and can never be
# provided through the custom-claims extension point.
RESERVED_TOKEN_CLAIMS = frozenset(
    {
        "iss",
        "sub",
        "aud",
        "exp",
        "nbf",
        "iat",
        "jti",
        "scope",
        "scp",
        "did",
        "did_status",
        "did_verified_at",
        "did_verification_status",
        "role",
        "roles",
        "permissions",
        "groups",
        "is_admin",
        "admin",
        "auth_time",
        "acr",
        "amr",
        "tenant",
        "client_id",
    }
)

# Only informational correlation metadata is accepted as a custom claim.
ALLOWED_EXTRA_TOKEN_CLAIMS = frozenset({"trace_id"})


def validate_extra_token_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Accept only allowlisted non-authorization metadata claims."""
    for name, value in claims.items():
        if name in RESERVED_TOKEN_CLAIMS:
            raise ValueError(f"extra_claims cannot set reserved claim '{name}'.")
        if name not in ALLOWED_EXTRA_TOKEN_CLAIMS:
            raise ValueError(f"Custom token claim '{name}' is not allowed.")
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ValueError(
                "The trace_id custom claim must be a non-empty string of at most 128 characters."
            )
    return dict(claims)

# Default token lifetime in seconds (1 hour)
DEFAULT_TOKEN_EXPIRY_SECONDS: int = 3600
# Maximum ordinary-token lifetime. Revocation records are retained for at least
# the target token's remaining lifetime, so storage TTLs share this bound.
MAX_TOKEN_LIFETIME_SECONDS: int = 30 * 24 * 60 * 60

# JWT issuer and audience identifiers
TOKEN_ISSUER: str = "idp-mesh-v1"
TOKEN_AUDIENCE: str = "idp-mesh-api"


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class TokenIssueRequest(BaseModel):
    """Payload to request a new JWT access token for an authenticated DID."""

    model_config = ConfigDict(extra="forbid")

    did: str = Field(
        min_length=3,
        description="Decentralized Identifier (e.g. did:mesh:key:z6Mku...) to issue the token for",
    )
    scope: List[str] = Field(
        default_factory=lambda: ["read:profile"],
        description="List of requested permission scopes",
    )
    extra_claims: Dict[str, Any] = Field(
        default_factory=dict,
        description="Allowlisted informational claims only (currently trace_id)",
    )
    require_webauthn: bool = Field(
        default=False,
        description=(
            "If True, the Zero-Trust policy engine will enforce Check 5: "
            "the DID must have at least one registered WebAuthn credential before "
            "a token is issued. Set to True for production flows that follow the "
            "full DID → WebAuthn → Token ceremony."
        ),
    )

    @field_validator("scope")
    @classmethod
    def validate_scope_not_empty(cls, v: List[str]) -> List[str]:
        """Ensure at least one scope is requested."""
        if not v:
            raise ValueError("scope must contain at least one entry")
        invalid = [scope for scope in v if scope not in ALLOWED_SCOPES]
        if invalid:
            raise ValueError(f"scope contains values not permitted for ordinary tokens: {invalid}")
        return v

    @field_validator("extra_claims")
    @classmethod
    def validate_extra_claims_field(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        return validate_extra_token_claims(v)


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
