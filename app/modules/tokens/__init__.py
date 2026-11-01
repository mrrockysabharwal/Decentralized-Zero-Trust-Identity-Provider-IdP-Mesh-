"""JWT Access Token & Zero-Trust Policy Engine Module.

This module provides the authorization layer for the Decentralized Zero-Trust
IdP Mesh — issuing, verifying, and revoking Ed25519-signed JWT access tokens
after enforcing Zero-Trust policy checks against the simulated blockchain ledger.

Public API::

    from app.modules.tokens import (
        tokens_router,          # Mount in FastAPI app
        ZeroTrustPolicyEngine,  # Evaluate DID authorization
        TokenRevocationStore,   # JTI deny-list (Redis / in-memory)
        issue_token,            # Low-level JWT issuance
        verify_token,           # Low-level JWT verification
        load_or_create_keys,    # Key management
    )
"""

from app.modules.tokens.models import (
    ALLOWED_SCOPES,
    DEFAULT_TOKEN_EXPIRY_SECONDS,
    TOKEN_AUDIENCE,
    TOKEN_ISSUER,
    AllowedScopesResponse,
    PolicyCheckResult,
    PublicKeyResponse,
    TokenIssueRequest,
    TokenIssueResponse,
    TokenRevokeRequest,
    TokenRevokeResponse,
    TokenVerifyRequest,
    TokenVerifyResponse,
)
from app.modules.tokens.jwt_engine import (
    decode_token_unverified,
    generate_signing_keypair,
    issue_token,
    load_or_create_keys,
    verify_token,
)
from app.modules.tokens.revocation import TokenRevocationStore
from app.modules.tokens.policy import ZeroTrustPolicyEngine


def __getattr__(name: str):
    """Load the HTTP router only when callers explicitly request it.

    Importing token models, policy, JWT helpers, or revocation storage must not
    initialize externally provisioned signing keys as a side effect.
    """
    if name == "tokens_router":
        from app.modules.tokens.router import router

        return router
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    # Models
    "ALLOWED_SCOPES",
    "DEFAULT_TOKEN_EXPIRY_SECONDS",
    "TOKEN_AUDIENCE",
    "TOKEN_ISSUER",
    "AllowedScopesResponse",
    "PolicyCheckResult",
    "PublicKeyResponse",
    "TokenIssueRequest",
    "TokenIssueResponse",
    "TokenRevokeRequest",
    "TokenRevokeResponse",
    "TokenVerifyRequest",
    "TokenVerifyResponse",
    # JWT Engine
    "decode_token_unverified",
    "generate_signing_keypair",
    "issue_token",
    "load_or_create_keys",
    "verify_token",
    # Revocation
    "TokenRevocationStore",
    # Policy
    "ZeroTrustPolicyEngine",
    # Router
    "tokens_router",
]
