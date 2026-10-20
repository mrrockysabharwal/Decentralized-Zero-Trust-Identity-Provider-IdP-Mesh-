"""FastAPI Router for the JWT Access Token & Zero-Trust Policy Engine.

Endpoints (all mounted under /api/v1/tokens by Member 1's main.py):

  POST   /tokens/issue          - Returns HTTP 503 until verified caller authentication is integrated
  POST   /tokens/verify         — Verify & decode a JWT
  POST   /tokens/revoke         - Returns HTTP 503 until token ownership authorization is integrated
  GET    /tokens/public-key     — Return the current Ed25519 signing public key
  GET    /tokens/policy/scopes  — Return the list of policy-allowed scopes

Integration for Member 1 (mount in app/main.py):

    from app.modules.tokens import tokens_router
    app.include_router(tokens_router, prefix="/api/v1")
"""

import os
from pathlib import Path

import jwt as pyjwt
from fastapi import APIRouter, HTTPException, status

from app.modules.ledger.chain import SimulatedLedger
from app.modules.tokens.jwt_engine import (
    load_or_create_keys,
    verify_token,
)
from app.modules.tokens.models import (
    TOKEN_ISSUER,
    AllowedScopesResponse,
    PublicKeyResponse,
    TokenIssueRequest,
    TokenRevokeRequest,
    TokenVerifyRequest,
    TokenVerifyResponse,
)
from app.modules.tokens.policy import ZeroTrustPolicyEngine
from app.modules.tokens.revocation import TokenRevocationStore

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/tokens", tags=["JWT Tokens & Zero-Trust Policy"])

# ---------------------------------------------------------------------------
# Singletons (shared across requests; replaceable via tests)
# ---------------------------------------------------------------------------

# Signing keys must be provisioned outside the repository before importing the app.
_configured_key_dir = os.environ.get("TOKEN_KEY_DIR")
if not _configured_key_dir or not _configured_key_dir.strip():
    raise RuntimeError("TOKEN_KEY_DIR must be explicitly set to an external signing-key directory.")

_KEY_DIR_PATH = Path(_configured_key_dir).expanduser().resolve()
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
try:
    _KEY_DIR_PATH.relative_to(_REPOSITORY_ROOT)
except ValueError:
    pass
else:
    raise RuntimeError("TOKEN_KEY_DIR must resolve to a directory outside the repository.")

if not _KEY_DIR_PATH.is_dir():
    raise RuntimeError("TOKEN_KEY_DIR must point to an existing directory outside the repository.")

_KEY_DIR = str(_KEY_DIR_PATH)
_private_key_pem, _public_key_pem = load_or_create_keys(_KEY_DIR)

# Shared ledger instance — the same ledger used by the ledger module
_shared_ledger = SimulatedLedger(auto_genesis=True)

# Policy engine backed by the shared ledger
_policy_engine = ZeroTrustPolicyEngine(ledger=_shared_ledger)

# Revocation store (Redis or in-memory fallback)
_revocation_store = TokenRevocationStore(
    redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0")
)


# ---------------------------------------------------------------------------
# Dependency helpers (replaceable in tests via module-level reassignment)
# ---------------------------------------------------------------------------


def get_private_key() -> bytes:
    return _private_key_pem


def get_public_key() -> bytes:
    return _public_key_pem


def get_ledger() -> SimulatedLedger:
    return _shared_ledger


def get_policy_engine() -> ZeroTrustPolicyEngine:
    return _policy_engine


def get_revocation_store() -> TokenRevocationStore:
    return _revocation_store


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/issue",
    response_model=None,
    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    summary="Unavailable until authenticated DID verification is integrated",
)
def issue_access_token(payload: TokenIssueRequest) -> None:
    """Reject token issuance until a verified caller identity is available.

    Ledger registration and scope policy do not prove that the caller controls
    the requested DID. Issuance stays unavailable until authentication can
    supply a verified DID principal.
    """
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Token issuance is unavailable until authenticated DID verification is integrated.",
    )


@router.post(
    "/verify",
    response_model=TokenVerifyResponse,
    summary="Verify and decode a JWT access token",
)
def verify_access_token(payload: TokenVerifyRequest) -> TokenVerifyResponse:
    """Verify a JWT's signature, expiry, and revocation status.

    Returns **401 Unauthorized** if the token is expired, has an invalid
    signature, or has been explicitly revoked.
    """
    revocation_store = get_revocation_store()

    # Step 1: Verify signature and standard claims
    try:
        claims = verify_token(payload.token, get_public_key())
    except pyjwt.ExpiredSignatureError:
        return TokenVerifyResponse(valid=False, error="Token has expired.")
    except pyjwt.InvalidTokenError as exc:
        return TokenVerifyResponse(valid=False, error=f"Invalid token: {exc}")

    # Step 2: Check revocation deny-list
    jti = claims.get("jti", "")
    if revocation_store.is_revoked(jti):
        return TokenVerifyResponse(
            valid=False,
            error=f"Token (jti={jti}) has been explicitly revoked.",
        )

    return TokenVerifyResponse(valid=True, claims=claims)


@router.post(
    "/revoke",
    response_model=None,
    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    summary="Unavailable until authenticated token ownership is integrated",
)
def revoke_access_token(payload: TokenRevokeRequest) -> None:
    """Reject revocation until a verified caller identity is available.

    A JTI alone carries no proof of ownership, and this service currently has
    no authenticated principal with which to authorize revocation.
    """
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Token revocation is unavailable until authenticated token ownership is integrated.",
    )


@router.get(
    "/public-key",
    response_model=PublicKeyResponse,
    summary="Get the JWT signing public key",
)
def get_signing_public_key() -> PublicKeyResponse:
    """Return the Ed25519 public key used to sign JWTs.

    Downstream services (e.g. Member 6 Admin Dashboard) can use this key
    to independently verify access tokens without calling the /verify endpoint.
    """
    return PublicKeyResponse(
        public_key_pem=get_public_key().decode("utf-8"),
        algorithm="EdDSA",
        issuer=TOKEN_ISSUER,
    )


@router.get(
    "/policy/scopes",
    response_model=AllowedScopesResponse,
    summary="List all policy-allowed permission scopes",
)
def list_allowed_scopes() -> AllowedScopesResponse:
    """Return the complete list of scopes that the policy engine will accept.

    Clients should request only scopes from this list when calling /tokens/issue.
    """
    engine = get_policy_engine()
    return AllowedScopesResponse(scopes=engine.get_allowed_scopes())
