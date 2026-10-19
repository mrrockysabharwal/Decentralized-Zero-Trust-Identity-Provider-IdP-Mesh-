"""FastAPI Router for the JWT Access Token & Zero-Trust Policy Engine.

Endpoints (all mounted under /api/v1/tokens by Member 1's main.py):

  POST   /tokens/issue          — Issue a JWT for an authenticated DID
  POST   /tokens/verify         — Verify & decode a JWT
  POST   /tokens/revoke         — Revoke a token by JTI
  GET    /tokens/public-key     — Return the current Ed25519 signing public key
  GET    /tokens/policy/scopes  — Return the list of policy-allowed scopes

Integration for Member 1 (mount in app/main.py):

    from app.modules.tokens import tokens_router
    app.include_router(tokens_router, prefix="/api/v1")
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import jwt as pyjwt
from fastapi import APIRouter, HTTPException, status

from app.modules.ledger.chain import SimulatedLedger
from app.modules.tokens.jwt_engine import (
    decode_token_unverified,
    issue_token,
    load_or_create_keys,
    verify_token,
)
from app.modules.tokens.models import (
    ALLOWED_SCOPES,
    DEFAULT_TOKEN_EXPIRY_SECONDS,
    TOKEN_ISSUER,
    AllowedScopesResponse,
    PublicKeyResponse,
    TokenIssueRequest,
    TokenIssueResponse,
    TokenRevokeRequest,
    TokenRevokeResponse,
    TokenVerifyRequest,
    TokenVerifyResponse,
)
from app.modules.tokens.policy import ZeroTrustPolicyEngine
from app.modules.tokens.revocation import TokenRevocationStore

logger = logging.getLogger(__name__)

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
    response_model=TokenIssueResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Issue a JWT access token for an authenticated DID",
)
def issue_access_token(payload: TokenIssueRequest) -> TokenIssueResponse:
    """Issue a signed JWT access token after evaluating Zero-Trust policy.

    The policy engine checks:
    1. DID is registered on the ledger.
    2. DID is not deactivated.
    3. Ledger cryptographic integrity is intact.
    4. All requested scopes are policy-permitted.

    Returns **403 Forbidden** if any policy check fails.
    """
    engine = get_policy_engine()
    policy_result = engine.evaluate(did=payload.did, requested_scope=payload.scope)

    if not policy_result.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=policy_result.reason,
        )

    # Fetch latest ledger record to embed DID state in token claims
    ledger = get_ledger()
    latest_record = ledger.get_latest_record(payload.did)
    did_verified_at: Optional[str] = latest_record.timestamp if latest_record else None

    try:
        token_str, jti = issue_token(
            did=payload.did,
            scope=payload.scope,
            private_key_pem=get_private_key(),
            audience=payload.audience,
            expiry_seconds=DEFAULT_TOKEN_EXPIRY_SECONDS,
            did_verified_at=did_verified_at,
            did_status="ACTIVE",
            extra_claims=payload.extra_claims,
        )
    except Exception as exc:
        logger.exception("Token issuance failed for DID=%s: %s", payload.did, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token issuance failed: {exc}",
        ) from exc

    return TokenIssueResponse(
        access_token=token_str,
        token_type="Bearer",
        expires_in=DEFAULT_TOKEN_EXPIRY_SECONDS,
        jti=jti,
        did=payload.did,
        scope=payload.scope,
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
    response_model=TokenRevokeResponse,
    summary="Revoke a JWT access token by JTI",
)
def revoke_access_token(payload: TokenRevokeRequest) -> TokenRevokeResponse:
    """Add a token's JTI to the deny-list, preventing future use.

    The revocation entry is stored with a TTL equal to the default token
    lifetime so the deny-list self-cleans when the token would have expired.
    """
    revocation_store = get_revocation_store()
    revocation_store.revoke(jti=payload.jti, ttl_seconds=DEFAULT_TOKEN_EXPIRY_SECONDS)

    reason_note = f" Reason: {payload.reason}" if payload.reason else ""
    logger.info("Token revoked: jti=%s.%s", payload.jti, reason_note)

    return TokenRevokeResponse(
        revoked=True,
        jti=payload.jti,
        message=f"Token (jti={payload.jti}) has been revoked and added to the deny-list.{reason_note}",
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
