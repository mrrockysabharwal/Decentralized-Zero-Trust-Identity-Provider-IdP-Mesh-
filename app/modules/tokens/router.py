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
from typing import Optional

import jwt as pyjwt
from fastapi import APIRouter, Header, HTTPException, status

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
from app.modules.webauthn.session_store import auth_session_store, VerifiedPrincipal
from app.modules.audit.event_store import record_security_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/tokens", tags=["JWT Tokens & Zero-Trust Policy"])

# ---------------------------------------------------------------------------
# Singletons (shared across requests; replaceable via tests)
# ---------------------------------------------------------------------------

# Key directory respects TOKEN_KEY_DIR env var for deployment flexibility
_KEY_DIR = os.environ.get("TOKEN_KEY_DIR", ".token_keys")
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
def issue_access_token(payload: TokenIssueRequest, authorization: str | None = Header(default=None)) -> TokenIssueResponse:
    """Issue a signed JWT access token after evaluating Zero-Trust policy.

    The policy engine checks:
    1. DID is registered on the ledger.
    2. DID is not deactivated.
    3. Ledger cryptographic integrity is intact.
    4. All requested scopes are policy-permitted.

    Returns **403 Forbidden** if any policy check fails.
    """
    try:
        principal = _session_principal(authorization)
    except HTTPException:
        record_security_event(event_type="token_issuance", outcome="failure", severity="medium",
                              reason="verified_authentication_required")
        raise
    if payload.did != principal.did:
        record_security_event(event_type="policy_decision", outcome="deny", severity="high",
                              did=principal.did, reason="requested_did_mismatch")
        raise HTTPException(status_code=403, detail="Requested DID does not match the authenticated principal.")

    engine = get_policy_engine()
    policy_result = engine.evaluate(
        did=payload.did,
        requested_scope=payload.scope,
        require_webauthn=payload.require_webauthn,
    )

    if not policy_result.allowed:
        record_security_event(event_type="policy_decision", outcome="deny", severity="medium",
                              did=payload.did, reason="policy_denied")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=policy_result.reason,
        )

    # Fetch latest ledger record to embed DID state in token claims
    ledger = get_ledger()
    latest_record = ledger.get_latest_record(payload.did)
    did_verified_at: Optional[str] = latest_record.timestamp if latest_record else None

    try:
        configured_admin_dids = {
            did.strip() for did in os.environ.get("IDP_ADMIN_DIDS", "").split(",") if did.strip()
        }
        # Never permit a caller to assign a trusted authorization claim.
        server_claims = {key: value for key, value in payload.extra_claims.items() if key != "role"}
        server_claims["role"] = "admin" if payload.did in configured_admin_dids else "user"
        token_str, jti = issue_token(
            did=payload.did,
            scope=payload.scope,
            private_key_pem=get_private_key(),
            audience=payload.audience,
            expiry_seconds=DEFAULT_TOKEN_EXPIRY_SECONDS,
            did_verified_at=did_verified_at,
            did_status="ACTIVE",
            extra_claims=server_claims,
        )
    except Exception as exc:
        logger.exception("Token issuance failed for DID=%s: %s", payload.did, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token issuance failed: {exc}",
        ) from exc

    record_security_event(event_type="policy_decision", outcome="allow", severity="low",
                          did=payload.did, reason="policy_allowed", metadata={"scope_count": len(payload.scope)})
    record_security_event(event_type="token_issuance", outcome="success", severity="low",
                          did=payload.did, reason="access_token_issued", metadata={"scope_count": len(payload.scope)})

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
def revoke_access_token(payload: TokenRevokeRequest, authorization: str | None = Header(default=None)) -> TokenRevokeResponse:
    """Add a token's JTI to the deny-list, preventing future use.

    The revocation entry is stored with a TTL equal to the default token
    lifetime so the deny-list self-cleans when the token would have expired.
    """
    try:
        claims = _access_token_claims(authorization)
    except HTTPException:
        record_security_event(event_type="token_revocation", outcome="failure", severity="medium",
                              reason="valid_access_token_required")
        raise
    if claims.get("jti") != payload.jti:
        record_security_event(event_type="token_revocation", outcome="failure", severity="high",
                              did=claims.get("sub"), reason="jti_ownership_mismatch")
        raise HTTPException(status_code=403, detail="A user may revoke only their own presented token.")
    revocation_store = get_revocation_store()
    ttl = max(1, int(claims.get("exp", 0) - datetime.now(timezone.utc).timestamp()))
    revocation_store.revoke(jti=payload.jti, ttl_seconds=ttl)
    record_security_event(event_type="token_revocation", outcome="success", severity="low",
                          did=claims.get("sub"), reason="owner_revoked_token")

    reason_note = f" Reason: {payload.reason}" if payload.reason else ""
    logger.info("Token revoked: jti=%s.%s", payload.jti, reason_note)

    return TokenRevokeResponse(
        revoked=True,
        jti=payload.jti,
        message=f"Token (jti={payload.jti}) has been revoked and added to the deny-list.{reason_note}",
    )


def _bearer_value(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Bearer authentication is required.")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value:
        raise HTTPException(status_code=401, detail="Invalid bearer authorization header.")
    return value


def _session_principal(authorization: str | None) -> VerifiedPrincipal:
    principal = auth_session_store.resolve(_bearer_value(authorization))
    if principal is None:
        raise HTTPException(status_code=401, detail="Authentication session is invalid or expired.")
    return principal


def _access_token_claims(authorization: str | None) -> dict:
    try:
        return verify_token(_bearer_value(authorization), get_public_key())
    except pyjwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="A valid access token is required to revoke it.") from exc


@router.get("/protected/profile", tags=["Protected Resources"])
def get_protected_profile(authorization: str | None = Header(default=None)) -> dict:
    """Example protected resource: valid, unrevoked token with read:profile scope."""
    claims = _access_token_claims(authorization)
    jti = claims.get("jti", "")
    if get_revocation_store().is_revoked(jti):
        raise HTTPException(status_code=401, detail="Access token has been revoked.")
    scopes = claims.get("scope", [])
    if isinstance(scopes, str):
        scopes = scopes.split()
    if "read:profile" not in scopes:
        raise HTTPException(status_code=403, detail="Token does not grant read:profile.")
    return {"resource": "profile", "did": claims["sub"], "allowed": True}


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
