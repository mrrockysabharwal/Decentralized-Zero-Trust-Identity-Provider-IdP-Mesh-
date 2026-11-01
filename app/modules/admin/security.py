"""Authentication dependency shared by privileged API routes."""

from __future__ import annotations

import os
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from jwt import InvalidTokenError

from app.modules.revocation_provider import get_revocation_store
from app.modules.tokens.revocation import RevocationStoreError

MAX_ADMIN_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60

_bearer = HTTPBearer(auto_error=False)


def require_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict[str, Any]:
    """Require a valid, unrevoked admin-issuer JWT and an allowlisted subject.

    The admin JWT has a separate configured public key and issuer/audience from
    ordinary API access tokens. A role or identity supplied in a request is never
    consulted.
    """
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="A valid administrator bearer token is required.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized

    try:
        admin_public_key = os.environ.get("ADMIN_JWT_PUBLIC_KEY", "").replace("\\n", "\n")
        if not admin_public_key:
            raise unauthorized
        claims = jwt.decode(
            credentials.credentials,
            admin_public_key,
            algorithms=["EdDSA"],
            audience="idp-mesh-admin",
            issuer="idp-mesh-admin",
            options={"require": ["sub", "jti", "iat", "exp", "iss", "aud", "scope"]},
        )
    except HTTPException:
        raise
    except (InvalidTokenError, KeyError, TypeError, ValueError, OSError):
        raise unauthorized

    jti = claims.get("jti")
    if (
        not isinstance(jti, str)
        or not jti
        or len(jti) > 256
        or not jti.isprintable()
        or jti != jti.strip()
    ):
        raise unauthorized
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, (int, float))
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_ADMIN_TOKEN_LIFETIME_SECONDS
    ):
        raise unauthorized

    try:
        revocation_store = get_revocation_store()
        revocation_store.require_durable()
        is_revoked = revocation_store.is_revoked(jti)
    except RevocationStoreError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Administrator authentication is temporarily unavailable.",
        ) from None
    except Exception:
        # Missing wiring and unexpected backend failures must never authorize an admin.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Administrator authentication is temporarily unavailable.",
        ) from None

    if is_revoked:
        raise unauthorized

    raw_scopes = claims.get("scope", [])
    scopes = raw_scopes.split() if isinstance(raw_scopes, str) else raw_scopes
    if not isinstance(scopes, (list, tuple)) or "admin:ledger" not in scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator scope is required.",
        )

    allowed_admin_dids = {
        did.strip()
        for did in os.environ.get("ADMIN_DIDS", "").split(",")
        if did.strip()
    }
    if not allowed_admin_dids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator identities are not configured.",
        )
    if claims.get("sub") not in allowed_admin_dids:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This identity is not an authorized administrator.",
        )
    return claims


def require_tamper_demo_enabled() -> None:
    """Keep demo-only tampering unavailable unless explicitly enabled."""
    if os.environ.get("ENABLE_LEDGER_TAMPER_DEMO", "").strip().lower() not in {
        "1", "true", "yes", "on"
    }:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ledger tamper simulation is disabled.",
        )
