"""JWT role checks for administrative API operations."""

from __future__ import annotations

import jwt
from fastapi import Cookie, Header, HTTPException

from app.modules.tokens.jwt_engine import verify_token
import app.modules.tokens.router as token_router


def verify_admin_token(token: str | None) -> dict:
    if not token:
        raise HTTPException(status_code=401, detail="Administrator bearer token required.")
    try:
        claims = verify_token(token, token_router.get_public_key())
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired administrator token.") from exc
    if token_router.get_revocation_store().is_revoked(claims.get("jti", "")):
        raise HTTPException(status_code=401, detail="Administrator token has been revoked.")
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator role is required.")
    return claims


def require_admin(
    authorization: str | None = Header(default=None),
    idp_admin_session: str | None = Cookie(default=None),
) -> dict:
    token = idp_admin_session
    if authorization:
        scheme, _, bearer_token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not bearer_token:
            raise HTTPException(status_code=401, detail="Invalid bearer authorization header.")
        token = bearer_token
    return verify_admin_token(token)
