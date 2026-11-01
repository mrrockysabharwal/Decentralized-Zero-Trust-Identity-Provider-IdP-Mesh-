"""JWT role checks for administrative API operations."""

from __future__ import annotations

import jwt
from fastapi import Header, HTTPException

from app.modules.tokens.jwt_engine import verify_token
import app.modules.tokens.router as token_router


def require_admin(authorization: str | None = Header(default=None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Administrator bearer token required.")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid bearer authorization header.")
    try:
        claims = verify_token(token, token_router.get_public_key())
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired administrator token.") from exc
    if token_router.get_revocation_store().is_revoked(claims.get("jti", "")):
        raise HTTPException(status_code=401, detail="Administrator token has been revoked.")
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator role is required.")
    return claims
