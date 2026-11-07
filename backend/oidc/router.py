from fastapi import APIRouter, HTTPException, Query, Header, Request
from typing import Optional
from backend.oidc.service import (
    generate_authorization_code,
    validate_client_redirect_uri,
    create_authorization_transaction,
)
from fastapi.responses import RedirectResponse
from urllib.parse import urlencode

router = APIRouter(prefix="/oidc", tags=["OIDC"])


# 1. OpenID Connect Discovery Endpoint
@router.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request):
    issuer = f"{str(request.base_url).rstrip('/')}/api/v1/oidc"
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "grant_types_supported": ["authorization_code"],
    }



import re

@router.get("/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("openid"),
    state: Optional[str] = Query(None),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query("S256"),
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")
    if not validate_client_redirect_uri(client_id, redirect_uri):
        raise HTTPException(
        status_code=400,
        detail="Invalid client_id or redirect_uri",
    )

    if "openid" not in scope.split():
        raise HTTPException(status_code=400, detail="The openid scope is required")

    if code_challenge_method != "S256":
        raise HTTPException(status_code=400, detail="Only PKCE S256 is supported")

    # RFC 7636: an S256 challenge is 43 characters
    # for a SHA-256 digest encoded using Base64URL without padding.
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", code_challenge):
        raise HTTPException(status_code=400, detail="Invalid PKCE code_challenge")

    # Do not issue a code until client registration,
    # redirect URI validation, and user authentication exist.
    raise HTTPException(
        status_code=501,
        detail="Client validation and authenticated OIDC session are not implemented yet",
    )



# 3. Token Exchange Endpoint
@router.post("/token")
async def token_exchange():
    # Validate the client and authorization code,
    # then issue properly signed tokens.
    raise HTTPException(
        status_code=501,
        detail="Token exchange is not implemented yet",
    )


# 4. UserInfo Endpoint
@router.get("/userinfo")
async def userinfo(
    authorization: Optional[str] = Header(None),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="A Bearer access token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate the access token and retrieve the
    # authenticated user's claims before returning them.
    raise HTTPException(
        status_code=501,
        detail="Access-token validation is not implemented yet",
    )
