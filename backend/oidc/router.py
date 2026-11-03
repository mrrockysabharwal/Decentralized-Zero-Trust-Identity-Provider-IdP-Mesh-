from fastapi import APIRouter, HTTPException, Query, Header
from fastapi import Cookie
from typing import Optional
from backend.oidc.service import (
    generate_authorization_code,
    validate_client_redirect_uri,
    consume_authorization_code,
    create_access_token,
    validate_access_token,
    ACCESS_TOKEN_TTL_SECONDS,
    validate_login_session,
)

from backend.oidc.schemas import TokenRequest, TokenResponse
from fastapi.responses import RedirectResponse
from urllib.parse import urlencode

router = APIRouter(prefix="/oidc", tags=["OIDC"])


# 1. OpenID Connect Discovery Endpoint
@router.get("/.well-known/openid-configuration")
async def openid_configuration():
    return {
        "issuer": "http://127.0.0.1:8000/oidc",
        "authorization_endpoint": "http://127.0.0.1:8000/oidc/authorize",
        "token_endpoint": "http://127.0.0.1:8000/oidc/token",
        "userinfo_endpoint": "http://127.0.0.1:8000/oidc/userinfo",
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
    session_token: Optional[str] = Cookie(
        None,
        alias="tm_login_session",
    ),
):
    # Validate response type
    if response_type != "code":
        raise HTTPException(
            status_code=400,
            detail="Unsupported response_type",
        )

    # Validate registered client and redirect URI
    if not validate_client_redirect_uri(client_id, redirect_uri):
        raise HTTPException(
            status_code=400,
            detail="Invalid client_id or redirect_uri",
        )

    # Require OpenID scope
    if "openid" not in scope.split():
        raise HTTPException(
            status_code=400,
            detail="The openid scope is required",
        )

    # Validate PKCE
    if code_challenge_method != "S256":
        raise HTTPException(
            status_code=400,
            detail="Only PKCE S256 is supported",
        )

    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", code_challenge):
        raise HTTPException(
            status_code=400,
            detail="Invalid PKCE code_challenge",
        )

    # Validate authenticated WebAuthn session
    user = validate_login_session(session_token)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Please log in with your passkey first.",
        )

    # Generate authorization code
    code = generate_authorization_code(
        client_id=client_id,
        redirect_uri=redirect_uri,
        username=user["username"],
        scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    # Redirect back to registered client
    params = {
        "code": code,
    }

    if state:
        params["state"] = state

    separator = "&" if "?" in redirect_uri else "?"

    return RedirectResponse(
        url=f"{redirect_uri}{separator}{urlencode(params)}",
        status_code=302,
    )


# 3. Token Exchange Endpoint
@router.post("/token", response_model=TokenResponse)
async def token_exchange(body: TokenRequest):

    if body.grant_type != "authorization_code":
        raise HTTPException(
            status_code=400,
            detail="Unsupported grant_type",
        )

    if not validate_client_redirect_uri(
        body.client_id,
        body.redirect_uri,
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid client_id or redirect_uri",
        )

    result = consume_authorization_code(
        code=body.code,
        client_id=body.client_id,
        redirect_uri=body.redirect_uri,
        code_verifier=body.code_verifier,
    )

    if result is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid, expired, reused code or failed PKCE verification",
        )

    access_token = create_access_token(
        username=result["username"],
        client_id=result["client_id"],
        scope=result["scope"],
    )

    return TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=ACCESS_TOKEN_TTL_SECONDS,
        id_token=None,
        scope=result["scope"],
    )

# 4. UserInfo Endpoint
@router.get("/userinfo")
async def userinfo(
    authorization: Optional[str] = Header(None),
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="A valid Bearer access token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = authorization.split(" ", 1)[1].strip()

    user = validate_access_token(access_token)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "sub": user["username"],
        "preferred_username": user["username"],
    }