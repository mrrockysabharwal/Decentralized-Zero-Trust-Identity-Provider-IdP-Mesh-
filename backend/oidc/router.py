from fastapi import APIRouter, HTTPException, Query, Header
from typing import Optional

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


# 2. Authorization Endpoint
@router.get("/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("openid"),
    state: Optional[str] = Query(None),
):
    if response_type != "code":
        raise HTTPException(
            status_code=400,
            detail="Unsupported response_type",
        )

    if "openid" not in scope.split():
        raise HTTPException(
            status_code=400,
            detail="The openid scope is required",
        )

    # Client registration, redirect URI validation,
    # user authentication, and authorization-code
    # generation must be implemented before this
    # endpoint can complete the authorization flow.
    raise HTTPException(
        status_code=501,
        detail="Authorization flow is not implemented yet",
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