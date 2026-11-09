"""OpenID Connect (OIDC) Provider Router.

Implements the OIDC Discovery, Authorization Code Flow with PKCE (RFC 7636),
Token Exchange, JWKS, and UserInfo endpoints for decentralized identity.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Header, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from app.modules.tokens.jwt_engine import (
    _load_public_key,
    issue_token,
    verify_token,
)
from app.modules.tokens.models import TOKEN_AUDIENCE
import app.modules.tokens.router as token_router
from app.modules.webauthn.session_store import auth_session_store
from backend.oidc.service import (
    consume_authorization_code,
    create_authorization_transaction,
    generate_authorization_code,
    get_authorization_transaction,
    get_registered_client_redirect_uris,
    register_client,
    validate_client_redirect_uri,
)

router = APIRouter(prefix="/oidc", tags=["OIDC"])


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class RegisterClientRequest(BaseModel):
    client_id: str = Field(..., min_length=3, description="Unique client identifier")
    redirect_uris: List[str] = Field(..., min_length=1, description="Whitelisted redirect URIs")


class AuthorizeCompleteRequest(BaseModel):
    transaction_id: str = Field(..., description="ID of pending authorization transaction")
    session_token: str = Field(..., description="Authenticated session token")


class TokenExchangeRequest(BaseModel):
    grant_type: str = Field(..., description="Grant type, must be authorization_code")
    code: str = Field(..., description="Authorization code")
    redirect_uri: str = Field(..., description="Redirect URI matching authorization request")
    client_id: str = Field(..., description="Client identifier")
    code_verifier: str = Field(..., description="PKCE S256 code verifier")


# ---------------------------------------------------------------------------
# 1. OpenID Connect Discovery
# ---------------------------------------------------------------------------

@router.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request) -> Dict[str, Any]:
    """Return OpenID Connect provider configuration metadata."""
    base_url = str(request.base_url).rstrip("/")
    issuer = f"{base_url}/api/v1/oidc"
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/jwks.json",
        "registration_endpoint": f"{issuer}/clients",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    }


# ---------------------------------------------------------------------------
# 2. JSON Web Key Set (JWKS)
# ---------------------------------------------------------------------------

@router.get("/jwks.json")
async def jwks() -> Dict[str, Any]:
    """Return public keys in RFC 8037 JWK format for Ed25519 (EdDSA)."""
    public_pem = token_router.get_public_key()
    pub_obj = _load_public_key(public_pem)
    raw_public_bytes = pub_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x = base64.urlsafe_b64encode(raw_public_bytes).rstrip(b"=").decode("ascii")

    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x,
                "use": "sig",
                "alg": "EdDSA",
                "kid": "idp-mesh-token-key-1",
            }
        ]
    }


# ---------------------------------------------------------------------------
# 3. Client Registration Endpoints
# ---------------------------------------------------------------------------

@router.post("/clients", status_code=status.HTTP_201_CREATED)
async def register_oidc_client_endpoint(body: RegisterClientRequest) -> Dict[str, Any]:
    """Register an OIDC client with its allowed redirect URIs."""
    try:
        register_client(body.client_id, body.redirect_uris)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "client_id": body.client_id,
        "redirect_uris": body.redirect_uris,
        "message": "Client registered successfully.",
    }


@router.get("/clients/{client_id}")
async def get_oidc_client_endpoint(client_id: str) -> Dict[str, Any]:
    """Get registered redirect URIs for a client."""
    uris = get_registered_client_redirect_uris(client_id)
    if not uris:
        raise HTTPException(status_code=404, detail="Client not found.")
    return {
        "client_id": client_id,
        "redirect_uris": uris,
    }


# ---------------------------------------------------------------------------
# 4. Authorization Endpoint
# ---------------------------------------------------------------------------

@router.get("/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("openid"),
    state: Optional[str] = Query(None),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query("S256"),
    session_token: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None),
):
    """Handle OIDC authorization requests with PKCE.

    If an active session token is present, issues the authorization code
    immediately and redirects to redirect_uri.
    If no session exists, creates a pending transaction and redirects the user
    to the login page.
    """
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

    # RFC 7636: an S256 challenge is 43 characters for a base64url-encoded SHA-256 digest
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", code_challenge):
        raise HTTPException(status_code=400, detail="Invalid PKCE code_challenge")

    # Determine caller session token from query param or Authorization header
    token = session_token
    if not token and authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()

    did: Optional[str] = None
    if token:
        principal = auth_session_store.resolve(token)
        if principal:
            did = principal.did

    if did:
        # Authenticated session exists — generate authorization code and redirect
        code = generate_authorization_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            username=did,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        params = {"code": code}
        if state:
            params["state"] = state
        delimiter = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(
            url=f"{redirect_uri}{delimiter}{urlencode(params)}",
            status_code=status.HTTP_302_FOUND,
        )

    # Not yet authenticated: store authorization transaction and redirect to login
    tx_id = create_authorization_transaction(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state or "",
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    login_url = f"/shad/login.html?tx={tx_id}"
    return RedirectResponse(url=login_url, status_code=status.HTTP_302_FOUND)


# ---------------------------------------------------------------------------
# 5. Authorization Complete (Consent / Post-Login Hook)
# ---------------------------------------------------------------------------

@router.post("/authorize/complete")
async def authorize_complete(body: AuthorizeCompleteRequest) -> Dict[str, Any]:
    """Complete a pending authorization transaction after user login."""
    tx = get_authorization_transaction(body.transaction_id)
    if not tx:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired authorization transaction.",
        )

    principal = auth_session_store.resolve(body.session_token)
    if not principal:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication session.",
        )
    did = principal.did

    code = generate_authorization_code(
        client_id=tx["client_id"],
        redirect_uri=tx["redirect_uri"],
        username=did,
        scope=tx["scope"],
        code_challenge=tx["code_challenge"],
        code_challenge_method=tx["code_challenge_method"],
    )

    params = {"code": code}
    if tx["state"]:
        params["state"] = tx["state"]

    delimiter = "&" if "?" in tx["redirect_uri"] else "?"
    redirect_url = f"{tx['redirect_uri']}{delimiter}{urlencode(params)}"

    return {
        "redirect_uri": redirect_url,
        "code": code,
        "state": tx["state"],
    }


# ---------------------------------------------------------------------------
# 6. Token Exchange Endpoint
# ---------------------------------------------------------------------------

@router.post("/token")
async def token_exchange(request: Request) -> Dict[str, Any]:
    """Exchange an authorization code and PKCE verifier for OIDC tokens.

    Supports both application/x-www-form-urlencoded and application/json.
    """
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
    else:
        try:
            body_bytes = await request.body()
            raw_data = parse_qs(body_bytes.decode("utf-8"))
            data = {
                k: v[0] if isinstance(v, list) and len(v) > 0 else v
                for k, v in raw_data.items()
            }
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid form body")

    grant_type = str(data.get("grant_type", "")).strip()
    code = str(data.get("code", "")).strip()
    redirect_uri = str(data.get("redirect_uri", "")).strip()
    client_id = str(data.get("client_id", "")).strip()
    code_verifier = str(data.get("code_verifier", "")).strip()

    if grant_type != "authorization_code":
        raise HTTPException(
            status_code=400,
            detail="Unsupported grant_type; must be authorization_code",
        )

    if not all([code, redirect_uri, client_id, code_verifier]):
        raise HTTPException(
            status_code=400,
            detail="Missing required fields: code, redirect_uri, client_id, and code_verifier",
        )

    auth_record = consume_authorization_code(
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
    )

    if auth_record is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid, expired, or already-used authorization code, or PKCE verification failed",
        )

    did = auth_record["username"]
    scopes = auth_record["scope"].split()

    # Issue access token scoped to Resource Server API
    access_token, access_jti = issue_token(
        did=did,
        scope=scopes,
        private_key_pem=token_router.get_private_key(),
        audience=TOKEN_AUDIENCE,
        extra_claims={
            "client_id": client_id,
            "token_use": "access_token",
        },
    )

    # Issue OIDC ID token audience-targeted to the client
    id_token, _ = issue_token(
        did=did,
        scope=["openid"],
        private_key_pem=token_router.get_private_key(),
        audience=client_id,
        extra_claims={
            "sub": did,
            "aud": client_id,
            "preferred_username": did,
            "token_use": "id_token",
        },
    )

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
        "scope": auth_record["scope"],
    }


# ---------------------------------------------------------------------------
# 7. UserInfo Endpoint
# ---------------------------------------------------------------------------

@router.get("/userinfo")
async def userinfo(
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Return user claims for an authenticated Bearer access token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="A Bearer access token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:].strip()
    try:
        claims = verify_token(token, token_router.get_public_key(), audience=TOKEN_AUDIENCE)
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc

    jti = claims.get("jti", "")
    if token_router.get_revocation_store().is_revoked(jti):
        raise HTTPException(
            status_code=401,
            detail="Access token has been revoked",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )

    did = claims.get("sub", "")
    return {
        "sub": did,
        "did": did,
        "preferred_username": claims.get("preferred_username", did),
        "role": claims.get("role", "user"),
        "scope": claims.get("scope", ["openid"]),
    }
