"""
app/modules/webauthn/router.py — FastAPI Router for WebAuthn/FIDO2 Module
=========================================================================
Owner  : Member 2 (WebAuthn / FIDO2 Biometric Auth)
Branch : feature/webauthn-module

Endpoints (all mounted under /api/v1/webauthn by Member 1's main.py):

  POST   /webauthn/register/begin          — Issue a registration challenge
  POST   /webauthn/register/complete       — Verify registration & store credential
  POST   /webauthn/authenticate/begin      — Issue an authentication challenge
  POST   /webauthn/authenticate/complete   — Verify authentication response
  GET    /webauthn/credentials/{did}       — List credentials for a DID

Integration for Member 1 (mount in app/main.py):

    from app.modules.webauthn import webauthn_router
    app.include_router(webauthn_router, prefix="/api/v1")
"""

from __future__ import annotations

import base64
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status

from app.modules.webauthn.challenge_store import ChallengeStore
from app.modules.webauthn.credential_store import CredentialStore
from app.modules.webauthn.models import (
    AuthenticationBeginRequest,
    AuthenticationBeginResponse,
    AuthenticationCompleteRequest,
    AuthenticationCompleteResponse,
    CredentialInfo,
    CredentialListResponse,
    RegistrationBeginRequest,
    RegistrationBeginResponse,
    RegistrationCompleteRequest,
    RegistrationCompleteResponse,
)
from app.modules.webauthn.webauthn_service import WebAuthnService
from app.modules.webauthn.session_store import auth_session_store
from app.modules.audit.event_store import record_security_event

logger = logging.getLogger("idp_mesh.webauthn.router")

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/webauthn", tags=["WebAuthn / FIDO2 Passwordless Auth"])

# ---------------------------------------------------------------------------
# Singletons (shared across requests; injectable via module-level reassignment
# as done in tests and main.py's shared-ledger wiring)
# ---------------------------------------------------------------------------

_challenge_store = ChallengeStore()
_credential_store = CredentialStore()

# _shared_ledger is None by default; Member 1's main.py replaces this at
# startup with the same SimulatedLedger instance used by Module C/E.
_shared_ledger = None

_webauthn_service = WebAuthnService(
    challenge_store=_challenge_store,
    credential_store=_credential_store,
    ledger=_shared_ledger,
)


def _get_service() -> WebAuthnService:
    """Return the module-level WebAuthnService singleton."""
    return _webauthn_service


# ---------------------------------------------------------------------------
# Registration Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/register/begin",
    response_model=RegistrationBeginResponse,
    status_code=status.HTTP_200_OK,
    summary="Begin WebAuthn credential registration",
)
def register_begin(payload: RegistrationBeginRequest) -> RegistrationBeginResponse:
    """Generate a registration challenge for a DID.

    The client must sign the returned challenge with its Ed25519 private key
    and submit the result to ``POST /webauthn/register/complete``.

    Canonical message to sign:
    ``SHA256(challenge_bytes + did_utf8 + b"register")``
    """
    try:
        return _get_service().begin_registration(
            did=payload.did,
            display_name=payload.display_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/register/complete",
    response_model=RegistrationCompleteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Complete WebAuthn credential registration",
)
def register_complete(payload: RegistrationCompleteRequest) -> RegistrationCompleteResponse:
    """Verify the signed registration response and store the credential.

    On success:
    - The Ed25519 public key is bound to the DID.
    - A ``CREATE`` record is anchored on the SimulatedLedger.
    - The credential is immediately usable for authentication.

    Returns **400 Bad Request** if the challenge has expired, the signature is
    invalid, or the DID binding does not match.
    """
    try:
        result = _get_service().complete_registration(
            did=payload.did,
            challenge_b64=payload.challenge,
            public_key_b64=payload.public_key_b64,
            signature_b64=payload.signature_b64,
            credential_id=payload.credential_id,
            device_info=payload.device_info,
        )
        record_security_event(event_type="credential_registration", outcome="success",
                              severity="low", did=payload.did, reason="credential_registered")
        return result
    except ValueError as exc:
        record_security_event(event_type="credential_registration", outcome="failure",
                              severity="medium", did=payload.did, reason="registration_verification_failed")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        record_security_event(event_type="credential_registration", outcome="failure",
                              severity="high", did=payload.did, reason="registration_internal_error")
        logger.exception("Unexpected error during registration completion: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {exc}",
        )


# ---------------------------------------------------------------------------
# Authentication Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/authenticate/begin",
    response_model=AuthenticationBeginResponse,
    status_code=status.HTTP_200_OK,
    summary="Begin WebAuthn authentication",
)
def authenticate_begin(payload: AuthenticationBeginRequest) -> AuthenticationBeginResponse:
    """Generate an authentication challenge for a registered DID.

    The client must sign the returned challenge with its Ed25519 private key
    and submit the result to ``POST /webauthn/authenticate/complete``.

    Canonical message to sign:
    ``SHA256(challenge_bytes + did_utf8 + b"authenticate")``

    Returns **404 Not Found** if no credentials are registered for the DID.
    """
    try:
        result = _get_service().begin_authentication(did=payload.did)
        record_security_event(event_type="authentication_challenge", outcome="success",
                              severity="low", did=payload.did, reason="challenge_issued")
        return result
    except ValueError as exc:
        record_security_event(event_type="authentication_challenge", outcome="failure",
                              severity="medium", did=payload.did, reason="challenge_not_issued")
        # No credentials registered → meaningful 404
        if "No credentials registered" in str(exc):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/authenticate/complete",
    response_model=AuthenticationCompleteResponse,
    status_code=status.HTTP_200_OK,
    summary="Complete WebAuthn authentication",
)
def authenticate_complete(payload: AuthenticationCompleteRequest) -> AuthenticationCompleteResponse:
    """Verify the signed authentication response.

    On success:
    - The DID is authenticated.
    - ``sign_count`` is incremented (replay-attack protection).
    - The caller can now request a JWT via ``POST /api/v1/tokens/issue``.

    Returns **401 Unauthorized** if the signature is invalid, the challenge
    has expired, or the credential does not belong to the DID.
    """
    try:
        result = _get_service().complete_authentication(
            did=payload.did,
            challenge_b64=payload.challenge,
            credential_id=payload.credential_id,
            signature_b64=payload.signature_b64,
        )
        session_token, ttl = auth_session_store.create(result.did)
        record_security_event(event_type="authentication", outcome="success",
                              severity="low", did=result.did, reason="assertion_verified")
        return result.model_copy(update={"session_token": session_token, "session_expires_in": ttl})
    except ValueError as exc:
        record_security_event(event_type="authentication", outcome="failure",
                              severity="medium", did=payload.did, reason="assertion_verification_failed")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    except Exception as exc:
        record_security_event(event_type="authentication", outcome="failure",
                              severity="high", did=payload.did, reason="authentication_internal_error")
        logger.exception("Unexpected error during authentication completion: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication failed: {exc}",
        )


# ---------------------------------------------------------------------------
# Credential Info Endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/credentials/{did:path}",
    response_model=CredentialListResponse,
    summary="List registered credentials for a DID",
)
def list_credentials(did: str) -> CredentialListResponse:
    """Return all WebAuthn credentials registered for the specified DID.

    Returns **404 Not Found** if no credentials exist for the DID.
    """
    creds = _credential_store.list_credentials_for_did(did)
    if not creds:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No credentials found for DID '{did}'.",
        )

    credential_infos = [
        CredentialInfo(
            credential_id=c.credential_id,
            did=c.did,
            public_key_b64=base64.urlsafe_b64encode(c.public_key_bytes).rstrip(b"=").decode(),
            registered_at=c.registered_at,
            device_info=c.device_info,
            sign_count=c.sign_count,
        )
        for c in creds
    ]

    return CredentialListResponse(
        did=did,
        credentials=credential_infos,
        total=len(credential_infos),
    )
