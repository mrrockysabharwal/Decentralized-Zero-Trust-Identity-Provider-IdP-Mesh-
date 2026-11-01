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
import binascii
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status

from app.modules.did.router import (
    did_mutation_proof_message,
    issue_did_ownership_challenge,
    verify_did_ownership_proof,
)

from app.modules.webauthn.challenge_store import ChallengeStore
from app.modules.webauthn.credential_store import CredentialStore
from app.modules.webauthn.models import (
    AuthenticationBeginRequest,
    AuthenticationBeginResponse,
    AuthenticationCompleteRequest,
    AuthenticationCompleteResponse,
    CredentialInfo,
    CredentialListChallengeResponse,
    CredentialListResponse,
    RegistrationBeginRequest,
    RegistrationBeginResponse,
    RegistrationCompleteRequest,
    RegistrationCompleteResponse,
)
from app.modules.webauthn.webauthn_service import WebAuthnService

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
_DID_PROOF_TTL_SECONDS = 300
_REGISTER_OPERATION = "WEBAUTHN_REGISTER"
_LIST_OPERATION = "WEBAUTHN_CREDENTIAL_LIST"


def _canonical_public_key(encoded: str) -> str:
    try:
        raw = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=422, detail="Invalid credential public key encoding.") from exc
    if len(raw) != 32:
        raise HTTPException(status_code=422, detail="Credential public key must be 32 bytes.")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


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
        response = _get_service().begin_registration(
            did=payload.did,
            display_name=payload.display_name,
        )
        ownership_challenge = issue_did_ownership_challenge(
            payload.did,
            _REGISTER_OPERATION,
            {"registration_challenge": response.challenge},
        )
        response.ownership_challenge = ownership_challenge
        return response
    except HTTPException:
        raise
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
    public_key_b64 = _canonical_public_key(payload.public_key_b64)
    credential_id = payload.credential_id or CredentialStore.derive_credential_id(
        base64.urlsafe_b64decode(public_key_b64 + "=" * (-len(public_key_b64) % 4))
    )
    registration_changes = {
        "registration_challenge": payload.challenge,
        "public_key_b64": public_key_b64,
        "credential_id": credential_id,
        "device_info": payload.device_info,
    }
    verify_did_ownership_proof(
        did=payload.did,
        operation=_REGISTER_OPERATION,
        challenge_binding={"registration_challenge": payload.challenge},
        signed_changes=registration_changes,
        challenge=payload.ownership_challenge,
        signature_b64=payload.ownership_signature_b64,
    )

    try:
        return _get_service().complete_registration(
            did=payload.did,
            challenge_b64=payload.challenge,
            public_key_b64=public_key_b64,
            signature_b64=payload.signature_b64,
            credential_id=credential_id,
            device_info=payload.device_info,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    except Exception as exc:
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
        return _get_service().begin_authentication(did=payload.did)
    except ValueError as exc:
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
        return _get_service().complete_authentication(
            did=payload.did,
            challenge_b64=payload.challenge,
            credential_id=payload.credential_id,
            signature_b64=payload.signature_b64,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    except Exception as exc:
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
def list_credentials(
    did: str,
    ownership_challenge: Optional[str] = Query(default=None),
    ownership_signature_b64: Optional[str] = Query(default=None),
) -> CredentialListResponse:
    """Return all WebAuthn credentials registered for the specified DID.

    Returns **404 Not Found** if no credentials exist for the DID.
    """
    verify_did_ownership_proof(
        did=did,
        operation=_LIST_OPERATION,
        challenge_binding={"purpose": "credential-list"},
        signed_changes={"purpose": "credential-list"},
        challenge=ownership_challenge,
        signature_b64=ownership_signature_b64,
    )
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


@router.post(
    "/credentials/challenge/{did:path}",
    response_model=CredentialListChallengeResponse,
    summary="Issue a one-time DID ownership challenge for credential listing",
)
def credential_list_challenge(did: str) -> CredentialListChallengeResponse:
    challenge = issue_did_ownership_challenge(
        did, _LIST_OPERATION, {"purpose": "credential-list"}
    )
    return CredentialListChallengeResponse(
        did=did,
        challenge=challenge,
        expires_in_seconds=_DID_PROOF_TTL_SECONDS,
    )
