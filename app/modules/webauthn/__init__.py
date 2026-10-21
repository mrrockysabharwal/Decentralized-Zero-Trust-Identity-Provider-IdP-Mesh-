"""
app/modules/webauthn/__init__.py — WebAuthn / FIDO2 Module Public API
======================================================================
Owner  : Member 2 (WebAuthn / FIDO2 Biometric Auth)
Branch : feature/webauthn-module

Exposes:
    webauthn_router    — FastAPI APIRouter; mount at /api/v1 in main.py
    WebAuthnService    — Core ceremony service (for direct Python integration)
    ChallengeStore     — In-memory nonce registry
    CredentialStore    — In-memory credential binding registry

Mount in app/main.py:
    from app.modules.webauthn import webauthn_router
    app.include_router(webauthn_router, prefix="/api/v1")
"""

from app.modules.webauthn.router import router as webauthn_router
from app.modules.webauthn.webauthn_service import WebAuthnService
from app.modules.webauthn.challenge_store import ChallengeStore
from app.modules.webauthn.credential_store import CredentialStore

__all__ = [
    "webauthn_router",
    "WebAuthnService",
    "ChallengeStore",
    "CredentialStore",
]
