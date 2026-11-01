"""
app/modules/did/__init__.py — DID Registry & Cryptography Module (Module A)
============================================================================
Owner  : Member 3 (DID Registry & Cryptography)
Module : A — DID Registry HTTP API
Branch : feature/identity-module

Public exports for Member 1 (Core Backend) to wire into app/main.py:

    from app.modules.did import did_router
    app.include_router(did_router, prefix="/api/v1")

Also re-exports the underlying services for use by other modules:

    from app.modules.did import DIDService, Ed25519Service, DIDResolutionError
"""

from app.modules.did.router import router as did_router
from app.modules.identity.did_service import DIDService, DIDResolutionError
from app.modules.identity.ed25519_service import Ed25519Service

__all__ = [
    "did_router",
    "DIDService",
    "Ed25519Service",
    "DIDResolutionError",
]
