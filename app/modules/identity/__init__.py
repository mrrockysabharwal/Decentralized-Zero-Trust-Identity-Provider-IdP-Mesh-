"""
app/modules/identity/__init__.py — Ed25519 & DID Identity Module
=================================================================
Owner  : Member 3 (DID Registry & Cryptography)
Branch : feature/identity-module

Exposes:
    Ed25519Service  — key generation, signing, verification
    DIDService      — DID creation, resolution, and document management

Security note: Private keys are NEVER stored on the ledger or in any
shared state.  They are returned to the caller once at key-generation
time and are the caller's responsibility to safeguard.
"""

from app.modules.identity.ed25519_service import Ed25519Service
from app.modules.identity.did_service import DIDService, DIDResolutionError

__all__ = [
    "Ed25519Service",
    "DIDService",
    "DIDResolutionError",
]
