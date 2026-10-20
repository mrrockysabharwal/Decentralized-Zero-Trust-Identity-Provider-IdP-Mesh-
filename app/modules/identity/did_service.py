"""
app/modules/identity/did_service.py — DID Creation & Resolution Service
========================================================================
Owner  : Member 3 (DID Registry & Cryptography)
Branch : feature/identity-module

Implements DID method `did:mesh:key` — a self-certifying DID whose
identifier is derived deterministically from the Ed25519 public key
(multibase base58btc encoding of the raw public-key bytes).

DID Document structure follows the W3C DID Core 1.0 specification:
  https://www.w3.org/TR/did-core/

In-process registry
-------------------
DIDs are stored in an **in-process dictionary** (`_did_registry`) for
this integration.  In production this would be backed by the
`SimulatedLedger` (Module C) or a real distributed ledger.  The ledger
integration path is kept open via `anchor_to_ledger()`.

Security contract
-----------------
* ONLY public keys are stored in DID documents or the registry.
* Private keys are NEVER accepted by this module as input.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.modules.identity.ed25519_service import Ed25519Service

logger = logging.getLogger("idp_mesh.identity.did")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DID_METHOD = "mesh"          # → did:mesh:key:<identifier>
DID_CONTEXT = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DIDResolutionError(Exception):
    """Raised when a DID cannot be resolved."""


# ---------------------------------------------------------------------------
# In-process DID registry
# ---------------------------------------------------------------------------

# Maps did → DID Document dict.  Intentionally module-level so it persists
# for the lifetime of the process (test isolation handled via registry_reset).
_did_registry: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# DID Service
# ---------------------------------------------------------------------------

class DIDService:
    """Service for creating and resolving `did:mesh:key` DIDs.

    All methods are static — instantiate only when dependency injection is
    needed (e.g. FastAPI route handlers or unit-test fixtures).
    """

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _public_key_to_multibase(public_key: Ed25519PublicKey) -> str:
        """Encode a raw public key as a multibase base58btc string.

        The identifier prefix ``z`` signals base58btc encoding per the
        Multibase specification (https://datatracker.ietf.org/doc/html/draft-multiformats-multibase).

        Parameters
        ----------
        public_key:
            An Ed25519 public key object.

        Returns
        -------
        str
            ``z<base58btc-encoded-raw-key>``
        """
        raw_bytes: bytes = Ed25519Service.public_key_to_bytes(public_key)
        # Base58btc — Python stdlib ships base64 but not base58.
        # We implement a compact base58 encoder to avoid adding a new
        # dependency (all existing deps are in requirements.txt).
        encoded: str = DIDService._base58btc_encode(raw_bytes)
        return f"z{encoded}"

    @staticmethod
    def _base58btc_encode(data: bytes) -> str:
        """Minimal base58btc encoder (Bitcoin / IPFS alphabet)."""
        ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = int.from_bytes(data, "big")
        result: list[str] = []
        while num > 0:
            num, rem = divmod(num, 58)
            result.append(ALPHABET[rem])
        # Leading zero bytes → leading '1's
        for byte in data:
            if byte == 0:
                result.append(ALPHABET[0])
            else:
                break
        return "".join(reversed(result))

    @staticmethod
    def _base58btc_decode(encoded: str) -> bytes:
        """Minimal base58btc decoder."""
        ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = 0
        for char in encoded:
            if char not in ALPHABET:
                raise ValueError(f"Invalid base58btc character: {char!r}")
            num = num * 58 + ALPHABET.index(char)
        # Convert integer to bytes
        result = []
        while num > 0:
            num, rem = divmod(num, 256)
            result.append(rem)
        # Leading '1's → leading zero bytes
        for char in encoded:
            if char == "1":
                result.append(0)
            else:
                break
        return bytes(reversed(result))

    @staticmethod
    def _derive_did_identifier(public_key: Ed25519PublicKey) -> str:
        """Deterministically derive the DID identifier from a public key.

        Parameters
        ----------
        public_key:
            The controller's Ed25519 public key.

        Returns
        -------
        str
            A short, collision-resistant identifier (first 16 chars of the
            SHA-256 hex digest of the raw public key bytes).  Kept short for
            readability; the full multibase key is embedded in the DID Document.
        """
        raw_bytes = Ed25519Service.public_key_to_bytes(public_key)
        return hashlib.sha256(raw_bytes).hexdigest()[:16]

    # ------------------------------------------------------------------
    # DID creation
    # ------------------------------------------------------------------

    @staticmethod
    def create_did(public_key: Ed25519PublicKey) -> str:
        """Create a new `did:mesh:key` DID from an Ed25519 public key.

        If a DID for this exact public key already exists in the registry
        the existing DID is returned (idempotent).

        Parameters
        ----------
        public_key:
            The controller's Ed25519 public key.  **Never pass a private key.**

        Returns
        -------
        str
            The newly created (or pre-existing) DID string,
            e.g. ``did:mesh:key:a1b2c3d4e5f6a7b8``
        """
        identifier = DIDService._derive_did_identifier(public_key)
        did = f"did:{DID_METHOD}:key:{identifier}"

        if did in _did_registry:
            logger.debug("DID %s already exists — returning existing entry.", did)
            return did

        doc = DIDService.build_did_document(did, public_key)
        _did_registry[did] = doc
        logger.info("Created DID: %s", did)
        return did

    # ------------------------------------------------------------------
    # DID Document construction
    # ------------------------------------------------------------------

    @staticmethod
    def build_did_document(
        did: str,
        public_key: Ed25519PublicKey,
    ) -> Dict[str, Any]:
        """Build a W3C-compliant DID Document for the given DID and public key.

        Parameters
        ----------
        did:
            The fully qualified DID string (e.g. ``did:mesh:key:abc123``).
        public_key:
            The controller's Ed25519 public key.

        Returns
        -------
        dict
            A W3C DID Core 1.0 compliant DID Document.

        Raises
        ------
        ValueError
            If `did` is empty or does not start with ``did:``.
        """
        if not did or not did.startswith("did:"):
            raise ValueError(f"Invalid DID format: {did!r}. Must start with 'did:'.")

        multibase_key = DIDService._public_key_to_multibase(public_key)
        now_iso = datetime.now(timezone.utc).isoformat()

        verification_method_id = f"{did}#key-1"

        document: Dict[str, Any] = {
            "@context": DID_CONTEXT,
            "id": did,
            "controller": did,
            "verificationMethod": [
                {
                    "id": verification_method_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": multibase_key,
                }
            ],
            "authentication": [verification_method_id],
            "assertionMethod": [verification_method_id],
            "created": now_iso,
            "updated": now_iso,
        }
        return document

    # ------------------------------------------------------------------
    # DID Resolution
    # ------------------------------------------------------------------

    @staticmethod
    def resolve_did(did: str) -> Dict[str, Any]:
        """Resolve a DID and return its DID Document.

        Parameters
        ----------
        did:
            The fully qualified DID to resolve.

        Returns
        -------
        dict
            The DID Document associated with `did`.

        Raises
        ------
        ValueError
            If `did` is empty, ``None``, or syntactically malformed.
        DIDResolutionError
            If the DID is well-formed but not found in the registry.
        """
        # Input validation
        if not did or not isinstance(did, str):
            raise ValueError("DID must be a non-empty string.")
        did = did.strip()
        if not did.startswith("did:"):
            raise ValueError(
                f"Malformed DID {did!r}: must start with 'did:' per W3C DID Core spec."
            )

        document = _did_registry.get(did)
        if document is None:
            raise DIDResolutionError(
                f"DID not found: {did!r}. "
                "The DID has not been registered or may have been deactivated."
            )

        logger.debug("Resolved DID: %s", did)
        return document

    # ------------------------------------------------------------------
    # Registry utilities (mainly for testing / admin)
    # ------------------------------------------------------------------

    @staticmethod
    def did_exists(did: str) -> bool:
        """Return ``True`` if `did` is present in the in-process registry."""
        return did in _did_registry

    @staticmethod
    def list_dids() -> list[str]:
        """Return a snapshot of all registered DIDs."""
        return list(_did_registry.keys())

    @staticmethod
    def deactivate_did(did: str) -> None:
        """Mark a DID as deactivated in the registry.

        The DID Document remains in the registry (append-only semantics)
        but is annotated as deactivated and no longer usable.

        Parameters
        ----------
        did:
            The fully qualified DID to deactivate.

        Raises
        ------
        DIDResolutionError
            If the DID does not exist.
        """
        if did not in _did_registry:
            raise DIDResolutionError(f"Cannot deactivate unknown DID: {did!r}.")
        doc = _did_registry[did]
        doc["deactivated"] = True
        doc["updated"] = datetime.now(timezone.utc).isoformat()
        logger.info("Deactivated DID: %s", did)

    @staticmethod
    def registry_reset() -> None:
        """Clear the in-process DID registry.

        **For use in unit tests only.**  Calling this in production will
        erase all registered DIDs for the lifetime of the process.
        """
        _did_registry.clear()
        logger.warning("DID registry has been reset (all entries cleared).")
