"""
app/modules/identity/ed25519_service.py — Ed25519 Cryptographic Service
========================================================================
Owner  : Member 3 (DID Registry & Cryptography)
Branch : feature/identity-module

Provides a stateless service class for Ed25519 key-pair generation,
message signing, and signature verification using the `cryptography`
library (pyca/cryptography ≥ 43.0.0), which is already listed in
requirements.txt.

Security contract
-----------------
* Private keys are NEVER serialised to disk by this module.
* Callers receive the raw private key object only at generation time
  and must protect it themselves.
* The ledger ONLY ever receives / stores the public key or its
  multibase-encoded form — never the private key.
"""

from __future__ import annotations

import logging
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("idp_mesh.identity.ed25519")


class Ed25519Service:
    """Stateless helper for Ed25519 key operations.

    All methods are static so the class can be used as a namespace
    without instantiation, but also supports instantiation for dependency
    injection in tests or FastAPI routes.
    """

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_key_pair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        """Generate a fresh Ed25519 key pair.

        Returns
        -------
        (private_key, public_key)
            Both are live `cryptography` key objects.
            **The private key must NEVER be stored on the ledger.**

        Example
        -------
        >>> priv, pub = Ed25519Service.generate_key_pair()
        """
        private_key: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        public_key: Ed25519PublicKey = private_key.public_key()
        logger.debug("Generated new Ed25519 key pair.")
        return private_key, public_key

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def public_key_to_bytes(public_key: Ed25519PublicKey) -> bytes:
        """Return the raw 32-byte DER-free public key bytes."""
        return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    @staticmethod
    def private_key_to_bytes(private_key: Ed25519PrivateKey) -> bytes:
        """Return the raw 32-byte private key seed bytes.

        Warning
        -------
        Handle the output with care — treat it as a secret.
        Never log or transmit these bytes over the network.
        """
        return private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    @staticmethod
    def public_key_from_bytes(raw_bytes: bytes) -> Ed25519PublicKey:
        """Reconstruct a public key from raw 32-byte representation.

        Parameters
        ----------
        raw_bytes:
            The 32-byte raw public key (as returned by `public_key_to_bytes`).

        Raises
        ------
        ValueError
            If `raw_bytes` is not exactly 32 bytes.
        """
        if len(raw_bytes) != 32:
            raise ValueError(
                f"Ed25519 public key must be exactly 32 bytes, got {len(raw_bytes)}."
            )
        return Ed25519PublicKey.from_public_bytes(raw_bytes)

    @staticmethod
    def private_key_from_bytes(raw_bytes: bytes) -> Ed25519PrivateKey:
        """Reconstruct a private key from its raw 32-byte seed.

        Parameters
        ----------
        raw_bytes:
            The 32-byte raw private key seed.

        Raises
        ------
        ValueError
            If `raw_bytes` is not exactly 32 bytes.
        """
        if len(raw_bytes) != 32:
            raise ValueError(
                f"Ed25519 private key must be exactly 32 bytes, got {len(raw_bytes)}."
            )
        return Ed25519PrivateKey.from_private_bytes(raw_bytes)

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    @staticmethod
    def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
        """Sign `message` with `private_key` and return the 64-byte signature.

        Parameters
        ----------
        private_key:
            The signer's Ed25519 private key.
        message:
            Arbitrary bytes to sign.  If you have a string, encode it
            first: ``message.encode()``

        Returns
        -------
        bytes
            64-byte Ed25519 signature.

        Raises
        ------
        TypeError
            If `message` is not ``bytes``.
        """
        if not isinstance(message, bytes):
            raise TypeError(
                f"message must be bytes, got {type(message).__name__!r}."
            )
        signature = private_key.sign(message)
        logger.debug("Signed %d-byte message; signature length=%d.", len(message), len(signature))
        return signature

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    @staticmethod
    def verify(
        public_key: Ed25519PublicKey,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """Verify `signature` against `message` using `public_key`.

        Parameters
        ----------
        public_key:
            The alleged signer's Ed25519 public key.
        message:
            The original message bytes.
        signature:
            The 64-byte signature to verify.

        Returns
        -------
        bool
            ``True`` if the signature is valid, ``False`` otherwise.
            This method never raises on an invalid signature — it
            always returns a boolean so callers can branch cleanly.

        Raises
        ------
        TypeError
            If `message` or `signature` are not ``bytes``.
        """
        if not isinstance(message, bytes):
            raise TypeError(
                f"message must be bytes, got {type(message).__name__!r}."
            )
        if not isinstance(signature, bytes):
            raise TypeError(
                f"signature must be bytes, got {type(signature).__name__!r}."
            )
        try:
            public_key.verify(signature, message)
            logger.debug("Signature verified successfully.")
            return True
        except InvalidSignature:
            logger.debug("Signature verification FAILED — signature is invalid.")
            return False
