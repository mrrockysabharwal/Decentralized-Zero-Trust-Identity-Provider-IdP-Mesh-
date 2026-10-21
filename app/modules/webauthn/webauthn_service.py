"""
app/modules/webauthn/webauthn_service.py — Core WebAuthn Ceremony Service
=========================================================================
Owner  : Member 2 (WebAuthn / FIDO2 Biometric Auth)
Branch : feature/webauthn-module

Implements the server-side logic for both WebAuthn ceremonies:

1. Registration Ceremony
   - ``begin_registration``   → generates and issues a challenge
   - ``complete_registration`` → verifies the signed challenge, stores the
                                 credential, and anchors a CREATE record on
                                 the SimulatedLedger (Module C integration)

2. Authentication Ceremony
   - ``begin_authentication``   → generates and issues a challenge
   - ``complete_authentication`` → verifies the signed challenge against the
                                   stored public key; increments sign_count

Cryptographic Simulation
------------------------
Real WebAuthn uses a browser ``AuthenticatorAssertionResponse`` with CBOR-
encoded authenticatorData and clientDataJSON. In this educational, single-node
simulation we use a simplified but cryptographically sound substitute:

    signature = Ed25519Sign(
        private_key,
        SHA256(challenge_bytes + did_utf8 + ceremony_tag)
    )

where ``ceremony_tag`` is ``b"register"`` or ``b"authenticate"``.

The server reconstructs the same pre-image from the stored challenge and
verifies using the submitted / stored Ed25519 public key.

Integration Points
------------------
* ChallengeStore  — issues and consumes single-use nonces
* CredentialStore — persists public key ↔ DID bindings
* SimulatedLedger — anchors DID CREATE events on registration completion
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.modules.webauthn.challenge_store import ChallengeStore
from app.modules.webauthn.credential_store import CredentialStore, StoredCredential
from app.modules.webauthn.models import (
    AuthenticationBeginResponse,
    AuthenticationCompleteResponse,
    RegistrationBeginResponse,
    RegistrationCompleteResponse,
)

logger = logging.getLogger("idp_mesh.webauthn.service")

# Relying Party constants
RP_ID = "idp-mesh-v1"
RP_NAME = "Decentralized Zero-Trust IdP Mesh"
CHALLENGE_TTL_SECONDS = 300  # 5 minutes


class WebAuthnService:
    """Server-side implementation of the simulated WebAuthn/FIDO2 ceremonies.

    Parameters
    ----------
    challenge_store:
        The ``ChallengeStore`` instance to issue and consume nonces.
    credential_store:
        The ``CredentialStore`` instance to persist credential bindings.
    ledger:
        Optional ``SimulatedLedger`` instance. When provided, a CREATE
        record is anchored for each successful registration.
    """

    def __init__(
        self,
        challenge_store: ChallengeStore,
        credential_store: CredentialStore,
        ledger=None,  # SimulatedLedger — typed as Any to avoid circular imports
    ) -> None:
        self._challenges = challenge_store
        self._credentials = credential_store
        self._ledger = ledger

    # ------------------------------------------------------------------
    # Registration ceremony
    # ------------------------------------------------------------------

    def begin_registration(self, did: str, display_name: Optional[str] = None) -> RegistrationBeginResponse:
        """Issue a registration challenge for the given DID.

        Parameters
        ----------
        did:
            The DID that will own the new credential.
        display_name:
            Optional human-readable name (included in Swagger responses).

        Returns
        -------
        RegistrationBeginResponse
            Contains the base64url challenge and RP metadata.
        """
        _validate_did(did)
        _, challenge_b64 = self._challenges.create_challenge(did=did, ceremony="register")

        logger.info("Registration challenge issued for DID=%s", did)
        return RegistrationBeginResponse(
            challenge=challenge_b64,
            did=did,
            rp_id=RP_ID,
            rp_name=RP_NAME,
            expires_in_seconds=CHALLENGE_TTL_SECONDS,
        )

    def complete_registration(
        self,
        did: str,
        challenge_b64: str,
        public_key_b64: str,
        signature_b64: str,
        credential_id: Optional[str] = None,
        device_info: Optional[dict] = None,
    ) -> RegistrationCompleteResponse:
        """Verify a registration response and persist the credential.

        Verification steps
        ------------------
        1. Consume the challenge (checks TTL, DID binding, ceremony type).
        2. Decode the submitted public key (base64url → 32-byte raw Ed25519).
        3. Reconstruct the canonical pre-image: ``SHA256(challenge_bytes + did_bytes + b"register")``.
        4. Verify the Ed25519 signature.
        5. Store the credential in ``CredentialStore``.
        6. Anchor a ``CREATE`` event on the ``SimulatedLedger`` (if wired).

        Raises
        ------
        ValueError
            On any verification failure (challenge expired, bad signature, etc.).
        """
        _validate_did(did)

        # Step 1 — Consume challenge
        challenge_bytes = self._challenges.consume_challenge(
            challenge_b64=challenge_b64,
            did=did,
            ceremony="register",
        )

        # Step 2 — Decode public key
        public_key_bytes = _decode_b64url(public_key_b64, label="public_key_b64")
        if len(public_key_bytes) != 32:
            raise ValueError(
                f"Ed25519 public key must be 32 bytes, got {len(public_key_bytes)}."
            )

        # Step 3 — Build canonical pre-image
        pre_image = _build_pre_image(challenge_bytes, did, "register")

        # Step 4 — Verify signature
        signature_bytes = _decode_b64url(signature_b64, label="signature_b64")
        _verify_ed25519(public_key_bytes, pre_image, signature_bytes)

        # Step 5 — Store credential
        cred = self._credentials.register(
            did=did,
            public_key_bytes=public_key_bytes,
            credential_id=credential_id,
            device_info=device_info,
        )
        logger.info(
            "Credential registered: credential_id=%s  DID=%s",
            cred.credential_id,
            did,
        )

        # Step 6 — Anchor on ledger (optional integration)
        ledger_index: Optional[int] = None
        if self._ledger is not None:
            try:
                from app.modules.ledger import hash_did_document, LedgerOperation
                # Build a minimal DID document hash for anchoring
                doc = {
                    "id": did,
                    "credential_id": cred.credential_id,
                    "registered_at": cred.registered_at,
                }
                doc_hash = hash_did_document(doc)
                record = self._ledger.append_record(
                    did=did,
                    doc_hash=doc_hash,
                    operation=LedgerOperation.CREATE,
                    metadata={
                        "source": "webauthn_registration",
                        "credential_id": cred.credential_id,
                    },
                )
                ledger_index = record.index
                logger.info(
                    "Ledger CREATE anchored at block #%d for DID=%s", ledger_index, did
                )
            except Exception as exc:
                # Ledger anchoring failure is non-fatal in simulation mode
                logger.warning("Ledger anchor failed (non-fatal): %s", exc)

        return RegistrationCompleteResponse(
            success=True,
            credential_id=cred.credential_id,
            did=did,
            ledger_record_index=ledger_index,
            message=(
                f"Credential '{cred.credential_id}' successfully registered and "
                f"bound to DID '{did}'."
            ),
        )

    # ------------------------------------------------------------------
    # Authentication ceremony
    # ------------------------------------------------------------------

    def begin_authentication(self, did: str) -> AuthenticationBeginResponse:
        """Issue an authentication challenge for the given DID.

        Parameters
        ----------
        did:
            The DID attempting to authenticate.

        Returns
        -------
        AuthenticationBeginResponse
            Contains the base64url challenge and list of allowed credential IDs.

        Raises
        ------
        ValueError
            If no credentials are registered for the DID.
        """
        _validate_did(did)

        creds = self._credentials.list_credentials_for_did(did)
        if not creds:
            raise ValueError(
                f"No credentials registered for DID '{did}'. "
                "Complete the registration ceremony first."
            )

        _, challenge_b64 = self._challenges.create_challenge(did=did, ceremony="authenticate")

        logger.info("Authentication challenge issued for DID=%s", did)
        return AuthenticationBeginResponse(
            challenge=challenge_b64,
            did=did,
            credential_ids=[c.credential_id for c in creds],
            expires_in_seconds=CHALLENGE_TTL_SECONDS,
        )

    def complete_authentication(
        self,
        did: str,
        challenge_b64: str,
        credential_id: str,
        signature_b64: str,
    ) -> AuthenticationCompleteResponse:
        """Verify an authentication response.

        Verification steps
        ------------------
        1. Consume the challenge (checks TTL, DID binding, ceremony type).
        2. Retrieve the stored credential and extract the public key.
        3. Reconstruct the canonical pre-image: ``SHA256(challenge_bytes + did_bytes + b"authenticate")``.
        4. Verify the Ed25519 signature.
        5. Increment sign_count (anti-replay counter).

        Raises
        ------
        ValueError
            On any verification failure.
        """
        _validate_did(did)

        # Step 1 — Consume challenge
        challenge_bytes = self._challenges.consume_challenge(
            challenge_b64=challenge_b64,
            did=did,
            ceremony="authenticate",
        )

        # Step 2 — Retrieve stored credential
        cred: Optional[StoredCredential] = self._credentials.get_credential(credential_id)
        if cred is None:
            raise ValueError(
                f"Credential '{credential_id}' is not registered. "
                "Run the registration ceremony first."
            )
        if cred.did != did:
            raise ValueError(
                f"Credential '{credential_id}' belongs to DID '{cred.did}', "
                f"not the requesting DID '{did}'."
            )

        # Step 3 — Build canonical pre-image
        pre_image = _build_pre_image(challenge_bytes, did, "authenticate")

        # Step 4 — Verify signature against stored public key
        signature_bytes = _decode_b64url(signature_b64, label="signature_b64")
        _verify_ed25519(cred.public_key_bytes, pre_image, signature_bytes)

        # Step 5 — Increment sign_count
        new_count = self._credentials.increment_sign_count(credential_id)
        logger.info(
            "Authentication successful: credential_id=%s  DID=%s  sign_count=%d",
            credential_id,
            did,
            new_count,
        )

        return AuthenticationCompleteResponse(
            success=True,
            did=did,
            credential_id=credential_id,
            message=f"DID '{did}' authenticated successfully (sign_count={new_count}).",
        )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _validate_did(did: str) -> None:
    """Raise ValueError for empty or malformed DID strings."""
    if not did or not isinstance(did, str) or not did.startswith("did:"):
        raise ValueError(
            f"Invalid DID '{did}': must be a non-empty string starting with 'did:'."
        )


def _decode_b64url(value: str, label: str = "value") -> bytes:
    """Decode a base64url string (with or without padding) to bytes."""
    # Restore padding
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise ValueError(f"Failed to base64url-decode {label!r}: {exc}") from exc


def _build_pre_image(challenge_bytes: bytes, did: str, ceremony: str) -> bytes:
    """Build the canonical SHA-256 pre-image for signature verification.

    Pre-image = SHA256(challenge_bytes || did_utf8_bytes || ceremony_tag_bytes)
    """
    ceremony_tag = ceremony.encode()
    digest = hashlib.sha256(challenge_bytes + did.encode() + ceremony_tag).digest()
    return digest


def _verify_ed25519(public_key_bytes: bytes, message: bytes, signature: bytes) -> None:
    """Verify an Ed25519 signature. Raises ValueError on failure.

    Parameters
    ----------
    public_key_bytes:
        Raw 32-byte Ed25519 public key.
    message:
        The message (pre-image) bytes to verify against.
    signature:
        The 64-byte Ed25519 signature to check.

    Raises
    ------
    ValueError
        If the signature is invalid (wrong key, tampered message, etc.).
    ValueError
        If signature length is not exactly 64 bytes.
    """
    if len(signature) != 64:
        raise ValueError(
            f"Ed25519 signature must be 64 bytes, got {len(signature)}."
        )
    try:
        pub_key: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key.verify(signature, message)
    except InvalidSignature:
        raise ValueError(
            "Signature verification failed: the signature is invalid. "
            "The authenticator private key may not match the registered public key, "
            "or the challenge/ceremony data was tampered with."
        )
    except Exception as exc:
        raise ValueError(f"Signature verification error: {exc}") from exc
