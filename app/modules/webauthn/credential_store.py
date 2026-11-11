"""
app/modules/webauthn/credential_store.py — In-Memory Credential Registry
=========================================================================
Owner  : Member 2 (WebAuthn / FIDO2 Biometric Auth)
Branch : feature/webauthn-module

Stores registered WebAuthn credentials, binding:
  credential_id  →  (public_key_bytes, did, sign_count, metadata)

In production this would be a persistent database table. For this
educational implementation we use an in-process dictionary that survives
for the lifetime of the FastAPI process.

Security Properties
-------------------
* Only the public key is ever stored — the private key never leaves the client.
* ``sign_count`` is tracked and incremented on every successful authentication;
  a stale or replayed assertion (lower count) is rejected.
* All mutations are protected by a ``threading.RLock``.
"""

from __future__ import annotations

import base64
import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass
class StoredCredential:
    """Internal record for a registered WebAuthn credential."""

    credential_id: str
    did: str
    public_key_bytes: bytes      # Public key bytes; encoding depends on device_info/source
    registered_at: str           # ISO 8601 UTC
    device_info: Optional[dict] = None
    sign_count: int = 0          # Monotonically increasing auth counter


class CredentialStore:
    """Thread-safe in-memory registry of registered WebAuthn credentials.

    Credential IDs are derived deterministically from the SHA-256 of the
    raw public key bytes, ensuring a stable identifier even if the client
    does not supply one.
    """

    def __init__(self) -> None:
        # Primary index: credential_id → StoredCredential
        self._credentials: Dict[str, StoredCredential] = {}
        # Secondary index: did → list[credential_id] for fast DID lookups
        self._did_index: Dict[str, List[str]] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Credential ID derivation
    # ------------------------------------------------------------------

    @staticmethod
    def derive_credential_id(public_key_bytes: bytes) -> str:
        """Derive a stable credential_id from a public key (first 24 hex chars of SHA-256)."""
        return "cred-" + hashlib.sha256(public_key_bytes).hexdigest()[:24]

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        did: str,
        public_key_bytes: bytes,
        credential_id: Optional[str] = None,
        device_info: Optional[dict] = None,
        sign_count: int = 0,
    ) -> StoredCredential:
        """Store a new credential binding a public key to a DID.

        Parameters
        ----------
        did:
            The DID to bind this credential to.
        public_key_bytes:
            Public key bytes. Core simulated credentials use raw Ed25519 keys;
            native passkeys may use their WebAuthn/COSE encoding.
        credential_id:
            Optional explicit ID. Derived from the public key if not supplied.
        device_info:
            Optional authenticator device metadata.

        Returns
        -------
        StoredCredential
            The newly created credential record.

        Raises
        ------
        ValueError
            If a credential with this ID is already registered.
        """
        cred_id = credential_id or self.derive_credential_id(public_key_bytes)
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._lock:
            if cred_id in self._credentials:
                raise ValueError(
                    f"Credential '{cred_id}' is already registered. "
                    "Use a new key pair for each credential."
                )

            cred = StoredCredential(
                credential_id=cred_id,
                did=did,
                public_key_bytes=public_key_bytes,
                registered_at=now_iso,
                device_info=device_info,
                sign_count=sign_count,
            )
            self._credentials[cred_id] = cred
            self._did_index.setdefault(did, []).append(cred_id)

        return cred

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get_credential(self, credential_id: str) -> Optional[StoredCredential]:
        """Return the credential for the given ID, or None if not found."""
        with self._lock:
            return self._credentials.get(credential_id)

    def list_credentials_for_did(self, did: str) -> List[StoredCredential]:
        """Return all credentials registered for a DID (may be empty list)."""
        with self._lock:
            ids = self._did_index.get(did, [])
            return [self._credentials[i] for i in ids if i in self._credentials]

    def credential_exists(self, credential_id: str) -> bool:
        """Return True if the credential_id is registered."""
        with self._lock:
            return credential_id in self._credentials

    def has_credentials_for_did(self, did: str) -> bool:
        """Return True if the DID has at least one registered credential."""
        with self._lock:
            return bool(self._did_index.get(did))

    # ------------------------------------------------------------------
    # Authentication (sign count update)
    # ------------------------------------------------------------------

    def increment_sign_count(self, credential_id: str) -> int:
        """Atomically increment sign_count and return the new value.

        Raises
        ------
        KeyError
            If credential_id is not registered.
        """
        with self._lock:
            cred = self._credentials.get(credential_id)
            if cred is None:
                raise KeyError(f"Credential '{credential_id}' not found.")
            cred.sign_count += 1
            return cred.sign_count

    # ------------------------------------------------------------------
    # Admin / test utilities
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Remove all credentials. For testing only."""
        with self._lock:
            self._credentials.clear()
            self._did_index.clear()

    def total_count(self) -> int:
        """Return the total number of registered credentials."""
        with self._lock:
            return len(self._credentials)

    def credential_id_to_public_key_b64(self, credential_id: str) -> Optional[str]:
        """Return the base64url-encoded public key for a credential_id, or None."""
        with self._lock:
            cred = self._credentials.get(credential_id)
            if cred is None:
                return None
            return base64.urlsafe_b64encode(cred.public_key_bytes).rstrip(b"=").decode()
