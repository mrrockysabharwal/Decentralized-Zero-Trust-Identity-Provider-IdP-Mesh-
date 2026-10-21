"""
app/modules/webauthn/challenge_store.py — In-Memory Challenge/Nonce Registry
=============================================================================
Owner  : Member 2 (WebAuthn / FIDO2 Biometric Auth)
Branch : feature/webauthn-module

Stores server-generated challenges (nonces) issued during WebAuthn ceremonies.
Each challenge has a hard TTL to prevent replay attacks — expired challenges
are automatically rejected.

Thread-safety
-------------
All mutations are protected by a single ``threading.Lock`` so this store is
safe to use from concurrent FastAPI request handlers.

Security Properties
-------------------
* Each challenge is single-use: it is deleted the moment it is consumed
  (whether valid or expired), preventing replay.
* Challenge bytes are generated with ``secrets.token_bytes`` (CSPRNG).
* TTL defaults to 300 seconds (5 minutes) — a practical window for a human
  to complete a WebAuthn ceremony.
"""

from __future__ import annotations

import base64
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

# Default challenge lifetime in seconds
DEFAULT_CHALLENGE_TTL: int = 300  # 5 minutes
CHALLENGE_BYTES: int = 32         # 256 bits of entropy


@dataclass
class _ChallengeEntry:
    """Internal storage record for an outstanding challenge."""
    challenge_bytes: bytes
    did: str
    ceremony: str          # "register" | "authenticate"
    issued_at: float = field(default_factory=time.monotonic)
    ttl_seconds: int = DEFAULT_CHALLENGE_TTL

    @property
    def is_expired(self) -> bool:
        return (time.monotonic() - self.issued_at) > self.ttl_seconds


class ChallengeStore:
    """Thread-safe, TTL-aware in-memory store for WebAuthn challenge nonces.

    Challenges are keyed by their base64url representation so they can be
    round-tripped through JSON without encoding loss.
    """

    def __init__(self, ttl_seconds: int = DEFAULT_CHALLENGE_TTL) -> None:
        self._ttl = ttl_seconds
        self._store: Dict[str, _ChallengeEntry] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_challenge(self, did: str, ceremony: str) -> tuple[bytes, str]:
        """Generate a fresh challenge for the given DID and ceremony type.

        Parameters
        ----------
        did:
            The DID the challenge is bound to.
        ceremony:
            ``"register"`` or ``"authenticate"``.

        Returns
        -------
        (challenge_bytes, challenge_b64url)
            Raw bytes for signature verification; base64url string for JSON.
        """
        challenge_bytes = secrets.token_bytes(CHALLENGE_BYTES)
        challenge_b64 = base64.urlsafe_b64encode(challenge_bytes).rstrip(b"=").decode()

        with self._lock:
            self._purge_expired_unlocked()
            self._store[challenge_b64] = _ChallengeEntry(
                challenge_bytes=challenge_bytes,
                did=did,
                ceremony=ceremony,
                ttl_seconds=self._ttl,
            )

        return challenge_bytes, challenge_b64

    def consume_challenge(
        self,
        challenge_b64: str,
        did: str,
        ceremony: str,
    ) -> bytes:
        """Retrieve and immediately delete a challenge, enforcing TTL and binding.

        Parameters
        ----------
        challenge_b64:
            The base64url challenge string to look up.
        did:
            Must match the DID the challenge was issued for.
        ceremony:
            Must match ``"register"`` or ``"authenticate"``.

        Returns
        -------
        bytes
            The raw challenge bytes (for signature verification).

        Raises
        ------
        ValueError
            If the challenge does not exist, has expired, or the
            did/ceremony binding does not match.
        """
        with self._lock:
            entry = self._store.pop(challenge_b64, None)

        if entry is None:
            raise ValueError(
                "Challenge not found or already consumed. "
                "Request a new challenge and retry."
            )

        if entry.is_expired:
            raise ValueError(
                f"Challenge expired after {entry.ttl_seconds}s. "
                "Request a new challenge and retry."
            )

        if entry.did != did:
            raise ValueError(
                f"Challenge was issued for DID '{entry.did}', "
                f"but the request claims DID '{did}'."
            )

        if entry.ceremony != ceremony:
            raise ValueError(
                f"Challenge ceremony mismatch: expected '{entry.ceremony}', "
                f"got '{ceremony}'."
            )

        return entry.challenge_bytes

    def has_challenge(self, challenge_b64: str) -> bool:
        """Return True if the challenge exists and has not expired (non-consuming peek)."""
        with self._lock:
            entry = self._store.get(challenge_b64)
            return entry is not None and not entry.is_expired

    def clear(self) -> None:
        """Remove all challenges. Intended for testing only."""
        with self._lock:
            self._store.clear()

    def pending_count(self) -> int:
        """Return the number of non-expired outstanding challenges."""
        with self._lock:
            return sum(1 for e in self._store.values() if not e.is_expired)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _purge_expired_unlocked(self) -> None:
        """Remove all expired entries. Must be called while holding self._lock."""
        expired_keys = [k for k, e in self._store.items() if e.is_expired]
        for k in expired_keys:
            del self._store[k]
