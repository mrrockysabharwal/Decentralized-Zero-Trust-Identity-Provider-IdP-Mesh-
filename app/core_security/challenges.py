"""Process-local, single-use challenges bound to an operation and request."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable


class ChallengeError(ValueError):
    """A challenge is missing, expired, replayed, or bound to other data."""


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON-compatible values to deterministic UTF-8 bytes."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Challenge data must be finite JSON-compatible values.") from exc


@dataclass(frozen=True)
class _Challenge:
    subject: str
    operation: str
    request_digest: bytes
    issued_at: float


class ChallengeService:
    """Issue five-minute challenges that can be consumed only once.

    The service is deliberately independent of any HTTP or identity framework.
    Challenges are process-local and therefore require a shared atomic store in
    a multi-process deployment.
    """

    def __init__(
        self,
        ttl_seconds: int = 300,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("Challenge TTL must be positive.")
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._pending: dict[str, _Challenge] = {}
        self._lock = threading.Lock()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    @staticmethod
    def _request_digest(request: Any) -> bytes:
        return hashlib.sha256(canonical_json_bytes(request)).digest()

    def issue(self, subject: str, operation: str, request: Any) -> str:
        if not subject or not operation:
            raise ValueError("Challenge subject and operation are required.")
        request_digest = self._request_digest(request)
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        entry = _Challenge(subject, operation, request_digest, self._clock())
        with self._lock:
            now = self._clock()
            expired = [
                key for key, pending in self._pending.items()
                if now - pending.issued_at >= self._ttl_seconds
            ]
            for key in expired:
                del self._pending[key]
            self._pending[challenge] = entry
        return challenge

    def consume(self, challenge: str, subject: str, operation: str, request: Any) -> None:
        """Consume a challenge, enforcing expiry and exact request binding.

        Consumption occurs before validation, so even a malformed or
        mismatched attempt cannot replay the same challenge.
        """
        with self._lock:
            entry = self._pending.pop(challenge, None)
        if entry is None:
            raise ChallengeError("Challenge not found or already consumed.")
        if self._clock() - entry.issued_at >= self._ttl_seconds:
            raise ChallengeError("Challenge has expired.")
        if entry.subject != subject:
            raise ChallengeError("Challenge subject does not match.")
        if entry.operation != operation:
            raise ChallengeError("Challenge operation does not match.")
        if not secrets.compare_digest(entry.request_digest, self._request_digest(request)):
            raise ChallengeError("Challenge request binding does not match.")

