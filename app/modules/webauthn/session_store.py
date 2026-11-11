"""Short-lived server-side sessions created only after a verified ceremony."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

SESSION_TTL_SECONDS = 300


@dataclass(frozen=True)
class VerifiedPrincipal:
    did: str


class AuthSessionStore:
    """Bearer session store with interchangeable process-local and Redis backends."""

    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._sessions: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._redis = None

    def use_redis(self, client) -> None:
        """Use a shared Redis client; existing local sessions are discarded."""
        with self._lock:
            self._sessions.clear()
            self._redis = client

    def use_memory(self) -> None:
        with self._lock:
            self._redis = None
            self._sessions.clear()

    def create(self, did: str) -> tuple[str, int]:
        token = secrets.token_urlsafe(32)
        if self._redis is not None:
            self._redis.setex(f"webauthn:auth-session:{token}", self._ttl, did)
            return token, self._ttl
        with self._lock:
            self._sessions[token] = (did, time.monotonic() + self._ttl)
        return token, self._ttl

    def resolve(self, token: str) -> VerifiedPrincipal | None:
        if self._redis is not None:
            did = self._redis.get(f"webauthn:auth-session:{token}")
            return VerifiedPrincipal(did=did) if did else None
        now = time.monotonic()
        with self._lock:
            entry = self._sessions.get(token)
            if entry is None:
                return None
            did, expires_at = entry
            if expires_at <= now:
                self._sessions.pop(token, None)
                return None
            return VerifiedPrincipal(did=did)

    def clear(self) -> None:
        if self._redis is not None:
            for key in self._redis.scan_iter(match="webauthn:auth-session:*"):
                self._redis.delete(key)
            return
        with self._lock:
            self._sessions.clear()


auth_session_store = AuthSessionStore()
