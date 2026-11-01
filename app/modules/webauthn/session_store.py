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
    """In-memory bearer session store for the educational single-process app."""

    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._sessions: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def create(self, did: str) -> tuple[str, int]:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[token] = (did, time.monotonic() + self._ttl)
        return token, self._ttl

    def resolve(self, token: str) -> VerifiedPrincipal | None:
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
        with self._lock:
            self._sessions.clear()


auth_session_store = AuthSessionStore()
