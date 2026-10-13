"""Redis-backed JTI deny-list for token revocation.

Architecture:
  - Primary store: Redis (key = "revoked_jti:<jti>", TTL = remaining token lifetime).
  - Fallback store: in-memory Python set (used automatically when Redis is
    unavailable — enables tests to run without a running Redis server).

Redis key format:   revoked_jti:<jti>
Redis value:        "1"  (presence is sufficient; no value semantics needed)
Redis TTL:          Caller provides remaining seconds so the deny-list entry
                    self-expires when the token would have been invalid anyway.
"""

import logging
from typing import Optional, Set

# Default TTL in seconds — matches the default token lifetime
DEFAULT_TTL: int = 3600

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# In-memory fallback (used when Redis is unavailable)
# ---------------------------------------------------------------------------


class _InMemoryRevocationStore:
    """Simple in-process set-based JTI deny-list (no TTL enforcement)."""

    def __init__(self) -> None:
        self._revoked: Set[str] = set()

    def revoke(self, jti: str, ttl_seconds: int = 0) -> None:  # noqa: ARG002
        self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked

    def clear(self) -> None:
        """Clear all revoked JTIs — intended for test teardown only."""
        self._revoked.clear()


# ---------------------------------------------------------------------------
# Redis-backed store
# ---------------------------------------------------------------------------

_REDIS_KEY_PREFIX = "revoked_jti:"


class _RedisRevocationStore:
    """Redis-backed JTI deny-list with automatic TTL expiry."""

    def __init__(self, redis_client) -> None:  # type: ignore[type-arg]
        self._redis = redis_client

    def revoke(self, jti: str, ttl_seconds: int = 3600) -> None:
        """Add *jti* to the deny-list with a TTL matching the token's remaining lifetime."""
        key = f"{_REDIS_KEY_PREFIX}{jti}"
        self._redis.setex(key, max(ttl_seconds, 1), "1")

    def is_revoked(self, jti: str) -> bool:
        """Return True if the JTI is present in the deny-list."""
        key = f"{_REDIS_KEY_PREFIX}{jti}"
        return bool(self._redis.exists(key))


# ---------------------------------------------------------------------------
# Public facade
# ---------------------------------------------------------------------------


class TokenRevocationStore:
    """Unified token revocation deny-list.

    Attempts to connect to Redis on construction.  If Redis is unavailable
    (ConnectionError / ImportError / misconfiguration), falls back silently to
    an in-memory store and logs a warning — this ensures tests and development
    environments work without a running Redis server.

    Usage::

        store = TokenRevocationStore()
        store.revoke(jti, ttl_seconds=3600)
        store.is_revoked(jti)  # → True
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0") -> None:
        self._redis_url = redis_url
        self._backend = self._connect(redis_url)

    def _connect(self, redis_url: str) -> "_InMemoryRevocationStore | _RedisRevocationStore":
        try:
            import redis  # type: ignore[import]

            client = redis.from_url(redis_url, socket_connect_timeout=1)
            client.ping()  # Fast connectivity check
            logger.info("TokenRevocationStore: connected to Redis at %s", redis_url)
            return _RedisRevocationStore(client)
        except Exception as exc:
            logger.warning(
                "TokenRevocationStore: Redis unavailable (%s) — falling back to in-memory store. "
                "Token revocations will NOT survive process restarts.",
                exc,
            )
            return _InMemoryRevocationStore()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def revoke(self, jti: str, ttl_seconds: int = DEFAULT_TTL) -> None:
        """Add *jti* to the deny-list.

        Args:
            jti: Unique JWT identifier to revoke.
            ttl_seconds: How long to retain the entry (should match the
                         token's remaining lifetime so it auto-expires).
        """
        self._backend.revoke(jti, ttl_seconds)

    def is_revoked(self, jti: str) -> bool:
        """Return True if the token identified by *jti* has been revoked."""
        return self._backend.is_revoked(jti)

    def clear_in_memory(self) -> None:
        """Clear all in-memory revocations — for test teardown only.

        Has no effect when the backend is Redis (entries expire via TTL).
        """
        if isinstance(self._backend, _InMemoryRevocationStore):
            self._backend.clear()

    @property
    def backend_type(self) -> str:
        """Return a human-readable identifier of the active backend."""
        if isinstance(self._backend, _RedisRevocationStore):
            return "redis"
        return "in-memory"
