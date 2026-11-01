"""Test-only shared store double for admin authorization tests.

This models the durable Redis contract without requiring a Redis server. It is
never imported by application code and does not claim to provide persistence.
"""

import time

from app.modules.tokens.revocation import RevocationDurabilityAssessment


class DurableRevocationStoreStub:
    backend_type = "redis"
    is_durable = True

    def __init__(self) -> None:
        self._revoked_until: dict[str, float] = {}

    def require_durable(self) -> None:
        return None

    def assess_durability(self) -> RevocationDurabilityAssessment:
        return RevocationDurabilityAssessment(
            backend_type="redis",
            redis_available=True,
            persistence_status="verified",
            eviction_status="verified",
            durability_status="configuration_verified",
        )

    def revoke(self, jti: str, ttl_seconds: int = 3600) -> None:
        self._revoked_until[jti] = time.monotonic() + ttl_seconds

    def is_revoked(self, jti: str) -> bool:
        expires_at = self._revoked_until.get(jti)
        if expires_at is None:
            return False
        if expires_at <= time.monotonic():
            self._revoked_until.pop(jti, None)
            return False
        return True

    def clear_in_memory(self) -> None:
        self._revoked_until.clear()
