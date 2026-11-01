"""Redis-backed JTI deny-list with explicit ephemeral development fallback.

Redis can share revocations across application instances, but process-restart
durability depends on its persistence and eviction configuration. Administrator
authentication verifies those settings before accepting a Redis backend. The
optional in-memory backend is process-local, bounded, and TTL-aware; it is never
suitable for administrator authentication.

Redis key format: ``revoked_jti:<jti>``
Redis value: ``1``
Redis expiry: the remaining lifetime supplied by the caller.
"""

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Literal, Optional

from app.modules.tokens.models import MAX_TOKEN_LIFETIME_SECONDS

DEFAULT_TTL: int = 3600
DEFAULT_MAX_MEMORY_ENTRIES: int = 10_000
MAX_TTL_SECONDS: int = MAX_TOKEN_LIFETIME_SECONDS
MAX_JTI_LENGTH: int = 256

logger = logging.getLogger(__name__)
_REDIS_KEY_PREFIX = "revoked_jti:"
_EXTEND_REVOCATION_SCRIPT = """
local key = KEYS[1]
local requested_ttl = tonumber(ARGV[1])
local current_value = redis.call('GET', key)
if not current_value then
    redis.call('SETEX', key, requested_ttl, '1')
    return requested_ttl
end
if current_value ~= '1' then
    return redis.error_reply('invalid revocation record value')
end
local current_ttl = redis.call('TTL', key)
if current_ttl == -1 then
    return redis.error_reply('revocation record has no expiry')
end
if current_ttl == -2 then
    redis.call('SETEX', key, requested_ttl, '1')
    return requested_ttl
end
if current_ttl >= requested_ttl then
    return current_ttl
end
redis.call('SETEX', key, requested_ttl, '1')
return requested_ttl
"""


class RevocationStoreError(RuntimeError):
    """Base class for revocation storage failures."""


class RevocationStoreUnavailable(RevocationStoreError):
    """Durable revocation status could not be checked or updated."""


class RevocationRecordError(RevocationStoreError):
    """A Redis revocation record has invalid data or expiry metadata."""


class RevocationStoreCapacityError(RevocationStoreError):
    """The bounded ephemeral store is full of live entries."""


@dataclass(frozen=True)
class RevocationDurabilityAssessment:
    """Sanitized assessment of Redis availability and runtime configuration."""

    backend_type: Literal["redis", "in-memory", "unavailable"]
    redis_available: bool
    persistence_status: Literal["verified", "unsafe", "unverifiable"]
    eviction_status: Literal[
        "verified", "unsafe", "unverifiable", "not_applicable"
    ]
    durability_status: Literal[
        "configuration_verified", "unsafe", "unverifiable", "unavailable"
    ]


def _validate_jti(jti: str) -> None:
    if (
        not isinstance(jti, str)
        or not jti
        or len(jti) > MAX_JTI_LENGTH
        or not jti.isprintable()
        or jti != jti.strip()
    ):
        raise ValueError("JTI must be a non-empty printable string within the supported length limit.")


def _validate_ttl(ttl_seconds: int) -> None:
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not 1 <= ttl_seconds <= MAX_TTL_SECONDS
    ):
        raise ValueError(f"Revocation TTL must be between 1 and {MAX_TTL_SECONDS} seconds.")


class _InMemoryRevocationStore:
    """Bounded, process-local development store with monotonic TTL expiry."""

    def __init__(self, max_entries: int = DEFAULT_MAX_MEMORY_ENTRIES) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer.")
        self._revoked: OrderedDict[str, float] = OrderedDict()
        self._max_entries = max_entries
        self._lock = threading.RLock()

    def _purge_expired(self, now: float) -> None:
        expired = [jti for jti, expires_at in self._revoked.items() if expires_at <= now]
        for jti in expired:
            self._revoked.pop(jti, None)

    def revoke(self, jti: str, ttl_seconds: int = DEFAULT_TTL) -> None:
        _validate_jti(jti)
        _validate_ttl(ttl_seconds)
        now = time.monotonic()
        with self._lock:
            self._purge_expired(now)
            existing_expiry = self._revoked.get(jti)
            requested_expiry = now + ttl_seconds
            if existing_expiry is not None and existing_expiry >= requested_expiry:
                return
            self._revoked.pop(jti, None)
            if len(self._revoked) >= self._max_entries:
                raise RevocationStoreCapacityError(
                    "Ephemeral revocation store is at capacity; no entries were evicted."
                )
            self._revoked[jti] = requested_expiry

    def is_revoked(self, jti: str) -> bool:
        _validate_jti(jti)
        with self._lock:
            self._purge_expired(time.monotonic())
            return jti in self._revoked

    def clear(self) -> None:
        """Clear the process-local store, intended for test teardown."""
        with self._lock:
            self._revoked.clear()


class _RedisRevocationStore:
    """Redis-backed JTI deny-list with value and expiry validation."""

    def __init__(self, redis_client) -> None:  # type: ignore[type-arg]
        self._redis = redis_client

    @staticmethod
    def _normalized_value(value: object) -> Optional[str]:
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8").strip().lower()
            except UnicodeDecodeError:
                return None
        if isinstance(value, (str, int)):
            return str(value).strip().lower()
        return None

    def _config_value(self, name: str) -> Optional[str]:
        settings = self._redis.config_get(name)
        if not isinstance(settings, dict):
            return None
        for key, value in settings.items():
            if self._normalized_value(key) == name:
                return self._normalized_value(value)
        return None

    def _assess_persistence(self) -> Literal["verified", "unsafe", "unverifiable"]:
        try:
            info = self._redis.info("persistence")
            if not isinstance(info, dict):
                return "unverifiable"
            normalized_info = {
                self._normalized_value(key): self._normalized_value(value)
                for key, value in info.items()
            }
            appendonly = self._config_value("appendonly")
            appendfsync = self._config_value("appendfsync")
        except Exception as exc:
            logger.warning(
                "Redis persistence settings could not be inspected (%s).",
                type(exc).__name__,
            )
            return "unverifiable"

        aof_enabled = normalized_info.get("aof_enabled")
        last_write_status = normalized_info.get("aof_last_write_status")
        if (
            (aof_enabled is not None and aof_enabled != "1")
            or (last_write_status is not None and last_write_status != "ok")
            or (appendonly is not None and appendonly != "yes")
            or (appendfsync is not None and appendfsync != "always")
        ):
            return "unsafe"
        if any(
            value is None
            for value in (aof_enabled, last_write_status, appendonly, appendfsync)
        ):
            return "unverifiable"
        return "verified"

    def _assess_eviction(self) -> Literal["verified", "unsafe", "unverifiable"]:
        try:
            maxmemory_policy = self._config_value("maxmemory-policy")
        except Exception as exc:
            logger.warning(
                "Redis eviction settings could not be inspected (%s).",
                type(exc).__name__,
            )
            return "unverifiable"
        if maxmemory_policy is None:
            return "unverifiable"
        if maxmemory_policy != "noeviction":
            return "unsafe"
        return "verified"

    def assess_durability(self) -> RevocationDurabilityAssessment:
        """Inspect only read-only Redis status/configuration commands."""
        try:
            if not self._redis.ping():
                raise ConnectionError("Redis health check did not succeed.")
        except Exception as exc:
            logger.warning(
                "Redis is unavailable during durability assessment (%s).",
                type(exc).__name__,
            )
            return RevocationDurabilityAssessment(
                backend_type="redis",
                redis_available=False,
                persistence_status="unverifiable",
                eviction_status="unverifiable",
                durability_status="unavailable",
            )

        persistence_status = self._assess_persistence()
        eviction_status = self._assess_eviction()
        try:
            if not self._redis.ping():
                raise ConnectionError("Redis health check did not succeed.")
        except Exception as exc:
            logger.warning(
                "Redis became unavailable during durability assessment (%s).",
                type(exc).__name__,
            )
            return RevocationDurabilityAssessment(
                backend_type="redis",
                redis_available=False,
                persistence_status=persistence_status,
                eviction_status=eviction_status,
                durability_status="unavailable",
            )

        if "unsafe" in (persistence_status, eviction_status):
            durability_status = "unsafe"
        elif persistence_status == eviction_status == "verified":
            durability_status = "configuration_verified"
        else:
            durability_status = "unverifiable"

        return RevocationDurabilityAssessment(
            backend_type="redis",
            redis_available=True,
            persistence_status=persistence_status,
            eviction_status=eviction_status,
            durability_status=durability_status,
        )

    def revoke(self, jti: str, ttl_seconds: int = DEFAULT_TTL) -> None:
        _validate_jti(jti)
        _validate_ttl(ttl_seconds)
        self._redis.eval(
            _EXTEND_REVOCATION_SCRIPT,
            1,
            f"{_REDIS_KEY_PREFIX}{jti}",
            ttl_seconds,
        )

    def is_revoked(self, jti: str) -> bool:
        _validate_jti(jti)
        key = f"{_REDIS_KEY_PREFIX}{jti}"
        value = self._redis.get(key)
        if value is None:
            return False
        if value not in ("1", b"1"):
            raise RevocationRecordError("Revocation record has an invalid value.")

        ttl = self._redis.ttl(key)
        if (
            isinstance(ttl, bool)
            or not isinstance(ttl, int)
            or ttl == -1
            or ttl < -2
            or ttl > MAX_TTL_SECONDS
        ):
            raise RevocationRecordError("Revocation record has invalid expiry metadata.")
        if ttl == -2:
            # It expired between GET and TTL; the record is no longer present.
            return False
        return True


class TokenRevocationStore:
    """Revocation facade; Redis is strict by default, memory is explicit dev-only.

    If Redis cannot be initialized without ``allow_in_memory_fallback=True``,
    the store reports ``backend_type == "unavailable"`` and operations raise
    :class:`RevocationStoreUnavailable`. The application enables the memory
    fallback only for explicit development configuration. Memory entries expire
    and are bounded, but are not durable or shared across processes. Redis is
    not considered durable for admin authentication until its persistence and
    eviction settings are verified.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        *,
        allow_in_memory_fallback: bool = False,
        max_memory_entries: int = DEFAULT_MAX_MEMORY_ENTRIES,
    ) -> None:
        self._redis_url = redis_url
        self._allow_in_memory_fallback = allow_in_memory_fallback
        self._max_memory_entries = max_memory_entries
        self._backend: Optional[_RedisRevocationStore | _InMemoryRevocationStore] = self._connect(
            redis_url
        )

    def _connect(
        self, redis_url: str
    ) -> Optional[_RedisRevocationStore | _InMemoryRevocationStore]:
        try:
            import redis  # type: ignore[import]

            client = redis.from_url(
                redis_url,
                socket_connect_timeout=1,
                socket_timeout=1,
            )
            if not client.ping():
                raise ConnectionError("Redis health check did not succeed.")
            logger.info("TokenRevocationStore connected to Redis.")
            return _RedisRevocationStore(client)
        except Exception as exc:
            if self._allow_in_memory_fallback:
                logger.warning(
                    "Redis revocation storage unavailable (%s); using bounded, ephemeral "
                    "development-only memory storage. This backend is not durable or shared.",
                    type(exc).__name__,
                )
                return _InMemoryRevocationStore(self._max_memory_entries)

            logger.error(
                "Redis revocation storage unavailable (%s); revocation operations will fail closed.",
                type(exc).__name__,
            )
            return None

    def _run(self, method: str, *args):
        if self._backend is None:
            raise RevocationStoreUnavailable("Durable revocation storage is unavailable.")
        try:
            return getattr(self._backend, method)(*args)
        except RevocationStoreError:
            raise
        except ValueError:
            raise
        except Exception as exc:
            logger.error(
                "Revocation storage operation failed (%s); request will fail closed.",
                type(exc).__name__,
            )
            raise RevocationStoreUnavailable("Revocation storage operation failed.") from None

    def revoke(self, jti: str, ttl_seconds: int = DEFAULT_TTL) -> None:
        """Add a validated JTI to the active backend until its TTL expires."""
        self._run("revoke", jti, ttl_seconds)

    def is_revoked(self, jti: str) -> bool:
        """Query revocation state; storage errors are never treated as not revoked."""
        return self._run("is_revoked", jti)

    def require_durable(self) -> None:
        """Reject storage without verified persistence and no-eviction settings."""
        if self.assess_durability().durability_status != "configuration_verified":
            raise RevocationStoreUnavailable(
                "Redis persistence and no-eviction settings must be verified "
                "for administrator authentication."
            )

    def assess_durability(self) -> RevocationDurabilityAssessment:
        """Report sanitized backend and durability status without exposing config."""
        if isinstance(self._backend, _RedisRevocationStore):
            return self._backend.assess_durability()
        if isinstance(self._backend, _InMemoryRevocationStore):
            return RevocationDurabilityAssessment(
                backend_type="in-memory",
                redis_available=False,
                persistence_status="unsafe",
                eviction_status="not_applicable",
                durability_status="unsafe",
            )
        return RevocationDurabilityAssessment(
            backend_type="unavailable",
            redis_available=False,
            persistence_status="unverifiable",
            eviction_status="unverifiable",
            durability_status="unavailable",
        )

    def clear_in_memory(self) -> None:
        """Clear only an active ephemeral backend, intended for test teardown."""
        if isinstance(self._backend, _InMemoryRevocationStore):
            self._backend.clear()

    @property
    def is_durable(self) -> bool:
        """Return whether required runtime settings are verified, not infra durability."""
        return (
            self.assess_durability().durability_status == "configuration_verified"
        )

    @property
    def backend_type(self) -> str:
        """Report the configured backend without claiming memory is durable."""
        if isinstance(self._backend, _RedisRevocationStore):
            return "redis"
        if isinstance(self._backend, _InMemoryRevocationStore):
            return "in-memory"
        return "unavailable"
