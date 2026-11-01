import sys
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.modules.admin import security as admin_security
import app.modules.admin.router as admin_router_module
from app.modules.ledger.chain import SimulatedLedger
from app.modules.tokens.revocation import (
    RevocationStoreUnavailable,
    TokenRevocationStore,
    _RedisRevocationStore,
)
from app.modules.webauthn.credential_store import CredentialStore


_UNSET = object()


class FakeRedis:
    def __init__(
        self,
        *,
        aof_enabled="1",
        aof_last_write_status="ok",
        appendonly="yes",
        appendfsync="always",
        maxmemory_policy="noeviction",
        restricted=(),
        unavailable=False,
        persistence_response=_UNSET,
        config_responses=None,
        command_errors=None,
    ):
        self.persistence = {
            "aof_enabled": aof_enabled,
            "aof_last_write_status": aof_last_write_status,
        }
        self.persistence_response = persistence_response
        self.settings = {
            "appendonly": appendonly,
            "appendfsync": appendfsync,
            "maxmemory-policy": maxmemory_policy,
        }
        self.config_responses = config_responses or {}
        self.command_errors = command_errors or {}
        self.restricted = set(restricted)
        self.unavailable = unavailable
        self.commands = []
        self.ping_count = 0
        self.revocation_lookups = []

    def ping(self):
        self.commands.append("PING")
        self.ping_count += 1
        error = self.command_errors.get(("PING", self.ping_count))
        if error is not None:
            raise error
        if self.unavailable:
            raise ConnectionError("Redis unavailable")
        return True

    def info(self, section):
        self.commands.append(("INFO", section))
        error = self.command_errors.get(("INFO", section))
        if error is not None:
            raise error
        if self.unavailable:
            raise ConnectionError("Redis unavailable")
        if self.persistence_response is not _UNSET:
            return self.persistence_response
        return self.persistence

    def config_get(self, name):
        self.commands.append(("CONFIG GET", name))
        error = self.command_errors.get(("CONFIG GET", name))
        if error is not None:
            raise error
        if name in self.restricted:
            raise PermissionError("configuration inspection is restricted")
        if name in self.config_responses:
            return self.config_responses[name]
        return {name: self.settings[name]} if name in self.settings else {}

    def get(self, key):
        self.revocation_lookups.append(key)
        return None


def _store(redis_client):
    store = TokenRevocationStore.__new__(TokenRevocationStore)
    store._backend = _RedisRevocationStore(redis_client)
    return store


def _admin_credentials(monkeypatch, store):
    now = 1_800_000_000
    claims = {
        "sub": "did:mesh:admin:test",
        "jti": "admin-jti",
        "iat": now,
        "exp": now + 3600,
        "iss": "idp-mesh-admin",
        "aud": "idp-mesh-admin",
        "scope": ["admin:ledger"],
    }
    monkeypatch.setenv("ADMIN_JWT_PUBLIC_KEY", "test-only-public-key")
    monkeypatch.setenv("ADMIN_DIDS", "did:mesh:admin:test")
    monkeypatch.setattr(admin_security.jwt, "decode", lambda *_args, **_kwargs: claims)
    monkeypatch.setattr(admin_security, "get_revocation_store", lambda: store)
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials="test-token")


def test_redis_with_verified_persistence_and_noeviction_is_accepted():
    redis_client = FakeRedis()
    store = _store(redis_client)

    assessment = store.assess_durability()

    assert assessment.backend_type == "redis"
    assert assessment.redis_available is True
    assert assessment.persistence_status == "verified"
    assert assessment.eviction_status == "verified"
    assert assessment.durability_status == "configuration_verified"
    store.require_durable()
    assert all(
        command == "PING"
        or command == ("INFO", "persistence")
        or command[0] == "CONFIG GET"
        for command in redis_client.commands
    )


def test_redis_without_persistence_is_unsafe():
    store = _store(FakeRedis(aof_enabled="0", appendonly="no"))

    assessment = store.assess_durability()

    assert assessment.persistence_status == "unsafe"
    assert assessment.durability_status == "unsafe"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


def test_aof_disabled_is_unsafe():
    store = _store(FakeRedis(aof_enabled="0"))

    assessment = store.assess_durability()

    assert assessment.persistence_status == "unsafe"
    assert assessment.durability_status == "unsafe"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


def test_appendfsync_everysec_is_unsafe():
    store = _store(FakeRedis(appendfsync="everysec"))

    assessment = store.assess_durability()

    assert assessment.persistence_status == "unsafe"
    assert assessment.durability_status == "unsafe"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


def test_unhealthy_aof_last_write_status_is_unsafe():
    store = _store(FakeRedis(aof_last_write_status="err"))

    assessment = store.assess_durability()

    assert assessment.persistence_status == "unsafe"
    assert assessment.durability_status == "unsafe"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


def test_missing_aof_information_is_unverifiable():
    store = _store(
        FakeRedis(persistence_response={"aof_enabled": "1"})
    )

    assessment = store.assess_durability()

    assert assessment.persistence_status == "unverifiable"
    assert assessment.durability_status == "unverifiable"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


@pytest.mark.parametrize(
    "config_response",
    [
        {},
        None,
        ["always"],
        {"unexpected-setting": "always"},
        {"appendfsync": []},
    ],
)
def test_missing_or_malformed_config_response_is_unverifiable(config_response):
    store = _store(
        FakeRedis(config_responses={"appendfsync": config_response})
    )

    assessment = store.assess_durability()

    assert assessment.persistence_status == "unverifiable"
    assert assessment.durability_status == "unverifiable"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


@pytest.mark.parametrize(
    ("persistence_response", "config_responses"),
    [
        ([], {}),
        ({"aof_enabled": [], "aof_last_write_status": "ok"}, {}),
        (_UNSET, {"appendfsync": {"appendfsync": object()}}),
    ],
)
def test_unexpected_redis_response_types_never_verify_durability(
    persistence_response, config_responses
):
    store = _store(
        FakeRedis(
            persistence_response=persistence_response,
            config_responses=config_responses,
        )
    )

    assessment = store.assess_durability()

    assert assessment.durability_status != "configuration_verified"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


@pytest.mark.parametrize(
    ("failed_commands", "expected_status"),
    [
        ((("PING", 1), ("PING", 3)), "unavailable"),
        ((("INFO", "persistence"),), "unverifiable"),
        ((("CONFIG GET", "appendonly"),), "unverifiable"),
        ((("CONFIG GET", "appendfsync"),), "unverifiable"),
        ((("CONFIG GET", "maxmemory-policy"),), "unverifiable"),
        ((("PING", 2), ("PING", 4)), "unavailable"),
    ],
)
def test_redis_inspection_command_errors_fail_closed(
    failed_commands, expected_status
):
    redis_client = FakeRedis(
        command_errors={
            command: ConnectionError("mock Redis command failure")
            for command in failed_commands
        }
    )
    store = _store(redis_client)

    assessment = store.assess_durability()

    assert assessment.durability_status == expected_status
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


def test_redis_inspection_timeout_is_unverifiable():
    redis_client = FakeRedis(
        command_errors={
            ("CONFIG GET", "appendfsync"): TimeoutError("mock Redis timeout")
        }
    )
    store = _store(redis_client)

    assessment = store.assess_durability()

    assert assessment.redis_available is True
    assert assessment.persistence_status == "unverifiable"
    assert assessment.durability_status == "unverifiable"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


def test_unsafe_eviction_policy_is_rejected():
    store = _store(FakeRedis(maxmemory_policy="allkeys-lru"))

    assessment = store.assess_durability()

    assert assessment.persistence_status == "verified"
    assert assessment.eviction_status == "unsafe"
    assert assessment.durability_status == "unsafe"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


def test_restricted_config_inspection_is_unverifiable():
    store = _store(
        FakeRedis(restricted={"appendonly", "appendfsync", "maxmemory-policy"})
    )

    assessment = store.assess_durability()

    assert assessment.redis_available is True
    assert assessment.persistence_status == "unverifiable"
    assert assessment.eviction_status == "unverifiable"
    assert assessment.durability_status == "unverifiable"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


def test_missing_config_value_is_unverifiable():
    redis_client = FakeRedis()
    del redis_client.settings["appendfsync"]
    store = _store(redis_client)

    assessment = store.assess_durability()

    assert assessment.redis_available is True
    assert assessment.persistence_status == "unverifiable"
    assert assessment.durability_status == "unverifiable"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


def test_redis_unavailable_is_reported_separately():
    store = _store(FakeRedis(unavailable=True))

    assessment = store.assess_durability()

    assert assessment.backend_type == "redis"
    assert assessment.redis_available is False
    assert assessment.durability_status == "unavailable"
    with pytest.raises(RevocationStoreUnavailable):
        store.require_durable()


def test_admin_auth_fails_closed_when_config_is_unverifiable(monkeypatch):
    redis_client = FakeRedis(restricted={"maxmemory-policy"})
    store = _store(redis_client)
    credentials = _admin_credentials(monkeypatch, store)

    with pytest.raises(HTTPException) as raised:
        admin_security.require_admin(credentials)

    assert raised.value.status_code == 503
    assert redis_client.revocation_lookups == []


@pytest.mark.parametrize(
    "redis_kwargs",
    [
        {"appendfsync": "everysec"},
        {"aof_last_write_status": "err"},
    ],
)
def test_admin_auth_fails_closed_for_unsafe_durability(redis_kwargs, monkeypatch):
    redis_client = FakeRedis(**redis_kwargs)
    store = _store(redis_client)
    credentials = _admin_credentials(monkeypatch, store)

    with pytest.raises(HTTPException) as raised:
        admin_security.require_admin(credentials)

    assert raised.value.status_code == 503
    assert redis_client.revocation_lookups == []


def test_admin_auth_does_not_accept_explicit_in_memory_fallback(monkeypatch):
    class FailedRedis:
        def ping(self):
            raise ConnectionError("Redis unavailable")

    monkeypatch.setitem(
        sys.modules,
        "redis",
        SimpleNamespace(from_url=lambda *_args, **_kwargs: FailedRedis()),
    )
    store = TokenRevocationStore(
        redis_url="redis://unavailable/0",
        allow_in_memory_fallback=True,
    )
    credentials = _admin_credentials(monkeypatch, store)
    revocation_lookups = []
    monkeypatch.setattr(
        store, "is_revoked", lambda jti: revocation_lookups.append(jti) or False
    )

    assert store.backend_type == "in-memory"
    assessment = store.assess_durability()
    assert assessment.persistence_status == "unsafe"
    assert assessment.eviction_status == "not_applicable"
    assert assessment.durability_status == "unsafe"
    with pytest.raises(HTTPException) as raised:
        admin_security.require_admin(credentials)
    assert raised.value.status_code == 503
    assert revocation_lookups == []


def test_admin_health_reports_backend_availability_separately_from_durability(
    monkeypatch,
):
    store = _store(FakeRedis(restricted={"maxmemory-policy"}))
    monkeypatch.setattr(
        admin_router_module, "_shared_ledger", SimulatedLedger(auto_genesis=True)
    )
    monkeypatch.setattr(
        admin_router_module, "_credential_store", CredentialStore()
    )
    monkeypatch.setattr(
        admin_router_module, "get_revocation_store", lambda: store
    )

    health = admin_router_module.get_system_health()

    assert health.revocation_redis_available is True
    assert health.revocation_persistence == "verified"
    assert health.revocation_eviction == "unverifiable"
    assert health.revocation_durability == "unverifiable"
    assert health.overall_status == "degraded"
    tokens = next(item for item in health.subsystems if item.name == "tokens")
    assert tokens.status == "degraded"
    assert "noeviction" not in (tokens.detail or "")
