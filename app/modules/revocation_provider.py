"""Shared, lazy provider for token and administrator revocation state."""

from __future__ import annotations

import os
import threading

from app.modules.tokens.revocation import TokenRevocationStore

_provider_lock = threading.Lock()
_revocation_store: TokenRevocationStore | None = None


def get_revocation_store() -> TokenRevocationStore:
    """Return the process's single configured revocation-store instance."""
    global _revocation_store
    if _revocation_store is None:
        with _provider_lock:
            if _revocation_store is None:
                development_memory_fallback = (
                    os.environ.get("TRUSTMESH_ENV", "").strip().lower() == "development"
                    and os.environ.get("TOKEN_REVOCATION_ALLOW_IN_MEMORY", "")
                    .strip()
                    .lower()
                    in {"1", "true", "yes", "on"}
                )
                _revocation_store = TokenRevocationStore(
                    redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
                    allow_in_memory_fallback=development_memory_fallback,
                )
    return _revocation_store


def set_revocation_store(store: TokenRevocationStore | None) -> None:
    """Replace the shared store for application wiring and isolated tests."""
    global _revocation_store
    with _provider_lock:
        _revocation_store = store
