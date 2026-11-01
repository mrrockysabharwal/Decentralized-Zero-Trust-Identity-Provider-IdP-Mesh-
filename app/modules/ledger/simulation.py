"""Helpers for running destructive ledger demonstrations on isolated state."""

from __future__ import annotations

from copy import deepcopy

from app.modules.ledger.chain import SimulatedLedger


def isolated_ledger_copy(source: SimulatedLedger) -> SimulatedLedger:
    """Return a detached ledger snapshot with no persistence target."""
    isolated = SimulatedLedger(auto_genesis=False)
    with source._lock:
        isolated._chain = deepcopy(source._chain)
    return isolated
