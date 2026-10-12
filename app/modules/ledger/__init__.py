"""Simulated Blockchain Ledger Module (Identity Integrity Anchoring).

This module implements an append-only, cryptographic hash-linked ledger
recording Decentralized Identifier (DID) creations and updates.
"""

from app.modules.ledger.models import (
    LedgerRecord,
    LedgerOperation,
    RecordCreateInput,
    GENESIS_PREVIOUS_HASH,
)
from app.modules.ledger.hasher import (
    canonical_json_dumps,
    calculate_sha256,
    calculate_record_hash,
    verify_record_hash,
    hash_did_document,
)
from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.router import router as ledger_router

__all__ = [
    "LedgerRecord",
    "LedgerOperation",
    "RecordCreateInput",
    "GENESIS_PREVIOUS_HASH",
    "canonical_json_dumps",
    "calculate_sha256",
    "calculate_record_hash",
    "verify_record_hash",
    "hash_did_document",
    "SimulatedLedger",
    "ledger_router",
]
