"""Cryptographic hashing and canonical serialization utilities for the Simulated Ledger.

To guarantee tamper-evidence across disparate systems and runtime environments,
all hashes MUST be calculated over canonical representations where keys are
strictly sorted, separators are standardized, and encoding is UTF-8.
"""

import hashlib
import json
from typing import Any, Dict
from app.modules.ledger.models import LedgerRecord


def canonical_json_dumps(data: Any) -> str:
    """Serialize Python data into a deterministic, sorted, compact JSON string.

    Rules applied:
    - Keys are alphabetically sorted (sort_keys=True).
    - Whitespace separators are compact (',' and ':').
    - ASCII-safe characters (ensure_ascii=True).
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def calculate_sha256(content: str | bytes) -> str:
    """Calculate the SHA-256 digest of string or bytes, returning a 64-char lowercase hex string."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest().lower()


def calculate_record_hash(payload: Dict[str, Any]) -> str:
    """Calculate the canonical SHA-256 hash for a ledger record payload.

    Args:
        payload: Dictionary of record fields (excluding the 'record_hash' itself).

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.
    """
    canonical_repr = canonical_json_dumps(payload)
    return calculate_sha256(canonical_repr)


def verify_record_hash(record: LedgerRecord) -> bool:
    """Verify that a LedgerRecord's stored record_hash matches its content.

    Returns:
        True if the record_hash exactly matches the calculated hash of its payload.
        False if the data has been altered.
    """
    expected_hash = calculate_record_hash(record.get_hashable_payload())
    return record.record_hash == expected_hash


def hash_did_document(did_document: Dict[str, Any]) -> str:
    """Helper to compute the deterministic SHA-256 hash (doc_hash) of a DID Document.

    Can be used by Member 3 (DID/Crypto) and Member 1 (API) when anchoring DID documents.
    """
    return calculate_sha256(canonical_json_dumps(did_document))
