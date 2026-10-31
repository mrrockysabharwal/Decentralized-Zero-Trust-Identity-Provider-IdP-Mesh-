"""Append-only SHA-256 hash-linked ledger core, independent of HTTP routers."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Mapping

from app.core_security.challenges import canonical_json_bytes

GENESIS_PREVIOUS_HASH = "0" * 64
GENESIS_DOCUMENT = "TrustMesh-Core-Ledger-Genesis-v1"


def sha256_hex(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def hash_document(document: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json_bytes(document))


@dataclass(frozen=True)
class CoreLedgerRecord:
    index: int
    timestamp: str
    did: str
    doc_hash: str
    operation: str
    previous_hash: str
    record_hash: str
    _metadata_json: str

    @property
    def metadata(self) -> dict[str, Any]:
        """Return a fresh value so callers cannot mutate stored ledger state."""
        return json.loads(self._metadata_json)

    def hash_payload(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "did": self.did,
            "doc_hash": self.doc_hash,
            "operation": self.operation,
            "previous_hash": self.previous_hash,
            "metadata": self.metadata,
        }


class CoreLedger:
    """In-memory append-only ledger with verifiable SHA-256 linkage."""

    def __init__(self, *, create_genesis: bool = True) -> None:
        self._records: list[CoreLedgerRecord] = []
        self._lock = threading.RLock()
        if create_genesis:
            self._append(
                did="did:mesh:genesis",
                doc_hash=sha256_hex(GENESIS_DOCUMENT),
                operation="GENESIS",
                metadata={"network": "trustmesh-core-v1"},
                previous_hash=GENESIS_PREVIOUS_HASH,
            )

    @property
    def records(self) -> tuple[CoreLedgerRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    @staticmethod
    def _record_hash(payload: Mapping[str, Any]) -> str:
        return sha256_hex(canonical_json_bytes(payload))

    def _append(
        self,
        *,
        did: str,
        doc_hash: str,
        operation: str,
        metadata: Mapping[str, Any],
        previous_hash: str,
    ) -> CoreLedgerRecord:
        metadata_json = canonical_json_bytes(dict(metadata)).decode("utf-8")
        index = len(self._records)
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {
            "index": index,
            "timestamp": timestamp,
            "did": did,
            "doc_hash": doc_hash,
            "operation": operation,
            "previous_hash": previous_hash,
            "metadata": json.loads(metadata_json),
        }
        record = CoreLedgerRecord(
            index=index,
            timestamp=timestamp,
            did=did,
            doc_hash=doc_hash,
            operation=operation,
            previous_hash=previous_hash,
            record_hash=self._record_hash(payload),
            _metadata_json=metadata_json,
        )
        self._records.append(record)
        return record

    def append_record(
        self,
        *,
        did: str,
        doc_hash: str,
        operation: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> CoreLedgerRecord:
        if not did or operation not in {"CREATE", "UPDATE", "DEACTIVATE", "ANCHOR"}:
            raise ValueError("A DID and supported non-genesis operation are required.")
        if len(doc_hash) != 64 or any(ch not in "0123456789abcdef" for ch in doc_hash.lower()):
            raise ValueError("Document hash must be a 32-byte SHA-256 hex digest.")
        with self._lock:
            if not self._records:
                raise RuntimeError("Ledger genesis record is missing.")
            return self._append(
                did=did,
                doc_hash=doc_hash.lower(),
                operation=operation,
                metadata=metadata or {},
                previous_hash=self._records[-1].record_hash,
            )

    def verify_integrity(self) -> tuple[bool, str | None]:
        with self._lock:
            if not self._records:
                return False, "Ledger has no genesis record."
            for expected_index, record in enumerate(self._records):
                if record.index != expected_index:
                    return False, f"Record index mismatch at position {expected_index}."
                expected_previous = GENESIS_PREVIOUS_HASH if expected_index == 0 else self._records[expected_index - 1].record_hash
                if record.previous_hash != expected_previous:
                    return False, f"Previous-hash link mismatch at record {expected_index}."
                if record.record_hash != self._record_hash(record.hash_payload()):
                    return False, f"Record hash mismatch at record {expected_index}."
                if expected_index == 0 and (
                    record.operation != "GENESIS"
                    or record.did != "did:mesh:genesis"
                    or record.doc_hash != sha256_hex(GENESIS_DOCUMENT)
                ):
                    return False, "Genesis record does not match the expected core genesis."
            return True, None

    def tampered_copy_for_testing(self, index: int, field: str, value: Any) -> "CoreLedger":
        """Return a tampered copy for demonstrations/tests; never mutates this ledger."""
        if field not in {"did", "doc_hash", "operation", "previous_hash", "record_hash", "metadata"}:
            raise ValueError("Unsupported ledger field for isolated tampering.")
        with self._lock:
            if index < 0 or index >= len(self._records):
                raise IndexError("Ledger record index is out of range.")
            copied = CoreLedger(create_genesis=False)
            copied._records = list(self._records)
            record = copied._records[index]
            if field == "metadata":
                value = canonical_json_bytes(value).decode("utf-8")
                copied._records[index] = replace(record, _metadata_json=value)
            else:
                copied._records[index] = replace(record, **{field: value})
            return copied

