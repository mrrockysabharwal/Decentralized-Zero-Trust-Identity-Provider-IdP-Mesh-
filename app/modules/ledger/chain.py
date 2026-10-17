"""Simulated Blockchain Ledger Chain implementation.

Provides the core append-only, thread-safe hash-linked record chain.
"""

from datetime import datetime, timezone
import json
import os
import threading
from typing import Any, Dict, List, Optional

from app.modules.ledger.models import (
    LedgerRecord,
    LedgerOperation,
    GENESIS_PREVIOUS_HASH,
)
from app.modules.ledger.hasher import (
    calculate_record_hash,
    calculate_sha256,
    verify_record_hash,
)


class SimulatedLedger:
    """An append-only simulated blockchain ledger with optional JSON file persistence.
    
    Anchors Decentralized Identifier (DID) state transitions in a tamper-evident,
    cryptographically linked hash chain.
    """

    def __init__(
        self,
        auto_genesis: bool = True,
        storage_path: Optional[str] = None,
    ):
        self._lock = threading.Lock()
        self._chain: List[LedgerRecord] = []
        self._storage_path = storage_path

        if self._storage_path and os.path.exists(self._storage_path):
            self.load_from_file(self._storage_path)
        elif auto_genesis:
            self._create_genesis_record()
            if self._storage_path:
                self.save_to_file(self._storage_path)

    def _create_genesis_record(self) -> LedgerRecord:
        """Create and anchor the immutable genesis record at index 0."""
        timestamp = datetime.now(timezone.utc).isoformat()
        genesis_did = "did:mesh:genesis"
        genesis_doc_hash = calculate_sha256("GENESIS_DOCUMENT_SEED")
        metadata = {
            "network": "idp-mesh-simulated-v1",
            "description": "Genesis anchor for Decentralized Zero-Trust IdP Mesh",
        }
        
        payload = {
            "index": 0,
            "timestamp": timestamp,
            "did": genesis_did,
            "doc_hash": genesis_doc_hash,
            "operation": LedgerOperation.GENESIS.value,
            "previous_hash": GENESIS_PREVIOUS_HASH,
            "metadata": metadata,
        }
        
        rec_hash = calculate_record_hash(payload)
        
        genesis_record = LedgerRecord(
            index=0,
            timestamp=timestamp,
            did=genesis_did,
            doc_hash=genesis_doc_hash,
            operation=LedgerOperation.GENESIS,
            previous_hash=GENESIS_PREVIOUS_HASH,
            record_hash=rec_hash,
            metadata=metadata,
        )
        
        self._chain.append(genesis_record)
        return genesis_record

    def append_record(
        self,
        did: str,
        doc_hash: str,
        operation: LedgerOperation | str = LedgerOperation.CREATE,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> LedgerRecord:
        """Append a new DID record to the ledger, cryptographically linking to previous head.
        
        Args:
            did: Decentralized identifier string (e.g. did:mesh:key:...).
            doc_hash: 64-char hex SHA-256 digest of the DID Document.
            operation: CREATE, UPDATE, or DEACTIVATE.
            metadata: Optional non-sensitive metadata dictionary.
            
        Returns:
            The newly minted, verified LedgerRecord.
        """
        if isinstance(operation, str):
            operation = LedgerOperation(operation.upper())

        with self._lock:
            if not self._chain:
                # If chain was empty, start with genesis first
                self._create_genesis_record()

            head = self._chain[-1]
            new_index = head.index + 1
            previous_hash = head.record_hash
            timestamp = datetime.now(timezone.utc).isoformat()
            clean_metadata = metadata.copy() if metadata else {}

            payload = {
                "index": new_index,
                "timestamp": timestamp,
                "did": did,
                "doc_hash": doc_hash.lower(),
                "operation": operation.value,
                "previous_hash": previous_hash.lower(),
                "metadata": clean_metadata,
            }

            rec_hash = calculate_record_hash(payload)

            record = LedgerRecord(
                index=new_index,
                timestamp=timestamp,
                did=did,
                doc_hash=doc_hash.lower(),
                operation=operation,
                previous_hash=previous_hash.lower(),
                record_hash=rec_hash,
                metadata=clean_metadata,
            )

            self._chain.append(record)
            if self._storage_path:
                self.save_to_file(self._storage_path)
            return record

    def save_to_file(self, filepath: Optional[str] = None) -> None:
        """Serialize and save the current ledger state to a JSON file.
        
        Args:
            filepath: Destination file path. If None, uses self._storage_path.
        """
        target_path = filepath or self._storage_path
        if not target_path:
            raise ValueError("No filepath provided and self._storage_path is not set.")

        with self._lock:
            records_data = [rec.model_dump() for rec in self._chain]
            
            # Ensure parent directory exists
            parent_dir = os.path.dirname(target_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)

            with open(target_path, "w", encoding="utf-8") as f:
                json.dump(records_data, f, indent=2)

    def load_from_file(self, filepath: str) -> None:
        """Load and deserialize ledger records from a JSON file, validating chain integrity.
        
        Args:
            filepath: Path to the JSON file to read.
            
        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file contents fail cryptographic integrity verification.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Ledger file not found at '{filepath}'.")

        with open(filepath, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        if not isinstance(raw_data, list):
            raise ValueError("Invalid ledger format: root must be a JSON array of records.")

        loaded_chain = [LedgerRecord(**item) for item in raw_data]

        with self._lock:
            original_chain = self._chain
            self._chain = loaded_chain
            
            # Validate integrity of loaded chain immediately
            is_valid, error = self.verify_integrity()
            if not is_valid:
                # Rollback on failure to prevent corrupted in-memory state
                self._chain = original_chain
                raise ValueError(f"Integrity check failed while loading ledger: {error}")

    def get_head(self) -> Optional[LedgerRecord]:
        """Return the most recent record on the chain, or None if empty."""
        with self._lock:
            return self._chain[-1] if self._chain else None

    def get_record_by_index(self, index: int) -> Optional[LedgerRecord]:
        """Retrieve a specific record by its sequential index."""
        with self._lock:
            if 0 <= index < len(self._chain):
                return self._chain[index]
            return None

    def get_records_by_did(self, did: str) -> List[LedgerRecord]:
        """Retrieve the complete chronological history of records for a given DID."""
        with self._lock:
            return [rec for rec in self._chain if rec.did == did]

    def get_latest_record(self, did: str) -> Optional[LedgerRecord]:
        """Retrieve the most recent record for a given DID, or None if never registered."""
        with self._lock:
            records = [rec for rec in self._chain if rec.did == did]
            return records[-1] if records else None

    def get_all_records(self) -> List[LedgerRecord]:
        """Return a shallow copy of all records on the chain."""
        with self._lock:
            return list(self._chain)

    def verify_integrity(self) -> tuple[bool, Optional[str]]:
        """Verify the cryptographic integrity of the entire ledger chain.
        
        Performs three levels of validation:
        1. Genesis block validity (index 0, previous_hash=64 zeroes, valid record_hash).
        2. Intra-record content integrity (record_hash matches canonical payload).
        3. Inter-record linkage (record[i].previous_hash == record[i-1].record_hash).
        4. Strict sequential indexing (record[i].index == record[i-1].index + 1).

        Returns:
            (True, None) if the entire chain is valid and untampered.
            (False, error_message) describing the exact failure location and reason.
        """
        with self._lock:
            if not self._chain:
                return False, "Ledger is empty: missing genesis block."

            genesis = self._chain[0]
            if genesis.index != 0:
                return False, f"Genesis block must have index 0, found {genesis.index}."

            if genesis.previous_hash != GENESIS_PREVIOUS_HASH:
                return False, (
                    f"Genesis block previous_hash must be {GENESIS_PREVIOUS_HASH}, "
                    f"found {genesis.previous_hash}."
                )

            if not verify_record_hash(genesis):
                return False, "Genesis block record_hash does not match its contents: tampering detected."

            for i in range(1, len(self._chain)):
                prev_record = self._chain[i - 1]
                curr_record = self._chain[i]

                # Check 1: Strict sequential index
                if curr_record.index != prev_record.index + 1:
                    return False, (
                        f"Non-sequential index at chain position {i}: "
                        f"expected {prev_record.index + 1}, found {curr_record.index}."
                    )

                # Check 2: Cryptographic link to previous block
                if curr_record.previous_hash != prev_record.record_hash:
                    return False, (
                        f"Broken cryptographic hash linkage at index {curr_record.index}: "
                        f"previous_hash '{curr_record.previous_hash}' does not match "
                        f"preceding record #{prev_record.index} hash '{prev_record.record_hash}'."
                    )

                # Check 3: Content integrity of current block
                if not verify_record_hash(curr_record):
                    return False, (
                        f"Data tampering detected at record #{curr_record.index}: "
                        f"stored record_hash '{curr_record.record_hash}' does not match "
                        f"recalculated canonical payload hash."
                    )

            return True, None

    def tamper_record(
        self,
        index: int,
        field: str,
        new_value: Any,
        recalculate_record_hash: bool = False,
    ) -> None:
        """Simulate a malicious tampering attack on a record at the specified index.
        
        Used exclusively for security testing, audits, and dashboard demonstrations
        to prove that modifying historical records invalidates the ledger chain.
        
        Args:
            index: The index of the record to tamper with.
            field: The field name to alter (e.g. 'did', 'doc_hash', 'previous_hash').
            new_value: The malicious replacement value.
            recalculate_record_hash: If True, updates record_hash for this block
                                    to simulate an attacker attempting to fix the block's
                                    internal hash (which still breaks linkage in subsequent blocks).
        """
        with self._lock:
            if not (0 <= index < len(self._chain)):
                raise IndexError(f"Record index {index} out of range (chain length {len(self._chain)}).")

            target = self._chain[index]
            data_dict = target.model_dump()
            data_dict[field] = new_value

            if recalculate_record_hash:
                # Recalculate this block's hash, but do not touch subsequent blocks
                payload = dict(data_dict)
                payload.pop("record_hash", None)
                if "operation" in payload and isinstance(payload["operation"], LedgerOperation):
                    payload["operation"] = payload["operation"].value
                data_dict["record_hash"] = calculate_record_hash(payload)

            # Reconstruct the record with model_construct to bypass initial pydantic validators if simulating malformed data
            self._chain[index] = LedgerRecord.model_construct(**data_dict)

    def count(self) -> int:
        """Return total number of records currently on the ledger."""
        with self._lock:
            return len(self._chain)

    def __len__(self) -> int:
        return self.count()

