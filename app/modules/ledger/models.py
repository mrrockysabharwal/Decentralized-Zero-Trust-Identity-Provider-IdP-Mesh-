"""Data models for the Simulated Blockchain Ledger (Identity Integrity Anchoring)."""

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict
from pydantic import BaseModel, Field, field_validator


class LedgerOperation(str, Enum):
    """Supported identity operations on the ledger."""
    GENESIS = "GENESIS"
    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DEACTIVATE = "DEACTIVATE"


SHA256_HEX_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
GENESIS_PREVIOUS_HASH = "0" * 64


class LedgerRecord(BaseModel):
    """An immutable, hash-linked block representing a DID anchoring event."""

    index: int = Field(ge=0, description="Sequential record index starting from 0 (Genesis)")
    timestamp: str = Field(description="ISO 8601 UTC timestamp of record creation")
    did: str = Field(min_length=3, description="Decentralized Identifier (e.g. did:mesh:... or genesis)")
    doc_hash: str = Field(description="SHA-256 hex digest of the normalized DID Document")
    operation: LedgerOperation = Field(description="Identity operation type")
    previous_hash: str = Field(description="SHA-256 hash of the preceding record (or 64 zeroes for genesis)")
    record_hash: str = Field(description="SHA-256 hash of this record's canonical contents")
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-sensitive operational metadata"
    )

    @field_validator("doc_hash", "previous_hash", "record_hash")
    @classmethod
    def validate_sha256_hex(cls, value: str) -> str:
        """Ensure hash fields are exactly 64 hexadecimal characters."""
        if not SHA256_HEX_REGEX.match(value):
            raise ValueError(f"Value must be a valid 64-character SHA-256 hex string, got '{value}'")
        return value.lower()

    def get_hashable_payload(self) -> Dict[str, Any]:
        """Return the dictionary of fields that determine the record_hash.

        The record_hash itself is excluded because it is the product of hashing
        this exact payload.
        """
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "did": self.did,
            "doc_hash": self.doc_hash.lower(),
            "operation": self.operation.value,
            "previous_hash": self.previous_hash.lower(),
            "metadata": self.metadata,
        }


class RecordCreateInput(BaseModel):
    """Input payload to anchor a new DID record to the ledger."""

    did: str = Field(min_length=3, description="The Decentralized Identifier to anchor")
    doc_hash: str = Field(description="SHA-256 hex digest of the resolved DID Document")
    operation: LedgerOperation = Field(
        default=LedgerOperation.CREATE,
        description="Operation: CREATE, UPDATE, or DEACTIVATE"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-sensitive metadata (e.g., anchoring node id, version)"
    )

    @field_validator("doc_hash")
    @classmethod
    def validate_doc_hash(cls, value: str) -> str:
        if not SHA256_HEX_REGEX.match(value):
            raise ValueError(f"doc_hash must be a valid 64-character SHA-256 hex string, got '{value}'")
        return value.lower()
