"""Unit tests for Ledger models, canonical serialization, and hashing logic (Milestone 1)."""

import unittest
from datetime import datetime, timezone
from pydantic import ValidationError

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


class TestLedgerModelsAndHasher(unittest.TestCase):
    """Test suite for Milestone 1 models and hasher verification."""

    def setUp(self):
        self.sample_did = "did:mesh:key:z6MkuTL1k4n4x8bQ9"
        self.sample_doc = {
            "id": self.sample_did,
            "authentication": [f"{self.sample_did}#keys-1"],
            "verificationMethod": [{
                "id": f"{self.sample_did}#keys-1",
                "type": "Ed25519VerificationKey2020",
                "publicKeyMultibase": "z6MkuTL1k4n4x8bQ9"
            }]
        }
        self.doc_hash = hash_did_document(self.sample_doc)

    def test_canonical_json_determinism(self):
        """Dicts with identical content but different key insertion orders must yield identical JSON."""
        dict_a = {"b": 2, "a": 1, "c": {"z": 9, "y": 8}}
        dict_b = {"a": 1, "c": {"y": 8, "z": 9}, "b": 2}

        json_a = canonical_json_dumps(dict_a)
        json_b = canonical_json_dumps(dict_b)

        self.assertEqual(json_a, json_b)
        self.assertEqual(calculate_sha256(json_a), calculate_sha256(json_b))
        # Ensure compact separators (no space after colon or comma)
        self.assertNotIn(": ", json_a)
        self.assertNotIn(", ", json_a)

    def test_sha256_output_format(self):
        """calculate_sha256 must return a 64-char lowercase hexadecimal string."""
        digest = calculate_sha256("test-content")
        self.assertEqual(len(digest), 64)
        self.assertTrue(digest.islower())
        self.assertTrue(all(c in "0123456789abcdef" for c in digest))

    def test_record_hash_computation_and_verification(self):
        """A validly constructed LedgerRecord must pass integrity verification."""
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {
            "index": 1,
            "timestamp": timestamp,
            "did": self.sample_did,
            "doc_hash": self.doc_hash,
            "operation": LedgerOperation.CREATE.value,
            "previous_hash": GENESIS_PREVIOUS_HASH,
            "metadata": {"version": "1.0"},
        }

        rec_hash = calculate_record_hash(payload)

        record = LedgerRecord(
            index=1,
            timestamp=timestamp,
            did=self.sample_did,
            doc_hash=self.doc_hash,
            operation=LedgerOperation.CREATE,
            previous_hash=GENESIS_PREVIOUS_HASH,
            record_hash=rec_hash,
            metadata={"version": "1.0"},
        )

        self.assertTrue(verify_record_hash(record))

    def test_tamper_detection_in_record(self):
        """Tampering with any payload attribute in a record must fail hash verification."""
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {
            "index": 1,
            "timestamp": timestamp,
            "did": self.sample_did,
            "doc_hash": self.doc_hash,
            "operation": LedgerOperation.CREATE.value,
            "previous_hash": GENESIS_PREVIOUS_HASH,
            "metadata": {},
        }
        rec_hash = calculate_record_hash(payload)

        # Tampered DID:
        tampered_record = LedgerRecord(
            index=1,
            timestamp=timestamp,
            did="did:mesh:key:ATTACKER",
            doc_hash=self.doc_hash,
            operation=LedgerOperation.CREATE,
            previous_hash=GENESIS_PREVIOUS_HASH,
            record_hash=rec_hash,  # old hash kept
            metadata={},
        )
        self.assertFalse(verify_record_hash(tampered_record))

        # Tampered doc_hash:
        fake_doc_hash = "f" * 64
        tampered_doc_record = LedgerRecord(
            index=1,
            timestamp=timestamp,
            did=self.sample_did,
            doc_hash=fake_doc_hash,
            operation=LedgerOperation.CREATE,
            previous_hash=GENESIS_PREVIOUS_HASH,
            record_hash=rec_hash,
            metadata={},
        )
        self.assertFalse(verify_record_hash(tampered_doc_record))

    def test_hash_format_validation_rejection(self):
        """Invalid SHA-256 strings (wrong length or characters) must be rejected by Pydantic."""
        timestamp = datetime.now(timezone.utc).isoformat()

        with self.assertRaises(ValidationError):
            LedgerRecord(
                index=1,
                timestamp=timestamp,
                did=self.sample_did,
                doc_hash="too-short",
                operation=LedgerOperation.CREATE,
                previous_hash=GENESIS_PREVIOUS_HASH,
                record_hash="a" * 64,
            )

        with self.assertRaises(ValidationError):
            RecordCreateInput(
                did=self.sample_did,
                doc_hash="invalid-non-hex-characters-!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
            )

    def test_record_create_input_normalization(self):
        """Uppercase hex hash must be normalized to lowercase."""
        upper_hash = ("A" * 32) + ("B" * 32)
        input_data = RecordCreateInput(
            did=self.sample_did,
            doc_hash=upper_hash,
            operation=LedgerOperation.CREATE,
        )
        self.assertEqual(input_data.doc_hash, upper_hash.lower())


if __name__ == "__main__":
    unittest.main()
