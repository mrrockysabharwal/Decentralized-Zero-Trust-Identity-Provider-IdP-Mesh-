"""Security and Tamper Detection unit tests for Simulated Blockchain Ledger (Milestone 3).

Proves that modifying historical records, altering identity hashes, or forging
intermediate block hashes breaks the cryptographic chain and is detected by verify_integrity().
"""

import unittest
from app.modules.ledger import (
    SimulatedLedger,
    LedgerOperation,
)


class TestLedgerTamperDetection(unittest.TestCase):
    """Test suite proving tamper-evident properties of the ledger."""

    def setUp(self):
        """Create a fresh ledger populated with multiple blocks."""
        self.ledger = SimulatedLedger(auto_genesis=True)
        self.alice_did = "did:mesh:key:z6MkuAliceKey1"
        self.bob_did = "did:mesh:key:z6MkuBobKey2"
        self.charlie_did = "did:mesh:key:z6MkuCharlieKey3"

        # Block 1
        self.ledger.append_record(
            did=self.alice_did,
            doc_hash="1" * 64,
            operation=LedgerOperation.CREATE,
            metadata={"user": "Alice"},
        )
        # Block 2
        self.ledger.append_record(
            did=self.bob_did,
            doc_hash="2" * 64,
            operation=LedgerOperation.CREATE,
            metadata={"user": "Bob"},
        )
        # Block 3
        self.ledger.append_record(
            did=self.charlie_did,
            doc_hash="3" * 64,
            operation=LedgerOperation.CREATE,
            metadata={"user": "Charlie"},
        )

    def test_unaltered_ledger_passes_verification(self):
        """A legitimately created ledger must pass integrity verification."""
        is_valid, error = self.ledger.verify_integrity()
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_tampering_historical_did_invalidates_chain(self):
        """Tampering with a DID in block #1 must be detected."""
        self.ledger.tamper_record(index=1, field="did", new_value="did:mesh:key:MalloryMalicious")
        
        is_valid, error = self.ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertIn("Data tampering detected at record #1", error)

    def test_tampering_historical_doc_hash_invalidates_chain(self):
        """Tampering with an identity document hash in block #2 must be detected."""
        malicious_doc_hash = "f" * 64
        self.ledger.tamper_record(index=2, field="doc_hash", new_value=malicious_doc_hash)

        is_valid, error = self.ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertIn("Data tampering detected at record #2", error)

    def test_tampering_with_recalculated_hash_breaks_linkage(self):
        """If an attacker modifies block #1 and recalculates its record_hash,
        block #2's previous_hash will not match, failing linkage check."""
        self.ledger.tamper_record(
            index=1,
            field="did",
            new_value="did:mesh:key:MalloryMalicious",
            recalculate_record_hash=True,
        )

        is_valid, error = self.ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertIn("Broken cryptographic hash linkage at index 2", error)
        self.assertIn("preceding record #1", error)

    def test_tampering_genesis_block(self):
        """Altering genesis block previous_hash or contents must be detected immediately."""
        self.ledger.tamper_record(
            index=0,
            field="previous_hash",
            new_value="e" * 64,
        )

        is_valid, error = self.ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertIn("Genesis block previous_hash must be", error)

    def test_tampering_non_sequential_index(self):
        """Altering a record's index must be detected by sequential index check."""
        self.ledger.tamper_record(index=2, field="index", new_value=99)

        is_valid, error = self.ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertIn("Non-sequential index at chain position 2", error)

    def test_tamper_out_of_bounds_raises_error(self):
        """Attempting to tamper with an invalid index raises IndexError."""
        with self.assertRaises(IndexError):
            self.ledger.tamper_record(index=999, field="did", new_value="fake")


if __name__ == "__main__":
    unittest.main()
