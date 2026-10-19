"""Unit tests for SimulatedLedger chain operations (Milestone 2)."""

import unittest
from app.modules.ledger import (
    SimulatedLedger,
    LedgerOperation,
    GENESIS_PREVIOUS_HASH,
    verify_record_hash,
)


class TestLedgerChain(unittest.TestCase):
    """Test suite for chain creation, appending, and querying."""

    def setUp(self):
        self.ledger = SimulatedLedger(auto_genesis=True)
        self.alice_did = "did:mesh:key:z6MkuAliceKey1"
        self.bob_did = "did:mesh:key:z6MkuBobKey2"
        self.alice_hash_v1 = "1" * 64
        self.alice_hash_v2 = "2" * 64
        self.bob_hash_v1 = "3" * 64

    def test_genesis_block_creation(self):
        """Newly created ledger must contain a single valid genesis block."""
        self.assertEqual(len(self.ledger), 1)
        genesis = self.ledger.get_head()
        self.assertIsNotNone(genesis)
        self.assertEqual(genesis.index, 0)
        self.assertEqual(genesis.did, "did:mesh:genesis")
        self.assertEqual(genesis.operation, LedgerOperation.GENESIS)
        self.assertEqual(genesis.previous_hash, GENESIS_PREVIOUS_HASH)
        self.assertTrue(verify_record_hash(genesis))

    def test_append_record_linkage(self):
        """Appended records must correctly link to the previous record's hash."""
        genesis = self.ledger.get_head()

        # Append Alice
        rec_alice = self.ledger.append_record(
            did=self.alice_did,
            doc_hash=self.alice_hash_v1,
            operation=LedgerOperation.CREATE,
            metadata={"owner": "Alice"}
        )
        self.assertEqual(len(self.ledger), 2)
        self.assertEqual(rec_alice.index, 1)
        self.assertEqual(rec_alice.previous_hash, genesis.record_hash)
        self.assertTrue(verify_record_hash(rec_alice))

        # Append Bob
        rec_bob = self.ledger.append_record(
            did=self.bob_did,
            doc_hash=self.bob_hash_v1,
            operation=LedgerOperation.CREATE,
            metadata={"owner": "Bob"}
        )
        self.assertEqual(len(self.ledger), 3)
        self.assertEqual(rec_bob.index, 2)
        self.assertEqual(rec_bob.previous_hash, rec_alice.record_hash)
        self.assertTrue(verify_record_hash(rec_bob))

        # Append Alice Update
        rec_alice_update = self.ledger.append_record(
            did=self.alice_did,
            doc_hash=self.alice_hash_v2,
            operation=LedgerOperation.UPDATE,
            metadata={"version": 2}
        )
        self.assertEqual(len(self.ledger), 4)
        self.assertEqual(rec_alice_update.index, 3)
        self.assertEqual(rec_alice_update.previous_hash, rec_bob.record_hash)
        self.assertTrue(verify_record_hash(rec_alice_update))

    def test_query_did_records_and_latest(self):
        """get_records_by_did and get_latest_record must accurately track DID history."""
        self.ledger.append_record(self.alice_did, self.alice_hash_v1, LedgerOperation.CREATE)
        self.ledger.append_record(self.bob_did, self.bob_hash_v1, LedgerOperation.CREATE)
        self.ledger.append_record(self.alice_did, self.alice_hash_v2, LedgerOperation.UPDATE)

        # Alice should have 2 records in history
        alice_history = self.ledger.get_records_by_did(self.alice_did)
        self.assertEqual(len(alice_history), 2)
        self.assertEqual(alice_history[0].doc_hash, self.alice_hash_v1)
        self.assertEqual(alice_history[1].doc_hash, self.alice_hash_v2)

        # Latest Alice record must be the update
        latest_alice = self.ledger.get_latest_record(self.alice_did)
        self.assertIsNotNone(latest_alice)
        self.assertEqual(latest_alice.operation, LedgerOperation.UPDATE)
        self.assertEqual(latest_alice.doc_hash, self.alice_hash_v2)

        # Bob should have 1 record
        bob_history = self.ledger.get_records_by_did(self.bob_did)
        self.assertEqual(len(bob_history), 1)

        # Unknown DID must return empty list / None
        self.assertEqual(self.ledger.get_records_by_did("did:mesh:unknown"), [])
        self.assertIsNone(self.ledger.get_latest_record("did:mesh:unknown"))

    def test_get_record_by_index(self):
        """Index retrieval must return the expected record or None when out of bounds."""
        self.ledger.append_record(self.alice_did, self.alice_hash_v1)

        record_0 = self.ledger.get_record_by_index(0)
        record_1 = self.ledger.get_record_by_index(1)
        record_invalid = self.ledger.get_record_by_index(999)
        record_negative = self.ledger.get_record_by_index(-1)

        self.assertEqual(record_0.did, "did:mesh:genesis")
        self.assertEqual(record_1.did, self.alice_did)
        self.assertIsNone(record_invalid)
        self.assertIsNone(record_negative)

    def test_auto_genesis_disabled_recovers_on_append(self):
        """If auto_genesis is False, the first append automatically creates genesis first."""
        custom_ledger = SimulatedLedger(auto_genesis=False)
        self.assertEqual(len(custom_ledger), 0)
        self.assertIsNone(custom_ledger.get_head())

        # Appending should generate genesis (index 0) and then the new record (index 1)
        rec = custom_ledger.append_record(self.alice_did, self.alice_hash_v1)
        self.assertEqual(len(custom_ledger), 2)
        self.assertEqual(rec.index, 1)
        self.assertEqual(custom_ledger.get_record_by_index(0).index, 0)


if __name__ == "__main__":
    unittest.main()
