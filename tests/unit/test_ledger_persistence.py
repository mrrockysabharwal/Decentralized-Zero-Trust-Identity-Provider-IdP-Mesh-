"""Unit tests for SimulatedLedger JSON persistence (Milestone 4)."""

import json
import os
import tempfile
import unittest
from app.modules.ledger import (
    SimulatedLedger,
    LedgerOperation,
)


class TestLedgerPersistence(unittest.TestCase):
    """Test suite verifying file serialization, reloading, and corrupt-state protection."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.file_path = os.path.join(self.temp_dir.name, "test_ledger.json")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_and_reload_clean_ledger(self):
        """A saved ledger must reload completely and pass integrity verification."""
        ledger1 = SimulatedLedger(auto_genesis=True)
        ledger1.append_record(
            did="did:mesh:key:z6MkuAlice",
            doc_hash="a" * 64,
            operation=LedgerOperation.CREATE,
            metadata={"name": "Alice"}
        )
        ledger1.append_record(
            did="did:mesh:key:z6MkuBob",
            doc_hash="b" * 64,
            operation=LedgerOperation.CREATE,
            metadata={"name": "Bob"}
        )

        ledger1.save_to_file(self.file_path)
        self.assertTrue(os.path.exists(self.file_path))

        # Reload in a separate instance
        ledger2 = SimulatedLedger(auto_genesis=False)
        ledger2.load_from_file(self.file_path)

        self.assertEqual(len(ledger2), 3)
        self.assertEqual(ledger2.get_record_by_index(1).did, "did:mesh:key:z6MkuAlice")
        self.assertEqual(ledger2.get_record_by_index(2).did, "did:mesh:key:z6MkuBob")

        is_valid, error = ledger2.verify_integrity()
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_auto_save_on_append(self):
        """When storage_path is specified, append_record automatically persists to disk."""
        ledger = SimulatedLedger(auto_genesis=True, storage_path=self.file_path)
        self.assertTrue(os.path.exists(self.file_path))

        ledger.append_record("did:mesh:key:z6MkuAutoSave", "c" * 64)

        # Inspect raw JSON file directly
        with open(self.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data), 2)
        self.assertEqual(data[1]["did"], "did:mesh:key:z6MkuAutoSave")

    def test_load_corrupted_file_raises_value_error(self):
        """Loading a file that has been modified on disk must be rejected by integrity check."""
        ledger = SimulatedLedger(auto_genesis=True, storage_path=self.file_path)
        ledger.append_record("did:mesh:key:z6MkuLegit", "d" * 64)

        # Maliciously modify the file on disk
        with open(self.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data[1]["did"] = "did:mesh:key:z6MkuAttacker"
        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        # Attempting to load into another ledger instance must fail
        new_ledger = SimulatedLedger(auto_genesis=False)
        with self.assertRaises(ValueError) as ctx:
            new_ledger.load_from_file(self.file_path)
        self.assertIn("Integrity check failed", str(ctx.exception))

    def test_load_nonexistent_file_raises_filenotfound(self):
        """Attempting to load a non-existent path raises FileNotFoundError."""
        ledger = SimulatedLedger(auto_genesis=False)
        with self.assertRaises(FileNotFoundError):
            ledger.load_from_file("non_existent_file_path.json")


if __name__ == "__main__":
    unittest.main()
