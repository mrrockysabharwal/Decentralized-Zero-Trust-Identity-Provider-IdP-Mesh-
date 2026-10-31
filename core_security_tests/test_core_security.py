"""Isolated tests for the framework-independent TrustMesh core."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core_security import ChallengeError, ChallengeService, CoreDIDService, CoreLedger, OwnershipError
from app.core_security.ledger import hash_document


def _public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes_raw()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _create_identity(service: CoreDIDService, key: Ed25519PrivateKey, metadata=None) -> str:
    public_key = _public_bytes(key)
    did = service.derive_did(public_key)
    request = {
        "public_key_b64": _b64url(public_key),
        "metadata": metadata or {},
    }
    challenge = service.create_creation_challenge(public_key, metadata=metadata)
    signature = key.sign(service.ownership_message(did, "DID_CREATE", request, challenge))
    return service.create_identity(
        public_key, challenge=challenge, signature=signature, metadata=metadata
    )


class CoreDIDSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = CoreLedger()
        self.challenges = ChallengeService()
        self.service = CoreDIDService(self.ledger, self.challenges)
        self.owner_key = Ed25519PrivateKey.generate()
        self.did = _create_identity(self.service, self.owner_key, metadata={"name": "Owner"})

    def test_creation_and_ed25519_identity_verification(self) -> None:
        message = b"TrustMesh identity proof"
        signature = self.owner_key.sign(message)
        self.assertTrue(self.service.verify_identity_signature(self.did, message, signature))
        self.assertFalse(self.service.verify_identity_signature(self.did, message + b"!", signature))
        self.assertEqual(self.ledger.records[-1].operation, "CREATE")
        self.assertEqual(self.ledger.verify_integrity(), (True, None))

    def test_creation_requires_proof_of_private_key_possession(self) -> None:
        attacker_key = Ed25519PrivateKey.generate()
        public_key = _public_bytes(attacker_key)
        did = self.service.derive_did(public_key)
        request = {"public_key_b64": _b64url(public_key), "metadata": {}}
        challenge = self.service.create_creation_challenge(public_key)
        wrong_key = Ed25519PrivateKey.generate()
        signature = wrong_key.sign(
            self.service.ownership_message(did, "DID_CREATE", request, challenge)
        )
        before = self.ledger.records
        with self.assertRaises(OwnershipError):
            self.service.create_identity(public_key, challenge=challenge, signature=signature)
        with self.assertRaises(LookupError):
            self.service.resolve(did)
        self.assertEqual(self.ledger.records, before)

    def test_successful_owner_update_rotates_controller_and_anchors(self) -> None:
        replacement_key = Ed25519PrivateKey.generate()
        metadata = {"name": "Updated owner", "purpose": "rotation"}
        request = {
            "new_public_key_b64": _b64url(_public_bytes(replacement_key)),
            "metadata": metadata,
        }
        challenge = self.service.create_update_challenge(
            self.did, _public_bytes(replacement_key), metadata=metadata
        )
        proof = self.owner_key.sign(
            self.service.ownership_message(self.did, "DID_UPDATE", request, challenge)
        )
        updated = self.service.update_identity(
            self.did, _public_bytes(replacement_key), challenge=challenge,
            signature=proof, metadata=metadata,
        )
        self.assertEqual(updated.revision, 1)
        self.assertEqual(updated.public_key_bytes, _public_bytes(replacement_key))
        self.assertEqual(self.ledger.records[-1].operation, "UPDATE")
        self.assertTrue(self.service.verify_identity_signature(
            self.did, b"new controller", replacement_key.sign(b"new controller")
        ))
        self.assertEqual(self.ledger.verify_integrity(), (True, None))

    def test_successful_owner_deactivation_is_audited(self) -> None:
        reason = "owner request"
        request = {"reason": reason}
        challenge = self.service.create_deactivation_challenge(self.did, reason=reason)
        signature = self.owner_key.sign(
            self.service.ownership_message(self.did, "DID_DEACTIVATE", request, challenge)
        )
        record = self.service.deactivate_identity(
            self.did, challenge=challenge, signature=signature, reason=reason
        )
        self.assertFalse(record.active)
        self.assertEqual(record.revision, 1)
        self.assertEqual(self.ledger.records[-1].operation, "DEACTIVATE")
        self.assertFalse(self.service.verify_identity_signature(self.did, b"x", b"bad"))
        self.assertEqual(self.ledger.verify_integrity(), (True, None))

    def test_invalid_deactivation_proof_leaves_registry_and_ledger_unchanged(self) -> None:
        reason = "must not apply"
        request = {"reason": reason}
        challenge = self.service.create_deactivation_challenge(self.did, reason=reason)
        attacker = Ed25519PrivateKey.generate()
        bad_signature = attacker.sign(
            self.service.ownership_message(self.did, "DID_DEACTIVATE", request, challenge)
        )
        before_record, before_ledger = self.service.resolve(self.did), self.ledger.records
        with self.assertRaises(OwnershipError):
            self.service.deactivate_identity(
                self.did, challenge=challenge, signature=bad_signature, reason=reason
            )
        self.assertEqual(self.service.resolve(self.did), before_record)
        self.assertEqual(self.ledger.records, before_ledger)
        self.assertEqual(self.ledger.verify_integrity(), (True, None))

    def test_invalid_signature_leaves_registry_and_ledger_unchanged(self) -> None:
        replacement_key = Ed25519PrivateKey.generate()
        metadata = {"name": "must not apply"}
        request = {
            "new_public_key_b64": _b64url(_public_bytes(replacement_key)),
            "metadata": metadata,
        }
        challenge = self.service.create_update_challenge(
            self.did, _public_bytes(replacement_key), metadata=metadata
        )
        attacker = Ed25519PrivateKey.generate()
        bad_signature = attacker.sign(
            self.service.ownership_message(self.did, "DID_UPDATE", request, challenge)
        )
        before_record = self.service.resolve(self.did)
        before_ledger = self.ledger.records
        with self.assertRaises(OwnershipError):
            self.service.update_identity(
                self.did, _public_bytes(replacement_key), challenge=challenge,
                signature=bad_signature, metadata=metadata,
            )
        self.assertEqual(self.service.resolve(self.did), before_record)
        self.assertEqual(self.ledger.records, before_ledger)
        self.assertEqual(self.ledger.verify_integrity(), (True, None))

    def test_request_binding_mismatch_is_rejected_without_mutation(self) -> None:
        replacement_key = Ed25519PrivateKey.generate()
        challenge = self.service.create_update_challenge(self.did, _public_bytes(replacement_key))
        before_record, before_ledger = self.service.resolve(self.did), self.ledger.records
        with self.assertRaises(OwnershipError):
            self.service.update_identity(
                self.did, _public_bytes(replacement_key), challenge=challenge,
                signature=b"", metadata={"changed": True},
            )
        self.assertEqual(self.service.resolve(self.did), before_record)
        self.assertEqual(self.ledger.records, before_ledger)

    def test_replayed_update_challenge_is_rejected(self) -> None:
        replacement_key = Ed25519PrivateKey.generate()
        metadata = {"revision_note": "rotate"}
        request = {
            "new_public_key_b64": _b64url(_public_bytes(replacement_key)),
            "metadata": metadata,
        }
        challenge = self.service.create_update_challenge(
            self.did, _public_bytes(replacement_key), metadata=metadata
        )
        signature = self.owner_key.sign(
            self.service.ownership_message(self.did, "DID_UPDATE", request, challenge)
        )
        self.service.update_identity(
            self.did, _public_bytes(replacement_key), challenge=challenge,
            signature=signature, metadata=metadata,
        )
        after_success = self.ledger.records
        with self.assertRaises(OwnershipError):
            self.service.update_identity(
                self.did, _public_bytes(replacement_key), challenge=challenge,
                signature=signature, metadata=metadata,
            )
        self.assertEqual(self.ledger.records, after_success)

    def test_expired_update_challenge_is_rejected(self) -> None:
        now = [100.0]
        challenges = ChallengeService(ttl_seconds=300, clock=lambda: now[0])
        service = CoreDIDService(self.ledger, challenges)
        _create_identity(service, self.owner_key)
        replacement_key = Ed25519PrivateKey.generate()
        metadata = {"expired": True}
        request = {
            "new_public_key_b64": _b64url(_public_bytes(replacement_key)),
            "metadata": metadata,
        }
        challenge = service.create_update_challenge(
            self.did, _public_bytes(replacement_key), metadata=metadata
        )
        signature = self.owner_key.sign(
            service.ownership_message(self.did, "DID_UPDATE", request, challenge)
        )
        before_record, before_ledger = service.resolve(self.did), self.ledger.records
        now[0] += 300
        with self.assertRaises(OwnershipError):
            service.update_identity(
                self.did, _public_bytes(replacement_key), challenge=challenge,
                signature=signature, metadata=metadata,
            )
        self.assertEqual(service.resolve(self.did), before_record)
        self.assertEqual(self.ledger.records, before_ledger)


class CoreChallengeAndLedgerTests(unittest.TestCase):
    def test_challenge_is_single_use_and_bound_to_subject_operation_request(self) -> None:
        challenges = ChallengeService()
        challenge = challenges.issue("did:mesh:test", "UPDATE", {"revision": 2})
        with self.assertRaises(ChallengeError):
            challenges.consume(challenge, "did:mesh:other", "UPDATE", {"revision": 2})
        with self.assertRaises(ChallengeError):
            challenges.consume(challenge, "did:mesh:test", "UPDATE", {"revision": 2})

        operation_challenge = challenges.issue("did:mesh:test", "UPDATE", {"revision": 2})
        with self.assertRaises(ChallengeError):
            challenges.consume(operation_challenge, "did:mesh:test", "DEACTIVATE", {"revision": 2})

        request_challenge = challenges.issue("did:mesh:test", "UPDATE", {"revision": 2})
        with self.assertRaises(ChallengeError):
            challenges.consume(request_challenge, "did:mesh:test", "UPDATE", {"revision": 3})

    def test_ledger_append_integrity_and_isolated_tamper_detection(self) -> None:
        ledger = CoreLedger()
        ledger.append_record(
            did="did:mesh:test", doc_hash=hash_document({"id": "did:mesh:test"}),
            operation="ANCHOR", metadata={"source": "unit test"},
        )
        self.assertEqual(ledger.verify_integrity(), (True, None))
        tampered = ledger.tampered_copy_for_testing(1, "doc_hash", "f" * 64)
        self.assertFalse(tampered.verify_integrity()[0])
        self.assertEqual(ledger.verify_integrity(), (True, None))
        self.assertEqual(len(ledger), 2)

    def test_records_and_metadata_are_not_mutable_through_public_views(self) -> None:
        ledger = CoreLedger()
        ledger.append_record(
            did="did:mesh:test", doc_hash=hash_document({"id": "did:mesh:test"}),
            operation="ANCHOR", metadata={"safe": True},
        )
        exposed = ledger.records[-1].metadata
        exposed["safe"] = False
        self.assertTrue(ledger.verify_integrity()[0])
        self.assertTrue(ledger.records[-1].metadata["safe"])


class CoreImportIsolationTests(unittest.TestCase):
    def test_core_imports_in_clean_process_without_token_or_framework_modules(self) -> None:
        script = """
import sys
import app.core_security
for name in ('fastapi', 'app.modules.admin', 'app.modules.tokens', 'app.modules.webauthn'):
    assert not any(key == name or key.startswith(name + '.') for key in sys.modules), name
print('core imports cleanly')
"""
        environment = os.environ.copy()
        environment.pop("TOKEN_KEY_DIR", None)
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=os.path.dirname(os.path.dirname(__file__)),
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "core imports cleanly")


if __name__ == "__main__":
    unittest.main()
