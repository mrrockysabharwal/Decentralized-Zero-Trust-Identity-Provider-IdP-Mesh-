"""
tests/unit/test_identity.py — Unit Tests for the Ed25519 & DID Identity Module
================================================================================
Owner  : Member 3 (DID Registry & Cryptography)
Branch : feature/identity-module

Test coverage
-------------
Ed25519Service:
  ✓ Key pair generation — types, sizes
  ✓ Round-trip serialisation (bytes → key object → bytes)
  ✓ Signing — produces 64-byte signature
  ✓ Verification — valid signature accepted
  ✓ Verification — tampered message rejected
  ✓ Verification — wrong key rejected
  ✓ Verification — corrupted signature rejected
  ✓ Type enforcement on sign() and verify()
  ✓ Private key round-trip bytes

DIDService:
  ✓ DID creation — correct format `did:mesh:key:<id>`
  ✓ DID creation — idempotent (same key → same DID)
  ✓ DID creation — different keys → different DIDs
  ✓ DID Document — W3C structure and fields
  ✓ DID Document — build_did_document() invalid input
  ✓ DID resolution — success path
  ✓ DID resolution — unknown DID raises DIDResolutionError
  ✓ DID resolution — empty / None / malformed raises ValueError
  ✓ DID deactivation
  ✓ did_exists() and list_dids()
  ✓ registry_reset() clears all state
"""

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.modules.identity.ed25519_service import Ed25519Service
from app.modules.identity.did_service import (
    DIDService,
    DIDResolutionError,
    _did_registry,          # imported for direct inspection in one test
)


# ===========================================================================
# Ed25519Service Tests
# ===========================================================================

class TestEd25519KeyGeneration(unittest.TestCase):
    """Tests for generate_key_pair()."""

    def test_returns_private_and_public_key_objects(self):
        """generate_key_pair must return the correct cryptography types."""
        priv, pub = Ed25519Service.generate_key_pair()
        self.assertIsInstance(priv, Ed25519PrivateKey)
        self.assertIsInstance(pub, Ed25519PublicKey)

    def test_public_key_is_derived_from_private_key(self):
        """The returned public key must match the one derived from the private key."""
        priv, pub = Ed25519Service.generate_key_pair()
        derived_pub = priv.public_key()
        self.assertEqual(
            Ed25519Service.public_key_to_bytes(pub),
            Ed25519Service.public_key_to_bytes(derived_pub),
        )

    def test_public_key_raw_length_is_32_bytes(self):
        """Ed25519 raw public key is always exactly 32 bytes."""
        _, pub = Ed25519Service.generate_key_pair()
        raw = Ed25519Service.public_key_to_bytes(pub)
        self.assertEqual(len(raw), 32)

    def test_private_key_raw_length_is_32_bytes(self):
        """Ed25519 raw private key seed is always exactly 32 bytes."""
        priv, _ = Ed25519Service.generate_key_pair()
        raw = Ed25519Service.private_key_to_bytes(priv)
        self.assertEqual(len(raw), 32)

    def test_each_call_generates_unique_keys(self):
        """Consecutive calls should not produce the same key pair."""
        _, pub1 = Ed25519Service.generate_key_pair()
        _, pub2 = Ed25519Service.generate_key_pair()
        self.assertNotEqual(
            Ed25519Service.public_key_to_bytes(pub1),
            Ed25519Service.public_key_to_bytes(pub2),
        )


class TestEd25519Serialisation(unittest.TestCase):
    """Tests for key serialisation / deserialisation round-trips."""

    def setUp(self):
        self.priv, self.pub = Ed25519Service.generate_key_pair()

    def test_public_key_round_trip(self):
        """Bytes → public_key_from_bytes → bytes must be identical."""
        raw = Ed25519Service.public_key_to_bytes(self.pub)
        recovered = Ed25519Service.public_key_from_bytes(raw)
        self.assertEqual(raw, Ed25519Service.public_key_to_bytes(recovered))

    def test_private_key_round_trip(self):
        """Bytes → private_key_from_bytes → sign → verify must succeed."""
        raw = Ed25519Service.private_key_to_bytes(self.priv)
        recovered_priv = Ed25519Service.private_key_from_bytes(raw)
        msg = b"round-trip check"
        sig = Ed25519Service.sign(recovered_priv, msg)
        self.assertTrue(Ed25519Service.verify(self.pub, msg, sig))

    def test_public_key_from_bytes_wrong_length_raises(self):
        """public_key_from_bytes must raise ValueError for non-32-byte input."""
        with self.assertRaises(ValueError):
            Ed25519Service.public_key_from_bytes(b"\x00" * 16)

    def test_private_key_from_bytes_wrong_length_raises(self):
        """private_key_from_bytes must raise ValueError for non-32-byte input."""
        with self.assertRaises(ValueError):
            Ed25519Service.private_key_from_bytes(b"\x00" * 64)


class TestEd25519Signing(unittest.TestCase):
    """Tests for sign() and verify()."""

    def setUp(self):
        self.priv, self.pub = Ed25519Service.generate_key_pair()
        self.message = b"hello, decentralized world"

    # ------------------------------------------------------------------
    # sign()
    # ------------------------------------------------------------------

    def test_sign_returns_64_byte_signature(self):
        """Ed25519 signatures are always 64 bytes."""
        sig = Ed25519Service.sign(self.priv, self.message)
        self.assertEqual(len(sig), 64)

    def test_sign_rejects_non_bytes_message(self):
        """sign() must raise TypeError when message is not bytes."""
        with self.assertRaises(TypeError):
            Ed25519Service.sign(self.priv, "not bytes")  # type: ignore

    def test_sign_empty_message(self):
        """Signing an empty byte string should succeed."""
        sig = Ed25519Service.sign(self.priv, b"")
        self.assertEqual(len(sig), 64)

    # ------------------------------------------------------------------
    # verify() — valid signatures
    # ------------------------------------------------------------------

    def test_verify_returns_true_for_valid_signature(self):
        """A signature produced by sign() must be accepted by verify()."""
        sig = Ed25519Service.sign(self.priv, self.message)
        result = Ed25519Service.verify(self.pub, self.message, sig)
        self.assertTrue(result)

    def test_verify_different_messages_same_key(self):
        """Multiple distinct messages can be signed and verified independently."""
        messages = [b"msg1", b"msg2", b"msg3", b"A" * 1000]
        for msg in messages:
            sig = Ed25519Service.sign(self.priv, msg)
            with self.subTest(msg=msg):
                self.assertTrue(Ed25519Service.verify(self.pub, msg, sig))

    # ------------------------------------------------------------------
    # verify() — INVALID signatures (must return False)
    # ------------------------------------------------------------------

    def test_verify_returns_false_for_tampered_message(self):
        """Changing the message after signing must invalidate the signature."""
        sig = Ed25519Service.sign(self.priv, self.message)
        tampered = self.message + b" (tampered)"
        result = Ed25519Service.verify(self.pub, tampered, sig)
        self.assertFalse(result)

    def test_verify_returns_false_for_wrong_public_key(self):
        """A signature from key-A must not verify under key-B."""
        _, other_pub = Ed25519Service.generate_key_pair()
        sig = Ed25519Service.sign(self.priv, self.message)
        result = Ed25519Service.verify(other_pub, self.message, sig)
        self.assertFalse(result)

    def test_verify_returns_false_for_corrupted_signature(self):
        """Flipping one bit in the signature must cause verification failure."""
        sig = Ed25519Service.sign(self.priv, self.message)
        corrupted = bytearray(sig)
        corrupted[0] ^= 0xFF          # flip first byte
        result = Ed25519Service.verify(self.pub, self.message, bytes(corrupted))
        self.assertFalse(result)

    def test_verify_returns_false_for_all_zeros_signature(self):
        """An all-zero signature (clearly invalid) must be rejected."""
        result = Ed25519Service.verify(self.pub, self.message, b"\x00" * 64)
        self.assertFalse(result)

    def test_verify_returns_false_for_wrong_key_and_tampered_message(self):
        """Both wrong key AND tampered message: must still return False."""
        _, other_pub = Ed25519Service.generate_key_pair()
        sig = Ed25519Service.sign(self.priv, self.message)
        result = Ed25519Service.verify(other_pub, b"totally different", sig)
        self.assertFalse(result)

    # ------------------------------------------------------------------
    # verify() — type enforcement
    # ------------------------------------------------------------------

    def test_verify_rejects_non_bytes_message(self):
        """verify() must raise TypeError when message is not bytes."""
        sig = Ed25519Service.sign(self.priv, self.message)
        with self.assertRaises(TypeError):
            Ed25519Service.verify(self.pub, "not bytes", sig)  # type: ignore

    def test_verify_rejects_non_bytes_signature(self):
        """verify() must raise TypeError when signature is not bytes."""
        with self.assertRaises(TypeError):
            Ed25519Service.verify(self.pub, self.message, 12345)  # type: ignore


# ===========================================================================
# DIDService Tests
# ===========================================================================

class TestDIDServiceBase(unittest.TestCase):
    """Base class: resets the DID registry before every test."""

    def setUp(self):
        DIDService.registry_reset()
        self.priv, self.pub = Ed25519Service.generate_key_pair()


class TestDIDCreation(TestDIDServiceBase):
    """Tests for create_did()."""

    def test_did_format_is_correct(self):
        """Created DID must follow the `did:mesh:key:<hex16>` format."""
        did = DIDService.create_did(self.pub)
        parts = did.split(":")
        self.assertEqual(len(parts), 4)
        self.assertEqual(parts[0], "did")
        self.assertEqual(parts[1], "mesh")
        self.assertEqual(parts[2], "key")
        self.assertEqual(len(parts[3]), 16)         # SHA-256[:16]

    def test_did_is_registered_after_creation(self):
        """After create_did(), did_exists() must return True."""
        did = DIDService.create_did(self.pub)
        self.assertTrue(DIDService.did_exists(did))

    def test_create_did_is_idempotent(self):
        """Calling create_did() twice with the same key returns the same DID."""
        did1 = DIDService.create_did(self.pub)
        did2 = DIDService.create_did(self.pub)
        self.assertEqual(did1, did2)
        # Registry should have only one entry for this key
        self.assertEqual(len(DIDService.list_dids()), 1)

    def test_different_keys_produce_different_dids(self):
        """Two distinct public keys must produce two distinct DIDs."""
        _, pub2 = Ed25519Service.generate_key_pair()
        did1 = DIDService.create_did(self.pub)
        did2 = DIDService.create_did(pub2)
        self.assertNotEqual(did1, did2)

    def test_list_dids_grows_with_each_new_key(self):
        """list_dids() should track all created DIDs."""
        self.assertEqual(DIDService.list_dids(), [])
        DIDService.create_did(self.pub)
        self.assertEqual(len(DIDService.list_dids()), 1)
        _, pub2 = Ed25519Service.generate_key_pair()
        DIDService.create_did(pub2)
        self.assertEqual(len(DIDService.list_dids()), 2)


class TestDIDDocumentStructure(TestDIDServiceBase):
    """Tests for build_did_document() and the DID Document structure."""

    def setUp(self):
        super().setUp()
        self.did = DIDService.create_did(self.pub)
        self.doc = DIDService.resolve_did(self.did)

    def test_document_has_context(self):
        """DID Document must have @context with W3C DID v1."""
        self.assertIn("@context", self.doc)
        self.assertIn("https://www.w3.org/ns/did/v1", self.doc["@context"])

    def test_document_id_matches_did(self):
        """DID Document id field must equal the DID."""
        self.assertEqual(self.doc["id"], self.did)

    def test_document_controller_matches_did(self):
        """Controller must be the DID itself (self-sovereign)."""
        self.assertEqual(self.doc["controller"], self.did)

    def test_document_has_verification_method(self):
        """DID Document must contain at least one verificationMethod."""
        self.assertIn("verificationMethod", self.doc)
        self.assertIsInstance(self.doc["verificationMethod"], list)
        self.assertGreater(len(self.doc["verificationMethod"]), 0)

    def test_verification_method_type(self):
        """Verification method type must be Ed25519VerificationKey2020."""
        vm = self.doc["verificationMethod"][0]
        self.assertEqual(vm["type"], "Ed25519VerificationKey2020")

    def test_verification_method_has_public_key_multibase(self):
        """Verification method must contain publicKeyMultibase starting with 'z'."""
        vm = self.doc["verificationMethod"][0]
        self.assertIn("publicKeyMultibase", vm)
        self.assertTrue(vm["publicKeyMultibase"].startswith("z"))

    def test_verification_method_contains_no_private_key(self):
        """No private key material should appear anywhere in the DID Document."""
        import json
        doc_str = json.dumps(self.doc)
        self.assertNotIn("privateKey", doc_str)
        self.assertNotIn("private_key", doc_str)
        self.assertNotIn("secretKey", doc_str)

    def test_document_has_authentication_and_assertion(self):
        """DID Document must have authentication and assertionMethod arrays."""
        self.assertIn("authentication", self.doc)
        self.assertIn("assertionMethod", self.doc)
        self.assertIsInstance(self.doc["authentication"], list)
        self.assertIsInstance(self.doc["assertionMethod"], list)

    def test_document_has_timestamps(self):
        """DID Document must have created and updated timestamps."""
        self.assertIn("created", self.doc)
        self.assertIn("updated", self.doc)

    def test_build_did_document_raises_for_empty_did(self):
        """build_did_document() must raise ValueError for an empty DID."""
        with self.assertRaises(ValueError):
            DIDService.build_did_document("", self.pub)

    def test_build_did_document_raises_for_malformed_did(self):
        """build_did_document() must raise ValueError for a DID not starting with 'did:'."""
        with self.assertRaises(ValueError):
            DIDService.build_did_document("notadid:something", self.pub)


class TestDIDResolution(TestDIDServiceBase):
    """Tests for resolve_did()."""

    def test_resolve_returns_did_document(self):
        """resolve_did() must return the same document stored at creation."""
        did = DIDService.create_did(self.pub)
        doc = DIDService.resolve_did(did)
        self.assertEqual(doc["id"], did)

    def test_resolve_unknown_did_raises_resolution_error(self):
        """Resolving a DID that was never registered must raise DIDResolutionError."""
        with self.assertRaises(DIDResolutionError):
            DIDService.resolve_did("did:mesh:key:nonexistent0000")

    def test_resolve_empty_string_raises_value_error(self):
        """resolve_did('') must raise ValueError."""
        with self.assertRaises(ValueError):
            DIDService.resolve_did("")

    def test_resolve_none_raises_value_error(self):
        """resolve_did(None) must raise ValueError."""
        with self.assertRaises(ValueError):
            DIDService.resolve_did(None)  # type: ignore

    def test_resolve_malformed_did_raises_value_error(self):
        """resolve_did() with a string not starting with 'did:' must raise ValueError."""
        with self.assertRaises(ValueError):
            DIDService.resolve_did("thisisnotadid")

    def test_resolve_whitespace_only_raises_value_error(self):
        """resolve_did() with whitespace-only string must raise ValueError."""
        with self.assertRaises(ValueError):
            DIDService.resolve_did("   ")

    def test_resolve_strips_surrounding_whitespace(self):
        """resolve_did() should normalise leading/trailing whitespace and still resolve."""
        did = DIDService.create_did(self.pub)
        doc = DIDService.resolve_did(f"  {did}  ")
        self.assertEqual(doc["id"], did)


class TestDIDDeactivation(TestDIDServiceBase):
    """Tests for deactivate_did()."""

    def test_deactivate_marks_document(self):
        """Deactivated DID Document must have deactivated=True."""
        did = DIDService.create_did(self.pub)
        DIDService.deactivate_did(did)
        doc = DIDService.resolve_did(did)
        self.assertTrue(doc.get("deactivated", False))

    def test_deactivate_unknown_did_raises(self):
        """Deactivating a non-existent DID must raise DIDResolutionError."""
        with self.assertRaises(DIDResolutionError):
            DIDService.deactivate_did("did:mesh:key:doesnotexist")

    def test_deactivated_did_still_resolvable(self):
        """Deactivated DIDs remain in registry and are still resolvable (audit trail)."""
        did = DIDService.create_did(self.pub)
        DIDService.deactivate_did(did)
        # Should NOT raise — just returns the document with deactivated=True
        doc = DIDService.resolve_did(did)
        self.assertIsNotNone(doc)


class TestRegistryReset(TestDIDServiceBase):
    """Tests for registry_reset() — used to isolate unit tests."""

    def test_reset_clears_all_dids(self):
        """registry_reset() must empty the registry completely."""
        DIDService.create_did(self.pub)
        self.assertGreater(len(DIDService.list_dids()), 0)
        DIDService.registry_reset()
        self.assertEqual(DIDService.list_dids(), [])

    def test_did_exists_returns_false_after_reset(self):
        """After reset, did_exists() must return False for previously registered DIDs."""
        did = DIDService.create_did(self.pub)
        DIDService.registry_reset()
        self.assertFalse(DIDService.did_exists(did))


# ===========================================================================
# Integration: Ed25519 + DID round-trip
# ===========================================================================

class TestIdentityIntegration(unittest.TestCase):
    """End-to-end flow: generate keys → create DID → sign → verify via DID doc."""

    def setUp(self):
        DIDService.registry_reset()

    def test_full_identity_flow(self):
        """Generate keys, create DID, sign a challenge, verify using DID doc key."""
        # 1. Generate key pair
        priv, pub = Ed25519Service.generate_key_pair()

        # 2. Create DID
        did = DIDService.create_did(pub)
        self.assertTrue(did.startswith("did:mesh:key:"))

        # 3. Resolve DID document and extract the public key
        doc = DIDService.resolve_did(did)
        vm = doc["verificationMethod"][0]
        multibase_pub_key = vm["publicKeyMultibase"]

        # 4. Sign an authentication challenge
        challenge = b"authenticate:user:session:abc123"
        signature = Ed25519Service.sign(priv, challenge)

        # 5. Verify using the public key from the DID Document
        #    (simulate what a verifier does — they only have the DID doc)
        raw_pub_bytes = DIDService._base58btc_decode(multibase_pub_key[1:])  # strip 'z'
        recovered_pub = Ed25519Service.public_key_from_bytes(raw_pub_bytes)
        is_valid = Ed25519Service.verify(recovered_pub, challenge, signature)

        self.assertTrue(is_valid)

    def test_tampered_challenge_fails_in_integration(self):
        """Integration: a tampered challenge must not verify under the DID's key."""
        priv, pub = Ed25519Service.generate_key_pair()
        did = DIDService.create_did(pub)
        doc = DIDService.resolve_did(did)
        vm = doc["verificationMethod"][0]
        multibase_pub_key = vm["publicKeyMultibase"]

        challenge = b"authenticate:user:session:xyz789"
        signature = Ed25519Service.sign(priv, challenge)

        raw_pub_bytes = DIDService._base58btc_decode(multibase_pub_key[1:])
        recovered_pub = Ed25519Service.public_key_from_bytes(raw_pub_bytes)

        # Tamper the challenge
        is_valid = Ed25519Service.verify(recovered_pub, b"tampered challenge!!", signature)
        self.assertFalse(is_valid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
