"""Framework-independent Ed25519 DID registry and ownership operations."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from dataclasses import dataclass, replace
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core_security.challenges import ChallengeError, ChallengeService, canonical_json_bytes
from app.core_security.ledger import CoreLedger, hash_document


class DIDNotFoundError(LookupError):
    """The requested DID is not registered in this core service."""


class OwnershipError(PermissionError):
    """The DID controller proof is invalid, expired, replayed, or unauthorized."""


@dataclass(frozen=True)
class CoreDIDRecord:
    did: str
    public_key_bytes: bytes
    active: bool
    revision: int
    metadata_json: str

    @property
    def metadata(self) -> dict[str, Any]:
        return json.loads(self.metadata_json)


class CoreDIDService:
    """Manage in-memory DIDs with controller-authorized, audited mutations."""

    _DOMAIN = "TrustMesh-Core-DID-Mutation-v1"

    def __init__(self, ledger: CoreLedger, challenges: ChallengeService | None = None) -> None:
        self.ledger = ledger
        self.challenges = challenges or ChallengeService(ttl_seconds=300)
        self._registry: dict[str, CoreDIDRecord] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _validate_public_key(public_key_bytes: bytes) -> Ed25519PublicKey:
        if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
            raise ValueError("Ed25519 public keys must be exactly 32 raw bytes.")
        return Ed25519PublicKey.from_public_bytes(public_key_bytes)

    @staticmethod
    def _public_key_b64(public_key_bytes: bytes) -> str:
        return base64.urlsafe_b64encode(public_key_bytes).rstrip(b"=").decode("ascii")

    @staticmethod
    def _metadata_json(metadata: Mapping[str, Any] | None) -> str:
        value = dict(metadata or {})
        return canonical_json_bytes(value).decode("utf-8")

    @classmethod
    def ownership_message(
        cls,
        did: str,
        operation: str,
        request: Mapping[str, Any],
        challenge: str,
    ) -> bytes:
        return canonical_json_bytes({
            "domain": cls._DOMAIN,
            "did": did,
            "operation": operation,
            "request": dict(request),
            "challenge": challenge,
        })

    @staticmethod
    def _document(record: CoreDIDRecord) -> dict[str, Any]:
        return {
            "id": record.did,
            "controller": record.did,
            "controller_public_key_b64": CoreDIDService._public_key_b64(record.public_key_bytes),
            "active": record.active,
            "revision": record.revision,
            "metadata": record.metadata,
        }

    @staticmethod
    def derive_did(public_key_bytes: bytes) -> str:
        CoreDIDService._validate_public_key(public_key_bytes)
        suffix = hashlib.sha256(public_key_bytes).hexdigest()[:16]
        return f"did:mesh:key:{suffix}"

    def create_creation_challenge(
        self,
        public_key_bytes: bytes,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        """Challenge a proposed controller to prove key possession at creation."""
        did = self.derive_did(public_key_bytes)
        request = {
            "public_key_b64": self._public_key_b64(public_key_bytes),
            "metadata": json.loads(self._metadata_json(metadata)),
        }
        return self.challenges.issue(did, "DID_CREATE", request)

    def create_identity(
        self,
        public_key_bytes: bytes,
        *,
        challenge: str,
        signature: bytes,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        """Register a DID only after proving possession of its controller key."""
        public_key = self._validate_public_key(public_key_bytes)
        metadata_json = self._metadata_json(metadata)
        did = self.derive_did(public_key_bytes)
        request = {
            "public_key_b64": self._public_key_b64(public_key_bytes),
            "metadata": json.loads(metadata_json),
        }
        record = CoreDIDRecord(did, bytes(public_key_bytes), True, 0, metadata_json)
        with self._lock:
            if did in self._registry:
                raise ValueError("This public key is already registered.")
            try:
                self.challenges.consume(challenge, did, "DID_CREATE", request)
                public_key.verify(
                    signature,
                    self.ownership_message(did, "DID_CREATE", request, challenge),
                )
            except ChallengeError as exc:
                raise OwnershipError(str(exc)) from exc
            except (InvalidSignature, ValueError, TypeError) as exc:
                raise OwnershipError("DID creation signature is invalid.") from exc
            self.ledger.append_record(
                did=did,
                doc_hash=hash_document(self._document(record)),
                operation="CREATE",
                metadata={"source": "core_did_service"},
            )
            self._registry[did] = record
        return did

    def resolve(self, did: str, *, require_active: bool = False) -> CoreDIDRecord:
        with self._lock:
            record = self._registry.get(did)
        if record is None:
            raise DIDNotFoundError(did)
        if require_active and not record.active:
            raise OwnershipError("Inactive DIDs cannot perform this operation.")
        return record

    def verify_identity_signature(self, did: str, message: bytes, signature: bytes) -> bool:
        try:
            record = self.resolve(did, require_active=True)
            self._validate_public_key(record.public_key_bytes).verify(signature, message)
            return True
        except (DIDNotFoundError, OwnershipError, InvalidSignature, ValueError, TypeError):
            return False

    def create_update_challenge(
        self,
        did: str,
        new_public_key_bytes: bytes,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        self.resolve(did, require_active=True)
        self._validate_public_key(new_public_key_bytes)
        request = {
            "new_public_key_b64": self._public_key_b64(new_public_key_bytes),
            "metadata": json.loads(self._metadata_json(metadata)),
        }
        return self.challenges.issue(did, "DID_UPDATE", request)

    def create_deactivation_challenge(self, did: str, *, reason: str = "") -> str:
        self.resolve(did, require_active=True)
        return self.challenges.issue(did, "DID_DEACTIVATE", {"reason": reason})

    def update_identity(
        self,
        did: str,
        new_public_key_bytes: bytes,
        *,
        challenge: str,
        signature: bytes,
        metadata: Mapping[str, Any] | None = None,
    ) -> CoreDIDRecord:
        self._validate_public_key(new_public_key_bytes)
        request = {
            "new_public_key_b64": self._public_key_b64(new_public_key_bytes),
            "metadata": json.loads(self._metadata_json(metadata)),
        }
        with self._lock:
            current = self.resolve(did, require_active=True)
            self._verify_ownership(current, did, "DID_UPDATE", request, challenge, signature)
            updated = replace(
                current,
                public_key_bytes=bytes(new_public_key_bytes),
                revision=current.revision + 1,
                metadata_json=self._metadata_json(metadata),
            )
            self.ledger.append_record(
                did=did,
                doc_hash=hash_document(self._document(updated)),
                operation="UPDATE",
                metadata={"source": "core_did_service", "revision": updated.revision},
            )
            self._registry[did] = updated
            return updated

    def deactivate_identity(
        self,
        did: str,
        *,
        challenge: str,
        signature: bytes,
        reason: str = "",
    ) -> CoreDIDRecord:
        request = {"reason": reason}
        with self._lock:
            current = self.resolve(did, require_active=True)
            self._verify_ownership(current, did, "DID_DEACTIVATE", request, challenge, signature)
            updated = replace(current, active=False, revision=current.revision + 1)
            self.ledger.append_record(
                did=did,
                doc_hash=hash_document(self._document(updated)),
                operation="DEACTIVATE",
                metadata={"source": "core_did_service", "revision": updated.revision},
            )
            self._registry[did] = updated
            return updated

    def _verify_ownership(
        self,
        current: CoreDIDRecord,
        did: str,
        operation: str,
        request: Mapping[str, Any],
        challenge: str,
        signature: bytes,
    ) -> None:
        try:
            self.challenges.consume(challenge, did, operation, request)
        except ChallengeError as exc:
            raise OwnershipError(str(exc)) from exc
        try:
            self._validate_public_key(current.public_key_bytes).verify(
                signature,
                self.ownership_message(did, operation, request, challenge),
            )
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise OwnershipError("DID ownership signature is invalid.") from exc

