# Module C — Simulated Blockchain Ledger (Identity Integrity)

**Author / Owner**: Member 4
**Branch**: `midhun`
**Status**: Fully Implemented & Tested (26 passing tests)

---

## 1. Overview & Purpose

The **Simulated Blockchain Ledger** provides tamper-evident, append-only integrity anchoring for Decentralized Identifiers (DIDs).

In a traditional Identity Provider (IdP), identity records and public keys stored in a standard database can be silently modified by an attacker or rogue administrator. This module anchors each DID creation and update into a cryptographic hash-linked chain (similar to a blockchain block) so that:
1. Every record is permanently linked to its predecessor via SHA-256 hashes.
2. Any historical modification (changing a public key, altering a DID, or reordering blocks) immediately breaks the hash chain and is detected by `verify_integrity()`.

> **Note on Scope**: This is an educational, single-node simulated ledger designed to demonstrate cryptographic immutability and tamper-detection. It does not implement distributed consensus (Proof of Work / Proof of Stake) or peer-to-peer gossip networking.

---

## 2. Block & Record Structure

Each block on the ledger is represented by a `LedgerRecord` object:

| Field | Type | Description |
| :--- | :--- | :--- |
| `index` | `int` | Sequential record index starting at `0` (Genesis block). |
| `timestamp` | `str` | ISO 8601 UTC timestamp of creation. |
| `did` | `str` | The Decentralized Identifier (e.g., `did:mesh:key:z6Mku...`). |
| `doc_hash` | `str` | 64-character lowercase SHA-256 digest of the resolved DID Document. |
| `operation` | `str` | Identity lifecycle state: `GENESIS`, `CREATE`, `UPDATE`, or `DEACTIVATE`. |
| `previous_hash` | `str` | SHA-256 hash of the preceding block (64 zeroes for Genesis). |
| `record_hash` | `str` | Canonical SHA-256 digest calculated over all above fields. |
| `metadata` | `dict` | Optional non-sensitive operational metadata (e.g., version, node id). |

### Security Guarantees
* **No Sensitive Data**: Private keys, biometric data, credentials, and PII are **never** stored on the ledger.
* **Deterministic Serialization**: Hashes are computed using canonical JSON (`sort_keys=True`, compact separators `,` and `:`).

---

## 3. How Other Team Members Integrate with Module C

### For Member 3 (DID & Cryptography) & Member 1 (Core Backend)
When a user registers or updates their DID, anchor it directly in Python:

```python
from app.modules.ledger import SimulatedLedger, hash_did_document, LedgerOperation

ledger = SimulatedLedger(auto_genesis=True)

# 1. Member 3 provides the DID Document dict
did_document = {
    "id": "did:mesh:key:z6MkuExample",
    "verificationMethod": [{
        "id": "did:mesh:key:z6MkuExample#keys-1",
        "type": "Ed25519VerificationKey2020",
        "publicKeyMultibase": "z6Mku..."
    }]
}

# 2. Compute canonical doc_hash
doc_hash = hash_did_document(did_document)

# 3. Anchor to the ledger
record = ledger.append_record(
    did="did:mesh:key:z6MkuExample",
    doc_hash=doc_hash,
    operation=LedgerOperation.CREATE,
    metadata={"created_by": "registration_flow"}
)
print(f"Anchored at block #{record.index} with hash {record.record_hash}")
```

### For Member 6 (Admin Dashboard & Deployment)
Member 1 simply mounts `ledger_router` in `app/main.py`:

```python
from fastapi import FastAPI
from app.modules.ledger import ledger_router

app = FastAPI()
app.include_router(ledger_router, prefix="/api/v1")
```

The Dashboard can call:
* `GET /api/v1/ledger`: Returns all blocks for the ledger viewer table.
* `GET /api/v1/ledger/verify`: Returns real-time cryptographic audit status:
  ```json
  {
    "valid": true,
    "error": null,
    "total_records": 12,
    "head_hash": "a4b7c8..."
  }
  ```
* `POST /api/v1/ledger/simulate-tamper`: Allows instructors or judges to test live tamper-detection by simulating an attack.

---

## 4. Running the Tests

To run the complete automated test suite:

```bash
pytest
```

Output:
```text
tests/unit/test_ledger_chain.py .....             [ 19%]
tests/unit/test_ledger_models_hasher.py ......    [ 42%]
tests/unit/test_ledger_persistence.py ....        [ 57%]
tests/unit/test_ledger_router.py ....             [ 73%]
tests/unit/test_ledger_tampering.py .......       [100%]
====================== 26 passed in 0.44s ======================
```
