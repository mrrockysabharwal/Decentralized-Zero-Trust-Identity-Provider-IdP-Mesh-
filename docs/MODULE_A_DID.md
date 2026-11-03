# Module A — DID Registry & Cryptography HTTP API

> **Supplemental module note.** This document predates later route and integration changes. In particular, current DID update/deactivation APIs require controller-proof challenges, and DID storage is process-local. Use [API_DOCUMENTATION.md](API_DOCUMENTATION.md) and [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for current behavior.

**Author / Owner**: Member 3
**Branch**: `feature/identity-module`
**Status**: Implemented; integration and end-to-end validation remain incomplete
**API Prefix**: `/api/v1/did`

---

## 1. Overview & Purpose

The **DID Registry & Cryptography** module provides the foundational identity layer for the
Decentralized Zero-Trust IdP Mesh. It exposes the existing `Ed25519Service` and `DIDService`
via a REST API, allowing any client or peer service to:

1. **Generate** a new Ed25519 key pair and derive a `did:mesh:key` DID in one call.
2. **Resolve** any registered DID to its W3C DID Core 1.0 compliant DID Document.
3. **Update** a DID's associated public key with automatic ledger anchoring.
4. **Deactivate** a DID, permanently marking it as untrusted.
5. **Verify** an Ed25519 signature using only the DID (no private key sharing required).

Every mutating operation automatically anchors the event on the **SimulatedLedger (Module C)**,
guaranteeing a tamper-evident, append-only audit trail of the full DID lifecycle.

### Zero-Trust Principle Applied

> The DID identifier is derived **deterministically** from the public key — it cannot be forged.
> Every authentication event can be independently verified against the DID Document without
> trusting any central authority.

---

## 2. Module Structure

```
app/modules/did/
├── __init__.py     — Public exports: did_router, DIDService, Ed25519Service
├── models.py       — Pydantic request/response schemas (7 request + 8 response types)
└── router.py       — FastAPI router (7 endpoints)

app/modules/identity/          ← underlying services (Member 3, unchanged)
├── ed25519_service.py         — Key generation, signing, verification
└── did_service.py             — DID creation, resolution, registry management
```

---

## 3. API Endpoints

| Method | Path | Description | Status Code |
|--------|------|-------------|-------------|
| `POST` | `/did/create` | Generate key pair, register DID, anchor CREATE on ledger | 201 |
| `GET`  | `/did/resolve/{did}` | Resolve DID → W3C DID Document | 200 |
| `GET`  | `/did/exists/{did}` | Check if a DID is registered (never 404) | 200 |
| `GET`  | `/did/list` | List all registered DIDs | 200 |
| `POST` | `/did/update/{did}` | Update public key + anchor UPDATE | 200 |
| `POST` | `/did/deactivate/{did}` | Deactivate DID + anchor DEACTIVATE | 200 |
| `POST` | `/did/verify-signature` | Verify Ed25519 signature using DID's public key | 200 |

---

## 4. DID Creation

### `POST /api/v1/did/create`

Generates a fresh Ed25519 key pair, derives a `did:mesh:key` DID, registers it in the
in-process registry, and anchors a `CREATE` event on the SimulatedLedger.

**Request:**
```json
{
  "display_name": "Alice",
  "anchor_to_ledger": true,
  "metadata": {}
}
```

**Response (201 Created):**
```json
{
  "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
  "public_key_b64": "<base64url 32-byte Ed25519 public key>",
  "private_key_b64": "<base64url 32-byte Ed25519 private key seed>",
  "did_document": {
    "@context": ["https://www.w3.org/ns/did/v1", "..."],
    "id": "did:mesh:key:a1b2c3d4e5f6a7b8",
    "controller": "did:mesh:key:a1b2c3d4e5f6a7b8",
    "verificationMethod": [{
      "id": "did:mesh:key:a1b2c3d4e5f6a7b8#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:mesh:key:a1b2c3d4e5f6a7b8",
      "publicKeyMultibase": "z<base58btc-encoded-key>"
    }],
    "authentication": ["did:mesh:key:a1b2c3d4e5f6a7b8#key-1"],
    "assertionMethod": ["did:mesh:key:a1b2c3d4e5f6a7b8#key-1"],
    "created": "2026-10-22T18:00:00+00:00",
    "updated": "2026-10-22T18:00:00+00:00"
  },
  "ledger_record_index": 1,
  "message": "DID 'did:mesh:key:a1b2c3d4e5f6a7b8' successfully created. Anchored at ledger block #1."
}
```

> ⚠️ **`private_key_b64` is shown ONCE.** The server never stores the private key. Save it securely.

---

## 5. Signature Verification

### `POST /api/v1/did/verify-signature`

Verifies a 64-byte Ed25519 signature using only the DID — no private key required by the server.
This is the core Zero-Trust verification primitive.

**Client-side signing (Python):**
```python
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

priv_bytes = base64.urlsafe_b64decode(private_key_b64 + "==")
priv_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
message = b"zero-trust identity proof"
signature = priv_key.sign(message)

message_b64 = base64.urlsafe_b64encode(message).rstrip(b"=").decode()
signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
```

**Request:**
```json
{
  "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
  "message_b64": "<base64url message bytes>",
  "signature_b64": "<base64url 64-byte Ed25519 signature>"
}
```

**Response (200 OK — valid):**
```json
{
  "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
  "valid": true,
  "message": "Signature verified successfully for DID 'did:mesh:key:a1b2c3d4e5f6a7b8'."
}
```

**Response (200 OK — invalid):**
```json
{
  "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
  "valid": false,
  "message": "Signature verification FAILED for DID '...'."
}
```

---

## 6. Full Lifecycle Flow

```
POST /did/create
    └─→ Ed25519 key pair generated
    └─→ DID derived: did:mesh:key:<sha256[:16] of pub key>
    └─→ DID Document registered in-process
    └─→ CREATE anchored on SimulatedLedger ──────────────────────┐
                                                                  │
POST /did/update/{did}                                            │
    └─→ New public key validated                                  │  Shared
    └─→ DID Document updated in-process                          │  SimulatedLedger
    └─→ UPDATE anchored on SimulatedLedger ──────────────────────┤  (Module C)
                                                                  │
POST /did/deactivate/{did}                                        │
    └─→ DID marked deactivated in-process                        │
    └─→ DEACTIVATE anchored on SimulatedLedger ─────────────────┘
                                                                  │
POST /tokens/issue ─────────────────────────────────────────────→ Zero-Trust policy
    └─→ Reads DEACTIVATE record, DENIES token issuance            (Module E)
```

---

## 7. Security Properties

| Property | Implementation |
|---|---|
| **Self-certifying DIDs** | DID identifier = SHA-256[:16] of Ed25519 public key |
| **No private keys stored** | Only 32-byte public keys are registered |
| **Append-only audit trail** | All lifecycle events anchored on tamper-evident ledger |
| **Replay-safe deactivation** | Deactivated DIDs blocked by Module E Zero-Trust policy engine |
| **Deterministic DID Documents** | W3C DID Core 1.0 compliant, multibase base58btc public keys |
| **Signature verification** | No private key escrow — server only needs the DID |

---

## 8. Integration with Other Modules

### For Member 1 (Core Backend — `app/main.py`)

```python
from app.modules.did import did_router
import app.modules.did.router as _did_router_module

app.include_router(did_router, prefix="/api/v1")

# In _wire_shared_ledger():
_did_router_module._shared_ledger = ledger_instance
```

### For Member 2 (WebAuthn)

After `POST /did/create`, use the returned DID as the subject for WebAuthn registration:

```python
# 1. Create DID
did_resp = httpx.post("http://localhost:8000/api/v1/did/create", json={})
did = did_resp.json()["did"]

# 2. Begin WebAuthn registration
reg_resp = httpx.post("http://localhost:8000/api/v1/webauthn/register/begin",
                      json={"did": did, "display_name": "Alice"})
```

### For Member 5 (Tokens)

After DID creation (which anchors it on the shared ledger), tokens can be issued immediately:

```python
token_resp = httpx.post("http://localhost:8000/api/v1/tokens/issue",
                        json={"did": did, "scope": ["read:profile", "write:did"]})
jwt = token_resp.json()["access_token"]
```

### For Member 6 (Admin Dashboard)

- `GET /api/v1/did/list` — Show all registered identities
- `GET /api/v1/did/exists/{did}` — Poll DID status + deactivation flag
- `GET /api/v1/did/resolve/{did}` — Display full DID Document
- `GET /api/v1/ledger/history/{did}` — Show complete lifecycle audit trail

---

## 9. Running the Tests

```bash
pytest tests/unit/test_did_router.py -v
```

Expected output:
```
tests/unit/test_did_router.py::TestDIDCreate::test_create_returns_201 PASSED
tests/unit/test_did_router.py::TestDIDCreate::test_create_response_contains_did PASSED
...
tests/unit/test_did_router.py::TestDIDEndToEndIntegration::test_ledger_integrity_after_did_lifecycle PASSED
====================== 43 passed in X.XXs ======================
```

> **Note**: Tests do **not** require Redis, a running server, or any external dependencies.
> All operations run in-process using the `cryptography` library.
