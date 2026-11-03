# Module B — WebAuthn / FIDO2 Passwordless Authentication

> **Supplemental module note.** The `/api/v1/webauthn` flow described here is an Ed25519 challenge-response simulation, not browser WebAuthn. The current repository also mounts a separate browser WebAuthn implementation under `/webauthn`; their stores are separate, and neither login flow issues an application JWT/session. See [API_DOCUMENTATION.md](API_DOCUMENTATION.md) and [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).

**Author / Owner**: Member 2
**Branch**: `feature/webauthn-module`
**Status**: Implemented; integration and end-to-end validation remain incomplete
**API Prefix**: `/api/v1/webauthn`

---

## 1. Overview & Purpose

The **WebAuthn/FIDO2 Passwordless Authentication** module replaces traditional username/password
login with a cryptographic challenge-response ceremony using **Ed25519 keys** (simulating a
hardware security key or biometric authenticator).

### Zero-Trust Principle Applied

> "Never trust, always verify." Every authentication request requires a valid Ed25519 signature
> over a fresh, single-use server nonce. Replayed challenges are rejected. Sign-count ensures
> each login is strictly newer than the last.

### Why Ed25519 Simulation?

Real WebAuthn uses browser authenticators (`navigator.credentials.create()`) with CBOR-encoded
`AuthenticatorData` and `clientDataJSON`. In this educational, single-node system we implement a
**cryptographically sound simulation** using Ed25519:

```
signature = Ed25519Sign(
    private_key,
    SHA256(challenge_bytes || did_utf8 || ceremony_tag)
)
```

where `ceremony_tag` is `b"register"` or `b"authenticate"`.

---

## 2. Module Structure

```
app/modules/webauthn/
├── __init__.py           — Public exports + webauthn_router
├── models.py             — Pydantic request/response schemas
├── challenge_store.py    — In-memory nonce/challenge registry (TTL-aware, thread-safe)
├── credential_store.py   — In-memory credential registry (public key + DID binding)
├── webauthn_service.py   — Core WebAuthn ceremony logic (register + authenticate)
└── router.py             — FastAPI router (5 endpoints)
```

---

## 3. Registration Ceremony

### Step 1 — `POST /api/v1/webauthn/register/begin`

Server generates a 32-byte CSPRNG challenge and returns it as base64url.

```json
// Request
{ "did": "did:mesh:key:a1b2c3d4e5f6a7b8", "display_name": "Alice" }

// Response (200 OK)
{
  "challenge": "7dR3mNqPXz4...",
  "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
  "rp_id": "idp-mesh-v1",
  "rp_name": "Decentralized Zero-Trust IdP Mesh",
  "expires_in_seconds": 300
}
```

### Step 2 — Client Signs

```python
import hashlib, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

challenge_bytes = base64.urlsafe_b64decode(challenge + "==")
pre_image = hashlib.sha256(challenge_bytes + did.encode() + b"register").digest()
signature = private_key.sign(pre_image)
signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
```

### Step 3 — `POST /api/v1/webauthn/register/complete`

```json
// Request
{
  "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
  "challenge": "7dR3mNqPXz4...",
  "public_key_b64": "<base64url 32-byte Ed25519 public key>",
  "signature_b64": "<base64url 64-byte signature>"
}

// Response (201 Created)
{
  "success": true,
  "credential_id": "cred-3f8a1b2c4d5e6f7a",
  "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
  "ledger_record_index": 1,
  "message": "Credential 'cred-3f8a...' successfully registered and bound to DID '...'."
}
```

Server verifies the signature, stores the credential, and **anchors a `CREATE` record on the
SimulatedLedger** (Module C integration).

---

## 4. Authentication Ceremony

### Step 1 — `POST /api/v1/webauthn/authenticate/begin`

```json
// Request
{ "did": "did:mesh:key:a1b2c3d4e5f6a7b8" }

// Response (200 OK)
{
  "challenge": "kQz9rMbSXn2...",
  "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
  "credential_ids": ["cred-3f8a1b2c4d5e6f7a"],
  "expires_in_seconds": 300
}
```

### Step 2 — Client Signs

```python
pre_image = hashlib.sha256(challenge_bytes + did.encode() + b"authenticate").digest()
signature = private_key.sign(pre_image)
```

### Step 3 — `POST /api/v1/webauthn/authenticate/complete`

```json
// Request
{
  "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
  "challenge": "kQz9rMbSXn2...",
  "credential_id": "cred-3f8a1b2c4d5e6f7a",
  "signature_b64": "<base64url 64-byte signature>"
}

// Response (200 OK)
{
  "success": true,
  "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
  "credential_id": "cred-3f8a1b2c4d5e6f7a",
  "message": "DID 'did:mesh:key:a1b2c3d4e5f6a7b8' authenticated successfully (sign_count=1)."
}
```

After successful authentication, call `POST /api/v1/tokens/issue` to receive a JWT access token.

---

## 5. All API Endpoints

| Method | Path | Description | Success Code |
|--------|------|-------------|-------------|
| `POST` | `/webauthn/register/begin` | Issue registration challenge | 200 |
| `POST` | `/webauthn/register/complete` | Verify + store credential, anchor on ledger | 201 |
| `POST` | `/webauthn/authenticate/begin` | Issue authentication challenge | 200 |
| `POST` | `/webauthn/authenticate/complete` | Verify authentication, increment sign_count | 200 |
| `GET` | `/webauthn/credentials/{did}` | List registered credentials for a DID | 200 |

---

## 6. Security Properties

| Property | Implementation |
|---|---|
| **No password** | Credentials are Ed25519 public keys only |
| **Replay prevention** | Challenges are single-use, deleted on consumption |
| **Challenge freshness** | 300-second TTL; expired challenges are rejected |
| **DID binding** | Each challenge is cryptographically bound to a specific DID |
| **Ceremony binding** | `"register"` and `"authenticate"` tags prevent cross-ceremony replay |
| **Sign-count** | Monotonically increasing counter detects credential cloning |
| **No private keys stored** | Only 32-byte public key bytes are persisted |
| **Ledger anchoring** | Registration is immortalized on the tamper-evident ledger |

---

## 7. Integration with Other Modules

### For Member 1 (Core Backend — `app/main.py`)

```python
from app.modules.webauthn import webauthn_router
app.include_router(webauthn_router, prefix="/api/v1")
```

The shared `SimulatedLedger` is wired at startup via `_wire_shared_ledger()`.

### For Member 5 (Tokens)

After `POST /webauthn/authenticate/complete` succeeds, issue a JWT:

```python
import httpx

# Step 1: Authenticate
auth_resp = httpx.post("http://localhost:8000/api/v1/webauthn/authenticate/complete", json={...})
assert auth_resp.json()["success"]

# Step 2: Issue token
token_resp = httpx.post("http://localhost:8000/api/v1/tokens/issue", json={
    "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
    "scope": ["read:profile", "auth:webauthn"]
})
jwt = token_resp.json()["access_token"]
```

### For Member 6 (Admin Dashboard)

- `GET /api/v1/webauthn/credentials/{did}` — display registered authenticators
- `POST /api/v1/webauthn/authenticate/complete` response shows `sign_count` — useful for audit

---

## 8. Running the Tests

```bash
pytest tests/unit/test_webauthn.py -v
```

Expected output:
```
tests/unit/test_webauthn.py::TestChallengeStore::test_clear_empties_store PASSED
tests/unit/test_webauthn.py::TestChallengeStore::test_consume_is_single_use PASSED
...
tests/unit/test_webauthn.py::TestWebAuthnEndToEndIntegration::test_ledger_integrity_preserved PASSED
====================== 43 passed in X.XXs ======================
```

> **Note**: Tests do **not** require a running Redis server, a browser, or a real FIDO2
> authenticator. All cryptographic operations are performed in-process using the `cryptography`
> library already in `requirements.txt`.
