# Module E — JWT Access Token & Zero-Trust Policy Engine

**Author / Owner**: Member 5  
**Branch**: `member5`  
**Status**: Fully Implemented & Tested

---

## 1. Overview & Purpose

The **JWT Access Token & Zero-Trust Policy Engine** is the authorization layer of the Decentralized Zero-Trust IdP Mesh. After a user's identity has been proven via WebAuthn (Member 2) and anchored to a DID on the Ledger (Member 4), this module:

1. **Issues short-lived, signed JWT access tokens** containing DID-bound claims.
2. **Enforces Zero-Trust policies** — every token request is validated against the live ledger state before a token is issued.
3. **Manages token revocation** via a Redis-backed JTI deny-list (with automatic in-memory fallback).
4. **Exposes FastAPI endpoints** for Member 1 (Core Backend) and Member 6 (Admin Dashboard) to integrate with.

> **Zero-Trust principle**: Never implicit trust. Every token issuance validates the DID's current ledger state in real time. If the ledger is tampered with, token issuance halts entirely.

---

## 2. Module Structure

```
app/modules/tokens/
├── __init__.py        — Public exports
├── models.py          — Pydantic request/response schemas & constants
├── jwt_engine.py      — Ed25519 JWT sign / verify / decode
├── policy.py          — Zero-Trust policy evaluation engine
├── revocation.py      — Redis-backed JTI deny-list (in-memory fallback)
└── router.py          — FastAPI router (5 endpoints)
```

---

## 3. JWT Token Structure

Each token is a signed JWT (EdDSA / Ed25519) with the following claims:

| Claim | Description |
|:--|:--|
| `sub` | DID the token was issued for |
| `jti` | Unique UUID4 identifier (used for revocation) |
| `iat` | Issued-at timestamp (Unix epoch) |
| `exp` | Expiry timestamp (default: `iat + 3600s`) |
| `iss` | `"idp-mesh-v1"` |
| `aud` | `"idp-mesh-api"` |
| `scope` | List of granted permission scopes |
| `did_verified_at` | ISO timestamp of the last ledger anchor event |
| `did_status` | `"ACTIVE"` at time of issuance |

---

## 4. Zero-Trust Policy Checks

The `ZeroTrustPolicyEngine` evaluates requests in strict order (fail-fast):

| # | Check | Deny Condition |
|:--|:--|:--|
| 1 | **DID Registered** | No ledger record found for the DID |
| 2 | **DID Not Deactivated** | Latest ledger operation is `DEACTIVATE` |
| 3 | **Ledger Integrity** | `ledger.verify_integrity()` returns `False` |
| 4 | **Scope Allowed** | Any requested scope not in the allowed list |

**Allowed scopes**: `read:profile`, `write:did`, `admin:ledger`, `auth:webauthn`

---

## 5. API Endpoints

All endpoints are mounted at `/api/v1/tokens`.

### `POST /tokens/issue`

Issue a JWT access token for an authenticated DID.

**Request**:
```json
{
  "did": "did:mesh:key:z6MkuExample",
  "scope": ["read:profile", "write:did"]
}
```

**Response** (201 Created):
```json
{
  "access_token": "<JWT string>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "did": "did:mesh:key:z6MkuExample",
  "scope": ["read:profile", "write:did"]
}
```

**Error** (403 Forbidden — policy denied):
```json
{ "detail": "DID 'did:mesh:key:z6MkuExample' is not registered on the ledger..." }
```

---

### `POST /tokens/verify`

Verify and decode a JWT.

**Request**: `{ "token": "<JWT string>" }`

**Response** (200):
```json
{
  "valid": true,
  "claims": { "sub": "did:mesh:key:z6MkuExample", "scope": [...], ... },
  "error": null
}
```

---

### `POST /tokens/revoke`

Add a token's JTI to the deny-list.

**Request**: `{ "jti": "<UUID>", "reason": "User logged out" }`

**Response** (200): `{ "revoked": true, "jti": "<UUID>", "message": "..." }`

---

### `GET /tokens/public-key`

Return the Ed25519 public key for independent token verification.

**Response**: `{ "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...", "algorithm": "EdDSA", "issuer": "idp-mesh-v1" }`

---

### `GET /tokens/policy/scopes`

List all policy-allowed permission scopes.

**Response**: `{ "scopes": ["read:profile", "write:did", "admin:ledger", "auth:webauthn"] }`

---

## 6. Integration with Other Members

### For Member 1 (Core Backend — `app/main.py`)

```python
from fastapi import FastAPI
from app.modules.tokens import tokens_router

app = FastAPI()
app.include_router(tokens_router, prefix="/api/v1")
```

### For Member 3 (DID & Cryptography)

After registering a DID and anchoring it to the ledger, call the issue endpoint:

```python
import httpx

response = httpx.post("http://localhost:8000/api/v1/tokens/issue", json={
    "did": "did:mesh:key:z6MkuExample",
    "scope": ["read:profile"]
})
token = response.json()["access_token"]
```

### For Member 6 (Admin Dashboard)

- `GET /api/v1/tokens/public-key` — display the active signing key
- `POST /api/v1/tokens/verify` — validate tokens presented by users
- `GET /api/v1/tokens/policy/scopes` — display allowed scopes

---

## 7. Environment Variables

| Variable | Default | Description |
|:--|:--|:--|
| `TOKEN_KEY_DIR` | `.token_keys` | Directory to store/load Ed25519 PEM key files |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL for the JTI deny-list |
| `TOKEN_EXPIRY_SECONDS` | `3600` | Token lifetime in seconds |

---

## 8. Running the Tests

```bash
pytest tests/unit/test_tokens_jwt_engine.py tests/unit/test_tokens_policy.py tests/unit/test_tokens_revocation.py tests/unit/test_tokens_router.py -v
```

Expected output:
```
tests/unit/test_tokens_jwt_engine.py .......    [ 23%]
tests/unit/test_tokens_policy.py ...........    [ 59%]
tests/unit/test_tokens_revocation.py .......    [ 82%]
tests/unit/test_tokens_router.py .........      [100%]
====================== 34 passed ======================
```

> **Note**: Tests do **not** require a running Redis server. The revocation store falls back to an in-memory backend automatically.
