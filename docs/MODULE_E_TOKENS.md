# Module E — JWT Access Token & Zero-Trust Policy Engine

**Author / Owner**: Member 5
**Branch**: `member5`
**Status**: JWT and policy components implemented; HTTP issuance and revocation unavailable pending authentication integration

---

## 1. Overview & Purpose

The **JWT Access Token & Zero-Trust Policy Engine** provides JWT and policy components for the Decentralized Zero-Trust IdP Mesh. A verified WebAuthn identity is not currently integrated with these HTTP endpoints. The internal components:

1. **Provides JWT signing components** for DID-bound claims; HTTP issuance is unavailable pending verified caller authentication.
2. **Provides Zero-Trust policy checks** for DID registration, status, ledger integrity, and allowed scopes; these checks do not authenticate callers.
3. **Provides JTI deny-list storage** via Redis or an in-memory fallback; the HTTP revocation operation remains disabled pending ownership checks.
4. **Exposes FastAPI routes** for integration; HTTP issuance and revocation remain disabled pending authentication and ownership authorization.

> **Zero-Trust principle**: Never implicit trust. The policy engine checks current ledger state for a DID and requested scopes; this does not establish who controls the DID.

**Authorization status:** The repository does not currently integrate a
verified WebAuthn identity or authenticated session. Ledger registration alone
does not authenticate the caller. Accordingly, the HTTP issue and revoke
endpoints fail closed with `503 Service Unavailable` until verified DID
ownership and token ownership checks are integrated. See
[`token-authorization-gap.md`](token-authorization-gap.md) for the gap and next
step. The policy engine and JWT engine remain available as internal components;
their existence does not secure these HTTP endpoints.

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

Currently unavailable: this endpoint returns `503 Service Unavailable` until
the caller's DID is verified by the authentication module. A DID in the request
body or a matching ledger record is not caller authentication.

**Request**:
```json
{
  "did": "did:mesh:key:z6MkuExample",
  "scope": ["read:profile", "write:did"]
}
```

**Future response after authentication integration (201 Created; currently unavailable):**
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

**Future policy error after authentication integration** (403 Forbidden):
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

Currently unavailable: this endpoint returns `503 Service Unavailable` until
the caller's authority over the requested token is verified. A caller-supplied
JTI does not prove token ownership.

**Request**: `{ "jti": "<UUID>", "reason": "User logged out" }`

**Response** (503 Service Unavailable): token revocation is disabled pending
authenticated token ownership checks.

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

Token issuance through the HTTP endpoint is currently unavailable and returns
`503 Service Unavailable`. A caller must not treat DID registration as proof of
identity. Integrate a verified principal before documenting or using a live
issuance example.

### For Member 6 (Admin Dashboard)

- `GET /api/v1/tokens/public-key` — display the active signing key
- `POST /api/v1/tokens/verify` — validate tokens presented by users
- `GET /api/v1/tokens/policy/scopes` — display allowed scopes

---

## 7. Environment Variables

| Variable | Default | Description |
|:--|:--|:--|
| `TOKEN_KEY_DIR` | Required | Protected directory outside the repository containing the provisioned Ed25519 PEM key files |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL for the JTI deny-list |
| `TOKEN_EXPIRY_SECONDS` | `3600` | Token lifetime in seconds |

### Signing-key provisioning and startup

Provision both `token_signing_private.pem` and `token_signing_public.pem` before
starting the application. Set `TOKEN_KEY_DIR` in the service environment to the
protected directory containing that pair. Keep the private key outside the
repository and restrict filesystem access to the service account.

Startup fails with a non-secret error if `TOKEN_KEY_DIR` is unset, resolves
inside the repository, does not identify an existing directory, either key file
is missing or unreadable, either file is not a valid Ed25519 PEM key, or the
public key does not match the private key. Startup never creates or overwrites
signing keys. Correct the external configuration or provision the pair before
restarting; do not copy private key material into the repository.

The current verifier accepts tokens signed by the single configured key. A
signing-key replacement therefore makes tokens signed by the previous key fail
verification. Existing JWT-backed sessions must authenticate again and obtain
new tokens after cutover. Update every external verifier to trust the replacement
public key as part of the same operation.

---

## 8. Running the Tests

```bash
pytest tests/unit/test_tokens_jwt_engine.py tests/unit/test_tokens_policy.py tests/unit/test_tokens_revocation.py tests/unit/test_tokens_router.py -v
```

Pytest prints the collected test results and final summary. The test count can
change as the suite evolves; use the summary from the run you perform.

> **Note**: Tests do **not** require a running Redis server. The revocation store falls back to an in-memory backend automatically.
