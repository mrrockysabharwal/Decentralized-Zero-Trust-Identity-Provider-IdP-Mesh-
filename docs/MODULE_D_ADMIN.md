# Module D — Admin Dashboard API

**Author / Owner**: Member 6  
**Branch**: `feature/admin-dashboard`  
**Status**: Fully Implemented & Tested  
**API Prefix**: `/api/v1/admin`

---

## 1. Overview & Purpose

The **Admin Dashboard API** is the operational visibility layer for the Decentralized
Zero-Trust IdP Mesh. It exposes **read-only aggregation** of live data from all other
modules, plus two privileged write operations:

- **Force-revoke** any JWT by JTI (emergency admin lockout)
- **Simulate tamper** on the ledger (demo / security audit mode)

> **Zero-Trust principle**: The admin module never stores any new data.
> It reads exclusively from the live in-memory state of Modules A, B, C, and E.
> The ledger integrity status shown in the dashboard is the same boolean
> `verify_integrity()` result that gates token issuance.

---

## 2. Administrative Access

Every `/api/v1/admin/*` route requires a valid, unrevoked bearer JWT with
`role=admin`. Configure trusted administrator DIDs using the comma-separated
`IDP_ADMIN_DIDS` environment variable. The token service assigns this role
based on the authenticated DID; a caller's `extra_claims.role` is ignored.
Missing or invalid tokens receive 401, while a valid non-admin token receives
403.

## 3. Module Structure

```
app/modules/admin/
├── __init__.py    — Public exports: admin_router
├── models.py      — Pydantic response schemas (10 models)
└── router.py      — FastAPI router (10 endpoints)

docs/MODULE_D_ADMIN.md          ← this file
tests/unit/test_admin_router.py ← 35+ unit tests
tests/integration/test_full_flow.py            ← full ceremony e2e tests
tests/integration/test_ledger_tamper_e2e.py    ← tamper → 403 chain reaction
```

---

## 4. API Endpoints

| Method | Path | Description | Status Code |
|--------|------|-------------|-------------|
| `GET`  | `/admin/dashboard` | Aggregate stats: DIDs, ledger integrity, credentials, health | 200 |
| `GET`  | `/admin/identities` | List all DIDs with status + credential count | 200 |
| `GET`  | `/admin/identities/{did}` | Full DID detail: ledger history + credentials | 200/404 |
| `GET`  | `/admin/ledger` | All ledger blocks with integrity status | 200 |
| `GET`  | `/admin/ledger/verify` | Real-time cryptographic audit | 200 |
| `GET`  | `/admin/credentials` | All WebAuthn credentials across all DIDs | 200 |
| `POST` | `/admin/tokens/{jti}/revoke` | Admin force-revoke any token | 200 |
| `GET`  | `/admin/tokens/policy` | Active token policy (scopes, TTL, algorithm) | 200 |
| `POST` | `/admin/ledger/simulate-tamper` | Demo tamper-detection (destructive, in-memory) | 200/400 |
| `GET`  | `/admin/health` | Aggregate health of all subsystems | 200 |
| `GET`  | `/admin/events` | Filtered, paginated security event feed | 200 |
| `GET`  | `/admin/events/{event_id}` | One event detail | 200/404 |

Security events are persisted in SQLite (`AUDIT_DB_PATH`, default
`data/security_events.sqlite3`). Identity values are returned as SHA-256
pseudonymous references. Event records exclude access tokens, JTIs, private
keys, credential public-key bytes, and raw IP addresses.

---

## 5. Dashboard Summary

### `GET /api/v1/admin/dashboard`

**Response (200 OK):**
```json
{
  "total_dids": 5,
  "active_dids": 4,
  "deactivated_dids": 1,
  "total_ledger_records": 12,
  "ledger_integrity": true,
  "ledger_head_hash": "a4b7c8d9...",
  "total_credentials": 7,
  "revocation_backend": "in-memory",
  "subsystems": [
    { "name": "ledger",       "status": "healthy", "detail": "Chain integrity verified" },
    { "name": "tokens",       "status": "healthy", "detail": "Revocation backend: in-memory" },
    { "name": "webauthn",     "status": "healthy", "detail": "7 credential(s) registered" },
    { "name": "did_registry", "status": "healthy", "detail": "5 DID(s) registered" }
  ]
}
```

---

## 5. Identity Detail Drill-Down

### `GET /api/v1/admin/identities/{did}`

**Response (200 OK):**
```json
{
  "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
  "status": "ACTIVE",
  "latest_operation": "CREATE",
  "ledger_history": [
    { "index": 1, "operation": "CREATE", "timestamp": "2026-10-27T...", ... }
  ],
  "credentials": [
    {
      "credential_id": "cred-3f8a1b2c4d5e6f7a",
      "did": "did:mesh:key:a1b2c3d4e5f6a7b8",
      "public_key_b64": "<base64url>",
      "registered_at": "2026-10-27T...",
      "sign_count": 2,
      "device_info": null
    }
  ],
  "credential_count": 1
}
```

---

## 6. Force-Revoke Token

### `POST /api/v1/admin/tokens/{jti}/revoke`

Adds the JTI to the revocation deny-list immediately. Any subsequent
`POST /tokens/verify` with this token will return `valid: false`.

**Response (200 OK):**
```json
{
  "revoked": true,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "reason": "Admin force-revocation",
  "message": "Token (jti=...) has been force-revoked and added to the deny-list."
}
```

---

## 7. Tamper-Detection Demo

### `POST /api/v1/admin/ledger/simulate-tamper`

**Query params**: `index`, `field`, `new_value`, `recalculate_record_hash`

Modifies a ledger block in-memory and immediately returns the post-tamper
integrity audit result. Used to demonstrate the hash-linkage tamper detection
to judges or instructors.

⚠️ **Destructive**: mutates live in-memory state. For demonstration use only.

**Response (200 OK — after tampering):**
```json
{
  "total_records": 3,
  "integrity_valid": false,
  "integrity_error": "Data tampering detected at record #0: ...",
  "head_hash": "...",
  "records": [...]
}
```

---

## 8. Zero-Trust Chain Reaction (Key Architecture)

```
POST /admin/ledger/simulate-tamper   (or any in-memory tamper)
    └─→ ledger.tamper_record(index, field, value)
    └─→ ledger.verify_integrity() → False
         │
         ├─→ GET /admin/health        → "overall_status": "degraded"
         ├─→ GET /admin/dashboard     → "ledger_integrity": false
         │
         └─→ POST /tokens/issue (Check 3)
                 └─→ ZeroTrustPolicyEngine.evaluate()
                         └─→ is_valid = False
                         └─→ 403 Forbidden — all token issuance halted
```

This chain reaction is the core Zero-Trust guarantee:
**a tampered ledger immediately halts token issuance system-wide.**

---

## 9. Integration with Other Modules

### For Member 1 (Core Backend — `app/main.py`)

```python
from app.modules.admin import admin_router
import app.modules.admin.router as _admin_router_module

app.include_router(admin_router, prefix="/api/v1")

# In _wire_shared_ledger():
_admin_router_module._shared_ledger    = ledger_instance
_admin_router_module._credential_store = _webauthn_router_module._credential_store
_admin_router_module._revocation_store = _tokens_router_module._revocation_store
```

The admin module reads only from these three shared singletons.
It does not write to any of them (except force-revoke, which calls `_revocation_store.revoke()`).

---

## 10. Running the Tests

### Unit Tests
```bash
pytest tests/unit/test_admin_router.py -v
```

Expected:
```
tests/unit/test_admin_router.py::TestDashboard::test_dashboard_returns_200 PASSED
...
tests/unit/test_admin_router.py::TestUnwiredStores::test_dashboard_503_when_not_wired PASSED
====================== 35 passed in X.XXs ======================
```

### Integration Tests
```bash
pytest tests/integration/ -v
```

Expected:
```
tests/integration/test_full_flow.py::TestFullIdentityLifecycle::test_01_did_create PASSED
...
tests/integration/test_full_flow.py::TestRequireWebAuthnGate::test_token_denied_without_credential PASSED
tests/integration/test_ledger_tamper_e2e.py::TestLedgerTamperChainReaction::test_06_token_issuance_blocked_after_tamper PASSED
...
====================== XX passed ======================
```

> **Note**: Integration tests do **not** require Redis, a browser, or any
> external infrastructure. All operations run in-process against the TestClient.

---

## 11. New Cross-Cutting Features (Phases 2 & 3)

### Phase 2a — WebAuthn → Token Policy Bridge

`POST /tokens/issue` now accepts `"require_webauthn": true`:

```json
{
  "did": "did:mesh:key:...",
  "scope": ["read:profile"],
  "require_webauthn": true
}
```

When set, the Zero-Trust policy engine runs **Check 5**:
the DID must have at least one registered WebAuthn credential or issuance is denied (403).

This is the enforcement point for the **full ceremony flow**:
`DID Create → WebAuthn Register → WebAuthn Authenticate → Token Issue`.
