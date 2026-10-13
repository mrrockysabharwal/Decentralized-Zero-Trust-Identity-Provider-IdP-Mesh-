# Member 6 — Dashboard API Contract
**Date:** 2026-10-14
**Author:** Member 6 (Dashboard, Testing and Deployment)
**Status:** Proposed — requires team review and approval

This document defines the API contract the administrative dashboard will consume.
It distinguishes between endpoints already implemented in the repository and endpoints
that Member 6 must create or request from other members.

---

## 1. Base URL Convention

All REST endpoints follow the prefix convention proposed in `docs/MODULE_C_LEDGER.md`:

```
/api/v1
```

Member 1 must mount all routers under this prefix in `app/main.py`.

Full example: `GET https://idp-mesh.local/api/v1/ledger/verify`

---

## 2. Authentication and Authorization for Dashboard Endpoints

All dashboard endpoints require an authenticated administrator session.

**Proposed mechanism (to be confirmed with Member 1 and Member 5):**
- The dashboard backend verifies a JWT issued by Member 5's token service.
- The JWT must contain a claim identifying the principal as an administrator role.
- Endpoints return `401 Unauthorized` if no valid token is present.
- Endpoints return `403 Forbidden` if the token is valid but the role is insufficient.
- Member 6 does NOT implement token issuance — that belongs to Member 5.

**Open question for Member 5:** What is the exact JWT claim name and administrator
role value? Example: `"role": "admin"` or `"scope": "admin:read"`.

---

## 3. Existing Endpoints (IMPLEMENTED — Member 4)

These endpoints already exist in `app/modules/ledger/router.py`.
The dashboard can consume them directly once `app/main.py` mounts the router.

### 3.1 GET /api/v1/ledger

**Purpose:** Retrieve all blocks on the simulated ledger for display in a ledger viewer table.

**Auth required:** Proposed — admin JWT (currently no auth on the existing router)

**Query parameters:** None (pagination can be added if chain grows large)

**Response 200:**
```json
[
  {
    "index": 0,
    "timestamp": "2026-10-14T00:00:00.000000+00:00",
    "did": "did:mesh:genesis",
    "doc_hash": "a4b7c8...",
    "operation": "GENESIS",
    "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "record_hash": "e1f2a3...",
    "metadata": {"network": "idp-mesh-simulated-v1"}
  }
]
```

**Error responses:** 500 (unexpected server error)

**Owner:** Member 4 (implemented)

---

### 3.2 GET /api/v1/ledger/verify

**Purpose:** Real-time cryptographic audit status of the ledger chain.
Used by the dashboard integrity panel.

**Auth required:** Proposed — admin JWT

**Query parameters:** None

**Response 200 (chain intact):**
```json
{
  "valid": true,
  "error": null,
  "total_records": 12,
  "head_hash": "a4b7c8..."
}
```

**Response 200 (tampering detected):**
```json
{
  "valid": false,
  "error": "Data tampering detected at record #3: ...",
  "total_records": 12,
  "head_hash": "a4b7c8..."
}
```

**Error responses:** 500

**Owner:** Member 4 (implemented)

---

### 3.3 GET /api/v1/ledger/history/{did}

**Purpose:** Retrieve the chronological history of a specific DID.

**Auth required:** Proposed — admin JWT

**Path parameter:** `did` — the Decentralized Identifier string

**Response 200:** Array of `LedgerRecord` objects (same schema as 3.1)

**Response 404:**
```json
{"detail": "No ledger records found for DID 'did:mesh:key:...'"}
```

**Owner:** Member 4 (implemented)

---

### 3.4 GET /api/v1/ledger/latest/{did}

**Purpose:** Retrieve the most recent verified state for a DID.

**Auth required:** Proposed — admin JWT

**Path parameter:** `did`

**Response 200:** Single `LedgerRecord` object

**Response 404:** `{"detail": "DID '...' is not registered on the ledger"}`

**Owner:** Member 4 (implemented)

---

### 3.5 POST /api/v1/ledger/simulate-tamper

**Purpose:** Simulate a malicious tamper attack for dashboard demonstration.
Returns the updated integrity status immediately.

**Auth required:** Proposed — admin JWT (should be restricted to admin only)

**Request body:**
```json
{
  "index": 1,
  "field": "did",
  "new_value": "did:mesh:key:HackedIdentity",
  "recalculate_record_hash": false
}
```

**Response 200:** `IntegrityStatusResponse` (same as 3.2)

**Owner:** Member 4 (implemented)

---

## 4. Proposed Endpoints (NEED TO BE IMPLEMENTED)

These endpoints are required for the dashboard but do not yet exist in the repository.
Member 6 will implement them in a new router at `app/modules/dashboard/router.py`
unless another member already owns the relevant data.

---

### 4.1 GET /api/v1/dashboard/summary

**Purpose:** Single request to populate the dashboard summary statistics cards.

**Auth required:** Admin JWT

**Query parameters:** None

**Response 200:**
```json
{
  "ledger_total_records": 24,
  "ledger_integrity": true,
  "ledger_head_hash": "a4b7c8...",
  "security_events_total": 142,
  "security_events_last_24h": 17,
  "active_dids": 10,
  "revoked_dids": 2,
  "services": {
    "ledger": "healthy",
    "auth": "unknown",
    "policy": "unknown",
    "redis": "unknown"
  }
}
```

**Notes:**
- `ledger_*` fields sourced from Member 4's ledger.
- `security_events_*` fields depend on Member 2 and Member 5 event stores (pending).
- `active_dids` and `revoked_dids` depend on Member 1 and Member 3 (pending).
- `services` health check pings sub-services or reads health flags.

**Status:** MUST IMPLEMENT — Member 6

---

### 4.2 GET /api/v1/dashboard/events

**Purpose:** Paginated list of security events for the dashboard event table.

**Auth required:** Admin JWT

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | 1 | Page number (1-based) |
| `page_size` | int | 20 | Records per page (max 100) |
| `event_type` | string | null | Filter by event type |
| `outcome` | string | null | Filter by outcome (success/failure) |
| `severity` | string | null | Filter by severity (low/medium/high/critical) |
| `from_ts` | datetime | null | ISO 8601 start timestamp |
| `to_ts` | datetime | null | ISO 8601 end timestamp |
| `did` | string | null | Filter by pseudonymous DID reference |

**Response 200:**
```json
{
  "total": 142,
  "page": 1,
  "page_size": 20,
  "events": [
    {
      "event_id": "evt_01J9X...",
      "timestamp": "2026-10-14T00:00:00Z",
      "event_type": "authentication_attempt",
      "outcome": "failure",
      "severity": "medium",
      "did_ref": "did:mesh:key:z6Mku...TRUNCATED",
      "reason": "webauthn_assertion_failed",
      "correlation_id": "req_abc123"
    }
  ]
}
```

**Notes:**
- `did_ref` must be a pseudonymous reference — never the full private DID key.
- `reason` codes must never expose passwords or cryptographic material.
- Pagination prevents exposing the entire event log at once.
- Actual event store depends on Members 2 and 5 providing a queryable source.

**Status:** MUST IMPLEMENT — Member 6 (depends on event store from Members 2 and 5)

---

### 4.3 GET /api/v1/dashboard/events/{event_id}

**Purpose:** Retrieve the full detail of a single security event.

**Auth required:** Admin JWT

**Path parameter:** `event_id`

**Response 200:**
```json
{
  "event_id": "evt_01J9X...",
  "timestamp": "2026-10-14T00:00:00Z",
  "event_type": "authentication_attempt",
  "outcome": "failure",
  "severity": "medium",
  "did_ref": "did:mesh:key:z6Mku...TRUNCATED",
  "reason": "webauthn_assertion_failed",
  "correlation_id": "req_abc123",
  "metadata": {
    "user_agent": "Mozilla/5.0",
    "source_ip_hash": "sha256:aabbcc..."
  }
}
```

**Notes:**
- `source_ip_hash` is hashed, never the raw IP.
- No passwords, tokens or private keys in the response.

**Response 404:** `{"detail": "Event not found"}`

**Status:** MUST IMPLEMENT — Member 6 (depends on event store)

---

### 4.4 GET /api/v1/dashboard/health

**Purpose:** Service health status panel.

**Auth required:** Admin JWT

**Response 200:**
```json
{
  "status": "degraded",
  "services": {
    "ledger": {"status": "healthy", "latency_ms": 2},
    "redis": {"status": "unreachable", "error": "Connection refused"},
    "auth": {"status": "unknown"},
    "policy": {"status": "unknown"}
  }
}
```

**Status:** MUST IMPLEMENT — Member 6

---

### 4.5 GET /api/v1/dashboard/ledger

**Purpose:** Dashboard-specific ledger view with pagination (wraps Member 4's endpoint).

**Auth required:** Admin JWT

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Rows per page (max 100) |
| `operation` | string | null | Filter by operation type |

**Response 200:**
```json
{
  "total": 24,
  "page": 1,
  "page_size": 20,
  "integrity_valid": true,
  "records": [ ... ]
}
```

**Status:** MUST IMPLEMENT — Member 6 (wraps existing `/api/v1/ledger`)

---

## 5. Security Event Data Model

The following minimal model is proposed for security events consumed by the dashboard.
It must be agreed with Members 2 (WebAuthn) and 5 (JWT/Redis) who generate events.

```python
class SecurityEvent(BaseModel):
    event_id: str          # Unique identifier (e.g., UUID or ULID)
    timestamp: str         # ISO 8601 UTC
    event_type: str        # e.g., "authentication_attempt", "token_revocation",
                           #       "policy_denial", "did_creation", "ledger_anchor"
    outcome: str           # "success" or "failure"
    severity: str          # "low", "medium", "high", "critical"
    did_ref: str           # Pseudonymous DID reference (truncated or hashed)
    reason: str            # Safe reason code — never passwords or secrets
    correlation_id: str    # Request correlation ID for tracing
    metadata: dict         # Optional non-sensitive context
```

**Fields NEVER included in events:**
- Private keys or key material
- Raw passwords or credentials
- Complete JWTs
- Raw IP addresses (hash if needed)
- Full biometric data

**Event types expected from each member:**

| Source member | Event types |
|---|---|
| Member 1 (Core API) | `api_request`, `identity_created`, `identity_updated` |
| Member 2 (WebAuthn) | `authentication_attempt`, `credential_registered` |
| Member 3 (DID/Crypto) | `did_created`, `did_updated`, `signature_verified` |
| Member 4 (Ledger) | `ledger_anchor`, `ledger_tamper_detected` |
| Member 5 (JWT/Redis) | `token_issued`, `token_revoked`, `policy_decision` |

---

## 6. Integration Dependencies from Other Members

| Dependency | Member | Required for | Interface needed | Status |
|---|---|---|---|---|
| `app/main.py` with router mounting | Member 1 | All endpoints to work | `app.include_router(ledger_router, prefix="/api/v1")` | MISSING |
| Security event store | Members 2 and 5 | `GET /events` dashboard | Queryable list (SQLite table or Redis list) | MISSING |
| JWT verification utility | Member 5 | Dashboard auth middleware | `verify_token(token) -> payload` | MISSING |
| Admin role claim definition | Member 5 | Authorization | JWT claim name and value | UNKNOWN |
| DID count / revocation list | Members 1 and 3 | Summary statistics | `GET /api/v1/identity/stats` or equivalent | MISSING |
| Health check endpoints | All members | Service health panel | Standard `/health` or `/status` per service | MISSING |
| Redis connection config | Member 5 | Health check | `REDIS_URL` env variable | UNKNOWN |

---

## 7. Error Handling Conventions

The dashboard API adopts FastAPI's default error format:

```json
{"detail": "Human-readable error description"}
```

| Code | Meaning |
|---|---|
| 200 | Success |
| 201 | Resource created |
| 400 | Invalid request |
| 401 | Missing or invalid authentication |
| 403 | Authenticated but insufficient privileges |
| 404 | Resource not found |
| 500 | Internal server error |
| 503 | Service unavailable (downstream dependency down) |

---

## 8. Open Questions Requiring Team Decision

1. What prefix does Member 1 use in `app/main.py`? (`/api/v1` assumed here)
2. What is the JWT claim name and value for administrator access?
3. Will security events be stored in SQLite, Redis or an in-memory log?
4. What is the agreed `.env` variable name for the Redis URL?
5. Does the `Shad` branch contain any event or auth implementation relevant to the dashboard?
6. Should pagination be cursor-based or page-number-based for large event logs?
