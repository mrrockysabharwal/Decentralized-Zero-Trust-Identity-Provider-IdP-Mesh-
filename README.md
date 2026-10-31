# Decentralized Zero-Trust Identity Provider (IdP) Mesh

A decentralized Zero-Trust Identity Provider built with Python and FastAPI. The system replaces centralized username/password databases with Decentralized Identifiers (DIDs), WebAuthn (FIDO2) biometric ceremony simulation, cryptographic identity anchoring on a simulated blockchain ledger, and continuous Zero-Trust JWT policy validation.

---

## Architecture Overview

```text
Browser Dashboard ──> FastAPI Application (:8000)
                           ├── /dashboard/         ──> Static Admin Web Dashboard
                           ├── /api/v1/did/*       ──> Module A: DID Registry & Ed25519 Cryptography
                           ├── /api/v1/webauthn/*  ──> Module B: WebAuthn / FIDO2 Biometric Ceremonies
                           ├── /api/v1/ledger/*    ──> Module C: Simulated Hash-Linked Blockchain Ledger
                           ├── /api/v1/tokens/*    ──> Module E: JWT Access Tokens & Zero-Trust Policy Engine
                           ├── /api/v1/admin/*     ──> Module D: Admin Dashboard & Telemetry API
                           └── /health             ──> Composite Subsystem Health Probe
```

### Module Responsibilities

| Module | Component | Owner | Branch | API Prefix | Description |
|:---|:---|:---|:---|:---|:---|
| **Core Backend** | Main Entry & Orchestration | Member 1 | `main` | `/` | Boots FastAPI, manages CORS, wires shared singletons across modules. |
| **Module A** | DID Registry & Cryptography | Member 3 | `feature/identity-module` | `/api/v1/did` | Ed25519 key generation, W3C DID Core 1.0 `did:mesh:key` derivation, document resolution, signature verification, and ledger anchoring. |
| **Module B** | WebAuthn / FIDO2 Passwordless Auth | Member 2 | `feature/webauthn-module` | `/api/v1/webauthn` | Dual-phase ceremonies (Begin / Complete), TTL-enforced nonces in `ChallengeStore`, credential registration, sign-count replay defense. |
| **Module C** | Simulated Blockchain Ledger | Member 4 | `midhun` | `/api/v1/ledger` | SHA-256 hash-chained block records (`Genesis` $\to$ `Create` $\to$ `Update` $\to$ `Deactivate`), tamper detection via `verify_integrity()`, optional JSON file persistence. |
| **Module D** | Admin Dashboard API | Member 6 | `feature/admin-dashboard` | `/api/v1/admin` | Aggregate stats, real-time cryptographic audit, emergency token revocation, tamper simulation endpoint. |
| **Module E** | JWT Access Tokens & Zero-Trust Engine | Member 5 | `member5` | `/api/v1/tokens` | Short-lived asymmetric JWT issuance (EdDSA / Ed25519), Redis/in-memory JTI revocation deny-list, 5-stage Zero-Trust verification gate. |
| **Frontend** | Browser Administration UI | Member 6 | `Albin-Gervasis` | `/dashboard/` | Static HTML/CSS/JS dashboard inspecting live ledger blocks, DIDs, system health, and token verification. |

---

## Zero-Trust Principles Applied

1. **Deterministic Identity**: DIDs are derived mathematically from public keys (`did:mesh:key:...`). They cannot be spoofed or centrally fabricated.
2. **Never Trust, Always Verify**: Every token request validates that:
   * The DID is registered on the ledger.
   * The DID has not been deactivated.
   * The blockchain ledger hash chain is completely intact (no tampering).
   * Requested permission scopes are permitted by policy.
   * (Optional) The DID has a registered WebAuthn credential bound to it.
3. **Cryptographic Immutability**: If any past block in the ledger is altered (e.g. key tampered with), the hash chain breaks, `verify_integrity()` returns `False`, and token issuance immediately halts with `403 Forbidden`.

---

## Directory Layout

```text
├── app/
│   ├── main.py                     # Central FastAPI application, shared wiring, static dashboard mount
│   └── modules/
│       ├── admin/                  # Module D: Admin Dashboard API
│       ├── did/                    # Module A: DID Registry & HTTP routes
│       ├── identity/               # Module A: Ed25519 and DID core cryptographic services
│       ├── ledger/                 # Module C: Simulated blockchain chain, models, hasher, router
│       ├── tokens/                 # Module E: JWT engine, Zero-Trust policy engine, revocation
│       └── webauthn/               # Module B: WebAuthn ceremonies, challenge store, credential store
├── frontend/
│   ├── README.md                   # Frontend architecture notes
│   └── dashboard/
│       ├── index.html              # Static Admin Dashboard UI
│       ├── app.js                  # Frontend API integration logic
│       └── style.css               # Dashboard styling
├── backend/
│   └── README.md                   # Backend integration guide
├── docs/                           # Architecture, API specifications, and audits
│   ├── README.md                   # Documentation index
│   ├── MODULE_A_DID.md             # Specification for Module A
│   ├── MODULE_B_WEBAUTHN.md        # Specification for Module B
│   ├── MODULE_C_LEDGER.md          # Specification for Module C
│   ├── MODULE_D_ADMIN.md           # Specification for Module D
│   ├── MODULE_E_TOKENS.md          # Specification for Module E
│   ├── api-contract.md             # API contract specification
│   ├── architecture-audit.md       # Architecture audit report
│   └── implementation-plan.md      # Implementation plan
├── tests/
│   ├── conftest.py                 # Pytest shared fixtures
│   ├── integration/
│   │   ├── test_full_flow.py       # Full end-to-end ceremony integration tests
│   │   └── test_ledger_tamper_e2e.py # Cascading tamper-detection tests
│   ├── unit/                       # Unit tests for each module
│   │   ├── test_admin_router.py
│   │   ├── test_app_cors.py
│   │   ├── test_did_router.py
│   │   ├── test_identity.py
│   │   ├── test_ledger_chain.py
│   │   ├── test_ledger_models_hasher.py
│   │   ├── test_ledger_persistence.py
│   │   ├── test_ledger_router.py
│   │   ├── test_ledger_tampering.py
│   │   ├── test_tokens_jwt_engine.py
│   │   ├── test_tokens_policy.py
│   │   ├── test_tokens_revocation.py
│   │   ├── test_tokens_router.py
│   │   └── test_webauthn.py
│   └── security/                   # Security invariant tests
└── requirements.txt                # Project dependencies
```

---

## Quickstart

### 1. Install Dependencies

Requires Python 3.10+:

```powershell
pip install -r requirements.txt
```

### 2. Run the Application

```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Access UIs & Endpoints

* **Interactive Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
* **ReDoc Documentation**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
* **Admin Web Dashboard**: [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/)
* **Composite Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

## Running the Test Suite

Run the full pytest suite (289 tests across unit, integration, and security checks):

```powershell
pytest
```
