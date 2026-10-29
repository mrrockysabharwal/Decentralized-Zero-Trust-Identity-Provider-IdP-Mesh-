# Decentralized Zero-Trust Identity Provider Mesh

A Python and FastAPI prototype exploring decentralized identity records, tamper-evident ledger anchoring, and Zero-Trust token policies.

> **Project status:** The ledger, token verification components, API shell, and administrative dashboard are implemented. WebAuthn authentication and DID identity management are not integrated. Token issuance and revocation endpoints deliberately return `503` until authenticated identity and token ownership checks exist. This is not yet a production-ready or distributed identity provider.

## Current capabilities

- Append-only simulated ledger for DID lifecycle events, with SHA-256 hash linking and integrity verification.
- Optional JSON file persistence in the ledger class. The default application singleton is in-memory unless configured in code.
- Ed25519 JWT signing and verification components, public-key endpoint, and allowed-scope endpoint.
- Zero-Trust policy component that checks ledger registration, deactivation state, ledger integrity, and requested scopes.
- Redis-backed token revocation storage with an in-memory fallback. HTTP revocation is currently disabled pending ownership authorization.
- FastAPI endpoints and a browser dashboard for ledger inspection, integrity checks, health status, and token verification.
- Unit, integration, and security test suites are present in `tests/`.

## Architecture

```text
Browser dashboard ──> FastAPI application
                           ├── /api/v1/ledger/*  ──> Simulated hash-linked ledger
                           ├── /api/v1/tokens/*  ──> JWT / policy / revocation components
                           └── /health           ──> Composite subsystem status
```

The dashboard derives its identity list from ledger records. It does not represent a separate DID registry. Security events are not yet backed by an event store, so the dashboard reports that capability as unavailable rather than displaying simulated data.

## Project layout

```text
app/main.py                   FastAPI application, router wiring, health and dashboard mount
app/modules/ledger/           Hash-linked ledger, data models, hashing and API routes
app/modules/tokens/           JWT engine, policy checks, revocation store and API routes
frontend/dashboard/           Static administration dashboard
tests/                        Unit, integration and security tests
docs/                         Architecture, API, module and review documentation
```

## Run locally

Use Python 3.10 or newer. Install dependencies in a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Before importing the application, provision a matching Ed25519 private/public PEM key pair in a protected directory **outside the repository**, then set `TOKEN_KEY_DIR` to that directory. The application does not create signing keys, and startup fails when the variable or either valid key is missing. The private key must remain protected.

```powershell
$env:TOKEN_KEY_DIR = "C:\path\to\protected\token-keys"
# Optional: configure explicit comma-separated browser origins.
$env:ALLOWED_ORIGINS = "http://localhost:3000"
uvicorn app.main:app --reload --port 8000
```

Open the API docs at `http://localhost:8000/docs`. The application serves the dashboard at `http://localhost:8000/dashboard/`.

To serve the dashboard separately instead, follow [frontend/README.md](frontend/README.md). When using a separate origin, configure `ALLOWED_ORIGINS` explicitly.

## API overview

The API is mounted under `/api/v1`:

| Area | Routes | Notes |
|---|---|---|
| Ledger | `GET /ledger`, `/ledger/verify`, `/ledger/history/{did}`, `/ledger/latest/{did}` | Read and audit ledger records |
| Ledger writes | `POST /ledger/anchor`, `/ledger/simulate-tamper` | Anchoring and demonstration tampering; currently no caller authentication |
| Token verification | `POST /tokens/verify` | Verifies signature, standard claims and revocation status |
| Token metadata | `GET /tokens/public-key`, `/tokens/policy/scopes` | Publishes verification key and policy scope list |
| Token operations | `POST /tokens/issue`, `/tokens/revoke` | Return `503` until authentication and ownership authorization are integrated |
| Health | `GET /health`, `/api/v1/health` | Reports ledger, token subsystem, and pending identity integrations |

## Tests

The repository contains tests for the ledger, token engine, policy, revocation, API routes, CORS, integration behavior, and security invariants. Run them with:

```powershell
python -m pytest tests/ -v
```

## Current limitations

- WebAuthn/FIDO2 credential registration and assertion verification are not implemented.
- DID creation, resolution, and cryptographic identity lifecycle are not integrated.
- Token issuance and revocation are disabled at the HTTP layer until the service can authenticate a caller and verify ownership.
- The ledger is a single-process simulation, not a consensus-based distributed blockchain.
- The application does not configure ledger file persistence by default.
- Security event storage/API and deployment assets such as Docker Compose and Traefik are not present.
- Ledger write and tamper-demonstration routes currently lack authentication; restrict them to a trusted local environment until authorization is added.

See [docs/README.md](docs/README.md) for the documentation index and [docs/report.md](docs/report.md) for the implementation review and end-to-end flow.
