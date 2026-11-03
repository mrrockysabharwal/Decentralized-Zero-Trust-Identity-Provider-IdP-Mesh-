# TrustMesh installation and setup

This guide covers the combined FastAPI application, `app.main:app`. It reflects the checked-in dependency manifests and runtime configuration; it does not provision keys, change an existing database, or claim production readiness.

## Prerequisites

- Python 3.10 or newer. The source uses Python 3.10 union type syntax; the repository does not publish a tested-version matrix.
- Git.
- A Redis server for durable revocation and admin authorization. Redis is not bundled.
- A provisioned Ed25519 JWT signing key pair in an existing external directory (see below).
- Node.js is not needed: frontend assets are static HTML/CSS/JavaScript.

The root `requirements.txt` is the dependency manifest for the combined app and tests. There is also a separate `backend/requirements.txt`, but the primary application should be installed from the repository root manifest.

## Clone and install

```powershell
git clone <repository-url>
Set-Location <repository-directory>
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Replace the clone placeholders with the repository URL and local directory. Do not use a destructive Git command to overwrite local work.

## Configure signing keys

Before importing `app.main`, configure `TOKEN_KEY_DIR` to an **existing directory outside the repository** containing both:

- `token_signing_private.pem`
- `token_signing_public.pem`

The application reads and validates the PEM files, verifies that both keys are Ed25519 and that they match, and never creates or overwrites either file. The private key must be accessible only to the service account and must not be copied into the repository. This guide deliberately provides no key-generation command or key material. Use the project's approved key-management process to provision the pair.

Startup fails if `TOKEN_KEY_DIR` is absent/blank, resolves inside the repository, points to a missing directory, or either file is missing, unreadable, invalid, or mismatched. A signing-key directory inside the checkout does not meet the external-directory requirement.

PowerShell environment example (path only; use your already-provisioned directory):

```powershell
$env:TOKEN_KEY_DIR = "C:\secure\trustmesh-token-keys"
```

## Environment variables

| Variable | Required | Default | Actual use |
|---|---:|---|---|
| `TOKEN_KEY_DIR` | Yes for `app.main:app` | None | Existing external directory containing the matching Ed25519 PEM key files above. |
| `REDIS_URL` | Required for durable revocation/admin use | `redis://localhost:6379/0` | Redis connection for the shared JTI revocation store. |
| `TRUSTMESH_ENV` | No | None | Must equal `development` (case-insensitive) to permit the optional memory fallback. |
| `TOKEN_REVOCATION_ALLOW_IN_MEMORY` | No | Disabled | Must be `1`, `true`, `yes`, or `on` together with `TRUSTMESH_ENV=development`; fallback is bounded, process-local, and not durable. It can never authorize admin requests. |
| `ALLOWED_ORIGINS` | No | Local development origins | Comma-separated CORS origin list for the combined app. `CORS_ORIGINS` is a fallback alias. Wildcard `*` is rejected. |
| `ADMIN_JWT_PUBLIC_KEY` | For admin endpoints | None | PEM public key for the externally issued admin JWT; newline characters may be represented as `\n`. Never configure the admin private key here. |
| `ADMIN_DIDS` | For admin endpoints | Empty | Comma-separated allowlist of admin JWT `sub` values. |
| `ENABLE_LEDGER_TAMPER_DEMO` | No | Disabled | Enables the demonstration-only tamper routes when set to `1`, `true`, `yes`, or `on`; admin authorization is still required. |
| `WEBAUTHN_RP_ID` | No | `localhost` | Relying-party ID used by the browser WebAuthn implementation. |
| `WEBAUTHN_RP_NAME` | No | `Zero Trust Identity Mesh` | WebAuthn relying-party display name. |
| `WEBAUTHN_ORIGIN` | No | `http://localhost:8000` | Exact browser origin expected by WebAuthn verification. |
| `WEBAUTHN_DB_PATH` | No | `backend/webauthn.sqlite3` | SQLite file used by the browser passkey flow. Startup initializes/updates its schema. |

`app.main` calls `python-dotenv`'s `load_dotenv()` before loading its application modules. Environment variables set in the shell take precedence. `backend/.env.example` is an example, not an automatically loaded configuration file.

Admin tokens are not issued by this application. The external admin issuer must sign an EdDSA JWT whose issuer and audience are `idp-mesh-admin`, whose subject is present in `ADMIN_DIDS`, and whose scope includes `admin:ledger`. Its lifetime is limited to 24 hours. Admin authentication and force-revocation also require Redis's required runtime settings to be verifiable.

## Redis setup and persistence

The application defaults to `redis://localhost:6379/0`. It checks Redis with a short connection timeout. With Redis unavailable, the main app can still start, but the revocation backend is unavailable, the composite health result is degraded, token verification cannot establish revocation status (503), and admin authentication fails closed (503).

For admin authentication, the connected Redis node must report all of the following:

- AOF enabled (`appendonly yes` and `aof_enabled=1`).
- `appendfsync always`.
- `aof_last_write_status=ok`.
- `maxmemory-policy noeviction`.

These checks use read-only Redis status/configuration commands. `configuration_verified` verifies reported settings only; it is not a guarantee of disk durability, replication, backup, or recovery. Configure and monitor those at the infrastructure layer. Managed Redis services that deny these inspection commands may remain unverifiable and therefore unusable for admin authentication.

If Redis is installed locally, configure those settings in its server configuration and start it using the installation method for that Redis distribution. For example, a compatible `redis-server` may accept:

```powershell
redis-server --appendonly yes --appendfsync always --maxmemory-policy noeviction
```

This command is illustrative; it does not configure persistent volumes, backups, or failover. Do not enable the in-memory fallback outside isolated development. Even when enabled, it is intentionally unsuitable for admin authentication.

## Start the combined application

After installing dependencies, provisioning the external signing key pair, and configuring Redis as required:

```powershell
$env:TOKEN_KEY_DIR = "C:\secure\trustmesh-token-keys"
$env:REDIS_URL = "redis://localhost:6379/0"
# Optional when serving the frontend from another origin:
$env:ALLOWED_ORIGINS = "http://localhost:3000"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Use `http://localhost:8000` (not `127.0.0.1`) for the portal unless `WEBAUTHN_ORIGIN` is adjusted to match the browser origin exactly. Open:

- API/OpenAPI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- Dashboard: `http://localhost:8000/dashboard/`
- Portal: `http://localhost:8000/portal/`
- Composite health: `http://localhost:8000/health` or `/api/v1/health`

The alternate `backend.main:app` is a separate FastAPI entry point for the browser passkey backend and its own unversioned ledger/OIDC routes. It is not equivalent to the combined application and does not provide the combined DID, token, or admin APIs. The root `app.main:app` mounts the backend passkey router directly.

## Frontend

The combined app serves `frontend/dashboard/` at `/dashboard/` and the portal assets at `/portal/` (as well as login asset routes). No frontend build or Node package install is required.

For optional dashboard-only static serving, run this from the repository root in another terminal:

```powershell
python -m http.server 3000
```

Then open `http://localhost:3000/frontend/dashboard/`; the dashboard JavaScript uses `http://localhost:8000/api/v1` for API calls when it is not served from port 8000. Set `ALLOWED_ORIGINS=http://localhost:3000` in the API process. The dashboard does not authenticate as an admin, so this does not unlock the protected admin API or the tamper action.

## Database and local data

The browser passkey API uses SQLite at `WEBAUTHN_DB_PATH`, defaulting to `backend/webauthn.sqlite3`. On startup, `init_db` creates missing tables and may add the `did` column to an older `users` table. Registration and login mutate this database. Review or explicitly set the path before starting the app if you must preserve an existing database unchanged. The OIDC helper separately names `backend/oidc/oidc.sqlite3`, but the current route handlers do not execute a working OIDC exchange.

The DID module registry, its challenge store, the simulated WebAuthn module stores, and the ledger singleton are in memory. Restarting the process loses those in-memory states.

## Troubleshooting

| Symptom | Likely cause and action |
|---|---|
| Startup says `TOKEN_KEY_DIR` must be set / external / existing | Set it before Uvicorn imports `app.main`; use an already-provisioned directory outside the checkout. Verify both filenames exist and their Ed25519 public/private keys match. Do not generate or overwrite keys as a troubleshooting shortcut. |
| Startup says key file is missing, unreadable, invalid, or mismatched | Correct the protected external key configuration through the approved key-management process. Do not paste key material into logs or documentation. |
| `GET /health` reports `degraded` or revocation is unavailable | Check that Redis is running at `REDIS_URL`, reachable from the app, and reports AOF/`appendfsync always`/`noeviction` as required. Check reported durability subfields rather than treating Redis ping alone as durable. |
| Admin API returns 401 | Send `Authorization: Bearer <admin-token>` with a valid EdDSA token from the external issuer. |
| Admin API returns 403 | Check the `admin:ledger` scope and that the signed token subject appears in `ADMIN_DIDS`. |
| Admin API returns 503 despite a valid token | Redis must be available and its persistence and eviction configuration must be verifiable. The memory backend is never accepted for admin auth. |
| Browser passkey verification fails on localhost | Use the configured `WEBAUTHN_ORIGIN` exactly. The default is `http://localhost:8000`; using `127.0.0.1`, another port, or an unconfigured origin will not match. Use a secure browser context for non-local deployments. |
| Portal cannot reach passkey endpoints | Ensure the combined `app.main:app` server is running; inspect browser network errors and CORS origins. Passkey endpoints are mounted at `/webauthn/...`, not under `/api/v1`. |
| Dashboard says API unavailable | Confirm `app.main:app` is listening on port 8000 and the browser can reach `/api/v1/ledger`, `/api/v1/ledger/verify`, `/api/v1/tokens/public-key`, `/api/v1/tokens/policy/scopes`, and `/api/v1/health`. Its separate-server API base currently falls back to localhost:8000. |
| A dashboard admin action returns 401/422 | The UI does not send an admin bearer token; its tamper request also targets the ledger demo route. Enablement requires `ENABLE_LEDGER_TAMPER_DEMO` plus a separately authenticated admin caller; the dashboard does not currently implement that flow. |
| `ModuleNotFoundError` during import | Activate the intended virtual environment and install the root `requirements.txt` from the repository root. The alternate backend requirements file is not the dependency manifest for `app.main:app`. |

For endpoint shapes and status codes, see [API documentation](API_DOCUMENTATION.md); for integration boundaries, see [Implementation status](IMPLEMENTATION_STATUS.md).
