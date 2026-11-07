# TrustMesh Local Docker Deployment

This guide covers the repository's local Docker Compose stack: the combined
`app.main:app` FastAPI application, Redis, and Traefik with local HTTPS.

This deployment is intended for development and evaluation only. It is not a
production deployment guide.

For direct Python installation, see the [Installation Guide](INSTALLATION_GUIDE.md).

## 1. Prerequisites

Before starting, ensure you have:

- Docker Desktop installed, with Docker Compose available as `docker compose`.
- [mkcert](https://github.com/FiloSottile/mkcert) installed for generating a
  locally trusted HTTPS certificate.
- A checkout of the repository containing `Dockerfile`,
  `docker-compose.yml`, `app/`, `backend/`, `frontend/`,
  `traefik/traefik.yml`, and `traefik/dynamic.yml`.
- A provisioned Ed25519 JWT signing key pair in an existing directory outside
  the repository. The signing-key directory must contain:
  - `token_signing_private.pem`
  - `token_signing_public.pem`

  The keys must match.

Run all Docker commands from the repository root. The certificate files
described in the [Local HTTPS Setup](#3-local-https-setup) section must exist
before starting the stack.

## 2. Environment Configuration

Docker Compose reads the following required values from the shell environment
or a root-level `.env` file.

| Variable | Required value / purpose |
|---|---|
| `TOKEN_KEY_HOST_DIR` | Absolute path to the existing external host directory containing the JWT signing keys. Compose mounts it read-only at `/run/secrets/trustmesh-keys`; the application uses this container path as `TOKEN_KEY_DIR`. |
| `ALLOWED_ORIGINS` | Explicit browser origin or comma-separated origins. For this HTTPS setup, use `https://trustmesh.test`. |
| `WEBAUTHN_RP_ID` | WebAuthn relying-party domain. Use `trustmesh.test`. |
| `WEBAUTHN_ORIGIN` | Exact browser origin, including scheme. Use `https://trustmesh.test`. |

### PowerShell example

Set the required environment variables before running Docker Compose:

```powershell
$env:TOKEN_KEY_HOST_DIR = "C:\secure\trustmesh-token-keys"
$env:ALLOWED_ORIGINS = "https://trustmesh.test"
$env:WEBAUTHN_RP_ID = "trustmesh.test"
$env:WEBAUTHN_ORIGIN = "https://trustmesh.test"
```

Make sure the signing-key directory already exists and contains both matching
PEM files.

The application does not create or replace these keys. Keep them outside the
repository. Never commit signing keys or include their contents in
documentation.

### Optional environment variables

| Variable | Default | Purpose |
|---|---|---|
| `WEBAUTHN_RP_NAME` | `TrustMesh` | WebAuthn relying-party display name. |
| `ADMIN_JWT_PUBLIC_KEY` | Empty | Public key for the separately issued admin JWT. Do not provide an admin private key. |
| `ADMIN_DIDS` | Empty | Comma-separated allowlist of admin JWT subjects. |
| `ENABLE_LEDGER_TAMPER_DEMO` | `false` | Enables the demonstration-only ledger tamper route. Admin authorization is still required. |

### Container configuration

Compose configures the following values inside the application container:

- `REDIS_URL`: `redis://redis:6379/0`
- `TOKEN_KEY_DIR`: `/run/secrets/trustmesh-keys`
- `WEBAUTHN_DB_PATH`: `/data/webauthn.sqlite3`

Do not replace the in-network Redis hostname with `localhost` inside the
application container.

## 3. Local HTTPS Setup

This deployment uses `trustmesh.test` as a local hostname and mkcert to
generate a locally trusted TLS certificate.

### Step 1: Install the local certificate authority

Run PowerShell and execute:

```powershell
mkcert -install
```

This installs mkcert's local certificate authority for the current machine.

### Step 2: Create the certificate directory

From the repository root, create the directory used by the Docker Compose
certificate mounts:

```powershell
New-Item -ItemType Directory -Force certs
```

### Step 3: Generate the certificate

Generate a certificate and private key for `trustmesh.test`:

```powershell
mkcert -cert-file certs\trustmesh.test.pem -key-file certs\trustmesh.test-key.pem trustmesh.test
```

The following files must exist before starting Docker Compose:

- Certificate: `certs\trustmesh.test.pem`
- Private key: `certs\trustmesh.test-key.pem`

The certificate private key is sensitive. Keep it local and never commit or
share it. The certificate is intended for this local development setup, not
public production use.

### Step 4: Configure the Windows hosts file

Open the Windows hosts file using an editor with administrator privileges:

```text
C:\Windows\System32\drivers\etc\hosts
```

Add this entry:

```text
127.0.0.1 trustmesh.test
```

Save the file.

This maps `trustmesh.test` to the local machine.

### WebAuthn note

WebAuthn credentials are bound to their relying-party domain. Credentials
registered under `localhost` are not automatically usable at `trustmesh.test`.
Users may need to register their credentials again.

## 4. Docker Deployment

After configuring the required environment variables and generating the TLS
certificate files, run the following commands from the repository root.

### Step 1: Validate the Compose configuration

```powershell
docker compose config
```

### Step 2: Build the application image

```powershell
docker compose build
```

### Step 3: Start the services

```powershell
docker compose up -d
```

### Step 4: Check container status

```powershell
docker compose ps
```

The application and Redis containers should report a healthy status after
successful startup.

### View service logs

To follow logs from the application, Redis, and Traefik:

```powershell
docker compose logs -f app redis traefik
```

### Stop the services

```powershell
docker compose down
```

The named volumes remain when using `docker compose down` without the `-v`
option.

## 5. Architecture and Local Network

The Docker Compose deployment contains three primary services.

### Traefik

- Acts as the reverse proxy.
- Listens on host loopback only.
- Maps host port `8080` to container HTTP port `80`.
- Maps host port `443` to container HTTPS port `443`.
- Redirects HTTP requests to HTTPS.
- Routes requests for `trustmesh.test` to the application at `app:8000`.

### Application

- Runs the combined FastAPI application.
- Is built using the root `Dockerfile`.
- Is not published directly on a host port.
- Is accessible through Traefik on the proxy network.

### Redis

- Provides the application's Redis-backed functionality.
- Is accessible to the application through the private backend network.
- Uses Append Only File (AOF) persistence.
- Configures `appendfsync always` and `noeviction`.

### Docker networks and volumes

- The proxy network connects Traefik and the application.
- The separate backend network is internal and connects the application and
  Redis. Traefik is not attached to this network.
- The `redis_data` named volume stores Redis data.
- The `webauthn_data` named volume stores the browser WebAuthn SQLite database
  at `/data/webauthn.sqlite3`.

### Health checks

The Redis container health check uses:

```text
redis-cli ping
```

A successful Redis ping alone does not establish the durability checks
required by admin authorization.

The application's `/health` endpoint also reflects revocation-store
availability and configuration.

The application container health check requires:

- The `/health` endpoint to report `healthy`.
- The WebAuthn SQLite database's `PRAGMA quick_check` to return `ok`.

Redis must pass its ping health check before the application starts. Traefik
waits for the application health check. Traefik does not have a configured
container health check.

### Traefik dashboard

The Traefik management dashboard is disabled through:

```yaml
api:
  dashboard: false
```

This is different from the TrustMesh web dashboard served by the application
at `/dashboard/`.

## 6. Access and Verification

After configuring the hosts file and starting the containers, open the
following addresses in your browser.

| Service | URL |
|---|---|
| TrustMesh application | [https://trustmesh.test/](https://trustmesh.test/) |
| TrustMesh web dashboard | [https://trustmesh.test/dashboard/](https://trustmesh.test/dashboard/) |
| Application health | [https://trustmesh.test/health](https://trustmesh.test/health) |

The TrustMesh dashboard is a read-only frontend view. It is not the Traefik
management UI and does not authenticate to protected admin endpoints. When
served through this reverse proxy, the dashboard uses the same-origin
`/api/v1` endpoint, which Traefik routes to the application.

### Verify service health

Check container status:

```powershell
docker compose ps
```

The application and Redis containers should report `healthy`.

You can also check the application health endpoint:

```text
https://trustmesh.test/health
```

The health endpoint should return a JSON status of `healthy` when the
application health check succeeds and Redis revocation checks are available
and report the required settings.

A degraded response means the service is running without a healthy dependency
result. Check the service logs and Redis configuration.

A healthy result is not a production-readiness or end-to-end durability
guarantee.

## 7. Troubleshooting

| Symptom | Checks |
|---|---|
| Compose reports a missing variable | Set `TOKEN_KEY_HOST_DIR`, `ALLOWED_ORIGINS`, `WEBAUTHN_RP_ID`, and `WEBAUTHN_ORIGIN` in the current shell or root `.env` file. Rerun `docker compose config`. |
| Application exits because the signing-key directory is missing | Confirm `TOKEN_KEY_HOST_DIR` points to an existing directory outside the repository containing both required PEM files. |
| Compose cannot mount the TLS files | Generate `certs\trustmesh.test.pem` and `certs\trustmesh.test-key.pem` with mkcert before starting Compose. The bind mounts require existing files. |
| A port is already in use | Check whether another process is listening on localhost port `8080` or `443`. Stop or reconfigure that process and retry. |
| `trustmesh.test` does not resolve | Verify that the Windows hosts file contains exactly `127.0.0.1 trustmesh.test`. Save it with administrator permission. |
| Browser reports an untrusted or mismatched certificate | Run `mkcert -install` on the browsing machine, regenerate the certificate for `trustmesh.test` at the expected paths, and access the exact HTTPS hostname. Do not bypass certificate validation as a permanent fix. |
| Application container is unhealthy or exits | Run `docker compose logs app`. Check the external signing-key mount and required environment variables. For health failures, also check `/health` and the SQLite database check in the container health status. |
| Redis container is unhealthy | Run `docker compose logs redis`. Confirm that the container starts and responds to its configured `redis-cli ping` health check. |
| Health is degraded or admin APIs return 503 | Confirm Redis is reachable and reports AOF enabled, `appendfsync always`, healthy AOF write status, and `maxmemory-policy noeviction`. Redis ping alone is insufficient for admin authorization. |
| Dashboard loads but data is unavailable | Check browser developer tools for failed `/api/v1` requests. Confirm that the application is healthy and Traefik is routing requests to the application. |

## 8. Limitations and Security Notes

This stack is intended for local development and evaluation. It is **not
production-ready**.

It does not provide:

- Production-grade key management.
- Backup and restore procedures.
- Distributed application state.
- Production deployment monitoring.

The DID registry, simulated WebAuthn state, and primary ledger are
process-local. Only Redis and the browser WebAuthn SQLite database use the
configured Docker volumes.

WebAuthn relying-party IDs are domain-specific. Credentials created at
`localhost` may need to be registered again at `trustmesh.test`.

The browser dashboard does not implement admin authentication. Protected admin
endpoints still require their configured authorization.

OIDC discovery is static, and the authorization, token, and userinfo flows are
incomplete. This deployment does not make TrustMesh a complete OIDC provider.

The use of `TRUSTMESH_ENV=production` in the Compose configuration does not
mean that the stack is production-ready. Review the security, persistence,
key-management, monitoring, and deployment requirements before considering
any public deployment.
