# TrustMesh Local Demo Runbook

This runbook starts and verifies the repository's Docker Compose deployment for
a local TrustMesh demonstration. It is for local development and evaluation
only; it does not describe a production-ready deployment.

## Purpose and prerequisites

The Compose stack runs the combined FastAPI application, Redis, and Traefik.
Traefik serves the application at `https://trustmesh.test` and redirects HTTP
traffic to HTTPS.

Before starting, have:

- Docker Desktop running with `docker compose` available.
- The repository checkout and its Compose, Dockerfile, and Traefik
  configuration.
- A provisioned, matching Ed25519 JWT signing-key pair in an existing
  directory outside the repository. Follow the
  [Deployment Guide](DEPLOYMENT_GUIDE.md) for key handling and required
  environment configuration; do not put key material in this repository.
- A locally trusted certificate for `trustmesh.test` at
  `certs\trustmesh.test.pem` and `certs\trustmesh.test-key.pem`. Follow the
  [Deployment Guide](DEPLOYMENT_GUIDE.md) for mkcert setup, certificate
  generation, and the Windows hosts-file entry.
- The required Compose environment variables configured as described in the
  [Deployment Guide](DEPLOYMENT_GUIDE.md): `TOKEN_KEY_HOST_DIR`,
  `ALLOWED_ORIGINS`, `WEBAUTHN_RP_ID`, and `WEBAUTHN_ORIGIN`.

Run the following PowerShell commands from the repository root. Set required
environment variables in the current shell or in the root `.env` file before
validating Compose. Use the exact values and setup steps in the Deployment
Guide.

## Validate and start

Validate the resolved Compose configuration:

```powershell
docker compose config
```

If validation succeeds, build the application image and start the services:

```powershell
docker compose build
docker compose up -d
```

The application depends on Redis passing its health check. Traefik starts
after the application is healthy. The application health check also verifies
the `/health` response and the WebAuthn SQLite database quick check.

## Inspect status and logs

Show service state and health:

```powershell
docker compose ps
```

The expected steady state is `app` healthy, `redis` healthy, and `traefik`
running. Traefik has no configured container health check, so it is expected
to show as running rather than healthy.

View all service logs, or follow selected services:

```powershell
docker compose logs app redis traefik
docker compose logs -f app redis traefik
```

Press Ctrl+C to stop following logs; this does not stop the containers.

## Verify the endpoints

These commands use `curl.exe` from PowerShell. A locally trusted mkcert
certificate and working `trustmesh.test` hosts-file entry are needed for HTTPS.

Check application health:

```powershell
curl.exe -fsS https://trustmesh.test/health
```

The JSON response should include `"status":"healthy"`. This is a health result,
not a production-readiness or end-to-end durability guarantee.

Check that the TrustMesh dashboard is served successfully:

```powershell
curl.exe -sS -o NUL -w "HTTP %{http_code}`n" https://trustmesh.test/dashboard/
```

Expect HTTP `200`. The same URL can be opened in a browser:

```text
https://trustmesh.test/dashboard/
```

Check the HTTP-to-HTTPS redirect without following it:

```powershell
curl.exe -sS -o NUL -w "HTTP %{http_code}`nRedirect: %{redirect_url}`n" http://trustmesh.test:8080/
```

Expect HTTP `308 Permanent Redirect` and a redirect URL using HTTPS. The
Compose configuration binds HTTP to host port `8080` and HTTPS to host port
`443`, both on loopback.

## Demonstrate the dashboard

Open `https://trustmesh.test/dashboard/` in a browser. The dashboard is a
read-only interface for public data, including the ledger and status
information available from the application. You can show its page load and
compare its status with `/health`.

The dashboard does **not** currently provide admin login or admin-token
handoff. It is not an authenticated admin console, and its visible controls
must not be presented as a working authenticated admin flow. There is also no
security-event store API for dashboard event monitoring. The Traefik
management dashboard is disabled and is separate from the TrustMesh dashboard.

## Verified local results

The following results were verified for the local deployment on November 11,
2026:

- The app container was healthy, Redis was healthy, and Traefik was running.
- `https://trustmesh.test/health` returned `status: healthy`.
- Redis persistence and eviction checks passed, and the ledger audit was valid.
- `https://trustmesh.test/dashboard/` returned HTTP `200 OK`.
- `http://trustmesh.test:8080/` returned HTTP `308 Permanent Redirect` to
  HTTPS.

These results describe that verification run; they are not a guarantee about
other machines or subsequent runs. Redis reporting its persistence and
eviction configuration is not, by itself, a backup, recovery, or
end-to-end durability guarantee.

## Troubleshooting

| Symptom | Checks |
|---|---|
| Docker commands fail or the daemon is unavailable | Start Docker Desktop, confirm its engine is running, then retry `docker compose config` and `docker compose ps` from the repository root. |
| `docker compose config` reports missing variables | Set `TOKEN_KEY_HOST_DIR`, `ALLOWED_ORIGINS`, `WEBAUTHN_RP_ID`, and `WEBAUTHN_ORIGIN` as shown in the Deployment Guide. Re-run `docker compose config`. |
| App exits during startup | Inspect `docker compose logs app`. Confirm the external signing-key directory exists and contains the matching required files, and check the required Compose variables. Do not copy key material into the repository or logs. |
| Certificate files cannot be mounted, or the browser reports a certificate error | Confirm both expected files exist under `certs\`, the certificate is for `trustmesh.test`, and mkcert's local CA is installed on the browsing machine. Use the Deployment Guide's certificate instructions; do not permanently bypass browser certificate checks. |
| `trustmesh.test` does not resolve | Confirm the Windows hosts file maps `trustmesh.test` to `127.0.0.1`, as described in the Deployment Guide. |
| A port is already in use | Check whether another process is using loopback port `8080` or `443`. Resolve the conflict before starting the stack. |
| App or Redis remains unhealthy | Run `docker compose ps` and inspect `docker compose logs app redis`. Redis must pass `redis-cli ping`; the app health check also requires a healthy `/health` result and a successful SQLite quick check. Check required environment and mounted files. |
| Health is degraded, or the dashboard cannot load data | Inspect app and Redis logs and verify `https://trustmesh.test/health`. Check that Redis is reachable and configured as required by the Deployment Guide. Browser developer tools can show failed dashboard API requests. |
| Dashboard loads but an admin action or event view is unavailable | This is an implementation limitation: the dashboard has no admin login/token handoff, and there is no security-event store API for dashboard monitoring. Do not troubleshoot this as a local configuration problem. |

## Safe shutdown

Stop and remove the Compose containers and networks while preserving the
`redis_data` and `webauthn_data` named volumes:

```powershell
docker compose down
```

Do **not** add `-v` or `--volumes` if you want to preserve the named volumes.
Restart the demo later with `docker compose up -d`.
