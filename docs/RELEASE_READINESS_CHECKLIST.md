# TrustMesh Release Readiness Checklist

Use this checklist to prepare a local demonstration or review a proposed
submission. It is not a production-readiness certification. For setup details,
refer to the [Deployment Guide](DEPLOYMENT_GUIDE.md) and
[Local Demo Runbook](LOCAL_DEMO_RUNBOOK.md).

Record the date, commit or branch, environment, commands run, exit status, and
relevant output for each verification. Redact credentials, tokens, private
keys, and other sensitive values from any saved evidence.

## 1. Git and repository cleanliness

- [ ] Confirm the branch and commit being reviewed:

  ```powershell
  git branch --show-current
  git rev-parse HEAD
  ```

- [ ] Review tracked changes, staged changes, and untracked files:

  ```powershell
  git status --short
  git diff --stat
  git diff --cached --stat
  ```

- [ ] Confirm every changed file is intentional and in scope. Do not overwrite,
  delete, or stage unrelated untracked files.
- [ ] Check whitespace in tracked changes:

  ```powershell
  git diff --check
  git diff --cached --check
  ```

- [ ] Confirm no signing keys, certificates' private keys, access tokens, or
  environment files were added to the change.

## 2. Environment variables and secret/key handling

- [ ] Configure the required Compose variables from the
  [Deployment Guide](DEPLOYMENT_GUIDE.md): `TOKEN_KEY_HOST_DIR`,
  `ALLOWED_ORIGINS`, `WEBAUTHN_RP_ID`, and `WEBAUTHN_ORIGIN`.
- [ ] Keep JWT signing keys outside the repository. Do not paste key material,
  credentials, or tokens into the checklist, logs, screenshots, or submitted
  evidence.
- [ ] Keep TLS certificate private keys local and do not commit them.
- [ ] Check that `.env` files and key/certificate files are not included in
  changes or build context unexpectedly. The repository's `.dockerignore`
  excludes environment files and PEM/key material.
- [ ] Review optional admin configuration, if used:
  `ADMIN_JWT_PUBLIC_KEY` must be a public key only; `ADMIN_DIDS` must contain
  the intended admin subject identifiers. Do not configure an admin private
  key in the application.
- [ ] Keep the demonstration-only ledger tamper feature disabled unless the
  specific demonstration requires it; admin authorization still applies.

## 3. JWT signing-key validation

- [ ] Confirm `TOKEN_KEY_HOST_DIR` points to an existing directory outside the
  repository containing `token_signing_private.pem` and
  `token_signing_public.pem`.
- [ ] Confirm the pair is a matching Ed25519 pair using the approved key
  management process. Do not generate or replace release keys as a
  troubleshooting shortcut.
- [ ] Confirm the application mounts the key directory read-only and uses
  `/run/secrets/trustmesh-keys` as `TOKEN_KEY_DIR`.
- [ ] Confirm startup accepts the configured pair and fails closed for missing,
  unreadable, invalid, or mismatched keys. The key loader does not create or
  replace these files.
- [ ] Use the signing-key unit tests when checking loader behavior; never print
  or record private-key contents.

## 4. CORS configuration and allowed origins

- [ ] Set `ALLOWED_ORIGINS` to the exact browser origin or explicit
  comma-separated origins required for this environment. For the documented
  local HTTPS deployment, use `https://trustmesh.test`.
- [ ] Confirm origins include the scheme and do not contain unintended hosts,
  ports, or wildcard `*`.
- [ ] Run the CORS regression tests:

  ```powershell
  python -m pytest tests/unit/test_app_cors.py -v
  ```

- [ ] For an active deployment, verify the expected browser origin succeeds
  and an unapproved origin is not granted CORS access. Do not infer this only
  from a successful page load.

## 5. WebAuthn configuration

- [ ] Confirm `WEBAUTHN_RP_ID` is the intended relying-party domain and
  `WEBAUTHN_ORIGIN` exactly matches the browser origin, including scheme and
  port where applicable. For the documented local HTTPS deployment, these are
  `trustmesh.test` and `https://trustmesh.test`.
- [ ] Confirm any `WEBAUTHN_RP_NAME` override is intentional.
- [ ] Remember that WebAuthn credentials are bound to an RP ID; credentials
  registered at `localhost` are not automatically valid for `trustmesh.test`.
- [ ] Run the relevant WebAuthn unit tests:

  ```powershell
  python -m pytest tests/unit/test_webauthn.py -v
  ```

- [ ] If demonstrating browser passkeys, test registration and authentication
  using the actual hostname and browser origin. A successful passkey login
  does not create an application JWT, admin JWT, cookie, or server-side
  authenticated session.

## 6. Redis revocation storage and persistence

- [ ] Confirm the app uses the intended Redis URL. In Compose, it must use the
  service hostname `redis`, not `localhost`.
- [ ] Confirm Redis is healthy and check its configured persistence and
  eviction settings:

  ```powershell
  docker compose ps redis
  docker compose exec -T redis redis-cli ping
  docker compose exec -T redis redis-cli INFO persistence
  docker compose exec -T redis redis-cli CONFIG GET appendonly
  docker compose exec -T redis redis-cli CONFIG GET appendfsync
  docker compose exec -T redis redis-cli CONFIG GET maxmemory-policy
  ```

- [ ] For admin authorization, verify AOF is enabled, `appendfsync` is
  `always`, `aof_last_write_status` is `ok`, and `maxmemory-policy` is
  `noeviction`.
- [ ] Confirm the `redis_data` named volume is present for the Compose
  deployment. Do not use `docker compose down -v` when data must be retained.
- [ ] Do not treat Redis `PING` or reported configuration as proof of backup,
  recovery, replication, or end-to-end durability. Do not use the development
  in-memory fallback for admin authorization.
- [ ] Run revocation tests where applicable:

  ```powershell
  python -m pytest tests/unit/test_tokens_revocation.py -v
  ```

## 7. Ledger integrity and audit verification

- [ ] Verify ledger integrity through the running application:

  ```powershell
  curl.exe -fsS https://trustmesh.test/api/v1/ledger/verify
  ```

- [ ] Confirm the response indicates a valid ledger and record the result
  without altering the ledger.
- [ ] Run the ledger regression tests when relevant:

  ```powershell
  python -m pytest tests/unit/test_ledger_chain.py tests/unit/test_ledger_tampering.py -v
  ```

- [ ] Describe the ledger accurately: the primary application ledger is a
  process-local simulated hash-linked log, not a replicated or consensus-based
  blockchain. Its state is not persisted across app restarts by the Compose
  volume.

## 8. Admin API authorization

- [ ] Confirm protected admin routes require a separately issued admin JWT and
  validate the configured public key, allowed subject (`ADMIN_DIDS`), required
  scope, issuer/audience, token lifetime, and revocation state.
- [ ] Confirm the application does not issue admin tokens and that a valid
  user/passkey login is not an admin authorization handoff.
- [ ] Exercise the admin authorization regression tests:

  ```powershell
  python -m pytest tests/unit/test_admin_router.py -v
  ```

- [ ] Verify missing or invalid credentials are rejected and authorization
  failures remain fail-closed. Redis availability and verifiable required
  persistence settings are necessary for admin authorization.
- [ ] Do not include bearer tokens or private signing material in command
  history, logs, or evidence.

## 9. Dashboard functionality and limitations

- [ ] Verify the dashboard loads at `https://trustmesh.test/dashboard/` and
  inspect browser developer tools for failed public API requests.
- [ ] Confirm its current scope is a read-only public-data interface.
- [ ] Do not present it as providing admin login, admin-token handoff, or an
  authenticated admin console; these are not currently implemented.
- [ ] Do not claim dashboard security-event monitoring: there is no
  security-event store API.
- [ ] Keep the TrustMesh dashboard distinct from the Traefik management
  dashboard, which is disabled in this configuration.
- [ ] Do not promise durable ledger continuity across restarts: the main ledger
  state is process-local.

## 10. Docker image and Compose configuration

- [ ] From the repository root, render and review the Compose configuration:

  ```powershell
  docker compose config
  ```

- [ ] Confirm required variables resolve and the rendered configuration does
  not expose secret values in saved output.
- [ ] Build the image successfully:

  ```powershell
  docker compose build
  ```

- [ ] Review that Compose builds the app from the repository `Dockerfile`,
  mounts signing keys read-only, keeps Redis on the private backend network,
  and publishes the proxy only on loopback ports `8080` and `443`.
- [ ] Confirm Compose retains the named `redis_data` and `webauthn_data`
  volumes, and that the configured health checks match the deployment guide.

## 11. App, Redis, and Traefik container status

- [ ] Start the local deployment and inspect service state:

  ```powershell
  docker compose up -d
  docker compose ps
  docker compose logs app redis traefik
  ```

- [ ] Confirm `app` and `redis` report `healthy`; confirm `traefik` is
  `running`. Traefik has no configured container health check, so do not
  require a `healthy` status for it.
- [ ] Check logs for startup errors, repeated restarts, failed dependencies,
  and configuration problems.
- [ ] Confirm the app health check and SQLite quick check complete; a running
  container alone is not sufficient.

## 12. HTTPS and HTTP redirect verification

- [ ] Confirm `trustmesh.test` resolves to `127.0.0.1` on the local demo host
  and that the locally trusted certificate covers this hostname. See the
  [Deployment Guide](DEPLOYMENT_GUIDE.md) and
  [Local Demo Runbook](LOCAL_DEMO_RUNBOOK.md) for setup instructions.
- [ ] Verify health and dashboard responses:

  ```powershell
  curl.exe -fsS https://trustmesh.test/health
  curl.exe -sS -o NUL -w "HTTP %{http_code}`n" https://trustmesh.test/dashboard/
  ```

- [ ] Verify HTTP redirects without following the redirect:

  ```powershell
  curl.exe -sS -o NUL -w "HTTP %{http_code}`nRedirect: %{redirect_url}`n" http://trustmesh.test:8080/
  ```

- [ ] For the documented local deployment, expected results are healthy
  `/health`, dashboard HTTP `200`, and HTTP port `8080` returning `308` to
  HTTPS. Do not bypass certificate validation as a permanent workaround.

## 13. Regression tests and test-result recording

- [ ] Run and record the selected regression command:

  ```powershell
  python -m pytest tests/unit/test_admin_router.py tests/unit/test_app_cors.py tests/security/test_security_audit.py -v
  ```

- [ ] A previous run of this selected suite passed **80 tests with 6
  warnings**. Treat that as a historical result, not a result for the current
  commit; rerun the command and record its actual output, date, and exit code.
- [ ] The full test suite has **not** been confirmed as passing. Do not state
  that it passed unless it has been run successfully for the reviewed code and
  its result has been recorded.
- [ ] If running the full suite, capture the exact command, completion status,
  pass/fail/skip counts, warnings, and any failures. Investigate failures
  before claiming readiness.
- [ ] Keep test evidence free of secrets and distinguish selected regression
  results from full-suite results.

## 14. Final review before submission or demonstration

- [ ] Recheck `git status --short`, staged and unstaged diffs, and
  `git diff --check`. Confirm only intended files are included; do not stage or
  commit unrelated files.
- [ ] Confirm environment files, private signing keys, TLS private keys, and
  tokens are excluded from the submission and captured evidence.
- [ ] Ensure all documented test and deployment results identify whether they
  are current or historical and do not exceed the evidence collected.
- [ ] Clearly disclose the read-only dashboard, missing admin login/token
  handoff, absence of the security-event store API, and process-local ledger
  limitation.
- [ ] If demonstrating locally, use the
  [Local Demo Runbook](LOCAL_DEMO_RUNBOOK.md) for startup, endpoint checks,
  and safe shutdown. Use `docker compose down` without `-v` to preserve named
  volumes.
- [ ] Do not describe the local Docker deployment or this checklist as a
  production-readiness certification.

## Recorded local verification

The local Docker deployment was verified on **November 11, 2026**: the app
and Redis containers were healthy, Traefik was running, `/health` returned
healthy, Redis persistence and eviction checks were verified, and the ledger
audit was valid. `/dashboard/` returned HTTP `200`, and HTTP on port `8080`
returned HTTP `308` redirecting to HTTPS. These are results of that local
verification, not a production-readiness certification or a guarantee for
other environments.
