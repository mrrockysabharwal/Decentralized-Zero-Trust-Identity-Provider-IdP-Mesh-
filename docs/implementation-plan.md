# Implementation status and remaining phases

Updated 2026-11-02 for the `midhun` branch. The original 20-day schedule described
an earlier repository snapshot and is superseded by this current status.

## Implemented

- FastAPI application wiring for DID, WebAuthn, ledger, token, admin, login, and OIDC routes.
- DID and Ed25519 services; native browser WebAuthn registration and login.
- Shared hash-linked simulated ledger with JSON file persistence.
- Optional persistence for public core DID documents, enabled in Compose.
- Zero-Trust policy checks, JWT issue/verify/revoke routes, and server-assigned admin role.
- Admin dashboard API and frontend, including security-event history and composite health.
- Unit and integration test suites.
- Docker image, Compose services for API/Redis/Traefik, persistent storage volume, and local HTTPS routing.

Token issuance requires a verified authentication session; revocation requires the
caller's own valid access token. Admin routes require an unrevoked admin JWT. These
checks are implemented; earlier API-contract statements that these routes return
503 are stale.

## Validation completed in this pass

- `python -m pytest -q`: 304 passed, 4 subtests passed; 3 dependency deprecation/cache warnings.
- DID registry write/reload check passed with a temporary data file.
- Compose YAML parsed successfully and contains the API, Redis, and Traefik services.
- `git diff --check` passed.
- Docker Desktop Linux engine is available. `docker compose up --build -d` built the API
  image and started API, Redis, and Traefik. API and Redis report healthy. HTTPS health,
  login, signup-page, dashboard, and HTTP-to-HTTPS routes all return successfully. The
  browser WebAuthn registration and login ceremonies still need to be exercised.
  Traefik now uses a file provider to route to the API without a Docker socket mount.
- Added a dedicated `/register` passkey account-creation page. Registration rejects
  usernames that already have a passkey, preventing unauthenticated extra-credential
  enrollment; unfinished accounts with no credential can retry.
- Successful passkey login now opens `/account`, which shows the authenticated DID,
  token scope/expiry, and the result of calling the protected profile API. Sign-out
  revokes the user's own token.

## Deployed-flow validation (2026-11-03)

- Rebuilt and started the Compose stack. API and Redis reported healthy; HTTPS health,
  registration, login, and dashboard routes returned 200, and HTTP redirected to HTTPS.
- Completed browser passkey registration and login in headless Chromium with a virtual
  authenticator. Token issuance and the protected profile call succeeded. Self-revocation
  succeeded, and verification rejected the revoked token.
- A regular-user token was denied by the admin API (403); an unauthenticated request was
  denied (401). No administrator DID is configured in this deployment, so successful
  administrator access remains unverified.
- Restarted the full Compose stack. The passkey account and credential remained in the
  WebAuthn database; DID resolution and ledger history still succeeded. The JWT signing
  key remained in the data volume. The Redis revocation entry survived the restart, and
  the revoked token remained invalid afterward.
- The post-restart passkey credential row was confirmed in storage, but the virtual
  authenticator itself was scoped to its browser debugging session and was not available
  for another assertion after that session ended.

## Remaining phases

1. Configure the production hostname, trusted certificate, and administrator DID as
   described in `docs/deployment.md` before public exposure.

## Production TLS and host configuration

- Compose now accepts configurable Traefik route, certificate, and private-key paths;
  local development keeps its localhost defaults.
- Added `traefik/render-production-config.py` to validate production hostname, matching
  WebAuthn RP ID/origin, explicit CORS origins, administrator DID, and certificate/key
  files. It also checks certificate hostname coverage, validity dates, and matching
  private key before rendering a host-specific Traefik route. CA trust still depends on
  the supplied certificate chain.
- Documented production setup in `docs/deployment.md`. The actual public hostname,
  trusted certificate, and administrator DID must be supplied by the deployment
  operator before publishing the service.

## Shared authentication state

- Authentication sessions and WebAuthn challenges now support Redis with five-minute
  expirations. WebAuthn challenges are consumed atomically with Redis `GETDEL`.
- Compose selects Redis-backed state by default and waits for Redis health before API
  startup. When `EPHEMERAL_STATE_BACKEND=redis`, Redis connection failure stops startup
  instead of silently enabling per-process state. Direct single-process runs default
  to memory; set the variable to `redis` to enable shared state there.

## Administrator flow validation

- Added and passed `tests/integration/test_configured_admin_flow.py`. It creates a DID,
  configures it through `IDP_ADMIN_DIDS`, issues a JWT from an authenticated session,
  and confirms that the JWT can read the admin dashboard. Run it with the command in
  `docs/deployment.md`.
- This verifies configured role assignment and route authorization in-process. A
  deployed browser passkey ceremony for an administrator account remains a manual
  deployment check.

## External deployment values still required

- This workspace has no production hostname, TLS certificate/key, or provisioned
  administrator DID. Those values cannot be generated safely by the application
  implementation; supply them in `.env` before public deployment.
- The Docker engine was inaccessible from this session, so no live Compose deployment
  or deployed browser passkey validation was performed.
- Keep one API process for now. The ledger is loaded into a process-local object from a
  JSON file, and the core credential registry is also process-local; Redis sharing for
  sessions/challenges alone does not make concurrent replica writes safe. Those stores
  need a shared transactional backend before horizontal scaling.

The Shad passkey account database, core DID documents, ledger, audit events, JWT signing
keys, and Redis revocation entries are persisted by the Compose volumes. Authentication
sessions and WebAuthn challenges expire in Redis after five minutes.

Traefik uses its self-signed default certificate locally. This setup is for development;
it must use a trusted certificate before public deployment.
