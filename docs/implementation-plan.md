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

## Remaining phases

1. **Exercise the full deployed flow:** complete browser passkey registration and login,
   token issuance and revocation, admin access, and persistence checks across restarts.
2. **Prepare production TLS and host configuration:** install a trusted certificate and
   set the public hostname, WebAuthn RP ID/origin, CORS origins, and administrator DIDs.
3. **Share ephemeral state before scaling:** authentication sessions and WebAuthn
   challenges are in process memory. Use shared state before adding API
   workers or replicas. The current Compose deployment runs one API process.

The Shad passkey account database, core DID documents, ledger, audit events, JWT signing
keys, and Redis revocation entries are persisted by the Compose volumes. Core
authentication sessions and WebAuthn challenges remain in memory and expire or are
discarded on process restart.

Traefik uses its self-signed default certificate locally. This setup is for development;
it must use a trusted certificate before public deployment.
