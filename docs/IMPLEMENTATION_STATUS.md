# TrustMesh implementation status

This status is based on the current source, not on module names, plans, or older documentation. "Implemented" means the described component exists and can be exercised at its own boundary; it does not imply production suitability or complete cross-module integration.

## A. Implemented

| Feature | Current behavior | Relevant source |
|---|---|---|
| Combined FastAPI application | `app.main:app` mounts the DID, simulated WebAuthn, ledger, token, and admin routers under `/api/v1`; also mounts browser passkey/OIDC routers and static pages. | `app/main.py` |
| DID generation and document construction | Ed25519 DID identifiers and DID documents are created and held in a process-local registry. Creation can append a ledger record. Creation returns the private seed once; it is not stored by the DID service. | `app/modules/did/router.py`, `app/modules/identity/` |
| DID controller proof | One-use challenges bind update/deactivation data and signatures to the current DID controller key. | `app/modules/did/router.py`, `app/modules/webauthn/challenge_store.py` |
| Simulated WebAuthn ceremony | `/api/v1/webauthn` issues challenges, verifies Ed25519 signatures, stores credential public keys in a process-local `CredentialStore`, and increments a credential use counter. This is not the browser WebAuthn protocol. | `app/modules/webauthn/` |
| Browser WebAuthn operations | `/webauthn/register/*` and `/webauthn/login/*` use the `webauthn` library and SQLite for browser passkey registration and assertion verification. The login result is a boolean/message, not an app session. | `backend/main.py` |
| JWT cryptographic engine | EdDSA signing/verification helpers, constrained claims/scopes, and external key-pair validation are present. | `app/modules/tokens/jwt_engine.py`, `models.py` |
| Token verification endpoint | Verifies JWT signature/required claims and checks JTI revocation. Invalid tokens return `valid: false`; inability to check revocation returns 503. | `app/modules/tokens/router.py` |
| Public token key and scope metadata | Public-key and allowed-scope GET routes return configured Ed25519 public key/issuer and the ordinary-token scope list. | `app/modules/tokens/router.py` |
| Zero-trust policy component | Internal engine checks ledger registration, latest deactivation state, ledger integrity, allowed scopes, and optionally simulated WebAuthn credential presence. It does not identify/authenticate the HTTP caller. | `app/modules/tokens/policy.py` |
| Revocation persistence component | Redis JTI deny-list, TTL validation, Redis runtime persistence/eviction assessment, and an explicitly gated development-only memory backend are implemented. | `app/modules/tokens/revocation.py`, `app/modules/revocation_provider.py` |
| Admin authorization | Protected admin router validates separately issued EdDSA admin JWT claims, scope, subject allowlist, and revocation/durability state. | `app/modules/admin/security.py`, `app/modules/admin/router.py` |
| Hash-linked ledger | In-memory append/query/verify chain with SHA-256-linked records; optional JSON persistence is supported by the class when a caller supplies a file path. | `app/modules/ledger/chain.py`, `hasher.py` |
| Ledger APIs | Read/list/history/latest, ownership-proof anchor challenges/append, and integrity audit are implemented. Tamper demos are flag-gated, admin-protected, and run against a copy. | `app/modules/ledger/router.py` |
| Admin API | Dashboard summaries, ledger/identity/credential views, policy metadata, health, and verified target-token force-revocation are present behind `require_admin`. | `app/modules/admin/router.py` |
| Static portal and dashboard | FastAPI serves HTML/CSS/JS directly; the dashboard reads public ledger/token/health APIs and derives identity rows from ledger records. | `app/main.py`, `frontend/` |
| Separate core-security package | Process-local challenge, DID ownership, and hash-chain primitives exist with a separate test directory; this package is not the implementation wired into `app.main`. | `app/core_security/`, `core_security_tests/` |

## B. Partially implemented

### Distinct DID registries and credential stores

- **Current behavior:** `/api/v1/did` uses `DIDService`'s in-memory registry and creates `did:mesh:key:<16 hex>` identifiers. Browser passkey registration derives `did:mesh:<32 hex>` identifiers from SQLite user handles and stores DID documents in SQLite. `/api/v1/webauthn` has a third, separate in-memory credential store; the browser WebAuthn route uses SQLite credentials.
- **Relevant modules/routes:** `app/modules/identity/did_service.py`, `app/modules/webauthn/credential_store.py`, `backend/main.py`, `backend/storage.py`, `backend/webauthn_service.py`.
- **Integration gap:** The models, DID formats, lifetimes, and credential stores are not synchronized. The secondary `backend/storage.py`/`backend/webauthn_service.py` path is not the storage implementation used by `backend.main`.
- **Future improvement:** Choose a canonical DID/credential schema and storage boundary; provide explicit migration/synchronization and consistency tests before combining these APIs.

### Passkey login does not issue application or admin credentials

- **Current behavior:** Browser assertion verification succeeds and returns `authenticated: true`, username, and a message. The simulated Ed25519 authentication route returns `success: true` and DID/credential metadata. Neither route sets a cookie, creates a server session, issues an application JWT, or issues an admin JWT.
- **Relevant routes:** `POST /webauthn/login/verify`; `POST /api/v1/webauthn/authenticate/complete`.
- **Integration gap:** No verified principal is injected into the token router or admin dependency. Therefore a completed passkey login cannot authorize protected token/admin endpoints.
- **Future improvement:** Establish a server-trusted principal/session contract after assertion validation, protect session transport, and test that the authenticated identity—not a request-body DID—controls authorization.

### Dashboard does not complete authenticated admin workflows

- **Current behavior:** `frontend/dashboard/app.js` fetches public `/api/v1/ledger`, ledger verification, public key, scopes, and health. It does not call `/api/v1/admin/*` or send an admin bearer token. It displays no event-store data because no event API exists.
- **Relevant modules/routes:** `frontend/dashboard/app.js`; protected routes in `app/modules/admin/router.py`.
- **Integration gap:** The admin API is guarded by separately configured admin JWTs, but no dashboard login/token handoff exists. The UI's tamper request goes to `/api/v1/ledger/simulate-tamper` without authentication and cannot complete the protected flow. The UI expects a JSON body there; that route also requires the admin bearer and feature flag.
- **Future improvement:** Implement an authenticated admin login/credential handoff or a server-side dashboard backend; use the documented admin endpoints, and ensure the UI reflects route authorization failures.

### Dashboard API URL is fixed for non-8000 origins

- **Current behavior:** The dashboard uses `/api/v1` when served from a URL containing port 8000; otherwise it hard-codes `http://localhost:8000/api/v1`.
- **Relevant source:** `frontend/dashboard/app.js`.
- **Integration gap:** A remote deployment or API on another host/port cannot be configured in the UI.
- **Future improvement:** Supply the API base via server-rendered configuration or a reviewed environment-specific build/config mechanism and validate CORS against that origin.

### OIDC discovery and code helpers are not a complete provider

- **Current behavior:** Discovery returns static loopback URLs and advertises `RS256`; `/authorize` validates a subset of response-type, `openid` scope, and PKCE S256 fields before returning `501`; `/token` returns `501`; `/userinfo` returns `401` without a bearer header and `501` when one is supplied. The OIDC service contains SQLite authorization-code/PKCE helpers, but the router does not call them.
- **Relevant source/routes:** `backend/oidc/router.py`, `backend/oidc/service.py`.
- **Integration gap:** No client registration/redirect validation, authenticated consent flow, token issuance, or verified userinfo exists. The metadata is not dynamically tied to a deployable issuer or a working signing algorithm.
- **Future improvement:** Implement client registration and redirect allowlisting, bind authorization to an authenticated session, connect one-time code storage/PKCE consumption to signed tokens, and return discovery metadata consistent with the actual issuer and keys.

### Ledger persistence and cross-module registration

- **Current behavior:** The application uses one in-memory `SimulatedLedger` singleton. The class can load/save JSON when configured directly, but `app.main` supplies no storage path. Browser passkey registration writes a separate SQLite DID document and appends a ledger record; it does not register that DID in `DIDService`.
- **Relevant modules:** `app/modules/ledger/chain.py`, `app/modules/ledger/router.py`, `app/main.py`, `backend/main.py`.
- **Integration gap:** State is lost on restart for the app DID registry, app WebAuthn challenges/credentials, and main ledger; the browser DB has its own persistent identity state. Multiple workers would not share process-local state.
- **Future improvement:** Define durable, transactional canonical storage for DID state, challenge state, credential bindings, and ledger records; add restart and multi-worker consistency tests. Do not infer persistence from the ledger class's optional API.

### Admin-token provisioning is external

- **Current behavior:** Admin endpoints can validate a separately issued EdDSA JWT using `ADMIN_JWT_PUBLIC_KEY` and `ADMIN_DIDS`, but the repository contains no admin token issuer or passkey-to-admin session integration.
- **Relevant source:** `app/modules/admin/security.py`.
- **Integration gap:** Admin APIs are unusable until an operator provisions a matching external token issuer and the required Redis configuration; the portal does not obtain such a token.
- **Future improvement:** Specify the trusted issuer lifecycle, admin onboarding, key rotation/revocation, and session integration without reusing ordinary user tokens as admin credentials.

### Core-security primitives are not the routed application implementation

- **Current behavior:** `app/core_security` implements a separate DID/challenge/ledger API with its own in-memory state. The mounted routers use `app/modules/identity`, `app/modules/did`, and `app/modules/ledger` instead.
- **Relevant source:** `app/core_security/`, `app/main.py`.
- **Integration gap:** Behavior tested in `core_security_tests` does not automatically govern the public FastAPI routes.
- **Future improvement:** Decide whether to integrate this package or retire it; avoid parallel implementations without explicit adapters and shared behavioral tests.

### Composite health is a prototype-level assessment

- **Current behavior:** `/health` and `/api/v1/health` check the main ledger and revocation durability configuration, but some subsystem entries are reported as healthy based on wiring/counts rather than full end-to-end readiness. Browser SQLite initialization failure is logged as a warning by the main lifespan.
- **Relevant source:** `app/main.py`.
- **Integration gap:** Health does not prove that login produces a session, that admin is configured, or that DID/passkey stores agree. The backend's standalone `/health` is a separate simple response.
- **Future improvement:** Define readiness versus liveness and report actual dependency checks without treating unintegrated modules as fully operational.

## C. Pending / not implemented

| Missing capability | Current evidence | Suggested future improvement |
|---|---|---|
| Ordinary HTTP JWT issuance | `POST /api/v1/tokens/issue` always returns `503` and performs no issuance. The internal engine/helper does not change this route behavior. | Add a verified caller principal and DID-ownership authorization before enabling token issuance; retain ledger/policy checks as additional controls. |
| Ordinary self-service HTTP revocation | `POST /api/v1/tokens/revoke` always returns `503`. | Bind revocation to a verified token/principal and enforce JTI ownership; do not trust a caller-supplied JTI. |
| Application JWT/admin session after passkey login | Neither passkey path issues a JWT, cookie, or server session. | Integrate a secure session/principal layer and explicit ordinary/admin trust boundaries. |
| Working OIDC authorization/token/userinfo flow | Token and authorize paths return `501`; userinfo is `501` after the bearer-header check. | Complete client registration, redirect validation, PKCE, signed token claims, and userinfo validation. |
| Distributed ledger and consensus | Only an in-process chain with local hash linking is implemented. | If genuinely required, define a peer protocol, consensus/finality model, replicated state, and threat model; do not label the current ledger a distributed blockchain. |
| Durable canonical DID/credential/challenge state | Main DID, simulated WebAuthn, and challenge state are process-local; browser path persists separately in SQLite. | Design and integrate shared transactional persistence and restart/multi-instance behavior. |
| Dashboard admin authentication and event store | The dashboard has no admin login/token transport; no security-event API/store is present. | Add protected server-side workflows and a real event store, with retention/privacy controls. |
| Production deployment/security controls | No deployment container/reverse proxy configuration, production session hardening, or end-to-end persistence/recovery guarantee is provided in this source tree. | Add and review deployment hardening, operational monitoring, backup/recovery, and production threat modeling before deployment. |

## Endpoint implementation-state summary

- **Implemented:** DID reads/creation, controller-proof DID mutations, controller-proof ledger anchoring, ledger reads/integrity audit, simulated WebAuthn routes, browser WebAuthn routes, token verification/public key/scopes, admin APIs subject to admin configuration, root/health routes.
- **Partially implemented:** browser login (authentication result only), admin dashboard UI (public-data view only), OIDC discovery/preflight validation, internal policy and JWT issuance components, optional ledger JSON persistence.
- **Disabled/placeholders:** ordinary token issue and revoke (`503`); OIDC authorize/token (`501`), userinfo (`501` after missing-token check); ledger tamper demos hidden with `404` until explicitly enabled.

The API-level details and response examples are in [API documentation](API_DOCUMENTATION.md). Setup details are in the [Installation Guide](INSTALLATION_GUIDE.md).
