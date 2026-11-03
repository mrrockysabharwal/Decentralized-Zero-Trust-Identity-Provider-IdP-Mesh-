# Token issuance and revocation integration gap

## Current behavior

The repository contains a browser WebAuthn assertion verifier at
`backend.main` routes (`POST /webauthn/login/verify`) and a separate simulated
Ed25519 ceremony under `/api/v1/webauthn/authenticate/complete`. Neither
implementation creates an application JWT, cookie, authenticated server
session, or verified principal consumed by the ordinary token router.

The `ZeroTrustPolicyEngine` and JWT issue helper exist internally, but
`POST /api/v1/tokens/issue` currently always returns `503` and does not run
those checks. `POST /api/v1/tokens/revoke` likewise returns `503` until token
ownership authorization is integrated. Token signature/claim verification,
public-key publication, scope listing, Redis JTI storage, and separately
authorized admin force-revocation are distinct implemented behaviors.

## Integration boundary

The browser WebAuthn API stores users, credentials, and DID documents in
SQLite; the DID module and simulated WebAuthn credentials use separate
in-process stores and different DID formats. The browser login response is
informational only. Admin authorization uses an externally issued admin JWT,
an `ADMIN_DIDS` allowlist, and a Redis revocation store whose durability
configuration must be verified; it is not connected to passkey login.

## Suggested future work

1. Select one canonical credential and DID identity model and define how a
   successful authenticator assertion maps to a server-trusted principal.
2. Add a protected application session/principal dependency and require it
   before token issuance; bind the requested subject to the authenticated
   identity, then run ledger and scope policy.
3. Design self-service revocation so an authenticated principal can revoke
   only a verified token it owns. Keep admin revocation in its separate trust
   domain.
4. Add integration tests for successful authentication-to-session-to-token
   flow and cross-identity denial.

Do not treat a request-body DID, a ledger record, an unverified JWT payload, or
a caller-supplied JTI as proof of identity or token ownership. For the current
route contract and complete status table, see
[API_DOCUMENTATION.md](API_DOCUMENTATION.md) and
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).
