# Token Authorization Status

The ordinary token API currently fails closed. `POST /api/v1/tokens/issue`
returns HTTP 503 until the application can provide a cryptographically verified
caller DID principal. A ledger record, requested DID, WebAuthn state, or scope
request by itself does not authenticate the caller.

`POST /api/v1/tokens/revoke` also returns HTTP 503 until token ownership or an
explicit authorized revoker identity is available. A caller-supplied JTI does
not prove permission to revoke a token. These endpoints do not mutate token or
revocation state while unavailable.

The admin JWT mechanism is separate: it protects admin routes and does not
authorize ordinary issuance or revocation. Token verification and the public
signing-key and policy-scope endpoints remain available. The application
requires an externally provisioned matching Ed25519 keypair via
`TOKEN_KEY_DIR`; startup never creates or replaces those key files.

## Revocation storage

Redis is required for durable revocation by default. If it is unavailable,
revocation checks and administrator authentication fail closed with HTTP 503;
the application does not silently switch to process-local storage. Redis
timeouts and malformed revocation records also fail closed.
Ordinary token verification and admin authentication obtain this same store from
the lazy neutral provider `app.modules.revocation_provider`; admin security does
not import the ordinary token router or initialize its signing keys.

Ordinary tokens have a server-enforced maximum lifetime of 30 days, applied by
both token creation and verification. Administrator force-revocation requires
the signed target token and matching JTI; it verifies the signature, issuer,
audience, active expiry, and lifetime policy before writing. The Redis entry TTL
is rounded up to the token's remaining lifetime, so it cannot expire before the
target token. Admin JWTs use their separate key and claims configuration and
remain limited to 24 hours.

For local development only, an ephemeral in-memory fallback can be explicitly
enabled with both `TRUSTMESH_ENV=development` and
`TOKEN_REVOCATION_ALLOW_IN_MEMORY=true`. This store expires entries and has a
fixed capacity, but does not survive restarts or synchronize between processes.
It cannot authorize administrator requests, which require a durable Redis
backend. Do not enable this fallback in production.
