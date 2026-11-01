# Admin API security configuration

Admin routes require a separately provisioned EdDSA JWT. Ordinary API access
tokens are not accepted, even if they contain an `admin:ledger` scope.

Configure both values in the service environment:

- `ADMIN_JWT_PUBLIC_KEY`: PEM-encoded Ed25519 public key trusted for admin JWTs.
  Newlines may be represented as `\n` in a single-line environment value.
- `ADMIN_DIDS`: comma-separated list of administrator DIDs allowed to use the
  admin API.

The external admin token issuer must sign tokens with the matching private key
and include `iss` and `aud` equal to `idp-mesh-admin`, an allowlisted `sub`, a
unique `jti`, valid `iat` and `exp` claims, and the signed `admin:ledger` scope.
Admin JWT lifetimes are limited to 24 hours so their own revocation entries can
cover their full validity.
Admin authentication requires the shared Redis revocation backend to be
available and its persistence and eviction settings to be verifiable. The
service uses read-only `INFO persistence` and `CONFIG GET` checks. It accepts
only AOF enabled, `appendfsync always`, a healthy AOF write status, and
`maxmemory-policy noeviction`. Restricted, missing, or malformed inspection
results are reported as unverifiable; known noncompliant settings are unsafe.
Either state, Redis unavailability, backend errors, or malformed revocation
records cause protected admin requests to fail closed with HTTP 503. The
optional bounded in-memory store is development-only, process-local, and can
never satisfy admin authentication's durability requirement.
Health responses report Redis availability separately from persistence,
eviction, and durability status. `configuration_verified` means only that the
connected node reported the required settings; it is not an end-to-end
durability guarantee.

These checks verify only the connected Redis node's reported runtime
configuration; they do not prove end-to-end durability. Operators must configure
and monitor persistent storage, suitable replication and failover behavior,
backups and tested restoration, and Redis availability outside this
application. The application cannot reliably inspect every managed-service
replica, cluster member, storage layer, or backup. Services that restrict
`INFO persistence` or the required `CONFIG GET` commands will remain unverifiable
and admin authentication will return HTTP 503; grant only the read-only
permissions needed for these checks where the deployment permits them.
The private key belongs only with that trusted issuer and must not be configured
in this service.

Admin force-revocation requires the complete signed target token in the request
body along with its JTI. The service verifies the target against either the
ordinary-token Ed25519 key and claims policy or the separate admin key and claims
policy. The body JTI must match the path JTI. Expired, malformed, or unverifiable
tokens are rejected without writing a revocation entry. The Redis TTL is rounded
up to cover the verified token's remaining lifetime. Ordinary tokens may live
for at most 30 days, and the revocation store enforces the same TTL ceiling.

The ledger tamper demonstration is disabled by default. Set
`ENABLE_LEDGER_TAMPER_DEMO=true` only in an environment where the demo is
intentionally available. The simulation requires admin authentication and
operates on a detached ledger copy; the shared ledger remains unchanged.
