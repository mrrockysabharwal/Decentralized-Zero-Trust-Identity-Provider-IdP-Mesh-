# DID and Ledger Core Security

## Architecture

`app.core_security` is a framework-independent security core. It imports no
FastAPI routers, admin, token, WebAuthn, or frontend code.

- `ChallengeService` issues cryptographically random challenges with a five
  minute default lifetime. Each challenge is single-use and bound to a subject,
  operation, and canonical request digest.
- `CoreDIDService` stores only registered Ed25519 public keys. It verifies
  proof of key possession for DID creation, identity signatures, and requires
  the current active controller key to sign domain-separated update and
  deactivation requests. Challenges are consumed before signature
  verification. Registry and ledger state change only after the proof succeeds.
- `CoreLedger` appends immutable records linked by SHA-256 hashes and verifies
  each record, index, and previous-hash link. The test/demo tampering helper
  modifies only a returned copy.

DID creation accepts a public key plus a possession signature and never accepts
or stores private key material. DID identifiers are derived from the initial
public key. An authorized key rotation updates the controller key while
preserving that DID.

## Integration status and limits

These services are not mounted by the existing application routers. They are
an independent core implementation for review and testing; the existing DID,
ledger, admin, and WebAuthn APIs continue to use their existing service paths.

The DID registry, ledger, and challenge state are in memory. Challenges do not
survive process restarts and cannot be safely shared across workers or hosts.
The ledger is a local tamper-evident chain, not a consensus network or durable
database. A production deployment needs durable atomic storage, distributed
challenge consumption, operational key custody, and a separately reviewed
adapter between these core services and HTTP routes.
