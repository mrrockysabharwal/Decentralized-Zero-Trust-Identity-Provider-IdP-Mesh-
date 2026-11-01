# WebAuthn DID Ownership Authorization

WebAuthn credential registration requires two independent signatures. The
authenticator key signs the existing WebAuthn registration ceremony, and the
currently registered active DID controller key signs a domain-separated DID
ownership proof. The ownership proof covers the exact DID, operation, WebAuthn
registration challenge, canonical credential public key, credential ID, and
device metadata.

`POST /api/v1/webauthn/register/begin` returns both challenges. The DID proof is
single-use and expires after five minutes. Completion verifies it against the
active Ed25519 key resolved from that DID's registry document before the
credential store or ledger can be changed. Inactive DIDs, missing or invalid
proofs, expired challenges, mismatched DIDs, and replayed challenges are
rejected.

Credential listing is owner-only. A caller obtains a one-time challenge from
`POST /api/v1/webauthn/credentials/challenge/{did}`, signs the
`WEBAUTHN_CREDENTIAL_LIST` proof with that DID's active controller key, and
supplies the challenge and signature to `GET /api/v1/webauthn/credentials/{did}`.
The admin dashboard continues to use its separately authenticated admin API.

DID ownership challenge state is held in process memory. A multi-worker or
multi-instance deployment therefore needs a shared, atomic challenge store
before these flows can safely span workers or survive process restarts.
