# DID ownership proof for ledger anchors

`POST /api/v1/ledger/anchor` requires a fresh controller signature. First call
`POST /api/v1/ledger/anchor/challenge` with the intended `did`, `doc_hash`,
`operation`, and `metadata`. Then sign the canonical message below and submit
the same fields plus `ownership_challenge` and `ownership_signature_b64` to
`POST /api/v1/ledger/anchor`.

The signing message is UTF-8 JSON with sorted keys and compact separators:

```json
{"challenge":"<challenge>","did":"<did>","doc_hash":"<lowercase sha256>","domain":"TrustMesh-Ledger-Anchor-v1","metadata":{},"operation":"CREATE"}
```

The signature is Ed25519 and encoded as unpadded base64url. The challenge is
single-use, bound to the DID, and expires after five minutes. The signature
binds the operation, document hash, metadata, DID, and challenge. The DID must
resolve to an active `did:mesh:key` record whose current verification key still
matches its self-certifying identifier.

The server stores challenge state in memory and resolves the DID's public key
from the DID registry when verifying the signature. Callers retain their
private keys. Outstanding challenges are invalidated if the process restarts.

## DID key updates and deactivation

The DID registry's `POST /api/v1/did/update/{did}` and
`POST /api/v1/did/deactivate/{did}` operations also require controller proof.
First request a challenge from `/api/v1/did/challenge/update/{did}` or
`/api/v1/did/challenge/deactivate/{did}` with the intended change set. The
challenge is bound to that DID, operation, and canonicalized change set, and
expires after five minutes. Submit the challenge and an Ed25519 signature with
the mutation request. The signature uses UTF-8 JSON with sorted keys and
compact separators:

```json
{"challenge":"<challenge>","changes":{"metadata":{},"new_public_key_b64":"<new-key>"},"did":"<did>","domain":"TrustMesh-DID-Mutation-v1","operation":"UPDATE"}
```

For deactivation, `operation` is `DEACTIVATE` and `changes` contains the
requested `reason`. For an update, `changes` contains `new_public_key_b64` and
`metadata`. The signature must verify against the current active public key in
the DID registry. Challenges are single-use; expired, replayed, mismatched,
and invalid proofs are rejected before the DID document or ledger is changed.
Challenge state is held in memory, so a process restart invalidates outstanding
challenges.
