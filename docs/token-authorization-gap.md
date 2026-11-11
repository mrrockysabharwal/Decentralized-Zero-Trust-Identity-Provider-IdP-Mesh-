# Authentication-to-token authorization

## Implemented behavior

The custom Ed25519 authentication simulation now creates a short-lived,
opaque bearer session only after the challenge has been consumed and the
credential signature has been verified. The session is stored server-side and
bound to the verified DID. `POST /api/v1/tokens/issue` requires that session
and rejects requests for a different DID before evaluating policy.

`POST /api/v1/tokens/revoke` requires a signed, unexpired access JWT. The
request JTI must match that JWT's JTI, so a caller cannot revoke another
session's token by submitting an arbitrary identifier. The deny-list TTL is
bounded by the token's remaining lifetime.

## Limitations

- Authentication sessions are held in process memory. They expire after five
  minutes and are lost on restart; a multi-worker deployment needs shared,
  expiring session storage.
- This is still the project's Ed25519 ceremony simulation, not browser
  WebAuthn/FIDO2 verification.
- Configure administrator identities in `IDP_ADMIN_DIDS` as a comma-separated
  list of DIDs. Only those identities receive the server-assigned `role=admin`
  claim when tokens are issued; client-supplied `role` claims are discarded.
- Every `/api/v1/admin/*` route requires a valid, unrevoked JWT with
  `role=admin`. Missing or invalid tokens receive 401; a regular-user token
  receives 403.

## API flow

1. Complete `/api/v1/webauthn/authenticate/complete` and retain the returned
   `session_token` until its `session_expires_in` timeout.
2. Send `Authorization: Bearer <session_token>` to `/api/v1/tokens/issue`.
   The requested body DID must equal the authenticated DID.
3. To revoke, send `Authorization: Bearer <access_token>` to
   `/api/v1/tokens/revoke` with the same token's JTI in the request body.
4. Subsequent token verification rejects that revoked access token.
