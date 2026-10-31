# Token issuance and revocation authorization gap

## Current behavior

The token router has no authenticated caller identity to authorize. The
application health response reports WebAuthn as
`pending_module_integration`, and the repository contains no passkey assertion
verifier, authenticated session store, or FastAPI dependency that supplies a
verified DID principal. A ledger entry proves only that a DID was recorded; it
does not prove that the current caller controls that DID.

Before this change, `POST /api/v1/tokens/issue` accepted a DID from the request
body and checked only ledger state and requested scopes. `POST
/api/v1/tokens/revoke` accepted a caller-supplied JTI and revoked it without
checking its owner. Neither endpoint authenticated its caller.

Both endpoints now return `503 Service Unavailable` without performing the
operation. This is a fail-closed availability measure, not an authentication
implementation. Token verification, public-key publication, and scope listing
remain available.

## Smallest sound next step

Complete or integrate the real WebAuthn authentication module so it verifies
assertions and returns a server-trusted principal containing the DID bound to
the authenticated credential. Add a FastAPI dependency for that verified
principal, then:

1. Require it on token issuance and reject any request whose target DID differs
   from the authenticated principal's DID. Continue applying ledger and scope
   policy after that ownership check.
2. Require an authenticated principal on revocation and establish token
   ownership before writing a JTI to the deny-list. For self-service
   revocation, validate a signed, unexpired bearer token and permit only its
   own JTI. Any cross-user or administrative revocation needs a separately
   defined trusted role and ownership policy.
3. Add positive tests for the real verified-principal dependency as well as
   cross-DID issuance and revocation denial.

Do not treat a request-body DID, an unverified JWT payload, a ledger record,
or a caller-supplied JTI as proof of identity or ownership.
