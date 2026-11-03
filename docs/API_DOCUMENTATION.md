# TrustMesh API documentation

This reference describes routes mounted by the current `app.main:app` application. Open `http://localhost:8000/docs` for the runtime-generated OpenAPI schema. This project has no stable external API/versioning guarantee.

## Conventions and authentication

- Combined application API prefix: `/api/v1`.
- JSON request bodies use `Content-Type: application/json`.
- Except where noted, no bearer token is required. DID mutation/anchor routes require one-use DID-controller challenges and Ed25519 signatures; this is not HTTP bearer authentication.
- Every `/api/v1/admin/*` route requires `Authorization: Bearer <admin-JWT>`. It must be separately issued and satisfy the issuer, audience, subject allowlist, `admin:ledger` scope, lifetime, and Redis durability checks described in [Admin security](admin-security.md).
- The browser passkey routes are mounted at `/webauthn/...`, not beneath `/api/v1`. They use actual browser WebAuthn. `/api/v1/webauthn/...` is a different Ed25519-based simulation.
- FastAPI request validation commonly returns `422` with `{"detail":[...]}`. `HTTPException` responses use `{"detail":"..."}` unless a route's response model describes another shape.
- `POST /api/v1/tokens/verify` is an exception to ordinary error handling: a cryptographically invalid, expired, or revoked token returns HTTP `200` with `valid:false`. If revocation state cannot be checked, it returns `503`.

The endpoint state labels below mean:

- **Implemented:** the route performs the documented behavior.
- **Partial:** the route exists but does not complete the protocol or integration.
- **Disabled:** the handler always returns `503`.
- **Placeholder:** the current route returns `501` or does not yet validate the advertised operation.

## 1. DID APIs

All paths below start with `/api/v1/did`. The DID registry is process-local; this does not resolve DIDs from the separate browser-passkey SQLite store.

### Create a DID — Implemented

`POST /api/v1/did/create`

- **Purpose:** Generate an Ed25519 key pair, derive and register a `did:mesh:key:<16 hex>` DID, and (by default) append a `CREATE` ledger record.
- **Authentication/headers:** No bearer token. JSON body.
- **Request:**

  ```json
  {
    "display_name": "Example identity",
    "anchor_to_ledger": true,
    "metadata": {}
  }
  ```

- **Validation:** `display_name` is optional and at most 128 characters; `anchor_to_ledger` defaults to `true`; `metadata` defaults to an empty object.
- **Success `201`:** The `private_key_b64` field is returned once and is secret material. It is intentionally redacted in this example.

  ```json
  {
    "did": "did:mesh:key:0123456789abcdef",
    "public_key_b64": "<base64url public-key bytes>",
    "private_key_b64": "<redacted; returned once by the live API>",
    "did_document": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
      ],
      "id": "did:mesh:key:0123456789abcdef",
      "controller": "did:mesh:key:0123456789abcdef",
      "verificationMethod": [
        {
          "id": "did:mesh:key:0123456789abcdef#key-1",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:mesh:key:0123456789abcdef",
          "publicKeyMultibase": "z<base58btc-public-key>"
        }
      ],
      "authentication": ["did:mesh:key:0123456789abcdef#key-1"],
      "assertionMethod": ["did:mesh:key:0123456789abcdef#key-1"],
      "created": "<ISO-8601 timestamp>",
      "updated": "<ISO-8601 timestamp>"
    },
    "ledger_record_index": 1,
    "message": "<status message>"
  }
  ```

- **Errors:** `422` for request validation; startup-level signing-key misconfiguration prevents the app from loading.
- **Important:** Securely retain the private key from the actual response. The server does not retain it.

### Resolve a DID — Implemented

`GET /api/v1/did/resolve/{did}`

- **Purpose:** Return a document from the in-process DID registry.
- **Authentication/headers:** None.
- **Parameters:** `did` is a path parameter; the route uses a path converter.
- **Success `200`:**

  ```json
  {
    "did": "did:mesh:key:0123456789abcdef",
    "did_document": {"id": "did:mesh:key:0123456789abcdef"},
    "deactivated": false
  }
  ```

  `did_document` contains the registered document fields; the shortened document above is illustrative.
- **Errors:** `400` malformed DID; `404` not present in the in-process registry.

### Check DID existence — Implemented

`GET /api/v1/did/exists/{did}`

- **Purpose:** Return presence and, if found, deactivation state.
- **Authentication/headers:** None.
- **Success `200`:** `{"did":"did:mesh:key:0123456789abcdef","exists":true,"deactivated":false}`. A missing DID returns `exists:false` and `deactivated:null`, not 404.
- **Errors:** `422` for FastAPI path/query validation.

### List DIDs — Implemented

`GET /api/v1/did/list`

- **Purpose:** Snapshot all DIDs in the in-process registry.
- **Authentication/headers:** None.
- **Success `200`:** `{"dids":["did:mesh:key:0123456789abcdef"],"total":1}`.
- **Errors:** No route-specific error is declared.

### Request a key-update challenge — Implemented

`POST /api/v1/did/challenge/update/{did}`

- **Purpose:** Issue a five-minute, single-use challenge bound to the proposed new public key and metadata.
- **Authentication/headers:** No bearer token; JSON body.
- **Request:**

  ```json
  {
    "new_public_key_b64": "<base64url raw 32-byte Ed25519 public key>",
    "metadata": {}
  }
  ```

- **Success `200`:** `{"did":"did:mesh:key:0123456789abcdef","operation":"UPDATE","challenge":"<one-time challenge>","expires_in_seconds":300}`.
- **Errors:** `400` invalid DID; `403` inactive DID or invalid controller key; `404` unknown DID; `422` invalid public key encoding/length.

### Update a DID key — Implemented

`POST /api/v1/did/update/{did}`

- **Purpose:** Replace the DID document's controller public key and append an `UPDATE` record after verifying the current controller's proof.
- **Authentication/headers:** No bearer token; JSON body with the exact challenge and signature.
- **Request:**

  ```json
  {
    "new_public_key_b64": "<base64url raw 32-byte Ed25519 public key>",
    "metadata": {},
    "ownership_challenge": "<challenge from challenge/update>",
    "ownership_signature_b64": "<base64url Ed25519 signature>"
  }
  ```

- **Validation:** The new public key must decode to 32 bytes. The one-time challenge is bound to the exact normalized key and metadata; the signature must be a valid 64-byte Ed25519 signature by the currently registered controller.
- **Success `200`:** `{"did":"did:mesh:key:0123456789abcdef","ledger_record_index":2,"message":"<status message>"}`.
- **Errors:** `400` invalid DID/update document; `401` missing, expired, mismatched, replayed, or invalid proof; `403` inactive/invalid controller; `404` unknown DID; `422` invalid new public key.

### Request a deactivation challenge — Implemented

`POST /api/v1/did/challenge/deactivate/{did}`

- **Purpose:** Issue a five-minute, single-use challenge bound to the deactivation reason.
- **Authentication/headers:** No bearer token; JSON body.
- **Request:** `{"reason":"No longer in use"}`; `reason` is optional and at most 256 characters.
- **Success `200`:** `{"did":"did:mesh:key:0123456789abcdef","operation":"DEACTIVATE","challenge":"<one-time challenge>","expires_in_seconds":300}`.
- **Errors:** `400` invalid DID; `403` inactive/invalid controller; `404` unknown DID; `422` invalid reason.

### Deactivate a DID — Implemented

`POST /api/v1/did/deactivate/{did}`

- **Purpose:** Mark the in-process DID document deactivated and append a `DEACTIVATE` ledger record.
- **Authentication/headers:** No bearer token; JSON body required for a successful operation.
- **Request:**

  ```json
  {
    "reason": "No longer in use",
    "ownership_challenge": "<challenge from challenge/deactivate>",
    "ownership_signature_b64": "<base64url Ed25519 signature>"
  }
  ```

- **Success `200`:** `{"did":"did:mesh:key:0123456789abcdef","deactivated":true,"ledger_record_index":3,"message":"<status message>"}`.
- **Errors:** `401` missing/invalid proof (including an omitted body); `403` inactive/invalid controller; `404` unknown/unresolvable DID; `409` already deactivated; `422` invalid body.

### Verify an Ed25519 signature — Implemented

`POST /api/v1/did/verify-signature`

- **Purpose:** Verify message bytes using an active DID document's registered public key.
- **Authentication/headers:** No bearer token; JSON body.
- **Request:** `{"did":"did:mesh:key:0123456789abcdef","message_b64":"<base64url message bytes>","signature_b64":"<base64url signature>"}`.
- **Success `200`:** `{"did":"did:mesh:key:0123456789abcdef","valid":true,"message":"<verification result>"}`. An invalid cryptographic signature is still a `200` response with `valid:false`.
- **Errors:** `400` malformed DID; `403` deactivated DID; `404` unknown DID; `422` invalid base64url payload; `500` if the stored document key cannot be extracted.

## 2. WebAuthn APIs

### DID-bound Ed25519 simulation — `/api/v1/webauthn`

These are not actual browser WebAuthn attestation/assertion routes. Challenges/credentials are in process memory; registration and authentication verify Ed25519 challenge signatures. Successful authentication does not issue a JWT or session.

#### Begin simulated registration — Implemented

`POST /api/v1/webauthn/register/begin`

- **Purpose:** Create a registration challenge and a DID-controller challenge.
- **Authentication/headers:** No bearer token; JSON body.
- **Request:** `{"did":"did:mesh:key:0123456789abcdef","display_name":"Example device"}`; `display_name` is optional.
- **Success `200`:** `{"challenge":"<registration challenge>","ownership_challenge":"<DID proof challenge>","did":"did:mesh:key:0123456789abcdef","rp_id":"idp-mesh-v1","rp_name":"Decentralized Zero-Trust IdP Mesh","expires_in_seconds":300}`.
- **Errors:** `400` invalid DID/ceremony; `403` inactive or invalid DID controller; `404` unknown DID; `422` invalid body.

#### Complete simulated registration — Implemented

`POST /api/v1/webauthn/register/complete`

- **Purpose:** Verify registration and DID-ownership signatures, store the credential in memory, and attempt a CREATE anchor.
- **Authentication/headers:** No bearer token; JSON body.
- **Request:**

  ```json
  {
    "did": "did:mesh:key:0123456789abcdef",
    "challenge": "<registration challenge>",
    "public_key_b64": "<base64url 32-byte Ed25519 key>",
    "signature_b64": "<base64url 64-byte ceremony signature>",
    "ownership_challenge": "<DID proof challenge>",
    "ownership_signature_b64": "<base64url 64-byte DID-controller signature>",
    "credential_id": "optional-client-id",
    "device_info": {}
  }
  ```

- **Success `201`:** `{"success":true,"credential_id":"<stored-or-derived-id>","did":"did:mesh:key:0123456789abcdef","ledger_record_index":2,"message":"<status message>"}`. `ledger_record_index` can be `null` when not wired or anchoring fails; the credential registration code treats ledger anchoring failure as non-fatal.
- **Errors:** `401` bad/expired/replayed challenge or signature; `422` invalid public-key base64url or length; `500` unexpected registration failure.

#### Begin simulated authentication — Implemented

`POST /api/v1/webauthn/authenticate/begin`

- **Purpose:** Create a single-use authentication challenge for a DID with stored credentials.
- **Authentication/headers:** No bearer token; JSON body.
- **Request:** `{"did":"did:mesh:key:0123456789abcdef"}`.
- **Success `200`:** `{"challenge":"<authentication challenge>","did":"did:mesh:key:0123456789abcdef","credential_ids":["<credential-id>"],"expires_in_seconds":300}`.
- **Errors:** `400` invalid DID; `404` no credential registered for the DID; `422` invalid body.

#### Complete simulated authentication — Implemented, session integration pending

`POST /api/v1/webauthn/authenticate/complete`

- **Purpose:** Verify the credential signature and update its counter.
- **Authentication/headers:** No bearer token; JSON body.
- **Request:** `{"did":"did:mesh:key:0123456789abcdef","challenge":"<authentication challenge>","credential_id":"<credential-id>","signature_b64":"<base64url 64-byte signature>"}`.
- **Success `200`:** `{"success":true,"did":"did:mesh:key:0123456789abcdef","credential_id":"<credential-id>","message":"<status message>"}`.
- **Errors:** `401` invalid/expired/replayed challenge, credential mismatch, or signature; `500` unexpected failure.
- **Important:** This response does not create an authenticated application principal, JWT, or admin session.

#### Request credential-list challenge — Implemented

`POST /api/v1/webauthn/credentials/challenge/{did}`

- **Purpose:** Issue a short-lived DID-ownership challenge for listing credentials.
- **Authentication/headers:** No bearer token or request body.
- **Success `200`:** `{"did":"did:mesh:key:0123456789abcdef","challenge":"<one-time challenge>","expires_in_seconds":300}`.
- **Errors:** `400` invalid DID; `403` inactive/invalid controller; `404` unknown DID.

#### List credentials for a DID — Implemented

`GET /api/v1/webauthn/credentials/{did}`

- **Purpose:** Return credentials from the simulated module's in-memory store.
- **Authentication/headers:** No bearer token. The controller proof is supplied as query parameters:
  - `ownership_challenge` (string)
  - `ownership_signature_b64` (string)
- **Success `200`:** `{"did":"did:mesh:key:0123456789abcdef","credentials":[{"credential_id":"<id>","did":"did:mesh:key:0123456789abcdef","public_key_b64":"<base64url key>","registered_at":"<ISO-8601>","device_info":null,"sign_count":1}],"total":1}`.
- **Errors:** `401` missing/invalid proof; `403` inactive DID; `404` no credentials; `422` invalid query values.

### Browser WebAuthn — `/webauthn`

These routes use `backend.main` and the Python `webauthn` library with the browser's WebAuthn APIs. The portal JavaScript is the client. SQLite stores users, credentials, challenges, and DID documents. `WEBAUTHN_ORIGIN` and `WEBAUTHN_RP_ID` must match the browser context.

#### Registration options — Partial flow

`POST /webauthn/register/options`

- **Purpose:** Create/find a username and return WebAuthn registration options.
- **Authentication/headers:** No bearer token; JSON body.
- **Request:** `{"username":"alice@example.test"}`. Username is 3–254 characters and cannot contain whitespace; it is trimmed and lowercased before use.
- **Success `200`:** Dynamic WebAuthn options JSON, e.g. fields include `challenge`, `rp`, `user`, `pubKeyCredParams`, `authenticatorSelection`, and `excludeCredentials`. The challenge and user handle are generated at runtime.
- **Errors:** `409` account creation conflict; `422` invalid username.

#### Verify registration — Implemented browser ceremony

`POST /webauthn/register/verify`

- **Purpose:** Verify the browser credential response, persist the credential, build the SQLite DID document, and append a CREATE/UPDATE ledger record if needed.
- **Authentication/headers:** No bearer token; JSON body.
- **Request shape:** `{"username":"alice@example.test","credential":{...WebAuthn PublicKeyCredential JSON...}}`; the nested credential is the response produced by the browser client.
- **Success `200`:** `{"verified":true,"did":"did:mesh:<32-hex-characters>","document_hash":"<64-char SHA-256 hex>","message":"Passkey registered and DID document anchored successfully."}`.
- **Errors:** `404` registration was not started; `400` challenge missing/expired or WebAuthn verification failure; `409` credential already registered; `422` invalid request shape.
- **Important:** This DID and SQLite document are not inserted into the separate `/api/v1/did` registry. The success message describes the SQLite document hash being appended to the shared in-memory ledger.

#### Login options — Implemented browser ceremony

`POST /webauthn/login/options`

- **Purpose:** Return WebAuthn assertion options for a username's registered credentials.
- **Authentication/headers:** No bearer token; JSON body.
- **Request:** `{"username":"alice@example.test"}`.
- **Success `200`:** Dynamic WebAuthn request options JSON, including `challenge`, `rpId`, `allowCredentials`, and `userVerification`.
- **Errors:** `400` account has no passkey; `422` invalid username.

#### Verify login — Implemented authentication, no app session

`POST /webauthn/login/verify`

- **Purpose:** Verify a browser assertion and update the stored credential sign count.
- **Authentication/headers:** No bearer token; JSON body.
- **Request shape:** `{"username":"alice@example.test","credential":{...WebAuthn PublicKeyCredential JSON...}}`.
- **Success `200`:** `{"authenticated":true,"username":"alice@example.test","message":"Passwordless login successful."}`.
- **Errors:** `400` missing/expired challenge or credential ID; `401` credential not found or assertion verification failure; `422` invalid request shape.
- **Important:** No JWT, cookie, or application/admin session is issued.

#### Resolve browser-passkey DID document — Implemented for SQLite records

`GET /did/{did}`

- **Purpose:** Read a DID document from the browser passkey SQLite database and compare its hash with the latest shared-ledger record.
- **Authentication/headers:** None.
- **Success `200`:** `{"did":"did:mesh:<32-hex-characters>","document":{},"document_hash":"<hash>","stored_hash":"<hash>","ledger_hash":"<hash-or-null>","document_storage_valid":true,"ledger_verified":true,"updated_at":1234567890}`. `document` contains stored verification methods.
- **Errors:** `404` no SQLite DID document; `500` stored document parse/hash failure.

## 3. Token APIs

Base path: `/api/v1/tokens`. Scope list for ordinary tokens: `read:profile`, `write:did`, `auth:webauthn`. These are **not** admin scopes.

### Issue token — Disabled

`POST /api/v1/tokens/issue`

- **Purpose:** Reserved for ordinary token issuance; current handler does not parse a request body or issue a token.
- **Authentication/headers:** No usable caller-authentication dependency is integrated.
- **Request:** No body is consumed by the current handler. A DID/scope JSON body does not enable issuance.
- **Response:** Always `503 Service Unavailable`: `{"detail":"Token issuance is unavailable until authenticated caller authorization is implemented."}`.
- **Validation/errors:** It does not evaluate request fields or policy through this route.

### Verify token — Implemented

`POST /api/v1/tokens/verify`

- **Purpose:** Verify configured EdDSA JWT signature, issuer/audience/required claims/lifetime, then check JTI revocation.
- **Authentication/headers:** No bearer token; JSON body.
- **Request:** `{"token":"<JWT string>"}`.
- **Success `200` valid:** `{"valid":true,"claims":{"sub":"did:mesh:key:0123456789abcdef","jti":"<jti>","iat":1790000000,"exp":1790003600,"iss":"idp-mesh-v1","aud":"idp-mesh-api","scope":["read:profile"]},"error":null}`. Claims vary with the signed token.
- **Success `200` invalid:** `{"valid":false,"claims":null,"error":"Token has expired."}` or an invalid/revoked-token explanation.
- **Errors:** `503` revocation state unavailable; `422` invalid request shape. The route returns false in the response model for signature/claim/expiry/revocation rejection rather than using 401.

### Revoke token — Disabled

`POST /api/v1/tokens/revoke`

- **Purpose:** Reserved for self-service revocation; current handler does not parse a request body or write a revocation record.
- **Authentication/headers:** No usable caller ownership check is integrated.
- **Request:** No body is consumed by the current handler.
- **Response:** Always `503 Service Unavailable`: `{"detail":"Token revocation is unavailable until authenticated token ownership authorization is implemented."}`.

### Get public signing key — Implemented

`GET /api/v1/tokens/public-key`

- **Purpose:** Publish the configured public Ed25519 PEM key for ordinary JWT verification.
- **Authentication/headers:** None.
- **Success `200`:** `{"public_key_pem":"<configured public PEM>","algorithm":"EdDSA","issuer":"idp-mesh-v1"}`. No key contents are included in this documentation.
- **Errors:** Startup fails if the external signing key configuration is invalid.

### List policy scopes — Implemented

`GET /api/v1/tokens/policy/scopes`

- **Purpose:** List permitted ordinary-token scopes.
- **Authentication/headers:** None.
- **Success `200`:** `{"scopes":["read:profile","write:did","auth:webauthn"]}`.
- **Errors:** No route-specific error is declared.

## 4. Revocation APIs

Ordinary self-service revocation is disabled as described under [Token APIs](#3-token-apis). The administrative force-revoke route below is implemented separately and requires admin authorization plus durable Redis.

### Force-revoke a verified target token — Implemented with durable Redis

`POST /api/v1/admin/tokens/{jti}/revoke`

- **Purpose:** Verify an active ordinary/admin JWT target and add its JTI to the deny-list until the signed expiration.
- **Authentication/headers:** Admin bearer token; JSON body.
- **Request:**

  ```json
  {
    "jti": "target-jti",
    "target_token": "<complete signed unexpired JWT>",
    "reason": "Administrative revocation"
  }
  ```

- **Success `200`:** `{"revoked":true,"jti":"target-jti","reason":"Administrative revocation","message":"<confirmation>"}`.
- **Validation:** Path JTI must equal body JTI; the target token must have a valid supported signature and claims, be unexpired, and remain within token-lifetime limits. Redis must be verified durable. `reason` is optional.
- **Errors:** `401` invalid admin credentials; `403` missing admin scope/allowlist; `422` mismatch, invalid/expired target, or invalid TTL; `503` durability/revocation store unavailable.

## 5. Admin APIs

Every route in this section uses `/api/v1/admin` and is protected by the same `require_admin` dependency. A valid bearer token alone is insufficient if Redis durability cannot be verified.

### Dashboard summary — Implemented

`GET /api/v1/admin/dashboard`

- **Purpose:** Aggregate ledger-derived DID counts, integrity, credentials, revocation backend, and subsystem data.
- **Authentication/headers:** `Authorization: Bearer <admin-JWT>`.
- **Success `200`:** `{"total_dids":1,"active_dids":1,"deactivated_dids":0,"total_ledger_records":2,"ledger_integrity":true,"ledger_head_hash":"<hash>","total_credentials":0,"revocation_backend":"redis","subsystems":[{"name":"ledger","status":"healthy","detail":"Chain integrity verified"}]}`. The response includes all subsystem entries; the list is abbreviated here.
- **Errors:** Admin dependency `401`/`403`/`503`; `503` if required ledger/store wiring is missing.

### List admin identities — Implemented

`GET /api/v1/admin/identities`

- **Purpose:** Summaries derived from ledger records, with credential counts from the simulated in-memory credential store.
- **Authentication/headers:** Admin bearer token.
- **Success `200`:** Array of `{"did":"did:mesh:key:0123456789abcdef","status":"ACTIVE","latest_operation":"CREATE","ledger_record_index":1,"latest_ledger_timestamp":"<ISO-8601>","total_ledger_records":1,"credential_count":0}`.
- **Errors:** Admin dependency `401`/`403`/`503`; `503` if stores are not wired.

### Identity detail — Implemented

`GET /api/v1/admin/identities/{did}`

- **Purpose:** Return ledger history and credentials for one DID.
- **Authentication/headers:** Admin bearer token.
- **Success `200`:** `{"did":"did:mesh:key:0123456789abcdef","status":"ACTIVE","latest_operation":"CREATE","ledger_history":[{"index":1,"did":"did:mesh:key:0123456789abcdef","operation":"CREATE"}],"credentials":[],"credential_count":0}`. Each ledger record contains the full ledger record schema; the example is shortened.
- **Errors:** `404` no ledger records for the DID; admin dependency errors.

### Admin ledger view — Implemented

`GET /api/v1/admin/ledger`

- **Purpose:** Return all ledger records plus an integrity audit.
- **Authentication/headers:** Admin bearer token.
- **Success `200`:** `{"total_records":1,"integrity_valid":true,"integrity_error":null,"head_hash":"<hash>","records":[{"index":0,"timestamp":"<ISO-8601>","did":"did:mesh:genesis","doc_hash":"<64-char hash>","operation":"GENESIS","previous_hash":"<64-char hash>","record_hash":"<64-char hash>","metadata":{}}]}`.
- **Errors:** Admin dependency errors; `503` if ledger is not wired.

### Admin ledger verification — Implemented

`GET /api/v1/admin/ledger/verify`

- **Purpose:** Run integrity verification and return the same complete `LedgerAdminView` shape as `/admin/ledger`.
- **Authentication/headers:** Admin bearer token.
- **Success `200`:** Same response schema as `/api/v1/admin/ledger`; `integrity_valid` and `integrity_error` contain the audit result.
- **Errors:** Admin dependency errors; `503` if ledger is not wired.

### List all admin credentials — Implemented

`GET /api/v1/admin/credentials`

- **Purpose:** Return credentials from the simulated module credential store for DIDs present on the ledger.
- **Authentication/headers:** Admin bearer token.
- **Success `200`:** `{"total_credentials":1,"credentials":[{"credential_id":"<id>","did":"did:mesh:key:0123456789abcdef","public_key_b64":"<base64url public key>","registered_at":"<ISO-8601>","sign_count":1,"device_info":null}]}`.
- **Errors:** Admin dependency errors; `503` if stores are not wired.

### Admin token policy — Implemented

`GET /api/v1/admin/tokens/policy`

- **Purpose:** Return ordinary token allowed scopes, issuer/audience, expiry default, revocation backend, and signing algorithm.
- **Authentication/headers:** Admin bearer token.
- **Success `200`:** `{"allowed_scopes":["read:profile","write:did","auth:webauthn"],"token_issuer":"idp-mesh-v1","token_audience":"idp-mesh-api","default_expiry_seconds":3600,"revocation_backend":"redis","signing_algorithm":"EdDSA"}`.
- **Errors:** Admin dependency errors.

### Admin isolated tamper demonstration — Partial/disabled by default

`POST /api/v1/admin/ledger/simulate-tamper`

- **Purpose:** Tamper with a detached ledger copy and return the audit result; shared ledger state is not changed.
- **Authentication/headers:** Admin bearer token. `ENABLE_LEDGER_TAMPER_DEMO` must be truthy.
- **Query parameters:** `index` (integer), `field` (string), `new_value` (string), `recalculate_record_hash` (boolean, default `false`). The current admin route takes query parameters, not a JSON model.
- **Example:** `POST /api/v1/admin/ledger/simulate-tamper?index=0&field=did&new_value=did%3Amesh%3Atampered`
- **Success `200`:** Full `LedgerAdminView` as above, describing the simulated copy's records and integrity result.
- **Errors:** `404` unless the demo flag is enabled; `401`/`403`/`503` admin authorization errors; `400` invalid index or simulation input; `422` invalid query parameters.

### Admin health — Implemented

`GET /api/v1/admin/health`

- **Purpose:** Report ledger, DID/credential counts, and revocation backend configuration assessment.
- **Authentication/headers:** Admin bearer token.
- **Success `200`:** `{"overall_status":"healthy","ledger_integrity":true,"ledger_records":1,"total_dids":0,"total_credentials":0,"revocation_backend":"redis","revocation_redis_available":true,"revocation_persistence":"verified","revocation_eviction":"verified","revocation_durability":"configuration_verified","subsystems":[{"name":"ledger","status":"healthy","detail":"1 record(s) — chain intact"}]}`. Actual subsystem list includes ledger, DID registry, WebAuthn, and token status.
- **Errors:** `401`/`403`/`503` from admin authentication; `503` if required in-process stores are not wired.

## 6. Ledger APIs

Base path: `/api/v1/ledger`.

### List records — Implemented

`GET /api/v1/ledger`

- **Purpose:** Return all records in chronological order.
- **Authentication/headers:** None.
- **Success `200`:** JSON array of `LedgerRecord`, e.g. `[{"index":0,"timestamp":"<ISO-8601>","did":"did:mesh:genesis","doc_hash":"<64-char SHA-256 hex>","operation":"GENESIS","previous_hash":"<64-char SHA-256 hex>","record_hash":"<64-char SHA-256 hex>","metadata":{}}]`.
- **Errors:** No route-specific error is declared.

### Verify ledger integrity — Implemented

`GET /api/v1/ledger/verify`

- **Purpose:** Recompute record hashes and chain links.
- **Authentication/headers:** None.
- **Success `200`:** `{"valid":true,"error":null,"total_records":1,"head_hash":"<hash>"}`. A detected integrity failure is reported as `valid:false` and an explanatory `error`, not an HTTP error.
- **Errors:** No route-specific error is declared.

### Get DID ledger history — Implemented

`GET /api/v1/ledger/history/{did}`

- **Purpose:** Return all records for the exact DID in chronological order.
- **Authentication/headers:** None.
- **Success `200`:** Array of full `LedgerRecord` objects, as in `/api/v1/ledger`.
- **Errors:** `404` when no record exists for that DID.

### Get latest DID record — Implemented

`GET /api/v1/ledger/latest/{did}`

- **Purpose:** Return the latest record for a DID.
- **Authentication/headers:** None.
- **Success `200`:** One full `LedgerRecord` object.
- **Errors:** `404` when the DID has no ledger record.

### Request ledger-anchor challenge — Implemented

`POST /api/v1/ledger/anchor/challenge`

- **Purpose:** Issue a five-minute challenge for an active DID controller to approve an anchor.
- **Authentication/headers:** No bearer token; JSON body.
- **Request:** `{"did":"did:mesh:key:0123456789abcdef","doc_hash":"<64 hex SHA-256>","operation":"CREATE","metadata":{}}`. `operation` defaults to `CREATE`; `GENESIS` is not accepted.
- **Success `200`:** `{"did":"did:mesh:key:0123456789abcdef","challenge":"<one-time challenge>","expires_in_seconds":300}`.
- **Errors:** `400` genesis/invalid DID; `403` deactivated or invalid controller key; `404` DID missing from the in-process registry; `422` invalid hash/model.

### Append a ledger anchor — Implemented

`POST /api/v1/ledger/anchor`

- **Purpose:** Append CREATE/UPDATE/DEACTIVATE record after consuming a challenge and validating the DID controller's Ed25519 signature.
- **Authentication/headers:** No bearer token; controller proof in JSON body.
- **Request:**

  ```json
  {
    "did": "did:mesh:key:0123456789abcdef",
    "doc_hash": "<64 hex SHA-256>",
    "operation": "CREATE",
    "metadata": {},
    "ownership_challenge": "<challenge from /anchor/challenge>",
    "ownership_signature_b64": "<base64url Ed25519 signature>"
  }
  ```

- **Success `201`:** Full `LedgerRecord` with the assigned index/timestamp, DID/document hash, operation, predecessor hash, record hash, and metadata.
- **Errors:** `400` genesis or append rejected; `401` missing/expired/replayed/malformed/invalid proof; `403` inactive or unbound controller key; `404` DID unknown; `422` invalid request/hash.

### Isolated ledger tamper demonstration — Partial/disabled by default

`POST /api/v1/ledger/simulate-tamper`

- **Purpose:** Tamper with an isolated ledger snapshot and return the snapshot audit result. The shared ledger is unchanged.
- **Authentication/headers:** Admin bearer token; `ENABLE_LEDGER_TAMPER_DEMO` must be truthy. This route uses a JSON body.
- **Request:** `{"index":0,"field":"did","new_value":"did:mesh:example-tamper","recalculate_record_hash":false}`. `index` must be non-negative; field/value accepted depend on the simulation implementation.
- **Success `200`:** `{"valid":false,"error":"<integrity diagnostic>","total_records":1,"head_hash":"<hash>"}`.
- **Errors:** `404` when disabled; `401`/`403`/`503` admin authorization errors; `400` invalid index or simulation failure; `422` invalid body.

The dashboard currently posts to this route without an admin bearer, so its demonstration action does not complete successfully.

## 7. OIDC APIs

Base path: `/oidc`. Discovery metadata is static and is not proof of a functioning OIDC provider. It advertises loopback URLs and `RS256`, while TrustMesh ordinary JWT code uses EdDSA; no working token endpoint currently backs the metadata.

### Discovery — Partial

`GET /oidc/.well-known/openid-configuration`

- **Purpose:** Return static OIDC discovery-like metadata.
- **Authentication/headers:** None.
- **Success `200`:**

  ```json
  {
    "issuer": "http://127.0.0.1:8000/oidc",
    "authorization_endpoint": "http://127.0.0.1:8000/oidc/authorize",
    "token_endpoint": "http://127.0.0.1:8000/oidc/token",
    "userinfo_endpoint": "http://127.0.0.1:8000/oidc/userinfo",
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "profile", "email"],
    "grant_types_supported": ["authorization_code"]
  }
  ```

- **Errors:** No route-specific error is declared. Metadata is not configured per deployment.

### Authorization request — Placeholder

`GET /oidc/authorize`

- **Purpose:** Validate a subset of authorization-code/PKCE parameters; does not authenticate a user or redirect with a code.
- **Authentication/headers:** None.
- **Query parameters:** Required `response_type`, `client_id`, `redirect_uri`, `code_challenge`; optional `scope` (default `openid`), `state`, `code_challenge_method` (default `S256`).
- **Success:** None; a syntactically acceptable request returns `501`.
- **Validation/errors:** `400` unless `response_type=code`, scope contains `openid`, challenge method is `S256`, and `code_challenge` matches 43 base64url characters; then `501` because client/redirect validation and authenticated session are not implemented.

### Token exchange — Placeholder

`POST /oidc/token`

- **Purpose:** Reserved for token exchange; handler does not read or validate a body.
- **Authentication/headers:** No functioning client authentication.
- **Success:** None.
- **Response:** Always `501 Not Implemented`.

### UserInfo — Placeholder

`GET /oidc/userinfo`

- **Purpose:** Reserved for returning claims for a validated access token.
- **Authentication/headers:** Optional `Authorization` header is checked for the `Bearer ` prefix only.
- **Success:** None.
- **Errors:** `401` if the header is missing or does not start with `Bearer `; `501` if a bearer-formatted header is supplied because token validation and userinfo are not implemented.

## 8. Health and status APIs

### Combined app metadata — Implemented

`GET /`

- **Purpose:** Return service metadata, docs/static paths, endpoint prefixes, and module labels.
- **Authentication/headers:** None.
- **Success `200`:**

  ```json
  {
    "service": "Decentralized Zero-Trust IdP Mesh",
    "status": "operational",
    "version": "1.0.0",
    "api_docs": "/docs",
    "docs": "/docs",
    "redoc": "/redoc",
    "portal": "/portal/index.html",
    "login": "/login.html",
    "dashboard": "/dashboard/",
    "endpoints": {
      "ledger": "/api/v1/ledger",
      "ledger_verify": "/api/v1/ledger/verify",
      "token_issue": "/api/v1/tokens/issue",
      "token_verify": "/api/v1/tokens/verify",
      "token_revoke": "/api/v1/tokens/revoke",
      "public_key": "/api/v1/tokens/public-key",
      "did": "/api/v1/did",
      "webauthn": "/api/v1/webauthn",
      "admin": "/api/v1/admin",
      "oidc": "/oidc/.well-known/openid-configuration",
      "health": "/api/v1/health"
    },
    "active_modules": {
      "did": {"owner": "Member 3", "prefix": "/api/v1/did"},
      "webauthn": {"owner": "Member 2", "prefix": "/api/v1/webauthn"},
      "ledger": {"owner": "Member 4", "prefix": "/api/v1/ledger"},
      "tokens": {"owner": "Member 5", "prefix": "/api/v1/tokens"},
      "admin": {"owner": "Member 6", "prefix": "/api/v1/admin"},
      "portal": {"owner": "Shad", "prefix": "/portal"},
      "oidc": {"owner": "Shad", "prefix": "/oidc"}
    }
  }
  ```

- **Errors:** No route-specific error is declared.

### Composite health — Implemented, prototype assessment

`GET /health` and `GET /api/v1/health`

- **Purpose:** Same composite ledger/revocation/module status response at either path.
- **Authentication/headers:** None.
- **Success `200`:** `{"status":"degraded","version":"1.0.0","revocation":{"backend":"unavailable","redis_available":false,"persistence":"unverifiable","eviction":"unverifiable","durability":"unavailable"},"subsystems":{"ledger":{"status":"healthy","blocks":1,"head_hash":"<hash>","audit":{"valid":true,"error":null,"total_records":1,"head_hash":"<hash>"}},"tokens_and_policy":{"status":"degraded","signing_algorithm":"EdDSA (Ed25519)","revocation_store":"unavailable","revocation_redis_available":false,"revocation_persistence":"unverifiable","revocation_eviction":"unverifiable","revocation_durability":"unavailable"},"auth_webauthn":{"status":"healthy","owner":"Member 2","registered_credentials":0},"did_cryptography":{"status":"healthy","owner":"Member 3","registered_dids":0},"admin_dashboard":{"status":"healthy","owner":"Member 6"},"oidc":{"status":"healthy","owner":"Shad"}}}`.
- **Important:** `status` is `healthy` only when ledger integrity passes and revocation durability is `configuration_verified`; module-level healthy labels do not establish end-to-end integration. This route can lazily initialize and inspect Redis.
- **Errors:** No route-specific error is declared; dependency/runtime failures may return server errors.

### Standalone backend health — Separate entry point only

`GET /health` on `backend.main:app`

- **Purpose:** Simple standalone backend status response.
- **Authentication/headers:** None.
- **Success `200`:** `{"status":"ok","service":"webauthn"}`.
- **Important:** When using `app.main:app`, this separate backend app route is not mounted; the combined app's `/health` is used instead.

## Route inventory at a glance

| Category | Method and path |
|---|---|
| DID | `POST /api/v1/did/create`; `GET /api/v1/did/resolve/{did}`; `GET /api/v1/did/exists/{did}`; `GET /api/v1/did/list`; `POST /api/v1/did/challenge/update/{did}`; `POST /api/v1/did/update/{did}`; `POST /api/v1/did/challenge/deactivate/{did}`; `POST /api/v1/did/deactivate/{did}`; `POST /api/v1/did/verify-signature` |
| Simulated WebAuthn | `POST /api/v1/webauthn/register/begin`; `POST /api/v1/webauthn/register/complete`; `POST /api/v1/webauthn/authenticate/begin`; `POST /api/v1/webauthn/authenticate/complete`; `POST /api/v1/webauthn/credentials/challenge/{did}`; `GET /api/v1/webauthn/credentials/{did}` |
| Browser WebAuthn | `POST /webauthn/register/options`; `POST /webauthn/register/verify`; `POST /webauthn/login/options`; `POST /webauthn/login/verify`; `GET /did/{did}` |
| Tokens | `POST /api/v1/tokens/issue`; `POST /api/v1/tokens/verify`; `POST /api/v1/tokens/revoke`; `GET /api/v1/tokens/public-key`; `GET /api/v1/tokens/policy/scopes` |
| Admin | `GET /api/v1/admin/dashboard`; `GET /api/v1/admin/identities`; `GET /api/v1/admin/identities/{did}`; `GET /api/v1/admin/ledger`; `GET /api/v1/admin/ledger/verify`; `GET /api/v1/admin/credentials`; `POST /api/v1/admin/tokens/{jti}/revoke`; `GET /api/v1/admin/tokens/policy`; `POST /api/v1/admin/ledger/simulate-tamper`; `GET /api/v1/admin/health` |
| Ledger | `GET /api/v1/ledger`; `GET /api/v1/ledger/verify`; `GET /api/v1/ledger/history/{did}`; `GET /api/v1/ledger/latest/{did}`; `POST /api/v1/ledger/anchor/challenge`; `POST /api/v1/ledger/anchor`; `POST /api/v1/ledger/simulate-tamper` |
| OIDC | `GET /oidc/.well-known/openid-configuration`; `GET /oidc/authorize`; `POST /oidc/token`; `GET /oidc/userinfo` |
| Health | `GET /`; `GET /health`; `GET /api/v1/health`; standalone-only `GET /health` on `backend.main:app` |
