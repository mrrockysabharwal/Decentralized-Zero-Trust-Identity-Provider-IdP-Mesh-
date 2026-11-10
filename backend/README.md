# TrustMesh Backend Architecture

The TrustMesh backend is a high-performance Python FastAPI service providing:
1. **Passwordless WebAuthn / FIDO2 Authentication**: Cryptographic user verification using device authenticators without password storage.
2. **Decentralized Identifier (DID) Generation & Resolution**: W3C compliant `did:mesh:<hash>` generation anchored to public keys.
3. **Simulated Blockchain Ledger Integration**: Cryptographically anchors DID document states and updates using SHA-256 hash chains.
4. **OpenID Connect (OIDC) Identity Provider**: Authorization Code Flow with PKCE (`S256`), RS256 token signing (RSA-2048), discovery, and JWKS endpoints.

## Directory Structure
- `main.py`: Core FastAPI application, WebAuthn routes, session issuance, and DID resolution.
- `oidc/`: OpenID Connect router, schemas, and cryptographic key/token services.
  - `router.py`: Discovery (`/.well-known/openid-configuration`), `/authorize`, `/token`, `/userinfo`, `/jwks`.
  - `service.py`: PKCE verification, RS256 signing, authorization code state management.
  - `schemas.py`: Pydantic models for OIDC requests and responses.
  - `oidc_key.pem`: Persistent 2048-bit RSA private key for RS256 token signing.
- `register_oidc_client.py`: Administrative utility to register external OAuth2 / OIDC clients.
- `webauthn.sqlite3`: Local SQLite database storing credentials, user handles, and active sessions.

## Starting the Backend
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive documentation is available at `http://localhost:8000/docs`.
