# Shad passkey integration

Shad's passkey implementation is now registered as routers inside the core
FastAPI application. Start the project from the repository root with:

```powershell
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- Shad UI: `/shad/` and `/shad/login.html`
- Native passkey API: `/api/v1/webauthn/register/*` and `/api/v1/webauthn/login/*`
- Shad DID resolution: `/api/v1/shad/did/{did}`
- Albin admin UI: `/dashboard/`
- Midhun APIs: `/api/v1/did`, `/api/v1/webauthn`, `/api/v1/ledger`,
  `/api/v1/tokens`, and `/api/v1/admin`

Shad's verified passkeys and DID documents are synchronized into the core
credential and DID registries at startup and after registration. Shad login
uses the shared ledger and returns a JWT issued by Midhun's token module.
Shad's native WebAuthn credentials remain in the SQLite database; the core
WebAuthn simulation endpoints use their separate Ed25519 ceremony format.
