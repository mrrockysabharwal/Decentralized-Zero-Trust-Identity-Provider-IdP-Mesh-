# Local container deployment

## Start

Copy `.env.example` to `.env`, then start the stack:

```powershell
Copy-Item .env.example .env
docker compose up --build -d
```

Open `https://localhost/` or `https://localhost/dashboard/`. Traefik redirects HTTP
to HTTPS. Its local default certificate is self-signed, so the browser will show a
certificate warning. For local browser passkey testing, accept the certificate
warning first. The API's Swagger UI is at `https://localhost/docs`.

The `idp_data` volume stores the ledger, audit events, passkey account database, public
DID documents, and JWT signing keys. The `redis_data` volume stores the token revocation deny-list.
Use `docker compose down` to stop the stack; `docker compose down -v` removes its
persistent data.

## Configuration

Set `IDP_HOST`, `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGIN`, and `ALLOWED_ORIGINS` in `.env`
to the public hostname and HTTPS origin before deployment. Set `IDP_ADMIN_DIDS` to
the comma-separated administrator DIDs. Keep `.env` and signing keys private.

The provided TLS certificate is for local development. Configure a trusted
certificate resolver or mount a managed certificate at the production proxy before
exposing the service publicly. The application currently keeps authentication
sessions and WebAuthn challenges in process memory. Run a single API process; a
multi-worker or replicated deployment requires shared state for those components.
Sessions and pending ceremonies are discarded when the API restarts, so users must
authenticate again.
