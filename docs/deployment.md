# Local container deployment

## Start

Copy `.env.example` to `.env`, then start the stack:

```powershell
Copy-Item .env.example .env
python traefik/generate-local-cert.py
certutil -user -addstore Root traefik/certs/dev-root-ca.crt
docker compose up --build -d
```

Open `https://localhost/` or `https://localhost/dashboard/`. Traefik redirects HTTP
to HTTPS and serves the generated local certificate. Restart the browser after trusting
the certificate if it was already open. The API's Swagger UI is at `https://localhost/docs`.

Create a passkey account at `https://localhost/register`; sign in at
`https://localhost/login`. Successful login opens `https://localhost/account`, where the
app confirms the DID and checks the token against a protected profile endpoint. The
username is the account identifier; there is no password-based registration.

The `idp_data` volume stores the ledger, audit events, passkey account database, public
DID documents, and JWT signing keys. The `redis_data` volume stores the token revocation deny-list.
Use `docker compose down` to stop the stack; `docker compose down -v` removes its
persistent data.

## Configuration

The generated certificate is for local development only. Before deployment, change the
`Host` rules in `traefik/dynamic.yml` and set
`WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGIN`, and `ALLOWED_ORIGINS` in `.env` for the public
hostname and HTTPS origin. Set `IDP_ADMIN_DIDS` to the comma-separated administrator
DIDs. Keep `.env` and signing keys private.

The provided TLS certificate is for local development. Configure a trusted
certificate resolver or mount a managed certificate at the production proxy before
exposing the service publicly. The application currently keeps authentication
sessions and WebAuthn challenges in process memory. Run a single API process; a
multi-worker or replicated deployment requires shared state for those components.
Sessions and pending ceremonies are discarded when the API restarts, so users must
authenticate again.
