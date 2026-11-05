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

The generated certificate and `traefik/dynamic.yml` route are for local development.
For production, copy the trusted full-chain certificate and its private key to the host
and set these values in `.env`:

```dotenv
PUBLIC_HOSTNAME=id.example.com
WEBAUTHN_RP_ID=id.example.com
WEBAUTHN_ORIGIN=https://id.example.com
ALLOWED_ORIGINS=https://id.example.com
IDP_ADMIN_DIDS=did:mesh:key:your-provisioned-admin
TLS_CERT_PATH=/absolute/host/path/fullchain.pem
TLS_KEY_PATH=/absolute/host/path/privkey.pem
TRAEFIK_DYNAMIC_CONFIG=./traefik/dynamic.production.yml
```

Provision and register the administrator passkey first, then use its DID above. Keep
`.env`, the TLS private key, and signing keys private. Render the production route and
start the stack:

```powershell
python traefik/render-production-config.py
docker compose up --build -d
```

The renderer refuses localhost, mismatched RP/origin settings, wildcard CORS, a missing
administrator DID, absent certificate/key files, a certificate that does not cover the
hostname or is outside its validity period, and a key that does not match the
certificate. It writes the ignored `traefik/dynamic.production.yml` consumed by
Traefik. The certificate must come from a CA trusted by clients; the renderer checks
hostname, dates, and key matching, but does not validate the public trust chain.
Renewing/replacing a certificate requires replacing the mounted host file and
restarting Traefik.

Compose enables Redis-backed authentication sessions and WebAuthn challenges by
default. `EPHEMERAL_STATE_BACKEND=redis` makes Redis availability a startup requirement;
the API does not silently fall back to local state. Direct single-process runs default
to memory unless this variable is set. Sessions and pending ceremonies expire after
five minutes.

Keep one API process per deployment for now. The simulated ledger and core credential
registry still use process-local working state, so sharing auth sessions and challenges
does not make concurrent API replicas safe.

## Verify administrator authorization

Run the configured-DID integration check from the repository root:

```powershell
python -m pytest tests/integration/test_configured_admin_flow.py -q
```

The check creates a registered DID, configures that DID as an administrator, issues a
token from an authenticated session, and confirms that the token can read the admin
dashboard. It verifies server-assigned admin authorization without embedding an admin
role in the token request. The deployed browser flow still requires a real passkey
ceremony for an administrator account before exposing the deployment to operators.
