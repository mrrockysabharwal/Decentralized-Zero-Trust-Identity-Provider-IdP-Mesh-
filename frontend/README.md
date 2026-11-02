# TrustMesh — Frontend

The frontend is a framework-free administration dashboard for the Decentralized Zero-Trust Identity Provider Mesh.

## Dashboard files

- `dashboard/index.html` provides the accessible dashboard structure and navigation.
- `dashboard/style.css` contains the responsive dark Material-inspired surface and component styles. It keeps the existing TrustMesh navy, blue, and teal palette, Inter text, and JetBrains Mono identifiers.
- `dashboard/app.js` fetches data from the FastAPI application and renders live, ledger-derived status. It does not fill missing API capabilities with invented events or identity records.

## Dashboard sections

- **Passkey login:** `/login` serves browser-native WebAuthn/FIDO2 login. `/register` creates an account and its first passkey. A verified passkey login creates the DID-bound core session and access JWT.

- **Overview:** ledger record count and integrity, latest ledger activity, identity count derived from ledger records, and service health.
- **Identities:** latest state per DID derived from the ledger. This is not a separate identity registry.
- **Ledger audit:** ledger history, integrity result, CSV export, and the existing demonstration-only tamper simulation endpoint. The tamper endpoint changes the ledger; use it only with a disposable local ledger.
- **Token security:** active public key and allowed scopes, plus token verification using `POST /api/v1/tokens/verify`. The input is cleared after submission and the submitted JWT is never rendered in the result. Token issuance requires a short-lived verified authentication session; owner revocation requires the signed token and matching JTI.
- **Security events:** authenticated admin feed with counts, event type/outcome filters, pseudonymous DID references, and expandable event details. The short-lived admin JWT is read from browser `sessionStorage` and cleared when the tab session ends or the user clears the token.
- **Service health:** displays fields returned by the application health endpoint; it does not invent per-service latency.

## Run the dashboard

From the repository root, serve the static page:

```powershell
python -m http.server 3000
```

Open `http://localhost:3000/frontend/dashboard/`. For live data, run the FastAPI application separately, for example with `uvicorn app.main:app --port 8000`. When the page is served from another port, the dashboard requests the API at `http://localhost:8000/api/v1`.

The dashboard refreshes every 30 seconds and has a manual refresh control. If all API routes are unavailable, it shows an unavailable state; it does not present demo telemetry as real data. No frontend framework or additional UI dependency is required.

The login experience is served at `http://localhost:8000/shad/login.html` (also available at `/login` and `/login.html`). Account creation is at `/register` and uses a passkey; the username becomes the account identifier. Successful login opens `/account`, which confirms the DID and checks access to the protected profile endpoint. The landing page is at `http://localhost:8000/shad/`.
