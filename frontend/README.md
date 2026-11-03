# TrustMesh — Frontend

The frontend is a framework-free administration dashboard for the Decentralized Zero-Trust Identity Provider Mesh.

## Dashboard files

- `dashboard/index.html` provides the accessible dashboard structure and navigation.
- `dashboard/style.css` contains the responsive dark Material-inspired surface and component styles. It keeps the existing TrustMesh navy, blue, and teal palette, Inter text, and JetBrains Mono identifiers.
- `dashboard/app.js` fetches data from the FastAPI application and renders live, ledger-derived status. It does not fill missing API capabilities with invented events or identity records.

## Dashboard sections

- **Overview:** ledger record count and integrity, latest ledger activity, identity count derived from ledger records, and service health.
- **Identities:** latest state per DID derived from the ledger. This is not a separate identity registry.
- **Ledger audit:** ledger records, integrity result, CSV export, and a demonstration tamper control. The API simulates tampering against an isolated copy, so it does not change the shared ledger. The control currently sends no admin bearer token and cannot complete the protected endpoint flow.
- **Token security:** active public key and allowed scopes, plus token verification using `POST /api/v1/tokens/verify`. The input is cleared after submission and the submitted JWT is never rendered in the result. Issuance and revocation are shown as unavailable because their routes return HTTP 503 pending authentication and ownership authorization.
- **Security events:** states that no event-store API is currently available instead of displaying simulated events.
- **Service health:** displays fields returned by the application health endpoint; it does not invent per-service latency.

## Run the dashboard

From the repository root, serve the static page:

```powershell
python -m http.server 3000
```

Open `http://localhost:3000/frontend/dashboard/`. For live data, run the FastAPI application separately, for example with `uvicorn app.main:app --port 8000`. When the page is served from another port, the dashboard requests the API at `http://localhost:8000/api/v1`.

The dashboard refreshes every 30 seconds and has a manual refresh control. It does not call `/api/v1/admin/*` or perform admin authentication. Its API base is `/api/v1` on port 8000 and otherwise hard-coded to `http://localhost:8000/api/v1`. If all API routes are unavailable, it shows an unavailable state; it does not present demo telemetry as real data. No frontend framework or additional UI dependency is required. See [the API reference](../docs/API_DOCUMENTATION.md) and [implementation status](../docs/IMPLEMENTATION_STATUS.md).
