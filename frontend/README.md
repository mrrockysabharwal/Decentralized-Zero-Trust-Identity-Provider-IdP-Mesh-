# TrustMesh — Frontend Subsystem

This directory contains the user interface components of the **Decentralized Zero-Trust Identity Provider (IdP) Mesh**.

---

## 1. Directory Structure

```text
frontend/
├── README.md               # Frontend subsystem overview and run instructions (this file)
│
├── dashboard/              # Member 6: Administrative Security Dashboard
│   ├── index.html          # Semantic HTML5 dashboard shell with full accessibility
│   ├── style.css           # CSS3 responsive dark-theme stylesheet & design tokens
│   └── app.js              # Vanilla ES2022 controller & decoupled ApiClient
│
└── (landing page)          # Member 2 (branch Shad): Public landing page
    ├── index.html          # Public marketing & registration entry point
    └── style.css           # Hero section and globe visualization styling
```

---

## 2. Administrative Security Dashboard (`frontend/dashboard/`)

### Key Features
1. **Mesh Security Overview**:
   - Live ledger record count and cryptographic hash linkage verification.
   - 24-hour security audit metrics (authentication attempts, token issuances, revocations).
   - Decentralized Identifier (DID) active vs revoked status.
   - Continuous Zero-Trust pass rate evaluation.
2. **Security Audit Event Log**:
   - Filterable by Event Type, Outcome (Success/Failure), and Severity (Low to Critical).
   - Full-text search over DID references and diagnostic reason strings.
   - Client-side pagination and JSON audit log export.
   - Interactive event inspection dialog with complete metadata drilldown.
3. **Module C Blockchain Ledger Audit**:
   - Displays all append-only blocks anchored to the simulated blockchain ledger.
   - Live re-verification of SHA-256 chain linkage (`previous_hash` → `record_hash`).
   - Interactive **Tamper Attack Simulation** modal to demonstrate real-time cryptographic audit detection.
4. **Zero-Trust Access Decisions**:
   - Continuous risk-based evaluation feed showing ALLOW, CHALLENGE, and DENY decisions.
5. **Subsystem Health & Dependency Mesh**:
   - Visual health matrix covering all six component modules (Ledger, Core API, WebAuthn, DID Crypto, Policy Engine, Redis Revocation).
   - API contract reference map detailing endpoints and ownership.

### Architecture & Standards
- **Zero Framework Overhead**: Built exclusively with standards-compliant HTML5, CSS3, and Vanilla JavaScript. No React, Vue, Next.js, or external node runtime needed.
- **Decoupled API Client**: `ApiClient` layer cleanly separates presentation logic from HTTP operations. It connects to FastAPI at `http://localhost:8000/api/v1`.
- **Graceful Offline / Demo Mode**: If the backend is unreachable or under development, the dashboard automatically falls back to simulated telemetry matching the exact data contracts documented in `docs/api-contract.md`. The interface clearly flags demo mode with an active notice badge.
- **Accessibility (a11y)**: Semantic HTML (`<nav>`, `<header>`, `<main>`, `<section>`, `<article>`, `<dialog>`), keyboard skip links, ARIA roles, and high-contrast dark theme.
- **Responsive Layout**: Fluid CSS grid and flexbox supporting desktop monitors, tablets, and mobile devices (with a slide-out navigation drawer).

---

## 3. How to Run the Dashboard

### Option A: Python HTTP Server (Recommended)
From the repository root directory:
```powershell
# Start local static server
python -m http.server 3000

# Open in your web browser:
# http://localhost:3000/frontend/dashboard/
```

### Option B: Node.js `npx serve`
```powershell
npx -y serve -l 3000

# Open in your web browser:
# http://localhost:3000/frontend/dashboard/
```

### Option C: Direct Browser File Opening
Open `frontend/dashboard/index.html` directly in any modern browser (Chrome, Edge, Firefox, Safari). All assets use relative paths.

---

## 4. Connecting to the Live Backend

When the backend FastAPI application is running (e.g. `uvicorn app.main:app --port 8000`):
1. The dashboard will automatically detect the active API on its periodic 30-second poll or when the **Refresh Data** button is clicked.
2. The top status pill will turn **green** (`Backend: Online`).
3. Real ledger blocks from Member 4 (`GET /api/v1/ledger`) and real integrity checks (`GET /api/v1/ledger/verify`) will replace the demonstration mock data.
