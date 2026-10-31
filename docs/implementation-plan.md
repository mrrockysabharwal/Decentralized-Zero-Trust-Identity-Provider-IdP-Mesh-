# Member 6 — Implementation Plan
**Date:** 2026-10-14
**Author:** Member 6 (Dashboard, Testing and Deployment)
**Project:** Decentralized Zero-Trust Identity Provider (IdP) Mesh

---

## 1. Project Overview

This is a six-member academic project building a decentralized, Zero-Trust Identity Provider.
The architecture replaces traditional username/password authentication with:
- Decentralized Identifiers (DIDs) with Ed25519 cryptography (Members 3 and 1)
- WebAuthn/FIDO2 biometric authentication (Member 2)
- A simulated append-only blockchain ledger (Member 4)
- JWT tokens with Redis-based revocation and Bloom filter (Member 5)
- Zero-Trust policy engine (Member 5)

Member 6 owns: administrative dashboard, security-event visualization,
integration and security tests, Docker, Traefik and TLS, and documentation.

---

## 2. Actual Architecture Discovered (Day 1)

### What exists on `main` (verified)

```
app/modules/ledger/  — Module C: simulated blockchain ledger (Member 4)
  chain.py           — SimulatedLedger (append, verify, query, persist)
  hasher.py          — SHA-256 canonical hashing utilities
  models.py          — LedgerRecord, RecordCreateInput, LedgerOperation
  router.py          — FastAPI APIRouter: 6 endpoints under /ledger
tests/unit/          — 26 unit tests for Module C (all expected to pass)
requirements.txt     — 10 packages declared, none installed
```

### What is missing (verified gaps)

- `app/main.py` — FastAPI application entry point (MISSING)
- Module A — Core API and Identity (Member 1)
- Module B — WebAuthn/FIDO2 auth (Member 2)
- Module C2 — DID and Ed25519 cryptography (Member 3)
- Module D/E — Zero-Trust policy engine and JWT/Redis (Member 5)
- Security event model and audit log (any member)
- Frontend dashboard (Member 6)
- Dockerfile, docker-compose.yml, Traefik config, TLS (Member 6)
- Integration tests (Member 6)
- `.env.example` (Member 6 in coordination with all members)

### Architecture diagram (proposed — components labeled by status)

```
[Browser / Admin Dashboard]    <-- HTML + CSS + vanilla JS (PROPOSED: Member 6)
        |
        | HTTPS (TLS via Traefik)
        v
[Traefik Reverse Proxy]        <-- PROPOSED: Member 6
        |
        v
[FastAPI Application]          <-- app/main.py (PROPOSED: Member 1)
  |   |   |   |   |
  |   |   |   |   +-- /api/v1/ledger/*   <-- IMPLEMENTED: Member 4
  |   |   |   +------ /api/v1/auth/*     <-- PROPOSED: Member 2
  |   |   +---------- /api/v1/did/*      <-- PROPOSED: Member 3
  |   +-------------- /api/v1/tokens/*   <-- PROPOSED: Member 5
  +------------------ /api/v1/dashboard/* <-- PROPOSED: Member 6
        |
        +-- Redis     <-- PROPOSED: Member 5 (token revocation)
        +-- SQLite    <-- PROPOSED: Members 1/3 (DID storage)
        +-- In-memory ledger chain <-- IMPLEMENTED: Member 4
```

---

## 3. Member 6 Responsibilities

| Responsibility | Status | Priority |
|---|---|---|
| Administrative dashboard (HTML/JS frontend) | Not started | HIGH |
| Security event display and filtering | Not started | HIGH |
| Dashboard backend API (`/api/v1/dashboard/*`) | Not started | HIGH |
| Integration tests (`tests/integration/`) | Not started | HIGH |
| Security tests | Not started | MEDIUM |
| Dockerfile (backend service) | Not started | HIGH |
| docker-compose.yml (full stack) | Not started | HIGH |
| Traefik reverse proxy configuration | Not started | MEDIUM |
| TLS (Let's Encrypt or self-signed for dev) | Not started | MEDIUM |
| `.env.example` | Not started | HIGH |
| Project setup documentation | Not started | MEDIUM |
| `conftest.py` shared test fixtures | Not started | HIGH |
| Running and verifying existing 26 tests | Blocked (no venv) | IMMEDIATE |

---

## 4. Required Backend Endpoints and Dependencies

See `docs/member-6-api-contract.md` for full details.

**Endpoints Member 6 will implement:**
- `GET /api/v1/dashboard/summary` — statistics overview
- `GET /api/v1/dashboard/events` — paginated security event list
- `GET /api/v1/dashboard/events/{event_id}` — event detail
- `GET /api/v1/dashboard/health` — service health status
- `GET /api/v1/dashboard/ledger` — paginated ledger view with integrity status

**Endpoints Member 6 depends on from other members:**
- `GET /api/v1/ledger/verify` — chain integrity (Member 4, IMPLEMENTED)
- `GET /api/v1/ledger` — all records (Member 4, IMPLEMENTED)
- Security event store queryable API (Members 2 and 5, MISSING)
- JWT token verification utility (Member 5, MISSING)
- DID statistics endpoint (Member 1 or 3, MISSING)
- Service health endpoints from all members (MISSING)

---

## 5. 20-Working-Day Implementation Schedule

### Phase 0: Environment Setup (Day 1 — TODAY)
- [x] Audit repository and document architecture
- [x] Create documentation files
- [ ] Set up Python virtual environment
- [ ] Install dependencies and run existing 26 tests
- [ ] Investigate `Shad` branch contents

---

### Phase 1: Foundation — Days 2–4

**Day 2:** Environment and baseline
- Create Python virtual environment (`.venv`)
- Install `requirements.txt`
- Run `pytest tests/unit/ -v` and confirm 26 tests pass
- Create `tests/conftest.py` with shared fixtures
- Create `tests/integration/` directory structure

**Day 3:** Dashboard backend scaffold
- Create `app/modules/dashboard/` module
- Implement `GET /api/v1/dashboard/health` (ping Redis, ledger, etc.)
- Wire up in a minimal `app/main.py` if Member 1 has not yet done so
- Write first integration test for the health endpoint

**Day 4:** Summary statistics endpoint
- Implement `GET /api/v1/dashboard/summary`
- Source ledger stats from Member 4's existing endpoints
- Stub missing fields (events, DIDs) with `"unknown"` until other members deliver
- Write integration tests

---

### Phase 2: Security Event Display — Days 5–8

**Day 5:** Security event data model
- Define `SecurityEvent` Pydantic model in `app/modules/dashboard/models.py`
- Create in-memory event store as stub (replaces real store once Members 2 and 5 deliver)
- Agree with Members 2 and 5 on event schema and storage contract

**Day 6:** Event list endpoint
- Implement `GET /api/v1/dashboard/events` with pagination and filtering
- Write integration tests covering pagination, filter by type, filter by outcome

**Day 7:** Event detail endpoint
- Implement `GET /api/v1/dashboard/events/{event_id}`
- Write integration tests for found and not-found cases

**Day 8:** Integrate real event sources
- Replace stub event store with actual queries to Members 2 and 5 once available
- Verify no sensitive fields (passwords, tokens, raw IPs) leak through event responses

---

### Phase 3: Admin Dashboard Frontend — Days 9–12

**Day 9:** Dashboard shell and navigation
- Create `frontend/dashboard/` with `index.html`, `style.css`, `main.js`
- Design layout: sidebar navigation, main content area, header with status indicator
- Apply dark-theme styling

**Day 10:** Summary statistics panel
- Implement summary cards (total DIDs, events in 24h, ledger status, service health)
- Fetch data from `GET /api/v1/dashboard/summary`
- Auto-refresh every 30 seconds

**Day 11:** Ledger viewer panel
- Implement block table with pagination
- Show integrity status badge (green/red)
- Tamper simulation button (calls `POST /api/v1/ledger/simulate-tamper`)
- Integrity re-verification and result display

**Day 12:** Security event panel
- Implement event table with pagination
- Add filter controls (event type, outcome, severity, time range)
- Event detail modal or sidebar

---

### Phase 4: Integration and Security Tests — Days 13–15

**Day 13:** Full integration test suite
- Write `tests/integration/test_dashboard_endpoints.py`
- Test all five dashboard endpoints end-to-end using FastAPI TestClient or httpx
- Test error handling: missing auth, invalid input, missing dependencies

**Day 14:** Security tests
- Test authentication bypass attempts (missing JWT, expired JWT, wrong role)
- Test that sensitive data does not appear in event API responses
- Test event pagination cannot be bypassed to dump all records
- Test ledger tamper-detection via simulate-tamper endpoint

**Day 15:** Cross-module integration tests
- Write `tests/integration/test_ledger_integration.py`
- Test ledger anchor + verify + dashboard summary flow end-to-end
- Integrate with Member 4's ledger directly
- Document any interface mismatches with other members

---

### Phase 5: Docker and Deployment — Days 16–18

**Day 16:** Dockerfile
- Create `Dockerfile` for the FastAPI backend (Python 3.13, uvicorn)
- Create `.env.example` listing all required environment variable names
- Test local `docker build` and `docker run`

**Day 17:** Docker Compose
- Create `docker-compose.yml` for full local stack:
  - `api` service — FastAPI backend
  - `redis` service — official Redis image
  - `traefik` service — Traefik v3 reverse proxy
- Configure service discovery and network

**Day 18:** Traefik and TLS
- Create `traefik/traefik.yml` static configuration
- Configure HTTP to HTTPS redirect
- Configure Let's Encrypt ACME or self-signed TLS for development
- Create `traefik/dynamic.yml` for routing rules
- Test full HTTPS stack locally

---

### Phase 6: Documentation and Final Validation — Days 19–20

**Day 19:** Documentation
- Update `docs/member-6-architecture-audit.md` with final architecture
- Write `docs/deployment.md` — complete setup and deployment guide
- Write `docs/testing.md` — how to run all tests
- Update `README.md` with startup instructions

**Day 20:** Final validation
- Run full test suite: `pytest tests/ -v --tb=short`
- Run Docker Compose stack and verify all services healthy
- Run security test sweep
- Check all Day 1 acceptance criteria
- Prepare final report

---

## 6. Testing Strategy

### Unit tests (existing — Member 4)
- 26 tests in `tests/unit/`
- Run with: `python -m pytest tests/unit/ -v`

### Integration tests (Member 6 to create)
- Location: `tests/integration/`
- Use FastAPI TestClient (from `httpx`)
- Test all dashboard endpoints
- Test ledger endpoints via mounted router
- Run with: `python -m pytest tests/integration/ -v`

### Security tests (Member 6 to create)
- Location: `tests/security/` or within `tests/integration/`
- Test auth bypass, data leakage, input validation
- Run with: `python -m pytest tests/ -k "security" -v`

### Full suite
```powershell
python -m pytest tests/ -v --tb=short
```

### With coverage report
```powershell
python -m pytest tests/ --cov=app --cov-report=html
```

---

## 7. Docker and Traefik Plan

### Files to create

| File | Purpose |
|---|---|
| `Dockerfile` | Backend container (Python 3.13, uvicorn) |
| `docker-compose.yml` | Full stack orchestration |
| `traefik/traefik.yml` | Traefik static config |
| `traefik/dynamic.yml` | Traefik routing rules |
| `.env.example` | Environment variable template |
| `data/.gitkeep` | Placeholder for ledger persistence volume |

### Environment variables needed (proposed — to be confirmed)

| Variable | Purpose | Owner |
|---|---|---|
| `SECRET_KEY` | JWT signing secret | Member 5 |
| `REDIS_URL` | Redis connection string | Member 5 |
| `LEDGER_STORAGE_PATH` | JSON file path for ledger persistence | Member 4 |
| `DASHBOARD_ADMIN_ROLE` | JWT claim value for admin access | Member 5/6 |
| `TRAEFIK_ACME_EMAIL` | Let's Encrypt email | Member 6 |
| `API_HOST` | Uvicorn bind host | Member 6 |
| `API_PORT` | Uvicorn bind port | Member 6 |

---

## 8. Risks and Unresolved Questions

| Risk | Severity | Mitigation |
|---|---|---|
| `app/main.py` missing — cannot run application | HIGH | Member 6 creates minimal stub if Member 1 is delayed |
| No security event store agreed with Members 2 and 5 | HIGH | Use in-memory stub; define schema in api-contract.md for team review |
| `Shad` branch not inspected | MEDIUM | Inspect on Day 2 before writing integration code |
| JWT admin role claim not defined | MEDIUM | Propose default in api-contract.md; request team confirmation |
| Redis not running locally | MEDIUM | Dashboard health endpoint degrades gracefully; docker-compose provides Redis |
| SQLite schema unknown | MEDIUM | Dashboard reads from SQLite once Members 1 and 3 define schema |
| Python venv not set up | IMMEDIATE | Must be done before any code runs |

**Unresolved questions:**

1. What prefix does Member 1 use in `app/main.py`? (`/api/v1` assumed)
2. What is the JWT claim name and value for administrator access?
3. Will security events be stored in SQLite, Redis or an in-memory log?
4. What does the `Shad` branch contain?
5. Which member owns the Zero-Trust policy engine?
6. What are the agreed environment variable names?

---

## 9. Day 1 Completion Checklist

- [x] Repository structure fully inspected
- [x] Architecture and technology stack documented
- [x] Git branch, status and history recorded
- [x] All implemented files identified and read
- [x] All missing components listed with owners
- [x] Declared dependencies documented with install status
- [x] Baseline test results recorded (blocked — venv missing)
- [x] API contract for dashboard endpoints documented
- [x] Integration dependencies from Members 1–5 mapped
- [x] 20-day implementation schedule created
- [x] Risks and open questions documented
- [x] `docs/member-6-architecture-audit.md` created
- [x] `docs/member-6-api-contract.md` created
- [x] `docs/member-6-implementation-plan.md` created
- [ ] Virtual environment set up and dependencies installed
- [ ] 26 existing unit tests verified to pass
- [ ] `Shad` branch contents inspected
- [ ] Nothing pushed to GitHub
- [ ] No Git commit made

---

## 10. Exact Commands (to be run manually by Member 6)

```powershell
# Set up virtual environment (run once)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run existing unit tests
python -m pytest tests/ -v

# Run tests with coverage (after coverage installed)
python -m pytest tests/ -v --cov=app --cov-report=html

# Start the application (once app/main.py exists)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Build Docker image (once Dockerfile created)
docker build -t idp-mesh-api .

# Start full stack (once docker-compose.yml created)
docker compose up -d

# Check running services
docker compose ps

# View API documentation (once app running)
# Open: http://localhost:8000/docs
```

**Git commands (to run manually — DO NOT run automatically):**

```powershell
# Inspect Shad branch (read-only)
git fetch origin Shad
git show origin/Shad --stat

# Stage Member 6 documentation
git add docs/member-6-architecture-audit.md
git add docs/member-6-api-contract.md
git add docs/member-6-implementation-plan.md

# Create Day 1 commit (when ready)
git commit -m "docs(member-6): add Day 1 architecture audit, API contract and implementation plan"

# Push Member 6 branch (when ready)
git push origin Albin-Gervasis
```

---

## 11. Recommended Day 2 Task

1. Set up the Python virtual environment and install `requirements.txt`.
2. Run `python -m pytest tests/unit/ -v` and confirm all 26 tests pass.
3. Inspect the `Shad` branch for any relevant implementation.
4. Create `tests/conftest.py` with basic shared fixtures.
5. Create a minimal `app/main.py` that mounts `ledger_router` under `/api/v1`.
6. Write the first integration test for `GET /api/v1/ledger`.
7. Begin scaffold for `app/modules/dashboard/`.
