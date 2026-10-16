"""
app/main.py — Core Backend Entry Point
=======================================
Owner  : Member 1 (Core Backend)
Purpose: Bootstraps the FastAPI application, wires together all module
         routers, and ensures a SHARED SimulatedLedger instance is used
         across both Module C (Ledger) and Module E (Tokens) so that:

           • DIDs anchored via  POST /api/v1/ledger/anchor
             are immediately visible to the Zero-Trust policy engine in
             POST /api/v1/tokens/issue

         Module C — Simulated Blockchain Ledger    (Member 4 / branch: midhun)
         Module E — JWT & Zero-Trust Policy Engine (Member 5 / branch: member5)

         Placeholder mounts are provided (commented-out) for modules not yet
         merged:
           Module A — WebAuthn / FIDO2 biometric auth   (Member 2)
           Module B — DID Registry & Cryptography        (Member 3)
           Module D — Admin Dashboard API                (Member 6)

Run locally:
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

Environment variables (optional — picked up via python-dotenv .env file):
    TOKEN_KEY_DIR          Ed25519 PEM key storage dir   (default: .token_keys)
    REDIS_URL              Redis URL for JTI deny-list   (default: redis://localhost:6379/0)
    TOKEN_EXPIRY_SECONDS   JWT lifetime in seconds       (default: 3600)
    CORS_ORIGINS           Comma-separated allowed CORS origins
    LEDGER_STORAGE_PATH    Optional path to persist ledger to a JSON file
"""

import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ── Load .env before any env-var reads ───────────────────────────────────────
load_dotenv()

# ── Module C (Member 4) — Simulated Blockchain Ledger ────────────────────────
from app.modules.ledger import (
    SimulatedLedger,
    ledger_router,
)
from app.modules.ledger.router import ledger_instance  # singleton created by Member 4

# ── Module E (Member 5) — JWT Tokens & Zero-Trust Policy Engine ──────────────
from app.modules.tokens import tokens_router
import app.modules.tokens.router as _tokens_router_module

# ── Future module routers — uncomment once branches are merged ────────────────
# from app.modules.did      import did_router        # Member 3 — DID Registry
# from app.modules.webauthn import webauthn_router   # Member 2 — WebAuthn/FIDO2
# from app.modules.admin    import admin_router      # Member 6 — Admin Dashboard

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("idp_mesh.main")

# ── CORS origins ──────────────────────────────────────────────────────────────
ALLOWED_ORIGINS: list[str] = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000",
).split(",")


# ── Shared ledger injection ────────────────────────────────────────────────────
# Member 4's router owns a singleton `ledger_instance` (SimulatedLedger).
# Member 5's router owns its own `_shared_ledger` singleton.
#
# To satisfy Zero-Trust: a DID anchored via /ledger/anchor must be found when
# /tokens/issue runs its policy check.  We point both routers at the SAME object.
def _wire_shared_ledger() -> None:
    """Replace the tokens router's internal ledger with Member 4's shared ledger.

    This ensures that any DID anchored through Module C (Ledger) endpoints is
    immediately visible to Module E's ZeroTrustPolicyEngine when issuing tokens.
    """
    _tokens_router_module._shared_ledger = ledger_instance
    _tokens_router_module._policy_engine = _tokens_router_module.ZeroTrustPolicyEngine(
        ledger=ledger_instance
    )
    logger.info(
        "Shared SimulatedLedger wired: Module C ledger_instance → Module E policy engine"
    )


# ── Application lifespan (startup / shutdown hooks) ───────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle handler."""
    # ── Startup ───────────────────────────────────────────────────────────────
    _wire_shared_ledger()

    logger.info("=" * 65)
    logger.info("  Decentralized Zero-Trust IdP Mesh — starting up")
    logger.info("  API base    : http://localhost:8000/api/v1")
    logger.info("  Swagger UI  : http://localhost:8000/docs")
    logger.info("  ReDoc       : http://localhost:8000/redoc")
    logger.info("  Active modules:")
    logger.info("    [M4] Ledger        → /api/v1/ledger")
    logger.info("    [M5] Tokens        → /api/v1/tokens")
    logger.info("  Pending modules:")
    logger.info("    [M2] WebAuthn      → /api/v1/webauthn  (not yet merged)")
    logger.info("    [M3] DID Registry  → /api/v1/did       (not yet merged)")
    logger.info("    [M6] Admin Dashboard → /api/v1/admin   (not yet merged)")
    logger.info("=" * 65)

    yield  # ── Application is live ───────────────────────────────────────────

    # ── Shutdown ──────────────────────────────────────────────────────────────
    logger.info("Decentralized Zero-Trust IdP Mesh — shutting down gracefully")


# ── FastAPI application ───────────────────────────────────────────────────────
app = FastAPI(
    title="Decentralized Zero-Trust Identity Provider (IdP) Mesh",
    description=(
        "A fully decentralized, Zero-Trust Identity Provider built with Python & FastAPI.\n\n"
        "Replaces username/password tables with **Decentralized Identifiers (DIDs)**, "
        "**WebAuthn (FIDO2)** biometrics, and cryptographic identity anchoring on a "
        "simulated blockchain ledger.\n\n"
        "---\n\n"
        "## Team Modules\n\n"
        "| Module | Owner | Branch | Status | API Prefix |\n"
        "|--------|-------|--------|--------|------------|\n"
        "| Core Backend (`main.py`) | Member 1 | `main` | ✅ Active | — |\n"
        "| WebAuthn / FIDO2 | Member 2 | TBD | 🔜 Pending | `/api/v1/webauthn` |\n"
        "| DID Registry & Cryptography | Member 3 | TBD | 🔜 Pending | `/api/v1/did` |\n"
        "| Simulated Blockchain Ledger | Member 4 | `midhun` | ✅ Active | `/api/v1/ledger` |\n"
        "| JWT & Zero-Trust Policy Engine | Member 5 | `member5` | ✅ Active | `/api/v1/tokens` |\n"
        "| Admin Dashboard API | Member 6 | TBD | 🔜 Pending | `/api/v1/admin` |\n\n"
        "---\n\n"
        "## Key Integration Detail\n\n"
        "Module C (Ledger) and Module E (Tokens) share a **single `SimulatedLedger` "
        "instance**, wired at startup by Member 1. This enforces the Zero-Trust guarantee: "
        "a DID must be anchored on the ledger before a JWT can be issued for it."
    ),
    version="1.0.0",
    contact={"name": "IdP Mesh Team"},
    license_info={"name": "MIT"},
    lifespan=lifespan,
)

# ── CORS Middleware ───────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Mount Module Routers
# ─────────────────────────────────────────────────────────────────────────────

# ── Module C — Member 4 (Simulated Blockchain Ledger) ────────────────────────
# Endpoints:
#   GET  /api/v1/ledger                         — List all blocks
#   GET  /api/v1/ledger/verify                  — Cryptographic integrity audit
#   GET  /api/v1/ledger/history/{did}           — Full DID event history
#   GET  /api/v1/ledger/latest/{did}            — Latest DID state
#   POST /api/v1/ledger/anchor                  — Anchor a DID document (CREATE/UPDATE/DEACTIVATE)
#   POST /api/v1/ledger/simulate-tamper         — Live tamper-detection demo
app.include_router(ledger_router, prefix="/api/v1")

# ── Module E — Member 5 (JWT Tokens & Zero-Trust Policy Engine) ──────────────
# Endpoints:
#   POST /api/v1/tokens/issue                   — Issue JWT after Zero-Trust policy evaluation
#   POST /api/v1/tokens/verify                  — Verify & decode a JWT (+ revocation check)
#   POST /api/v1/tokens/revoke                  — Revoke a token by JTI (deny-list)
#   GET  /api/v1/tokens/public-key              — Ed25519 public key for independent verification
#   GET  /api/v1/tokens/policy/scopes           — List all policy-allowed permission scopes
app.include_router(tokens_router, prefix="/api/v1")

# ── Future module routers (uncomment when branches are merged into main) ──────
# app.include_router(did_router,       prefix="/api/v1")   # Member 3
# app.include_router(webauthn_router,  prefix="/api/v1")   # Member 2
# app.include_router(admin_router,     prefix="/api/v1")   # Member 6


# ─────────────────────────────────────────────────────────────────────────────
# Utility Endpoints (Member 1)
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    "/",
    summary="Service info & liveness",
    tags=["Health"],
    response_class=JSONResponse,
)
async def root() -> Dict[str, Any]:
    """Root endpoint — returns service metadata and currently active modules."""
    return {
        "service": "Decentralized Zero-Trust IdP Mesh",
        "version": "1.0.0",
        "status": "healthy",
        "docs": "/docs",
        "redoc": "/redoc",
        "api_prefix": "/api/v1",
        "active_modules": {
            "ledger": {
                "owner": "Member 4",
                "branch": "midhun",
                "prefix": "/api/v1/ledger",
                "endpoints": [
                    "GET  /api/v1/ledger",
                    "GET  /api/v1/ledger/verify",
                    "GET  /api/v1/ledger/history/{did}",
                    "GET  /api/v1/ledger/latest/{did}",
                    "POST /api/v1/ledger/anchor",
                    "POST /api/v1/ledger/simulate-tamper",
                ],
            },
            "tokens": {
                "owner": "Member 5",
                "branch": "member5",
                "prefix": "/api/v1/tokens",
                "endpoints": [
                    "POST /api/v1/tokens/issue",
                    "POST /api/v1/tokens/verify",
                    "POST /api/v1/tokens/revoke",
                    "GET  /api/v1/tokens/public-key",
                    "GET  /api/v1/tokens/policy/scopes",
                ],
            },
        },
        "pending_modules": {
            "webauthn": {"owner": "Member 2", "prefix": "/api/v1/webauthn"},
            "did":      {"owner": "Member 3", "prefix": "/api/v1/did"},
            "admin":    {"owner": "Member 6", "prefix": "/api/v1/admin"},
        },
    }


@app.get(
    "/health",
    summary="Liveness probe",
    tags=["Health"],
    response_class=JSONResponse,
)
async def health_check() -> Dict[str, str]:
    """Lightweight liveness probe for load-balancers and Docker health checks."""
    return {"status": "ok"}
