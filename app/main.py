"""Decentralized Zero-Trust Identity Provider (IdP) Mesh — Central Application Entry Point.

Combines all 5 verified modules:
  - Module A (Member 3): DID Registry & Cryptography (/api/v1/did)
  - Module B (Member 2): WebAuthn / FIDO2 Passwordless Auth (/api/v1/webauthn)
  - Module C (Member 4): Simulated Blockchain Ledger (/api/v1/ledger)
  - Module D (Member 6): Admin Dashboard API (/api/v1/admin)
  - Module E (Member 5): JWT Access Tokens & Zero-Trust Policy Engine (/api/v1/tokens)

Configures CORS, static dashboard serving, health monitoring, and cross-module wiring.
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

# ── Load .env before any env-var reads ───────────────────────────────────────
load_dotenv()

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("idp_mesh.main")

# ── Module C (Member 4) — Simulated Blockchain Ledger ────────────────────────
from app.modules.ledger import (
    SimulatedLedger,
    ledger_router,
)
from app.modules.ledger.router import ledger_instance
import app.modules.ledger.router as ledger_router_module

# ── Module E (Member 5) — JWT Tokens & Zero-Trust Policy Engine ──────────────
from app.modules.tokens import tokens_router, ZeroTrustPolicyEngine
import app.modules.tokens.router as _tokens_router_module

# ── Module B (Member 2) — WebAuthn / FIDO2 Biometric Auth ───────────────────
from app.modules.webauthn import webauthn_router
import app.modules.webauthn.router as _webauthn_router_module

# ── Module A (Member 3) — DID Registry & Cryptography ───────────────────────
from app.modules.did import did_router
import app.modules.did.router as _did_router_module
from app.modules.identity.did_service import DIDService

# ── Module D (Member 6) — Admin Dashboard API ────────────────────────────────
from app.modules.admin import admin_router
import app.modules.admin.router as _admin_router_module
from app.modules.revocation_provider import get_revocation_store


def _cors_settings(allowed_origins_env: str | None) -> tuple[list[str], bool]:
    """Parse and validate CORS origins from environment."""
    if not allowed_origins_env:
        return [], False
    origins = [origin.strip() for origin in allowed_origins_env.split(",") if origin.strip()]
    if "*" in origins:
        raise RuntimeError("ALLOWED_ORIGINS must contain explicit origins; wildcard origins are not allowed.")
    return origins, bool(origins)


# ── Shared ledger injection ────────────────────────────────────────────────────
def _wire_shared_ledger() -> None:
    """Replace each module router's internal ledger with Member 4's shared ledger.

    This ensures that any DID anchored through Module C (Ledger) endpoints is
    immediately visible to Module E's ZeroTrustPolicyEngine when issuing tokens.
    Also wires Module A (DID Registry), Module B (WebAuthn) and Module D (Admin)
    so all registrations, credentials, and audits share the same state.
    """
    # Wire Module E — pass credential_store so Check 5 (WebAuthn gate) is active
    _tokens_router_module._shared_ledger = ledger_instance
    _tokens_router_module._policy_engine = ZeroTrustPolicyEngine(
        ledger=ledger_instance,
        credential_store=_webauthn_router_module._credential_store,
    )

    # Wire Module B — re-create WebAuthnService with the shared ledger
    from app.modules.webauthn.webauthn_service import WebAuthnService

    _webauthn_router_module._shared_ledger = ledger_instance
    _webauthn_router_module._webauthn_service = WebAuthnService(
        challenge_store=_webauthn_router_module._challenge_store,
        credential_store=_webauthn_router_module._credential_store,
        ledger=ledger_instance,
    )

    # Wire Module A — DID Registry uses the same shared ledger for anchoring
    _did_router_module._shared_ledger = ledger_instance

    # Wire Module D — Admin Dashboard gets the shared ledger + credential + revocation stores
    _admin_router_module._shared_ledger = ledger_instance
    _admin_router_module._credential_store = _webauthn_router_module._credential_store


# Execute initial wiring for direct imports and synchronous test harnesses
_wire_shared_ledger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle handler."""
    _wire_shared_ledger()
    try:
        init_passkey_db()
    except Exception as exc:
        logger.warning("Passkey DB init warning: %s", exc)
    logger.info("=" * 65)
    logger.info("  Decentralized Zero-Trust IdP Mesh — starting up")
    logger.info("  API base    : http://localhost:8000/api/v1")
    logger.info("  Active modules: DID, WebAuthn, Ledger, Tokens, Admin, Portal, OIDC")
    logger.info("=" * 65)
    yield
    logger.info("  Decentralized Zero-Trust IdP Mesh — shutting down")


app = FastAPI(
    title="Decentralized Zero-Trust IdP Mesh",
    version="1.0.0",
    description=(
        "Decentralized Zero-Trust Identity Provider Mesh combining cryptographic "
        "append-only ledger anchoring, Ed25519 token issuance, WebAuthn passwordless authentication, "
        "and continuous zero-trust policy evaluation."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS Middleware ───────────────────────────────────────────────────────────
configured_origins_env = os.environ.get("ALLOWED_ORIGINS") or os.environ.get("CORS_ORIGINS")
origins, allow_credentials = _cors_settings(configured_origins_env)

# Always allow local development origins by default if explicitly configured or locally running
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins else ["http://localhost:3000", "http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True if not origins else allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Mount Verified Module Routers under /api/v1 ───────────────────────────────
app.include_router(did_router, prefix="/api/v1")
app.include_router(webauthn_router, prefix="/api/v1")
app.include_router(ledger_router, prefix="/api/v1")
app.include_router(tokens_router, prefix="/api/v1")
app.include_router(admin_router, prefix="/api/v1")

# ── Mount Passkey WebAuthn & OIDC Routers (Shad) ──────────────────────────────
from backend.main import passkey_router, init_db as init_passkey_db
from backend.oidc.router import router as oidc_router

app.include_router(passkey_router)
app.include_router(oidc_router)


@app.get("/", summary="Service metadata and links", tags=["Health"], response_class=JSONResponse)
def root():
    """Root endpoint — returns service metadata, links to docs, dashboard, and modules."""
    return {
        "service": "Decentralized Zero-Trust IdP Mesh",
        "status": "operational",
        "version": "1.0.0",
        "api_docs": "/docs",
        "docs": "/docs",
        "redoc": "/redoc",
        "portal": "/portal/index.html",
        "login": "/login.html",
        "dashboard": "/dashboard/",
        "endpoints": {
            "ledger": "/api/v1/ledger",
            "ledger_verify": "/api/v1/ledger/verify",
            "token_issue": "/api/v1/tokens/issue",
            "token_verify": "/api/v1/tokens/verify",
            "token_revoke": "/api/v1/tokens/revoke",
            "public_key": "/api/v1/tokens/public-key",
            "did": "/api/v1/did",
            "webauthn": "/api/v1/webauthn",
            "admin": "/api/v1/admin",
            "oidc": "/oidc/.well-known/openid-configuration",
            "health": "/api/v1/health",
        },
        "active_modules": {
            "did": {"owner": "Member 3", "prefix": "/api/v1/did"},
            "webauthn": {"owner": "Member 2", "prefix": "/api/v1/webauthn"},
            "ledger": {"owner": "Member 4", "prefix": "/api/v1/ledger"},
            "tokens": {"owner": "Member 5", "prefix": "/api/v1/tokens"},
            "admin": {"owner": "Member 6", "prefix": "/api/v1/admin"},
            "portal": {"owner": "Shad", "prefix": "/portal"},
            "oidc": {"owner": "Shad", "prefix": "/oidc"},
        },
    }


@app.get("/health", summary="Composite healthcheck", tags=["System Health"])
@app.get("/api/v1/health", summary="Composite healthcheck alias", tags=["System Health"])
def system_health():
    """Composite healthcheck endpoint for load balancers, dashboard, and orchestration."""
    ledger = ledger_router_module.ledger_instance
    is_valid, error_msg = ledger.verify_integrity()
    records = ledger.get_all_records()
    head = records[-1] if records else None
    revocation_store = get_revocation_store()
    revocation_assessment = revocation_store.assess_durability()
    revocation_verified = (
        revocation_assessment.durability_status == "configuration_verified"
    )

    return {
        "status": "healthy" if is_valid and revocation_verified else "degraded",
        "version": "1.0.0",
        "revocation": {
            "backend": revocation_store.backend_type,
            "redis_available": revocation_assessment.redis_available,
            "persistence": revocation_assessment.persistence_status,
            "eviction": revocation_assessment.eviction_status,
            "durability": revocation_assessment.durability_status,
        },
        "subsystems": {
            "ledger": {
                "status": "healthy" if is_valid else "compromised",
                "blocks": len(records),
                "head_hash": head.record_hash if head else None,
                "audit": {
                    "valid": is_valid,
                    "error": error_msg,
                    "total_records": len(records),
                    "head_hash": head.record_hash if head else None,
                },
            },
            "tokens_and_policy": {
                "status": "healthy" if revocation_verified else "degraded",
                "signing_algorithm": "EdDSA (Ed25519)",
                "revocation_store": revocation_store.backend_type,
                "revocation_redis_available": revocation_assessment.redis_available,
                "revocation_persistence": revocation_assessment.persistence_status,
                "revocation_eviction": revocation_assessment.eviction_status,
                "revocation_durability": revocation_assessment.durability_status,
            },
            "auth_webauthn": {
                "status": "healthy",
                "owner": "Member 2",
                "registered_credentials": _webauthn_router_module._credential_store.total_count(),
            },
            "did_cryptography": {
                "status": "healthy",
                "owner": "Member 3",
                "registered_dids": len(DIDService.list_dids()),
            },
            "admin_dashboard": {
                "status": "healthy",
                "owner": "Member 6",
            },
            "oidc": {
                "status": "healthy",
                "owner": "Shad",
            },
        },
    }


# ── Mount Frontend Directories ────────────────────────────────────────────────
root_frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
dashboard_dir = root_frontend_dir / "dashboard"

if dashboard_dir.exists():
    app.mount("/dashboard", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")

if root_frontend_dir.exists():
    app.mount("/portal", StaticFiles(directory=str(root_frontend_dir), html=True), name="portal")


# ── User Portal Direct Routes ────────────────────────────────────────────────
from fastapi.responses import FileResponse

@app.get("/login", include_in_schema=False)
@app.get("/login.html", include_in_schema=False)
def login_page():
    login_path = root_frontend_dir / "login.html"
    if login_path.is_file():
        return FileResponse(login_path)
    raise HTTPException(status_code=404, detail="login.html not found")


@app.get("/login.css", include_in_schema=False)
def login_stylesheet():
    css_path = root_frontend_dir / "login.css"
    if css_path.is_file():
        return FileResponse(css_path, media_type="text/css")
    raise HTTPException(status_code=404, detail="login.css not found")


@app.get("/style.css", include_in_schema=False)
def landing_stylesheet():
    css_path = root_frontend_dir / "style.css"
    if css_path.is_file():
        return FileResponse(css_path, media_type="text/css")
    raise HTTPException(status_code=404, detail="style.css not found")


@app.get("/webauthn.js", include_in_schema=False)
def passkey_script():
    js_path = root_frontend_dir / "webauthn.js"
    if js_path.is_file():
        return FileResponse(js_path, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="webauthn.js not found")
