"""Decentralized Zero-Trust Identity Provider (IdP) Mesh — Central Application Entry Point.

Role: Member 6 (Dashboard, Integration Testing, Security Testing, Deployment, Documentation)
Mounts verified modules:
  - Module C (Member 4): Simulated Blockchain Ledger (/api/v1/ledger)
  - Module E (Member 5): JWT Access Tokens & Zero-Trust Policy Engine (/api/v1/tokens)

Configures CORS, static dashboard serving, health monitoring, and cross-module wiring.
"""

import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse

from app.modules.ledger import ledger_router
import app.modules.ledger.router as ledger_router_module
from app.modules.tokens import tokens_router, ZeroTrustPolicyEngine
import app.modules.tokens.router as tokens_router_module

# Wire shared ledger into token router policy engine so anchored DIDs are instantly verified
tokens_router_module._shared_ledger = ledger_router_module.ledger_instance
tokens_router_module._policy_engine = ZeroTrustPolicyEngine(
    ledger=ledger_router_module.ledger_instance
)

app = FastAPI(
    title="Decentralized Zero-Trust IdP Mesh",
    version="1.0.0",
    description=(
        "Decentralized Zero-Trust Identity Provider Mesh combining cryptographic "
        "append-only ledger anchoring, Ed25519 token issuance, and continuous policy evaluation."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)

# Cross-origin access is disabled by default. Same-origin dashboard use still
# works; development servers and deployments must list trusted origins explicitly.
def _cors_settings(allowed_origins_env: str | None) -> tuple[list[str], bool]:
    origins = [origin.strip() for origin in (allowed_origins_env or "").split(",") if origin.strip()]
    if "*" in origins:
        raise RuntimeError("ALLOWED_ORIGINS must contain explicit origins; wildcard origins are not allowed.")
    return origins, bool(origins)


origins, allow_credentials = _cors_settings(os.environ.get("ALLOWED_ORIGINS"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount verified API routers under /api/v1
app.include_router(ledger_router, prefix="/api/v1")
app.include_router(tokens_router, prefix="/api/v1")


@app.get("/", include_in_schema=False)
def root_redirect():
    """Redirect root path to interactive API documentation or dashboard."""
    return {
        "service": "Decentralized Zero-Trust IdP Mesh",
        "status": "operational",
        "api_docs": "/docs",
        "dashboard": "/dashboard/",
        "endpoints": {
            "ledger": "/api/v1/ledger",
            "ledger_verify": "/api/v1/ledger/verify",
            "token_issue": "/api/v1/tokens/issue",
            "token_verify": "/api/v1/tokens/verify",
            "token_revoke": "/api/v1/tokens/revoke",
            "public_key": "/api/v1/tokens/public-key",
            "health": "/api/v1/health",
        },
    }


@app.get("/health", tags=["System Health"])
@app.get("/api/v1/health", tags=["System Health"])
def system_health():
    """Composite healthcheck endpoint for orchestration, load balancers, and dashboard."""
    ledger = ledger_router_module.ledger_instance
    is_valid, error_msg = ledger.verify_integrity()
    records = ledger.get_all_records()
    head = records[-1] if records else None
    rev_backend = tokens_router_module._revocation_store.backend_type

    return {
        "status": "healthy" if is_valid else "degraded",
        "version": "1.0.0",
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
                "status": "healthy",
                "signing_algorithm": "EdDSA (Ed25519)",
                "revocation_store": rev_backend,
            },
            "auth_webauthn": {
                "status": "pending_module_integration",
                "owner": "Member 2",
            },
            "did_cryptography": {
                "status": "pending_module_integration",
                "owner": "Member 3",
            },
        },
    }


# Mount Frontend Dashboard static files if directory exists
frontend_dir = Path(__file__).resolve().parent.parent / "frontend" / "dashboard"
if frontend_dir.exists():
    app.mount("/dashboard", StaticFiles(directory=str(frontend_dir), html=True), name="dashboard")
