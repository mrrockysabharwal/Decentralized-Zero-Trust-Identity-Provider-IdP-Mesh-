"""
app/modules/admin/router.py — FastAPI Router for Admin Dashboard API (Module D)
================================================================================
Owner  : Member 6 (Admin Dashboard)
Branch : feature/admin-dashboard

Endpoints (all mounted under /api/v1/admin by Member 1's main.py):

  GET    /admin/dashboard                  — Aggregate stats for the home page
  GET    /admin/identities                 — List all DIDs with status + credential count
  GET    /admin/identities/{did}           — Full identity drill-down (ledger + credentials)
  GET    /admin/ledger                     — Full ledger view with integrity status
  GET    /admin/ledger/verify              — Cryptographic integrity audit (real-time)
  GET    /admin/credentials                — All WebAuthn credentials across all DIDs
  POST   /admin/tokens/{jti}/revoke        — Force-revoke any token by JTI
  GET    /admin/tokens/policy              — Active token policy (scopes, algorithm, TTL)
  POST   /admin/ledger/simulate-tamper     — Live tamper-detection demo for judges/instructors
  GET    /admin/health                     — Aggregate health of all subsystems

Integration for Member 1 (wire in app/main.py):

    from app.modules.admin import admin_router
    import app.modules.admin.router as _admin_router_module

    app.include_router(admin_router, prefix="/api/v1")

    # In _wire_shared_ledger():
    _admin_router_module._shared_ledger    = ledger_instance
    _admin_router_module._credential_store = _webauthn_router_module._credential_store
"""

from __future__ import annotations

import base64
import math
import logging
import os
import time
from typing import Any, Dict, List, Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, Path, status

from app.modules.admin.models import (
    CredentialAdminSummary,
    DashboardSummary,
    ForceRevokeRequest,
    ForceRevokeResponse,
    IdentityDetail,
    IdentitySummary,
    LedgerAdminView,
    SubsystemHealth,
    SystemHealthResponse,
    TokenPolicyInfo,
)
from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.models import LedgerOperation
from app.modules.tokens.models import (
    ALLOWED_SCOPES,
    DEFAULT_TOKEN_EXPIRY_SECONDS,
    MAX_TOKEN_LIFETIME_SECONDS,
    TOKEN_AUDIENCE,
    TOKEN_ISSUER,
)
from app.modules.tokens.revocation import (
    MAX_TTL_SECONDS,
    RevocationStoreError,
    TokenRevocationStore,
)
from app.modules.webauthn.credential_store import CredentialStore
from app.modules.admin.security import (
    MAX_ADMIN_TOKEN_LIFETIME_SECONDS,
    require_admin,
    require_tamper_demo_enabled,
)
from app.modules.ledger.simulation import isolated_ledger_copy
from app.modules.revocation_provider import get_revocation_store
from app.modules.tokens.jwt_engine import verify_token

logger = logging.getLogger("idp_mesh.admin.router")

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/admin", tags=["Admin Dashboard"], dependencies=[Depends(require_admin)]
)


def _finite_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False

# ---------------------------------------------------------------------------
# Module-level singletons — injected by Member 1's main.py at startup.
# Defaults are None so the module can be imported without a running server;
# routes that need them will raise a 503 if they are not wired.
# ---------------------------------------------------------------------------

_shared_ledger: Optional[SimulatedLedger] = None
_credential_store: Optional[CredentialStore] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_ledger() -> SimulatedLedger:
    if _shared_ledger is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin: shared ledger not wired. Contact Member 1 (Core Backend).",
        )
    return _shared_ledger


def _require_credential_store() -> CredentialStore:
    if _credential_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin: credential store not wired. Contact Member 1 (Core Backend).",
        )
    return _credential_store


def _require_revocation_store() -> TokenRevocationStore:
    return get_revocation_store()


def _did_status_from_operation(op: LedgerOperation) -> str:
    """Map the latest ledger operation to a human-readable DID status string."""
    if op in (LedgerOperation.CREATE, LedgerOperation.UPDATE):
        return "ACTIVE"
    if op == LedgerOperation.DEACTIVATE:
        return "DEACTIVATED"
    return "UNKNOWN"


def _unique_dids_from_ledger(ledger: SimulatedLedger) -> List[str]:
    """Return all unique DIDs that appear on the ledger, excluding the genesis DID."""
    genesis_did = "did:mesh:genesis"
    seen: Dict[str, None] = {}
    for rec in ledger.get_all_records():
        if rec.did != genesis_did:
            seen[rec.did] = None
    return list(seen.keys())


def _credential_to_dict(cred) -> Dict[str, Any]:  # type: ignore[no-untyped-def]
    """Serialize a StoredCredential dataclass to a JSON-safe dict."""
    return {
        "credential_id": cred.credential_id,
        "did": cred.did,
        "public_key_b64": base64.urlsafe_b64encode(cred.public_key_bytes).rstrip(b"=").decode(),
        "registered_at": cred.registered_at,
        "sign_count": cred.sign_count,
        "device_info": cred.device_info,
    }


def _get_ordinary_token_public_key() -> bytes:
    """Load the ordinary token public key only when verifying a target token."""
    from app.modules.tokens.router import get_public_key

    return get_public_key()


def _verified_target_expiration(target_token: str, expected_jti: str) -> float:
    """Verify an active ordinary/admin JWT and return its signed expiry.

    Target token claims are never decoded without signature and issuer/audience
    validation. The body/path JTI must match the signed JTI claim.
    """
    claims = None
    max_lifetime = MAX_TOKEN_LIFETIME_SECONDS

    try:
        claims = verify_token(target_token, _get_ordinary_token_public_key())
    except Exception:
        # Admin JWTs use a separate key and issuer/audience configuration.
        admin_public_key = os.environ.get("ADMIN_JWT_PUBLIC_KEY", "").replace("\\n", "\n")
        if not admin_public_key:
            raise ValueError("Target token could not be verified.") from None
        try:
            claims = jwt.decode(
                target_token,
                admin_public_key,
                algorithms=["EdDSA"],
                audience="idp-mesh-admin",
                issuer="idp-mesh-admin",
                options={"require": ["sub", "jti", "iat", "exp", "iss", "aud", "scope"]},
            )
        except Exception:
            raise ValueError("Target token could not be verified.") from None
        max_lifetime = MAX_ADMIN_TOKEN_LIFETIME_SECONDS

    target_jti = claims.get("jti")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        not isinstance(target_jti, str)
        or not target_jti
        or len(target_jti) > 256
        or not target_jti.isprintable()
        or target_jti != target_jti.strip()
        or target_jti != expected_jti
        or not _finite_number(issued_at)
        or not _finite_number(expires_at)
        or expires_at <= issued_at
        or expires_at - issued_at > max_lifetime
        or expires_at <= time.time()
    ):
        raise ValueError("Target token is expired or has invalid claims.")
    return float(expires_at)


def _remaining_revocation_ttl(expires_at: float, now: Optional[float] = None) -> int:
    """Round up to whole seconds so storage does not expire before the JWT."""
    current_time = time.time() if now is None else now
    if not _finite_number(expires_at) or expires_at <= current_time:
        raise ValueError("Expired target tokens cannot be revoked.")
    ttl_seconds = math.ceil(expires_at - current_time)
    if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError("Target token lifetime exceeds revocation storage policy.")
    return ttl_seconds


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/dashboard",
    response_model=DashboardSummary,
    summary="Admin dashboard — aggregate system statistics",
    description=(
        "Returns a high-level summary of the entire IdP Mesh system: "
        "total DIDs, ledger integrity status, WebAuthn credential count, "
        "and per-subsystem health indicators. Intended for the Admin Dashboard home page."
    ),
)
def get_dashboard_summary() -> DashboardSummary:
    """Aggregate live statistics across Modules A, B, C, and E."""
    ledger = _require_ledger()
    cred_store = _require_credential_store()
    rev_store = _require_revocation_store()

    all_records = ledger.get_all_records()
    unique_dids = _unique_dids_from_ledger(ledger)

    active_count = 0
    deactivated_count = 0
    for did in unique_dids:
        latest = ledger.get_latest_record(did)
        if latest:
            op_status = _did_status_from_operation(latest.operation)
            if op_status == "ACTIVE":
                active_count += 1
            elif op_status == "DEACTIVATED":
                deactivated_count += 1

    is_valid, integrity_error = ledger.verify_integrity()
    head = ledger.get_head()
    total_creds = cred_store.total_count()
    durability = rev_store.assess_durability()
    durability_verified = durability.durability_status == "configuration_verified"

    subsystems: List[SubsystemHealth] = [
        SubsystemHealth(
            name="ledger",
            status="healthy" if is_valid else "degraded",
            detail=integrity_error or "Chain integrity verified",
        ),
        SubsystemHealth(
            name="tokens",
            status="healthy" if durability_verified else "degraded",
            detail=(
                f"Redis {'available' if durability.redis_available else 'unavailable'}; "
                f"persistence {durability.persistence_status}; "
                f"eviction {durability.eviction_status}; "
                f"durability {durability.durability_status}"
            ),
        ),
        SubsystemHealth(
            name="webauthn",
            status="healthy",
            detail=f"{total_creds} credential(s) registered",
        ),
        SubsystemHealth(
            name="did_registry",
            status="healthy",
            detail=f"{len(unique_dids)} DID(s) registered",
        ),
    ]

    return DashboardSummary(
        total_dids=len(unique_dids),
        active_dids=active_count,
        deactivated_dids=deactivated_count,
        total_ledger_records=len(all_records),
        ledger_integrity=is_valid,
        ledger_head_hash=head.record_hash if head else None,
        total_credentials=total_creds,
        revocation_backend=rev_store.backend_type,
        subsystems=subsystems,
    )


@router.get(
    "/identities",
    response_model=List[IdentitySummary],
    summary="List all registered identities",
    description=(
        "Returns a summary row for every DID registered on the ledger. "
        "Each row includes the DID status (ACTIVE/DEACTIVATED), most recent ledger "
        "operation, and number of bound WebAuthn credentials."
    ),
)
def list_identities() -> List[IdentitySummary]:
    """Aggregate identity records from the ledger and credential store."""
    ledger = _require_ledger()
    cred_store = _require_credential_store()

    unique_dids = _unique_dids_from_ledger(ledger)
    result: List[IdentitySummary] = []

    for did in unique_dids:
        did_records = ledger.get_records_by_did(did)
        latest = did_records[-1] if did_records else None

        result.append(
            IdentitySummary(
                did=did,
                status=_did_status_from_operation(latest.operation) if latest else "UNKNOWN",
                latest_operation=latest.operation.value if latest else "UNKNOWN",
                ledger_record_index=latest.index if latest else -1,
                latest_ledger_timestamp=latest.timestamp if latest else "",
                total_ledger_records=len(did_records),
                credential_count=len(cred_store.list_credentials_for_did(did)),
            )
        )

    return result


@router.get(
    "/identities/{did:path}",
    response_model=IdentityDetail,
    summary="Full identity drill-down",
    description=(
        "Returns the complete identity profile for a single DID: "
        "full ledger history, all bound WebAuthn credentials, and current status."
    ),
)
def get_identity_detail(did: str) -> IdentityDetail:
    """Return the full ledger history and credentials for a specific DID."""
    ledger = _require_ledger()
    cred_store = _require_credential_store()

    did_records = ledger.get_records_by_did(did)
    if not did_records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DID '{did}' has no ledger records. It may not be registered.",
        )

    latest = did_records[-1]
    credentials = cred_store.list_credentials_for_did(did)

    return IdentityDetail(
        did=did,
        status=_did_status_from_operation(latest.operation),
        latest_operation=latest.operation.value,
        ledger_history=[rec.model_dump() for rec in did_records],
        credentials=[_credential_to_dict(c) for c in credentials],
        credential_count=len(credentials),
    )


@router.get(
    "/ledger",
    response_model=LedgerAdminView,
    summary="Full ledger block viewer",
    description=(
        "Returns all ledger records with a real-time integrity audit result. "
        "Suitable for the Admin Dashboard ledger viewer table."
    ),
)
def get_ledger_view() -> LedgerAdminView:
    """Return every ledger block plus live integrity status."""
    ledger = _require_ledger()

    all_records = ledger.get_all_records()
    is_valid, error = ledger.verify_integrity()
    head = ledger.get_head()

    return LedgerAdminView(
        total_records=len(all_records),
        integrity_valid=is_valid,
        integrity_error=error,
        head_hash=head.record_hash if head else None,
        records=[rec.model_dump() for rec in all_records],
    )


@router.get(
    "/ledger/verify",
    response_model=LedgerAdminView,
    summary="Real-time ledger integrity audit",
    description=(
        "Runs the full cryptographic audit (hash-linkage verification) over the "
        "entire ledger chain and returns the result immediately. "
        "Use this endpoint to drive a live integrity badge in the Admin Dashboard."
    ),
)
def verify_ledger_integrity() -> LedgerAdminView:
    """Run and return a real-time cryptographic integrity audit."""
    ledger = _require_ledger()

    all_records = ledger.get_all_records()
    is_valid, error = ledger.verify_integrity()
    head = ledger.get_head()

    logger.info(
        "Admin ledger audit: valid=%s records=%d head=%s",
        is_valid,
        len(all_records),
        head.record_hash[:16] + "..." if head else "none",
    )

    return LedgerAdminView(
        total_records=len(all_records),
        integrity_valid=is_valid,
        integrity_error=error,
        head_hash=head.record_hash if head else None,
        records=[rec.model_dump() for rec in all_records],
    )


@router.get(
    "/credentials",
    response_model=CredentialAdminSummary,
    summary="All registered WebAuthn credentials",
    description=(
        "Returns every WebAuthn credential registered across all DIDs. "
        "Includes credential ID, DID binding, sign_count (for cloning detection), "
        "and registration timestamp."
    ),
)
def list_all_credentials() -> CredentialAdminSummary:
    """Aggregate all credentials from the credential store."""
    ledger = _require_ledger()
    cred_store = _require_credential_store()

    unique_dids = _unique_dids_from_ledger(ledger)
    all_creds: List[Dict[str, Any]] = []

    for did in unique_dids:
        creds = cred_store.list_credentials_for_did(did)
        all_creds.extend(_credential_to_dict(c) for c in creds)

    return CredentialAdminSummary(
        total_credentials=len(all_creds),
        credentials=all_creds,
    )


@router.post(
    "/tokens/{jti}/revoke",
    response_model=ForceRevokeResponse,
    status_code=status.HTTP_200_OK,
    summary="Admin force-revoke a verified token by JTI",
    description=(
        "Verifies the signed target token and stores its JTI until its expiration. "
        "The token will be rejected on any subsequent `/tokens/verify` call. "
        "Use this for emergency revocation (e.g. compromised credential, admin lockout)."
    ),
)
def force_revoke_token(
    payload: ForceRevokeRequest,
    jti: str = Path(description="JWT ID (jti claim) to force-revoke"),
) -> ForceRevokeResponse:
    """Revoke a verified active JWT for its full remaining lifetime."""
    rev_store = _require_revocation_store()
    try:
        rev_store.require_durable()
    except RevocationStoreError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Durable token revocation storage is unavailable.",
        ) from None

    if payload.jti != jti:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request JTI does not match the target path.",
        )
    try:
        expires_at = _verified_target_expiration(payload.target_token, jti)
        ttl_seconds = _remaining_revocation_ttl(expires_at)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from None

    reason = payload.reason or "Admin force-revocation"
    try:
        rev_store.revoke(jti=jti, ttl_seconds=ttl_seconds)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from None
    except RevocationStoreError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Token revocation storage is unavailable.",
        ) from None

    logger.warning("ADMIN REVOCATION: jti=%s reason=%s", jti, reason)

    return ForceRevokeResponse(
        revoked=True,
        jti=jti,
        reason=reason,
        message=(
            f"Token (jti={jti}) has been force-revoked and added to the deny-list. "
            f"Reason: {reason}"
        ),
    )


@router.get(
    "/tokens/policy",
    response_model=TokenPolicyInfo,
    summary="Active token policy configuration",
    description=(
        "Returns the current Zero-Trust token policy: allowed scopes, issuer/audience "
        "identifiers, token lifetime, and active revocation backend. "
        "Useful for the Admin Dashboard policy settings panel."
    ),
)
def get_token_policy_info() -> TokenPolicyInfo:
    """Return the active token policy configuration."""
    rev_store = _require_revocation_store()

    return TokenPolicyInfo(
        allowed_scopes=ALLOWED_SCOPES,
        token_issuer=TOKEN_ISSUER,
        token_audience=TOKEN_AUDIENCE,
        default_expiry_seconds=DEFAULT_TOKEN_EXPIRY_SECONDS,
        revocation_backend=rev_store.backend_type,
        signing_algorithm="EdDSA",
    )


@router.post(
    "/ledger/simulate-tamper",
    response_model=LedgerAdminView,
    summary="Simulate a ledger tamper attack (Demo/Audit only)",
    description=(
        "Mutates a specified field in a ledger block to simulate a malicious tampering attack. "
        "Immediately returns the post-tamper integrity audit result, demonstrating how "
        "the hash-linked chain detects the modification. "
        "**⚠️ For demonstration and security audits only — modifies live in-memory state.**"
    ),
)
def simulate_ledger_tamper(
    index: int,
    field: str,
    new_value: str,
    recalculate_record_hash: bool = False,
) -> LedgerAdminView:
    """Tamper with an isolated snapshot and return its integrity audit result."""
    require_tamper_demo_enabled()
    ledger = _require_ledger()
    simulation = isolated_ledger_copy(ledger)

    try:
        simulation.tamper_record(
            index=index,
            field=field,
            new_value=new_value,
            recalculate_record_hash=recalculate_record_hash,
        )
    except IndexError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tamper simulation failed: {exc}",
        )

    all_records = simulation.get_all_records()
    is_valid, error = simulation.verify_integrity()
    head = simulation.get_head()

    logger.warning(
        "Admin tamper-demo isolated snapshot: modified record #%d field='%s'. "
        "Integrity post-tamper: valid=%s error=%s",
        index,
        field,
        is_valid,
        error,
    )

    return LedgerAdminView(
        total_records=len(all_records),
        integrity_valid=is_valid,
        integrity_error=error,
        head_hash=head.record_hash if head else None,
        records=[rec.model_dump() for rec in all_records],
    )


@router.get(
    "/health",
    response_model=SystemHealthResponse,
    summary="Aggregate system health check",
    description=(
        "Returns the health status of every subsystem: "
        "ledger integrity, DID registry size, credential count, and revocation backend. "
        "Suitable for the Admin Dashboard health status badge."
    ),
)
def get_system_health() -> SystemHealthResponse:
    """Return aggregate system health across all IdP Mesh subsystems."""
    ledger = _require_ledger()
    cred_store = _require_credential_store()
    rev_store = _require_revocation_store()

    all_records = ledger.get_all_records()
    unique_dids = _unique_dids_from_ledger(ledger)
    is_valid, integrity_error = ledger.verify_integrity()
    total_creds = cred_store.total_count()
    durability = rev_store.assess_durability()
    durability_verified = durability.durability_status == "configuration_verified"

    subsystems: List[SubsystemHealth] = [
        SubsystemHealth(
            name="ledger",
            status="healthy" if is_valid else "degraded",
            detail=integrity_error or f"{len(all_records)} record(s) — chain intact",
        ),
        SubsystemHealth(
            name="did_registry",
            status="healthy",
            detail=f"{len(unique_dids)} DID(s) registered",
        ),
        SubsystemHealth(
            name="webauthn",
            status="healthy",
            detail=f"{total_creds} credential(s) across {len(unique_dids)} DID(s)",
        ),
        SubsystemHealth(
            name="tokens",
            status="healthy" if durability_verified else "degraded",
            detail=(
                f"Redis {'available' if durability.redis_available else 'unavailable'}; "
                f"persistence {durability.persistence_status}; "
                f"eviction {durability.eviction_status}; "
                f"durability {durability.durability_status}"
            ),
        ),
    ]

    overall = "healthy" if is_valid and durability_verified else "degraded"

    return SystemHealthResponse(
        overall_status=overall,
        ledger_integrity=is_valid,
        ledger_records=len(all_records),
        total_dids=len(unique_dids),
        total_credentials=total_creds,
        revocation_backend=rev_store.backend_type,
        revocation_redis_available=durability.redis_available,
        revocation_persistence=durability.persistence_status,
        revocation_eviction=durability.eviction_status,
        revocation_durability=durability.durability_status,
        subsystems=subsystems,
    )
