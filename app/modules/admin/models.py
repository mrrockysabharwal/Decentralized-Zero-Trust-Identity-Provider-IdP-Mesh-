"""
app/modules/admin/models.py — Pydantic request/response schemas for Module D
=============================================================================
Owner  : Member 6 (Admin Dashboard)

All response models used by the Admin Dashboard API router.
The admin module is read-only — it aggregates live state from Modules A, B, C, and E.
No new persistent data is stored here.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Dashboard Summary
# ---------------------------------------------------------------------------


class SubsystemHealth(BaseModel):
    """Health status of a single subsystem."""

    name: str = Field(description="Module name (e.g. 'ledger', 'tokens')")
    status: str = Field(description="'healthy' | 'degraded' | 'unknown'")
    detail: Optional[str] = Field(default=None, description="Optional diagnostic detail")


class DashboardSummary(BaseModel):
    """Aggregate statistics summary for the Admin Dashboard home page."""

    total_dids: int = Field(description="Total number of registered DIDs (excluding genesis)")
    active_dids: int = Field(description="DIDs whose latest ledger operation is CREATE or UPDATE")
    deactivated_dids: int = Field(description="DIDs whose latest ledger operation is DEACTIVATE")
    total_ledger_records: int = Field(description="Total records on the ledger (including genesis)")
    ledger_integrity: bool = Field(description="True if ledger cryptographic audit passes")
    ledger_head_hash: Optional[str] = Field(default=None, description="Hash of the most recent ledger block")
    total_credentials: int = Field(description="Total WebAuthn credentials registered across all DIDs")
    revocation_backend: str = Field(description="Active revocation store backend: 'redis' or 'in-memory'")
    security_events_total: int = 0
    authentication_attempts: int = 0
    authentication_successes: int = 0
    authentication_failures: int = 0
    access_allowed: int = 0
    access_denied: int = 0
    tokens_revoked: int = 0
    subsystems: List[SubsystemHealth] = Field(
        default_factory=list,
        description="Per-subsystem health indicators",
    )


# ---------------------------------------------------------------------------
# Identity Admin
# ---------------------------------------------------------------------------


class IdentitySummary(BaseModel):
    """Condensed identity record for the Admin identities list view."""

    did: str = Field(description="Decentralized Identifier")
    status: str = Field(description="'ACTIVE' | 'DEACTIVATED' | 'UNKNOWN'")
    latest_operation: str = Field(description="Most recent ledger operation for this DID")
    ledger_record_index: int = Field(description="Index of the most recent ledger record")
    latest_ledger_timestamp: str = Field(description="ISO 8601 UTC timestamp of latest ledger anchor")
    total_ledger_records: int = Field(description="Number of ledger blocks for this DID")
    credential_count: int = Field(description="Number of registered WebAuthn credentials")


class IdentityDetail(BaseModel):
    """Full identity detail for the Admin identity drill-down view."""

    did: str = Field(description="Decentralized Identifier")
    status: str = Field(description="'ACTIVE' | 'DEACTIVATED' | 'UNKNOWN'")
    latest_operation: str = Field(description="Most recent ledger operation")
    ledger_history: List[Dict[str, Any]] = Field(description="Chronological ledger records for this DID")
    credentials: List[Dict[str, Any]] = Field(description="WebAuthn credentials bound to this DID")
    credential_count: int = Field(description="Total number of WebAuthn credentials")


# ---------------------------------------------------------------------------
# Ledger Admin
# ---------------------------------------------------------------------------


class LedgerAdminView(BaseModel):
    """Full ledger view with integrity status for the Admin Dashboard."""

    total_records: int = Field(description="Total number of records on the ledger")
    integrity_valid: bool = Field(description="True if cryptographic audit passes")
    integrity_error: Optional[str] = Field(default=None, description="Error details if integrity check fails")
    head_hash: Optional[str] = Field(default=None, description="Hash of the most recent ledger block")
    records: List[Dict[str, Any]] = Field(description="All ledger records in chronological order")


# ---------------------------------------------------------------------------
# Credentials Admin
# ---------------------------------------------------------------------------


class CredentialAdminSummary(BaseModel):
    """Summary of all WebAuthn credentials across all DIDs."""

    total_credentials: int = Field(description="Total number of registered WebAuthn credentials")
    credentials: List[Dict[str, Any]] = Field(
        description="List of credential records with DID binding, sign_count, registered_at"
    )


# ---------------------------------------------------------------------------
# Token Admin
# ---------------------------------------------------------------------------


class ForceRevokeRequest(BaseModel):
    """Request body for admin force-revocation of a token by JTI."""

    jti: str = Field(min_length=1, description="JWT ID (jti claim) of the token to force-revoke")
    reason: Optional[str] = Field(
        default="Admin force-revocation",
        description="Reason for administrative revocation (recorded in logs)",
    )


class ForceRevokeResponse(BaseModel):
    """Response after a successful admin force-revocation."""

    revoked: bool = Field(description="True if the JTI was added to the deny-list")
    jti: str = Field(description="The JTI that was revoked")
    reason: str = Field(description="Reason recorded for this revocation")
    message: str = Field(description="Human-readable confirmation")


class TokenPolicyInfo(BaseModel):
    """Active token policy information for the Admin Dashboard."""

    allowed_scopes: List[str] = Field(description="List of policy-permitted scope strings")
    token_issuer: str = Field(description="JWT issuer identifier")
    token_audience: str = Field(description="JWT audience identifier")
    default_expiry_seconds: int = Field(description="Default token lifetime in seconds")
    revocation_backend: str = Field(description="Active JTI revocation backend type")
    signing_algorithm: str = Field(description="JWT signing algorithm (always 'EdDSA')")


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class SystemHealthResponse(BaseModel):
    """Aggregate system health across all subsystems."""

    overall_status: str = Field(description="'healthy' | 'degraded' | 'critical'")
    ledger_integrity: bool = Field(description="Ledger cryptographic audit result")
    ledger_records: int = Field(description="Number of blocks on the ledger")
    total_dids: int = Field(description="Total registered DIDs")
    total_credentials: int = Field(description="Total WebAuthn credentials")
    revocation_backend: str = Field(description="Active revocation backend")
    subsystems: List[SubsystemHealth] = Field(description="Per-module health breakdown")


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    outcome: str
    severity: str
    did_ref: Optional[str] = None
    reason: str
    correlation_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityEventPage(BaseModel):
    total: int
    page: int
    page_size: int
    events: List[SecurityEvent]
