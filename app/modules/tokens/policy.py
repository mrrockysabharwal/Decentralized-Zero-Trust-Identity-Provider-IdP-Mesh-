"""Zero-Trust Policy Engine for JWT token issuance authorization.

Implements a multi-layered Zero-Trust evaluation model: every token request
is evaluated against the live ledger state before a token is issued.

Evaluation order (fail-fast — first failing check blocks issuance):
  1. DID must have at least one record on the ledger (is registered).
  2. The DID's most recent operation must NOT be DEACTIVATE.
  3. The overall ledger must pass cryptographic integrity verification.
  4. All requested scopes must appear in the configured ALLOWED_SCOPES list.

Design principles:
  - Stateless evaluation: the engine reads from the ledger on every call.
  - No caching of DID states — Zero-Trust means we always verify freshly.
  - All deny reasons are human-readable strings for audit logs and API responses.
"""

import logging
from typing import List

from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.models import LedgerOperation
from app.modules.tokens.models import ALLOWED_SCOPES, PolicyCheckResult

logger = logging.getLogger(__name__)


class ZeroTrustPolicyEngine:
    """Evaluates whether a DID is permitted to receive a JWT access token.

    Args:
        ledger: The shared ``SimulatedLedger`` instance used to verify DID
                registrations and the overall chain integrity.
        allowed_scopes: Overrideable list of permitted scope strings.
                        Defaults to ``ALLOWED_SCOPES`` from models.py.

    Example::

        engine = ZeroTrustPolicyEngine(ledger=my_ledger)
        result = engine.evaluate(did="did:mesh:key:z6Mku...", requested_scope=["read:profile"])
        if not result.allowed:
            raise PermissionError(result.reason)
    """

    def __init__(
        self,
        ledger: SimulatedLedger,
        allowed_scopes: List[str] = ALLOWED_SCOPES,
    ) -> None:
        self._ledger = ledger
        self._allowed_scopes = list(allowed_scopes)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        did: str,
        requested_scope: List[str],
        context: dict = {},  # noqa: B006  (intentionally mutable for extensibility)
    ) -> PolicyCheckResult:
        """Run all Zero-Trust policy checks for the given DID and scope.

        Args:
            did: The DID requesting a token.
            requested_scope: List of permission scopes the caller wants.
            context: Optional dict for future context-aware rules (e.g. IP,
                     user-agent, time-of-day). Currently unused.

        Returns:
            ``PolicyCheckResult`` with ``allowed=True`` if all checks pass,
            or ``allowed=False`` with a descriptive ``reason`` if any check fails.
        """
        logger.debug("PolicyEngine: evaluating DID=%s scope=%s", did, requested_scope)

        # ----------------------------------------------------------
        # Check 1: DID must be registered on the ledger
        # ----------------------------------------------------------
        all_did_records = self._ledger.get_records_by_did(did)
        if not all_did_records:
            return PolicyCheckResult(
                allowed=False,
                reason=f"DID '{did}' is not registered on the ledger. Token issuance denied.",
                did=did,
                checked_scope=requested_scope,
            )

        # ----------------------------------------------------------
        # Check 2: DID must not be deactivated
        # ----------------------------------------------------------
        latest_record = self._ledger.get_latest_record(did)
        if latest_record and latest_record.operation == LedgerOperation.DEACTIVATE:
            return PolicyCheckResult(
                allowed=False,
                reason=(
                    f"DID '{did}' has been deactivated (ledger record #{latest_record.index}). "
                    "Token issuance denied for deactivated identities."
                ),
                did=did,
                checked_scope=requested_scope,
            )

        # ----------------------------------------------------------
        # Check 3: Ledger must pass cryptographic integrity verification
        # ----------------------------------------------------------
        is_valid, integrity_error = self._ledger.verify_integrity()
        if not is_valid:
            logger.error("PolicyEngine: ledger integrity failure — %s", integrity_error)
            return PolicyCheckResult(
                allowed=False,
                reason=(
                    f"Ledger cryptographic integrity check failed: {integrity_error}. "
                    "Token issuance halted until ledger integrity is restored."
                ),
                did=did,
                checked_scope=requested_scope,
            )

        # ----------------------------------------------------------
        # Check 4: All requested scopes must be in the allowed list
        # ----------------------------------------------------------
        invalid_scopes = [s for s in requested_scope if s not in self._allowed_scopes]
        if invalid_scopes:
            return PolicyCheckResult(
                allowed=False,
                reason=(
                    f"Requested scope(s) {invalid_scopes} are not permitted by policy. "
                    f"Allowed scopes: {self._allowed_scopes}."
                ),
                did=did,
                checked_scope=requested_scope,
            )

        # ----------------------------------------------------------
        # All checks passed — ALLOW
        # ----------------------------------------------------------
        logger.info("PolicyEngine: ALLOW DID=%s scope=%s", did, requested_scope)
        return PolicyCheckResult(
            allowed=True,
            reason="All Zero-Trust policy checks passed. Token issuance authorized.",
            did=did,
            checked_scope=requested_scope,
        )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_allowed_scopes(self) -> List[str]:
        """Return the list of scopes currently permitted by this policy engine."""
        return list(self._allowed_scopes)
