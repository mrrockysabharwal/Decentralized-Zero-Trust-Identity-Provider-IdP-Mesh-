"""FastAPI Router for Simulated Blockchain Ledger (Identity Integrity Anchoring).

Provides endpoints for:
- Listing blocks
- Querying DID history and latest state
- Anchoring new DID identity events (used by Member 3 & Member 1)
- Audit integrity verification (used by Member 6 for the Admin Security Dashboard)
- Interactive tamper demonstration endpoint for security audits
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger.models import (
    LedgerRecord,
    LedgerOperation,
    RecordCreateInput,
)

router = APIRouter(prefix="/ledger", tags=["Simulated Ledger"])

# Shared singleton instance (can be overridden via dependency injection)
ledger_instance = SimulatedLedger(auto_genesis=True)


def get_ledger() -> SimulatedLedger:
    """Dependency injection helper returning the active SimulatedLedger instance."""
    return ledger_instance


class IntegrityStatusResponse(BaseModel):
    """Integrity audit result for the Admin Security Dashboard."""
    valid: bool = Field(description="True if chain is completely intact and untampered")
    error: Optional[str] = Field(default=None, description="Diagnostic error message if tampering detected")
    total_records: int = Field(description="Total number of records currently on the ledger")
    head_hash: Optional[str] = Field(default=None, description="Current head record hash")


class TamperSimulationRequest(BaseModel):
    """Payload to simulate a malicious tamper attack for demonstration."""
    index: int = Field(ge=0, description="Block index to tamper with")
    field: str = Field(description="Field to modify (e.g., 'did', 'doc_hash', 'previous_hash')")
    new_value: Any = Field(description="Malicious value to inject")
    recalculate_record_hash: bool = Field(
        default=False,
        description="Whether attacker tries to forge this block's hash (linkage still breaks)"
    )


@router.get("", response_model=List[LedgerRecord], summary="List all ledger records")
def get_all_records() -> List[LedgerRecord]:
    """Retrieve the complete list of append-only blocks on the simulated ledger."""
    return ledger_instance.get_all_records()


@router.get("/verify", response_model=IntegrityStatusResponse, summary="Verify ledger integrity")
def verify_ledger_integrity() -> IntegrityStatusResponse:
    """Audit the cryptographic integrity of the entire ledger chain.
    
    Used by the administrative security dashboard to display the live integrity status.
    """
    is_valid, error = ledger_instance.verify_integrity()
    head = ledger_instance.get_head()
    return IntegrityStatusResponse(
        valid=is_valid,
        error=error,
        total_records=len(ledger_instance),
        head_hash=head.record_hash if head else None,
    )


@router.get("/history/{did}", response_model=List[LedgerRecord], summary="Get DID record history")
def get_did_history(did: str) -> List[LedgerRecord]:
    """Retrieve the chronological update history for a specific DID."""
    records = ledger_instance.get_records_by_did(did)
    if not records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No ledger records found for DID '{did}'"
        )
    return records


@router.get("/latest/{did}", response_model=LedgerRecord, summary="Get latest DID record")
def get_latest_did_record(did: str) -> LedgerRecord:
    """Retrieve the most recent verified state for a given DID."""
    record = ledger_instance.get_latest_record(did)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DID '{did}' is not registered on the ledger"
        )
    return record


@router.post(
    "/anchor",
    response_model=LedgerRecord,
    status_code=status.HTTP_201_CREATED,
    summary="Anchor a DID document to the ledger"
)
def anchor_did_record(payload: RecordCreateInput) -> LedgerRecord:
    """Anchor a new DID creation or update event to the append-only ledger.
    
    Called by the backend registration and update workflows.
    """
    try:
        record = ledger_instance.append_record(
            did=payload.did,
            doc_hash=payload.doc_hash,
            operation=payload.operation,
            metadata=payload.metadata,
        )
        return record
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to anchor record to ledger: {str(e)}"
        )


@router.post(
    "/simulate-tamper",
    response_model=IntegrityStatusResponse,
    summary="Simulate a tampering attack (Demonstration only)"
)
def simulate_tampering_attack(payload: TamperSimulationRequest) -> IntegrityStatusResponse:
    """Simulate malicious tampering with a block to demonstrate integrity audit detection."""
    try:
        ledger_instance.tamper_record(
            index=payload.index,
            field=payload.field,
            new_value=payload.new_value,
            recalculate_record_hash=payload.recalculate_record_hash,
        )
    except IndexError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Tampering simulation failed: {str(e)}")

    # Return updated integrity status immediately
    is_valid, error = ledger_instance.verify_integrity()
    head = ledger_instance.get_head()
    return IntegrityStatusResponse(
        valid=is_valid,
        error=error,
        total_records=len(ledger_instance),
        head_hash=head.record_hash if head else None,
    )
