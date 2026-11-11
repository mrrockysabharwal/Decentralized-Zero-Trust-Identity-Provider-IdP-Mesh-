"""SQLite-backed audit events with pseudonymous identity references."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditEventStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.environ.get("AUDIT_DB_PATH", "data/security_events.sqlite3")
        self._lock = threading.Lock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
                outcome TEXT NOT NULL, severity TEXT NOT NULL, did_ref TEXT,
                reason TEXT NOT NULL, correlation_id TEXT NOT NULL, metadata TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(timestamp DESC)")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _did_ref(did: str | None) -> str | None:
        if not did:
            return None
        return "did#" + hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]

    def record(self, *, event_type: str, outcome: str, reason: str, did: str | None = None,
               severity: str = "low", metadata: dict[str, Any] | None = None,
               correlation_id: str | None = None) -> dict[str, Any]:
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "outcome": outcome,
            "severity": severity,
            "did_ref": self._did_ref(did),
            "reason": reason[:160],
            "correlation_id": correlation_id or str(uuid.uuid4()),
            "metadata": metadata or {},
        }
        with self._lock, self._connect() as db:
            db.execute("INSERT INTO security_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                event["event_id"], event["timestamp"], event_type, outcome, severity,
                event["did_ref"], event["reason"], event["correlation_id"],
                json.dumps(event["metadata"], separators=(",", ":")),
            ))
        return event

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        event = dict(row)
        event["metadata"] = json.loads(event["metadata"])
        return event

    def list_events(self, *, page: int = 1, page_size: int = 25, event_type: str | None = None,
                    outcome: str | None = None) -> tuple[list[dict[str, Any]], int]:
        clauses, args = [], []
        if event_type:
            clauses.append("event_type = ?"); args.append(event_type)
        if outcome:
            clauses.append("outcome = ?"); args.append(outcome)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connect() as db:
            total = db.execute("SELECT COUNT(*) FROM security_events" + where, args).fetchone()[0]
            rows = db.execute("SELECT * FROM security_events" + where +
                              " ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                              [*args, page_size, (page - 1) * page_size]).fetchall()
        return [self._row(row) for row in rows], total

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM security_events WHERE event_id = ?", (event_id,)).fetchone()
        return self._row(row) if row else None

    def counts(self) -> dict[str, int]:
        with self._connect() as db:
            rows = db.execute("SELECT event_type, outcome, COUNT(*) AS n FROM security_events GROUP BY event_type, outcome").fetchall()
        result: dict[str, int] = {}
        for row in rows:
            result[f"{row['event_type']}:{row['outcome']}"] = row["n"]
        return result

    def clear(self) -> None:
        with self._lock, self._connect() as db:
            db.execute("DELETE FROM security_events")


audit_event_store = AuditEventStore()


def record_security_event(**kwargs: Any) -> None:
    """Best-effort event logging must not turn a valid auth operation into a failure."""
    try:
        audit_event_store.record(**kwargs)
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Could not persist security event")
