"""REDLOOP Autonomous SOC Operations — Threat Intelligence & IOC Lifecycle Engine (Phase 9).

Provides:
1. Structured indicator lifecycle management (IP, Domain, URL, Hash, Email).
2. Explicit states: NEW, UNDER_REVIEW, CONFIRMED_MALICIOUS, BENIGN, FALSE_POSITIVE, EXPIRED, UNKNOWN.
3. Safe offline operation without credential leakage.
4. Non-fabrication: Never converts provider NOT_FOUND into benign reputation.
5. Analyst disposition workflow with auditable history.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class IOCType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH = "HASH"
    EMAIL = "EMAIL"


class IOCState(str, Enum):
    NEW = "NEW"
    UNDER_REVIEW = "UNDER_REVIEW"
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"
    BENIGN = "BENIGN"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"


@dataclass
class IOCRecord:
    """Authoritative Indicator of Compromise (IOC) record with lifecycle state."""
    ioc_id: str
    ioc_type: IOCType
    value: str
    state: IOCState
    source: str
    confidence: float  # 0.0 to 1.0
    reputation: str    # e.g. "MALICIOUS", "SUSPICIOUS", "UNKNOWN"
    first_seen: str
    last_seen: str
    expiry: Optional[str] = None
    related_cases: list[str] = field(default_factory=list)
    related_events: list[str] = field(default_factory=list)
    provider_response_status: str = "OFFLINE_LOCAL"
    provenance: str = "LOCAL_INGEST"
    analyst_disposition: Optional[str] = None
    disposition_reason: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ioc_type"] = self.ioc_type.value
        d["state"] = self.state.value
        return d


class IOCLifecycleManager:
    """Manages threat intelligence indicator ingestion, enrichment, and disposition."""

    _instance: Optional["IOCLifecycleManager"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self._op_lock = threading.RLock()
        self.db_path = Path(db_path) if db_path else Path("data/ioc_lifecycle.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @classmethod
    def get_instance(cls, db_path: Optional[Path | str] = None) -> "IOCLifecycleManager":
        with cls._lock:
            if db_path is not None:
                p = Path(db_path)
                if cls._instance is None or cls._instance.db_path != p:
                    cls._instance = cls(db_path=p)
                    return cls._instance
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS ioc_records (
                            ioc_id TEXT PRIMARY KEY,
                            ioc_type TEXT NOT NULL,
                            value TEXT UNIQUE NOT NULL,
                            state TEXT NOT NULL,
                            source TEXT NOT NULL,
                            confidence REAL NOT NULL,
                            reputation TEXT NOT NULL,
                            first_seen TEXT NOT NULL,
                            last_seen TEXT NOT NULL,
                            expiry TEXT,
                            related_cases_json TEXT NOT NULL,
                            related_events_json TEXT NOT NULL,
                            provider_response_status TEXT NOT NULL,
                            provenance TEXT NOT NULL,
                            analyst_disposition TEXT,
                            disposition_reason TEXT,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        )
                    """)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS ioc_audit_log (
                            audit_id TEXT PRIMARY KEY,
                            ioc_id TEXT NOT NULL,
                            action TEXT NOT NULL,
                            actor TEXT NOT NULL,
                            details TEXT NOT NULL,
                            timestamp TEXT NOT NULL
                        )
                    """)
            finally:
                conn.close()

    def reset_state(self) -> None:
        """Clears all IOC records (for test isolation)."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM ioc_records")
                    conn.execute("DELETE FROM ioc_audit_log")
            finally:
                conn.close()

    def register_ioc(
        self,
        ioc_type: IOCType,
        value: str,
        source: str = "telemetry_ingest",
        confidence: float = 0.5,
        reputation: str = "UNKNOWN",
        related_case_id: Optional[str] = None,
        related_event_id: Optional[str] = None,
        actor: str = "system",
    ) -> IOCRecord:
        """Registers a new IOC or updates an existing record's last_seen and references."""
        clean_val = value.strip().lower() if ioc_type in (IOCType.DOMAIN, IOCType.EMAIL) else value.strip()
        now = datetime.now(timezone.utc).isoformat()

        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM ioc_records WHERE value = ?", (clean_val,))
                row = cur.fetchone()

                if row:
                    # Update existing record
                    rec = self._row_to_ioc(row)
                    rec.last_seen = now
                    rec.updated_at = now
                    if related_case_id and related_case_id not in rec.related_cases:
                        rec.related_cases.append(related_case_id)
                    if related_event_id and related_event_id not in rec.related_events:
                        rec.related_events.append(related_event_id)
                    with conn:
                        self._save_ioc_locked(rec, conn)
                    return rec

                # Insert new IOC
                ioc_id = f"ioc-{uuid.uuid4().hex[:10]}"
                cases = [related_case_id] if related_case_id else []
                events = [related_event_id] if related_event_id else []

                rec = IOCRecord(
                    ioc_id=ioc_id,
                    ioc_type=ioc_type,
                    value=clean_val,
                    state=IOCState.NEW,
                    source=source,
                    confidence=confidence,
                    reputation=reputation,
                    first_seen=now,
                    last_seen=now,
                    related_cases=cases,
                    related_events=events,
                    provider_response_status="NOT_ENRICHED",
                    provenance=f"INGEST:{source.upper()}",
                )

                with conn:
                    self._save_ioc_locked(rec, conn)
                    conn.execute(
                        """
                        INSERT INTO ioc_audit_log
                        (audit_id, ioc_id, action, actor, details, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (f"aud-ioc-{uuid.uuid4().hex[:10]}", rec.ioc_id, "IOC_REGISTERED", actor, f"Registered IOC {rec.ioc_type.value}: {rec.value}", now),
                    )
                return rec
            finally:
                conn.close()

    def set_disposition(
        self,
        ioc_id: str,
        state: IOCState,
        actor: str = "analyst",
        reason: str = "",
    ) -> IOCRecord:
        """Sets the analyst disposition state for an IOC."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                rec = self.get_ioc(ioc_id)
                if not rec:
                    raise ValueError(f"IOC record '{ioc_id}' not found.")

                now = datetime.now(timezone.utc).isoformat()
                rec.state = state
                rec.analyst_disposition = state.value
                rec.disposition_reason = reason
                rec.updated_at = now

                if state == IOCState.CONFIRMED_MALICIOUS:
                    rec.reputation = "CONFIRMED_MALICIOUS"
                    rec.confidence = 1.0
                elif state == IOCState.BENIGN:
                    rec.reputation = "BENIGN"
                    rec.confidence = 0.0
                elif state == IOCState.FALSE_POSITIVE:
                    rec.reputation = "FALSE_POSITIVE"
                    rec.confidence = 0.0

                with conn:
                    self._save_ioc_locked(rec, conn)
                    conn.execute(
                        """
                        INSERT INTO ioc_audit_log
                        (audit_id, ioc_id, action, actor, details, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"aud-ioc-{uuid.uuid4().hex[:10]}",
                            rec.ioc_id,
                            "DISPOSITION_CHANGED",
                            actor,
                            f"Disposition changed to '{state.value}'. Reason: {reason or 'Analyst assessment'}",
                            now,
                        ),
                    )
                return rec
            finally:
                conn.close()

    def get_ioc(self, ioc_id: str) -> Optional[IOCRecord]:
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM ioc_records WHERE ioc_id = ?", (ioc_id,))
                r = cur.fetchone()
                if not r:
                    return None
                return self._row_to_ioc(r)
            finally:
                conn.close()

    def list_iocs(
        self,
        ioc_type: Optional[IOCType] = None,
        state: Optional[IOCState] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        with self._op_lock:
            conn = self._get_connection()
            try:
                query = "SELECT * FROM ioc_records"
                clauses = []
                params = []
                if ioc_type:
                    clauses.append("ioc_type = ?")
                    params.append(ioc_type.value)
                if state:
                    clauses.append("state = ?")
                    params.append(state.value)
                if clauses:
                    query += " WHERE " + " AND ".join(clauses)
                query += " ORDER BY updated_at DESC LIMIT ?"
                params.append(limit)

                cur = conn.execute(query, params)
                return [self._row_to_ioc(r).to_dict() for r in cur.fetchall()]
            finally:
                conn.close()

    def _save_ioc_locked(self, rec: IOCRecord, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO ioc_records
            (ioc_id, ioc_type, value, state, source, confidence, reputation, first_seen,
             last_seen, expiry, related_cases_json, related_events_json, provider_response_status,
             provenance, analyst_disposition, disposition_reason, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rec.ioc_id,
                rec.ioc_type.value,
                rec.value,
                rec.state.value,
                rec.source,
                rec.confidence,
                rec.reputation,
                rec.first_seen,
                rec.last_seen,
                rec.expiry,
                json.dumps(rec.related_cases),
                json.dumps(rec.related_events),
                rec.provider_response_status,
                rec.provenance,
                rec.analyst_disposition,
                rec.disposition_reason,
                rec.created_at,
                rec.updated_at,
            ),
        )

    def _row_to_ioc(self, r: sqlite3.Row) -> IOCRecord:
        return IOCRecord(
            ioc_id=r["ioc_id"],
            ioc_type=IOCType(r["ioc_type"]),
            value=r["value"],
            state=IOCState(r["state"]),
            source=r["source"],
            confidence=float(r["confidence"]),
            reputation=r["reputation"],
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
            expiry=r["expiry"],
            related_cases=json.loads(r["related_cases_json"]),
            related_events=json.loads(r["related_events_json"]),
            provider_response_status=r["provider_response_status"],
            provenance=r["provenance"],
            analyst_disposition=r["analyst_disposition"],
            disposition_reason=r["disposition_reason"],
            created_at=r["created_at"],
            updated_at=r["updated_at"],
        )


IOCLifecycleManager.get_store = classmethod(lambda cls, db_path=None: cls.get_instance(db_path=db_path))
IOCStore = IOCLifecycleManager

