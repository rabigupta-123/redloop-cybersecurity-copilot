"""REDLOOP Phase 10 — Threat-Hunting Hypothesis Lifecycle & Evidence Management Engine.

Provides:
1. Threat-hunting hypothesis lifecycle management:
   DRAFT -> READY -> RUNNING -> SUPPORTED | REFUTED | INCONCLUSIVE -> CLOSED.
2. Dual-track evidence ledger: supporting evidence vs contradictory evidence.
3. Mathematical confidence scoring based on weighed supporting and contradictory evidence.
4. Non-fabrication: Contradictory observations are never hidden, dismissed, or overwritten.
5. Entity and query links: association with MITRE techniques, hunting queries, incidents, and cases.
6. Full audit trail of transitions and modifications.
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


class HypothesisStatus(str, Enum):
    DRAFT = "DRAFT"
    READY = "READY"
    RUNNING = "RUNNING"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    CLOSED = "CLOSED"


@dataclass
class HypothesisEvidence:
    """An individual piece of supporting or contradictory evidence."""
    evidence_id: str
    description: str
    source_type: str  # e.g. "event", "query", "intel", "manual"
    source_reference: str  # e.g. "EVT-101", "sq-abc", "CVE-2024-1234"
    is_contradictory: bool
    weight: float = 1.0  # 0.1 to 2.0
    recorded_by: str = "analyst"
    recorded_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisRecord:
    """Authoritative threat-hunting hypothesis document."""
    hypothesis_id: str
    title: str
    description: str
    mitre_techniques: list[str]
    status: HypothesisStatus
    lead_hunter: str
    expected_evidence: list[str]
    supporting_evidence: list[HypothesisEvidence] = field(default_factory=list)
    contradictory_evidence: list[HypothesisEvidence] = field(default_factory=list)
    confidence_score: float = 0.5  # 0.0 to 1.0
    linked_queries: list[str] = field(default_factory=list)
    linked_incidents: list[str] = field(default_factory=list)
    linked_cases: list[str] = field(default_factory=list)
    findings_summary: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def calculate_confidence(self) -> float:
        """Dynamically computes confidence score weighing supporting vs contradictory evidence.
        
        Formula:
            weighted_supp = sum(e.weight for e in supporting)
            weighted_contra = sum(e.weight for e in contradictory)
            ratio = (weighted_supp + 1.0) / (weighted_supp + 2.0 * weighted_contra + 2.0)
        """
        w_supp = sum(e.weight for e in self.supporting_evidence)
        w_contra = sum(e.weight for e in self.contradictory_evidence)
        if w_supp == 0 and w_contra == 0:
            return 0.5
        score = (w_supp + 0.5) / (w_supp + 2.0 * w_contra + 1.0)
        return round(max(0.0, min(1.0, score)), 2)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["supporting_evidence"] = [e.to_dict() for e in self.supporting_evidence]
        d["contradictory_evidence"] = [e.to_dict() for e in self.contradictory_evidence]
        return d


class HypothesisManager:
    """Manages threat hunting hypotheses, dual-track evidence, and lifecycle transitions."""

    _instance: Optional["HypothesisManager"] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self._op_lock = threading.RLock()
        self.db_path = Path(db_path) if db_path else Path("data/hypotheses.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @classmethod
    def get_instance(cls, db_path: Optional[Path | str] = None) -> "HypothesisManager":
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
                        CREATE TABLE IF NOT EXISTS hunting_hypotheses (
                            hypothesis_id TEXT PRIMARY KEY,
                            title TEXT NOT NULL,
                            description TEXT NOT NULL,
                            mitre_techniques_json TEXT NOT NULL,
                            status TEXT NOT NULL,
                            lead_hunter TEXT NOT NULL,
                            expected_evidence_json TEXT NOT NULL,
                            supporting_evidence_json TEXT NOT NULL,
                            contradictory_evidence_json TEXT NOT NULL,
                            confidence_score REAL NOT NULL,
                            linked_queries_json TEXT NOT NULL,
                            linked_incidents_json TEXT NOT NULL,
                            linked_cases_json TEXT NOT NULL,
                            findings_summary TEXT,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        )
                    """)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS hypothesis_audit_log (
                            audit_id TEXT PRIMARY KEY,
                            hypothesis_id TEXT NOT NULL,
                            action TEXT NOT NULL,
                            actor TEXT NOT NULL,
                            details TEXT NOT NULL,
                            timestamp TEXT NOT NULL
                        )
                    """)
            finally:
                conn.close()

    def reset_state(self) -> None:
        """Clears all hypothesis records (for test isolation)."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM hunting_hypotheses")
                    conn.execute("DELETE FROM hypothesis_audit_log")
            finally:
                conn.close()

    def create_hypothesis(
        self,
        title: str,
        description: str,
        mitre_techniques: Optional[list[str]] = None,
        expected_evidence: Optional[list[str]] = None,
        lead_hunter: str = "analyst",
    ) -> HypothesisRecord:
        """Creates a new threat hunting hypothesis in DRAFT state."""
        hid = f"hyp-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()
        techniques = mitre_techniques or []
        expected = expected_evidence or []

        rec = HypothesisRecord(
            hypothesis_id=hid,
            title=title,
            description=description,
            mitre_techniques=techniques,
            status=HypothesisStatus.DRAFT,
            lead_hunter=lead_hunter,
            expected_evidence=expected,
            confidence_score=0.5,
            created_at=now,
            updated_at=now,
        )

        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    self._save_record_locked(rec, conn)
                    self._log_audit_locked(conn, hid, "CREATED", lead_hunter, f"Created hypothesis: '{title}'")
            finally:
                conn.close()

        return rec

    def get_hypothesis(self, hypothesis_id: str) -> Optional[HypothesisRecord]:
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM hunting_hypotheses WHERE hypothesis_id = ?", (hypothesis_id,))
                r = cur.fetchone()
                if not r:
                    return None
                return self._row_to_record(r)
            finally:
                conn.close()

    def list_hypotheses(
        self,
        status: Optional[HypothesisStatus] = None,
        mitre_technique: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        with self._op_lock:
            conn = self._get_connection()
            try:
                query = "SELECT * FROM hunting_hypotheses"
                params: list[Any] = []
                clauses = []
                if status:
                    clauses.append("status = ?")
                    params.append(status.value)
                if mitre_technique:
                    clauses.append("mitre_techniques_json LIKE ?")
                    params.append(f"%{mitre_technique}%")
                if clauses:
                    query += " WHERE " + " AND ".join(clauses)
                query += " ORDER BY updated_at DESC LIMIT ?"
                params.append(limit)

                cur = conn.execute(query, params)
                return [self._row_to_record(r).to_dict() for r in cur.fetchall()]
            finally:
                conn.close()

    def update_status(
        self,
        hypothesis_id: str,
        new_status: HypothesisStatus,
        findings_summary: Optional[str] = None,
        actor: str = "analyst",
    ) -> HypothesisRecord:
        """Transitions a hypothesis to a new lifecycle state with auditable reasoning."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                rec = self.get_hypothesis(hypothesis_id)
                if not rec:
                    raise ValueError(f"Hypothesis '{hypothesis_id}' not found.")

                old_status = rec.status
                rec.status = new_status
                if findings_summary is not None:
                    rec.findings_summary = findings_summary
                rec.updated_at = datetime.now(timezone.utc).isoformat()

                with conn:
                    self._save_record_locked(rec, conn)
                    self._log_audit_locked(
                        conn,
                        hypothesis_id,
                        "STATUS_CHANGED",
                        actor,
                        f"Status changed from {old_status.value} to {new_status.value}. Summary: {findings_summary or 'None'}",
                    )
                return rec
            finally:
                conn.close()

    def add_evidence(
        self,
        hypothesis_id: str,
        description: str,
        source_type: str,
        source_reference: str,
        is_contradictory: bool,
        weight: float = 1.0,
        recorded_by: str = "analyst",
    ) -> HypothesisRecord:
        """Records an evidence observation into either the supporting or contradictory track."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                rec = self.get_hypothesis(hypothesis_id)
                if not rec:
                    raise ValueError(f"Hypothesis '{hypothesis_id}' not found.")

                ev = HypothesisEvidence(
                    evidence_id=f"ev-{uuid.uuid4().hex[:8]}",
                    description=description,
                    source_type=source_type,
                    source_reference=source_reference,
                    is_contradictory=is_contradictory,
                    weight=max(0.1, min(5.0, float(weight))),
                    recorded_by=recorded_by,
                )

                if is_contradictory:
                    rec.contradictory_evidence.append(ev)
                else:
                    rec.supporting_evidence.append(ev)

                # Recompute confidence score dynamically
                rec.confidence_score = rec.calculate_confidence()
                rec.updated_at = datetime.now(timezone.utc).isoformat()

                with conn:
                    self._save_record_locked(rec, conn)
                    ev_type_str = "CONTRADICTORY" if is_contradictory else "SUPPORTING"
                    self._log_audit_locked(
                        conn,
                        hypothesis_id,
                        "EVIDENCE_RECORDED",
                        recorded_by,
                        f"Recorded {ev_type_str} evidence: '{description}' (Ref: {source_reference}, Weight: {ev.weight}). New confidence: {rec.confidence_score}",
                    )
                return rec
            finally:
                conn.close()

    def link_query(self, hypothesis_id: str, query_id: str, actor: str = "analyst") -> HypothesisRecord:
        with self._op_lock:
            conn = self._get_connection()
            try:
                rec = self.get_hypothesis(hypothesis_id)
                if not rec:
                    raise ValueError(f"Hypothesis '{hypothesis_id}' not found.")
                if query_id not in rec.linked_queries:
                    rec.linked_queries.append(query_id)
                    rec.updated_at = datetime.now(timezone.utc).isoformat()
                    with conn:
                        self._save_record_locked(rec, conn)
                        self._log_audit_locked(conn, hypothesis_id, "QUERY_LINKED", actor, f"Linked query: {query_id}")
                return rec
            finally:
                conn.close()

    def link_incident(self, hypothesis_id: str, incident_id: str, actor: str = "analyst") -> HypothesisRecord:
        with self._op_lock:
            conn = self._get_connection()
            try:
                rec = self.get_hypothesis(hypothesis_id)
                if not rec:
                    raise ValueError(f"Hypothesis '{hypothesis_id}' not found.")
                if incident_id not in rec.linked_incidents:
                    rec.linked_incidents.append(incident_id)
                    rec.updated_at = datetime.now(timezone.utc).isoformat()
                    with conn:
                        self._save_record_locked(rec, conn)
                        self._log_audit_locked(conn, hypothesis_id, "INCIDENT_LINKED", actor, f"Linked incident: {incident_id}")
                return rec
            finally:
                conn.close()

    def link_case(self, hypothesis_id: str, case_id: str, actor: str = "analyst") -> HypothesisRecord:
        with self._op_lock:
            conn = self._get_connection()
            try:
                rec = self.get_hypothesis(hypothesis_id)
                if not rec:
                    raise ValueError(f"Hypothesis '{hypothesis_id}' not found.")
                if case_id not in rec.linked_cases:
                    rec.linked_cases.append(case_id)
                    rec.updated_at = datetime.now(timezone.utc).isoformat()
                    with conn:
                        self._save_record_locked(rec, conn)
                        self._log_audit_locked(conn, hypothesis_id, "CASE_LINKED", actor, f"Linked case: {case_id}")
                return rec
            finally:
                conn.close()

    def get_audit_trail(self, hypothesis_id: str) -> list[dict[str, Any]]:
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM hypothesis_audit_log WHERE hypothesis_id = ? ORDER BY timestamp ASC", (hypothesis_id,))
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def _save_record_locked(self, rec: HypothesisRecord, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO hunting_hypotheses
            (hypothesis_id, title, description, mitre_techniques_json, status, lead_hunter,
             expected_evidence_json, supporting_evidence_json, contradictory_evidence_json,
             confidence_score, linked_queries_json, linked_incidents_json, linked_cases_json,
             findings_summary, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rec.hypothesis_id,
                rec.title,
                rec.description,
                json.dumps(rec.mitre_techniques),
                rec.status.value,
                rec.lead_hunter,
                json.dumps(rec.expected_evidence),
                json.dumps([e.to_dict() for e in rec.supporting_evidence]),
                json.dumps([e.to_dict() for e in rec.contradictory_evidence]),
                rec.confidence_score,
                json.dumps(rec.linked_queries),
                json.dumps(rec.linked_incidents),
                json.dumps(rec.linked_cases),
                rec.findings_summary,
                rec.created_at,
                rec.updated_at,
            ),
        )

    def _log_audit_locked(self, conn: sqlite3.Connection, hypothesis_id: str, action: str, actor: str, details: str) -> None:
        conn.execute(
            """
            INSERT INTO hypothesis_audit_log
            (audit_id, hypothesis_id, action, actor, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                f"ha-{uuid.uuid4().hex[:10]}",
                hypothesis_id,
                action,
                actor,
                details,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    def _row_to_record(self, r: sqlite3.Row) -> HypothesisRecord:
        supp_raw = json.loads(r["supporting_evidence_json"])
        contra_raw = json.loads(r["contradictory_evidence_json"])

        supp = [HypothesisEvidence(**e) for e in supp_raw]
        contra = [HypothesisEvidence(**e) for e in contra_raw]

        return HypothesisRecord(
            hypothesis_id=r["hypothesis_id"],
            title=r["title"],
            description=r["description"],
            mitre_techniques=json.loads(r["mitre_techniques_json"]),
            status=HypothesisStatus(r["status"]),
            lead_hunter=r["lead_hunter"],
            expected_evidence=json.loads(r["expected_evidence_json"]),
            supporting_evidence=supp,
            contradictory_evidence=contra,
            confidence_score=float(r["confidence_score"]),
            linked_queries=json.loads(r["linked_queries_json"]),
            linked_incidents=json.loads(r["linked_incidents_json"]),
            linked_cases=json.loads(r["linked_cases_json"]),
            findings_summary=r["findings_summary"],
            created_at=r["created_at"],
            updated_at=r["updated_at"],
        )
