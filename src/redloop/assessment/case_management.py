"""REDLOOP Incident Case Management & Investigation Tracking Engine (Phase 7).

Provides:
1. End-to-end Case Management lifecycle tracking:
   OPEN -> INVESTIGATING -> PENDING_APPROVAL -> CONTAINMENT_IN_PROGRESS ->
   MONITORING -> RESOLVED -> CLOSED -> REOPENED.
2. Linking to SOC Alerts, Incident records, Threat Hunt findings, and Evidence Ledger items.
3. Persistent SQLite storage with migrations, audit trails, and timeline event history.
4. Preserves evidence references without mutating underlying security event records.
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


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    CONTAINMENT_IN_PROGRESS = "CONTAINMENT_IN_PROGRESS"
    MONITORING = "MONITORING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"


class CaseSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CasePriority(str, Enum):
    P1 = "P1"  # Urgent containment required
    P2 = "P2"  # High priority investigation
    P3 = "P3"  # Standard incident response
    P4 = "P4"  # Low priority / informational


@dataclass
class CaseNote:
    """Analyst note attached to an investigation case."""
    note_id: str
    author: str
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CaseTimelineEvent:
    """Chronological event logged during the lifecycle of a case."""
    event_id: str
    event_type: str
    actor: str
    description: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentCase:
    """Full incident investigation case record."""
    case_id: str
    title: str
    description: str
    status: CaseStatus
    severity: CaseSeverity
    priority: CasePriority
    assigned_to: str  # local role: e.g. "lead_analyst", "tier1_analyst", "unassigned"
    created_at: str
    updated_at: str
    linked_alert_ids: list[str] = field(default_factory=list)
    linked_incident_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    related_indicators: dict[str, list[str]] = field(default_factory=dict)
    notes: list[CaseNote] = field(default_factory=list)
    timeline: list[CaseTimelineEvent] = field(default_factory=list)
    closure_reason: Optional[str] = None
    closure_timestamp: Optional[str] = None
    reopen_count: int = 0
    reopen_history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        d["priority"] = self.priority.value
        d["notes"] = [n.to_dict() for n in self.notes]
        d["timeline"] = [t.to_dict() for t in self.timeline]
        return d


class CaseManager:
    """Thread-safe SQLite-backed Incident Case Manager."""

    _instance: Optional["CaseManager"] = None
    _lock = threading.Lock()

    VALID_TRANSITIONS: dict[CaseStatus, set[CaseStatus]] = {
        CaseStatus.OPEN: {CaseStatus.INVESTIGATING, CaseStatus.CLOSED},
        CaseStatus.INVESTIGATING: {
            CaseStatus.PENDING_APPROVAL,
            CaseStatus.CONTAINMENT_IN_PROGRESS,
            CaseStatus.MONITORING,
            CaseStatus.RESOLVED,
            CaseStatus.CLOSED,
        },
        CaseStatus.PENDING_APPROVAL: {
            CaseStatus.CONTAINMENT_IN_PROGRESS,
            CaseStatus.INVESTIGATING,
            CaseStatus.RESOLVED,
        },
        CaseStatus.CONTAINMENT_IN_PROGRESS: {
            CaseStatus.MONITORING,
            CaseStatus.INVESTIGATING,
            CaseStatus.RESOLVED,
        },
        CaseStatus.MONITORING: {CaseStatus.RESOLVED, CaseStatus.INVESTIGATING, CaseStatus.CLOSED},
        CaseStatus.RESOLVED: {CaseStatus.CLOSED, CaseStatus.REOPENED},
        CaseStatus.CLOSED: {CaseStatus.REOPENED},
        CaseStatus.REOPENED: {CaseStatus.INVESTIGATING, CaseStatus.CLOSED},
    }

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self._op_lock = threading.Lock()
        self.db_path = Path(db_path) if db_path else Path("data/cases.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @classmethod
    def get_instance(cls, db_path: Optional[Path | str] = None) -> "CaseManager":
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
                        CREATE TABLE IF NOT EXISTS cases (
                            case_id TEXT PRIMARY KEY,
                            title TEXT NOT NULL,
                            description TEXT NOT NULL,
                            status TEXT NOT NULL,
                            severity TEXT NOT NULL,
                            priority TEXT NOT NULL,
                            assigned_to TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            linked_alert_ids_json TEXT NOT NULL,
                            linked_incident_ids_json TEXT NOT NULL,
                            evidence_ids_json TEXT NOT NULL,
                            related_indicators_json TEXT NOT NULL,
                            notes_json TEXT NOT NULL,
                            timeline_json TEXT NOT NULL,
                            closure_reason TEXT,
                            closure_timestamp TEXT,
                            reopen_count INTEGER NOT NULL DEFAULT 0,
                            reopen_history_json TEXT NOT NULL
                        )
                    """)
            finally:
                conn.close()

    def reset_state(self) -> None:
        """Clears all case records (for test isolation)."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM cases")
            finally:
                conn.close()

    def create_case(
        self,
        title: str,
        description: str,
        severity: CaseSeverity = CaseSeverity.MEDIUM,
        priority: CasePriority = CasePriority.P3,
        assigned_to: str = "unassigned",
        linked_alert_ids: Optional[list[str]] = None,
        linked_incident_ids: Optional[list[str]] = None,
        evidence_ids: Optional[list[str]] = None,
        related_indicators: Optional[dict[str, list[str]]] = None,
        creator: str = "system",
    ) -> IncidentCase:
        """Creates and stores a new incident case."""
        case_id = f"case-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()

        init_timeline = CaseTimelineEvent(
            event_id=f"evt-{uuid.uuid4().hex[:8]}",
            event_type="CASE_CREATED",
            actor=creator,
            description=f"Case opened by {creator}: '{title}'.",
            data={"severity": severity.value, "priority": priority.value},
            timestamp=now,
        )

        case = IncidentCase(
            case_id=case_id,
            title=title,
            description=description,
            status=CaseStatus.OPEN,
            severity=severity,
            priority=priority,
            assigned_to=assigned_to,
            created_at=now,
            updated_at=now,
            linked_alert_ids=linked_alert_ids or [],
            linked_incident_ids=linked_incident_ids or [],
            evidence_ids=evidence_ids or [],
            related_indicators=related_indicators or {},
            notes=[],
            timeline=[init_timeline],
        )

        self._save_case(case)
        return case

    def get_case(self, case_id: str) -> Optional[IncidentCase]:
        """Retrieves an incident case by ID."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return self._row_to_case(row)
            finally:
                conn.close()

    def update_case(
        self,
        case_id: str,
        status: Optional[CaseStatus] = None,
        severity: Optional[CaseSeverity] = None,
        priority: Optional[CasePriority] = None,
        assigned_to: Optional[str] = None,
        closure_reason: Optional[str] = None,
        actor: str = "operator",
    ) -> IncidentCase:
        """Updates case attributes and logs transitions in the timeline."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' not found.")

        now = datetime.now(timezone.utc).isoformat()
        events: list[CaseTimelineEvent] = []

        # State transition validation
        if status is not None and status != case.status:
            allowed = self.VALID_TRANSITIONS.get(case.status, set())
            if status not in allowed:
                raise ValueError(f"Invalid state transition: Cannot move case from '{case.status.value}' to '{status.value}'.")

            from_state = case.status
            case.status = status
            events.append(
                CaseTimelineEvent(
                    event_id=f"evt-{uuid.uuid4().hex[:8]}",
                    event_type="STATUS_CHANGED",
                    actor=actor,
                    description=f"Status transitioned from {from_state.value} to {status.value}.",
                    data={"from": from_state.value, "to": status.value},
                    timestamp=now,
                )
            )

            # Reopen handling
            if status == CaseStatus.REOPENED:
                case.reopen_count += 1
                case.reopen_history.append({"reopened_at": now, "reopened_by": actor, "reason": closure_reason or "Re-opened for additional investigation"})
                case.closure_reason = None
                case.closure_timestamp = None

            # Close handling
            if status in (CaseStatus.CLOSED, CaseStatus.RESOLVED):
                case.closure_reason = closure_reason or "Investigation complete"
                case.closure_timestamp = now

        if severity is not None and severity != case.severity:
            old_sev = case.severity
            case.severity = severity
            events.append(
                CaseTimelineEvent(
                    event_id=f"evt-{uuid.uuid4().hex[:8]}",
                    event_type="SEVERITY_CHANGED",
                    actor=actor,
                    description=f"Severity updated from {old_sev.value} to {severity.value}.",
                    data={"from": old_sev.value, "to": severity.value},
                    timestamp=now,
                )
            )

        if priority is not None and priority != case.priority:
            old_pri = case.priority
            case.priority = priority
            events.append(
                CaseTimelineEvent(
                    event_id=f"evt-{uuid.uuid4().hex[:8]}",
                    event_type="PRIORITY_CHANGED",
                    actor=actor,
                    description=f"Priority updated from {old_pri.value} to {priority.value}.",
                    data={"from": old_pri.value, "to": priority.value},
                    timestamp=now,
                )
            )

        if assigned_to is not None and assigned_to != case.assigned_to:
            old_assignee = case.assigned_to
            case.assigned_to = assigned_to
            events.append(
                CaseTimelineEvent(
                    event_id=f"evt-{uuid.uuid4().hex[:8]}",
                    event_type="ASSIGNEE_CHANGED",
                    actor=actor,
                    description=f"Assignment changed from '{old_assignee}' to '{assigned_to}'.",
                    data={"from": old_assignee, "to": assigned_to},
                    timestamp=now,
                )
            )

        case.updated_at = now
        case.timeline.extend(events)
        self._save_case(case)
        return case

    def add_note(self, case_id: str, author: str, content: str) -> CaseNote:
        """Adds an analyst investigation note to the case."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' not found.")

        note = CaseNote(
            note_id=f"not-{uuid.uuid4().hex[:8]}",
            author=author,
            content=content,
        )
        case.notes.append(note)
        case.updated_at = note.timestamp
        case.timeline.append(
            CaseTimelineEvent(
                event_id=f"evt-{uuid.uuid4().hex[:8]}",
                event_type="NOTE_ADDED",
                actor=author,
                description=f"Analyst note added by {author}.",
                data={"note_id": note.note_id, "content_snippet": content[:60]},
                timestamp=note.timestamp,
            )
        )
        self._save_case(case)
        return note

    def attach_evidence(self, case_id: str, evidence_ids: list[str], actor: str = "operator") -> list[str]:
        """Attaches evidence ledger IDs to the case without mutating underlying evidence records."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case '{case_id}' not found.")

        added = []
        for eid in evidence_ids:
            if eid not in case.evidence_ids:
                case.evidence_ids.append(eid)
                added.append(eid)

        if added:
            now = datetime.now(timezone.utc).isoformat()
            case.updated_at = now
            case.timeline.append(
                CaseTimelineEvent(
                    event_id=f"evt-{uuid.uuid4().hex[:8]}",
                    event_type="EVIDENCE_ATTACHED",
                    actor=actor,
                    description=f"Attached {len(added)} evidence records: {', '.join(added)}",
                    data={"evidence_ids": added},
                    timestamp=now,
                )
            )
            self._save_case(case)

        return case.evidence_ids

    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        severity: Optional[CaseSeverity] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Returns cases matching optional status and severity filters."""
        query = "SELECT * FROM cases"
        params: list[Any] = []
        clauses: list[str] = []

        if status:
            clauses.append("status = ?")
            params.append(status.value)
        if severity:
            clauses.append("severity = ?")
            params.append(severity.value)

        if clauses:
            query += " WHERE " + " AND ".join(clauses)

        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(query, params)
                rows = cur.fetchall()
                return [self._row_to_case(r).to_dict() for r in rows]
            finally:
                conn.close()

    def _save_case(self, case: IncidentCase) -> None:
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO cases
                        (case_id, title, description, status, severity, priority, assigned_to, created_at, updated_at,
                         linked_alert_ids_json, linked_incident_ids_json, evidence_ids_json, related_indicators_json,
                         notes_json, timeline_json, closure_reason, closure_timestamp, reopen_count, reopen_history_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            case.case_id,
                            case.title,
                            case.description,
                            case.status.value,
                            case.severity.value,
                            case.priority.value,
                            case.assigned_to,
                            case.created_at,
                            case.updated_at,
                            json.dumps(case.linked_alert_ids),
                            json.dumps(case.linked_incident_ids),
                            json.dumps(case.evidence_ids),
                            json.dumps(case.related_indicators),
                            json.dumps([n.to_dict() for n in case.notes]),
                            json.dumps([t.to_dict() for t in case.timeline]),
                            case.closure_reason,
                            case.closure_timestamp,
                            case.reopen_count,
                            json.dumps(case.reopen_history),
                        ),
                    )
            finally:
                conn.close()

    def _row_to_case(self, row: sqlite3.Row) -> IncidentCase:
        notes_raw = json.loads(row["notes_json"])
        notes = [CaseNote(**n) for n in notes_raw]

        tl_raw = json.loads(row["timeline_json"])
        timeline = [CaseTimelineEvent(**t) for t in tl_raw]

        return IncidentCase(
            case_id=row["case_id"],
            title=row["title"],
            description=row["description"],
            status=CaseStatus(row["status"]),
            severity=CaseSeverity(row["severity"]),
            priority=CasePriority(row["priority"]),
            assigned_to=row["assigned_to"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            linked_alert_ids=json.loads(row["linked_alert_ids_json"]),
            linked_incident_ids=json.loads(row["linked_incident_ids_json"]),
            evidence_ids=json.loads(row["evidence_ids_json"]),
            related_indicators=json.loads(row["related_indicators_json"]),
            notes=notes,
            timeline=timeline,
            closure_reason=row["closure_reason"],
            closure_timestamp=row["closure_timestamp"],
            reopen_count=row["reopen_count"],
            reopen_history=json.loads(row["reopen_history_json"]),
        )
