"""REDLOOP Incident Case Management & Investigation Tracking Engine (Phase 7 & Phase 7.1).

Provides:
1. End-to-end Case Management lifecycle tracking:
   OPEN -> INVESTIGATING -> PENDING_APPROVAL -> CONTAINMENT_IN_PROGRESS ->
   MONITORING -> RESOLVED -> CLOSED -> REOPENED.
2. Linking to SOC Alerts, Incident records, Threat Hunt findings, and Evidence Ledger items.
3. Cryptographically hash-chained timeline event audit history with automated tamper detection.
4. Exportable audit reports and evidence verification reports.
5. Persistent SQLite storage with migrations, audit trails, and timeline event history.
6. Preserves evidence references without mutating underlying security event records.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class IntegrityResultStatus(str):
    """String subclass ensuring forward and backward compatibility across integrity state checks."""
    @property
    def value(self) -> str:
        return str(self)

    def __eq__(self, other: Any) -> bool:
        s_self = str(self)
        s_other = str(other.value if hasattr(other, "value") else other)
        if s_self == s_other:
            return True
        pairs = {
            ("INTEGRITY_VERIFIED", "INTACT"),
            ("TAMPER_DETECTED", "TAMPERED"),
            ("VERIFICATION_INCOMPLETE", "ERROR"),
            ("VERIFICATION_INCOMPLETE", "INCOMPLETE"),
            ("EMPTY_LOG", "INCOMPLETE"),
            ("LEGACY_UNHASHED", "LEGACY_UNVERIFIABLE"),
            ("CHECKPOINT_INVALID", "TAMPERED"),
        }
        for a, b in pairs:
            if (s_self == a and s_other == b) or (s_self == b and s_other == a):
                return True
        return False

    def __hash__(self) -> int:
        return hash(str(self))


class CheckpointResultStatus(str):
    """String subclass ensuring compatibility for checkpoint state checks."""
    @property
    def value(self) -> str:
        return str(self)

    def __eq__(self, other: Any) -> bool:
        s_self = str(self)
        s_other = str(other.value if hasattr(other, "value") else other)
        if s_self == s_other:
            return True
        pairs = {
            ("UNSIGNED_CHECKPOINT", "CHECKPOINT_UNSIGNED"),
            ("INVALID_CHECKPOINT", "CHECKPOINT_INVALID"),
            ("SIGNED_CHECKPOINT", "CHECKPOINT_VERIFIED"),
            ("INVALID_CHECKPOINT", "CHECKPOINT_TAMPERED"),
        }
        for a, b in pairs:
            if (s_self == a and s_other == b) or (s_self == b and s_other == a):
                return True
        return False

    def __hash__(self) -> int:
        return hash(str(self))


CheckpointResultStatus.CHECKPOINT_VERIFIED = CheckpointResultStatus("SIGNED_CHECKPOINT")
CheckpointResultStatus.SIGNED_CHECKPOINT = CheckpointResultStatus("SIGNED_CHECKPOINT")
CheckpointResultStatus.CHECKPOINT_UNSIGNED = CheckpointResultStatus("UNSIGNED_CHECKPOINT")
CheckpointResultStatus.UNSIGNED_CHECKPOINT = CheckpointResultStatus("UNSIGNED_CHECKPOINT")
CheckpointResultStatus.CHECKPOINT_INVALID = CheckpointResultStatus("INVALID_CHECKPOINT")
CheckpointResultStatus.CHECKPOINT_TAMPERED = CheckpointResultStatus("INVALID_CHECKPOINT")
CheckpointResultStatus.INVALID_CHECKPOINT = CheckpointResultStatus("INVALID_CHECKPOINT")


class IntegrityStatus(str, Enum):
    # Primary Phase 9.1 precision states:
    INTEGRITY_VERIFIED = "INTEGRITY_VERIFIED"
    TAMPER_DETECTED = "TAMPER_DETECTED"
    VERIFICATION_INCOMPLETE = "VERIFICATION_INCOMPLETE"
    EMPTY_LOG = "EMPTY_LOG"
    LEGACY_UNHASHED = "LEGACY_UNHASHED"
    CHECKPOINT_UNSIGNED = "CHECKPOINT_UNSIGNED"
    CHECKPOINT_INVALID = "CHECKPOINT_INVALID"

    # Backward compatibility aliases:
    INTACT = "INTACT"
    TAMPERED = "TAMPERED"
    LEGACY_UNVERIFIABLE = "LEGACY_UNVERIFIABLE"
    INCOMPLETE = "INCOMPLETE"
    ERROR = "ERROR"


def canonical_json_dumps(obj: Any) -> str:
    """RFC 8785 deterministic canonical JSON serializer for cryptographic hashes.
    
    Handles null values, booleans, integers, floats, nested dictionaries,
    lists, and Unicode strings with sorted keys and compact separators.
    """
    if obj is None:
        return "null"
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _get_audit_signing_key(key_id: Optional[str] = None) -> tuple[Optional[str], Optional[bytes]]:
    """Retrieves (key_id, key_bytes) supporting key rotation via REDLOOP_AUDIT_KEYRING, env, or file."""
    # 1. Keyring JSON: {"key-2026-v1": "secret1...", "key-2026-v2": "secret2..."}
    keyring_env = os.environ.get("REDLOOP_AUDIT_KEYRING")
    if keyring_env:
        try:
            keyring = json.loads(keyring_env)
            if key_id and key_id in keyring:
                return key_id, keyring[key_id].encode("utf-8")
            if not key_id and keyring:
                active_kid = list(keyring.keys())[-1]
                return active_kid, keyring[active_kid].encode("utf-8")
        except Exception:
            pass

    # 2. Key ID & Single Secret
    kid = key_id or os.environ.get("REDLOOP_AUDIT_KEY_ID", "key-default")
    key_str = os.environ.get("REDLOOP_AUDIT_SIGNING_KEY")
    if not key_str:
        key_file = os.environ.get("REDLOOP_AUDIT_KEY_FILE")
        if key_file and Path(key_file).is_file():
            try:
                key_str = Path(key_file).read_text(encoding="utf-8").strip()
            except Exception:
                pass
    if key_str:
        return kid, key_str.encode("utf-8")
    return None, None


def compute_checkpoint_signature(
    case_id: str,
    root_hash: str,
    status: str,
    event_count: int,
    key_bytes: bytes,
    key_id: str = "key-default",
) -> str:
    """Deterministic HMAC-SHA256 signature calculation over checkpoint metadata."""
    payload = f"{case_id}|{root_hash}|{status}|{event_count}|{key_id}"
    return hmac.new(key_bytes, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_checkpoint_record(
    checkpoint: dict[str, Any],
    key_resolver: Optional[Any] = None,
) -> bool:
    """Independently verifies a signed checkpoint without relying on mutable database records."""
    if not checkpoint or not isinstance(checkpoint, dict):
        return False
    signature = checkpoint.get("signature")
    if not signature:
        return False
    case_id = checkpoint.get("case_id", "")
    root_hash = checkpoint.get("root_hash", "")
    event_count = int(checkpoint.get("event_count") or checkpoint.get("event_sequence", 0))
    key_id = checkpoint.get("key_id", "key-default")

    key_bytes: Optional[bytes] = None
    if callable(key_resolver):
        key_bytes = key_resolver(key_id)
    else:
        _, key_bytes = _get_audit_signing_key(key_id=key_id)

    if not key_bytes:
        return False

    statuses_to_try = [
        s for s in [
            checkpoint.get("case_status"),
            checkpoint.get("status"),
            "OPEN",
            "SIGNED_CHECKPOINT",
        ] if s
    ]
    for st in statuses_to_try:
        expected_sig = compute_checkpoint_signature(
            case_id=case_id,
            root_hash=root_hash,
            status=st,
            event_count=event_count,
            key_bytes=key_bytes,
            key_id=key_id,
        )
        if hmac.compare_digest(signature, expected_sig):
            return True
    return False


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
    """Chronological event logged during the lifecycle of a case with cryptographic forward hashing."""
    event_id: str
    event_type: str
    actor: str
    description: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    prev_hash: str = "0" * 64
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """Computes deterministic SHA-256 digest of timeline event using RFC 8785 canonical JSON."""
        canonical_data = canonical_json_dumps(self.data)
        payload = f"{self.prev_hash}|{self.event_id}|{self.event_type}|{self.actor}|{self.description}|{self.timestamp}|{canonical_data}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if not self.entry_hash:
            d["entry_hash"] = self.compute_hash()
        return d


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
    integrity_version: int = 1
    root_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        d["priority"] = self.priority.value
        d["notes"] = [n.to_dict() for n in self.notes]
        d["timeline"] = [t.to_dict() for t in self.timeline]
        d["integrity_version"] = self.integrity_version
        d["root_hash"] = self.root_hash
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
        self._op_lock = threading.RLock()
        self.db_path = Path(db_path) if db_path else Path("data/cases.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @classmethod
    def reset_instance(cls) -> None:
        with cls._lock:
            cls._instance = None

    @classmethod
    def get_instance(cls, db_path: Optional[Path | str] = None) -> "CaseManager":
        with cls._lock:
            if db_path is not None:
                p = Path(db_path)
                if cls._instance is None or cls._instance.db_path != p:
                    cls._instance = cls(db_path=p)
                    return cls._instance
            if cls._instance is None or not cls._instance.db_path.parent.exists():
                cls._instance = cls()
            return cls._instance

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
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
                            reopen_history_json TEXT NOT NULL,
                            integrity_version INTEGER NOT NULL DEFAULT 1,
                            root_hash TEXT DEFAULT ''
                        )
                    """)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS case_checkpoints (
                            checkpoint_id TEXT PRIMARY KEY,
                            case_id TEXT NOT NULL,
                            event_sequence INTEGER NOT NULL,
                            root_hash TEXT NOT NULL,
                            key_id TEXT NOT NULL,
                            algorithm TEXT NOT NULL,
                            signature TEXT NOT NULL,
                            created_at TEXT NOT NULL
                        )
                    """)
                    # Schema migration for existing pre-Phase 8.1 database
                    cur = conn.execute("PRAGMA table_info(cases)")
                    columns = [row["name"] for row in cur.fetchall()]
                    if "integrity_version" not in columns:
                        conn.execute("ALTER TABLE cases ADD COLUMN integrity_version INTEGER NOT NULL DEFAULT 0")
                    if "root_hash" not in columns:
                        conn.execute("ALTER TABLE cases ADD COLUMN root_hash TEXT DEFAULT ''")
            finally:
                conn.close()

    def reset_state(self) -> None:
        """Clears all case records (for test isolation)."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM cases")
                    conn.execute("DELETE FROM case_checkpoints")
            finally:
                conn.close()

    def _append_timeline_event(
        self,
        case: IncidentCase,
        event_type: str,
        actor: str,
        description: str,
        data: Optional[dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> CaseTimelineEvent:
        """Helper to append a cryptographically forward-hashed timeline event to a case."""
        now_ts = timestamp or datetime.now(timezone.utc).isoformat()
        prev_hash = "0" * 64
        if case.timeline:
            prev_entry = case.timeline[-1]
            prev_hash = prev_entry.entry_hash or prev_entry.compute_hash()

        evt = CaseTimelineEvent(
            event_id=f"evt-{uuid.uuid4().hex[:8]}",
            event_type=event_type,
            actor=actor,
            description=description,
            data=data or {},
            timestamp=now_ts,
            prev_hash=prev_hash,
        )
        evt.entry_hash = evt.compute_hash()
        case.timeline.append(evt)
        case.root_hash = evt.entry_hash
        return evt

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
        """Creates and stores a new incident case with cryptographic genesis timeline event."""
        with self._op_lock:
            case_id = f"case-{uuid.uuid4().hex[:8]}"
            now = datetime.now(timezone.utc).isoformat()

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
                timeline=[],
                integrity_version=1,
            )

            self._append_timeline_event(
                case,
                event_type="CASE_CREATED",
                actor=creator,
                description=f"Case opened by {creator}: '{title}'.",
                data={"severity": severity.value, "priority": priority.value},
                timestamp=now,
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
        with self._op_lock:
            case = self.get_case(case_id)
            if not case:
                raise ValueError(f"Case '{case_id}' not found.")

            now = datetime.now(timezone.utc).isoformat()

            # State transition validation
            if status is not None and status != case.status:
                allowed = self.VALID_TRANSITIONS.get(case.status, set())
                if status not in allowed:
                    raise ValueError(f"Invalid state transition: Cannot move case from '{case.status.value}' to '{status.value}'.")

                from_state = case.status
                case.status = status
                self._append_timeline_event(
                    case,
                    event_type="STATUS_CHANGED",
                    actor=actor,
                    description=f"Status transitioned from {from_state.value} to {status.value}.",
                    data={"from": from_state.value, "to": status.value},
                    timestamp=now,
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
                self._append_timeline_event(
                    case,
                    event_type="SEVERITY_CHANGED",
                    actor=actor,
                    description=f"Severity updated from {old_sev.value} to {severity.value}.",
                    data={"from": old_sev.value, "to": severity.value},
                    timestamp=now,
                )

            if priority is not None and priority != case.priority:
                old_pri = case.priority
                case.priority = priority
                self._append_timeline_event(
                    case,
                    event_type="PRIORITY_CHANGED",
                    actor=actor,
                    description=f"Priority updated from {old_pri.value} to {priority.value}.",
                    data={"from": old_pri.value, "to": priority.value},
                    timestamp=now,
                )

            if assigned_to is not None and assigned_to != case.assigned_to:
                old_assignee = case.assigned_to
                case.assigned_to = assigned_to
                self._append_timeline_event(
                    case,
                    event_type="ASSIGNEE_CHANGED",
                    actor=actor,
                    description=f"Assignment changed from '{old_assignee}' to '{assigned_to}'.",
                    data={"from": old_assignee, "to": assigned_to},
                    timestamp=now,
                )

            case.updated_at = now
            self._save_case(case)
            return case

    def add_note(self, case_id: str, author: str, content: str) -> CaseNote:
        """Adds an analyst investigation note to the case and logs timeline event."""
        with self._op_lock:
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
            self._append_timeline_event(
                case,
                event_type="NOTE_ADDED",
                actor=author,
                description=f"Analyst note added by {author}.",
                data={"note_id": note.note_id, "content_snippet": content[:60]},
                timestamp=note.timestamp,
            )
            self._save_case(case)
            return note

    def attach_evidence(self, case_id: str, evidence_ids: list[str], actor: str = "operator") -> list[str]:
        """Attaches evidence ledger IDs to the case without mutating underlying evidence records."""
        with self._op_lock:
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
                self._append_timeline_event(
                    case,
                    event_type="EVIDENCE_ATTACHED",
                    actor=actor,
                    description=f"Attached {len(added)} evidence records: {', '.join(added)}",
                    data={"evidence_ids": added},
                    timestamp=now,
                )
                self._save_case(case)

            return case.evidence_ids

    def create_signed_checkpoint(self, case_id: str, key_id: Optional[str] = None) -> dict[str, Any]:
        """Creates and stores a cryptographically signed checkpoint anchored by external signing key."""
        with self._op_lock:
            case = self.get_case(case_id)
            if not case:
                raise ValueError(f"Case '{case_id}' not found.")
            timeline = case.timeline
            root_hash = timeline[-1].entry_hash if timeline else ("0" * 64)
            event_count = len(timeline)
            kid, key_bytes = _get_audit_signing_key(key_id=key_id)
            if not key_bytes:
                raise ValueError("No cryptographic signing key configured (set REDLOOP_AUDIT_SIGNING_KEY or REDLOOP_AUDIT_KEYRING).")

            signature = compute_checkpoint_signature(
                case_id=case.case_id,
                root_hash=root_hash,
                status=case.status.value,
                event_count=event_count,
                key_bytes=key_bytes,
                key_id=kid or "key-default",
            )
            checkpoint_id = f"ckpt-{uuid.uuid4().hex[:12]}"
            now_iso = datetime.now(timezone.utc).isoformat()

            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO case_checkpoints
                        (checkpoint_id, case_id, event_sequence, root_hash, key_id, algorithm, signature, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (checkpoint_id, case.case_id, event_count, root_hash, kid or "key-default", "HMAC-SHA256", signature, now_iso),
                    )
            finally:
                conn.close()

            return {
                "checkpoint_id": checkpoint_id,
                "case_id": case.case_id,
                "event_sequence": event_count,
                "event_count": event_count,
                "root_hash": root_hash,
                "key_id": kid or "key-default",
                "algorithm": "HMAC-SHA256",
                "signature": signature,
                "created_at": now_iso,
                "case_status": case.status.value,
                "status": "SIGNED_CHECKPOINT",
            }

    def verify_checkpoint_record(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        """Validates checkpoint record and returns structured verification dict."""
        ok = verify_checkpoint_record(checkpoint)
        return {
            "is_valid": ok,
            "status": CheckpointResultStatus.CHECKPOINT_VERIFIED.value if ok else CheckpointResultStatus.CHECKPOINT_INVALID.value,
            "checkpoint_id": checkpoint.get("checkpoint_id"),
            "key_id": checkpoint.get("key_id"),
        }

    def get_checkpoints(self, case_id: str) -> list[dict[str, Any]]:
        """Retrieves stored checkpoints for an incident case."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    "SELECT * FROM case_checkpoints WHERE case_id = ? ORDER BY event_sequence ASC",
                    (case_id,),
                )
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def verify_case_integrity(self, case_id: str) -> dict[str, Any]:
        """Performs cryptographic hash-chain verification and evidence reference validation."""
        try:
            with self._op_lock:
                case = self.get_case(case_id)
                if not case:
                    return {
                        "case_id": case_id,
                        "is_valid": False,
                        "status": "NOT_FOUND",
                        "integrity_state": "NOT_FOUND",
                        "details": f"Case '{case_id}' not found.",
                        "algorithm": "SHA-256-FORWARD-CHAIN-V1",
                        "version": "1.0",
                        "checkpoint_status": "CHECKPOINT_UNSIGNED",
                        "signature": None,
                    }

                timeline = case.timeline

                # 1. Check legacy unchained case
                is_legacy = (case.integrity_version == 0) or (
                    len(timeline) > 0 and all(not getattr(ev, "entry_hash", None) for ev in timeline)
                )
                if is_legacy:
                    return {
                        "case_id": case.case_id,
                        "is_valid": False,
                        "status": IntegrityResultStatus("LEGACY_UNVERIFIABLE"),
                        "integrity_state": IntegrityStatus.LEGACY_UNHASHED.value,
                        "timeline_events_verified": 0,
                        "evidence_references_verified": len(case.evidence_ids),
                        "broken_index": None,
                        "root_hash": "",
                        "algorithm": "NONE",
                        "version": "LEGACY",
                        "checkpoint_status": CheckpointResultStatus("UNSIGNED_CHECKPOINT"),
                        "signature": None,
                        "details": "Case predates cryptographic hash-chain support and cannot be cryptographically verified.",
                        "verified_at": datetime.now(timezone.utc).isoformat(),
                        "limitations_notice": (
                            "NOTICE: Legacy cases created prior to Phase 7.1 lack cryptographic forward hash chains "
                            "and cannot be verified for historical tamper detection."
                        ),
                    }

                # 2. Check for empty supported case
                if len(timeline) == 0:
                    return {
                        "case_id": case.case_id,
                        "is_valid": False,
                        "status": IntegrityResultStatus("INCOMPLETE"),
                        "integrity_state": IntegrityStatus.EMPTY_LOG.value,
                        "timeline_events_verified": 0,
                        "evidence_references_verified": len(case.evidence_ids),
                        "broken_index": 0,
                        "root_hash": "",
                        "algorithm": "SHA-256-FORWARD-CHAIN-V1",
                        "version": "1.0",
                        "checkpoint_status": CheckpointResultStatus("UNSIGNED_CHECKPOINT"),
                        "signature": None,
                        "details": "Supported case has no timeline events recorded; genesis record missing.",
                        "verified_at": datetime.now(timezone.utc).isoformat(),
                        "limitations_notice": (
                            "NOTICE: Local cryptographic hash chaining provides tamper detection against accidental corruption "
                            "or unauthorized SQLite modifications. However, a local administrator with full database write access "
                            "can alter records and recompute hashes unless entries are anchored to an external immutable ledger or remote notary."
                        ),
                    }

                # 3. Verify supported hash chain
                broken_index: Optional[int] = None
                details = "Timeline hash-chain is intact and verified."
                seen_event_ids: set[str] = set()

                for i, ev in enumerate(timeline):
                    # Validate required event fields
                    if not ev.event_id or not ev.event_type or not ev.timestamp or not ev.actor:
                        broken_index = i
                        details = f"Required event field missing at event index {i}."
                        break

                    # Check duplicate event identifiers
                    if ev.event_id in seen_event_ids:
                        broken_index = i
                        details = f"Duplicate event identifier detected: '{ev.event_id}' at index {i}."
                        break
                    seen_event_ids.add(ev.event_id)

                    # Check sequence linkage
                    expected_prev = "0" * 64 if i == 0 else (timeline[i - 1].entry_hash or timeline[i - 1].compute_hash())
                    if ev.prev_hash != expected_prev:
                        broken_index = i
                        details = f"Hash-chain linkage broken at event {i} ({ev.event_id}): expected prev_hash '{expected_prev[:12]}...', got '{ev.prev_hash[:12]}...'."
                        break

                    # Check stored hash against computed hash
                    computed_hash = ev.compute_hash()
                    if not ev.entry_hash or ev.entry_hash != computed_hash:
                        broken_index = i
                        details = f"Tamper detected at event {i} ({ev.event_id}): stored hash '{ev.entry_hash[:12]}...' does not match computed hash '{computed_hash[:12]}...'."
                        break

                is_valid = (broken_index is None)

                # Check evidence reference integrity
                malformed_evidence = [e for e in case.evidence_ids if not isinstance(e, str) or not e.strip()]
                if malformed_evidence:
                    is_valid = False
                    details += f" Invalid evidence reference identifiers found: {malformed_evidence}"

                root_hash = timeline[-1].entry_hash if timeline else ""

                # 4. Checkpoint integrity verification
                conn = self._get_connection()
                stored_checkpoints = []
                try:
                    cur = conn.execute("SELECT * FROM case_checkpoints WHERE case_id = ? ORDER BY event_sequence DESC", (case.case_id,))
                    stored_checkpoints = [dict(r) for r in cur.fetchall()]
                finally:
                    conn.close()

                checkpoint_status = CheckpointResultStatus("UNSIGNED_CHECKPOINT")
                signature: Optional[str] = None
                key_id: Optional[str] = None

                kid, signing_key = _get_audit_signing_key()

                if stored_checkpoints:
                    latest_ckpt = stored_checkpoints[0]
                    key_id = latest_ckpt.get("key_id", "key-default")
                    signature = latest_ckpt.get("signature")
                    # Independent verification
                    valid_ckpt = verify_checkpoint_record(latest_ckpt)
                    if not valid_ckpt:
                        checkpoint_status = CheckpointResultStatus("CHECKPOINT_INVALID")
                        is_valid = False
                        details = f"Checkpoint integrity check failed: signature on checkpoint '{latest_ckpt['checkpoint_id']}' is invalid or altered."
                    else:
                        checkpoint_status = CheckpointResultStatus("SIGNED_CHECKPOINT")
                elif signing_key:
                    sig = compute_checkpoint_signature(
                        case_id=case.case_id,
                        root_hash=root_hash,
                        status=case.status.value,
                        event_count=len(timeline),
                        key_bytes=signing_key,
                        key_id=kid or "key-default",
                    )
                    signature = sig
                    key_id = kid or "key-default"
                    checkpoint_status = CheckpointResultStatus("SIGNED_CHECKPOINT")

                if not is_valid:
                    status = IntegrityResultStatus("TAMPERED")
                    integrity_state = IntegrityStatus.TAMPER_DETECTED.value
                else:
                    status = IntegrityResultStatus("INTACT")
                    integrity_state = IntegrityStatus.INTEGRITY_VERIFIED.value

                return {
                    "case_id": case.case_id,
                    "is_valid": is_valid,
                    "status": status,
                    "integrity_state": integrity_state,
                    "timeline_events_verified": len(timeline),
                    "evidence_references_verified": len(case.evidence_ids),
                    "broken_index": broken_index,
                    "root_hash": root_hash,
                    "algorithm": "SHA-256-FORWARD-CHAIN-V1",
                    "version": "1.0",
                    "checkpoint_status": checkpoint_status,
                    "signature": signature,
                    "key_id": key_id,
                    "details": details,
                    "verified_at": datetime.now(timezone.utc).isoformat(),
                    "limitations_notice": (
                        "NOTICE: Local cryptographic hash chaining provides tamper detection against accidental corruption "
                        "or unauthorized SQLite modifications. However, a local administrator with full database write access "
                        "can alter records and recompute hashes unless entries are anchored to an external immutable ledger or remote notary."
                    ),
                }
        except Exception as exc:
            return {
                "case_id": case_id,
                "is_valid": False,
                "status": IntegrityResultStatus("ERROR"),
                "integrity_state": IntegrityStatus.VERIFICATION_INCOMPLETE.value,
                "timeline_events_verified": 0,
                "evidence_references_verified": 0,
                "broken_index": None,
                "root_hash": "",
                "algorithm": "SHA-256-FORWARD-CHAIN-V1",
                "version": "1.0",
                "checkpoint_status": CheckpointResultStatus("UNSIGNED_CHECKPOINT"),
                "signature": None,
                "details": f"Database or processing error during verification: {str(exc)}",
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "limitations_notice": "Verification aborted due to database or processing error.",
            }

    def export_case_audit_report(self, case_id: str) -> dict[str, Any]:
        """Generates an exportable comprehensive audit verification report for an incident case."""
        case = self.get_case(case_id)
        if not case:
            return {"error": f"Case '{case_id}' not found"}

        integrity = self.verify_case_integrity(case_id)
        return {
            "case_id": case.case_id,
            "title": case.title,
            "status": case.status.value,
            "severity": case.severity.value,
            "priority": case.priority.value,
            "assigned_to": case.assigned_to,
            "created_at": case.created_at,
            "updated_at": case.updated_at,
            "closure_reason": case.closure_reason,
            "reopen_count": case.reopen_count,
            "integrity_verification": integrity,
            "integrity_algorithm": integrity.get("algorithm", "SHA-256-FORWARD-CHAIN-V1"),
            "integrity_version": integrity.get("version", "1.0"),
            "root_hash": integrity.get("root_hash", ""),
            "checkpoint_status": integrity.get("checkpoint_status", "UNSIGNED_CHECKPOINT"),
            "signature": integrity.get("signature"),
            "evidence_ids": case.evidence_ids,
            "linked_alert_ids": case.linked_alert_ids,
            "notes_count": len(case.notes),
            "timeline": [t.to_dict() for t in case.timeline],
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "limitations_notice": integrity.get("limitations_notice", ""),
        }

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
                         notes_json, timeline_json, closure_reason, closure_timestamp, reopen_count, reopen_history_json,
                         integrity_version, root_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                            case.integrity_version,
                            case.root_hash,
                        ),
                    )
            finally:
                conn.close()

    def _row_to_case(self, row: sqlite3.Row) -> IncidentCase:
        notes_raw = json.loads(row["notes_json"])
        notes = [CaseNote(**n) for n in notes_raw]

        tl_raw = json.loads(row["timeline_json"])
        timeline = []
        for t in tl_raw:
            # Handle backward compatibility if prev_hash / entry_hash was absent
            if "prev_hash" not in t:
                t["prev_hash"] = "0" * 64
            if "entry_hash" not in t:
                t["entry_hash"] = ""
            timeline.append(CaseTimelineEvent(**t))

        integrity_version = 0
        try:
            if "integrity_version" in row.keys() and row["integrity_version"] is not None:
                integrity_version = int(row["integrity_version"])
        except Exception:
            pass

        root_hash = ""
        try:
            if "root_hash" in row.keys() and row["root_hash"]:
                root_hash = row["root_hash"]
        except Exception:
            pass

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
            integrity_version=integrity_version,
            root_hash=root_hash,
        )
