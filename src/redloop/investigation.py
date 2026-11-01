"""Investigation-first architecture for REDLOOP cybersecurity platform.

Unifies Chat, Workbench, Tasks, Evidence, Findings, Timeline, and Reports
under a persistent, shared investigation context.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TimelineEvent:
    id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:8]}")
    timestamp: str = field(default_factory=utc_now_iso)
    event_type: str = "activity"  # scope, tool, finding, evidence, task, note
    title: str = ""
    description: str = ""
    severity: str = "INFO"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Investigation:
    id: str = field(default_factory=lambda: f"inv-{uuid.uuid4().hex[:8]}")
    title: str = "Default Security Assessment"
    target: str = "127.0.0.1"
    scope_status: str = "AUTHORIZED"  # AUTHORIZED, PARTIALLY_AUTHORIZED, UNAUTHORIZED, UNKNOWN
    objective: str = "Identify open ports, services, security misconfigurations, and evaluate attack surface."
    conversation_id: str = "default"
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    status: str = "ACTIVE"  # ACTIVE, PAUSED, COMPLETED, ARCHIVED
    task_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    reports: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""
    tags: list[str] = field(default_factory=lambda: ["local-assessment", "authorized"])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def add_event(self, event_type: str, title: str, description: str = "", severity: str = "INFO", meta: dict[str, Any] | None = None) -> None:
        evt = TimelineEvent(
            event_type=event_type,
            title=title,
            description=description,
            severity=severity,
            metadata=meta or {},
        )
        self.timeline.append(evt.to_dict())
        self.updated_at = utc_now_iso()


class InvestigationStore:
    """Persistent SQLite store for Investigations."""

    def __init__(self, db_path: str | Path = "data/investigations.sqlite"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._ensure_default_investigation()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    target TEXT NOT NULL,
                    scope_status TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    data_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_inv_target ON investigations(target)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_inv_status ON investigations(status)"
            )
            conn.commit()

    def _ensure_default_investigation(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM investigations")
            if cursor.fetchone()[0] == 0:
                default_inv = Investigation(
                    id="inv-default",
                    title="Authorized Local Assessment",
                    target="127.0.0.1",
                    scope_status="AUTHORIZED",
                    objective="Initial discovery, port reconnaissance, and local-first security posture evaluation.",
                    conversation_id="default",
                )
                default_inv.add_event(
                    event_type="scope",
                    title="Investigation Initialized",
                    description="Investigation initialized for target 127.0.0.1 with authorized local scope contract.",
                )
                self.save(default_inv)


    def save(self, inv: Investigation) -> None:
        inv.updated_at = utc_now_iso()
        data_json = json.dumps(inv.to_dict())
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO investigations (id, title, target, scope_status, objective,
                                           conversation_id, created_at, updated_at, status, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title,
                    target=excluded.target,
                    scope_status=excluded.scope_status,
                    objective=excluded.objective,
                    conversation_id=excluded.conversation_id,
                    updated_at=excluded.updated_at,
                    status=excluded.status,
                    data_json=excluded.data_json
                """,
                (
                    inv.id,
                    inv.title,
                    inv.target,
                    inv.scope_status,
                    inv.objective,
                    inv.conversation_id,
                    inv.created_at,
                    inv.updated_at,
                    inv.status,
                    data_json,
                ),
            )
            conn.commit()

    def get(self, inv_id: str) -> Investigation | None:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT data_json FROM investigations WHERE id = ?", (inv_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = json.loads(row["data_json"])
            return Investigation(**data)

    def get_active(self) -> Investigation:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT data_json FROM investigations WHERE status = 'ACTIVE' ORDER BY updated_at DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if row:
                return Investigation(**json.loads(row["data_json"]))
        self._ensure_default_investigation()
        return self.get("inv-default") or Investigation(id="inv-default")

    def list_all(self, limit: int = 50) -> list[Investigation]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT data_json FROM investigations ORDER BY updated_at DESC LIMIT ?", (limit,)
            )
            results = []
            for row in cursor.fetchall():
                try:
                    results.append(Investigation(**json.loads(row["data_json"])))
                except Exception:
                    continue
            return results

    def link_finding(self, inv_id: str, finding_id: str) -> None:
        inv = self.get(inv_id)
        if inv and finding_id not in inv.finding_ids:
            inv.finding_ids.append(finding_id)
            inv.add_event("finding", f"Finding Linked: {finding_id}", meta={"finding_id": finding_id})
            self.save(inv)

    def link_evidence(self, inv_id: str, evidence_id: str) -> None:
        inv = self.get(inv_id)
        if inv and evidence_id not in inv.evidence_ids:
            inv.evidence_ids.append(evidence_id)
            inv.add_event("evidence", f"Evidence Linked: {evidence_id}", meta={"evidence_id": evidence_id})
            self.save(inv)

    def link_task(self, inv_id: str, task_id: str) -> None:
        inv = self.get(inv_id)
        if inv and task_id not in inv.task_ids:
            inv.task_ids.append(task_id)
            self.save(inv)


_DEFAULT_INVESTIGATION_STORE: InvestigationStore | None = None


def get_investigation_store(db_path: str | Path | None = None) -> InvestigationStore:
    global _DEFAULT_INVESTIGATION_STORE
    if _DEFAULT_INVESTIGATION_STORE is None or db_path is not None:
        _DEFAULT_INVESTIGATION_STORE = InvestigationStore(db_path or "data/investigations.sqlite")
    return _DEFAULT_INVESTIGATION_STORE
