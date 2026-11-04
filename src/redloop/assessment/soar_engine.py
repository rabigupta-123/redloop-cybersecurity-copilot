"""REDLOOP SOAR Workflow Engine & Incident Response Orchestration (Phase 7).

Provides:
1. Production-minded local SOAR workflow execution and state machine.
2. 11 Validated Workflow States: DRAFT, VALIDATED, READY, RUNNING, WAITING_FOR_APPROVAL,
   PAUSED, COMPLETED, PARTIAL, FAILED, CANCELLED, BLOCKED.
3. Event-driven triggers with deduplication keys preventing duplicate automated runs.
4. Approval-gated containment steps requiring cryptographic capability tokens.
5. Persistent execution history in SQLite with cancellation, timeout, and audit logging.
6. 10 Built-in Incident Response Playbooks covering identity, web, endpoint, and network threats.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from redloop.assessment.soar_actions import (
    ActionCategory,
    ActionExecutionStatus,
    ActionResult,
    SOARActionRegistry,
)


class WorkflowState(str, Enum):
    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    READY = "READY"
    RUNNING = "RUNNING"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    BLOCKED = "BLOCKED"
    TIMED_OUT = "TIMED_OUT"


class TriggerType(str, Enum):
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    HUNT = "HUNT"
    SIGMA = "SIGMA"
    INTEL = "INTEL"
    MANUAL = "MANUAL"


@dataclass
class WorkflowTrigger:
    """Trigger event initiating a SOAR workflow execution."""
    trigger_id: str
    trigger_type: TriggerType
    source_record_id: str
    event_timestamp: str
    target_context: str
    provenance: str
    deduplication_key: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["trigger_type"] = self.trigger_type.value
        return d


@dataclass
class WorkflowStep:
    """Individual typed execution step within a SOAR workflow."""
    step_id: str
    step_name: str
    action_name: str  # Must map to SOARActionRegistry
    category: ActionCategory
    parameters: dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    is_containment: bool = False
    max_retries: int = 1
    timeout_seconds: float = 30.0
    status: str = "PENDING"
    result: Optional[dict[str, Any]] = None
    approval_capability_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        return d


@dataclass
class SOARWorkflow:
    """Declarative SOAR workflow definition."""
    workflow_id: str
    title: str
    version: str
    description: str
    trigger_types: list[TriggerType]
    steps: list[WorkflowStep]
    state: WorkflowState = WorkflowState.READY
    required_telemetry: list[str] = field(default_factory=list)
    closure_criteria: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        d["trigger_types"] = [t.value for t in self.trigger_types]
        d["steps"] = [s.to_dict() for s in self.steps]
        return d


@dataclass
class WorkflowExecutionRecord:
    """Auditable execution instance of a SOAR workflow."""
    execution_id: str
    workflow_id: str
    workflow_title: str
    trigger: dict[str, Any]
    state: WorkflowState
    current_step_index: int
    total_steps: int
    executed_steps: list[dict[str, Any]]
    evidence_ids: list[str]
    error_message: Optional[str] = None
    cancelled_by: Optional[str] = None
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        return d


class SOAREngine:
    """Local SOAR execution orchestrator with state validation and persistence."""

    _instance: Optional["SOAREngine"] = None
    _lock = threading.Lock()

    # Allowed valid state transitions
    VALID_TRANSITIONS: dict[WorkflowState, set[WorkflowState]] = {
        WorkflowState.DRAFT: {WorkflowState.VALIDATED, WorkflowState.FAILED},
        WorkflowState.VALIDATED: {WorkflowState.READY, WorkflowState.DRAFT},
        WorkflowState.READY: {WorkflowState.RUNNING, WorkflowState.CANCELLED, WorkflowState.BLOCKED},
        WorkflowState.RUNNING: {
            WorkflowState.WAITING_FOR_APPROVAL,
            WorkflowState.PAUSED,
            WorkflowState.COMPLETED,
            WorkflowState.PARTIAL,
            WorkflowState.FAILED,
            WorkflowState.CANCELLED,
            WorkflowState.BLOCKED,
        },
        WorkflowState.WAITING_FOR_APPROVAL: {
            WorkflowState.RUNNING,
            WorkflowState.CANCELLED,
            WorkflowState.BLOCKED,
            WorkflowState.FAILED,
            WorkflowState.TIMED_OUT,
        },
        WorkflowState.PAUSED: {WorkflowState.RUNNING, WorkflowState.CANCELLED},
        WorkflowState.COMPLETED: set(),
        WorkflowState.PARTIAL: set(),
        WorkflowState.FAILED: {WorkflowState.READY},  # Retry allowed
        WorkflowState.CANCELLED: set(),
        WorkflowState.BLOCKED: {WorkflowState.READY},
    }

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self._op_lock = threading.RLock()
        self.db_path = Path(db_path) if db_path else Path("data/soar.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._WORKFLOWS: dict[str, SOARWorkflow] = {}
        self._initialize_builtins()

    @classmethod
    def get_instance(cls, db_path: Optional[Path | str] = None) -> "SOAREngine":
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
                        CREATE TABLE IF NOT EXISTS soar_executions (
                            execution_id TEXT PRIMARY KEY,
                            workflow_id TEXT NOT NULL,
                            workflow_title TEXT NOT NULL,
                            trigger_json TEXT NOT NULL,
                            state TEXT NOT NULL,
                            current_step_index INTEGER NOT NULL,
                            total_steps INTEGER NOT NULL,
                            executed_steps_json TEXT NOT NULL,
                            evidence_ids_json TEXT NOT NULL,
                            error_message TEXT,
                            cancelled_by TEXT,
                            started_at TEXT NOT NULL,
                            completed_at TEXT
                        )
                    """)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS soar_trigger_dedup (
                            deduplication_key TEXT PRIMARY KEY,
                            workflow_id TEXT NOT NULL,
                            execution_id TEXT NOT NULL,
                            created_at TEXT NOT NULL
                        )
                    """)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS soar_idempotency (
                            idempotency_key TEXT PRIMARY KEY,
                            execution_id TEXT NOT NULL,
                            workflow_id TEXT NOT NULL,
                            created_at TEXT NOT NULL
                        )
                    """)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS soar_audit_log (
                            audit_id TEXT PRIMARY KEY,
                            execution_id TEXT,
                            workflow_id TEXT NOT NULL,
                            from_state TEXT,
                            to_state TEXT NOT NULL,
                            actor TEXT NOT NULL,
                            details TEXT,
                            timestamp TEXT NOT NULL
                        )
                    """)
            finally:
                conn.close()
        self.recover_interrupted_executions()

    def reset_state(self) -> None:
        """Clears execution and trigger deduplication records (for test isolation)."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM soar_executions")
                    conn.execute("DELETE FROM soar_trigger_dedup")
                    conn.execute("DELETE FROM soar_audit_log")
            finally:
                conn.close()

    def _log_state_transition(
        self,
        execution_id: Optional[str],
        workflow_id: str,
        from_state: Optional[WorkflowState],
        to_state: WorkflowState,
        actor: str = "soar_engine",
        details: str = "",
    ) -> None:
        """Audits every workflow state change into persistent storage."""
        if from_state is not None:
            allowed = self.VALID_TRANSITIONS.get(from_state, set())
            if to_state not in allowed:
                raise ValueError(f"Invalid state transition: Cannot transition from {from_state.value} to {to_state.value}.")

        now_iso = datetime.now(timezone.utc).isoformat()
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO soar_audit_log
                        (audit_id, execution_id, workflow_id, from_state, to_state, actor, details, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"aud-{uuid.uuid4().hex[:10]}",
                            execution_id,
                            workflow_id,
                            from_state.value if from_state else None,
                            to_state.value,
                            actor,
                            details,
                            now_iso,
                        ),
                    )
            finally:
                conn.close()

    # ==========================================================================
    # Trigger Engine & Deduplication
    # ==========================================================================

    def create_trigger(
        self,
        trigger_type: TriggerType,
        source_record_id: str,
        target_context: str,
        provenance: str = "SOC_ALERT",
        event_timestamp: Optional[str] = None,
    ) -> WorkflowTrigger:
        """Constructs a deterministic, deduplicated trigger descriptor."""
        ts = event_timestamp or datetime.now(timezone.utc).isoformat()
        # Compute deterministic deduplication key
        raw_key = f"{trigger_type.value}:{source_record_id}:{target_context}"
        dedup_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

        return WorkflowTrigger(
            trigger_id=f"trg-{uuid.uuid4().hex[:8]}",
            trigger_type=trigger_type,
            source_record_id=source_record_id,
            event_timestamp=ts,
            target_context=target_context,
            provenance=provenance,
            deduplication_key=dedup_key,
        )

    def is_duplicate_trigger(self, workflow_id: str, trigger: WorkflowTrigger) -> bool:
        """Checks whether this trigger has already executed for this workflow."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    "SELECT execution_id FROM soar_trigger_dedup WHERE deduplication_key = ? AND workflow_id = ?",
                    (trigger.deduplication_key, workflow_id),
                )
                return cur.fetchone() is not None
            finally:
                conn.close()

    # ==========================================================================
    # Workflow Execution Orchestration
    # ==========================================================================

    def execute_workflow(
        self,
        workflow_id: str,
        trigger: WorkflowTrigger,
        allow_rerun: bool = False,
        capability_token: Optional[str] = None,
        operator: str = "operator",
        stored_events: Optional[list[Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> WorkflowExecutionRecord:
        """Executes a SOAR workflow sequentially through its defined steps."""
        wf = self._WORKFLOWS.get(workflow_id)
        if not wf:
            raise ValueError(f"Workflow '{workflow_id}' not found in registry.")

        if idempotency_key:
            existing = self.get_execution_by_idempotency_key(idempotency_key)
            if existing:
                return existing

        # Deduplication check
        if not allow_rerun and self.is_duplicate_trigger(workflow_id, trigger):
            raise ValueError(
                f"Duplicate execution blocked: Trigger with dedup key '{trigger.deduplication_key[:12]}...' "
                f"has already executed for workflow '{workflow_id}'."
            )

        exec_id = f"exec-{uuid.uuid4().hex[:10]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Audit transition to READY then RUNNING
        self._log_state_transition(exec_id, workflow_id, WorkflowState.READY, WorkflowState.RUNNING, actor=operator)

        if idempotency_key:
            with self._op_lock:
                conn = self._get_connection()
                try:
                    with conn:
                        conn.execute(
                            "INSERT OR REPLACE INTO soar_idempotency (idempotency_key, execution_id, workflow_id, created_at) VALUES (?, ?, ?, ?)",
                            (idempotency_key, exec_id, workflow_id, now_iso),
                        )
                finally:
                    conn.close()

        # Register dedup record
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO soar_trigger_dedup (deduplication_key, workflow_id, execution_id, created_at) VALUES (?, ?, ?, ?)",
                        (trigger.deduplication_key, workflow_id, exec_id, now_iso),
                    )
            finally:
                conn.close()

        record = WorkflowExecutionRecord(
            execution_id=exec_id,
            workflow_id=workflow_id,
            workflow_title=wf.title,
            trigger=trigger.to_dict(),
            state=WorkflowState.RUNNING,
            current_step_index=0,
            total_steps=len(wf.steps),
            executed_steps=[],
            evidence_ids=[],
        )
        self._save_execution_record(record)

        # Execute steps sequentially
        for idx, step in enumerate(wf.steps):
            record.current_step_index = idx

            # High-risk containment steps check for approval capability
            if step.is_containment and step.requires_approval:
                if not capability_token:
                    # Transition to WAITING_FOR_APPROVAL
                    self._log_state_transition(exec_id, workflow_id, WorkflowState.RUNNING, WorkflowState.WAITING_FOR_APPROVAL, actor=operator)
                    record.state = WorkflowState.WAITING_FOR_APPROVAL
                    step_result = {
                        "step_id": step.step_id,
                        "step_name": step.step_name,
                        "status": ActionExecutionStatus.WAITING_FOR_APPROVAL.value,
                        "details": "Step halted: High-risk containment requires explicit human approval and capability authorization token.",
                    }
                    record.executed_steps.append(step_result)
                    self._save_execution_record(record)
                    return record

            # Dispatch typed action
            step_params = dict(step.parameters)
            step_params["target_context"] = trigger.target_context
            step_params["capability_token"] = capability_token
            step_params["operator"] = operator
            step_params["stored_events"] = stored_events

            action_handler = getattr(SOARActionRegistry, step.action_name, None)
            if not action_handler or not callable(action_handler):
                record.state = WorkflowState.FAILED
                record.error_message = f"Unsupported action handler '{step.action_name}' in step '{step.step_id}'."
                self._save_execution_record(record)
                return record

            try:
                act_res: ActionResult = action_handler(**step_params)
                step_dict = act_res.to_dict()
                record.executed_steps.append(step_dict)
                record.evidence_ids.extend(act_res.evidence_ids)

                if act_res.status == ActionExecutionStatus.FAILED:
                    self._log_state_transition(exec_id, workflow_id, WorkflowState.RUNNING, WorkflowState.FAILED, actor=operator)
                    record.state = WorkflowState.FAILED
                    record.error_message = f"Step '{step.step_name}' failed: {act_res.details}"
                    self._save_execution_record(record)
                    return record

            except Exception as ex:
                self._log_state_transition(exec_id, workflow_id, WorkflowState.RUNNING, WorkflowState.FAILED, actor=operator)
                record.state = WorkflowState.FAILED
                record.error_message = f"Step '{step.step_name}' raised exception: {str(ex)}"
                self._save_execution_record(record)
                return record

        # All steps completed
        self._log_state_transition(exec_id, workflow_id, WorkflowState.RUNNING, WorkflowState.COMPLETED, actor=operator)
        record.state = WorkflowState.COMPLETED
        record.completed_at = datetime.now(timezone.utc).isoformat()
        self._save_execution_record(record)
        return record

    def recover_interrupted_executions(self) -> int:
        """Scans for executions left in RUNNING or EXECUTING state across restarts and marks them FAILED."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                now_iso = datetime.now(timezone.utc).isoformat()
                with conn:
                    cur = conn.execute(
                        """
                        UPDATE soar_executions
                        SET state = 'FAILED',
                            completed_at = ?,
                            error_message = 'Execution interrupted by host restart or worker termination; recovered during startup.'
                        WHERE state IN ('RUNNING', 'EXECUTING')
                        """,
                        (now_iso,),
                    )
                    return cur.rowcount
            finally:
                conn.close()

    def check_approval_timeouts(self, max_wait_seconds: float = 3600.0) -> list[str]:
        """Transitions executions waiting for approval beyond max_wait_seconds to TIMED_OUT."""
        timed_out_ids: list[str] = []
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM soar_executions WHERE state = 'WAITING_FOR_APPROVAL'")
                rows = cur.fetchall()
                now = datetime.now(timezone.utc)
                for row in rows:
                    st_str = row["started_at"]
                    try:
                        st_dt = datetime.fromisoformat(st_str)
                        if (now - st_dt).total_seconds() > max_wait_seconds:
                            exec_id = row["execution_id"]
                            wf_id = row["workflow_id"]
                            now_iso = now.isoformat()
                            with conn:
                                conn.execute(
                                    """
                                    UPDATE soar_executions
                                    SET state = 'TIMED_OUT', completed_at = ?,
                                        error_message = ?
                                    WHERE execution_id = ?
                                    """,
                                    (now_iso, f"Approval window expired after {max_wait_seconds}s.", exec_id),
                                )
                            self._log_state_transition(
                                exec_id, wf_id, WorkflowState.WAITING_FOR_APPROVAL, WorkflowState.TIMED_OUT,
                                actor="system_timeout_daemon", details="Approval window exceeded",
                            )
                            timed_out_ids.append(exec_id)
                    except Exception:
                        pass
            finally:
                conn.close()
        return timed_out_ids

    def get_execution_by_idempotency_key(self, idempotency_key: str) -> Optional[WorkflowExecutionRecord]:
        """Looks up an execution record by idempotency key."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT execution_id FROM soar_idempotency WHERE idempotency_key = ?", (idempotency_key,))
                row = cur.fetchone()
                if row:
                    return self.get_execution(row["execution_id"])
                return None
            finally:
                conn.close()

    def cancel_execution(self, execution_id: str, operator: str = "operator", reason: str = "") -> WorkflowExecutionRecord:
        """Gracefully cancels a running or approval-waiting workflow execution."""
        rec = self.get_execution(execution_id)
        if not rec:
            raise ValueError(f"Execution '{execution_id}' not found.")

        if rec.state in (WorkflowState.COMPLETED, WorkflowState.CANCELLED, WorkflowState.FAILED):
            raise ValueError(f"Cannot cancel execution in terminal state '{rec.state.value}'.")

        prev_state = rec.state
        self._log_state_transition(execution_id, rec.workflow_id, prev_state, WorkflowState.CANCELLED, actor=operator, details=reason)
        rec.state = WorkflowState.CANCELLED
        rec.cancelled_by = operator
        rec.completed_at = datetime.now(timezone.utc).isoformat()
        rec.error_message = f"Cancelled by {operator}: {reason}" if reason else f"Cancelled by {operator}."
        self._save_execution_record(rec)
        return rec

    def get_execution(self, execution_id: str) -> Optional[WorkflowExecutionRecord]:
        """Loads execution record from persistent storage."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM soar_executions WHERE execution_id = ?", (execution_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return WorkflowExecutionRecord(
                    execution_id=row["execution_id"],
                    workflow_id=row["workflow_id"],
                    workflow_title=row["workflow_title"],
                    trigger=json.loads(row["trigger_json"]),
                    state=WorkflowState(row["state"]),
                    current_step_index=row["current_step_index"],
                    total_steps=row["total_steps"],
                    executed_steps=json.loads(row["executed_steps_json"]),
                    evidence_ids=json.loads(row["evidence_ids_json"]),
                    error_message=row["error_message"],
                    cancelled_by=row["cancelled_by"],
                    started_at=row["started_at"],
                    completed_at=row["completed_at"],
                )
            finally:
                conn.close()

    def list_executions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Returns recent workflow execution records."""
        with self._op_lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT * FROM soar_executions ORDER BY started_at DESC LIMIT ?", (limit,))
                rows = cur.fetchall()
                results = []
                for r in rows:
                    rec = WorkflowExecutionRecord(
                        execution_id=r["execution_id"],
                        workflow_id=r["workflow_id"],
                        workflow_title=r["workflow_title"],
                        trigger=json.loads(r["trigger_json"]),
                        state=WorkflowState(r["state"]),
                        current_step_index=r["current_step_index"],
                        total_steps=r["total_steps"],
                        executed_steps=json.loads(r["executed_steps_json"]),
                        evidence_ids=json.loads(r["evidence_ids_json"]),
                        error_message=r["error_message"],
                        cancelled_by=r["cancelled_by"],
                        started_at=r["started_at"],
                        completed_at=r["completed_at"],
                    )
                    results.append(rec.to_dict())
                return results
            finally:
                conn.close()

    def _save_execution_record(self, record: WorkflowExecutionRecord) -> None:
        with self._op_lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO soar_executions
                        (execution_id, workflow_id, workflow_title, trigger_json, state, current_step_index,
                         total_steps, executed_steps_json, evidence_ids_json, error_message, cancelled_by, started_at, completed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record.execution_id,
                            record.workflow_id,
                            record.workflow_title,
                            json.dumps(record.trigger),
                            record.state.value,
                            record.current_step_index,
                            record.total_steps,
                            json.dumps(record.executed_steps),
                            json.dumps(record.evidence_ids),
                            record.error_message,
                            record.cancelled_by,
                            record.started_at,
                            record.completed_at,
                        ),
                    )
            finally:
                conn.close()

    # ==========================================================================
    # 10 Reusable Incident Response Playbooks (D5)
    # ==========================================================================

    def list_workflows(self) -> list[dict[str, Any]]:
        return [wf.to_dict() for wf in self._WORKFLOWS.values()]

    def get_workflow(self, workflow_id: str) -> Optional[SOARWorkflow]:
        return self._WORKFLOWS.get(workflow_id)

    def _initialize_builtins(self) -> None:
        """Initializes the 10 production-minded IR playbooks."""
        # 1. WF-BRUTE-FORCE
        self._WORKFLOWS["WF-BRUTE-FORCE"] = SOARWorkflow(
            workflow_id="WF-BRUTE-FORCE",
            title="Brute-Force Authentication Investigation & Edge Blocking",
            version="1.0.0",
            description="Investigates multiple failed login spikes, enriches attacker IP, and initiates simulated edge containment.",
            trigger_types=[TriggerType.ALERT, TriggerType.SIGMA, TriggerType.MANUAL],
            required_telemetry=["Authentication logs", "Source IP address", "Target username"],
            closure_criteria="Source IP blocked at edge and password reset triggered for targeted accounts.",
            steps=[
                WorkflowStep(
                    step_id="step-bf-1",
                    step_name="Triage & Event Gathering",
                    action_name="retrieve_related_events",
                    category=ActionCategory.INVESTIGATION,
                ),
                WorkflowStep(
                    step_id="step-bf-2",
                    step_name="Attacker IP Threat Intelligence",
                    action_name="enrich_indicator",
                    category=ActionCategory.INVESTIGATION,
                    parameters={"indicator_type": "ip"},
                ),
                WorkflowStep(
                    step_id="step-bf-3",
                    step_name="Containment Recommendation",
                    action_name="create_containment_recommendation",
                    category=ActionCategory.DEFENSIVE,
                    parameters={"recommendation": "Block malicious source IP and enforce MFA challenge."},
                ),
                WorkflowStep(
                    step_id="step-bf-4",
                    step_name="Edge Firewall Blacklist",
                    action_name="simulate_indicator_blocklist",
                    category=ActionCategory.DEFENSIVE,
                ),
            ],
        )

        # 2. WF-CRED-COMPROMISE
        self._WORKFLOWS["WF-CRED-COMPROMISE"] = SOARWorkflow(
            workflow_id="WF-CRED-COMPROMISE",
            title="Suspected Credential Compromise & Account Containment",
            version="1.0.0",
            description="Triages anomalous account access following failed attempts and gates account lockout behind human approval.",
            trigger_types=[TriggerType.ALERT, TriggerType.INCIDENT, TriggerType.MANUAL],
            required_telemetry=["Successful logon events", "User privilege role", "Geographic origin"],
            closure_criteria="Account session terminated and credentials rotated out-of-band.",
            steps=[
                WorkflowStep(
                    step_id="step-cc-1",
                    step_name="Session Log Verification",
                    action_name="retrieve_related_events",
                    category=ActionCategory.INVESTIGATION,
                ),
                WorkflowStep(
                    step_id="step-cc-2",
                    step_name="Account Lockout Approval Gate",
                    action_name="disable_account",
                    category=ActionCategory.CONTAINMENT,
                    requires_approval=True,
                    is_containment=True,
                ),
            ],
        )

        # 3. WF-POWERSHELL-EXEC
        self._WORKFLOWS["WF-POWERSHELL-EXEC"] = SOARWorkflow(
            workflow_id="WF-POWERSHELL-EXEC",
            title="Suspicious PowerShell Execution & Host Isolation",
            version="1.0.0",
            description="Analyzes obfuscated PowerShell commands, inspects process lineage, and isolates compromised host upon approval.",
            trigger_types=[TriggerType.ALERT, TriggerType.SIGMA, TriggerType.MANUAL],
            required_telemetry=["Process creation (Sysmon Event ID 1)", "Decoded command line", "Parent process"],
            closure_criteria="Malicious process killed and endpoint isolated pending forensic capture.",
            steps=[
                WorkflowStep(
                    step_id="step-ps-1",
                    step_name="Process Tree Investigation",
                    action_name="retrieve_related_events",
                    category=ActionCategory.INVESTIGATION,
                ),
                WorkflowStep(
                    step_id="step-ps-2",
                    step_name="Endpoint Isolation Approval Gate",
                    action_name="isolate_endpoint",
                    category=ActionCategory.CONTAINMENT,
                    requires_approval=True,
                    is_containment=True,
                ),
            ],
        )

        # 4. WF-WEB-ATTACK
        self._WORKFLOWS["WF-WEB-ATTACK"] = SOARWorkflow(
            workflow_id="WF-WEB-ATTACK",
            title="Web Application Attack & Web Shell Neutralization",
            version="1.0.0",
            description="Investigates SQL injection / directory traversal alerts and deploys simulated reverse-proxy blocklist.",
            trigger_types=[TriggerType.ALERT, TriggerType.SIGMA, TriggerType.MANUAL],
            required_telemetry=["Web server access logs", "URI path", "HTTP status code"],
            closure_criteria="Vulnerable URI patched and malicious client IP blocked at WAF.",
            steps=[
                WorkflowStep(
                    step_id="step-wa-1",
                    step_name="HTTP Access Log Review",
                    action_name="retrieve_related_events",
                    category=ActionCategory.INVESTIGATION,
                ),
                WorkflowStep(
                    step_id="step-wa-2",
                    step_name="Simulate WAF Rule Deployment",
                    action_name="simulate_indicator_blocklist",
                    category=ActionCategory.DEFENSIVE,
                ),
            ],
        )

        # 5. WF-PHISHING
        self._WORKFLOWS["WF-PHISHING"] = SOARWorkflow(
            workflow_id="WF-PHISHING",
            title="Phishing Investigation & Domain Takedown Triage",
            version="1.0.0",
            description="Enriches sender domain, verifies recipient click-through telemetry, and triggers email gateway block recommendation.",
            trigger_types=[TriggerType.ALERT, TriggerType.HUNT, TriggerType.MANUAL],
            required_telemetry=["Email headers", "Extracted URL / attachments", "User mailbox ID"],
            closure_criteria="Phishing message purged from mailboxes and destination URL blocked in secure web gateway.",
            steps=[
                WorkflowStep(
                    step_id="step-ph-1",
                    step_name="Enrich Phishing Domain",
                    action_name="enrich_indicator",
                    category=ActionCategory.INVESTIGATION,
                    parameters={"indicator_type": "domain"},
                ),
                WorkflowStep(
                    step_id="step-ph-2",
                    step_name="Mail Gateway Containment Recommendation",
                    action_name="create_containment_recommendation",
                    category=ActionCategory.DEFENSIVE,
                    parameters={"recommendation": "Block sender domain and purge message copies from exchange mailboxes."},
                ),
            ],
        )

        # 6. WF-MALWARE-HASH
        self._WORKFLOWS["WF-MALWARE-HASH"] = SOARWorkflow(
            workflow_id="WF-MALWARE-HASH",
            title="Malware Indicator Triage & Endpoint Quarantine",
            version="1.0.0",
            description="Enriches SHA-256 hash across threat intelligence and requests host quarantine.",
            trigger_types=[TriggerType.ALERT, TriggerType.INTEL, TriggerType.MANUAL],
            required_telemetry=["File hash (SHA-256)", "File path", "Antivirus detection string"],
            closure_criteria="File quarantined to secure directory and persistence hooks removed.",
            steps=[
                WorkflowStep(
                    step_id="step-mal-1",
                    step_name="Threat Intel Hash Enrichment",
                    action_name="enrich_indicator",
                    category=ActionCategory.INVESTIGATION,
                    parameters={"indicator_type": "hash"},
                ),
                WorkflowStep(
                    step_id="step-mal-2",
                    step_name="Host Quarantine Gate",
                    action_name="isolate_endpoint",
                    category=ActionCategory.CONTAINMENT,
                    requires_approval=True,
                    is_containment=True,
                ),
            ],
        )

        # 7. WF-OUTBOUND-C2
        self._WORKFLOWS["WF-OUTBOUND-C2"] = SOARWorkflow(
            workflow_id="WF-OUTBOUND-C2",
            title="Suspicious Outbound Communication & Null-Routing",
            version="1.0.0",
            description="Identifies rogue beaconing sockets and applies simulated perimeter routing nullification.",
            trigger_types=[TriggerType.ALERT, TriggerType.SIGMA, TriggerType.MANUAL],
            required_telemetry=["Netflow record", "Remote destination IP", "Socket duration"],
            closure_criteria="C2 IP blackholed at router and malicious socket terminated on endpoint.",
            steps=[
                WorkflowStep(
                    step_id="step-c2-1",
                    step_name="C2 IP Intelligence Lookup",
                    action_name="enrich_indicator",
                    category=ActionCategory.INVESTIGATION,
                    parameters={"indicator_type": "ip"},
                ),
                WorkflowStep(
                    step_id="step-c2-2",
                    step_name="Null-Route Blackhole Simulation",
                    action_name="simulate_indicator_blocklist",
                    category=ActionCategory.DEFENSIVE,
                ),
            ],
        )

        # 8. WF-DATA-EXFIL
        self._WORKFLOWS["WF-DATA-EXFIL"] = SOARWorkflow(
            workflow_id="WF-DATA-EXFIL",
            title="Potential Data Exfiltration & Channel Severing",
            version="1.0.0",
            description="Monitors anomalous outbound transfer volumes and recommends channel severance.",
            trigger_types=[TriggerType.ALERT, TriggerType.INCIDENT, TriggerType.MANUAL],
            required_telemetry=["Byte counters", "Source internal host", "Destination cloud endpoint"],
            closure_criteria="Active transfer terminated and user egress credentials rotated.",
            steps=[
                WorkflowStep(
                    step_id="step-ex-1",
                    step_name="Transfer Telemetry Verification",
                    action_name="retrieve_related_events",
                    category=ActionCategory.INVESTIGATION,
                ),
                WorkflowStep(
                    step_id="step-ex-2",
                    step_name="Egress Severance Recommendation",
                    action_name="create_containment_recommendation",
                    category=ActionCategory.DEFENSIVE,
                    parameters={"recommendation": "Sever outbound egress channel and revoke SaaS API tokens."},
                ),
            ],
        )

        # 9. WF-DNS-TUNNEL
        self._WORKFLOWS["WF-DNS-TUNNEL"] = SOARWorkflow(
            workflow_id="WF-DNS-TUNNEL",
            title="DNS Tunneling Investigation & Resolver Filtering",
            version="1.0.0",
            description="Investigates high-entropy subdomain requests and initiates internal resolver sinkholing.",
            trigger_types=[TriggerType.ALERT, TriggerType.SIGMA, TriggerType.MANUAL],
            required_telemetry=["Suricata DNS query logs", "Entropy calculation", "Client host IP"],
            closure_criteria="Tunneling domain sinkholed at internal DNS resolver.",
            steps=[
                WorkflowStep(
                    step_id="step-dns-1",
                    step_name="DNS Query Query Investigation",
                    action_name="retrieve_related_events",
                    category=ActionCategory.INVESTIGATION,
                ),
                WorkflowStep(
                    step_id="step-dns-2",
                    step_name="Domain Sinkhole Simulation",
                    action_name="simulate_indicator_blocklist",
                    category=ActionCategory.DEFENSIVE,
                ),
            ],
        )

        # 10. WF-VULN-EXPLOIT
        self._WORKFLOWS["WF-VULN-EXPLOIT"] = SOARWorkflow(
            workflow_id="WF-VULN-EXPLOIT",
            title="Vulnerability Exploitation Alert & Virtual Patching",
            version="1.0.0",
            description="Correlates public-facing application alerts with known CVE intelligence.",
            trigger_types=[TriggerType.ALERT, TriggerType.INCIDENT, TriggerType.MANUAL],
            required_telemetry=["CVE ID", "Exploit payload signature", "Affected server port"],
            closure_criteria="Virtual patch applied at reverse proxy and upstream software updated.",
            steps=[
                WorkflowStep(
                    step_id="step-vx-1",
                    step_name="Exploitation Telemetry Review",
                    action_name="retrieve_related_events",
                    category=ActionCategory.INVESTIGATION,
                ),
                WorkflowStep(
                    step_id="step-vx-2",
                    step_name="Virtual Patch Recommendation",
                    action_name="create_containment_recommendation",
                    category=ActionCategory.DEFENSIVE,
                    parameters={"recommendation": "Deploy WAF virtual patch blocking exploit payload pattern."},
                ),
            ],
        )
