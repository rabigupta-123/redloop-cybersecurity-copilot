"""Phase 7 SOAR Engine Automated Verification Suite.

Covers:
1. Declarative workflow catalog loading (10 built-in playbooks).
2. State transition validation (11 valid workflow states).
3. Trigger creation and deduplication key generation.
4. Deduplicated execution prevention.
5. Workflow execution lifecycle: READY -> RUNNING -> COMPLETED.
6. Workflow cancellation handling.
7. Persistence across simulated process restarts.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from redloop.assessment.soar_engine import (
    SOAREngine,
    TriggerType,
    WorkflowState,
    WorkflowTrigger,
)


@pytest.fixture
def clean_engine():
    """Provides a fresh SOAR engine backed by a temporary SQLite database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Path(tmpdir) / "soar_test.db"
        engine = SOAREngine(db_path=db)
        yield engine


def test_01_builtin_workflows_catalog(clean_engine: SOAREngine):
    """Verifies that all 10 required incident response playbooks are registered and valid."""
    wfs = clean_engine.list_workflows()
    assert len(wfs) >= 10
    wf_ids = {w["workflow_id"] for w in wfs}
    expected = {
        "WF-BRUTE-FORCE",
        "WF-CRED-COMPROMISE",
        "WF-POWERSHELL-EXEC",
        "WF-WEB-ATTACK",
        "WF-PHISHING",
        "WF-MALWARE-HASH",
        "WF-OUTBOUND-C2",
        "WF-DATA-EXFIL",
        "WF-DNS-TUNNEL",
        "WF-VULN-EXPLOIT",
    }
    for exp in expected:
        assert exp in wf_ids, f"Expected playbook '{exp}' missing from catalog"


def test_02_workflow_state_machine_valid_and_invalid_transitions(clean_engine: SOAREngine):
    """Validates state transitions and verifies invalid transitions raise ValueError."""
    # Valid transition: READY -> RUNNING
    clean_engine._log_state_transition(
        execution_id="exec-1",
        workflow_id="WF-BRUTE-FORCE",
        from_state=WorkflowState.READY,
        to_state=WorkflowState.RUNNING,
    )

    # Invalid transition: COMPLETED -> RUNNING (terminal state)
    with pytest.raises(ValueError) as exc:
        clean_engine._log_state_transition(
            execution_id="exec-1",
            workflow_id="WF-BRUTE-FORCE",
            from_state=WorkflowState.COMPLETED,
            to_state=WorkflowState.RUNNING,
        )
    assert "Invalid state transition" in str(exc.value)


def test_03_trigger_creation_and_deduplication(clean_engine: SOAREngine):
    """Tests deterministic deduplication key generation and duplicate prevention."""
    trig1 = clean_engine.create_trigger(
        trigger_type=TriggerType.ALERT,
        source_record_id="alt-101",
        target_context="192.168.1.100",
    )
    trig2 = clean_engine.create_trigger(
        trigger_type=TriggerType.ALERT,
        source_record_id="alt-101",
        target_context="192.168.1.100",
    )
    # Deduplication key must be identical for same source record and target context
    assert trig1.deduplication_key == trig2.deduplication_key

    # Execute workflow with trig1
    rec1 = clean_engine.execute_workflow("WF-BRUTE-FORCE", trig1)
    assert rec1.state == WorkflowState.COMPLETED

    # Executing again with trig2 must be blocked as duplicate unless allow_rerun=True
    with pytest.raises(ValueError) as exc:
        clean_engine.execute_workflow("WF-BRUTE-FORCE", trig2)
    assert "Duplicate execution blocked" in str(exc.value)

    # Allow explicit re-run
    rec2 = clean_engine.execute_workflow("WF-BRUTE-FORCE", trig2, allow_rerun=True)
    assert rec2.state == WorkflowState.COMPLETED


def test_04_workflow_cancellation(clean_engine: SOAREngine):
    """Cancels a workflow execution and ensures status is updated to CANCELLED."""
    trig = clean_engine.create_trigger(
        trigger_type=TriggerType.MANUAL,
        source_record_id="man-01",
        target_context="10.0.0.5",
    )
    # Execute approval-gated workflow (halts at WAITING_FOR_APPROVAL)
    rec = clean_engine.execute_workflow("WF-CRED-COMPROMISE", trig)
    assert rec.state == WorkflowState.WAITING_FOR_APPROVAL

    # Cancel execution
    cancelled = clean_engine.cancel_execution(rec.execution_id, operator="sec_lead", reason="False positive alert")
    assert cancelled.state == WorkflowState.CANCELLED
    assert cancelled.cancelled_by == "sec_lead"
    assert "False positive alert" in (cancelled.error_message or "")


def test_05_persistence_across_restart(clean_engine: SOAREngine):
    """Verifies workflow executions persist across simulated process restart."""
    db_path = clean_engine.db_path
    trig = clean_engine.create_trigger(
        trigger_type=TriggerType.ALERT,
        source_record_id="alt-restart-test",
        target_context="10.0.5.20",
    )
    rec = clean_engine.execute_workflow("WF-BRUTE-FORCE", trig)
    exec_id = rec.execution_id

    # Simulate restart by instantiating new engine with same SQLite database
    new_engine = SOAREngine(db_path=db_path)
    loaded = new_engine.get_execution(exec_id)
    assert loaded is not None
    assert loaded.execution_id == exec_id
    assert loaded.workflow_id == "WF-BRUTE-FORCE"
    assert loaded.state == WorkflowState.COMPLETED
    assert len(loaded.executed_steps) == 4
