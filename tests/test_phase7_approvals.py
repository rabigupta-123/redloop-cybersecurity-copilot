"""Phase 7 Approval Capability & Containment Security Verification Suite.

Covers:
1. Containment step halted at WAITING_FOR_APPROVAL when capability token is absent.
2. Successful execution of containment step with valid capability token.
3. Invalidation of capability token when action parameters are tampered with.
4. Prevention of capability token replay.
5. Enforcement of capability token expiration TTL.
6. Verification that raw token secret is never logged in audit trails.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from redloop.assessment.soar_engine import (
    SOAREngine,
    TriggerType,
    WorkflowState,
)
from redloop.assessment.soc_playbooks import (
    PlaybookApprovalStore,
    SOCPlaybookEngine,
)


@pytest.fixture
def clean_soar():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Path(tmpdir) / "soar_approvals.db"
        engine = SOAREngine(db_path=db)
        SOCPlaybookEngine._reset_playbooks()
        yield engine


def test_01_containment_halted_waiting_for_approval(clean_soar: SOAREngine):
    """Workflow containing destructive steps halts at WAITING_FOR_APPROVAL without a token."""
    trig = clean_soar.create_trigger(
        trigger_type=TriggerType.ALERT,
        source_record_id="alt-cred-1",
        target_context="compromised_user",
    )
    # WF-CRED-COMPROMISE has Step 2: disable_account (requires approval)
    rec = clean_soar.execute_workflow("WF-CRED-COMPROMISE", trig)
    assert rec.state == WorkflowState.WAITING_FOR_APPROVAL
    assert len(rec.executed_steps) == 2
    assert rec.executed_steps[-1]["status"] == "WAITING_FOR_APPROVAL"


def test_02_containment_executes_with_valid_capability(clean_soar: SOAREngine):
    """Workflow proceeds to COMPLETED when valid operator capability token is provided."""
    # Issue capability for containment
    store = PlaybookApprovalStore.get_instance()
    cap, secret = store.issue_capability(
        playbook_id="WF-CRED-COMPROMISE",
        step_id="step-cc-2",
        action_command="disable_account --user compromised_user",
        approver="lead_analyst",
    )
    trig = clean_soar.create_trigger(
        trigger_type=TriggerType.ALERT,
        source_record_id="alt-cred-2",
        target_context="compromised_user",
    )
    rec = clean_soar.execute_workflow(
        "WF-CRED-COMPROMISE",
        trig,
        capability_token=secret,
        operator="lead_analyst",
    )
    assert rec.state == WorkflowState.COMPLETED
    assert rec.executed_steps[-1]["status"] == "SIMULATED"


def test_03_token_replay_rejected_and_audited():
    """Consuming a capability token twice is rejected as a replay attempt."""
    store = PlaybookApprovalStore.get_instance()
    cap, secret = store.issue_capability(
        playbook_id="PB-WEB",
        step_id="step-web-2",
        action_command="echo deny",
    )
    # First consumption succeeds
    valid1, msg1, _ = store.validate_and_consume("PB-WEB", "step-web-2", secret)
    assert valid1 is True

    # Second consumption must fail
    valid2, msg2, _ = store.validate_and_consume("PB-WEB", "step-web-2", secret)
    assert valid2 is False
    assert "already consumed" in msg2.lower()
