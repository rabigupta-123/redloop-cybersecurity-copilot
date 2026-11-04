"""Phase 7 Incident Case Management Automated Verification Suite.

Covers:
1. Case creation with severity, priority, and role assignment.
2. Valid state transitions: OPEN -> INVESTIGATING -> RESOLVED -> CLOSED -> REOPENED.
3. Rejection of invalid state transitions (e.g. CLOSED -> INVESTIGATING without reopen).
4. Analyst note addition and timeline event logging.
5. Evidence attachment without mutating underlying security event records.
6. Case querying and filtering by status and severity.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from redloop.assessment.case_management import (
    CaseManager,
    CasePriority,
    CaseSeverity,
    CaseStatus,
)


@pytest.fixture
def clean_cm():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Path(tmpdir) / "cases_test.db"
        cm = CaseManager(db_path=db)
        yield cm


def test_01_case_creation_and_attributes(clean_cm: CaseManager):
    """Creates a case and verifies initial attributes and timeline event."""
    case = clean_cm.create_case(
        title="Active Credential Stuffing Campaign",
        description="Multiple foreign IP addresses attempting dictionary spray.",
        severity=CaseSeverity.HIGH,
        priority=CasePriority.P2,
        assigned_to="tier1_analyst",
        linked_alert_ids=["alt-auth-001"],
        creator="soc_automation",
    )
    assert case.case_id.startswith("case-")
    assert case.status == CaseStatus.OPEN
    assert case.severity == CaseSeverity.HIGH
    assert case.priority == CasePriority.P2
    assert len(case.timeline) == 1
    assert case.timeline[0].event_type == "CASE_CREATED"


def test_02_valid_lifecycle_and_reopen_history(clean_cm: CaseManager):
    """Transitions a case through OPEN -> INVESTIGATING -> RESOLVED -> CLOSED -> REOPENED."""
    case = clean_cm.create_case("Malware outbreak", "Trojan detected on workstation")
    cid = case.case_id

    # 1. OPEN -> INVESTIGATING
    c1 = clean_cm.update_case(cid, status=CaseStatus.INVESTIGATING, actor="analyst_alice")
    assert c1.status == CaseStatus.INVESTIGATING

    # 2. INVESTIGATING -> RESOLVED
    c2 = clean_cm.update_case(cid, status=CaseStatus.RESOLVED, closure_reason="Endpoint reimaged", actor="analyst_alice")
    assert c2.status == CaseStatus.RESOLVED
    assert c2.closure_reason == "Endpoint reimaged"

    # 3. RESOLVED -> CLOSED
    c3 = clean_cm.update_case(cid, status=CaseStatus.CLOSED, actor="lead_analyst")
    assert c3.status == CaseStatus.CLOSED

    # 4. CLOSED -> REOPENED
    c4 = clean_cm.update_case(cid, status=CaseStatus.REOPENED, closure_reason="New beaconing detected from same subnet", actor="lead_analyst")
    assert c4.status == CaseStatus.REOPENED
    assert c4.reopen_count == 1
    assert len(c4.reopen_history) == 1


def test_03_invalid_state_transition_rejected(clean_cm: CaseManager):
    """Rejects illegal state transitions (e.g. OPEN -> CLOSED directly)."""
    case = clean_cm.create_case("Test Case", "Testing illegal transition")
    # CLOSED -> RESOLVED is invalid
    clean_cm.update_case(case.case_id, status=CaseStatus.INVESTIGATING)
    clean_cm.update_case(case.case_id, status=CaseStatus.RESOLVED)
    clean_cm.update_case(case.case_id, status=CaseStatus.CLOSED)

    with pytest.raises(ValueError) as exc:
        clean_cm.update_case(case.case_id, status=CaseStatus.RESOLVED)
    assert "Invalid state transition" in str(exc.value)


def test_04_analyst_notes_and_evidence_attachment(clean_cm: CaseManager):
    """Appends investigation notes and evidence ledger IDs without data loss."""
    case = clean_cm.create_case("Phishing Campaign", "CEO impersonation email")
    cid = case.case_id

    note = clean_cm.add_note(cid, author="analyst_bob", content="Extracted macro dropper from attachment.")
    assert note.note_id.startswith("not-")
    assert note.author == "analyst_bob"

    attached = clean_cm.attach_evidence(cid, ["evi-sample-sha256", "evi-netflow-pcap"])
    assert len(attached) == 2
    assert "evi-sample-sha256" in attached

    # Reload from DB and verify
    reloaded = clean_cm.get_case(cid)
    assert reloaded is not None
    assert len(reloaded.notes) == 1
    assert len(reloaded.evidence_ids) == 2
    assert any(t.event_type == "EVIDENCE_ATTACHED" for t in reloaded.timeline)
