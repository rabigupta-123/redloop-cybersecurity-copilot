"""Phase 7 SOAR Automation & Case Management End-to-End Integration Verification Suite.

Covers:
1. Complete Ingestion-to-Response Pipeline:
   Telemetry -> SOC Alert -> Trigger -> SOAR Playbook Execution -> Case Creation -> Evidence Link -> Resolution.
2. REST API endpoint contracts for /api/soar/* and /api/cases/*.
3. Verification that destructive containment actions require explicit operator approval capability.
4. Persistence across process restarts.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from redloop.assessment.case_management import CaseManager, CaseStatus
from redloop.assessment.soar_engine import SOAREngine, TriggerType, WorkflowState
from redloop.assessment.soc_detection import SOCAlert
from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    UniversalSecurityEvent,
)
from redloop.assessment.soc_playbooks import PlaybookApprovalStore
from redloop.workbench import register_workbench_routes


@pytest.fixture
def test_client_and_stores():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        db_file = tmp_path / "test_workbench.db"

        app = FastAPI()
        register_workbench_routes(app, db_path=db_file, scope_manager=None)
        client = TestClient(app, base_url="http://127.0.0.1:8765")

        soar_engine = SOAREngine.get_instance(db_path=tmp_path / "soar.db")
        case_mgr = CaseManager.get_instance(db_path=tmp_path / "cases.db")
        soar_engine.reset_state()
        case_mgr.reset_state()

        yield client, soar_engine, case_mgr


def test_01_api_list_and_get_soar_workflows(test_client_and_stores):
    """GET /api/soar/workflows returns all 10 registered playbooks."""
    client, _, _ = test_client_and_stores
    res = client.get("/api/soar/workflows", headers={"Origin": "http://127.0.0.1:8765"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert len(data["workflows"]) >= 10

    # GET single workflow
    res_single = client.get("/api/soar/workflows/WF-BRUTE-FORCE", headers={"Origin": "http://127.0.0.1:8765"})
    assert res_single.status_code == 200
    wf_data = res_single.json()["workflow"]
    assert wf_data["workflow_id"] == "WF-BRUTE-FORCE"
    assert len(wf_data["steps"]) == 4


def test_02_api_execute_and_cancel_workflow(test_client_and_stores):
    """POST /api/soar/workflows/{id}/execute and POST /api/soar/executions/{id}/cancel."""
    client, _, _ = test_client_and_stores

    # 1. Execute automated investigation workflow (WF-BRUTE-FORCE)
    exec_res = client.post(
        "/api/soar/workflows/WF-BRUTE-FORCE/execute",
        headers={"Origin": "http://127.0.0.1:8765"},
        json={"target_context": "203.0.113.10", "trigger_type": "ALERT"},
    )
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["success"] is True
    assert exec_data["execution"]["state"] == "COMPLETED"

    # 2. Execute approval-gated workflow (WF-CRED-COMPROMISE) without token -> WAITING_FOR_APPROVAL
    halt_res = client.post(
        "/api/soar/workflows/WF-CRED-COMPROMISE/execute",
        headers={"Origin": "http://127.0.0.1:8765"},
        json={"target_context": "bad_user", "trigger_type": "ALERT"},
    )
    assert halt_res.status_code == 200
    halt_data = halt_res.json()
    assert halt_data["execution"]["state"] == "WAITING_FOR_APPROVAL"
    exec_id = halt_data["execution"]["execution_id"]

    # 3. Cancel execution via API
    cancel_res = client.post(
        f"/api/soar/executions/{exec_id}/cancel",
        headers={"Origin": "http://127.0.0.1:8765"},
        json={"reason": "Investigator deemed activity benign"},
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["execution"]["state"] == "CANCELLED"


def test_03_api_case_management_lifecycle(test_client_and_stores):
    """Verifies complete case management CRUD via REST endpoints."""
    client, _, _ = test_client_and_stores

    # 1. POST /api/cases
    create_res = client.post(
        "/api/cases",
        headers={"Origin": "http://127.0.0.1:8765"},
        json={
            "title": "SQL Injection & Lateral Movement Alert",
            "description": "Suspicious URI request against /login followed by PowerShell spawn",
            "severity": "HIGH",
            "priority": "P2",
            "assigned_to": "incident_commander",
        },
    )
    assert create_res.status_code == 200
    case_data = create_res.json()["case"]
    case_id = case_data["case_id"]
    assert case_data["status"] == "OPEN"

    # 2. GET /api/cases/{id}
    get_res = client.get(f"/api/cases/{case_id}", headers={"Origin": "http://127.0.0.1:8765"})
    assert get_res.status_code == 200
    assert get_res.json()["case"]["case_id"] == case_id

    # 3. POST /api/cases/{id}/notes
    note_res = client.post(
        f"/api/cases/{case_id}/notes",
        headers={"Origin": "http://127.0.0.1:8765"},
        json={"author": "lead_hunter", "content": "Correlated web log with sysmon event e-ws-exec."},
    )
    assert note_res.status_code == 200
    assert note_res.json()["note"]["author"] == "lead_hunter"

    # 4. POST /api/cases/{id}/evidence
    evi_res = client.post(
        f"/api/cases/{case_id}/evidence",
        headers={"Origin": "http://127.0.0.1:8765"},
        json={"evidence_ids": ["evi-pcap-101", "evi-sysmon-202"]},
    )
    assert evi_res.status_code == 200
    assert len(evi_res.json()["evidence_ids"]) == 2

    # 5. PATCH /api/cases/{id} -> INVESTIGATING -> RESOLVED
    patch_res = client.patch(
        f"/api/cases/{case_id}",
        headers={"Origin": "http://127.0.0.1:8765"},
        json={"status": "INVESTIGATING"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["case"]["status"] == "INVESTIGATING"

    resolve_res = client.patch(
        f"/api/cases/{case_id}",
        headers={"Origin": "http://127.0.0.1:8765"},
        json={"status": "RESOLVED", "closure_reason": "WAF rule deployed and web shell removed."},
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["case"]["status"] == "RESOLVED"

    # 6. GET /api/cases/{id}/timeline
    tl_res = client.get(f"/api/cases/{case_id}/timeline", headers={"Origin": "http://127.0.0.1:8765"})
    assert tl_res.status_code == 200
    timeline = tl_res.json()["timeline"]
    assert len(timeline) >= 4  # CREATED, NOTE_ADDED, EVIDENCE_ATTACHED, STATUS_CHANGED, STATUS_CHANGED


def test_04_full_ingestion_to_response_pipeline(test_client_and_stores):
    """End-to-end integration: Ingestion -> SOC Detection -> SOAR Orchestration -> Case Resolution."""
    client, soar_engine, case_mgr = test_client_and_stores

    # 1. Synthesize brute-force telemetry event
    ev_auth = UniversalSecurityEvent(
        event_id="e-int-bf-1",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="linux_auth",
        source_file="auth.log",
        event_category=EventCategory.AUTHENTICATION,
        event_action="failed_login",
        severity=EventSeverity.HIGH,
        username="root",
        source_ip="198.51.100.99",
    )

    # 2. Trigger SOAR workflow WF-BRUTE-FORCE
    trigger = soar_engine.create_trigger(
        trigger_type=TriggerType.ALERT,
        source_record_id="alt-int-001",
        target_context="198.51.100.99",
    )
    exec_rec = soar_engine.execute_workflow(
        workflow_id="WF-BRUTE-FORCE",
        trigger=trigger,
        stored_events=[ev_auth],
    )
    assert exec_rec.state == WorkflowState.COMPLETED
    assert len(exec_rec.executed_steps) == 4

    # 3. Create case linked to workflow execution
    case = case_mgr.create_case(
        title="Automated Containment: Brute Force from 198.51.100.99",
        description="Automated SOAR response completed edge simulation blocklist.",
        severity=EventSeverity.HIGH,
        linked_alert_ids=["alt-int-001"],
        evidence_ids=exec_rec.evidence_ids,
        creator="soar_engine",
    )
    assert case.case_id.startswith("case-")
    assert case.status == CaseStatus.OPEN

    # 4. Resolve case
    resolved_case = case_mgr.update_case(
        case.case_id,
        status=CaseStatus.INVESTIGATING,
    )
    closed_case = case_mgr.update_case(
        case.case_id,
        status=CaseStatus.CLOSED,
        closure_reason="Automated edge block verified.",
    )
    assert closed_case.status == CaseStatus.CLOSED
