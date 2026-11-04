"""REDLOOP Phase 5.1 — Full Platform Integration Audit, SOC Hardening & End-to-End Verification Suite.

Comprehensive 20-scenario integration suite verifying all modules from Phases 1, 2, 3, 4, 4.1, and 5:
1. Full ingestion-to-detection workflow
2. Full detection-to-incident workflow
3. Incident-to-timeline workflow
4. Incident-to-Copilot workflow
5. Incident-to-report workflow
6. Playbook approval and rejection enforcement
7. Duplicate ingestion deduplication
8. Malformed telemetry handling
9. Timestamp normalization (ISO-8601, epoch s, epoch ms, syslog, apache)
10. Evidence provenance linking
11. Target isolation across sequential queries
12. Concurrent task isolation
13. API pagination and filters
14. Report consistency across formats
15. Missing data behavior (NO_MATCHING_TELEMETRY)
16. Cancellation and timeout behavior
17. Context contamination prevention
18. Invalid approval and replay prevention
19. Detection false-positive scenarios
20. Full application startup and health verification
"""

import json
import threading
import uuid
from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from redloop.assessment.context_resolver import RequestContext, TargetResolver
from redloop.assessment.soc_detection import DetectionRule, SOCAlert, SOCDetectionEngine
from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    TelemetryIngestionEngine,
    TelemetryParsers,
    TimestampNormalizer,
    UniversalSecurityEvent,
)
from redloop.assessment.soc_playbooks import PlaybookStepStatus, SOCPlaybookEngine
from redloop.assessment.soc_timeline import (
    EvidenceObservationClass,
    IncidentRelationType,
    SOCIncident,
    SOCIncidentCorrelator,
    SOCTimelineEngine,
)
from redloop.assessment.soc_copilot import (
    InvestigationLifecycleState,
    InvestigationTask,
    SOCCopilotEngine,
)
from redloop.assessment.terminal_engine import ExecutionStatus, UnifiedTerminalEngine


@pytest.fixture(autouse=True)
def clean_soc_state():
    """Ensures clean playbook and copilot state for every test."""
    SOCPlaybookEngine._reset_playbooks()
    yield
    SOCPlaybookEngine._reset_playbooks()


@pytest.fixture
def integration_api_client(tmp_path):
    """Initializes workbench FastAPI app with SQLite storage for API tests."""
    from fastapi import FastAPI
    from redloop.workbench import register_workbench_routes

    db_path = str(tmp_path / "integration_audit.sqlite")
    app = FastAPI()
    register_workbench_routes(app, db_path=db_path, scope_manager=None)
    return TestClient(app, base_url="http://testserver")


# =========================================================================
# Scenario 1: Full Ingestion-to-Detection Workflow
# =========================================================================

def test_01_full_ingestion_to_detection_workflow():
    """Raw event -> normalized event -> detection rule match -> alert generated with MITRE mapping."""
    raw_web_log = '198.51.100.42 - - [04/Nov/2026:12:00:00 +0000] "GET /api/v1/users?id=1%20UNION%20SELECT%20username,password%20FROM%20admin-- HTTP/1.1" 200 4502'
    event = TelemetryParsers.parse_web_access(raw_web_log, "access.log", "evi-web-1")
    assert event is not None
    assert event.source_ip == "198.51.100.42"
    assert event.event_category == EventCategory.WEB

    det_engine = SOCDetectionEngine()
    alerts = det_engine.run_detections([event])
    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert.rule_id == "SEC-WEB-001"
    assert alert.severity == EventSeverity.HIGH
    assert alert.confidence >= 0.85
    assert alert.matched_event_ids[0] == event.event_id


# =========================================================================
# Scenario 2: Full Detection-to-Incident Workflow
# =========================================================================

def test_02_full_detection_to_incident_workflow():
    """Multiple related alerts -> correlated incident with aggregated severity and playbook."""
    events = [
        UniversalSecurityEvent(
            event_id=f"evt-auth-{i}",
            timestamp="2026-11-04T12:05:00+00:00",
            ingestion_timestamp="2026-11-04T12:05:01+00:00",
            source_type="linux_auth",
            source_file="auth.log",
            event_category=EventCategory.AUTHENTICATION,
            event_action="logon_failed",
            severity=EventSeverity.MEDIUM,
            source_ip="203.0.113.88",
            destination_ip="192.168.1.10",
            username="admin",
            raw_data=f"Failed password for admin attempt {i}",
        )
        for i in range(5)
    ]
    det_engine = SOCDetectionEngine()
    alerts = det_engine.run_detections(events)
    assert len(alerts) >= 1
    assert alerts[0].rule_id == "SEC-AUTH-001"

    incidents = SOCIncidentCorrelator.correlate_alerts(alerts, events)
    assert len(incidents) >= 1
    incident = incidents[0]
    assert incident.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL)
    assert len(incident.alerts) >= 1
    assert incident.recommended_playbook_id == "PB-BRUTE"
    assert "203.0.113.88" in incident.scope_ips or "admin" in incident.scope_users


# =========================================================================
# Scenario 3: Incident-to-Timeline Workflow
# =========================================================================

def test_03_incident_to_timeline_workflow():
    """Incident -> chronological timeline items with observation classes and evidence provenance."""
    e1 = UniversalSecurityEvent(
        event_id="evt-1",
        timestamp="2026-11-04T12:00:00+00:00",
        ingestion_timestamp="2026-11-04T12:00:01+00:00",
        source_type="linux_auth",
        source_file="auth.log",
        event_category=EventCategory.AUTHENTICATION,
        event_action="logon_failed",
        severity=EventSeverity.LOW,
        source_ip="10.0.0.5",
        raw_data="failed login",
    )
    e2 = UniversalSecurityEvent(
        event_id="evt-2",
        timestamp="2026-11-04T12:01:00+00:00",
        ingestion_timestamp="2026-11-04T12:01:01+00:00",
        source_type="sysmon",
        source_file="sysmon.log",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        process_name="powershell.exe",
        severity=EventSeverity.HIGH,
        source_ip="10.0.0.5",
        command_line="powershell -enc aW52b2tl",
        raw_data="powershell encoded",
    )
    a1 = SOCAlert(
        alert_id="alt-1",
        rule_id="SEC-PROC-001",
        title="Obfuscated PowerShell Execution",
        description="PowerShell process with encoded command",
        severity=EventSeverity.HIGH,
        timestamp="2026-11-04T12:01:05+00:00",
        target_ip="10.0.0.5",
        confidence=0.90,
        matched_event_ids=["evt-2"],
    )
    timeline = SOCTimelineEngine.build_timeline([e1, e2], [a1])
    assert len(timeline) == 3
    timestamps = [t.timestamp for t in timeline]
    assert timestamps == sorted(timestamps)
    assert timeline[0].item_type == "event"
    assert timeline[2].item_type == "alert"
    assert timeline[2].source_id == "alt-1"


# =========================================================================
# Scenario 4: Incident-to-Copilot Workflow
# =========================================================================

def test_04_incident_to_copilot_workflow():
    """Natural language query -> entity extraction -> incident retrieval -> playbook recommendation."""
    e = UniversalSecurityEvent(
        event_id="evt-auth-copilot",
        timestamp="2026-11-04T12:10:00+00:00",
        ingestion_timestamp="2026-11-04T12:10:01+00:00",
        source_type="linux_auth",
        source_file="auth.log",
        event_category=EventCategory.AUTHENTICATION,
        event_action="logon_failed",
        severity=EventSeverity.MEDIUM,
        source_ip="198.51.100.77",
        username="operator",
        raw_data="SSH password auth failed",
    )
    a = SOCAlert(
        alert_id="alt-auth-copilot",
        rule_id="SEC-AUTH-001",
        title="SSH Brute-Force Activity",
        description="Repeated failed logons",
        severity=EventSeverity.HIGH,
        timestamp="2026-11-04T12:10:05+00:00",
        target_ip="198.51.100.77",
        target_user="operator",
        confidence=0.88,
        matched_event_ids=["evt-auth-copilot"],
    )
    task = SOCCopilotEngine.start_investigation(
        user_query="Please investigate brute force attack originating from 198.51.100.77",
        events=[e],
        alerts=[a],
    )
    assert task.target_entity == "198.51.100.77"
    assert task.state == InvestigationLifecycleState.COMPLETED
    assert task.recommended_playbook_id == "PB-BRUTE"
    assert "No lateral movement observed" in task.findings_summary
    assert len(task.timeline) >= 2


# =========================================================================
# Scenario 5: Incident-to-Report Workflow
# =========================================================================

def test_05_incident_to_report_workflow():
    """Investigation -> JSON and Markdown reports with schema version, MITRE mappings, and hash."""
    task = SOCCopilotEngine.start_investigation(
        user_query="Investigate 192.168.10.50",
        events=[
            UniversalSecurityEvent(
                event_id="evt-rep-1",
                timestamp="2026-11-04T12:15:00+00:00",
                ingestion_timestamp="2026-11-04T12:15:01+00:00",
                source_type="sysmon",
                source_file="sysmon.log",
                event_category=EventCategory.PROCESS,
                event_action="process_create",
                process_name="powershell.exe",
                severity=EventSeverity.HIGH,
                source_ip="192.168.10.50",
                command_line="powershell -ep bypass -nop -enc cw== ",
                raw_data="ps execution",
            )
        ],
    )
    # JSON report
    rep_json = SOCCopilotEngine.generate_investigation_report(task.investigation_id, format="json")
    assert isinstance(rep_json, dict)
    assert rep_json["schema_version"] == "5.0"
    assert rep_json["target_entity"] == "192.168.10.50"
    assert rep_json["recommended_playbook"] == "PB-PSHELL"

    # Markdown report
    rep_md = SOCCopilotEngine.generate_investigation_report(task.investigation_id, format="markdown")
    assert isinstance(rep_md, str)
    assert "# REDLOOP SOC Investigation Report" in rep_md
    assert "192.168.10.50" in rep_md
    assert "PB-PSHELL" in rep_md


# =========================================================================
# Scenario 6: Playbook Approval and Rejection Enforcement
# =========================================================================

def test_06_playbook_approval_and_rejection_enforcement():
    """Action approval, rejection, and unapproved execution rejection."""
    pb = SOCPlaybookEngine.get_playbook("PB-CRED")
    assert pb is not None
    step = pb.steps[1]
    assert step.requires_approval is True
    assert step.approval_status == PlaybookStepStatus.PENDING

    # Attempt execution before approval -> rejected
    res_exec = SOCPlaybookEngine.execute_step("PB-CRED", step.step_id, auth_token="rl-auth-test-valid")
    assert res_exec["success"] is False
    assert "requires explicit human approval" in res_exec["error"]

    # Rejection workflow
    res_reject = SOCPlaybookEngine.approve_step("PB-CRED", step.step_id, approver="auditor_bob", approved=False)
    assert res_reject["success"] is True
    assert res_reject["status"] == PlaybookStepStatus.REJECTED.value

    # Lead override to approved
    res_app = SOCPlaybookEngine.approve_step("PB-CRED", step.step_id, approver="soc_lead_carol", approved=True)
    assert res_app["success"] is True
    assert res_app["status"] == PlaybookStepStatus.APPROVED.value

    # Now execution succeeds with valid token
    res_exec_ok = SOCPlaybookEngine.execute_step("PB-CRED", step.step_id, auth_token=res_app.get("capability_token", "rl-auth-lead-session-token"))
    assert res_exec_ok["success"] is True
    assert res_exec_ok["status"] == PlaybookStepStatus.EXECUTED.value


# =========================================================================
# Scenario 7: Duplicate Ingestion Deduplication
# =========================================================================

def test_07_duplicate_ingestion_deduplication(tmp_path):
    """Ingesting duplicate lines skips duplicates using deterministic content hashing."""
    log_file = tmp_path / "dup_test.log"
    log_file.write_text(
        "Oct 24 14:12:05 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.50 port 44222 ssh2\n"
        "Oct 24 14:12:05 web01 sshd[12345]: Failed password for invalid user admin from 192.168.1.50 port 44222 ssh2\n",
        encoding="utf-8",
    )
    engine = TelemetryIngestionEngine()
    res = engine.ingest_file(log_file, source_type="linux_auth")
    assert res["success"] is True
    assert res["total_ingested"] == 1
    assert res["duplicates_skipped"] == 1


# =========================================================================
# Scenario 8: Malformed Telemetry Handling
# =========================================================================

def test_08_malformed_telemetry_handling(tmp_path):
    """Ingesting corrupt JSON logs handles errors gracefully without crashing."""
    corrupt_file = tmp_path / "corrupt.json"
    corrupt_file.write_text("{ corrupt json syntax missing colon\n", encoding="utf-8")

    engine = TelemetryIngestionEngine()
    res = engine.ingest_file(corrupt_file, source_type="json")
    assert res["success"] is True
    assert res["total_ingested"] == 0
    assert len(engine.events) == 0


# =========================================================================
# Scenario 9: Timestamp Normalization
# =========================================================================

def test_09_timestamp_normalization():
    """Normalizes ISO-8601, epoch seconds, epoch milliseconds, syslog, and Apache formats to UTC ISO."""
    iso_norm = TimestampNormalizer.normalize("2026-11-04T12:30:00Z")
    assert "2026-11-04" in iso_norm

    epoch_s_norm = TimestampNormalizer.normalize(1762259400)
    assert len(epoch_s_norm) > 10

    epoch_ms_norm = TimestampNormalizer.normalize(1762259400000)
    assert len(epoch_ms_norm) > 10

    syslog_norm = TimestampNormalizer.normalize("Nov  4 12:30:00")
    assert "12:30:00" in syslog_norm

    apache_norm = TimestampNormalizer.normalize("04/Nov/2026:12:30:00 +0000")
    assert "2026-11-04" in apache_norm


# =========================================================================
# Scenario 10: Evidence Provenance Linking
# =========================================================================

def test_10_evidence_provenance_linking():
    """Verifiable hash linking from raw payload -> normalized event -> alert -> timeline item."""
    raw_payload = "Oct 24 14:12:05 web01 sshd[12345]: Failed password for invalid user root from 198.51.100.99 port 54321 ssh2"
    event = TelemetryParsers.parse_linux_auth(raw_payload, "auth.log", "evi-prov-1")
    assert event is not None
    assert event.event_hash != ""

    alert = SOCAlert(
        alert_id="alt-prov-1",
        rule_id="SEC-AUTH-001",
        title="SSH Brute-Force",
        description="Repeated failed authentications",
        severity=EventSeverity.HIGH,
        timestamp=event.timestamp,
        target_ip=event.source_ip,
        confidence=0.90,
        matched_event_ids=[event.event_id],
    )
    timeline = SOCTimelineEngine.build_timeline([event], [alert])
    assert len(timeline) == 2
    assert timeline[0].source_id == event.event_id
    assert timeline[0].raw_evidence_id == event.raw_evidence_id
    assert timeline[1].source_id == alert.alert_id


# =========================================================================
# Scenario 11: Target Isolation Across Sequential Queries
# =========================================================================

def test_11_target_isolation_across_sequential_queries():
    """Query A targets 10.0.0.1 -> Query B has no target -> Query B must NOT inherit 10.0.0.1."""
    target_a, ttype_a, src_a = TargetResolver.resolve_target("Assess 10.0.0.1", context={})
    assert target_a == "10.0.0.1"
    assert ttype_a == "ip"
    assert src_a == "prompt"

    target_b, ttype_b, src_b = TargetResolver.resolve_target("Summarize overall platform security posture", context={})
    assert target_b is None
    assert ttype_b == "none"
    assert src_b == "none"

    stale_ctx = {"target": "10.0.0.1", "ambient_target": "10.0.0.1"}
    target_c, ttype_c, src_c = TargetResolver.resolve_target("What is zero trust architecture?", context=stale_ctx)
    assert target_c is None
    assert ttype_c == "none"


# =========================================================================
# Scenario 12: Concurrent Task Isolation
# =========================================================================

def test_12_concurrent_task_isolation():
    """Concurrent investigations for different targets maintain distinct state and no leaked data."""
    ev_a = UniversalSecurityEvent(
        event_id="evt-conc-a",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="linux_auth",
        source_file="auth.log",
        event_category=EventCategory.AUTHENTICATION,
        event_action="logon_failed",
        severity=EventSeverity.LOW,
        source_ip="10.1.1.1",
        raw_data="Login from 10.1.1.1",
    )
    ev_b = UniversalSecurityEvent(
        event_id="evt-conc-b",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="sysmon",
        source_file="sysmon.log",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        process_name="test.exe",
        severity=EventSeverity.HIGH,
        source_ip="10.2.2.2",
        raw_data="Exec on 10.2.2.2",
    )
    task_a = SOCCopilotEngine.start_investigation("Triage host 10.1.1.1", events=[ev_a, ev_b])
    task_b = SOCCopilotEngine.start_investigation("Triage host 10.2.2.2", events=[ev_a, ev_b])

    assert task_a.investigation_id != task_b.investigation_id
    assert task_a.target_entity == "10.1.1.1"
    assert task_b.target_entity == "10.2.2.2"
    assert all("10.1.1.1" in t.title or t.source_ip == "10.1.1.1" or "evt-conc-a" in t.source_id for t in task_a.timeline)
    assert all("10.2.2.2" in t.title or t.source_ip == "10.2.2.2" or "evt-conc-b" in t.source_id for t in task_b.timeline)


# =========================================================================
# Scenario 13: API Pagination and Filters
# =========================================================================

def test_13_api_pagination_and_filters(integration_api_client):
    """API endpoint /api/soc/events enforces limit, offset, severity, and category filtering."""
    log_lines = []
    for i in range(25):
        log_lines.append(f'10.0.0.{i} - - [10/Oct/2026:13:{i:02d}:00 +0000] "GET /page_{i} HTTP/1.1" 200 100')
    content = "\n".join(log_lines)

    res_ingest = integration_api_client.post(
        "/api/soc/ingest",
        json={"content": content, "source_type": "web_access"},
        headers={"Origin": "http://testserver"},
    )
    assert res_ingest.status_code == 200

    res_page = integration_api_client.get("/api/soc/events?limit=10&offset=5")
    assert res_page.status_code == 200
    data = res_page.json()
    assert len(data["events"]) == 10
    assert data["limit"] == 10
    assert data["offset"] == 5
    assert data["total"] >= 25


# =========================================================================
# Scenario 14: Report Consistency Across Formats
# =========================================================================

def test_14_report_consistency_across_formats():
    """JSON and Markdown reports for the same investigation contain identical findings and entities."""
    task = SOCCopilotEngine.start_investigation("Investigate suspected breach on 172.20.10.1")
    rep_json = SOCCopilotEngine.generate_investigation_report(task.investigation_id, format="json")
    rep_md = SOCCopilotEngine.generate_investigation_report(task.investigation_id, format="markdown")

    assert isinstance(rep_json, dict)
    assert isinstance(rep_md, str)
    assert rep_json["target_entity"] == "172.20.10.1"
    assert "172.20.10.1" in rep_md
    assert rep_json["investigation_id"] == task.investigation_id
    assert task.investigation_id in rep_md
    assert rep_json["state"] in rep_md


# =========================================================================
# Scenario 15: Missing Data Behavior (NO_MATCHING_TELEMETRY)
# =========================================================================

def test_15_missing_data_no_matching_telemetry():
    """Target with zero ingested telemetry explicitly returns NO_MATCHING_TELEMETRY and lists gaps."""
    task = SOCCopilotEngine.start_investigation(
        user_query="Investigate compromised database host 192.0.2.254",
        events=[],
        alerts=[],
    )
    assert task.state == InvestigationLifecycleState.NO_MATCHING_TELEMETRY
    assert task.telemetry_status == "NO_MATCHING_TELEMETRY"
    assert task.confidence_score == 0.0
    assert "NO_MATCHING_TELEMETRY" in task.findings_summary
    assert len(task.missing_evidence) >= 3
    assert "clean" not in task.findings_summary.lower()
    assert "safe" not in task.findings_summary.lower()


# =========================================================================
# Scenario 16: Cancellation and Timeout Behavior
# =========================================================================

def test_16_cancellation_and_timeout_behavior():
    """Cancellation token immediately halts operations and records cancelled status."""
    token = threading.Event()
    token.set()  # Pre-cancelled token
    engine = UnifiedTerminalEngine()
    res = engine.execute_command(
        command_string_or_args=["ping", "127.0.0.1"],
        timeout_seconds=5,
        cancel_token=token,
    )
    assert res.cancelled is True
    assert res.status == ExecutionStatus.CANCELLED


# =========================================================================
# Scenario 17: Context Contamination Prevention
# =========================================================================

def test_17_context_contamination_prevention():
    """General conceptual query after investigation does NOT inherit target or mention prior entities."""
    task_prior = SOCCopilotEngine.start_investigation("Investigate targeted host 198.51.100.88")
    assert task_prior.target_entity == "198.51.100.88"

    task_general = SOCCopilotEngine.start_investigation("What is DNS tunneling and how does it work?")
    assert task_general.target_entity != "198.51.100.88"
    assert "198.51.100.88" not in task_general.findings_summary
    assert task_general.telemetry_status == "NOT_APPLICABLE"
    assert "DNS Tunneling Overview" in task_general.findings_summary


# =========================================================================
# Scenario 18: Invalid Approval and Replay Prevention
# =========================================================================

def test_18_invalid_approval_and_replay_prevention():
    """Replay of already-approved step or execution without authorization token is rejected."""
    # Approve step
    res1 = SOCPlaybookEngine.approve_step("PB-MALWARE", "step-mal-2", approver="lead_frank", approved=True)
    assert res1["success"] is True
    assert res1["status"] == PlaybookStepStatus.APPROVED.value

    # Replay attempt must be rejected
    res_replay = SOCPlaybookEngine.approve_step("PB-MALWARE", "step-mal-2", approver="lead_frank", approved=True)
    assert res_replay["success"] is False
    assert "already been resolved" in res_replay["error"]

    # Execution with missing/invalid auth token must be rejected
    res_exec_bad_tok = SOCPlaybookEngine.execute_step("PB-MALWARE", "step-mal-2", auth_token="invalid-token")
    assert res_exec_bad_tok["success"] is False
    assert "authorization token" in res_exec_bad_tok["error"]


# =========================================================================
# Scenario 19: Detection False-Positive Scenarios
# =========================================================================

def test_19_detection_false_positive_scenarios():
    """Benign operational events do not generate high or critical severity alerts."""
    benign_events = [
        UniversalSecurityEvent(
            event_id="evt-benign-1",
            timestamp="2026-11-04T12:00:00Z",
            ingestion_timestamp="2026-11-04T12:00:01Z",
            source_type="linux_auth",
            source_file="auth.log",
            event_category=EventCategory.AUTHENTICATION,
            event_action="logon_failed",
            severity=EventSeverity.LOW,
            source_ip="192.168.1.50",
            username="alice",
            raw_data="User mistyped password once",
        ),
        UniversalSecurityEvent(
            event_id="evt-benign-2",
            timestamp="2026-11-04T12:00:05Z",
            ingestion_timestamp="2026-11-04T12:00:06Z",
            source_type="web_access",
            source_file="access.log",
            event_category=EventCategory.WEB,
            event_action="http_request",
            severity=EventSeverity.INFORMATIONAL,
            source_ip="192.168.1.50",
            destination_port=80,
            command_line="GET /assets/style.css HTTP/1.1",
            raw_data="Normal CSS request",
        ),
    ]
    det_engine = SOCDetectionEngine()
    alerts = det_engine.run_detections(benign_events)
    assert not any(a.rule_id == "SEC-AUTH-001" for a in alerts)
    assert not any(a.rule_id in ("SEC-WEB-001", "SEC-WEB-002") for a in alerts)
    assert not any(a.severity in (EventSeverity.HIGH, EventSeverity.CRITICAL) for a in alerts)


# =========================================================================
# Scenario 20: Full Application Startup and Health Verification
# =========================================================================

def test_20_full_application_startup_and_health_verification(integration_api_client):
    """Full application routes /api/soc/events, /api/soc/playbooks, and /health are responsive."""
    res_events = integration_api_client.get("/api/soc/events")
    assert res_events.status_code == 200
    assert "events" in res_events.json()

    res_pb = integration_api_client.get("/api/soc/playbooks")
    assert res_pb.status_code == 200
    assert len(res_pb.json()["playbooks"]) == 8

    res_health = integration_api_client.get("/api/tools/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"].upper() in ("OK", "HEALTHY")
