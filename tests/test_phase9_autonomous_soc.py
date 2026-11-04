"""REDLOOP Autonomous SOC Operations & Detection Engineering Test Suite (Phase 9).

Validates:
1. Unified Telemetry Synchronization Pipeline (soc_sync)
2. Cross-Platform Detection Engineering Layer (detection_engineering)
3. Cross-Platform Incident Correlation Engine (incident_correlation)
4. Threat Intelligence & IOC Lifecycle Engine (ioc_engine)
5. SOC Operational Metrics (soc_metrics)
6. Copilot Operational Intelligence (soc_copilot)
7. Phase 9 REST API Endpoints (workbench)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from redloop.assessment.detection_engineering import (
    DetectionEngineeringManager,
    DetectionRule,
    RuleSeverity,
    RuleSource,
)
from redloop.assessment.incident_correlation import (
    IncidentCorrelationEngine,
    RelationshipType,
)
from redloop.assessment.ioc_engine import (
    IOCLifecycleManager,
    IOCState,
    IOCType,
)
from redloop.assessment.soc_copilot import SOCCopilotEngine
from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    ParserStatus,
    UniversalSecurityEvent,
)
from redloop.assessment.soc_metrics import SOCMetricsEngine
from redloop.assessment.soc_sync import (
    SyncJobStatus,
    TelemetrySyncPipeline,
)
from redloop.unified_app import get_app


@pytest.fixture
def tmp_sync_pipeline(tmp_path: Path):
    db = tmp_path / "telemetry_sync.db"
    pipe = TelemetrySyncPipeline.get_instance(db_path=db)
    pipe.reset_state()
    return pipe


@pytest.fixture
def tmp_detection_mgr(tmp_path: Path):
    db = tmp_path / "detections.db"
    mgr = DetectionEngineeringManager.get_instance(db_path=db)
    mgr.reset_state()
    return mgr


@pytest.fixture
def tmp_correlation_engine(tmp_path: Path):
    db = tmp_path / "incidents.db"
    engine = IncidentCorrelationEngine.get_instance(db_path=db)
    engine.reset_state()
    return engine


@pytest.fixture
def tmp_ioc_mgr(tmp_path: Path):
    db = tmp_path / "iocs.db"
    mgr = IOCLifecycleManager.get_instance(db_path=db)
    mgr.reset_state()
    return mgr


@pytest.fixture
def test_event():
    now_iso = datetime.now(timezone.utc).isoformat()
    return UniversalSecurityEvent(
        event_id="EVT-TEST-001",
        timestamp=now_iso,
        ingestion_timestamp=now_iso,
        source_type="edr_defender",
        source_file="edr_stream.json",
        hostname="WS-FINANCE-01",
        username="jdoe",
        source_ip="192.168.1.100",
        destination_ip="203.0.113.50",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        process_name="powershell.exe",
        command_line="powershell.exe -enc SQBFAFgA",
        file_hash="d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e5e31e07f3ff5",
        severity=EventSeverity.HIGH,
        parser_status=ParserStatus.NORMALIZED,
    )


# ==============================================================================
# B1: TELEMETRY SYNC PIPELINE TESTS
# ==============================================================================

def test_sync_job_lifecycle_and_cancellation(tmp_sync_pipeline: TelemetrySyncPipeline):
    # Job creation
    job = tmp_sync_pipeline.create_sync_job(provider_id="splunk")
    assert job.status == SyncJobStatus.CREATED
    assert job.events_synced == 0

    # Cancellation
    cancelled = tmp_sync_pipeline.cancel_sync_job(job.job_id)
    assert cancelled is True

    updated_job = tmp_sync_pipeline.get_sync_job(job.job_id)
    assert updated_job is not None
    assert updated_job.status == SyncJobStatus.CANCELLED
    assert "Cancelled" in (updated_job.partial_reason or "")


def test_sync_event_deduplication(tmp_sync_pipeline: TelemetrySyncPipeline, test_event: UniversalSecurityEvent):
    job = tmp_sync_pipeline.create_sync_job(provider_id="edr_defender")

    # Ingest event 1st time
    ok1 = tmp_sync_pipeline.ingest_event(test_event, sync_job_id=job.job_id)
    assert ok1 is True

    # Ingest same event 2nd time -> Deduplication ignores insertion
    ok2 = tmp_sync_pipeline.ingest_event(test_event, sync_job_id=job.job_id)
    assert ok2 is False  # Duplicate ignored

    events = tmp_sync_pipeline.query_events(provider_id="edr_defender")
    assert len(events) == 1
    assert events[0]["original_event_id"] == "EVT-TEST-001"
    assert "EDR_DEFENDER" in events[0]["provenance"]


def test_sync_metrics_calculation(tmp_sync_pipeline: TelemetrySyncPipeline, test_event: UniversalSecurityEvent):
    job = tmp_sync_pipeline.execute_sync(
        provider_id="edr_defender",
        limit=10,
        mock_events=[test_event],
    )
    assert job.status == SyncJobStatus.COMPLETED
    assert job.events_synced == 1
    assert job.events_failed == 0

    metrics = tmp_sync_pipeline.get_sync_metrics()
    assert metrics["total_events_ingested"] == 1
    assert metrics["total_sync_jobs"] >= 1
    assert metrics["sync_success_rate_percent"] > 0.0


# ==============================================================================
# B2: DETECTION ENGINEERING TESTS
# ==============================================================================

def test_detection_rule_validation(tmp_detection_mgr: DetectionEngineeringManager):
    # Valid rule
    rule = DetectionRule(
        rule_id="RL-DET-TEST",
        title="Valid Test Rule Title",
        description="Testing schema validation.",
        source=RuleSource.NATIVE,
        version="1.0",
        technique_id="T1059.001",
        tactic="Execution",
        severity=RuleSeverity.HIGH,
        confidence=0.85,
        data_sources=["process_creation"],
    )
    assert tmp_detection_mgr.validate_rule(rule) is True
    registered = tmp_detection_mgr.register_rule(rule)
    assert registered.rule_id == "RL-DET-TEST"

    # Invalid confidence
    with pytest.raises(ValueError, match="Confidence score"):
        bad_rule = DetectionRule(
            rule_id="RL-DET-BAD",
            title="Bad Confidence Rule",
            description="Testing.",
            source=RuleSource.NATIVE,
            version="1.0",
            technique_id="T1059",
            tactic="Execution",
            severity=RuleSeverity.LOW,
            confidence=1.5,  # > 1.0
            data_sources=[],
        )
        tmp_detection_mgr.validate_rule(bad_rule)

    # Invalid technique format
    with pytest.raises(ValueError, match="Invalid MITRE ATT&CK technique"):
        bad_tech = DetectionRule(
            rule_id="RL-DET-BAD2",
            title="Bad Technique Rule",
            description="Testing.",
            source=RuleSource.NATIVE,
            version="1.0",
            technique_id="INVALID123",
            tactic="Execution",
            severity=RuleSeverity.LOW,
            confidence=0.5,
            data_sources=[],
        )
        tmp_detection_mgr.validate_rule(bad_tech)


def test_detection_test_harness_positive_and_negative(tmp_detection_mgr: DetectionEngineeringManager):
    # Test built-in PowerShell rule (RL-DET-001)
    result = tmp_detection_mgr.run_rule_test_harness("RL-DET-001")
    assert result["all_tests_passed"] is True
    assert result["cases_executed"] >= 2
    for r in result["results"]:
        assert r["passed"] is True


def test_detection_false_positive_tracking(tmp_detection_mgr: DetectionEngineeringManager):
    ok = tmp_detection_mgr.mark_false_positive("RL-DET-001", actor="analyst", reason="Legitimate IT maintenance script")
    assert ok is True

    rule = tmp_detection_mgr.get_rule("RL-DET-001")
    assert rule is not None
    assert rule.false_positive_count >= 1


def test_attack_coverage_matrix(tmp_detection_mgr: DetectionEngineeringManager):
    matrix = tmp_detection_mgr.get_attack_coverage_matrix()
    assert matrix["total_active_rules"] >= 4
    assert matrix["covered_techniques_count"] >= 4
    assert matrix["coverage_ratio_percent"] > 0.0
    assert isinstance(matrix["identified_detection_gaps"], list)


# ==============================================================================
# B3: INCIDENT CORRELATION TESTS
# ==============================================================================

def test_incident_correlation_entity_overlap(tmp_correlation_engine: IncidentCorrelationEngine, test_event: UniversalSecurityEvent):
    # First event forms a new incident
    inc1 = tmp_correlation_engine.correlate_event(test_event)
    assert inc1.incident_id.startswith("INC-")
    assert inc1.primary_host == "WS-FINANCE-01"
    assert inc1.primary_user == "jdoe"
    assert len(inc1.linked_events) == 1

    # Second event with same host AND same user -> High entity overlap (Confirmed observation)
    now_iso = datetime.now(timezone.utc).isoformat()
    ev2 = UniversalSecurityEvent(
        event_id="EVT-TEST-002",
        timestamp=now_iso,
        source_type="wazuh",
        source_file="wazuh.log",
        hostname="WS-FINANCE-01",
        username="jdoe",
        source_ip="192.168.1.100",
        destination_ip="203.0.113.99",
        event_category=EventCategory.NETWORK,
        event_action="network_connection",
        severity=EventSeverity.HIGH,
        parser_status=ParserStatus.NORMALIZED,
    )
    inc2 = tmp_correlation_engine.correlate_event(ev2)
    # Correlated into the same incident
    assert inc2.incident_id == inc1.incident_id
    assert len(inc2.linked_events) == 2
    assert inc2.confirmed_observations_count >= 1


def test_incident_merge_and_split(tmp_correlation_engine: IncidentCorrelationEngine):
    now_iso = datetime.now(timezone.utc).isoformat()
    # Create two distinct incidents
    ev1 = UniversalSecurityEvent(
        event_id="EVT-A1",
        timestamp=now_iso,
        source_type="splunk",
        source_file="auth.log",
        hostname="SRV-LINUX-01",
        username="root",
        event_action="ssh_login",
    )
    ev2 = UniversalSecurityEvent(
        event_id="EVT-B1",
        timestamp=now_iso,
        source_type="splunk",
        source_file="access.log",
        hostname="SRV-WEB-02",
        username="www-data",
        event_action="file_upload",
    )
    inc1 = tmp_correlation_engine.correlate_event(ev1)
    inc2 = tmp_correlation_engine.correlate_event(ev2)
    assert inc1.incident_id != inc2.incident_id

    # Merge inc2 into inc1
    merged = tmp_correlation_engine.merge_incidents(
        primary_incident_id=inc1.incident_id,
        secondary_incident_id=inc2.incident_id,
        rationale="Shared external attacker IP corroborated via C2 feed.",
    )
    assert len(merged.linked_events) == 2
    sec_check = tmp_correlation_engine.get_incident(inc2.incident_id)
    assert sec_check is not None
    assert sec_check.merged_into == inc1.incident_id

    # Split EVT-B1 back out
    orig, new_inc = tmp_correlation_engine.split_incident(
        incident_id=inc1.incident_id,
        event_ids_to_split=["EVT-B1"],
        reason="Separate campaign confirmed by threat hunting team.",
    )
    assert len(orig.linked_events) == 1
    assert orig.linked_events[0].event_id == "EVT-A1"
    assert len(new_inc.linked_events) == 1
    assert new_inc.linked_events[0].event_id == "EVT-B1"


# ==============================================================================
# B5: THREAT INTELLIGENCE & IOC LIFECYCLE TESTS
# ==============================================================================

def test_ioc_registration_and_disposition(tmp_ioc_mgr: IOCLifecycleManager):
    rec = tmp_ioc_mgr.register_ioc(
        ioc_type=IOCType.IP,
        value="198.51.100.25",
        source="suricata_alert",
        confidence=0.8,
    )
    assert rec.ioc_id.startswith("ioc-")
    assert rec.state == IOCState.NEW

    # Update disposition to CONFIRMED_MALICIOUS
    updated = tmp_ioc_mgr.set_disposition(
        ioc_id=rec.ioc_id,
        state=IOCState.CONFIRMED_MALICIOUS,
        reason="Confirmed C2 node by external threat bulletin.",
        actor="soc_lead",
    )
    assert updated.state == IOCState.CONFIRMED_MALICIOUS
    assert updated.reputation == "CONFIRMED_MALICIOUS"
    assert updated.confidence == 1.0
    assert updated.analyst_disposition == "CONFIRMED_MALICIOUS"


def test_ioc_non_fabrication_reputation(tmp_ioc_mgr: IOCLifecycleManager):
    rec = tmp_ioc_mgr.register_ioc(
        ioc_type=IOCType.HASH,
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        source="local_scan",
    )
    # Default reputation must be UNKNOWN, NEVER fabricated as benign
    assert rec.reputation == "UNKNOWN"
    assert rec.state == IOCState.NEW


# ==============================================================================
# B7: OPERATIONAL METRICS TESTS
# ==============================================================================

def test_soc_operational_metrics_calculation(tmp_sync_pipeline: TelemetrySyncPipeline, tmp_correlation_engine: IncidentCorrelationEngine):
    metrics = SOCMetricsEngine.get_operational_metrics()
    assert "mean_time_to_detect_minutes" in metrics
    assert "mean_time_to_respond_minutes" in metrics
    assert "telemetry_sync_rate_percent" in metrics
    assert "provider_availability_percent" in metrics
    assert "alert_reduction_rate_percent" in metrics
    assert isinstance(metrics["telemetry_sync_rate_percent"], (int, float))


# ==============================================================================
# B8: COPILOT OPERATIONAL INTELLIGENCE TESTS
# ==============================================================================

def test_copilot_operational_intent_investigate_incident(tmp_correlation_engine: IncidentCorrelationEngine, test_event: UniversalSecurityEvent):
    inc = tmp_correlation_engine.correlate_event(test_event)

    res = SOCCopilotEngine.handle_operational_query(
        user_query=f"Investigate this incident {inc.incident_id}",
    )
    assert res["intent"] == "investigate_incident"
    assert res["status"] == "COMPLETED"
    assert res["incident_id"] == inc.incident_id
    assert len(res["evidence_citations"]) >= 1


def test_copilot_operational_intent_prepare_containment():
    res = SOCCopilotEngine.handle_operational_query(
        user_query="Prepare containment plan for host WS-FINANCE-01",
        entity_id="WS-FINANCE-01",
    )
    assert res["intent"] == "prepare_containment"
    assert res["status"] == "PLAN_PREPARED"
    plan = res["containment_plan"]
    assert plan["target_resource"] == "WS-FINANCE-01"
    assert plan["approval_required"] is True
    assert "Cryptographic" in plan["governance_rule"]


def test_copilot_operational_intent_verify_isolation():
    res = SOCCopilotEngine.handle_operational_query(
        user_query="Verify endpoint isolated for host WS-FINANCE-01",
        entity_id="WS-FINANCE-01",
    )
    assert res["intent"] == "verify_isolation"
    assert res["target"] == "WS-FINANCE-01"
    # Never fakes isolation when EDR is offline/unconfigured
    assert res["verified_with_live_edr"] is False


# ==============================================================================
# REST API INTEGRATION TESTS (FASTAPI)
# ==============================================================================

@pytest.fixture
def client():
    app = get_app()
    return TestClient(app)


def test_api_soc_sync_endpoints(client: TestClient):
    headers = {"Origin": "http://testserver"}

    # List jobs
    res = client.get("/api/soc/sync/jobs", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "jobs" in data

    # Trigger sync (unregistered/offline provider gracefully reports FAILED without network latency)
    res_trig = client.post("/api/soc/sync/trigger", json={"provider_id": "unregistered_test", "limit": 10}, headers=headers)
    assert res_trig.status_code == 200
    assert res_trig.json()["success"] is True
    assert res_trig.json()["sync_job"]["status"] == "FAILED"

    # Sync metrics
    res_m = client.get("/api/soc/sync/metrics", headers=headers)
    assert res_m.status_code == 200
    assert "metrics" in res_m.json()


def test_api_detections_endpoints(client: TestClient):
    headers = {"Origin": "http://testserver"}

    # List rules
    res = client.get("/api/detections/rules", headers=headers)
    assert res.status_code == 200
    rules = res.json()["rules"]
    assert len(rules) >= 4

    # Run test harness
    res_t = client.post("/api/detections/rules/RL-DET-001/test", headers=headers)
    assert res_t.status_code == 200
    assert res_t.json()["test_result"]["all_tests_passed"] is True

    # Coverage matrix
    res_c = client.get("/api/detections/coverage", headers=headers)
    assert res_c.status_code == 200
    assert res_c.json()["coverage"]["covered_techniques_count"] >= 4

    # Report false positive
    res_fp = client.post("/api/detections/rules/RL-DET-001/false-positive", json={"reason": "Testing FP endpoint"}, headers=headers)
    assert res_fp.status_code == 200
    assert res_fp.json()["success"] is True


def test_api_incidents_endpoints(client: TestClient):
    headers = {"Origin": "http://testserver"}

    # List incidents
    res = client.get("/api/incidents", headers=headers)
    assert res.status_code == 200
    assert res.json()["success"] is True

    # Correlate event
    event_payload = {
        "event_id": "EVT-API-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "wazuh",
        "source_file": "api_test.log",
        "hostname": "SRV-API-01",
        "source_ip": "10.0.0.50",
    }
    res_corr = client.post("/api/incidents/correlate", json={"event": event_payload}, headers=headers)
    assert res_corr.status_code == 200
    assert res_corr.json()["success"] is True
    inc_id = res_corr.json()["incident"]["incident_id"]

    # Get incident
    res_get = client.get(f"/api/incidents/{inc_id}", headers=headers)
    assert res_get.status_code == 200
    assert res_get.json()["incident"]["primary_host"] == "SRV-API-01"


def test_api_iocs_endpoints(client: TestClient):
    headers = {"Origin": "http://testserver"}

    # Create IOC
    res_c = client.post(
        "/api/iocs",
        json={"ioc_type": "IP", "value": "198.51.100.99", "source": "threat_feed", "confidence": 0.9},
        headers=headers,
    )
    assert res_c.status_code == 200
    ioc_id = res_c.json()["ioc"]["ioc_id"]

    # Get IOC
    res_g = client.get(f"/api/iocs/{ioc_id}", headers=headers)
    assert res_g.status_code == 200
    assert res_g.json()["ioc"]["value"] == "198.51.100.99"

    # Update disposition
    res_d = client.post(
        f"/api/iocs/{ioc_id}/disposition",
        json={"state": "CONFIRMED_MALICIOUS", "reason": "Verified active threat"},
        headers=headers,
    )
    assert res_d.status_code == 200
    assert res_d.json()["ioc"]["state"] == "CONFIRMED_MALICIOUS"


def test_api_soc_metrics_and_copilot_operational(client: TestClient):
    headers = {"Origin": "http://testserver"}

    # SOC metrics
    res_m = client.get("/api/metrics/soc", headers=headers)
    assert res_m.status_code == 200
    assert res_m.json()["success"] is True
    assert "mean_time_to_detect_minutes" in res_m.json()["metrics"]

    # Copilot Operational query
    res_cop = client.post(
        "/api/soc/copilot/op",
        json={"query": "Recommend next step for active incidents"},
        headers=headers,
    )
    assert res_cop.status_code == 200
    result = res_cop.json()["result"]
    assert result["intent"] == "recommend_next_step"
    assert "recommendations" in result
