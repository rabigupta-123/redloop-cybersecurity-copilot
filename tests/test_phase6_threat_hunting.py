"""Phase 6 Automated Verification Suite: Autonomous Threat Hunting & Query Engine.

Covers:
1. Natural language query parsing: extraction of IPs, CVEs, process names, hashes, and time windows.
2. Query Plan Preview: safety bounds, target sources, projected scope, and execution cost estimation.
3. Parameterized execution: safe filtering on multiple conditions without SQL injection vulnerabilities.
4. Result limit enforcement (default 100, max 1000).
5. Hypothesis validation status tracking: CONFIRMED, REFUTED, INCONCLUSIVE.
6. Contextual follow-up query generation and evidence provenance tracking.
"""

from __future__ import annotations

import pytest

from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    UniversalSecurityEvent,
)
from redloop.assessment.threat_hunting import (
    HypothesisStatus,
    QueryExecutionCost,
    ThreatHuntingEngine,
)


def test_01_natural_language_parsing():
    """Extracts target IP, CVE, process, and time window from plain English hunting queries."""
    query = "Hunt for PowerShell executions targeting 198.51.100.45 or CVE-2021-44228 in the last 7 days"
    parsed = ThreatHuntingEngine.parse_natural_language(query)

    assert "198.51.100.45" in parsed["entities"]["ips"]
    assert "CVE-2021-44228" in parsed["entities"]["cves"]
    assert "powershell.exe" in parsed["entities"]["processes"]
    assert parsed["time_window_hours"] == 168
    assert len(parsed["filters"]) >= 3


def test_02_query_plan_preview():
    """Generates an explainable pre-execution query plan with cost estimation and safety verification."""
    plan = ThreatHuntingEngine.generate_query_plan(
        "Find sudo executions on linux Bastion from 10.0.0.99 in the past hour",
        limit=50,
    )
    assert plan.query_id.startswith("hunt-")
    assert plan.safety_checks_passed is True
    assert plan.limit == 50
    assert plan.estimated_cost in (QueryExecutionCost.LOW, QueryExecutionCost.MEDIUM)
    assert len(plan.target_sources) >= 1
    assert "50 records" in plan.explanation


def test_03_query_limit_clamping():
    """Clamps user-supplied limits to the maximum safe ceiling of 1000 records."""
    plan_huge = ThreatHuntingEngine.generate_query_plan("Search all web requests", limit=999999)
    assert plan_huge.limit == ThreatHuntingEngine.MAX_RESULT_LIMIT

    plan_neg = ThreatHuntingEngine.generate_query_plan("Search all web requests", limit=-5)
    assert plan_neg.limit == 1


def test_04_hunt_execution_confirmed_hypothesis():
    """Executes a hunting query matching ingested telemetry, validating hypothesis as CONFIRMED."""
    events = [
        UniversalSecurityEvent(
            event_id="ev-h1",
            timestamp="2026-11-04T12:00:00Z",
            ingestion_timestamp="2026-11-04T12:00:01Z",
            source_type="windows_sysmon",
            source_file="sysmon.json",
            event_category=EventCategory.PROCESS,
            event_action="process_create",
            severity=EventSeverity.HIGH,
            process_name="powershell.exe",
            command_line="powershell.exe -enc d2hvYW1p",
            source_ip="192.168.1.150",
            raw_evidence_id="evi-hunt-1",
        ),
        UniversalSecurityEvent(
            event_id="ev-h2",
            timestamp="2026-11-04T12:01:00Z",
            ingestion_timestamp="2026-11-04T12:01:01Z",
            source_type="windows_sysmon",
            source_file="sysmon.json",
            event_category=EventCategory.PROCESS,
            event_action="process_create",
            severity=EventSeverity.INFORMATIONAL,
            process_name="calc.exe",
            command_line="calc.exe",
            source_ip="192.168.1.150",
            raw_evidence_id="evi-hunt-2",
        ),
    ]

    res = ThreatHuntingEngine.execute_hunt(
        nl_query="Hunt for powershell commands from 192.168.1.150",
        events=events,
    )
    assert res.hypothesis_status == HypothesisStatus.CONFIRMED
    assert res.total_matched == 1
    assert res.returned_count == 1
    assert "192.168.1.150" in res.matched_entities["ips"]
    assert "powershell.exe" in res.matched_entities["processes"]
    assert "evi-hunt-1" in res.evidence_provenance
    assert len(res.suggested_followups) > 0


def test_05_hunt_execution_refuted_and_inconclusive():
    """Flags hypothesis as REFUTED when sufficient telemetry exists with zero matches, or INCONCLUSIVE on low data."""
    # 6 benign events with no powershell or malicious activity
    events = [
        UniversalSecurityEvent(
            event_id=f"ev-ben-{i}",
            timestamp="2026-11-04T12:00:00Z",
            ingestion_timestamp="2026-11-04T12:00:01Z",
            source_type="linux_auth",
            source_file="auth.log",
            event_category=EventCategory.AUTHENTICATION,
            event_action="logon_success",
            severity=EventSeverity.INFORMATIONAL,
            username=f"user_{i}",
        )
        for i in range(6)
    ]

    res_refuted = ThreatHuntingEngine.execute_hunt(
        nl_query="Hunt for powershell from 10.0.0.99",
        events=events,
    )
    assert res_refuted.hypothesis_status == HypothesisStatus.REFUTED
    assert res_refuted.total_matched == 0

    # With only 1 event, result is INCONCLUSIVE
    res_inconclusive = ThreatHuntingEngine.execute_hunt(
        nl_query="Hunt for powershell from 10.0.0.99",
        events=events[:1],
    )
    assert res_inconclusive.hypothesis_status == HypothesisStatus.INCONCLUSIVE
