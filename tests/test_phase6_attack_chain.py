"""Phase 6 Automated Verification Suite: Unified Attack-Chain Reconstruction & Kill-Chain Engine.

Covers:
1. End-to-end chain reconstruction from multi-source security events and SOC alerts.
2. Canonical 13-stage kill-chain progression mapping.
3. Strict distinction between OBSERVED steps and INFERRED steps.
4. Automatic telemetry gap detection (e.g. unobserved initial access, skipping stages).
5. Accurate dwell-time calculation and entry-point / crown-jewel target identification.
6. Safe handling of empty or unmapped telemetry input.
"""

from __future__ import annotations

import pytest

from redloop.assessment.attack_chain import (
    AttackChain,
    AttackChainReconstructor,
    AttackChainStep,
    StepObservationType,
)
from redloop.assessment.soc_detection import SOCAlert
from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    UniversalSecurityEvent,
)


def test_01_empty_telemetry_handling():
    """Handles empty event/alert collections safely without exceptions."""
    chain = AttackChainReconstructor.reconstruct_chain(events=[], alerts=[])
    assert chain.chain_id.startswith("chn-")
    assert len(chain.steps) == 0
    assert chain.dwell_time_seconds == 0.0
    assert len(chain.telemetry_gaps) == 1
    assert "No observed events" in chain.telemetry_gaps[0]


def test_02_attack_chain_multi_stage_progression():
    """Reconstructs a multi-stage attack from Initial Access through Execution and Persistence."""
    # 1. Initial Access: Web SQL Injection
    ev_sqli = UniversalSecurityEvent(
        event_id="e-web-sqli",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="web_access",
        source_file="access.log",
        event_category=EventCategory.WEB,
        event_action="http_request",
        severity=EventSeverity.HIGH,
        url="/login.php?user=admin'%20OR%201=1--",
        source_ip="198.51.100.4",
        hostname="WEB-GATEWAY",
    )

    # 2. Execution: Web Shell Command
    ev_shell = UniversalSecurityEvent(
        event_id="e-ws-exec",
        timestamp="2026-11-04T12:03:00Z",
        ingestion_timestamp="2026-11-04T12:03:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.CRITICAL,
        parent_process="w3wp.exe",
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        source_ip="198.51.100.4",
        hostname="WEB-GATEWAY",
    )

    # 3. Privilege Escalation: Sudo Execution
    ev_sudo = UniversalSecurityEvent(
        event_id="e-sudo-priv",
        timestamp="2026-11-04T12:08:00Z",
        ingestion_timestamp="2026-11-04T12:08:01Z",
        source_type="linux_auth",
        source_file="auth.log",
        event_category=EventCategory.PROCESS,
        event_action="sudo_execution",
        severity=EventSeverity.HIGH,
        command_line="sudo -i",
        hostname="CORP-DC01",
    )

    chain = AttackChainReconstructor.reconstruct_chain(
        events=[ev_sqli, ev_shell, ev_sudo],
        chain_title="Compromise of Web Gateway and Lateral Movement",
    )

    assert len(chain.steps) >= 3
    assert chain.entry_point_candidate == "198.51.100.4"
    assert "CORP-DC01" in (chain.crown_jewel_target or "")
    # Dwell time from 12:00:00 to 12:08:00 = 480 seconds
    assert chain.dwell_time_seconds == 480.0
    assert chain.overall_confidence >= 0.85

    # Check observed stages
    assert "Initial Access" in chain.observed_stages
    assert "Persistence" in chain.observed_stages
    assert "Privilege Escalation" in chain.observed_stages


def test_03_telemetry_gap_detection_missing_initial_access():
    """Detects telemetry gap when execution is observed without prior initial access telemetry."""
    # Only execution and persistence observed (initial access missing)
    ev_exec = UniversalSecurityEvent(
        event_id="e-ps-isolated",
        timestamp="2026-11-04T12:10:00Z",
        ingestion_timestamp="2026-11-04T12:10:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.HIGH,
        process_name="powershell.exe",
        command_line="powershell.exe -w hidden -enc JABz...",
        hostname="CORP-WS10",
    )

    chain = AttackChainReconstructor.reconstruct_chain(events=[ev_exec])
    assert len(chain.telemetry_gaps) >= 1
    assert any("Initial Access" in g for g in chain.telemetry_gaps)


def test_04_inferred_steps_between_distant_stages():
    """Flags unobserved intermediate stages and inserts marked INFERRED steps."""
    # Initial Access (Stage 1) and Credential Access (Stage 6) observed directly
    alt_sqli = SOCAlert(
        alert_id="a-web",
        rule_id="SEC-WEB-001",
        title="Web SQLi",
        description="SQL injection in web request",
        severity=EventSeverity.HIGH,
        confidence=0.90,
        matched_event_ids=["e1"],
        target_ip="198.51.100.5",
        target_host="WEB-01",
    )
    alt_cred = SOCAlert(
        alert_id="a-cred",
        rule_id="SEC-AUTH-001",
        title="Brute force",
        description="Password spraying",
        severity=EventSeverity.HIGH,
        confidence=0.85,
        matched_event_ids=["e2"],
        target_ip="198.51.100.5",
        target_host="WEB-01",
    )

    chain = AttackChainReconstructor.reconstruct_chain(alerts=[alt_sqli, alt_cred])
    assert any(s.observation_type == StepObservationType.INFERRED for s in chain.steps)
    assert any("Unobserved Progression" in g for g in chain.telemetry_gaps)
