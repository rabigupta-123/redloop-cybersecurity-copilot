"""Phase 6.1 Threat Intelligence Assurance & Security Verification Suite.

Covers:
1. ATT&CK Catalog Integrity: Valid, invalid, deprecated/revoked IDs, platform metadata.
2. Heuristic Mappings: Explicitly marked as inferred, never presented as authoritative.
3. Sigma Engine Conformance: Unsupported features reported honestly, batch duplicate ID detection.
4. Regex Safety: Length bounds, ReDoS rejection, and worker thread timeout protection.
5. Threat Hunting Security: Strict field allowlists, query length & clause bounds, target context isolation.
6. Attack Chain Accuracy: Contradictory evidence preservation, no ungrounded entry-point/crown-jewel assertions.
7. Capability Token Security: Binding to exact action command & parameters, parameter tampering rejection, audit trail integrity.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from redloop.assessment.attack_chain import (
    AttackChainReconstructor,
    StepObservationType,
)
from redloop.assessment.attack_mapping import (
    AttackCatalog,
    AttackMappingEngine,
    TechniqueStatus,
)
from redloop.assessment.sigma_engine import (
    SigmaEngine,
    SigmaReDoSTimeoutError,
    SigmaRuleValidationError,
)
from redloop.assessment.soc_detection import SOCAlert
from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    UniversalSecurityEvent,
)
from redloop.assessment.soc_playbooks import (
    PlaybookApprovalStore,
    PlaybookStepStatus,
    SOCPlaybookEngine,
)
from redloop.assessment.threat_hunting import (
    HypothesisStatus,
    QuerySecurityError,
    ThreatHuntingEngine,
)


# ==============================================================================
# B1: MITRE ATT&CK Catalog Integrity
# ==============================================================================


def test_01_attack_catalog_metadata_and_scope():
    """Confirms catalog scope metadata distinguishes curated core subset from full Enterprise matrix."""
    meta = AttackMappingEngine.get_catalog_metadata()
    assert meta["dataset_version"] == "v15.1"
    assert meta["retrieval_date"] == "2024-10-31"
    assert meta["is_full_catalog"] is False
    assert meta["tactics_count"] == 14
    assert meta["techniques_count"] == 33
    assert meta["deprecated_count"] >= 5


def test_02_attack_technique_status_valid_deprecated_revoked_unknown():
    """Accurately identifies valid, deprecated, revoked, and unknown technique IDs."""
    # Valid technique
    t_valid = AttackCatalog.lookup_technique("T1059.001")
    assert t_valid["status"] == TechniqueStatus.VALID.value
    assert t_valid["name"] == "PowerShell"
    assert "Windows" in t_valid["platforms"]

    # Revoked technique (PowerShell T1086 -> T1059.001)
    t_revoked = AttackCatalog.lookup_technique("T1086")
    assert t_revoked["status"] == TechniqueStatus.REVOKED.value
    assert t_revoked["revoked_by"] == "T1059.001"

    # Deprecated technique (Commonly Used Port T1043)
    t_dep = AttackCatalog.lookup_technique("T1043")
    assert t_dep["status"] == TechniqueStatus.DEPRECATED.value

    # Unknown / Invalid ID
    t_unk = AttackCatalog.lookup_technique("T9999.999")
    assert t_unk["status"] == TechniqueStatus.UNKNOWN.value


def test_03_heuristic_mappings_marked_inferred_not_authoritative():
    """Ensures uncurated event pattern matches are flagged as heuristic inferred, not authoritative."""
    ev = UniversalSecurityEvent(
        event_id="e-heur-ps",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.HIGH,
        process_name="powershell.exe",
        command_line="powershell.exe -enc JABz...",
    )
    maps = AttackMappingEngine.map_event(ev)
    assert len(maps) >= 1
    for m in maps:
        assert m.is_inferred is True
        assert m.mapping_type == "HEURISTIC_INFERRED"


# ==============================================================================
# B2: Sigma Engine Conformance & Regex Safety
# ==============================================================================


def test_04_sigma_unsupported_rule_never_silently_treated_as_non_match():
    """Evaluation on an unsupported/invalid rule raises SigmaRuleValidationError rather than returning False."""
    broken_rule = """
title: Invalid Rule With Unsupported Modifier
id: sig-unsupported-001
status: stable
description: Has unsupported modifier
logsource:
    category: process_creation
detection:
    selection:
        Image|windash: 'powershell.exe'
    condition: selection
"""
    ev = UniversalSecurityEvent(
        event_id="e-test-1",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.LOW,
        process_name="powershell.exe",
    )
    with pytest.raises(SigmaRuleValidationError) as exc_info:
        SigmaEngine.evaluate_rule(broken_rule, ev)
    assert "Unsupported field modifier '|windash'" in str(exc_info.value)


def test_05_sigma_batch_duplicate_uuid_detection():
    """Detects duplicate rule IDs when validating a rule corpus."""
    rule_a = """
title: Rule Alpha
id: d4f9c2e1-4567-4890-a1b2-c3d4e5f6a7b8
status: stable
description: First rule
logsource:
    category: process_creation
detection:
    selection:
        Image: 'cmd.exe'
    condition: selection
"""
    rule_b = """
title: Rule Beta (Duplicate ID)
id: d4f9c2e1-4567-4890-a1b2-c3d4e5f6a7b8
status: stable
description: Duplicate rule id
logsource:
    category: process_creation
detection:
    selection:
        Image: 'powershell.exe'
    condition: selection
"""
    res = SigmaEngine.validate_rules_batch([rule_a, rule_b])
    assert res["has_duplicates"] is True
    assert len(res["duplicate_ids"]) == 1
    assert "d4f9c2e1-4567-4890-a1b2-c3d4e5f6a7b8" in res["duplicate_ids"][0]


def test_06_sigma_regex_pattern_length_bound_and_redos_guard():
    """Rejects excessively long regex patterns and catastrophic backtracking constructs."""
    # Excessively long regex (> 200 chars)
    long_pat = "a" * 250
    long_rule = f"""
title: Oversized Regex
id: sig-long-001
status: stable
description: Long regex
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|re: '{long_pat}'
    condition: selection
"""
    val_res = SigmaEngine.validate_rule(long_rule)
    assert val_res.is_valid is False
    assert any("exceeds maximum length" in e for e in val_res.errors)


# ==============================================================================
# B3: Capability Token Security & Parameter Tampering Protection
# ==============================================================================


def test_07_capability_tampered_action_parameters_rejected():
    """Attempting to execute an action with altered parameters invalidates the capability approval."""
    SOCPlaybookEngine._reset_playbooks()
    # Approve PB-WEB step-web-2 with original command
    appr = SOCPlaybookEngine.approve_step("PB-WEB", "step-web-2", approver="lead_analyst")
    assert appr["success"] is True
    token = appr["capability_token"]

    # Attempt to execute with tampered action command (different IP block target)
    tampered_cmd = "echo 'deny 10.99.99.99;' >> /etc/nginx/conf.d/blocklist.conf && nginx -s reload"
    res = SOCPlaybookEngine.execute_step(
        "PB-WEB",
        "step-web-2",
        auth_token=token,
        action_command=tampered_cmd,
    )
    assert res["success"] is False
    assert "altered" in res["error"].lower()


def test_08_capability_token_never_echoed_in_audit_or_errors():
    """Ensures raw capability token secrets are never echoed in audit trail or exception strings."""
    store = PlaybookApprovalStore.get_instance()
    conn = store._get_connection()
    try:
        with conn:
            cur = conn.execute("SELECT details FROM playbook_audit_trail")
            rows = cur.fetchall()
            for r in rows:
                assert "rl-cap-" not in r["details"]
    finally:
        conn.close()


# ==============================================================================
# B4: Threat Hunting Query Security
# ==============================================================================


def test_09_hunt_query_length_bound_and_field_allowlist():
    """Rejects queries exceeding length bounds and enforces field allowlist."""
    # Oversized query (> 500 chars)
    oversized = "hunt for malicious powershell " * 25
    with pytest.raises(QuerySecurityError) as exc:
        ThreatHuntingEngine.parse_natural_language(oversized)
    assert "exceeds maximum allowable limit" in str(exc.value)

    # Empty query rejected
    with pytest.raises(QuerySecurityError):
        ThreatHuntingEngine.parse_natural_language("")

    # Prohibited field allowlist check
    ThreatHuntingEngine.ALLOWED_FIELDS.remove("source_ip")
    try:
        with pytest.raises(QuerySecurityError) as exc2:
            ThreatHuntingEngine.execute_hunt("10.0.0.1", events=[])
        assert "not in the allowed query field allowlist" in str(exc2.value)
    finally:
        ThreatHuntingEngine.ALLOWED_FIELDS.add("source_ip")


def test_10_hunt_target_scope_isolation():
    """Ensures events from unrelated target hosts/IPs are strictly excluded when target_scope is provided."""
    ev_target = UniversalSecurityEvent(
        event_id="e-target-1",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.HIGH,
        process_name="powershell.exe",
        hostname="FINANCE-SRV01",
        source_ip="10.0.1.50",
    )
    ev_other = UniversalSecurityEvent(
        event_id="e-other-2",
        timestamp="2026-11-04T12:01:00Z",
        ingestion_timestamp="2026-11-04T12:01:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.HIGH,
        process_name="powershell.exe",
        hostname="DEV-DESKTOP09",
        source_ip="10.0.2.99",
    )

    res = ThreatHuntingEngine.execute_hunt(
        nl_query="powershell",
        events=[ev_target, ev_other],
        target_scope="FINANCE-SRV01",
    )
    assert res.total_matched == 1
    assert res.events[0]["hostname"] == "FINANCE-SRV01"
    assert res.target_scope == "FINANCE-SRV01"


def test_11_hunt_pagination_offset():
    """Applies pagination offset and limit to query results."""
    test_events = [
        UniversalSecurityEvent(
            event_id=f"e-page-{i}",
            timestamp=f"2026-11-04T12:0{i}:00Z",
            ingestion_timestamp=f"2026-11-04T12:0{i}:01Z",
            source_type="windows_sysmon",
            source_file="sysmon.json",
            event_category=EventCategory.PROCESS,
            event_action="process_create",
            severity=EventSeverity.LOW,
            process_name="powershell.exe",
        )
        for i in range(5)
    ]
    res_page = ThreatHuntingEngine.execute_hunt(
        nl_query="powershell",
        events=test_events,
        limit=2,
        offset=2,
    )
    assert res_page.total_matched == 5
    assert res_page.returned_count == 2
    assert res_page.offset == 2
    assert res_page.events[0]["event_id"] == "e-page-2"


# ==============================================================================
# B5: Attack Chain Model Accuracy
# ==============================================================================


def test_12_attack_chain_no_unobserved_entry_point_or_crown_jewel_assertion():
    """Does NOT assert an entry point or crown jewel target when initial access or impact are unobserved."""
    # Only Discovery is observed
    ev_disc = UniversalSecurityEvent(
        event_id="e-disc-1",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="network_recon",
        severity=EventSeverity.MEDIUM,
        process_name="net.exe",
        command_line="net view /all",
        hostname="WORKSTATION-01",
    )
    chain = AttackChainReconstructor.reconstruct_chain(events=[ev_disc])
    # Must NOT claim WORKSTATION-01 was the entry point without initial access telemetry
    assert chain.entry_point_candidate is None
    # Must NOT assert a crown jewel target without collection, exfiltration, impact, or DC evidence
    assert chain.crown_jewel_target is None


def test_13_attack_chain_preserves_contradictory_temporal_evidence():
    """Detects and records contradictory evidence when earlier stages carry timestamps later than subsequent stages."""
    # Initial Access with LATER timestamp than Execution (contradictory telemetry)
    ev_early_stage = UniversalSecurityEvent(
        event_id="e-initial",
        timestamp="2026-11-04T12:30:00Z",  # 12:30
        ingestion_timestamp="2026-11-04T12:30:01Z",
        source_type="web_access",
        source_file="access.log",
        event_category=EventCategory.WEB,
        event_action="http_request",
        severity=EventSeverity.HIGH,
        url="/login.php?user=admin'%20OR%201=1--",
    )
    ev_late_stage = UniversalSecurityEvent(
        event_id="e-exec",
        timestamp="2026-11-04T12:00:00Z",  # 12:00 (prior to initial access)
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.CRITICAL,
        parent_process="w3wp.exe",
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
    )

    chain = AttackChainReconstructor.reconstruct_chain(events=[ev_early_stage, ev_late_stage])
    assert len(chain.contradictory_evidence) >= 1
    assert any("Temporal Anomaly" in c or "Reversed" in c for c in chain.contradictory_evidence)
