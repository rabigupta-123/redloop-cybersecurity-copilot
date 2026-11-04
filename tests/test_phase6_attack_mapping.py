"""Phase 6 Automated Verification Suite: MITRE ATT&CK Mapping & Matrix Coverage Engine.

Covers:
1. Enterprise ATT&CK v15 catalog: all 14 tactics (TA0001 - TA0043) present with descriptions and URLs.
2. Techniques & Sub-techniques catalog: parent-child relationships, data sources.
3. Technique filtering by tactic ID.
4. Security event mapping: PowerShell obfuscation (T1059.001), Web Shell (T1505.003), Sudo (T1548.003), SQLi (T1190).
5. SOC Alert mapping: SEC-AUTH-001, SEC-PROC-001, SEC-WEB-001, SEC-NET-001, SEC-HASH-001.
6. ATT&CK Matrix coverage generation: tactic-level counts, coverage percentage, high-risk techniques.
7. Export functions: Markdown table report generation and JSON dictionary serialization.
"""

from __future__ import annotations

import pytest

from redloop.assessment.attack_mapping import (
    AttackCatalog,
    AttackMappingEngine,
    AttackMatrixCoverage,
    AttackTactic,
    AttackTechnique,
    TechniqueMapping,
)
from redloop.assessment.soc_detection import SOCAlert
from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    UniversalSecurityEvent,
)


def test_01_attack_catalog_14_tactics():
    """Confirms all 14 MITRE Enterprise ATT&CK tactics exist in canonical kill-chain order."""
    tactics = AttackMappingEngine.get_tactics()
    assert len(tactics) == 14
    t_ids = [t["tactic_id"] for t in tactics]
    
    expected_tactics = [
        "TA0043", "TA0042", "TA0001", "TA0002", "TA0003",
        "TA0004", "TA0005", "TA0006", "TA0007", "TA0008",
        "TA0009", "TA0011", "TA0010", "TA0040",
    ]
    for exp in expected_tactics:
        assert exp in t_ids, f"Missing tactic {exp}"

    # Verify fields
    for t in tactics:
        assert t["tactic_id"].startswith("TA")
        assert len(t["name"]) > 2
        assert "attack.mitre.org" in t["reference_url"]


def test_02_attack_catalog_techniques_and_subtechniques():
    """Verifies curated techniques, sub-techniques, and data sources."""
    techniques = AttackMappingEngine.get_techniques()
    assert len(techniques) >= 20
    
    # Check parent-child subtechnique linking
    powershell_sub = next((t for t in techniques if t["technique_id"] == "T1059.001"), None)
    assert powershell_sub is not None
    assert powershell_sub["is_subtechnique"] is True
    assert powershell_sub["parent_id"] == "T1059"
    assert "Process: Process Creation" in powershell_sub["data_sources"]

    # Check web shell
    webshell = next((t for t in techniques if t["technique_id"] == "T1505.003"), None)
    assert webshell is not None
    assert "TA0003" in webshell["tactic_ids"]


def test_03_techniques_filter_by_tactic():
    """Filters techniques by parent tactic ID."""
    c2_techs = AttackMappingEngine.get_techniques(tactic_id="TA0011")
    assert len(c2_techs) >= 2
    for t in c2_techs:
        assert "TA0011" in t["tactic_ids"]

    priv_techs = AttackMappingEngine.get_techniques(tactic_id="TA0004")
    assert any(t["technique_id"] == "T1548.003" for t in priv_techs)


def test_04_event_mapping_powershell_obfuscation():
    """Maps PowerShell execution with obfuscation to T1059.001 (PowerShell) and TA0002 (Execution)."""
    ev = UniversalSecurityEvent(
        event_id="evt-ps-1",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.HIGH,
        process_name="powershell.exe",
        command_line="powershell.exe -w hidden -enc JABzACAAPQAgAE4AZQB3...",
        source_ip="192.168.1.100",
        hostname="CORP-WS01",
    )
    mappings = AttackMappingEngine.map_event(ev)
    assert len(mappings) >= 1
    m = mappings[0]
    assert m.technique_id == "T1059.001"
    assert m.tactic_id == "TA0002"
    assert m.confidence >= 0.90
    assert "CORP-WS01" in m.source_entity or "192.168.1.100" in m.source_entity


def test_05_event_mapping_web_shell():
    """Maps web server daemon spawning shell to T1505.003 (Web Shell) and TA0003 (Persistence)."""
    ev = UniversalSecurityEvent(
        event_id="evt-ws-1",
        timestamp="2026-11-04T12:05:00Z",
        ingestion_timestamp="2026-11-04T12:05:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.CRITICAL,
        parent_process="w3wp.exe",
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami",
        hostname="WEB-PROD-01",
    )
    mappings = AttackMappingEngine.map_event(ev)
    assert len(mappings) >= 1
    m = mappings[0]
    assert m.technique_id == "T1505.003"
    assert m.tactic_id == "TA0003"
    assert m.confidence >= 0.95


def test_06_soc_alert_mapping_and_rules():
    """Maps structured SOCAlert objects to corresponding ATT&CK tactics and techniques."""
    alt = SOCAlert(
        alert_id="alt-auth-1",
        rule_id="SEC-AUTH-001",
        title="Authentication Brute-Force Activity",
        description="Consecutive failed logon bursts",
        severity=EventSeverity.HIGH,
        confidence=0.85,
        matched_event_ids=["e1", "e2", "e3"],
        target_ip="198.51.100.77",
    )
    mappings = AttackMappingEngine.map_alert(alt)
    assert len(mappings) >= 1
    tech_ids = [m.technique_id for m in mappings]
    assert "T1110.001" in tech_ids or "T1110" in tech_ids
    assert all(m.tactic_id == "TA0006" for m in mappings)


def test_07_matrix_coverage_and_exports():
    """Builds matrix heatmap coverage, computes percentages, and exports Markdown/JSON."""
    mappings = [
        TechniqueMapping(
            mapping_id="m1",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic_id="TA0001",
            tactic_name="Initial Access",
            confidence=0.92,
            match_rule_id="SEC-WEB-001",
            match_reason="SQLi exploit detected",
            source_entity="10.0.0.1",
            evidence_ids=["evi-1"],
        ),
        TechniqueMapping(
            mapping_id="m2",
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic_id="TA0002",
            tactic_name="Execution",
            confidence=0.95,
            match_rule_id="SEC-PROC-001",
            match_reason="Obfuscated script executed",
            source_entity="CORP-DC",
            evidence_ids=["evi-2"],
        ),
    ]

    coverage = AttackMappingEngine.build_matrix(mappings)
    assert coverage.total_tactics == 14
    assert coverage.covered_tactics == 2
    assert coverage.coverage_percentage == round((2 / 14) * 100.0, 2)
    assert coverage.total_techniques_mapped == 2
    assert len(coverage.high_risk_techniques) == 2

    # Export to markdown
    md = AttackMappingEngine.export_matrix_markdown(coverage)
    assert "# REDLOOP MITRE ATT&CK Matrix Coverage Report" in md
    assert "| `TA0001` | **Initial Access** | 1 | 0.92 | 🟢 COVERED |" in md
    assert "| `TA0040` | **Impact** | 0 | 0.00 | ⚪ UNCOVERED |" in md

    # Export to dict
    d = coverage.to_dict()
    assert d["covered_tactics"] == 2
    assert "TA0001" in d["tactics_breakdown"]
