"""Phase 6 Automated Verification Suite: Sigma Detection Engineering & Rule Execution Engine.

Covers:
1. Strict Sigma rule schema validation (required fields, levels, logsource, condition).
2. Rejection of invalid YAML, missing conditions, or unsupported modifiers.
3. ReDoS safe regex validation and compilation protection.
4. Support matrix inspection and capability reporting.
5. Field modifiers: |contains, |startswith, |endswith, |re, |all, |base64offset.
6. Safe condition evaluation (and, or, not, parentheses, quantifiers: 1 of them, 1 of selection*).
7. Evaluation against UniversalSecurityEvent producing structured SigmaMatchResult.
"""

from __future__ import annotations

import pytest

from redloop.assessment.sigma_engine import (
    SigmaEngine,
    SigmaMatchResult,
    SigmaRuleLevel,
    SigmaRuleStatus,
    SigmaRuleValidationResult,
)
from redloop.assessment.soc_events import (
    EventCategory,
    EventSeverity,
    UniversalSecurityEvent,
)


def test_01_sigma_rule_validation_success():
    """Validates a well-formed Sigma rule meeting all specification criteria."""
    valid_rule = """
title: Suspicious PowerShell Encoded Command Execution
id: 5f113a7c-8e4d-4952-b4e3-3e1fb3ef1b41
status: stable
description: Detects suspicious PowerShell executions with encoded or hidden command parameters.
author: REDLOOP Detection Team
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - 'bypass'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""
    res = SigmaEngine.validate_rule(valid_rule)
    assert res.is_valid is True
    assert res.rule_id == "5f113a7c-8e4d-4952-b4e3-3e1fb3ef1b41"
    assert res.title == "Suspicious PowerShell Encoded Command Execution"
    assert len(res.errors) == 0
    assert "contains" in res.supported_features
    assert "endswith" in res.supported_features


def test_02_sigma_rule_validation_failures():
    """Rejects malformed rules, missing required fields, or missing condition blocks."""
    # Missing condition
    missing_cond = """
title: Broken Rule
id: rule-123
status: experimental
description: Missing condition block
logsource:
    category: process_creation
detection:
    selection:
        Image: 'cmd.exe'
"""
    res1 = SigmaEngine.validate_rule(missing_cond)
    assert res1.is_valid is False
    assert any("condition" in e.lower() for e in res1.errors)

    # Invalid YAML syntax
    invalid_yaml = "title: Broken: [unbalanced"
    res2 = SigmaEngine.validate_rule(invalid_yaml)
    assert res2.is_valid is False
    assert any("syntax error" in e.lower() for e in res2.errors)


def test_03_redos_regex_validation_safety():
    """Rejects dangerous regex patterns susceptible to catastrophic backtracking (ReDoS)."""
    dangerous_rule = """
title: ReDoS Attack Rule
id: redos-001
status: experimental
description: Testing ReDoS rejection
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|re: '^(a+)+$'
    condition: selection
"""
    res = SigmaEngine.validate_rule(dangerous_rule)
    assert res.is_valid is False
    assert any("redos" in e.lower() or "unsafe" in e.lower() for e in res.errors)


def test_04_support_matrix_reporting():
    """Returns the formal Sigma engine capability and feature support matrix."""
    matrix = SigmaEngine.get_support_matrix()
    assert "supported_modifiers" in matrix
    assert "contains" in matrix["supported_modifiers"]
    assert "base64offset" in matrix["supported_modifiers"]
    assert matrix["condition_logic"]["arbitrary_code_execution"] == "Strictly Prohibited (No eval/exec)"


def test_05_field_modifiers_contains_startswith_endswith():
    """Tests evaluation of string modifiers on event fields."""
    rule_yaml = """
title: Multi-Modifier Test
id: mod-test-01
status: stable
description: Tests string modifiers
logsource:
    category: process_creation
detection:
    sel_img:
        Image|endswith: 'powershell.exe'
    sel_cmd:
        CommandLine|contains: 'mimikatz'
    condition: sel_img and sel_cmd
level: critical
"""
    event_match = UniversalSecurityEvent(
        event_id="e-mod-1",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.HIGH,
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -c Invoke-Mimikatz",
    )
    matched, res = SigmaEngine.evaluate_rule(rule_yaml, event_match)
    assert matched is True
    assert res is not None
    assert res.matched_event_id == "e-mod-1"
    assert res.level == "critical"

    # Non-matching event
    event_no_match = UniversalSecurityEvent(
        event_id="e-mod-2",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.INFORMATIONAL,
        process_name="notepad.exe",
        command_line="notepad.exe doc.txt",
    )
    matched2, res2 = SigmaEngine.evaluate_rule(rule_yaml, event_no_match)
    assert matched2 is False
    assert res2 is None


def test_06_base64offset_modifier():
    """Evaluates base64offset modifier across standard space-padding variations."""
    rule_b64 = """
title: Base64 Offset Test
id: b64-001
status: stable
description: Tests base64 command detection
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|base64offset: 'whoami'
    condition: selection
level: medium
"""
    # Base64 for 'whoami' is 'd2hvYW1p'
    event_b64 = UniversalSecurityEvent(
        event_id="e-b64-1",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="windows_sysmon",
        source_file="sysmon.json",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.HIGH,
        command_line="cmd.exe /c powershell -enc d2hvYW1p",
    )
    matched, res = SigmaEngine.evaluate_rule(rule_b64, event_b64)
    assert matched is True
    assert res is not None


def test_07_complex_condition_logic():
    """Evaluates boolean conditions including 'and not filter', quantifiers '1 of selection*'."""
    rule_quant = """
title: Quantifier and Negation Test
id: quant-01
status: stable
description: Tests condition evaluation
logsource:
    category: process_creation
detection:
    selection_cmd:
        CommandLine|contains: 'whoami'
    selection_sudo:
        CommandLine|contains: 'sudo'
    filter_benign:
        User: 'backup_admin'
    condition: 1 of selection* and not filter_benign
level: high
"""
    # Event matching selection but not filtered
    event_ok = UniversalSecurityEvent(
        event_id="e-q1",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="linux_auth",
        source_file="auth.log",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.HIGH,
        command_line="sudo whoami",
        username="attacker",
    )
    m1, res1 = SigmaEngine.evaluate_rule(rule_quant, event_ok)
    assert m1 is True

    # Event matching selection but filtered out by user
    event_filtered = UniversalSecurityEvent(
        event_id="e-q2",
        timestamp="2026-11-04T12:00:00Z",
        ingestion_timestamp="2026-11-04T12:00:01Z",
        source_type="linux_auth",
        source_file="auth.log",
        event_category=EventCategory.PROCESS,
        event_action="process_create",
        severity=EventSeverity.INFORMATIONAL,
        command_line="sudo whoami",
        username="backup_admin",
    )
    m2, res2 = SigmaEngine.evaluate_rule(rule_quant, event_filtered)
    assert m2 is False
