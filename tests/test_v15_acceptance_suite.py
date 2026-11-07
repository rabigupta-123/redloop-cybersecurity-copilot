"""REDLOOP V15.1 Acceptance Test Suite (Phase 6: Tests 1 through 9).

Verifies the end-to-end AI-to-tool-to-terminal-to-evidence workflow:
- Test 1: Tool Detection (Real binary detection & version)
- Test 2: Local Reconnaissance (Real loopback scan within scope)
- Test 3: Contextual Follow-up (Context reuse without redundant rescan)
- Test 4: TLS Investigation (Active TLS probe with TLSChecker)
- Test 5: Defensive Log Analysis (Sysmon process creation -> ATT&CK mapping)
- Test 6: Sigma Detection Engineering (Valid Sigma YAML rule generation)
- Test 7: Tool Failure (Unavailable tool reports failure without fabrication)
- Test 8: Cancellation (Long running operation terminated with CANCELLED state)
- Test 9: Report Generation (Comprehensive report with 6 blocks & evidence links)
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml

from redloop.assessment.ai_tool_agent import AIToolCallingAgent
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.assessment.terminal_engine import ExecutionStatus, UnifiedTerminalEngine
from redloop.audit import AuditLogger
from redloop.scope import ScopeManager, sign_scope


SECRET = "v15-1-acceptance-secret"


@pytest.fixture
def scope_manager(tmp_path):
    scope_yaml = tmp_path / "scope.yaml"
    raw = {
        "version": 1,
        "id": "v15-acceptance-scope",
        "authorized_by": "Security Lead",
        "signed_at": "2020-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "Local loopback",
                "authorized_from": "2020-01-01",
                "authorized_until": "2099-12-31",
                "allowed_actions": ["scan", "tls_check", "*"],
                "ports": [80, 443, 8765, 44339],
            }
        ],
    }
    raw["signature"] = sign_scope(raw, SECRET)
    scope_yaml.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return ScopeManager(str(scope_yaml), secret=SECRET)


@pytest.fixture
def agent(scope_manager, tmp_path):
    audit = AuditLogger(str(tmp_path / "audit.sqlite"))
    guard = AssessmentScopeGuard(scope_manager, audit)
    engine = UnifiedTerminalEngine(scope_guard=guard, audit=audit)
    return AIToolCallingAgent(
        scope_manager=scope_manager,
        scope_guard=guard,
        terminal_engine=engine,
        audit=audit,
    )


# --- TEST 1: Tool Detection ---
def test_01_tool_detection(agent):
    result = agent.run_tool_calling_loop("Check whether Nmap is installed on the local system.", target="127.0.0.1")
    assert result["status"] == "COMPLETED"
    assert len(result["tool_records"]) > 0
    rec = result["tool_records"][0]
    assert rec["tool_name"] == "detect_installed_tools"
    assert rec["exit_code"] == 0
    assert "nmap" in rec["stdout"].lower()
    assert len(result["evidence_ids"]) > 0
    assert "<Investigation Plan>" in result["report"]
    assert "<REDLOOP Terminal>" in result["report"]


# --- TEST 2: Local Reconnaissance ---
def test_02_local_reconnaissance(agent):
    result = agent.run_tool_calling_loop("Inspect my authorized localhost environment for open services.", target="127.0.0.1")
    assert result["status"] in ("COMPLETED", "PARTIAL")
    assert len(result["tool_records"]) > 0
    assert any(
        "nmap" in str(r["arguments"])
        or "netstat" in str(r["arguments"])
        or "ss" in str(r["arguments"])
        or "detect" in r["tool_name"]
        or r["tool_name"] == "execute_terminal_command"
        for r in result["tool_records"]
    )
    assert len(result["evidence_ids"]) > 0
    assert "<Execution Timeline>" in result["report"]


# --- TEST 3: Contextual Follow-up ---
def test_03_contextual_follow_up(agent):
    # Pass prior discovered context
    prior_context = {
        "discovered_ports": [80, 443, 8765],
        "services": ["http", "https", "redloop-console"],
        "target": "127.0.0.1"
    }
    result = agent.run_tool_calling_loop(
        "Analyze the services you just discovered on 127.0.0.1 based on context.",
        target="127.0.0.1",
        context=prior_context,
    )
    assert result["status"] in ("COMPLETED", "PARTIAL")
    assert "<Final Analysis & Recommendations>" in result["report"]


# --- TEST 4: TLS Investigation ---
def test_04_tls_investigation(agent):
    result = agent.run_tool_calling_loop(
        "Inspect the TLS configuration of the previously discovered local HTTPS service on port 8765.",
        target="127.0.0.1",
    )
    assert len(result["tool_records"]) > 0
    rec = result["tool_records"][0]
    assert rec["tool_name"] in ("inspect_tls_service", "execute_terminal_command")
    assert len(result["evidence_ids"]) > 0


# --- TEST 5: Defensive Log Analysis ---
def test_05_defensive_log_analysis(agent):
    sysmon_prompt = (
        "Investigate this process creation event: process_name='powershell.exe', "
        "command_line='powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA', parent_process='wmiprvse.exe'."
    )
    result = agent.run_tool_calling_loop(sysmon_prompt, target="127.0.0.1")
    assert result["status"] == "COMPLETED"
    rec = result["tool_records"][0]
    assert rec["tool_name"] == "analyze_sysmon_process_event"
    assert "T1059.001" in rec["stdout"]
    assert "<Discovered Security Findings & Attack Surface>" in result["report"]
    assert "T1059.001" in result["report"]


# --- TEST 6: Sigma Detection Engineering ---
def test_06_sigma_detection_engineering(agent):
    # 1. Direct tool dispatch verification
    rec_direct = agent._execute_tool_dispatch(
        "generate_sigma_rule",
        {
            "title": "Suspicious Encoded PowerShell Execution",
            "attack_technique": "T1059.001",
            "process_name": "powershell.exe",
            "detection_criteria": "-enc",
        },
        step_id="step-sigma",
    )
    assert rec_direct.status == "COMPLETED"
    assert "title:" in rec_direct.stdout
    assert "logsource:" in rec_direct.stdout
    assert "detection:" in rec_direct.stdout
    assert "attack.t1059_001" in rec_direct.stdout

    # 2. Agent invocation
    sigma_prompt = (
        "Generate a Sigma rule for the suspicious process behavior involving powershell.exe with -enc."
    )
    result = agent.run_tool_calling_loop(sigma_prompt, target="127.0.0.1")
    assert result["status"] in ("COMPLETED", "PARTIAL")
    assert len(result["tool_records"]) > 0
    assert any(r["tool_name"] in ("generate_sigma_rule", "analyze_sysmon_process_event") for r in result["tool_records"])


# --- TEST 7: Tool Failure ---
def test_07_tool_failure_handling(agent):
    # Invoking a deliberately non-existent binary through execute_terminal_command
    rec = agent._execute_tool_dispatch(
        "execute_terminal_command",
        {"command": "nonexistent_scanner_xyz_999 127.0.0.1", "target": "127.0.0.1"},
        step_id="step-fail",
    )
    assert rec.status in ("FAILED", "BLOCKED")
    assert rec.exit_code in (126, 127)
    assert "not found" in rec.stderr.lower() or "not permitted" in rec.stderr.lower()
    # Output must not be fabricated
    assert rec.stdout == ""
    assert rec.evidence_id != ""


# --- TEST 8: Cancellation ---
def test_08_cancellation_handling(agent):
    cancel_evt = threading.Event()
    cancel_evt.set()  # Cancel prior to execution
    res = agent.terminal_engine.execute_command(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        cancel_token=cancel_evt,
    )
    assert res.cancelled is True
    assert res.exit_code == -1
    assert res.status == ExecutionStatus.CANCELLED


# --- TEST 9: Report Generation ---
def test_09_comprehensive_report_generation(agent):
    result = agent.run_tool_calling_loop(
        "Generate a final security assessment report for target 127.0.0.1.",
        target="127.0.0.1",
    )
    rep = result["report"]
    # All 6 required structured tags must be present
    assert "<Investigation Plan>" in rep
    assert "</Investigation Plan>" in rep
    assert "<Execution Timeline>" in rep
    assert "</Execution Timeline>" in rep
    assert "<Tool Execution Cards>" in rep
    assert "</Tool Execution Cards>" in rep
    assert "<REDLOOP Terminal>" in rep
    assert "</REDLOOP Terminal>" in rep
    assert "<Discovered Security Findings & Attack Surface>" in rep
    assert "</Discovered Security Findings & Attack Surface>" in rep
    assert "<Final Analysis & Recommendations>" in rep
    assert "</Final Analysis & Recommendations>" in rep
