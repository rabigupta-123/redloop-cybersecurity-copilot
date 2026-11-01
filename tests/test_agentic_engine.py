"""Unit and integration tests for PentestGPT PTT Agentic Engine & Scope Enforcement."""

import pytest
from redloop.assessment.agentic_engine import (
    AgenticAIRuntime,
    AgentPlan,
    AgentRole,
    OutputAnalyst,
    PTTNode,
)
from datetime import date, timedelta
import yaml

from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.audit import AuditLogger
from redloop.scope import ScopeManager, sign_scope


@pytest.fixture
def test_scope_guard(tmp_path):
    today = date.today()
    secret = "unit_test_secret_key_123"
    scope_data = {
        "version": 1,
        "id": "test-scope",
        "authorized_by": "sec-ops",
        "signed_at": "2026-10-26T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback",
                "authorized_from": today.isoformat(),
                "authorized_until": (today + timedelta(days=365)).isoformat(),
                "allowed_actions": ["scan", "check", "assess", "probe"],
                "ports": [80, 443, 8080, 8081, 8082, 8765],
            }
        ],
    }
    scope_data["signature"] = sign_scope(scope_data, secret)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(yaml.safe_dump(scope_data), encoding="utf-8")
    sm = ScopeManager(scope_file, secret)
    audit = AuditLogger(db_path=str(tmp_path / "audit.db"))
    return AssessmentScopeGuard(sm, audit)


def test_agentic_plan_construction(test_scope_guard):
    runtime = AgenticAIRuntime(scope_guard=test_scope_guard)
    plan = runtime.build_pentestgpt_plan(
        target="127.0.0.1",
        user_intent="Enumerate listening services and inspect web application",
        authorized_ports=[8080, 8081],
    )

    assert plan.target == "127.0.0.1"
    assert len(plan.nodes) == 3
    node_list = list(plan.nodes.values())
    assert node_list[0].tool == "nmap"
    assert node_list[0].role == AgentRole.RECON_SPECIALIST
    assert node_list[1].tool == "gobuster"
    assert node_list[1].role == AgentRole.WEB_SPECIALIST


def test_agentic_plan_blocked_on_unauthorized_target(test_scope_guard):
    runtime = AgenticAIRuntime(scope_guard=test_scope_guard)
    result = runtime.run_autonomous_assessment(
        target="192.168.1.99",
        user_intent="Scan external unauthorized subnet",
        authorized_ports=[8080],
    )

    assert result["status"] == "BLOCKED"
    assert "UNAUTHORIZED_TARGET" in result["reason"] or "not authorized" in result["reason"].lower()
    assert len(result["completed_steps"]) == 0


def test_output_analyst_port_extraction():
    sample_nmap = """
    Starting Nmap 7.80 ( https://nmap.org ) at 2026-10-26 15:00
    Nmap scan report for localhost (127.0.0.1)
    Host is up (0.00010s latency).
    PORT     STATE SERVICE VERSION
    8080/tcp open  http    Apache Tomcat/9.0
    8081/tcp open  http    Node.js Express
    9000/tcp closed cslistener
    """
    analysis = OutputAnalyst.analyze_nmap_output(sample_nmap)
    assert 8080 in analysis["open_ports"]
    assert 8081 in analysis["open_ports"]
    assert 9000 not in analysis["open_ports"]
    assert 8080 in analysis["web_services"]
    assert 8081 in analysis["web_services"]


def test_output_analyst_gobuster_extraction():
    sample_gobuster = """
    ===============================================================
    Gobuster v3.5
    ===============================================================
    /admin                (Status: 301) [Size: 178]
    /api/v1               (Status: 200) [Size: 1024]
    /.env                 (Status: 200) [Size: 450]
    /login                (Status: 200) [Size: 2200]
    """
    analysis = OutputAnalyst.analyze_gobuster_output(sample_gobuster)
    assert len(analysis["discovered_paths"]) == 4
    assert any(p["path"] == "/.env" for p in analysis["discovered_paths"])
    assert any(p["path"] == "/admin" for p in analysis["discovered_paths"])
    assert any("/.env" in s for s in analysis["sensitive_findings"])


def test_agentic_autonomous_execution_authorized(test_scope_guard):
    runtime = AgenticAIRuntime(scope_guard=test_scope_guard)
    result = runtime.run_autonomous_assessment(
        target="127.0.0.1",
        user_intent="Autonomous evaluation of local ports",
        authorized_ports=[8080, 8081],
        max_iterations=3,
    )

    assert result["status"] == "COMPLETED"
    assert len(result["completed_steps"]) > 0
    assert result["evidence_count"] >= 1
    assert result["target"] == "127.0.0.1"
