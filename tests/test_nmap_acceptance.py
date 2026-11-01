"""Automated acceptance tests for Nmap execution and scope enforcement in REDLOOP.

Verifies:
1. User requests an Nmap operation.
2. AI/tool layer identifies Nmap.
3. Scope check occurs.
4. Authorized localhost target is allowed.
5. Nmap actually executes (or uses controlled runner).
6. Output is captured.
7. Parsed results are returned.
8. Evidence is created with SHA-256 fingerprint.
9. Audit event is created.
10. AI/orchestrator explains the result.
11. Unauthorized target is blocked before execution (0 network packets, audit blocked logged).
12. Truthful error if Nmap executable is missing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from redloop.assessment.controlled_runner import ControlledToolRunner
from redloop.assessment.models import StageStatus
from redloop.assessment.orchestrator import TaskOrchestrator, TaskStore
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.audit import AuditLogger
from redloop.scope import ScopeManager, UnauthorizedTargetError


class MockScopeManager:
    def __init__(self, allowed_targets: list[str] | None = None):
        self.allowed_targets = allowed_targets or ["127.0.0.1", "localhost"]
        self.scope = SimpleNamespace(
            targets=[SimpleNamespace(cidr="127.0.0.1/32", domain=None)],
            signature="test-sig",
        )

    def is_within_window(self) -> bool:
        return True

    def check(self, target: str, action: str, port: int | None = None):
        clean = target.split("/")[0].split(":")[0]
        if clean in self.allowed_targets:
            return SimpleNamespace(label="authorized-local-scope", ports=None)
        raise UnauthorizedTargetError(f"Target '{target}' is not authorized")


@pytest.fixture
def test_env(tmp_path):
    audit_db = tmp_path / "test_audit.sqlite"
    audit = AuditLogger(audit_db)
    scope_mgr = MockScopeManager(allowed_targets=["127.0.0.1", "localhost"])
    scope_guard = AssessmentScopeGuard(scope_mgr, audit)
    return {
        "tmp_path": tmp_path,
        "audit_db": audit_db,
        "audit": audit,
        "scope_mgr": scope_mgr,
        "scope_guard": scope_guard,
    }


def test_nmap_authorized_execution_and_evidence(test_env):
    """Verify that an authorized localhost target executes Nmap, captures output, parses ports, and creates evidence."""
    scope_guard = test_env["scope_guard"]
    audit = test_env["audit"]

    runner = ControlledToolRunner(scope_guard=scope_guard, audit=audit)

    # Mock subprocess.run to provide deterministic Nmap output if nmap isn't physically available in test
    fake_nmap_stdout = """Starting Nmap 7.80 ( https://nmap.org ) at 2026-10-26 12:00
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00010s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
443/tcp  open  https   OpenSSL 1.1.1f
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds
"""

    with patch("shutil.which", return_value="nmap"), patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["nmap", "-sT", "-Pn", "-sV", "-p", "80,443,8080", "127.0.0.1"],
            returncode=0,
            stdout=fake_nmap_stdout,
            stderr="",
        )

        result = runner.run_nmap("127.0.0.1", ports=[80, 443, 8080], operation_id="test-op")

        assert result.status == StageStatus.SUCCESS
        assert result.exit_code == 0
        assert mock_run.called
        assert result.target == "127.0.0.1"

        # Check structured open ports
        open_ports = result.structured_output.get("open_ports", [])
        assert len(open_ports) == 3
        port_nums = [p["port"] for p in open_ports]
        assert 80 in port_nums
        assert 443 in port_nums
        assert 8080 in port_nums

        # Check evidence creation
        assert result.evidence is not None
        assert result.evidence.sha256_hash != ""
        assert len(result.evidence.sha256_hash) == 64
        assert result.evidence.source == "nmap"

        # Check audit event
        from redloop.reporting import AuditReader
        entries, _ = AuditReader(test_env["audit_db"]).entries()
        assert any(e["action"] == "scan" and e["module"] == "nmap" for e in entries)


def test_nmap_unauthorized_target_blocked(test_env):
    """Verify that an unauthorized target is strictly blocked with zero subprocess execution."""
    scope_guard = test_env["scope_guard"]
    audit = test_env["audit"]

    runner = ControlledToolRunner(scope_guard=scope_guard, audit=audit)

    with patch("subprocess.run") as mock_run:
        result = runner.run_nmap("198.51.100.25", ports=[80, 443])

        # Under NO circumstances should subprocess.run be called!
        assert not mock_run.called
        assert result.status == StageStatus.BLOCKED
        assert result.exit_code == -1
        assert result.error_code == "AUTHORIZATION_BLOCKED"
        assert "Target unauthorized" in result.reason

        # Verify audit blocked event
        from redloop.reporting import AuditReader
        entries, _ = AuditReader(test_env["audit_db"]).entries()
        blocked_entries = [e for e in entries if e["status"] == "blocked"]
        assert len(blocked_entries) >= 1
        assert blocked_entries[0]["target"] == "198.51.100.25"


def test_nmap_not_installed_truthful_error(test_env):
    """Verify that if Nmap is not installed, REDLOOP returns a truthful operational error."""
    scope_guard = test_env["scope_guard"]
    audit = test_env["audit"]

    runner = ControlledToolRunner(scope_guard=scope_guard, audit=audit)

    with patch("shutil.which", return_value=None), patch("os.path.exists", return_value=False):
        result = runner.run_nmap("127.0.0.1", ports=[80])

        assert result.status == StageStatus.UNAVAILABLE
        assert result.error_code == "TOOL_NOT_INSTALLED"
        assert "executable not found" in result.reason


@pytest.mark.asyncio
async def test_orchestrator_nmap_intent_and_explanation(test_env):
    """Verify that orchestrator routes natural language scan requests to Nmap, executes it, and explains the result."""
    tmp_path = test_env["tmp_path"]
    scope_mgr = test_env["scope_mgr"]
    audit_db = test_env["audit_db"]

    task_store = TaskStore(tmp_path / "tasks.sqlite")
    orch = TaskOrchestrator(scope_manager=scope_mgr, audit_db=audit_db, task_store=task_store)

    fake_nmap_stdout = """PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.18.0
22/tcp   open  ssh     OpenSSH 8.2p1
"""

    with patch("shutil.which", return_value="nmap"), patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["nmap"],
            returncode=0,
            stdout=fake_nmap_stdout,
            stderr="",
        )

        resp = await orch.execute_task(
            prompt="Scan the authorized target 127.0.0.1 with Nmap",
            conversation_id="test-conv-nmap",
        )

        assert "task" in resp
        task_data = resp["task"]
        assert task_data["status"] == "COMPLETED"
        assert task_data["target"] == "127.0.0.1"
        assert "Specialized Assessment Executed" in resp["response"] or "COMPLETED" in resp["response"]
