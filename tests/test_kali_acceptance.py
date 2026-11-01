"""Acceptance tests for Kali Linux Command Execution and Authorization Gate.

Verifies:
1. Command parser & risk classification.
2. Dangerous destructive commands blocked immediately.
3. Safe local diagnostics execute cleanly.
4. Network commands strictly enforced by central scope authorization.
5. Audit events logged.
6. Execution states clearly distinguished.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from redloop.assessment.kali_copilot import (
    KaliCommandParser,
    KaliCommandRisk,
    KaliCommandRunner,
    KaliCommandState,
    ParsedKaliCommand,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.audit import AuditLogger
from redloop.scope import UnauthorizedTargetError


class MockScopeManager:
    def __init__(self, allowed_targets: list[str] | None = None):
        self.allowed_targets = allowed_targets or ["127.0.0.1", "localhost"]

    def is_within_window(self) -> bool:
        return True

    def check(self, target: str, action: str, port: int | None = None):
        clean = target.split("/")[0].split(":")[0]
        if clean in self.allowed_targets:
            return SimpleNamespace(label="authorized-local-scope", ports=None)
        raise UnauthorizedTargetError(f"Target '{target}' is not authorized")


@pytest.fixture
def kali_env(tmp_path):
    audit_db = tmp_path / "kali_audit.sqlite"
    audit = AuditLogger(audit_db)
    scope_mgr = MockScopeManager(allowed_targets=["127.0.0.1", "localhost"])
    scope_guard = AssessmentScopeGuard(scope_mgr, audit)
    return {
        "audit_db": audit_db,
        "audit": audit,
        "scope_guard": scope_guard,
    }


def test_kali_command_parser_classification():
    """Verify that Kali commands are accurately parsed, target extracted, and risks classified."""
    # 1. Local Safe Command
    parsed1 = KaliCommandParser.parse("uname -a")
    assert parsed1.binary == "uname"
    assert parsed1.risk == KaliCommandRisk.SAFE_READONLY
    assert not parsed1.is_network
    assert not parsed1.is_dangerous
    assert parsed1.state == KaliCommandState.READY

    # 2. Network Command with IP
    parsed2 = KaliCommandParser.parse("nmap -sT 127.0.0.1")
    assert parsed2.binary == "nmap"
    assert parsed2.target == "127.0.0.1"
    assert parsed2.is_network
    assert parsed2.risk == KaliCommandRisk.ACTIVE_PROBE
    assert parsed2.state == KaliCommandState.AUTHORIZATION_REQUIRED

    # 3. Dangerous Command
    parsed3 = KaliCommandParser.parse("rm -rf /")
    assert parsed3.is_dangerous
    assert parsed3.risk == KaliCommandRisk.DANGEROUS
    assert parsed3.state == KaliCommandState.BLOCKED


def test_kali_runner_blocks_dangerous_command(kali_env):
    """Verify that dangerous commands are rejected before subprocess invocation."""
    runner = KaliCommandRunner(scope_guard=kali_env["scope_guard"], audit=kali_env["audit"])

    with patch("subprocess.run") as mock_run:
        res = runner.execute("rm -rf /etc")
        assert not mock_run.called
        assert res["state"] == KaliCommandState.BLOCKED.value
        assert "Dangerous" in res["reason"] or "blocked" in res["reason"]


def test_kali_runner_blocks_unauthorized_network_target(kali_env):
    """Verify that network commands targeting unauthorized hosts are strictly blocked."""
    runner = KaliCommandRunner(scope_guard=kali_env["scope_guard"], audit=kali_env["audit"])

    with patch("subprocess.run") as mock_run:
        res = runner.execute("nmap -sT 198.51.100.99")
        assert not mock_run.called
        assert res["state"] == KaliCommandState.BLOCKED.value
        assert res["target"] == "198.51.100.99"
        assert "unauthorized" in res["reason"].lower()

        # Audit check
        from redloop.reporting import AuditReader
        entries, _ = AuditReader(kali_env["audit_db"]).entries()
        assert any(e["status"] == "blocked" and e["target"] == "198.51.100.99" for e in entries)


def test_kali_runner_executes_authorized_command(kali_env):
    """Verify that authorized safe commands execute and return output."""
    runner = KaliCommandRunner(scope_guard=kali_env["scope_guard"], audit=kali_env["audit"])

    with patch("shutil.which", return_value="/usr/bin/uname"), patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["/usr/bin/uname", "-a"],
            returncode=0,
            stdout="Linux redloop-box 6.5.0-kali3-amd64 #1 SMP PREEMPT_DYNAMIC Kali",
            stderr="",
        )

        res = runner.execute("uname -a")
        assert mock_run.called
        assert res["state"] == KaliCommandState.COMPLETED.value
        assert res["exit_code"] == 0
        assert "Linux" in res["stdout"]
        assert res["evidence_id"] is not None
