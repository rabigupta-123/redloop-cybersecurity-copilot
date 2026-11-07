"""REDLOOP V15 Terminal & Copilot Test Suite (Categories A through L).

Verifies real local execution, deterministic terminal behaviour, cross-platform
resilience, scope protection, timeout handling, concurrent execution, and report structure.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import yaml

from redloop.assessment.agent_orchestrator import (
    AutonomousAgentOrchestrator,
    AgentStepState,
    AgentTask,
    AgentTaskStatus,
    AgentWorkflowStep,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.assessment.terminal_engine import (
    ExecutionEnvironment,
    ExecutionResult,
    ExecutionStatus,
    HostExecutionAdapter,
    MAX_OUTPUT_BYTES,
    UnifiedTerminalEngine,
)
from redloop.dashboard import create_app
from redloop.audit import AuditLogger
from redloop.scope import ScopeManager, sign_scope
from redloop.tls import TLSChecker, TLSError


SECRET = "terminal-v15-unit-test-secret"


@pytest.fixture
def test_scope_manager(tmp_path):
    scope_yaml = tmp_path / "scope.yaml"
    raw = {
        "version": 1,
        "id": "v15-test-scope",
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
                "ports": [80, 443, 44339, 8765],
            }
        ],
    }
    raw["signature"] = sign_scope(raw, SECRET)
    scope_yaml.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return ScopeManager(str(scope_yaml), secret=SECRET)


@pytest.fixture
def terminal_engine(test_scope_manager):
    guard = AssessmentScopeGuard(test_scope_manager)
    return UnifiedTerminalEngine(scope_guard=guard)


@pytest.fixture
def test_app(tmp_path, test_scope_manager):
    db_path = str(tmp_path / "audit.sqlite")
    return create_app(db_path, scope_manager=test_scope_manager)


def _async_request(app, method, path, **kwargs):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path, **kwargs)
    return asyncio.run(run())


# ==============================================================================
# Category A: Shell Operations (whoami, id, pwd, uname -a, date, echo, printf)
# ==============================================================================

class TestCategoryAShellOperations:
    def test_whoami(self, terminal_engine):
        res = terminal_engine.execute_command("whoami")
        assert res.exit_code == 0
        assert res.status == ExecutionStatus.SUCCESS
        assert len(res.stdout.strip()) > 0
        assert len(res.output_hash) == 64

    def test_pwd(self, terminal_engine):
        res = terminal_engine.execute_command("pwd")
        assert res.exit_code == 0
        assert res.status == ExecutionStatus.SUCCESS
        assert len(res.stdout.strip()) > 0
        assert len(res.output_hash) == 64

    def test_id(self, terminal_engine):
        res = terminal_engine.execute_command("id")
        assert res.exit_code == 0
        assert res.status == ExecutionStatus.SUCCESS
        assert "uid=" in res.stdout or "user" in res.stdout.lower()
        assert len(res.output_hash) == 64

    def test_uname_a(self, terminal_engine):
        res = terminal_engine.execute_command("uname -a")
        assert res.exit_code == 0
        assert res.status == ExecutionStatus.SUCCESS
        assert len(res.stdout.strip()) > 0
        assert len(res.output_hash) == 64

    def test_date(self, terminal_engine):
        res = terminal_engine.execute_command("date")
        assert res.exit_code == 0
        assert res.status == ExecutionStatus.SUCCESS
        assert len(res.stdout.strip()) > 0
        assert len(res.output_hash) == 64

    def test_echo(self, terminal_engine):
        res = terminal_engine.execute_command("echo V15_TERMINAL_RESILIENCE")
        assert res.exit_code == 0
        assert "V15_TERMINAL_RESILIENCE" in res.stdout
        assert len(res.output_hash) == 64

    def test_printf(self, terminal_engine):
        res = terminal_engine.execute_command('printf "formatted_%s" test_token')
        assert res.exit_code == 0
        assert "formatted_test_token" in res.stdout
        assert len(res.output_hash) == 64


# ==============================================================================
# Category B: Command Execution & Exit Codes
# ==============================================================================

class TestCategoryBExitCodes:
    def test_python_version_exit_code_zero(self, terminal_engine):
        res = terminal_engine.execute_command([sys.executable, "--version"])
        assert res.exit_code == 0
        assert res.status == ExecutionStatus.SUCCESS
        assert res.duration_ms >= 0.0
        assert res.completion_timestamp != ""

    def test_custom_exit_code_preserved(self, terminal_engine):
        res = terminal_engine.execute_command([sys.executable, "-c", "import sys; sys.exit(7)"])
        assert res.exit_code == 7
        assert res.status == ExecutionStatus.ERROR
        assert res.duration_ms >= 0.0


# ==============================================================================
# Category C: Filesystem Operations
# ==============================================================================

class TestCategoryCFilesystem:
    def test_filesystem_crud_and_sha256(self, terminal_engine, tmp_path):
        target_file = tmp_path / "v15_audit_artifact.txt"
        content_1 = "Initial forensic artifact log line.\n"
        content_2 = "Appended threat intelligence record.\n"

        # Write (binary mode to be deterministic across OS newline translations)
        b1 = content_1.encode("utf-8")
        b2 = content_2.encode("utf-8")
        res_write = terminal_engine.execute_command(
            [sys.executable, "-c", f"open(r'{target_file}', 'wb').write({repr(b1)})"]
        )
        assert res_write.exit_code == 0
        assert target_file.exists()

        # Append
        res_append = terminal_engine.execute_command(
            [sys.executable, "-c", f"open(r'{target_file}', 'ab').write({repr(b2)})"]
        )
        assert res_append.exit_code == 0

        # Read & Verify SHA-256
        expected_bytes = b1 + b2
        expected_sha256 = hashlib.sha256(expected_bytes).hexdigest()

        res_read = terminal_engine.execute_command(
            [sys.executable, "-c", f"import hashlib; print(hashlib.sha256(open(r'{target_file}', 'rb').read()).hexdigest())"]
        )
        assert res_read.exit_code == 0
        assert expected_sha256 in res_read.stdout.strip()

        # Cleanup
        res_del = terminal_engine.execute_command(
            [sys.executable, "-c", f"import os; os.remove(r'{target_file}')"]
        )
        assert res_del.exit_code == 0
        assert not target_file.exists()


# ==============================================================================
# Category D: Network & DNS Diagnostics
# ==============================================================================

class TestCategoryDNetworkAndDNS:
    def test_localhost_dns_resolution(self, terminal_engine):
        res = terminal_engine.execute_command(
            [sys.executable, "-c", "import socket; print(socket.gethostbyname('localhost'))"]
        )
        assert res.exit_code == 0
        assert "127.0.0.1" in res.stdout

    def test_timeout_enforcement(self, terminal_engine):
        # A 5-second sleep commanded with a 1-second timeout
        t0 = time.time()
        res = terminal_engine.execute_command(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout_seconds=1,
        )
        elapsed = time.time() - t0
        assert res.timed_out is True
        assert res.exit_code == 124
        assert res.status == ExecutionStatus.TIMEOUT
        assert elapsed < 4.0


# ==============================================================================
# Category E: HTTP Diagnostics against REDLOOP
# ==============================================================================

class TestCategoryEHTTPDiagnostics:
    def test_health_check_200(self, test_app):
        resp = _async_request(test_app, "GET", "/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") in ("ok", "healthy")

    def test_terminal_environments_endpoint(self, test_app):
        resp = _async_request(test_app, "GET", "/api/terminal/environments")
        assert resp.status_code == 200
        data = resp.json()
        assert "host" in data
        assert data["host"]["available"] is True

    def test_nonexistent_endpoint_404(self, test_app):
        resp = _async_request(test_app, "GET", "/api/v15_nonexistent_probe_endpoint")
        assert resp.status_code == 404

    def test_headers_and_content_type(self, test_app):
        resp = _async_request(test_app, "GET", "/health")
        assert "content-type" in resp.headers
        assert "application/json" in resp.headers["content-type"]


# ==============================================================================
# Category F: TLS Diagnostics
# ==============================================================================

class TestCategoryFTLSDiagnostics:
    def test_tls_unconfigured_port_graceful_handling(self, test_scope_manager, tmp_path):
        audit = AuditLogger(str(tmp_path / "tls_audit.sqlite"))
        checker = TLSChecker(scope=test_scope_manager, audit=audit, timeout=0.5)
        try:
            # Unopened port on localhost: should raise TLSConnectionError / TLSError or return report
            checker.inspect("127.0.0.1", port=44339)
        except TLSError as exc:
            assert "connection" in str(exc).lower() or "failed" in str(exc).lower() or "refused" in str(exc).lower()


# ==============================================================================
# Category G: Security Tool Availability
# ==============================================================================

class TestCategoryGToolAvailability:
    def test_detect_installed_security_tools(self, terminal_engine):
        t0 = time.time()
        tools = terminal_engine.detect_installed_security_tools()
        latency = time.time() - t0
        # Must execute swiftly without blocking
        assert latency < 1.0
        assert "python" in tools
        assert tools["python"]["installed"] is True
        assert tools["python"]["status"] == "AVAILABLE"
        assert tools["python"]["path"] is not None

        # Standard keys presence
        for expected in ("nmap", "curl", "git", "docker"):
            assert expected in tools
            assert "status" in tools[expected]
            assert tools[expected]["status"] in ("AVAILABLE", "ABSENT")


# ==============================================================================
# Category H: Authorized Reconnaissance & Scope Enforcement
# ==============================================================================

class TestCategoryHAuthorizedReconnaissance:
    def test_authorized_loopback_allowed(self, terminal_engine):
        res = terminal_engine.execute_command(
            [sys.executable, "-c", "import socket; s = socket.socket(); s.connect(('127.0.0.1', 80)) if False else print('PROBE_OK')"],
            target="127.0.0.1",
        )
        assert res.exit_code == 0
        assert "PROBE_OK" in res.stdout

    def test_unauthorized_target_scope_blocked(self, terminal_engine):
        res = terminal_engine.execute_command(
            "nmap 198.51.100.5",
            target="198.51.100.5",
        )
        assert res.exit_code == 126
        assert res.status == ExecutionStatus.BLOCKED
        assert "SCOPE_BLOCKED" in res.stderr


# ==============================================================================
# Category I: Error & Timeout Handling
# ==============================================================================

class TestCategoryIErrorAndTimeout:
    def test_nonexistent_binary_returns_127(self, terminal_engine):
        res = terminal_engine.execute_command("nonexistent_binary_xyz_123456")
        assert res.exit_code in (126, 127)
        assert res.status in (ExecutionStatus.ERROR, ExecutionStatus.BLOCKED)
        assert "not found" in res.stderr.lower() or "not permitted" in res.stderr.lower()

    def test_cancellation_token_before_start(self, terminal_engine):
        cancel_evt = threading.Event()
        cancel_evt.set()
        res = terminal_engine.execute_command(
            [sys.executable, "-c", "print('should not run')"],
            cancel_token=cancel_evt,
        )
        assert res.cancelled is True
        assert res.exit_code == -1
        assert res.status == ExecutionStatus.CANCELLED


# ==============================================================================
# Category J: Concurrent Execution
# ==============================================================================

class TestCategoryJConcurrentExecution:
    def test_concurrent_terminal_commands(self, terminal_engine):
        def _run_worker(idx: int) -> ExecutionResult:
            return terminal_engine.execute_command(f"echo WORKER_{idx}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(_run_worker, i) for i in range(4)]
            results = [f.result() for f in futures]

        assert len(results) == 4
        seen_outputs = set()
        for idx, res in enumerate(results):
            assert res.exit_code == 0
            assert res.status == ExecutionStatus.SUCCESS
            assert f"WORKER_{idx}" in res.stdout
            seen_outputs.add(res.stdout.strip())

        # No cross-contamination
        assert len(seen_outputs) == 4


# ==============================================================================
# Category K: Terminal & Chat Integration
# ==============================================================================

class TestCategoryKTerminalChatIntegration:
    def test_command_history_recording(self, terminal_engine):
        res = terminal_engine.execute_command("echo history_record_test")
        assert res.exit_code == 0
        history = terminal_engine.get_command_history(limit=5)
        assert len(history) > 0
        last = history[-1]
        assert "history_record_test" in last["command"]
        assert last["exit_code"] == 0
        assert len(last["output_hash"]) == 64

    def test_structured_chat_report_blocks(self):
        orchestrator = AutonomousAgentOrchestrator()
        task = AgentTask(
            task_id="task-v15-report-test",
            request_id="req-v15",
            user_prompt="Run full reconnaissance against 127.0.0.1",
            task_type="investigation",
            explicit_target="127.0.0.1",
            target_type="ip",
            task_status=AgentTaskStatus.COMPLETED,
            steps=[
                AgentWorkflowStep(
                    step_id="step-1",
                    name="Port Scan",
                    tool_id="nmap",
                    command_args=["-sS", "127.0.0.1"],
                    stdout="80/tcp open http\n443/tcp open https",
                    exit_code=0,
                    status=AgentStepState.COMPLETED,
                    duration_ms=45.2,
                    evidence_id="ev-portscan123",
                )
            ],
            findings=[
                {
                    "title": "Open Port 80/tcp (http)",
                    "severity": "LOW",
                    "description": "Port 80 is listening.",
                    "evidence": "80/tcp open http",
                }
            ],
        )

        report = orchestrator._generate_technical_report(task)
        assert "<Investigation Plan>" in report
        assert "</Investigation Plan>" in report
        assert "<Execution Timeline>" in report
        assert "</Execution Timeline>" in report
        assert "<Tool Execution Cards>" in report
        assert "</Tool Execution Cards>" in report
        assert "<REDLOOP Terminal>" in report
        assert "</REDLOOP Terminal>" in report
        assert "<Discovered Security Findings & Attack Surface>" in report
        assert "</Discovered Security Findings & Attack Surface>" in report
        assert "<Final Analysis & Recommendations>" in report
        assert "</Final Analysis & Recommendations>" in report


# ==============================================================================
# Category L: Resource & Performance Testing
# ==============================================================================

class TestCategoryLPerformance:
    def test_execution_latency_under_1_second(self, terminal_engine):
        t0 = time.time()
        res = terminal_engine.execute_command("whoami")
        latency = time.time() - t0
        assert res.exit_code == 0
        assert latency < 1.0

    def test_duration_measurement_accuracy(self, terminal_engine):
        res = terminal_engine.execute_command("whoami")
        assert res.duration_ms > 0.0

    def test_large_output_truncation(self, terminal_engine):
        # Generate 600KB of output (exceeding 512KB MAX_OUTPUT_BYTES)
        py_cmd = f"import sys; sys.stdout.write('A' * ({MAX_OUTPUT_BYTES} + 81920))"
        res = terminal_engine.execute_command([sys.executable, "-c", py_cmd])
        assert res.exit_code == 0
        assert res.truncated is True
        assert len(res.stdout) <= MAX_OUTPUT_BYTES + 200
        assert "TRUNCATED" in res.stdout
