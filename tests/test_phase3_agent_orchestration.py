"""Phase 3 Automated Test Suite: Terminal Reliability, Autonomous Agent Orchestration & Workflow Engine.

Comprehensive testing of:
1.  Host command execution (whoami, hostname)
2.  WSL adapter execution and status reporting
3.  Kali unavailable truthful reporting
4.  Linux adapter execution
5.  Docker unavailable truthful reporting
6.  Missing executable handling (exit code 127, clear error)
7.  Dangerous command rejection by safety parser
8.  Process execution timeout handling (exit code 124, timed_out=True)
9.  Execution cancellation via cancel token
10. Output size limiting / truncation (truncated=True)
11. Concurrent execution isolation
12. Agent task persistence in AgentTaskStore
13. Multi-step dependency graph execution (depends_on prerequisite enforcement)
14. Intelligent fallback recovery on primary tool failure
15. Partial task completion status (PARTIAL when non-critical step fails)
16. Full task completion status (COMPLETED when all steps pass)
17. Missing target requests clarification (WAITING_FOR_INPUT)
18. Scope authorization gate blocks unauthorized active targets (BLOCKED)
19. General chat questions do NOT execute tools
20. Explicit target preservation
21. Context isolation (no stale target reuse)
22. Cryptographic SHA-256 evidence generation
23. Audit ledger event emission
24. REST API contract validation (/api/agent/tasks, /api/agent/tasks/{id}, /api/terminal/cancel)
25. End-to-end acceptance test against authorized lab target (127.0.0.1)
"""

import math
import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch
import pytest

from redloop.assessment.agent_orchestrator import (
    AgentStepState,
    AgentTask,
    AgentTaskStatus,
    AgentTaskStore,
    AgentWorkflowStep,
    AutonomousAgentOrchestrator,
)
from redloop.assessment.context_resolver import RequestContext, TargetResolver
from redloop.assessment.terminal_engine import (
    DockerExecutionAdapter,
    ExecutionEnvironment,
    ExecutionResult,
    ExecutionStatus,
    HostExecutionAdapter,
    KaliExecutionAdapter,
    UnifiedTerminalEngine,
    WSLExecutionAdapter,
)
from redloop.assessment.tools_v2 import EnvironmentDetector, ToolRegistryV2
from redloop.audit import AuditLogger
from redloop.dashboard import create_app
from redloop.scope import ScopeManager, UnauthorizedTargetError, sign_scope


# --- TEST 1: Host command execution ---
def test_01_host_command_execution():
    adapter = HostExecutionAdapter()
    res = adapter.execute(binary=sys.executable, args=["-c", "print('hello from host')"])
    assert res.exit_code == 0
    assert "hello from host" in res.stdout
    assert res.status == ExecutionStatus.SUCCESS
    assert res.duration_ms > 0


# --- TEST 2: WSL adapter execution ---
def test_02_wsl_adapter_handling():
    adapter = WSLExecutionAdapter()
    avail, reason = adapter.is_available()
    assert isinstance(avail, bool)
    if not avail:
        res = adapter.execute(binary="whoami", args=[])
        assert res.status == ExecutionStatus.ENVIRONMENT_UNAVAILABLE
        assert res.exit_code == 127


# --- TEST 3: Kali unavailable reporting ---
def test_03_kali_unavailable_reporting():
    with patch.object(EnvironmentDetector, "detect_kali", return_value={"available": False}):
        adapter = KaliExecutionAdapter()
        avail, reason = adapter.is_available()
        assert avail is False
        res = adapter.execute(binary="nmap", args=["127.0.0.1"])
        assert res.status == ExecutionStatus.ENVIRONMENT_UNAVAILABLE
        assert "kali linux" in res.stderr.lower()


# --- TEST 4: Linux adapter handling ---
def test_04_linux_adapter():
    engine = UnifiedTerminalEngine()
    # On Windows, linux environment falls back to WSL or host adapter cleanly
    res = engine.execute_command(command_string_or_args=["echo", "linux_test"], environment="linux")
    assert res.status in (ExecutionStatus.SUCCESS, ExecutionStatus.ENVIRONMENT_UNAVAILABLE)


# --- TEST 5: Docker unavailable handling ---
def test_05_docker_unavailable_reporting():
    with patch.object(EnvironmentDetector, "detect_docker", return_value={"available": False, "daemon_running": False}):
        adapter = DockerExecutionAdapter()
        avail, reason = adapter.is_available()
        assert avail is False
        res = adapter.execute(binary="nmap", args=["127.0.0.1"])
        assert res.status == ExecutionStatus.ENVIRONMENT_UNAVAILABLE
        assert res.exit_code == 127


# --- TEST 6: Missing executable handling ---
def test_06_missing_executable():
    adapter = HostExecutionAdapter()
    res = adapter.execute(binary="non_existent_binary_xyz_987", args=[])
    assert res.exit_code == 127
    assert res.status == ExecutionStatus.ERROR
    assert "not found" in res.stderr


# --- TEST 7: Dangerous command rejection ---
def test_07_dangerous_command_rejection():
    engine = UnifiedTerminalEngine()
    res = engine.execute_command(command_string_or_args="rm -rf / --no-preserve-root", environment="host")
    assert res.status == ExecutionStatus.BLOCKED
    assert res.exit_code == 126
    assert "SECURITY_ALERT" in res.stderr


# --- TEST 8: Timeout handling ---
def test_08_timeout_handling():
    adapter = HostExecutionAdapter()
    res = adapter.execute(binary=sys.executable, args=["-c", "import time; time.sleep(5)"], timeout_seconds=1)
    assert res.timed_out is True
    assert res.status == ExecutionStatus.TIMEOUT
    assert res.exit_code == 124


# --- TEST 9: Cancellation handling ---
def test_09_cancellation_handling():
    adapter = HostExecutionAdapter()
    cancel_token = threading.Event()

    def _cancel_after_delay():
        time.sleep(0.2)
        cancel_token.set()

    t = threading.Thread(target=_cancel_after_delay)
    t.start()
    res = adapter.execute(
        binary=sys.executable,
        args=["-c", "import time; time.sleep(10)"],
        timeout_seconds=10,
        cancel_token=cancel_token,
    )
    t.join()
    assert res.cancelled is True
    assert res.status == ExecutionStatus.CANCELLED


# --- TEST 10: Output truncation ---
def test_10_output_truncation():
    adapter = HostExecutionAdapter()
    # Generate 600 KB of output (greater than MAX_OUTPUT_BYTES = 512 KB)
    res = adapter.execute(
        binary=sys.executable,
        args=["-c", "print('A' * 600000)"],
    )
    assert res.exit_code == 0
    assert res.truncated is True
    assert len(res.stdout.encode("utf-8")) <= 512 * 1024


# --- TEST 11: Concurrent execution isolation ---
def test_11_concurrent_execution_isolation():
    engine = UnifiedTerminalEngine()
    results = [None, None]

    def _worker(idx, val):
        results[idx] = engine.execute_command(
            command_string_or_args=[sys.executable, "-c", f"print('{val}')"],
            task_id=f"concurrent-{idx}",
        )

    t1 = threading.Thread(target=_worker, args=(0, "OUTPUT_ALPHA"))
    t2 = threading.Thread(target=_worker, args=(1, "OUTPUT_BETA"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results[0].exit_code == 0
    assert results[1].exit_code == 0
    assert "OUTPUT_ALPHA" in results[0].stdout
    assert "OUTPUT_BETA" in results[1].stdout


# --- TEST 12: Agent task persistence ---
def test_12_agent_task_persistence():
    store = AgentTaskStore.get_instance()
    task = AgentTask(
        task_id="task-persist-test",
        request_id="req-test-12",
        user_prompt="Run port scan on 127.0.0.1",
        task_type="recon",
        explicit_target="127.0.0.1",
        target_type="ip",
        task_status=AgentTaskStatus.CREATED,
    )
    store.save(task)
    loaded = store.get("task-persist-test")
    assert loaded is not None
    assert loaded.explicit_target == "127.0.0.1"


# --- TEST 13: Multi-step dependency execution (prerequisite enforcement) ---
def test_13_dependency_execution_flow():
    orchestrator = AutonomousAgentOrchestrator()
    task = AgentTask(
        task_id="task-dep-test",
        request_id="req-dep-13",
        user_prompt="Scan 127.0.0.1",
        task_type="recon",
        explicit_target="127.0.0.1",
        target_type="ip",
        steps=[
            AgentWorkflowStep(
                step_id="step-1",
                name="Prereq Step",
                tool_id="python3",
                command_args=["-c", "print('step 1 success')"],
            ),
            AgentWorkflowStep(
                step_id="step-2",
                name="Dependent Step",
                tool_id="python3",
                command_args=["-c", "print('step 2 success')"],
                depends_on=["step-1"],
            ),
        ],
    )
    orchestrator._execute_workflow(task)
    assert task.steps[0].status == AgentStepState.COMPLETED
    assert task.steps[1].status == AgentStepState.COMPLETED
    assert task.task_status == AgentTaskStatus.COMPLETED


# --- TEST 14: Intelligent fallback recovery ---
def test_14_fallback_recovery():
    orchestrator = AutonomousAgentOrchestrator()
    task = AgentTask(
        task_id="task-fallback-test",
        request_id="req-fb-14",
        user_prompt="Probe host",
        task_type="recon",
        explicit_target="127.0.0.1",
        target_type="ip",
        steps=[
            AgentWorkflowStep(
                step_id="step-1",
                name="Failing Primary Step",
                tool_id="non_existent_tool_xyz",
                command_args=[],
                fallback_tool_id=sys.executable,
                fallback_rationale="Fallback to python diagnostic script.",
            )
        ],
    )
    orchestrator._execute_workflow(task)
    # The step engaged fallback
    assert task.steps[0].retry_count == 1
    assert task.steps[0].status == AgentStepState.COMPLETED
    assert "[FALLBACK_RECOVERY" in task.steps[0].stdout


# --- TEST 15: Partial task completion status ---
def test_15_partial_task_status():
    orchestrator = AutonomousAgentOrchestrator()
    task = AgentTask(
        task_id="task-partial-test",
        request_id="req-part-15",
        user_prompt="Recon 127.0.0.1",
        task_type="recon",
        explicit_target="127.0.0.1",
        target_type="ip",
        steps=[
            AgentWorkflowStep(
                step_id="step-1",
                name="Passing Step",
                tool_id="python3",
                command_args=["-c", "print('ok')"],
            ),
            AgentWorkflowStep(
                step_id="step-2",
                name="Failing Step",
                tool_id="non_existent_tool_abc_999",
                command_args=[],
            ),
        ],
    )
    orchestrator._execute_workflow(task)
    assert task.steps[0].status == AgentStepState.COMPLETED
    assert task.steps[1].status == AgentStepState.FAILED
    assert task.task_status == AgentTaskStatus.PARTIAL


# --- TEST 16: Full task completion status ---
def test_16_full_task_completion():
    orchestrator = AutonomousAgentOrchestrator()
    task = AgentTask(
        task_id="task-full-test",
        request_id="req-full-16",
        user_prompt="Scan localhost",
        task_type="recon",
        explicit_target="127.0.0.1",
        target_type="ip",
        steps=[
            AgentWorkflowStep(
                step_id="step-1",
                name="Step One",
                tool_id="python3",
                command_args=["-c", "print('step 1')"],
            ),
            AgentWorkflowStep(
                step_id="step-2",
                name="Step Two",
                tool_id="python3",
                command_args=["-c", "print('step 2')"],
                depends_on=["step-1"],
            ),
        ],
    )
    orchestrator._execute_workflow(task)
    assert task.task_status == AgentTaskStatus.COMPLETED
    assert task.technical_report is not None
    assert "REDLOOP SECURITY ASSESSMENT REPORT" in task.technical_report


# --- TEST 17: Missing target requests clarification ---
def test_17_missing_target_requests_clarification():
    orchestrator = AutonomousAgentOrchestrator()
    task = orchestrator.create_and_run_task(
        prompt="Scan all ports and perform vulnerability assessment",
        target=None,
    )
    assert task.task_status == AgentTaskStatus.WAITING_FOR_INPUT
    assert len(task.errors) > 0


# --- TEST 18: Scope authorization blocks unauthorized target ---
def test_18_scope_blocks_unauthorized_target(tmp_path):
    scope_yaml = tmp_path / "scope.yaml"
    secret = "test-secret"
    raw = {
        "version": 1,
        "id": "unit-test",
        "authorized_by": "Lead",
        "signed_at": "2020-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "Localhost only",
                "authorized_from": "2020-01-01",
                "authorized_until": "2099-12-31",
                "allowed_actions": ["scan"],
            }
        ],
    }
    raw["signature"] = sign_scope(raw, secret)
    import yaml
    scope_yaml.write_text(yaml.safe_dump(raw), encoding="utf-8")
    sm = ScopeManager(str(scope_yaml), secret=secret)
    orchestrator = AutonomousAgentOrchestrator(scope_manager=sm)

    task = orchestrator.create_and_run_task(
        prompt="Scan open TCP ports on 192.168.1.100",
        target="192.168.1.100",
        auto_approve=False,
    )
    assert task.task_status == AgentTaskStatus.BLOCKED
    assert task.requires_approval is True


# --- TEST 19: General chat does not execute tools ---
def test_19_general_chat_no_tools_executed():
    orchestrator = AutonomousAgentOrchestrator()
    task = orchestrator.create_and_run_task(
        prompt="What is SSRF and how does DNS rebinding work?",
        target=None,
    )
    assert task.task_type == "general_chat"
    assert task.task_status == AgentTaskStatus.COMPLETED
    assert len(task.steps) == 0
    assert "no active network scans" in task.technical_report.lower()


# --- TEST 20: Explicit target preservation ---
def test_20_explicit_target_preserved():
    orchestrator = AutonomousAgentOrchestrator()
    task = orchestrator.create_and_run_task(
        prompt="Audit server 10.10.10.5",
        target="10.10.10.5",
    )
    assert task.explicit_target == "10.10.10.5"


# --- TEST 21: Context isolation (no stale target reuse) ---
def test_21_context_isolation_no_stale_target():
    orchestrator = AutonomousAgentOrchestrator()
    ctx = RequestContext(
        request_id="req-prev",
        explicit_target="192.168.1.5",
    )
    # New prompt with general query should NOT adopt 192.168.1.5
    task = orchestrator.create_and_run_task(
        prompt="Explain the difference between symmetric and asymmetric cryptography.",
        request_context=ctx,
    )
    assert task.explicit_target is None
    assert task.task_type == "general_chat"


# --- TEST 22: Cryptographic evidence generation ---
def test_22_cryptographic_evidence_generation():
    orchestrator = AutonomousAgentOrchestrator()
    task = AgentTask(
        task_id="task-ev-test",
        request_id="req-ev-22",
        user_prompt="Run check",
        task_type="recon",
        explicit_target="127.0.0.1",
        target_type="ip",
        steps=[
            AgentWorkflowStep(
                step_id="step-ev",
                name="Evidence Producer",
                tool_id="python3",
                command_args=["-c", "print('CRYPTO_EVIDENCE_PAYLOAD_12345')"],
            )
        ],
    )
    orchestrator._execute_workflow(task)
    assert len(task.evidence_ids) > 0
    assert task.steps[0].evidence_id is not None
    assert task.steps[0].evidence_id.startswith("ev-")


# --- TEST 23: Audit ledger event emission ---
def test_23_audit_trail_logging():
    mock_audit = MagicMock()
    engine = UnifiedTerminalEngine(audit=mock_audit)
    res = engine.execute_command(command_string_or_args=[sys.executable, "-c", "print('audit test')"])
    assert res.exit_code == 0
    assert mock_audit.log.called
    call_args = mock_audit.log.call_args[1]
    assert call_args["module"] == "terminal"


# --- TEST 24: REST API contracts for agent tasks ---
def test_24_agent_api_endpoints(tmp_path):
    app = create_app(str(tmp_path / "audit.sqlite"))
    from starlette.testclient import TestClient

    client = TestClient(app, base_url="http://testserver")

    # 1. Create Task
    r_create = client.post(
        "/api/agent/tasks",
        headers={"Origin": "http://testserver"},
        json={"prompt": "What is SQL injection?"},
    )
    assert r_create.status_code == 200
    task_data = r_create.json()
    task_id = task_data["task_id"]
    assert task_data["task_type"] == "general_chat"

    # 2. Get Task Details
    r_get = client.get(f"/api/agent/tasks/{task_id}")
    assert r_get.status_code == 200
    assert r_get.json()["task_id"] == task_id

    # 3. Get Steps
    r_steps = client.get(f"/api/agent/tasks/{task_id}/steps")
    assert r_steps.status_code == 200
    assert "steps" in r_steps.json()

    # 4. Cancel Task
    r_cancel = client.post(
        f"/api/agent/tasks/{task_id}/cancel",
        headers={"Origin": "http://testserver"},
    )
    assert r_cancel.status_code == 200


# --- TEST 25: End-to-end acceptance test against authorized lab target ---
def test_25_end_to_end_acceptance():
    orchestrator = AutonomousAgentOrchestrator()
    task = orchestrator.create_and_run_task(
        prompt="Analyze the supplied lab target. Plan the assessment, select available tools, explain the execution sequence, perform the permitted checks, correlate the evidence and produce a technical security report.",
        target="127.0.0.1",
        auto_approve=True,
    )
    assert task.explicit_target == "127.0.0.1"
    assert task.task_status in (AgentTaskStatus.COMPLETED, AgentTaskStatus.PARTIAL)
    assert len(task.steps) > 0
    assert task.technical_report is not None
    assert "REDLOOP SECURITY ASSESSMENT REPORT" in task.technical_report
    assert "Tool Selection & Execution Transparency" in task.technical_report
    assert "Assessment Intelligence & Quality Metrics" in task.technical_report

