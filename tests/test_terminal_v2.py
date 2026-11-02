import asyncio
import os
import httpx
import pytest
import yaml
from redloop.assessment.kali_copilot import (
    KaliCommandRunner,
    KaliCommandState,
    TerminalCommandRequest,
    TerminalCommandResponse,
    detect_wsl_status,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.dashboard import create_app
from redloop.scope import ScopeManager, sign_scope

SECRET = "unit-test-secret"


@pytest.fixture
def test_scope_manager(tmp_path):
    scope_yaml = tmp_path / "scope.yaml"
    raw = {
        "version": 1,
        "id": "unit-test",
        "authorized_by": "Security Lead",
        "signed_at": "2020-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "Local loopback",
                "authorized_from": "2020-01-01",
                "authorized_until": "2099-12-31",
                "allowed_actions": ["*"],
            }
        ],
    }
    raw["signature"] = sign_scope(raw, SECRET)
    scope_yaml.write_text(yaml.safe_dump(raw), encoding="utf-8")
    sm = ScopeManager(str(scope_yaml), secret=SECRET)
    return sm


@pytest.fixture
def test_app(tmp_path, test_scope_manager):
    db_path = str(tmp_path / "audit.sqlite")
    return create_app(db_path, scope_manager=test_scope_manager)


def _request(app, method, path, **kwargs):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path, **kwargs)
    return asyncio.run(run())


def test_terminal_request_model_extra_forbidden():
    """Verify extra inputs are rejected by Pydantic schema validation."""
    with pytest.raises(Exception):
        TerminalCommandRequest(command="whoami", execution_environment="host", extra_field="forbidden")


def test_terminal_request_model_valid():
    req = TerminalCommandRequest(
        command="whoami",
        execution_environment="host",
        target="127.0.0.1",
        timeout_seconds=15,
    )
    assert req.command == "whoami"
    assert req.execution_environment == "host"
    assert req.target == "127.0.0.1"


def test_detect_wsl_status_structure():
    status = detect_wsl_status()
    assert "wsl_available" in status
    assert "distributions" in status
    assert "kali_available" in status
    assert isinstance(status["distributions"], list)
    # Kali is verified not installed on this test host
    assert status["kali_available"] is False


def test_terminal_empty_command():
    runner = KaliCommandRunner()
    req = TerminalCommandRequest(command="   ", execution_environment="host")
    res = runner.execute_terminal(req)
    assert res.success is False
    assert res.exit_code == -1
    assert "empty" in res.stderr.lower()


def test_terminal_missing_executable():
    runner = KaliCommandRunner()
    req = TerminalCommandRequest(command="nonexistent_binary_xyz_123", execution_environment="host")
    res = runner.execute_terminal(req)
    assert res.success is False
    assert res.exit_code == -1
    assert "not found" in res.stderr.lower()


def test_terminal_dangerous_command_blocked():
    runner = KaliCommandRunner()
    req = TerminalCommandRequest(command="rm -rf /", execution_environment="host")
    res = runner.execute_terminal(req)
    assert res.success is False
    assert res.state == KaliCommandState.BLOCKED.value
    assert "blocked" in res.stderr.lower() or "destructive" in res.stderr.lower()


def test_terminal_kali_unavailable_reporting():
    """When Kali is requested but not installed in WSL, runner reports clear missing status."""
    runner = KaliCommandRunner()
    req = TerminalCommandRequest(command="uname -a", execution_environment="kali")
    res = runner.execute_terminal(req)
    assert res.success is False
    assert res.execution_environment == "kali"
    assert "kali linux distribution is not installed" in res.stderr.lower() or "not available" in res.stderr.lower()


def test_terminal_network_command_scope_enforcement(test_scope_manager):
    guard = AssessmentScopeGuard(test_scope_manager)
    runner = KaliCommandRunner(scope_guard=guard)

    # Unauthorized target
    req_blocked = TerminalCommandRequest(command="nmap 198.51.100.5", execution_environment="host")
    res_blocked = runner.execute_terminal(req_blocked)
    assert res_blocked.success is False
    assert res_blocked.state == KaliCommandState.BLOCKED.value
    assert "not authorized" in res_blocked.stderr.lower()

    # Authorized local target (if nmap binary is missing, it fails on binary lookup, NOT scope block)
    req_auth = TerminalCommandRequest(command="nmap 127.0.0.1", execution_environment="host")
    res_auth = runner.execute_terminal(req_auth)
    assert res_auth.state != KaliCommandState.BLOCKED.value


def test_terminal_host_pwd():
    runner = KaliCommandRunner()
    req = TerminalCommandRequest(command="pwd", execution_environment="host")
    res = runner.execute_terminal(req)
    assert res.success is True
    assert res.exit_code == 0
    assert len(res.stdout.strip()) > 0


def test_api_terminal_execute_success(test_app):
    response = _request(
        test_app,
        "POST",
        "/api/terminal/execute",
        headers={"Origin": "http://testserver"},
        json={
            "command": "whoami",
            "execution_environment": "host",
            "target": "127.0.0.1",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "success" in data
    assert "stdout" in data
    assert "exit_code" in data
    assert data["execution_environment"] == "host"
    assert isinstance(data["duration_ms"], (int, float))


def test_api_kali_execute_alias_with_target(test_app):
    """Verify /api/kali/execute accepts target without Pydantic 422 extra_forbidden error."""
    response = _request(
        test_app,
        "POST",
        "/api/kali/execute",
        headers={"Origin": "http://testserver"},
        json={
            "command": "whoami",
            "execution_environment": "host",
            "target": "127.0.0.1",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["stdout"]) > 0


def test_api_terminal_environments(test_app):
    response = _request(test_app, "GET", "/api/terminal/environments")
    assert response.status_code == 200
    data = response.json()
    assert "host" in data
    assert "wsl" in data
    assert "kali" in data
    assert data["host"]["available"] is True
    assert data["kali"]["status"] == "NOT_INSTALLED"
