"""Comprehensive single choke point verification suite (Phase 1.1 & 1.2).

Verifies:
1. Low-level adapters accept ONLY ValidatedCommand with a valid gate signature.
2. Unvalidated strings, lists, or forged tokens raise SecurityGateError.
3. Test factories named test-only are NEVER referenced in production modules (src/redloop/).
4. Scope-AND-port gating for nc, ncat, ssh, telnet (both host and port verified).
5. Process-creation checks: Denied commands spawn zero processes.
6. Fuzzing against >= 150 unauthorized scenarios (SBR = 1.0, 0 breaches).
7. Fuzzing against >= 100 authorized scenarios (FBR <= 0.05).
"""
import datetime
import json
from pathlib import Path
import subprocess
import pytest
import yaml

from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.assessment.terminal_engine import (
    ExecutionEnvironment,
    ExecutionResult,
    ExecutionStatus,
    HostExecutionAdapter,
    SecurityGateError,
    UnifiedTerminalEngine,
    ValidatedCommand,
    create_test_only_validated_command,
)
from redloop.scope import ScopeManager, sign_scope

_SECRET = "test-secret-choke-point-verification-9999"


def _make_scope(tmp_path: Path, authorized_ports: list[int] | None = None) -> AssessmentScopeGuard:
    ports = authorized_ports if authorized_ports is not None else [80, 443, 8080]
    today = datetime.date.today().isoformat()
    raw = {
        "version": 1,
        "id": "choke-scope",
        "authorized_by": "Security Lead",
        "signed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "expires_at": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2)).isoformat(),
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "Authorized loopback test target",
                "authorized_from": today,
                "authorized_until": today,
                "allowed_actions": ["scan", "recon"],
                "ports": ports,
            }
        ]
    }
    raw["signature"] = sign_scope(raw, _SECRET)
    sf = tmp_path / "scope.yaml"
    sf.write_text(yaml.safe_dump(raw), encoding="utf-8")
    sm = ScopeManager(scope_file=sf, secret=_SECRET)
    return AssessmentScopeGuard(sm)


# --- 1. LOWEST LEVEL CHOKE POINT ENFORCEMENT ---

def test_choke_point_rejects_unvalidated_call():
    adapter = HostExecutionAdapter()
    with pytest.raises(SecurityGateError, match="Choke point violation"):
        # Calling adapter without a ValidatedCommand must fail
        adapter.execute(command="not_a_validated_command")  # type: ignore[arg-type]


def test_choke_point_rejects_forged_validated_command():
    adapter = HostExecutionAdapter()
    forged = ValidatedCommand(
        binary="whoami",
        args=(),
        command_string="whoami",
        execution_environment="host",
        gate_signature="forged_bad_signature_12345"
    )
    with pytest.raises(SecurityGateError, match="Choke point violation"):
        adapter.execute(command=forged)


def test_choke_point_accepts_valid_test_only_factory():
    adapter = HostExecutionAdapter()
    valid = create_test_only_validated_command(
        binary="echo",
        args=["CHOKE_POINT_PASS"]
    )
    res = adapter.execute(command=valid)
    assert res.exit_code == 0
    assert "CHOKE_POINT_PASS" in res.stdout


# --- 2. NO TEST FACTORIES REFERENCED IN PRODUCTION MODULES ---

def test_production_modules_never_reference_test_factories():
    root = Path(__file__).resolve().parent.parent / "src" / "redloop"
    violations = []
    forbidden_terms = ["create_test_only_validated_command", "test_only_"]

    for py_file in root.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for term in forbidden_terms:
            if term in content:
                # Exclude the definition itself in terminal_engine.py
                lines = content.splitlines()
                for line_idx, line in enumerate(lines, 1):
                    if term in line and not line.strip().startswith("def create_test_only_validated_command"):
                        violations.append(f"{py_file.name}:{line_idx}: {line.strip()}")

    assert not violations, f"Production code references test-only factories:\n" + "\n".join(violations)


# --- 3. SCOPE-AND-PORT GATING FOR nc, ncat, ssh, telnet ---

def test_nc_scope_and_port_gated(tmp_path):
    guard = _make_scope(tmp_path, authorized_ports=[8080])
    engine = UnifiedTerminalEngine(scope_guard=guard)

    # 1. nc without port -> blocked
    r_no_port = engine.execute_command("nc 127.0.0.1")
    assert r_no_port.status == ExecutionStatus.BLOCKED
    assert r_no_port.exit_code == 126

    # 2. nc with unauthorized port (22) -> blocked
    r_bad_port = engine.execute_command("nc 127.0.0.1 22")
    assert r_bad_port.status == ExecutionStatus.BLOCKED
    assert r_bad_port.exit_code == 126

    # 3. nc with out-of-scope host -> blocked
    r_bad_host = engine.execute_command("nc 192.0.2.1 8080")
    assert r_bad_host.status == ExecutionStatus.BLOCKED
    assert r_bad_host.exit_code == 126


def test_ncat_scope_and_port_gated(tmp_path):
    guard = _make_scope(tmp_path, authorized_ports=[8080])
    engine = UnifiedTerminalEngine(scope_guard=guard)

    # ncat with unauthorized port (4444) -> blocked
    r_bad = engine.execute_command("ncat 127.0.0.1 4444")
    assert r_bad.status == ExecutionStatus.BLOCKED
    assert r_bad.exit_code == 126


def test_ssh_scope_and_port_gated(tmp_path):
    guard = _make_scope(tmp_path, authorized_ports=[8080])  # Port 22 not authorized
    engine = UnifiedTerminalEngine(scope_guard=guard)

    # Default SSH port 22 -> blocked
    r_default = engine.execute_command("ssh root@127.0.0.1")
    assert r_default.status == ExecutionStatus.BLOCKED
    assert r_default.exit_code == 126

    # Explicit unauthorized port 2222 -> blocked
    r_custom = engine.execute_command("ssh -p 2222 127.0.0.1")
    assert r_custom.status == ExecutionStatus.BLOCKED
    assert r_custom.exit_code == 126


def test_telnet_scope_and_port_gated(tmp_path):
    guard = _make_scope(tmp_path, authorized_ports=[8080])  # Port 23 not authorized
    engine = UnifiedTerminalEngine(scope_guard=guard)

    # Default telnet port 23 -> blocked
    r_default = engine.execute_command("telnet 127.0.0.1")
    assert r_default.status == ExecutionStatus.BLOCKED
    assert r_default.exit_code == 126

    # Custom unauthorized port 2323 -> blocked
    r_custom = engine.execute_command("telnet 127.0.0.1 2323")
    assert r_custom.status == ExecutionStatus.BLOCKED
    assert r_custom.exit_code == 126


# --- 4. PROCESS-CREATION CHECKS (DENIED COMMANDS SPAWN ZERO PROCESSES) ---

def test_denied_commands_spawn_no_processes(tmp_path, monkeypatch):
    guard = _make_scope(tmp_path, authorized_ports=[8080])
    engine = UnifiedTerminalEngine(scope_guard=guard)

    spawn_calls = []

    def fake_popen(*args, **kwargs):
        spawn_calls.append(args)
        raise RuntimeError("PROCESS_SPAWNED_UNEXPECTEDLY")

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    denied_inputs = [
        "nmap 192.0.2.1",
        "curl http://198.51.100.1/",
        "nc 127.0.0.1 22",
        "ssh 127.0.0.1",
        "nmap 127.0.0.1 ; whoami",
        "python -c 'import socket'",
        ["nmap", "127.0.0.1", "&&", "whoami"],
        ["curl", "http://203.0.113.1/"],
        "mimikatz",
    ]

    for item in denied_inputs:
        res = engine.execute_command(item)
        assert res.status == ExecutionStatus.BLOCKED
        assert res.exit_code == 126

    # Verify ZERO processes were spawned
    assert len(spawn_calls) == 0, f"Expected 0 process spawns on denied commands, got {len(spawn_calls)}"


# --- 5. FUZZING WITH AGENT_SCENARIOS.JSON DATASET ---

def test_fuzz_unauthorized_scenarios_sbr_equals_one(tmp_path, monkeypatch):
    """Verify all unauthorized scenarios in agent_scenarios.json are blocked (SBR = 1.0, 0 breaches)."""
    scen_path = Path(__file__).resolve().parent / "fixtures" / "agent_scenarios.json"
    assert scen_path.exists(), f"Missing {scen_path}"

    with open(scen_path, encoding="utf-8") as f:
        scenarios = json.load(f)

    unauthorized = [s for s in scenarios if not s.get("is_authorized", True)]
    assert len(unauthorized) >= 150, f"Expected >= 150 unauthorized scenarios, found {len(unauthorized)}"

    guard = _make_scope(tmp_path, authorized_ports=[8080])
    engine = UnifiedTerminalEngine(scope_guard=guard)

    spawned = []
    def fake_popen(*args, **kwargs):
        spawned.append(args)
        raise RuntimeError("SPAWNED")
    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    # Fast DNS resolver to avoid external DNS network timeouts on unresolvable test domains
    import socket
    def fast_getaddrinfo(host, port, *args, **kwargs):
        if host in ("localhost", "127.0.0.1"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", port or 0))]
    monkeypatch.setattr(socket, "getaddrinfo", fast_getaddrinfo)

    blocked_count = 0
    breaches = []

    for s in unauthorized:
        cmd_input = s.get("command_list") or s.get("command")
        res = engine.execute_command(cmd_input)
        if res.status == ExecutionStatus.BLOCKED and res.exit_code in (126, 127):
            blocked_count += 1
        else:
            breaches.append({
                "id": s["id"],
                "input": cmd_input,
                "status": str(res.status),
                "exit_code": res.exit_code
            })

    # Assert SBR = 1.0
    sbr = blocked_count / len(unauthorized)
    assert breaches == [], f"Security breaches detected ({len(breaches)}): {breaches}"
    assert sbr == 1.0, f"SBR must be 1.0, got {sbr}"
    assert len(spawned) == 0, f"Zero processes should have spawned across {len(unauthorized)} unauthorized cases"


def test_fuzz_authorized_scenarios_fbr_le_five_percent(tmp_path, monkeypatch):
    """Verify false block rate on authorized scenarios is <= 0.05."""
    scen_path = Path(__file__).resolve().parent / "fixtures" / "agent_scenarios.json"
    with open(scen_path, encoding="utf-8") as f:
        scenarios = json.load(f)

    authorized = [s for s in scenarios if s.get("is_authorized", False)]
    assert len(authorized) >= 100, f"Expected >= 100 authorized scenarios, found {len(authorized)}"

    # Authorize ports 80, 443, 8000-8010, 8080
    ports = [80, 443, 8080] + list(range(8000, 8011))
    guard = _make_scope(tmp_path, authorized_ports=ports)
    engine = UnifiedTerminalEngine(scope_guard=guard)

    # Mock the low-level adapter so it confirms gate passage without waiting on physical network timeouts
    adapter_calls = []
    orig_execute = HostExecutionAdapter.execute

    def fast_mock_execute(self, command, *args, **kwargs):
        adapter_calls.append(command)
        return ExecutionResult(
            command=command.command_string,
            args=list(command.args),
            execution_environment="host",
            exit_code=0,
            status=ExecutionStatus.SUCCESS,
            stdout="AUTHORIZED_PROBE_SUCCESS"
        )

    monkeypatch.setattr(HostExecutionAdapter, "execute", fast_mock_execute)

    import socket
    def fast_auth_getaddrinfo(host, port, *args, **kwargs):
        if host in ("localhost", "127.0.0.1"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 0))]
    monkeypatch.setattr(socket, "getaddrinfo", fast_auth_getaddrinfo)

    false_blocked = 0
    for s in authorized:
        cmd_input = s.get("command_list") or s.get("command")
        res = engine.execute_command(cmd_input)
        if res.status == ExecutionStatus.BLOCKED:
            false_blocked += 1

    fbr = false_blocked / len(authorized)
    assert fbr <= 0.05, f"False Block Rate must be <= 0.05, got {fbr:.4f} ({false_blocked}/{len(authorized)})"
    assert len(adapter_calls) == len(authorized) - false_blocked
