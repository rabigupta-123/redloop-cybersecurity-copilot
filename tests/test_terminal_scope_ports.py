"""Tests for S1: Terminal scope gate, network target/port extraction, and DNS pinning."""
from __future__ import annotations

import datetime
from pathlib import Path
import pytest
import yaml

from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
from redloop.assessment.terminal_engine import (
    ExecutionStatus,
    UnifiedTerminalEngine,
    extract_network_targets,
)
from redloop.scope import ScopeManager, sign_scope


_SECRET = "test-scope-secret-terminal-ports-12345"


def _make_scope_file(tmp_path: Path, targets: list[dict]) -> Path:
    expires = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).isoformat()
    raw = {
        "version": 1,
        "id": "term-test-scope",
        "authorized_by": "sec-lead",
        "signed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "expires_at": expires,
        "targets": targets,
    }
    raw["signature"] = sign_scope(raw, _SECRET)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return scope_file


def _get_engine(tmp_path: Path, ports: list[int] | None = None) -> UnifiedTerminalEngine:
    today = datetime.date.today().isoformat()
    scope_file = _make_scope_file(
        tmp_path,
        [
            {
                "cidr": "10.0.0.1/32",
                "label": "test-host",
                "authorized_from": today,
                "authorized_until": today,
                "allowed_actions": ["scan", "recon"],
                "ports": ports if ports is not None else [80, 443],
            },
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback",
                "authorized_from": today,
                "authorized_until": today,
                "allowed_actions": ["scan", "recon"],
                "ports": [80, 443, 8765],
            },
        ],
    )
    sm = ScopeManager(scope_file=scope_file, secret=_SECRET)
    guard = AssessmentScopeGuard(sm)
    return UnifiedTerminalEngine(scope_guard=guard)


def test_nmap_ports_authorized_and_unauthorized(tmp_path):
    # Port 80 authorized, 8080 not authorized
    engine = _get_engine(tmp_path, ports=[80])
    res = engine.execute_command("nmap -p 80,8080 10.0.0.1")
    assert res.status == ExecutionStatus.BLOCKED
    assert res.exit_code == 126
    assert "8080" in res.stderr


def test_curl_port_not_authorized(tmp_path):
    # Port 80 authorized on 10.0.0.1, but 8080 is not
    engine = _get_engine(tmp_path, ports=[80])
    res = engine.execute_command("curl http://10.0.0.1:8080")
    assert res.status == ExecutionStatus.BLOCKED
    assert res.exit_code == 126
    assert "8080" in res.stderr


def test_nc_port_not_authorized(tmp_path):
    # Port 22 not authorized
    engine = _get_engine(tmp_path, ports=[80, 443])
    res = engine.execute_command("nc 10.0.0.1 22")
    assert res.status == ExecutionStatus.BLOCKED
    assert res.exit_code == 126
    assert "22" in res.stderr


def test_extract_url_userinfo_stripping():
    targets = extract_network_targets("curl http://user:pass@evil.com:443/")
    assert targets == [("evil.com", 443)]


def test_extract_obfuscated_decimal_ip():
    # 2130706433 == 127.0.0.1
    targets = extract_network_targets("curl http://2130706433/")
    assert targets == [("127.0.0.1", 80)]


def test_chained_command_rejected():
    with pytest.raises(ValueError, match="forbidden shell metacharacters"):
        extract_network_targets("nmap 10.0.0.1 && curl 10.0.0.2")

    engine = UnifiedTerminalEngine()
    res = engine.execute_command("nmap 10.0.0.1 && curl 10.0.0.2")
    assert res.status == ExecutionStatus.BLOCKED
    assert res.exit_code == 126


def test_unknown_binary_rejected():
    with pytest.raises(ValueError, match="not in trusted network allowlist"):
        extract_network_targets("python -c 'import socket'")

    engine = UnifiedTerminalEngine()
    res = engine.execute_command("python -c 'import socket'")
    assert res.status == ExecutionStatus.BLOCKED
    assert res.exit_code == 126


def test_dns_rebinding_rejected(tmp_path, monkeypatch):
    # Public domain resolving to private/loopback IP
    today = datetime.date.today().isoformat()
    scope_file = _make_scope_file(
        tmp_path,
        [
            {
                "domain": "example.com",
                "label": "public-domain",
                "authorized_from": today,
                "authorized_until": today,
                "allowed_actions": ["scan", "recon"],
                "ports": [80, 443],
            }
        ],
    )
    sm = ScopeManager(scope_file=scope_file, secret=_SECRET)
    guard = AssessmentScopeGuard(sm)
    engine = UnifiedTerminalEngine(scope_guard=guard)

    # Monkeypatch socket.getaddrinfo so example.com resolves to 127.0.0.1 (rebinding attempt)
    import socket
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))],
    )

    res = engine.execute_command("curl http://example.com/api")
    assert res.status == ExecutionStatus.BLOCKED
    assert res.exit_code == 126
    assert "SCOPE_BLOCKED" in res.stderr
