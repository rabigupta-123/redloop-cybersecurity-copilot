"""Unit tests for Kali Copilot Terminal Output Parsing and Guidance."""

from datetime import date, timedelta
import pytest
import yaml

from redloop.assessment.kali_copilot import KaliCopilot
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.audit import AuditLogger
from redloop.scope import ScopeManager, sign_scope


@pytest.fixture
def copilot_with_scope(tmp_path):
    today = date.today()
    secret = "secret123"
    scope_data = {
        "version": 1,
        "id": "test-scope",
        "authorized_by": "test",
        "signed_at": "2026-10-26T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "targets": [
            {
                "cidr": "127.0.0.1/32",
                "label": "loopback",
                "authorized_from": today.isoformat(),
                "authorized_until": (today + timedelta(days=365)).isoformat(),
                "allowed_actions": ["scan", "check", "assess", "probe"],
                "ports": [80, 443, 8080],
            }
        ],
    }
    scope_data["signature"] = sign_scope(scope_data, secret)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(yaml.safe_dump(scope_data), encoding="utf-8")
    sm = ScopeManager(scope_file, secret)
    audit = AuditLogger(db_path=str(tmp_path / "audit.db"))
    guard = AssessmentScopeGuard(sm, audit)
    return KaliCopilot(scope_guard=guard)


def test_copilot_parse_nmap_scan_output(copilot_with_scope):
    raw_nmap = """
    Starting Nmap 7.80 ( https://nmap.org ) at 2026-10-26 14:00
    Nmap scan report for 127.0.0.1
    Host is up (0.000050s latency).
    PORT     STATE SERVICE VERSION
    80/tcp   open  http    Apache httpd 2.4.41
    8080/tcp open  http    Apache Tomcat 9.0
    Nmap done: 1 IP address (1 host up) scanned in 0.25 seconds
    """
    res = copilot_with_scope.analyze_terminal_output(raw_nmap)
    assert res["tool_detected"] == "nmap"
    assert res["target"] == "127.0.0.1"
    assert len(res["findings"]) == 2
    assert "gobuster dir" in res["next_step"]["recommended_command"]
    assert res["next_step"]["can_execute_via_redloop"] is True
    assert res["evidence_id"].startswith("ev_term_")


def test_copilot_parse_gobuster_output(copilot_with_scope):
    raw_gobuster = """
    ===============================================================
    Gobuster v3.5
    ===============================================================
    /.env                 (Status: 200) [Size: 312]
    /admin                (Status: 403) [Size: 180]
    /login                (Status: 200) [Size: 4200]
    """
    res = copilot_with_scope.analyze_terminal_output(raw_gobuster, target="127.0.0.1:8080")
    assert res["tool_detected"] == "gobuster"
    assert len(res["findings"]) == 3
    assert any(f["path"] == "/.env" for f in res["findings"])
    assert "curl -i" in res["next_step"]["recommended_command"]


def test_copilot_parse_http_response(copilot_with_scope):
    raw_http = """
    HTTP/1.1 200 OK
    Date: Mon, 26 Oct 2026 14:10:00 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Content-Type: text/html; charset=UTF-8
    Content-Length: 1204
    """
    res = copilot_with_scope.analyze_terminal_output(raw_http, target="127.0.0.1")
    assert res["tool_detected"] == "http_response"
    assert len(res["findings"]) == 2
    # Missing headers finding
    missing = [f for f in res["findings"] if f.get("type") == "missing_security_headers"][0]["headers"]
    assert "Content-Security-Policy" in missing
    assert "Strict-Transport-Security" in missing


def test_copilot_parse_linux_error(copilot_with_scope):
    raw_err = "nmap: Permission denied while opening raw socket"
    res = copilot_with_scope.analyze_terminal_output(raw_err)
    assert res["tool_detected"] == "terminal_error"
    assert "sudo" in res["next_step"]["recommended_command"]
