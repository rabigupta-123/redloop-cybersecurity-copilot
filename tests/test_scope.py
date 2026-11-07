from datetime import date, timedelta

import pytest
import yaml

from redloop.scope import (
    ScopeManager,
    UnauthorizedTargetError,
    sign_scope,
)


SECRET = "unit-test-scope-secret"


def scope_document(expires_at=None):
    today = date.today()
    return {
        "version": 1,
        "id": "unit-test",
        "authorized_by": "tests",
        "signed_at": "2026-01-01T00:00:00Z",
        "expires_at": expires_at or "2099-12-31T23:59:59Z",
        "targets": [
            {
                "cidr": "192.168.56.0/24",
                "label": "test-lab",
                "authorized_from": today.isoformat(),
                "authorized_until": (today + timedelta(days=2)).isoformat(),
                "allowed_actions": ["recon", "scan"],
                "ports": [80],
            }
        ],
    }


def write_signed_scope(path, raw):
    raw["signature"] = sign_scope(raw, SECRET)
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")


def test_valid_signature_authorizes_target_and_action(tmp_path):
    path = tmp_path / "scope.yaml"
    write_signed_scope(path, scope_document())

    entry = ScopeManager(path, SECRET).check("192.168.56.10", "recon", port=80)

    assert entry.label == "test-lab"


def test_unsigned_scope_is_rejected_even_when_secret_is_present(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump(scope_document()), encoding="utf-8")

    with pytest.raises(UnauthorizedTargetError, match="signature is missing"):
        ScopeManager(path, SECRET)


def test_signature_covers_expiry_and_extra_target_fields(tmp_path):
    path = tmp_path / "scope.yaml"
    raw = scope_document()
    write_signed_scope(path, raw)

    changed = yaml.safe_load(path.read_text(encoding="utf-8"))
    changed["targets"][0]["ports"] = [443]
    path.write_text(yaml.safe_dump(changed), encoding="utf-8")

    with pytest.raises(UnauthorizedTargetError, match="signature is invalid"):
        ScopeManager(path, SECRET)


def test_expired_scope_is_rejected(tmp_path):
    path = tmp_path / "scope.yaml"
    raw = scope_document("2000-01-01T00:00:00Z")
    write_signed_scope(path, raw)
    manager = ScopeManager(path, SECRET)

    with pytest.raises(UnauthorizedTargetError, match="expired"):
        manager.check("192.168.56.10", "recon")


def test_port_must_be_explicitly_authorized(tmp_path):
    path = tmp_path / "scope.yaml"
    write_signed_scope(path, scope_document())
    manager = ScopeManager(path, SECRET)

    with pytest.raises(UnauthorizedTargetError, match="port 443"):
        manager.check("192.168.56.10", "recon", port=443)


def test_omitted_port_is_denied_for_port_restricted_entry(tmp_path):
    path = tmp_path / "scope.yaml"
    write_signed_scope(path, scope_document())
    manager = ScopeManager(path, SECRET)

    with pytest.raises(UnauthorizedTargetError, match="no port was specified"):
        manager.check("192.168.56.10", "recon")

    # Explicitly requesting an unauthorized port and omitting the port both fail.
    with pytest.raises(UnauthorizedTargetError):
        manager.check("192.168.56.10", "recon", port=443)


def test_unknown_action_is_denied(tmp_path):
    path = tmp_path / "scope.yaml"
    write_signed_scope(path, scope_document())
    manager = ScopeManager(path, SECRET)

    with pytest.raises(UnauthorizedTargetError, match="not permitted"):
        manager.check("192.168.56.10", "unknown_action", port=80)

def test_report_serve_refuses_to_start_without_valid_scope(monkeypatch):
    from typer.testing import CliRunner

    from redloop import cli

    def unavailable():
        raise UnauthorizedTargetError("signature missing")

    monkeypatch.setattr(cli, "_get_scope_manager", unavailable)
    result = CliRunner().invoke(cli.app, ["report", "serve", "--port", "8799"])

    assert result.exit_code == 1
    assert "Refusing to start dashboard" in result.output


def test_scope_entry_domain_matching():
    from redloop.scope import ScopeEntry
    today = date.today()
    entry = ScopeEntry(
        domain="example.com",
        label="test-domain",
        authorized_from=today,
        authorized_until=today + timedelta(days=1),
        allowed_actions=["recon", "scan"],
    )
    assert entry.matches("example.com")
    assert entry.matches("sub.example.com")
    assert entry.matches("deep.sub.example.com")
    assert not entry.matches("notexample.com")
    assert not entry.matches("evil.org")

    cidr_entry = ScopeEntry(
        cidr="10.0.0.0/24",
        authorized_from=today,
        authorized_until=today + timedelta(days=1),
    )
    assert not cidr_entry.matches("not-an-ip")
    assert cidr_entry.matches("10.0.0.5")


def test_scope_entry_validation():
    from redloop.scope import ScopeEntry, ScopeFile
    from pydantic import ValidationError
    today = date.today()

    with pytest.raises(ValidationError):
        ScopeEntry(cidr="999.999.999.999/24", authorized_from=today, authorized_until=today)

    with pytest.raises(ValidationError):
        ScopeEntry(cidr="10.0.0.0/24", authorized_from=today, authorized_until=today, ports=[0])

    with pytest.raises(ValidationError):
        ScopeEntry(cidr="10.0.0.0/24", authorized_from=today, authorized_until=today, ports=[70000])

    with pytest.raises(ValidationError):
        ScopeFile(expires_at="2026-01-01T00:00:00")  # missing timezone


def test_sign_and_verify_scope_edge_cases():
    from redloop.scope import sign_scope, verify_scope
    raw = scope_document()
    with pytest.raises(ValueError, match="secret must not be empty"):
        sign_scope(raw, "")

    assert not verify_scope(raw, "", "some-sig")
    assert not verify_scope(raw, SECRET, "")


def test_scope_manager_edge_cases(tmp_path):
    from redloop.scope import ScopeManager, UnauthorizedTargetError
    # Missing file
    with pytest.raises(FileNotFoundError):
        ScopeManager(tmp_path / "nonexistent.yaml", SECRET)

    # Non-dict YAML
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("- item1\n- item2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        ScopeManager(bad_yaml, SECRET)

    # Valid scope manager
    path = tmp_path / "scope.yaml"
    write_signed_scope(path, scope_document())
    sm = ScopeManager(path, SECRET)

    # require() alias when port is omitted on port-restricted entry fails closed
    with pytest.raises(UnauthorizedTargetError, match="no port was specified"):
        sm.require("192.168.56.10", "recon")

    # require_port=False allows omitting port
    entry2 = sm.check("192.168.56.10", "recon", require_port=False)
    assert entry2.label == "test-lab"

    # With open ports scope (ports=None), require() succeeds
    open_doc = scope_document()
    open_doc["targets"][0]["ports"] = None
    open_path = tmp_path / "scope_open.yaml"
    write_signed_scope(open_path, open_doc)
    sm_open = ScopeManager(open_path, SECRET)
    entry_open = sm_open.require("192.168.56.10", "recon")
    assert entry_open.label == "test-lab"

    # is_target_in_scope
    assert sm.is_target_in_scope("192.168.56.10")
    assert not sm.is_target_in_scope("10.0.0.1")

    # is_authorized
    assert sm.is_authorized("192.168.56.10", "recon", port=80)
    assert not sm.is_authorized("192.168.56.10", "recon", port=9999)
    assert not sm.is_authorized("10.0.0.1", "recon")


def test_scope_guard_coverage(tmp_path):
    from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
    from redloop.assessment.models import OperationClass
    from redloop.scope import ScopeManager

    path = tmp_path / "scope.yaml"
    write_signed_scope(path, scope_document())
    sm = ScopeManager(path, SECRET)
    guard = AssessmentScopeGuard(sm)

    # is_authorized without action
    assert guard.is_authorized("192.168.56.10")
    assert not guard.is_authorized("10.0.0.1")

    # is_authorized with action and explicit port
    entry_auth = guard.is_target_authorized("192.168.56.10", "recon", port=80)
    assert entry_auth.label == "test-lab"
    # Action without port on port-restricted entry returns False (fail-closed)
    assert not guard.is_authorized("192.168.56.10", "recon")
    assert not guard.is_authorized("192.168.56.10", "exploit")

    # verify_operation
    entry = guard.verify_operation("192.168.56.10", category="recon", port=80)
    assert entry.label == "test-lab"

    # normalize_target
    norm_url = guard.normalize_target("http://192.168.56.10:8080/path")
    assert norm_url["normalized"] == "192.168.56.10"
    assert norm_url["is_ip"] is True

    norm_host = guard.normalize_target("localhost")
    assert norm_host["is_loopback"] is True

    # is_target_allowed convenience
    ok, reason = guard.is_target_allowed("192.168.56.10", ports=[80])
    assert ok is True
    assert reason == "AUTHORIZED"

    not_ok, reason = guard.is_target_allowed("10.0.0.1")
    assert not_ok is False
    assert "not present in scope.yaml" in reason

    # validate_resolved_ip: target resolving to private IP without loopback authorization is blocked by policy
    with pytest.raises(ScopeBlockedError, match="Security block"):
        guard.validate_resolved_ip("192.168.56.10", "192.168.56.10", action="recon")

    # Loopback target resolving to loopback is permitted when in scope
    today = date.today()
    loopback_doc = scope_document()
    loopback_doc["targets"] = [{
        "cidr": "127.0.0.1/32",
        "label": "loopback",
        "authorized_from": today.isoformat(),
        "authorized_until": (today + timedelta(days=2)).isoformat(),
        "allowed_actions": ["recon", "scan"],
        "ports": None,
    }]
    lb_path = tmp_path / "scope_lb.yaml"
    write_signed_scope(lb_path, loopback_doc)
    guard_lb = AssessmentScopeGuard(ScopeManager(lb_path, SECRET))
    assert guard_lb.validate_resolved_ip("127.0.0.1", "127.0.0.1", action="recon")

    # Target resolving to unauthorized IP raises ScopeBlockedError
    with pytest.raises(ScopeBlockedError):
        guard.validate_resolved_ip("192.168.56.10", "10.0.0.99", action="recon")

    # Public hostname resolving to loopback/private raises ScopeBlockedError
    with pytest.raises(ScopeBlockedError, match="prohibited by policy"):
        guard.validate_resolved_ip("public-site.org", "127.0.0.1", action="recon")
