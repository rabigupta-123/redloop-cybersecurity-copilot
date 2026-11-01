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
                "allowed_actions": ["recon"],
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
