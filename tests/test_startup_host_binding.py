"""Tests for Phase 1 S6: Refuse non-loopback startup enforcement."""

import os
import sys
import pytest
from typer.testing import CliRunner

from redloop.cli import app
from redloop.unified_app import is_loopback_host, validate_server_host, create_unified_app, get_app


def test_is_loopback_host():
    assert is_loopback_host("127.0.0.1") is True
    assert is_loopback_host("127.0.0.2") is True
    assert is_loopback_host("localhost") is True
    assert is_loopback_host("::1") is True
    assert is_loopback_host("testserver") is True
    assert is_loopback_host("0.0.0.0") is False
    assert is_loopback_host("192.168.1.1") is False
    assert is_loopback_host("10.0.0.1") is False
    assert is_loopback_host("evil.com") is False
    assert is_loopback_host(None) is False
    assert is_loopback_host("") is False


def test_validate_server_host_loopback_succeeds():
    # Should not raise for loopback addresses
    validate_server_host("127.0.0.1")
    validate_server_host("localhost")
    validate_server_host("::1")


def test_validate_server_host_non_loopback_default_fails(monkeypatch):
    monkeypatch.delenv("REDLOOP_ALLOW_REMOTE", raising=False)
    monkeypatch.delenv("REDLOOP_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("REDLOOP_OPERATOR_TOKEN_HASH", raising=False)
    monkeypatch.setattr("redloop.assessment.soar_engine.is_operator_token_enabled", lambda: False)

    with pytest.raises(RuntimeError, match="Refusing to bind on non-loopback host '0.0.0.0'"):
        validate_server_host("0.0.0.0")

    with pytest.raises(RuntimeError, match="Refusing to bind on non-loopback host '192.168.1.10'"):
        validate_server_host("192.168.1.10")


def test_validate_server_host_remote_allowed_but_no_token_fails(monkeypatch):
    monkeypatch.setenv("REDLOOP_ALLOW_REMOTE", "1")
    monkeypatch.delenv("REDLOOP_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("REDLOOP_OPERATOR_TOKEN_HASH", raising=False)
    monkeypatch.setattr("redloop.assessment.soar_engine.is_operator_token_enabled", lambda: False)

    with pytest.raises(RuntimeError, match="Refusing to bind on non-loopback host '0.0.0.0'"):
        validate_server_host("0.0.0.0")


def test_validate_server_host_token_enabled_but_remote_disallowed_fails(monkeypatch):
    monkeypatch.setenv("REDLOOP_ALLOW_REMOTE", "0")
    monkeypatch.setenv("REDLOOP_OPERATOR_TOKEN", "valid_operator_token_value_12345")
    monkeypatch.setattr("redloop.assessment.soar_engine.is_operator_token_enabled", lambda: True)

    with pytest.raises(RuntimeError, match="Refusing to bind on non-loopback host '0.0.0.0'"):
        validate_server_host("0.0.0.0")


def test_validate_server_host_both_allowed_and_token_succeeds(monkeypatch):
    monkeypatch.setenv("REDLOOP_ALLOW_REMOTE", "1")
    monkeypatch.setenv("REDLOOP_OPERATOR_TOKEN", "valid_operator_token_value_12345")
    monkeypatch.setattr("redloop.assessment.soar_engine.is_operator_token_enabled", lambda: True)

    # Both conditions met -> binds successfully
    validate_server_host("0.0.0.0")
    validate_server_host("192.168.1.10")


def test_get_app_refuses_when_sys_argv_has_non_loopback(monkeypatch):
    monkeypatch.delenv("REDLOOP_ALLOW_REMOTE", raising=False)
    monkeypatch.setattr("redloop.assessment.soar_engine.is_operator_token_enabled", lambda: False)
    monkeypatch.setattr(sys, "argv", ["uvicorn", "redloop.unified_app:get_app", "--host", "0.0.0.0"])

    with pytest.raises(RuntimeError, match="Refusing to bind on non-loopback host '0.0.0.0'"):
        get_app()


def test_create_unified_app_refuses_non_loopback_bind_host(monkeypatch, tmp_path):
    monkeypatch.delenv("REDLOOP_ALLOW_REMOTE", raising=False)
    monkeypatch.setattr("redloop.assessment.soar_engine.is_operator_token_enabled", lambda: False)

    db_path = str(tmp_path / "test.db")
    with pytest.raises(RuntimeError, match="Refusing to bind on non-loopback host '0.0.0.0'"):
        create_unified_app(db_path, bind_host="0.0.0.0")


def test_cli_report_serve_refuses_non_loopback(monkeypatch):
    monkeypatch.delenv("REDLOOP_ALLOW_REMOTE", raising=False)
    monkeypatch.setattr("redloop.assessment.soar_engine.is_operator_token_enabled", lambda: False)

    runner = CliRunner()
    result = runner.invoke(app, ["report", "serve", "--host", "0.0.0.0"])
    assert result.exit_code != 0
    assert "Refusing to start dashboard" in result.output
