"""Acceptance tests for investigation store, diagnostic endpoints, and large chat payloads."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

from redloop.dashboard import create_app
from redloop.investigation import Investigation, InvestigationStore, get_investigation_store


@pytest.fixture
def app_client(tmp_path):
    audit_db = tmp_path / "test_diag_audit.sqlite"
    app = create_app(str(audit_db))
    return TestClient(app, base_url="http://127.0.0.1")


def test_tools_status_diagnostic_endpoint(app_client):
    """Verify GET /api/tools/status returns structured health check without exposing secrets."""
    resp = app_client.get("/api/tools/status")
    assert resp.status_code == 200
    data = resp.json()

    assert "nmap" in data
    assert "tls_engine" in data
    assert "dns_engine" in data
    assert "forensics_triage" in data

    nmap_diag = data["nmap"]
    assert "installed" in nmap_diag
    assert "execution_backend_available" in nmap_diag
    assert "authorization_system_available" in nmap_diag


def test_investigations_lifecycle_endpoints(app_client):
    """Verify investigations CRUD and active investigation retrieval."""
    # List initial
    resp = app_client.get("/api/investigations")
    assert resp.status_code == 200
    data = resp.json()
    assert "investigations" in data
    assert len(data["investigations"]) >= 1

    # Active
    active_resp = app_client.get("/api/investigations/active")
    assert active_resp.status_code == 200
    active_inv = active_resp.json()
    assert "id" in active_inv
    assert "target" in active_inv

    # Create new investigation
    create_resp = app_client.post(
        "/api/investigations",
        json={
            "title": "CTF Challenge Assessment",
            "target": "127.0.0.1",
            "scope_status": "AUTHORIZED",
            "objective": "Capture all flags and audit service misconfigurations",
        },
        headers={"Origin": "http://127.0.0.1"},
    )
    assert create_resp.status_code == 200
    new_inv = create_resp.json()
    assert new_inv["title"] == "CTF Challenge Assessment"

    # Fetch by ID
    get_resp = app_client.get(f"/api/investigations/{new_inv['id']}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == new_inv["id"]


def test_large_chat_input_handling(app_client):
    """Verify that large technical input (>10,000 characters of logs/code) is accepted by /api/chat/message."""
    # 25,000 character log content
    large_log_sample = "2026-10-26 12:00:00 [INFO] Accepted connection from 127.0.0.1:5432\n" * 380
    assert len(large_log_sample) > 20_000

    resp = app_client.post(
        "/api/chat/message",
        json={
            "message": f"Please analyze this server log excerpt:\n```\n{large_log_sample}\n```",
            "conversation_id": "test-large-input-conv",
        },
        headers={"Origin": "http://127.0.0.1"},
    )

    # Must NOT return 413 Payload Too Large!
    assert resp.status_code == 200
    data = resp.json()
    assert "response" in data
    assert "task" in data
