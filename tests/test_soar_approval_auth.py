"""Unit tests for S3: SOAR approval authentication, token validation, replay and expiry checks."""
from __future__ import annotations

import time
from starlette.testclient import TestClient
import pytest

from redloop.assessment.soc_playbooks import SOCPlaybookEngine
from redloop.assessment.soar_engine import (
    get_or_create_operator_token,
    verify_operator_token,
)
from redloop.unified_app import get_app


@pytest.fixture
def test_client():
    app = get_app()
    return TestClient(app, base_url="http://127.0.0.1:8765")


@pytest.fixture
def valid_token():
    token, _ = get_or_create_operator_token()
    return token


def test_approval_without_token_fails_401(test_client):
    res = test_client.post(
        "/api/soc/playbooks/PB-CRED/approve",
        json={"step_id": "step-cred-2", "approved": True},
        headers={"Sec-Fetch-Site": "same-origin", "Host": "127.0.0.1:8765"},
    )
    assert res.status_code == 401
    assert "X-Operator-Token header missing" in res.text


def test_approval_with_wrong_token_fails_403(test_client):
    res = test_client.post(
        "/api/soc/playbooks/PB-CRED/approve",
        json={"step_id": "step-cred-2", "approved": True},
        headers={
            "X-Operator-Token": "invalid-wrong-token-12345",
            "Sec-Fetch-Site": "same-origin",
            "Host": "127.0.0.1:8765",
        },
    )
    assert res.status_code == 403
    assert "Invalid operator token" in res.text


def test_approval_cross_origin_fails_403(test_client, valid_token):
    res = test_client.post(
        "/api/soc/playbooks/PB-CRED/approve",
        json={"step_id": "step-cred-2", "approved": True},
        headers={
            "X-Operator-Token": valid_token,
            "Sec-Fetch-Site": "cross-site",
            "Host": "127.0.0.1:8765",
        },
    )
    assert res.status_code == 403
    assert "cross-origin" in res.text.lower()


def test_approval_expired_fails_400(test_client, valid_token):
    expired_ts = time.time() - 400.0  # 400 seconds ago (> 5 minutes)
    res = test_client.post(
        "/api/soc/playbooks/PB-CRED/approve",
        json={
            "step_id": "step-cred-2",
            "approved": True,
            "timestamp": expired_ts,
        },
        headers={
            "X-Operator-Token": valid_token,
            "Sec-Fetch-Site": "same-origin",
            "Host": "127.0.0.1:8765",
        },
    )
    assert res.status_code == 400
    assert "expired" in res.text.lower()


def test_valid_approval_and_replayed_fails_409(test_client, valid_token, monkeypatch):
    monkeypatch.setenv("REDLOOP_OPERATOR_NAME", "lead_analyst_alice")
    now_ts = time.time()
    
    # 1. First valid approval
    res = test_client.post(
        "/api/soc/playbooks/PB-CRED/approve",
        json={
            "step_id": "step-cred-2",
            "approved": True,
            "timestamp": now_ts,
            "parameters": {"user": "target_user"},
        },
        headers={
            "X-Operator-Token": valid_token,
            "Sec-Fetch-Site": "same-origin",
            "Host": "127.0.0.1:8765",
        },
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["success"] is True

    # 2. Replay of same approval fails with 409 Conflict
    res_replay = test_client.post(
        "/api/soc/playbooks/PB-CRED/approve",
        json={
            "step_id": "step-cred-2",
            "approved": True,
            "timestamp": now_ts,
            "parameters": {"user": "target_user"},
        },
        headers={
            "X-Operator-Token": valid_token,
            "Sec-Fetch-Site": "same-origin",
            "Host": "127.0.0.1:8765",
        },
    )
    assert res_replay.status_code == 409
    assert "Replay detected" in res_replay.text
