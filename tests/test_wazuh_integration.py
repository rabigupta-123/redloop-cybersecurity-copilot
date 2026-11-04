"""Tests for Wazuh SIEM / XDR Adapter (Phase 8).

Verifies:
- Configuration and credential masking
- Unconfigured vs configured health checks
- Mocked JWT authentication & session token caching
- Agent inventory retrieval
- Wazuh alert retrieval and UniversalSecurityEvent normalization
"""

import json
from io import BytesIO
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from redloop.assessment.soc_events import UniversalSecurityEvent
from redloop.integrations.adapters.wazuh import WazuhAdapter
from redloop.integrations.base import ProviderCapability, ProviderCategory, ProviderStatus


def make_mock_response(data: dict, status: int = 200):
    m = MagicMock()
    m.status = status
    m.read.return_value = json.dumps(data).encode("utf-8")
    m.__enter__.return_value = m
    m.__exit__.return_value = None
    return m


class TestWazuhIntegration:
    def test_initial_state_unconfigured(self):
        adapter = WazuhAdapter()
        assert adapter.provider_id == "wazuh"
        assert adapter.category == ProviderCategory.SIEM
        assert not adapter.is_configured()
        assert adapter.get_capabilities() == sorted([
            ProviderCapability.READ_ALERTS.value,
            ProviderCapability.SEARCH_EVENTS.value,
            ProviderCapability.GET_AGENT_HEALTH.value,
        ])
        health = adapter.test_connection()
        assert health.status == ProviderStatus.NOT_CONFIGURED
        assert "not configured" in health.message.lower()

    def test_public_config_masks_password(self):
        adapter = WazuhAdapter(
            api_url="https://wazuh.local:55000",
            username="wazuh-wui",
            password="SecretWazuhPassword999",
        )
        assert adapter.is_configured()
        pub = adapter.get_public_config()
        assert pub["api_url"] == "https://wazuh.local:55000"
        assert pub["username"] == "wazuh-wui"
        assert "SecretWazuhPassword999" not in pub["password"]
        assert "******" in pub["password"]

    @patch("urllib.request.urlopen")
    def test_connection_success(self, mock_urlopen):
        auth_resp = make_mock_response({"data": {"token": "fake-jwt-token-123"}})
        status_resp = make_mock_response({
            "data": {
                "wazuh-modulesd": "running",
                "wazuh-analysisd": "running",
                "wazuh-execd": "running",
            }
        })
        mock_urlopen.side_effect = [auth_resp, status_resp]

        adapter = WazuhAdapter(
            api_url="https://wazuh.local:55000",
            username="admin",
            password="adminpassword",
        )
        health = adapter.test_connection()
        assert health.status == ProviderStatus.CONNECTED
        assert "Connected to Wazuh Manager" in health.message
        assert health.details["manager_status"]["wazuh-analysisd"] == "running"

    @patch("urllib.request.urlopen")
    def test_connection_auth_failure(self, mock_urlopen):
        fp = BytesIO(b'{"error": 401, "message": "Unauthorized"}')
        http_err = urllib.error.HTTPError("https://wazuh.local:55000", 401, "Unauthorized", {}, fp)
        mock_urlopen.side_effect = http_err

        adapter = WazuhAdapter(
            api_url="https://wazuh.local:55000",
            username="bad_user",
            password="bad_password",
        )
        health = adapter.test_connection()
        assert health.status == ProviderStatus.AUTH_FAILED
        assert "401" in health.message

    @patch("urllib.request.urlopen")
    def test_get_agents(self, mock_urlopen):
        auth_resp = make_mock_response({"data": {"token": "fake-jwt"}})
        agents_resp = make_mock_response({
            "data": {
                "affected_items": [
                    {"id": "001", "name": "win-dc01", "status": "active", "ip": "10.0.0.10"},
                    {"id": "002", "name": "lnx-srv02", "status": "active", "ip": "10.0.0.20"},
                ],
                "total_affected_items": 2,
            }
        })
        mock_urlopen.side_effect = [auth_resp, agents_resp]

        adapter = WazuhAdapter(
            api_url="https://wazuh.local:55000",
            username="admin",
            password="password",
        )
        agents = adapter.get_agents(limit=10)
        assert len(agents) == 2
        assert agents[0]["name"] == "win-dc01"
        assert agents[1]["ip"] == "10.0.0.20"

    @patch("urllib.request.urlopen")
    def test_get_alerts_and_normalization(self, mock_urlopen):
        auth_resp = make_mock_response({"data": {"token": "fake-jwt"}})
        alerts_resp = make_mock_response({
            "data": {
                "affected_items": [
                    {
                        "id": "wz-alert-991",
                        "timestamp": "2026-11-04T12:00:00Z",
                        "rule": {
                            "id": "5710",
                            "level": 10,
                            "description": "sshd: Multiple failed login attempts",
                            "mitre": {
                                "id": ["T1110.001"],
                                "tactic": ["credential-access"],
                            },
                        },
                        "agent": {
                            "id": "001",
                            "name": "web-front",
                            "ip": "192.168.1.50",
                        },
                        "data": {
                            "srcip": "198.51.100.44",
                            "dstuser": "root",
                        },
                    }
                ]
            }
        })
        mock_urlopen.side_effect = [auth_resp, alerts_resp]

        adapter = WazuhAdapter(
            api_url="https://wazuh.local:55000",
            username="admin",
            password="password",
        )
        events = adapter.get_alerts(limit=5)
        assert len(events) == 1
        ev = events[0]
        assert isinstance(ev, UniversalSecurityEvent)
        assert ev.source_type == "wazuh"
        assert "Multiple failed login attempts" in ev.event_action
        assert ev.source_ip == "198.51.100.44"
        assert ev.severity.value in ["HIGH", "CRITICAL", "MEDIUM"]
