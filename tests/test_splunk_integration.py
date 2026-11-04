"""Tests for Splunk Enterprise & Cloud SIEM Adapter (Phase 8).

Verifies:
- Configuration and credential masking
- Unconfigured vs configured health checks
- Prohibited SPL query enforcement (blocking destructive commands)
- Bounded search job execution and UniversalSecurityEvent normalization
"""

import json
from io import BytesIO
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from redloop.assessment.soc_events import UniversalSecurityEvent
from redloop.integrations.adapters.splunk import SplunkAdapter
from redloop.integrations.base import ProviderCapability, ProviderCategory, ProviderStatus


def make_mock_response(data: dict, status: int = 200):
    m = MagicMock()
    m.status = status
    m.read.return_value = json.dumps(data).encode("utf-8")
    m.__enter__.return_value = m
    m.__exit__.return_value = None
    return m


class TestSplunkIntegration:
    def test_initial_state_unconfigured(self):
        adapter = SplunkAdapter()
        assert adapter.provider_id == "splunk"
        assert adapter.category == ProviderCategory.SIEM
        assert not adapter.is_configured()
        assert adapter.get_capabilities() == sorted([
            ProviderCapability.READ_ALERTS.value,
            ProviderCapability.SEARCH_EVENTS.value,
        ])
        health = adapter.test_connection()
        assert health.status == ProviderStatus.NOT_CONFIGURED
        assert "not configured" in health.message.lower()

    def test_public_config_masks_secrets(self):
        adapter = SplunkAdapter(
            host="splunk.corp.net",
            port=8089,
            token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.splunk-session-token",
            username="splunk_admin",
            password="SuperSplunkPass!",
        )
        assert adapter.is_configured()
        pub = adapter.get_public_config()
        assert pub["host"] == "splunk.corp.net"
        assert pub["port"] == 8089
        assert "splunk-session-token" not in pub["token"]
        assert "******" in pub["token"]
        assert "SuperSplunkPass!" not in pub["password"]
        assert "******" in pub["password"]

    @patch("urllib.request.urlopen")
    def test_connection_success(self, mock_urlopen):
        server_info = {
            "entry": [
                {
                    "content": {
                        "serverName": "sh01.corp.internal",
                        "version": "9.2.1",
                    }
                }
            ]
        }
        mock_urlopen.return_value = make_mock_response(server_info, status=200)

        adapter = SplunkAdapter(
            host="splunk.corp.net",
            token="valid-token",
        )
        health = adapter.test_connection()
        assert health.status == ProviderStatus.CONNECTED
        assert "sh01.corp.internal" in health.message
        assert health.details["version"] == "9.2.1"

    @patch("urllib.request.urlopen")
    def test_connection_auth_failed(self, mock_urlopen):
        fp = BytesIO(b'<response status="401"><messages><msg type="WARN">Call not properly authenticated</msg></messages></response>')
        http_err = urllib.error.HTTPError("https://splunk.corp.net:8089", 401, "Unauthorized", {}, fp)
        mock_urlopen.side_effect = http_err

        adapter = SplunkAdapter(
            host="splunk.corp.net",
            token="invalid-token",
        )
        health = adapter.test_connection()
        assert health.status == ProviderStatus.AUTH_FAILED
        assert "401" in health.message

    def test_spl_injection_prevention(self):
        adapter = SplunkAdapter(host="splunk.corp.net", token="test-token")
        destructive_queries = [
            "index=main | delete",
            "index=firewall | outputlookup threat_intel.csv",
            "index=security | outputcsv dump.csv",
            "index=logs | collect index=test",
        ]
        for q in destructive_queries:
            with pytest.raises(ValueError, match="Prohibited non-read-only SPL command"):
                adapter.search_events(q)

    @patch("urllib.request.urlopen")
    def test_search_events_success(self, mock_urlopen):
        raw_splunk_results = {
            "results": [
                {
                    "_time": "2026-11-04T14:10:00.000+00:00",
                    "host": "srv-web01",
                    "user": "apache",
                    "src": "203.0.113.19",
                    "dest": "10.0.1.100",
                    "dest_port": "443",
                    "action": "blocked",
                    "signature": "SQL Injection attempt detected in URI parameter",
                    "app": "waf",
                }
            ]
        }
        mock_urlopen.return_value = make_mock_response(raw_splunk_results, status=200)

        adapter = SplunkAdapter(host="splunk.corp.net", token="test-token")
        events = adapter.search_events("index=waf action=blocked", limit=10)
        assert len(events) == 1
        ev = events[0]
        assert isinstance(ev, UniversalSecurityEvent)
        assert ev.source_type == "splunk"
        assert ev.event_action == "blocked"
        assert "SQL Injection attempt" in str(ev.raw_data)
        assert ev.hostname == "srv-web01"
        assert ev.username == "apache"
        assert ev.source_ip == "203.0.113.19"
        assert ev.destination_ip == "10.0.1.100"
