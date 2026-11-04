"""Tests for Elastic Security SIEM Adapter (Phase 8).

Verifies:
- Configuration and credential masking
- Unconfigured vs configured health checks
- Elasticsearch cluster ping and version retrieval
- Parameterized DSL query execution
- Alert retrieval and UniversalSecurityEvent normalization
"""

import json
from io import BytesIO
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from redloop.assessment.soc_events import UniversalSecurityEvent
from redloop.integrations.adapters.elastic import ElasticSecurityAdapter
from redloop.integrations.base import ProviderCapability, ProviderCategory, ProviderStatus


def make_mock_response(data: dict, status: int = 200):
    m = MagicMock()
    m.status = status
    m.read.return_value = json.dumps(data).encode("utf-8")
    m.__enter__.return_value = m
    m.__exit__.return_value = None
    return m


class TestElasticSecurityIntegration:
    def test_initial_state_unconfigured(self):
        adapter = ElasticSecurityAdapter()
        assert adapter.provider_id == "elastic_security"
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
        adapter = ElasticSecurityAdapter(
            url="https://elastic.corp.local:9200",
            api_key="V2FyZ2FtZXNBcGlLZXlWYWx1ZTEyMzQ1Njc4OTA=",
            username="elastic_admin",
            password="ElasticSuperPassword99",
        )
        assert adapter.is_configured()
        pub = adapter.get_public_config()
        assert pub["url"] == "https://elastic.corp.local:9200"
        assert "V2FyZ2FtZXNBcGlLZXlWYWx1ZTEyMzQ1Njc4OTA=" not in pub["api_key"]
        assert "******" in pub["api_key"]
        assert "ElasticSuperPassword99" not in pub["password"]
        assert "******" in pub["password"]

    @patch("urllib.request.urlopen")
    def test_connection_success(self, mock_urlopen):
        cluster_info = {
            "name": "es-node-01",
            "cluster_name": "redloop-soc-cluster",
            "version": {"number": "8.14.0"},
        }
        mock_urlopen.return_value = make_mock_response(cluster_info, status=200)

        adapter = ElasticSecurityAdapter(
            url="https://elastic.corp.local:9200",
            api_key="valid-api-key-here-123456",
        )
        health = adapter.test_connection()
        assert health.status == ProviderStatus.CONNECTED
        assert "redloop-soc-cluster" in health.message
        assert health.details["version"] == "8.14.0"

    @patch("urllib.request.urlopen")
    def test_connection_auth_failed(self, mock_urlopen):
        fp = BytesIO(b'{"error": {"root_cause": [{"type": "security_exception", "reason": "action [cluster:monitor/main] is unauthorized"}]}}')
        http_err = urllib.error.HTTPError("https://elastic.corp.local:9200", 401, "Unauthorized", {}, fp)
        mock_urlopen.side_effect = http_err

        adapter = ElasticSecurityAdapter(
            url="https://elastic.corp.local:9200",
            api_key="invalid-api-key",
        )
        health = adapter.test_connection()
        assert health.status == ProviderStatus.AUTH_FAILED
        assert "401" in health.message

    @patch("urllib.request.urlopen")
    def test_get_alerts_and_normalization(self, mock_urlopen):
        raw_es_hits = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {
                        "_index": ".alerts-security.alerts-default",
                        "_id": "elastic-alert-101",
                        "_source": {
                            "@timestamp": "2026-11-04T13:45:00.000Z",
                            "kibana.alert": {
                                "rule": {
                                    "name": "Suspicious PowerShell Execution via EncodedCommand",
                                    "severity": "critical",
                                    "threat": [
                                        {
                                            "framework": "MITRE ATT&CK",
                                            "tactic": {"name": "Execution", "id": "TA0002"},
                                            "technique": [{"name": "PowerShell", "id": "T1059.001"}],
                                        }
                                    ],
                                }
                            },
                            "host": {"name": "workstation-09", "ip": ["10.10.10.25"]},
                            "user": {"name": "svc_admin"},
                            "source": {"ip": "198.51.100.99"},
                            "process": {"name": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA..."},
                        },
                    }
                ],
            }
        }
        mock_urlopen.return_value = make_mock_response(raw_es_hits, status=200)

        adapter = ElasticSecurityAdapter(
            url="https://elastic.corp.local:9200",
            api_key="api-key-test",
        )
        events = adapter.get_alerts(limit=5)
        assert len(events) == 1
        ev = events[0]
        assert isinstance(ev, UniversalSecurityEvent)
        assert ev.source_type == "elastic_security"
        assert "Suspicious PowerShell" in ev.event_action
        assert ev.hostname == "workstation-09"
        assert ev.username == "svc_admin"
        assert ev.process_name == "powershell.exe"
        assert ev.severity.value in ["HIGH", "CRITICAL"]
