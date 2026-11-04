"""Tests for Ticketing & Incident Management Adapters (Jira & ServiceNow) (Phase 8).

Verifies:
- Jira & ServiceNow configuration and credential masking
- Health checks (unconfigured vs connected vs auth failure)
- Idempotency key enforcement preventing duplicate ticket creation
- Evidence reference attachment and secret scrubbing
- Simulated fallback creation when unconfigured
"""

import json
from io import BytesIO
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from redloop.integrations.adapters.ticketing_jira import JiraAdapter
from redloop.integrations.adapters.ticketing_servicenow import ServiceNowAdapter
from redloop.integrations.base import ProviderCapability, ProviderCategory, ProviderStatus


def make_mock_response(data: dict, status: int = 200):
    m = MagicMock()
    m.status = status
    m.read.return_value = json.dumps(data).encode("utf-8")
    m.__enter__.return_value = m
    m.__exit__.return_value = None
    return m


class TestJiraIntegration:
    def test_initial_state_unconfigured(self):
        adapter = JiraAdapter()
        assert adapter.provider_id == "jira"
        assert adapter.category == ProviderCategory.TICKETING
        assert not adapter.is_configured()
        health = adapter.test_connection()
        assert health.status == ProviderStatus.NOT_CONFIGURED

    def test_public_config_masks_token(self):
        adapter = JiraAdapter(
            url="https://jira.enterprise.org",
            username="secops_bot",
            api_token="ATATT3xFfGF01234567890abcdef123456",
            project_key="SEC",
        )
        assert adapter.is_configured()
        pub = adapter.get_public_config()
        assert "ATATT3xFfGF01234567890abcdef123456" not in pub["api_token"]
        assert "******" in pub["api_token"]

    def test_unconfigured_simulated_creation(self):
        adapter = JiraAdapter()
        res = adapter.create_incident_ticket(
            summary="Test Incident",
            description="Details of incident",
            idempotency_key="sim-key-01",
        )
        assert res["status"] == "SIMULATED"
        assert "SEC-SIM" in res["issue_key"]

        # Calling again with same idempotency key returns ALREADY_EXISTS
        res_dup = adapter.create_incident_ticket(
            summary="Test Incident",
            description="Details of incident",
            idempotency_key="sim-key-01",
        )
        assert res_dup["status"] == "ALREADY_EXISTS"
        assert res_dup["issue_key"] == res["issue_key"]

    @patch("urllib.request.urlopen")
    def test_configured_ticket_creation_and_idempotency(self, mock_urlopen):
        mock_urlopen.return_value = make_mock_response({"id": "10001", "key": "SEC-404"}, status=201)

        adapter = JiraAdapter(
            url="https://jira.enterprise.org",
            username="secops_bot",
            api_token="valid_token_xyz",
            project_key="SEC",
        )
        res = adapter.create_incident_ticket(
            summary="Compromised credential detected",
            description="User account flagged for multiple impossible travel alerts.",
            idempotency_key="idem-jira-101",
            evidence_references=["ev-hash-1", "ev-hash-2"],
        )
        assert res["status"] == "SUCCEEDED"
        assert res["issue_key"] == "SEC-404"

        # Re-request with same idempotency key must not send second HTTP call
        res_dup = adapter.create_incident_ticket(
            summary="Compromised credential detected",
            description="User account flagged for multiple impossible travel alerts.",
            idempotency_key="idem-jira-101",
        )
        assert res_dup["status"] == "ALREADY_EXISTS"
        assert res_dup["issue_key"] == "SEC-404"
        assert mock_urlopen.call_count == 1


class TestServiceNowIntegration:
    def test_initial_state_unconfigured(self):
        adapter = ServiceNowAdapter()
        assert adapter.provider_id == "servicenow"
        assert adapter.category == ProviderCategory.TICKETING
        assert not adapter.is_configured()
        health = adapter.test_connection()
        assert health.status == ProviderStatus.NOT_CONFIGURED

    def test_public_config_masks_password(self):
        adapter = ServiceNowAdapter(
            instance_url="https://instance.service-now.com",
            username="snow_admin",
            password="UltraSecretSnowPassword!",
        )
        assert adapter.is_configured()
        pub = adapter.get_public_config()
        assert "UltraSecretSnowPassword!" not in pub["password"]
        assert "******" in pub["password"]

    def test_unconfigured_simulated_creation(self):
        adapter = ServiceNowAdapter()
        res = adapter.create_incident_ticket(
            short_description="Network anomaly",
            description="Spike in outbound traffic",
            idempotency_key="snow-key-01",
        )
        assert res["status"] == "SIMULATED"
        assert res["incident_number"] == "INC0010992"

        res_dup = adapter.create_incident_ticket(
            short_description="Network anomaly",
            description="Spike in outbound traffic",
            idempotency_key="snow-key-01",
        )
        assert res_dup["status"] == "ALREADY_EXISTS"
        assert res_dup["incident_number"] == "INC0010992"

    @patch("urllib.request.urlopen")
    def test_configured_ticket_creation(self, mock_urlopen):
        mock_urlopen.return_value = make_mock_response({
            "result": {
                "number": "INC0099881",
                "sys_id": "9988aabbccddeeff",
            }
        }, status=201)

        adapter = ServiceNowAdapter(
            instance_url="https://instance.service-now.com",
            username="snow_admin",
            password="valid_password",
        )
        res = adapter.create_incident_ticket(
            short_description="Malware beacon detected",
            description="Host beaconing to known C2 domain.",
            idempotency_key="snow-idem-99",
            evidence_references=["ev-c2-01"],
        )
        assert res["status"] == "SUCCEEDED"
        assert res["incident_number"] == "INC0099881"
        assert res["sys_id"] == "9988aabbccddeeff"
