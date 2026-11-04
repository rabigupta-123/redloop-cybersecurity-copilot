"""Tests for EDR & XDR Enterprise Adapters (Phase 8).

Verifies:
- Microsoft Defender for Endpoint & CrowdStrike Falcon
- OAuth2 token retrieval and health checks
- Credential masking in public configs
- Mandatory capability-token approval gating for host isolation / network containment
"""

import json
from io import BytesIO
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from redloop.integrations.adapters.edr_crowdstrike import CrowdStrikeFalconAdapter
from redloop.integrations.adapters.edr_defender import DefenderForEndpointAdapter
from redloop.integrations.base import ProviderCapability, ProviderCategory, ProviderStatus


def make_mock_response(data: dict, status: int = 200):
    m = MagicMock()
    m.status = status
    m.read.return_value = json.dumps(data).encode("utf-8")
    m.__enter__.return_value = m
    m.__exit__.return_value = None
    return m


class TestDefenderForEndpointIntegration:
    def test_initial_state_unconfigured(self):
        adapter = DefenderForEndpointAdapter()
        assert adapter.provider_id == "defender_endpoint"
        assert adapter.category == ProviderCategory.EDR
        assert not adapter.is_configured()
        health = adapter.test_connection()
        assert health.status == ProviderStatus.NOT_CONFIGURED

    def test_public_config_masks_secret(self):
        adapter = DefenderForEndpointAdapter(
            tenant_id="11111111-2222-3333-4444-555555555555",
            client_id="66666666-7777-8888-9999-000000000000",
            client_secret="UltraSecretClientSecretXYZ123456789",
        )
        assert adapter.is_configured()
        pub = adapter.get_public_config()
        assert "UltraSecretClientSecretXYZ123456789" not in pub["client_secret"]
        assert "******" in pub["client_secret"]

    def test_isolation_requires_approval_token(self):
        adapter = DefenderForEndpointAdapter(
            tenant_id="tenant-1",
            client_id="client-1",
            client_secret="secret-1",
        )
        # Without capability token
        res = adapter.isolate_endpoint(machine_id="mach-001", capability_token=None)
        assert res["status"] == "WAITING_FOR_APPROVAL"
        assert "operator capability authorization token" in res["details"]
        assert res["machine_id"] == "mach-001"

    @patch("urllib.request.urlopen")
    def test_isolation_with_approval_token(self, mock_urlopen):
        token_resp = make_mock_response({"access_token": "mde-oauth-token-123", "expires_in": 3600})
        action_resp = make_mock_response({"id": "action-isolate-999", "status": "Succeeded"}, status=201)
        mock_urlopen.side_effect = [token_resp, action_resp]

        adapter = DefenderForEndpointAdapter(
            tenant_id="tenant-1",
            client_id="client-1",
            client_secret="secret-1",
        )
        res = adapter.isolate_endpoint(
            machine_id="mach-001",
            isolation_type="Full",
            comment="Isolating compromised host",
            capability_token="valid-approved-cap-token",
        )
        assert res["status"] == "SUCCEEDED"
        assert res["action_id"] == "action-isolate-999"


class TestCrowdStrikeFalconIntegration:
    def test_initial_state_unconfigured(self):
        adapter = CrowdStrikeFalconAdapter()
        assert adapter.provider_id == "crowdstrike_falcon"
        assert adapter.category == ProviderCategory.EDR
        assert not adapter.is_configured()
        health = adapter.test_connection()
        assert health.status == ProviderStatus.NOT_CONFIGURED

    def test_public_config_masks_secret(self):
        adapter = CrowdStrikeFalconAdapter(
            client_id="falcon-client-id",
            client_secret="FalconSuperSecretSecretKey123",
        )
        assert adapter.is_configured()
        pub = adapter.get_public_config()
        assert "FalconSuperSecretSecretKey123" not in pub["client_secret"]
        assert "******" in pub["client_secret"]

    def test_containment_requires_approval_token(self):
        adapter = CrowdStrikeFalconAdapter(
            client_id="client-cs",
            client_secret="secret-cs",
        )
        # Without capability token
        res = adapter.contain_host(device_id="aid-0001", capability_token=None)
        assert res["status"] == "WAITING_FOR_APPROVAL"
        assert "operator capability authorization token" in res["details"]
        assert res["device_id"] == "aid-0001"

    @patch("urllib.request.urlopen")
    def test_containment_with_approval_token(self, mock_urlopen):
        token_resp = make_mock_response({"access_token": "falcon-oauth-token-456", "expires_in": 1800})
        action_resp = make_mock_response({"resources": ["aid-0001"], "errors": []}, status=202)
        mock_urlopen.side_effect = [token_resp, action_resp]

        adapter = CrowdStrikeFalconAdapter(
            client_id="client-cs",
            client_secret="secret-cs",
        )
        res = adapter.contain_host(
            device_id="aid-0001",
            capability_token="valid-approved-cap-token",
        )
        assert res["status"] == "SUCCEEDED"
        assert res["device_id"] == "aid-0001"
