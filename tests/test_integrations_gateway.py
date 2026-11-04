"""Tests for Enterprise Integration Gateway Core Infrastructure (Phase 8).

Verifies:
- Registry lifecycle, singleton pattern, and registration
- Provider status models and capabilities
- Credential masking, sanitization, and pattern scrubbing
- Environment and file-based config resolution
- Audit trail logging
"""

import os
from unittest.mock import patch

import pytest

from redloop.integrations.base import (
    BaseProvider,
    HealthCheckResult,
    ProviderCapability,
    ProviderCategory,
    ProviderStatus,
)
from redloop.integrations.config import IntegrationConfigResolver
from redloop.integrations.credentials import (
    mask_secret,
    safe_error_message,
    sanitize_config,
)
from redloop.integrations.registry import IntegrationRegistry


class TestIntegrationGatewayCore:
    def test_registry_singleton_and_defaults(self):
        reg1 = IntegrationRegistry.get_instance()
        reg2 = IntegrationRegistry.get_instance()
        assert reg1 is reg2

        providers = reg1.list_providers()
        assert len(providers) >= 9
        ids = {p["provider_id"] for p in providers}
        assert "wazuh" in ids
        assert "elastic_security" in ids
        assert "splunk" in ids
        assert "defender_endpoint" in ids
        assert "crowdstrike_falcon" in ids
        assert "entra_id" in ids
        assert "active_directory" in ids
        assert "jira" in ids
        assert "servicenow" in ids

        # Test alias resolution
        assert reg1.get_provider("elastic") is not None
        assert reg1.get_provider("defender") is not None
        assert reg1.get_provider("crowdstrike") is not None
        assert reg1.get_provider("ad") is not None

    def test_provider_status_and_defaults(self):
        reg = IntegrationRegistry.get_instance()
        wazuh = reg.get_provider("wazuh")
        assert wazuh is not None
        assert wazuh.category == ProviderCategory.SIEM
        assert not wazuh.is_configured()
        health = wazuh.get_health()
        assert health.status == ProviderStatus.NOT_CONFIGURED
        assert "not configured" in health.message.lower()

    def test_credentials_masking(self):
        assert mask_secret(None) == ""
        assert mask_secret("") == ""
        assert mask_secret("short") == "******"
        masked = mask_secret("supersecretkey123456789")
        assert "supersecretkey" not in masked
        assert masked.startswith("su")
        assert masked.endswith("89")
        assert "******" in masked

    def test_config_sanitization(self):
        raw_config = {
            "api_url": "https://siem.local:55000",
            "api_key": "secret_api_key_value_here",
            "client_secret": "my-client-secret-token",
            "password": "SuperSecretPassword123",
            "timeout_seconds": 15,
            "nested": {
                "private_token": "token1234567890",
                "public_name": "Cluster-1",
            },
        }
        sanitized = sanitize_config(raw_config)
        assert sanitized["api_url"] == "https://siem.local:55000"
        assert sanitized["timeout_seconds"] == 15
        assert "secret_api_key_value_here" not in str(sanitized)
        assert "my-client-secret-token" not in str(sanitized)
        assert "SuperSecretPassword123" not in str(sanitized)
        assert "token1234567890" not in str(sanitized)
        assert sanitized["nested"]["public_name"] == "Cluster-1"

    def test_safe_error_message_scrubbing(self):
        raw_err = "Failed connecting to https://admin:SuperPass99@cluster.internal:55000 with Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
        cleaned = safe_error_message(raw_err)
        assert "SuperPass99" not in cleaned
        assert "******" in cleaned
        assert "eyJhbGciOiJIUzI1NiJ9" not in cleaned

    def test_config_resolver_env_and_defaults(self):
        resolver = IntegrationConfigResolver()
        cfg_empty = resolver.get_provider_config("wazuh")
        assert isinstance(cfg_empty, dict)

        with patch.dict(os.environ, {"REDLOOP_WAZUH_API_URL": "https://wazuh.enterprise.corp:55000", "REDLOOP_WAZUH_TIMEOUT": "25"}):
            cfg_override = resolver.get_provider_config("wazuh")
            assert cfg_override.get("api_url") == "https://wazuh.enterprise.corp:55000"
            assert cfg_override.get("timeout") == "25"

    def test_provider_enable_disable_and_audit(self):
        reg = IntegrationRegistry.get_instance()
        assert reg.enable_provider("wazuh", enabled=True)
        wazuh = reg.get_provider("wazuh")
        assert wazuh.enabled is True

        assert reg.enable_provider("wazuh", enabled=False)
        assert wazuh.enabled is False

        assert not reg.enable_provider("non_existent_provider_xyz")

        audit_entries = reg.get_audit_log(limit=10)
        assert len(audit_entries) >= 2
        actions = [a["action"] for a in audit_entries]
        assert "ENABLED" in actions or "DISABLED" in actions
