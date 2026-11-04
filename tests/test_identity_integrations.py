"""Tests for Identity Providers (Entra ID & Active Directory) (Phase 8).

Verifies:
- Microsoft Entra ID (Azure AD) and on-premises Active Directory
- OAuth2 token acquisition & Microsoft Graph user lookups
- LDAP connection probe
- Approval gating on high-risk identity actions (session revocation, account lockout)
"""

import json
from io import BytesIO
import socket
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from redloop.integrations.adapters.identity_ad import ActiveDirectoryAdapter
from redloop.integrations.adapters.identity_entra import EntraIDAdapter
from redloop.integrations.base import ProviderCapability, ProviderCategory, ProviderStatus


def make_mock_response(data: dict, status: int = 200):
    m = MagicMock()
    m.status = status
    m.read.return_value = json.dumps(data).encode("utf-8")
    m.__enter__.return_value = m
    m.__exit__.return_value = None
    return m


class TestEntraIDIntegration:
    def test_initial_state_unconfigured(self):
        adapter = EntraIDAdapter()
        assert adapter.provider_id == "entra_id"
        assert adapter.category == ProviderCategory.IDENTITY
        assert not adapter.is_configured()
        health = adapter.test_connection()
        assert health.status == ProviderStatus.NOT_CONFIGURED

    def test_public_config_masks_secrets(self):
        adapter = EntraIDAdapter(
            tenant_id="tenant-entra-1",
            client_id="client-entra-1",
            client_secret="UltraSecretEntraSecretKey999",
        )
        assert adapter.is_configured()
        pub = adapter.get_public_config()
        assert "UltraSecretEntraSecretKey999" not in pub["client_secret"]
        assert "******" in pub["client_secret"]

    def test_revoke_sessions_requires_approval(self):
        adapter = EntraIDAdapter(
            tenant_id="tenant-1",
            client_id="client-1",
            client_secret="secret-1",
        )
        # Without capability token
        res = adapter.revoke_sessions(user_id="analyst@corp.com", capability_token=None)
        assert res["status"] == "WAITING_FOR_APPROVAL"
        assert "operator capability token" in res["details"]

    @patch("urllib.request.urlopen")
    def test_revoke_sessions_with_approval(self, mock_urlopen):
        token_resp = make_mock_response({"access_token": "graph-token-xyz", "expires_in": 3600})
        revoke_resp = make_mock_response({"value": True}, status=200)
        mock_urlopen.side_effect = [token_resp, revoke_resp]

        adapter = EntraIDAdapter(
            tenant_id="tenant-1",
            client_id="client-1",
            client_secret="secret-1",
        )
        res = adapter.revoke_sessions(
            user_id="compromised_user@corp.com",
            capability_token="valid-capability-token-abc",
        )
        assert res["status"] == "SUCCEEDED"
        assert res["user_id"] == "compromised_user@corp.com"

    @patch("urllib.request.urlopen")
    def test_lookup_user(self, mock_urlopen):
        token_resp = make_mock_response({"access_token": "graph-token-xyz", "expires_in": 3600})
        user_resp = make_mock_response({
            "id": "usr-101",
            "userPrincipalName": "alice@corp.com",
            "displayName": "Alice Smith",
            "accountEnabled": True,
            "department": "Finance",
        }, status=200)
        mock_urlopen.side_effect = [token_resp, user_resp]

        adapter = EntraIDAdapter(
            tenant_id="tenant-1",
            client_id="client-1",
            client_secret="secret-1",
        )
        user = adapter.lookup_user("alice@corp.com")
        assert user is not None
        assert user["displayName"] == "Alice Smith"
        assert user["department"] == "Finance"


class TestActiveDirectoryIntegration:
    def test_initial_state_unconfigured(self):
        adapter = ActiveDirectoryAdapter()
        assert adapter.provider_id == "active_directory"
        assert adapter.category == ProviderCategory.IDENTITY
        assert not adapter.is_configured()
        health = adapter.test_connection()
        assert health.status == ProviderStatus.NOT_CONFIGURED

    def test_public_config_masks_password(self):
        adapter = ActiveDirectoryAdapter(
            server="dc01.corp.local",
            bind_dn="CN=svc_redloop,OU=ServiceAccounts,DC=corp,DC=local",
            bind_password="SuperSecretLdapPassword123!",
        )
        assert adapter.is_configured()
        pub = adapter.get_public_config()
        assert "SuperSecretLdapPassword123!" not in pub["bind_password"]
        assert "******" in pub["bind_password"]

    @patch("socket.create_connection")
    def test_connection_probe(self, mock_create_connection):
        mock_sock = MagicMock()
        mock_create_connection.return_value = mock_sock

        adapter = ActiveDirectoryAdapter(
            server="dc01.corp.local",
            port=636,
            bind_dn="CN=svc,DC=corp,DC=local",
            bind_password="pass",
        )
        health = adapter.test_connection()
        assert health.status == ProviderStatus.CONNECTED
        assert "dc01.corp.local:636" in health.message
        mock_sock.close.assert_called_once()

    def test_disable_account_requires_approval(self):
        adapter = ActiveDirectoryAdapter(
            server="dc01.corp.local",
            bind_dn="CN=svc,DC=corp,DC=local",
            bind_password="pass",
        )
        # Without capability token
        res = adapter.disable_account(sAMAccountName="badguy", capability_token=None)
        assert res["status"] == "WAITING_FOR_APPROVAL"

        # With capability token
        res_approved = adapter.disable_account(sAMAccountName="badguy", capability_token="cap-token-123")
        assert res_approved["status"] == "SUCCEEDED"
        assert res_approved["account"] == "badguy"
