"""Microsoft Entra ID (Azure AD) Identity Adapter (Phase 8).

Integrates with Microsoft Graph API for user identity queries, sign-in log retrieval,
session revocation, and approval-gated account lockout.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from redloop.assessment.soc_events import UniversalSecurityEvent
from redloop.integrations.base import (
    BaseProvider,
    HealthCheckResult,
    ProviderCapability,
    ProviderCategory,
    ProviderStatus,
)
from redloop.integrations.config import IntegrationConfig
from redloop.integrations.credentials import mask_secret, sanitize_error_message
from redloop.integrations.normalizers import normalize_entra_signin


class EntraIDAdapter(BaseProvider):
    """Adapter for Microsoft Entra ID via Microsoft Graph API."""

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        enabled: bool = False,
    ) -> None:
        super().__init__(
            provider_id="entra_id",
            display_name="Microsoft Entra ID (Azure AD)",
            category=ProviderCategory.IDENTITY,
            version="v1.0",
            enabled=enabled,
        )
        self._explicit_tenant_id = tenant_id
        self._explicit_client_id = client_id
        self._explicit_client_secret = client_secret
        self._bearer_token: Optional[str] = None
        self._token_expiry: float = 0.0

        self._capabilities = {
            ProviderCapability.LOOKUP_USER,
            ProviderCapability.LOOKUP_GROUP,
            ProviderCapability.GET_AUTH_EVENTS,
            ProviderCapability.REVOKE_USER_SESSIONS,
            ProviderCapability.DISABLE_USER_ACCOUNT,
        }

    @property
    def tenant_id(self) -> Optional[str]:
        return self._explicit_tenant_id or IntegrationConfig.get_setting("entra", "tenant_id") or IntegrationConfig.get_setting("entra_id", "tenant_id")

    @property
    def client_id(self) -> Optional[str]:
        return self._explicit_client_id or IntegrationConfig.get_setting("entra", "client_id") or IntegrationConfig.get_setting("entra_id", "client_id")

    @property
    def client_secret(self) -> Optional[str]:
        return self._explicit_client_secret or IntegrationConfig.get_setting("entra", "client_secret") or IntegrationConfig.get_setting("entra_id", "client_secret")

    def is_configured(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    def get_public_config(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "client_secret": mask_secret(self.client_secret),
        }

    def _get_token(self) -> Optional[str]:
        """Obtains OAuth2 token for Microsoft Graph."""
        now = time.time()
        if self._bearer_token and now < self._token_expiry:
            return self._bearer_token

        if not self.is_configured():
            return None

        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        body = urllib.parse.urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        }).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                token = data.get("access_token")
                expires_in = data.get("expires_in", 3600)
                if token:
                    self._bearer_token = token
                    self._token_expiry = now + expires_in - 60
                    return token
        except Exception:
            return None
        return None

    def test_connection(self) -> HealthCheckResult:
        """Executes health probe against Microsoft Graph organization root."""
        if not self.is_configured():
            res = HealthCheckResult(
                status=ProviderStatus.NOT_CONFIGURED,
                latency_ms=0.0,
                message="Entra ID is not configured. Supply ENTRA_TENANT_ID, CLIENT_ID, and CLIENT_SECRET.",
            )
            self._last_health = res
            return res

        start = time.time()
        token = self._get_token()
        if not token:
            elapsed = (time.time() - start) * 1000.0
            res = HealthCheckResult(
                status=ProviderStatus.AUTH_FAILED,
                latency_ms=round(elapsed, 2),
                message="Microsoft Graph token acquisition failed.",
            )
            self._last_health = res
            return res

        try:
            url = "https://graph.microsoft.com/v1.0/organization?$select=id,displayName"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = (time.time() - start) * 1000.0
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    org_name = data.get("value", [{}])[0].get("displayName", "Entra Organization")
                    res = HealthCheckResult(
                        status=ProviderStatus.CONNECTED,
                        latency_ms=round(elapsed, 2),
                        message=f"Connected to Microsoft Entra tenant '{org_name}'.",
                        details={"organization": org_name},
                    )
                else:
                    res = HealthCheckResult(
                        status=ProviderStatus.DEGRADED,
                        latency_ms=round(elapsed, 2),
                        message=f"Microsoft Graph returned HTTP {resp.status}.",
                    )
        except Exception as e:
            elapsed = (time.time() - start) * 1000.0
            res = HealthCheckResult(
                status=ProviderStatus.UNAVAILABLE,
                latency_ms=round(elapsed, 2),
                message=sanitize_error_message(f"Connection failed: {str(e)}"),
            )

        self._last_health = res
        return res

    def lookup_user(self, user_principal_name: str) -> Optional[dict[str, Any]]:
        """Queries user attributes and account status."""
        if not self.is_configured():
            return None
        token = self._get_token()
        if not token:
            return None

        clean_user = urllib.parse.quote(user_principal_name.strip())
        url = f"https://graph.microsoft.com/v1.0/users/{clean_user}?$select=id,userPrincipalName,displayName,accountEnabled,jobTitle,department"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None
        return None

    def revoke_sessions(self, user_id: str, capability_token: Optional[str] = None) -> dict[str, Any]:
        """Revokes all active refresh tokens and sign-in sessions for a user."""
        if not capability_token:
            return {"status": "WAITING_FOR_APPROVAL", "details": "Session revocation requires operator capability token."}
        if not self.is_configured():
            return {"status": "NOT_CONFIGURED", "details": "Entra ID is not configured."}

        token = self._get_token()
        if not token:
            return {"status": "FAILED", "details": "Authentication token acquisition failed."}

        clean_user = urllib.parse.quote(user_id.strip())
        url = f"https://graph.microsoft.com/v1.0/users/{clean_user}/revokeSignInSessions"
        req = urllib.request.Request(url, data=b"{}", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status in (200, 204):
                    return {"status": "SUCCEEDED", "user_id": user_id, "details": "Sign-in sessions revoked successfully."}
                return {"status": "FAILED", "user_id": user_id, "details": f"Graph returned HTTP {resp.status}."}
        except Exception as e:
            return {"status": "FAILED", "user_id": user_id, "details": sanitize_error_message(str(e))}
